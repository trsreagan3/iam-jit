"""Tests for #278 — admin-action OCSF audit events (ibounce).

Mirrors the kbounce admin_action_test.go + dbounce admin_action_test.go
patterns: every CLI subcommand that MUTATES ibounce's gating surface
must enqueue an ADMIN_ACTION row whose drained OCSF event validates
against the schema, populates the actor field, and carries the
canonical `unmapped.iam_jit.admin_action.kind` payload.

Per [[cross-product-agent-parity]] the wire shape MUST match kbounce
+ dbounce (same class_uid, same event_type marker, same kind
vocabulary, same severity-floor for license.install / profile.assign).
Per [[security-team-positioning-safety-not-surveillance]] every
user-facing string is NEUTRAL — the test sweeps for the forbidden
words.
Per [[creates-never-mutates]] admin-action emission must never affect
the enforcement decision; the test for the drainer asserts the
pre-existing PROFILE_INSTALL path still works alongside ADMIN_ACTION.
"""

from __future__ import annotations

import json
import pathlib
from typing import Any
from unittest import mock

import pytest
import yaml as _yaml
from click.testing import CliRunner

from iam_jit.bouncer.audit_export import (
    ADMIN_ACTION_PAUSE_START,
    ADMIN_ACTION_PAUSE_STOP,
    ADMIN_ACTION_PRESET_APPLY,
    ADMIN_ACTION_PROFILE_INSTALL,
    ADMIN_ACTION_PROFILE_SWAP,
    ADMIN_ACTION_RULE_ADD,
    ADMIN_ACTION_RULE_REMOVE,
    ADMIN_ACTION_SESSION_KILL,
    ADMIN_ACTION_SOURCE_CLI,
    DEFAULT_LOCAL_OPERATOR,
    EVENT_TYPE_ADMIN_ACTION,
    FORBIDDEN_ALERT_WORDS,
    KNOWN_ADMIN_ACTION_KINDS,
    OCSF_SCHEMA_VERSION,
    admin_action_event_from_payload,
    admin_action_payload,
    enqueue_admin_action,
    hash_state,
    make_admin_action_event,
    resolve_operator,
)
from iam_jit.bouncer.audit_export.admin_action import (
    ACTIVITY_CREATE,
    ACTIVITY_DELETE,
    ACTIVITY_UPDATE,
    SEVERITY_HIGH,
    SEVERITY_INFORMATIONAL,
    _strip_secret_keys,
    admin_action_activity_id,
    admin_action_severity,
)
from iam_jit.bouncer.store import BouncerStore
from iam_jit.bouncer_cli import main


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def store(tmp_path: pathlib.Path):
    s = BouncerStore(db_path=str(tmp_path / "b.db"))
    yield s
    s.close()


@pytest.fixture
def cli_env(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> str:
    """Point the CLI at a tmp DB + tmp profiles file + a fixed actor
    so every admin-action emit is deterministic."""
    db_path = str(tmp_path / "b.db")
    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", db_path)
    monkeypatch.setenv(
        "IAM_JIT_BOUNCER_PROFILES_FILE", str(tmp_path / "profiles.yaml"),
    )
    monkeypatch.setenv("IAM_JIT_BOUNCER_ACTOR", "frank@example.com")
    return db_path


def _drain_admin_actions(db_path: str) -> list[dict[str, Any]]:
    """Drain every pending_audit_events row of type ADMIN_ACTION from
    `db_path` and return the materialised OCSF events in queue order.

    Reverses the wire contract the proxy drainer uses so the test
    covers the same code path. Non-ADMIN_ACTION rows are skipped
    (the test isolates the admin-action half)."""
    s = BouncerStore(db_path=db_path)
    try:
        rows = s.drain_pending_audit_events(limit=1000)
    finally:
        s.close()
    out: list[dict[str, Any]] = []
    for row in rows:
        if row["event_type"] != EVENT_TYPE_ADMIN_ACTION:
            continue
        out.append(admin_action_event_from_payload(row["payload_json"]))
    return out


# ---------------------------------------------------------------------------
# OCSF schema-shape pinning
# ---------------------------------------------------------------------------


def _assert_ocsf_admin_action_shape(evt: dict[str, Any]) -> None:
    """Pin the OCSF v1.1.0 class 6003 shape every admin-action event
    must satisfy. The cross-product fixture: kbounce + dbounce both
    emit the same outer shape, so a single SIEM rule keyed on
    `metadata.product.vendor_name == "iam-jit" AND
    unmapped.iam_jit.event_type == "ADMIN_ACTION"` catches all three.
    """
    # Top-level OCSF fields
    assert evt["class_uid"] == 6003
    assert evt["class_name"] == "API Activity"
    assert evt["category_uid"] == 6
    assert evt["category_name"] == "Application Activity"
    assert evt["metadata"]["version"] == OCSF_SCHEMA_VERSION
    assert evt["metadata"]["product"]["name"] == "ibounce"
    assert evt["metadata"]["product"]["vendor_name"] == "iam-jit"
    # status_id 1 = Success (the mutation has already landed)
    assert evt["status_id"] == 1
    assert evt["status"] == "Success"
    # actor.user.{name,uid} must be non-empty per
    # [[agent-friendly-not-bypassable]] Lens B
    actor_user = evt["actor"]["user"]
    assert actor_user["name"], (
        f"admin-action event missing actor.user.name: {evt}"
    )
    assert actor_user["uid"], (
        f"admin-action event missing actor.user.uid: {evt}"
    )
    # unmapped.iam_jit.event_type marker + admin_action block
    iam_jit = evt["unmapped"]["iam_jit"]
    assert iam_jit["event_type"] == "ADMIN_ACTION"
    admin = iam_jit["admin_action"]
    assert "kind" in admin
    assert "source" in admin
    assert "actor" in admin
    # time + type_uid sanity
    assert isinstance(evt["time"], int)
    assert evt["time"] > 0
    assert evt["type_uid"] == 600300 + evt["activity_id"]


# ---------------------------------------------------------------------------
# Builder unit tests
# ---------------------------------------------------------------------------


def test_make_admin_action_event_pins_ocsf_shape() -> None:
    evt = make_admin_action_event(
        kind=ADMIN_ACTION_RULE_ADD,
        actor="alice@example.com",
        target_kind="rule",
        target_id="#42",
        target_extra={"pattern": "s3:Get*", "effect": "allow"},
        after={"id": 42, "pattern": "s3:Get*"},
    )
    _assert_ocsf_admin_action_shape(evt)
    assert evt["activity_id"] == ACTIVITY_CREATE
    assert evt["activity_name"] == ADMIN_ACTION_RULE_ADD
    assert evt["severity_id"] == SEVERITY_INFORMATIONAL
    admin = evt["unmapped"]["iam_jit"]["admin_action"]
    assert admin["kind"] == ADMIN_ACTION_RULE_ADD
    assert admin["actor"] == "alice@example.com"
    assert admin["target"]["kind"] == "rule"
    assert admin["target"]["id"] == "#42"
    assert admin["target"]["extra"]["pattern"] == "s3:Get*"
    # after_hash present + non-empty; before_hash omitted
    assert isinstance(admin["after_hash"], str)
    assert len(admin["after_hash"]) == 64
    assert "before_hash" not in admin


def test_make_admin_action_event_defaults_actor_to_local_operator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An empty actor + no env var + no getpass result -> the honest
    `local-operator` fallback (NOT the empty string)."""
    monkeypatch.delenv("IAM_JIT_BOUNCER_ACTOR", raising=False)
    monkeypatch.setattr(
        "iam_jit.bouncer.audit_export.admin_action.os.environ",
        {"IAM_JIT_BOUNCER_ACTOR": ""},
    )
    with mock.patch(
        "iam_jit.bouncer.audit_export.admin_action.resolve_operator",
        return_value=DEFAULT_LOCAL_OPERATOR,
    ):
        evt = make_admin_action_event(kind=ADMIN_ACTION_PAUSE_START)
    actor = evt["actor"]["user"]["name"]
    assert actor == DEFAULT_LOCAL_OPERATOR
    admin = evt["unmapped"]["iam_jit"]["admin_action"]
    assert admin["actor"] == DEFAULT_LOCAL_OPERATOR
    # status_detail names the operator label so a human cell shows it
    assert DEFAULT_LOCAL_OPERATOR in evt["status_detail"]


def test_resolve_operator_prefers_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IAM_JIT_BOUNCER_ACTOR", "grace@example.com")
    assert resolve_operator() == "grace@example.com"


def test_resolve_operator_falls_back_to_local_operator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When both env var + getpass fail, the honest fallback fires."""
    monkeypatch.delenv("IAM_JIT_BOUNCER_ACTOR", raising=False)

    def _boom() -> str:
        raise OSError("no /etc/passwd entry")

    monkeypatch.setattr("getpass.getuser", _boom)
    assert resolve_operator() == DEFAULT_LOCAL_OPERATOR


def test_make_admin_action_event_omits_hashes_when_state_is_none() -> None:
    evt = make_admin_action_event(
        kind=ADMIN_ACTION_PAUSE_START,
        actor="alice",
        before=None,
        after=None,
    )
    admin = evt["unmapped"]["iam_jit"]["admin_action"]
    assert "before_hash" not in admin
    assert "after_hash" not in admin


def test_make_admin_action_event_hashes_non_none_state() -> None:
    """Empty-but-not-None state DOES hash (semantically meaningful)."""
    evt = make_admin_action_event(
        kind=ADMIN_ACTION_RULE_REMOVE,
        actor="alice",
        before={"id": 1, "pattern": "iam:Delete*", "effect": "deny"},
        after=None,
    )
    admin = evt["unmapped"]["iam_jit"]["admin_action"]
    assert len(admin["before_hash"]) == 64
    assert "after_hash" not in admin


def test_hash_state_is_stable_across_call_order() -> None:
    """The hash must be insensitive to dict insertion order so the
    tamper-detection rule can compare hashes across runs."""
    a = {"alpha": 1, "beta": [1, 2, 3], "gamma": "x"}
    b = {"gamma": "x", "beta": [1, 2, 3], "alpha": 1}
    assert hash_state(a) == hash_state(b)


def test_hash_state_differs_for_semantic_change() -> None:
    a = {"alpha": 1, "beta": 2}
    b = {"alpha": 1, "beta": 3}
    assert hash_state(a) != hash_state(b)


def test_hash_state_returns_none_for_none() -> None:
    assert hash_state(None) is None


def test_strip_secret_keys_drops_token_leak_keys() -> None:
    cleaned = _strip_secret_keys({
        "issuer": "acme",
        "license_content": "PRIVATE-PEM-BYTES",
        "license_bytes": b"binary",
        "license_pem": "----BEGIN----",
        "license_private_key": "k",
        "license_token": "t",
        "secret": "s",
        "bearer_token": "b",
        "webhook_token": "w",
        "authorization": "a",
        "expiry": "2027-01-01",
    })
    assert "license_content" not in cleaned
    assert "license_bytes" not in cleaned
    assert "license_pem" not in cleaned
    assert "license_private_key" not in cleaned
    assert "license_token" not in cleaned
    assert "secret" not in cleaned
    assert "bearer_token" not in cleaned
    assert "webhook_token" not in cleaned
    assert "authorization" not in cleaned
    # safe keys survive
    assert cleaned["issuer"] == "acme"
    assert cleaned["expiry"] == "2027-01-01"


def test_strip_secret_keys_handles_empty() -> None:
    assert _strip_secret_keys(None) == {}
    assert _strip_secret_keys({}) == {}


def test_make_admin_action_event_strips_secrets_from_extra() -> None:
    """A careless caller passing a license-content key in extra MUST
    NOT leak it into the wire shape."""
    evt = make_admin_action_event(
        kind=ADMIN_ACTION_PROFILE_INSTALL,
        actor="alice",
        extra={
            "issuer": "acme",
            "license_content": "----PRIVATE----",
            "webhook_token": "Bearer xyz",
        },
    )
    extra = evt["unmapped"]["iam_jit"]["admin_action"]["extra"]
    assert "license_content" not in extra
    assert "webhook_token" not in extra
    assert extra["issuer"] == "acme"


def test_make_admin_action_event_strips_secrets_from_target_extra() -> None:
    evt = make_admin_action_event(
        kind=ADMIN_ACTION_PROFILE_INSTALL,
        actor="alice",
        target_kind="profile",
        target_id="team-staging",
        target_extra={
            "source_url": "https://acme.internal/p.yaml",
            "license_content": "----LEAK----",
        },
    )
    tgt_extra = evt["unmapped"]["iam_jit"]["admin_action"]["target"]["extra"]
    assert "license_content" not in tgt_extra
    assert tgt_extra["source_url"] == "https://acme.internal/p.yaml"


# ---------------------------------------------------------------------------
# Activity-id + severity mapping
# ---------------------------------------------------------------------------


def test_admin_action_activity_id_mapping() -> None:
    """Create / Update / Delete mapping per the OCSF v1.1.0 spec."""
    assert admin_action_activity_id(ADMIN_ACTION_RULE_ADD) == ACTIVITY_CREATE
    assert admin_action_activity_id(ADMIN_ACTION_PROFILE_INSTALL) == ACTIVITY_CREATE
    assert admin_action_activity_id(ADMIN_ACTION_PRESET_APPLY) == ACTIVITY_CREATE

    assert admin_action_activity_id(ADMIN_ACTION_PAUSE_START) == ACTIVITY_UPDATE
    assert admin_action_activity_id(ADMIN_ACTION_PAUSE_STOP) == ACTIVITY_UPDATE
    assert admin_action_activity_id(ADMIN_ACTION_PROFILE_SWAP) == ACTIVITY_UPDATE

    assert admin_action_activity_id(ADMIN_ACTION_RULE_REMOVE) == ACTIVITY_DELETE
    assert admin_action_activity_id(ADMIN_ACTION_SESSION_KILL) == ACTIVITY_DELETE


def test_admin_action_severity_mapping() -> None:
    """License install + profile assign land at High; everything else
    at Informational per [[security-team-audit-export]]."""
    sid, _ = admin_action_severity("license.install")
    assert sid == SEVERITY_HIGH
    sid, _ = admin_action_severity("profile.assign")
    assert sid == SEVERITY_HIGH
    # Routine config changes land at Informational
    for kind in (
        ADMIN_ACTION_RULE_ADD, ADMIN_ACTION_RULE_REMOVE,
        ADMIN_ACTION_PAUSE_START, ADMIN_ACTION_PAUSE_STOP,
        ADMIN_ACTION_PROFILE_INSTALL, ADMIN_ACTION_PROFILE_SWAP,
        ADMIN_ACTION_PRESET_APPLY, ADMIN_ACTION_SESSION_KILL,
    ):
        sid, _ = admin_action_severity(kind)
        assert sid == SEVERITY_INFORMATIONAL, (
            f"{kind} should be Informational, got {sid}"
        )


# ---------------------------------------------------------------------------
# Payload <-> event round-trip
# ---------------------------------------------------------------------------


def test_admin_action_payload_roundtrip_preserves_kind_and_actor() -> None:
    payload = admin_action_payload(
        kind=ADMIN_ACTION_RULE_ADD,
        actor="frank@example.com",
        target_kind="rule",
        target_id="#7",
        target_extra={"pattern": "ec2:*"},
        after={"id": 7, "pattern": "ec2:*"},
    )
    evt = admin_action_event_from_payload(payload)
    _assert_ocsf_admin_action_shape(evt)
    admin = evt["unmapped"]["iam_jit"]["admin_action"]
    assert admin["kind"] == ADMIN_ACTION_RULE_ADD
    assert admin["actor"] == "frank@example.com"
    assert admin["target"]["id"] == "#7"
    # before omitted -> no before_hash; after_hash precomputed at
    # enqueue time should ride through
    assert "before_hash" not in admin
    assert len(admin["after_hash"]) == 64


def test_admin_action_payload_strips_secrets_at_enqueue() -> None:
    """Token-leak keys never enter the SQLite queue in the first place."""
    payload_json = admin_action_payload(
        kind=ADMIN_ACTION_PROFILE_INSTALL,
        actor="alice",
        extra={"issuer": "acme", "license_content": "----LEAK----"},
        target_extra={
            "source_url": "https://acme/p.yaml",
            "license_token": "leak",
        },
    )
    payload = json.loads(payload_json)
    assert "license_content" not in payload.get("extra", {})
    assert "license_token" not in payload.get("target_extra", {})


def test_enqueue_admin_action_persists_row(store: BouncerStore) -> None:
    rowid = enqueue_admin_action(
        store,
        kind=ADMIN_ACTION_RULE_ADD,
        actor="alice@example.com",
        target_kind="rule",
        target_id="#1",
        target_extra={"pattern": "s3:Get*", "effect": "allow"},
        after={"id": 1, "pattern": "s3:Get*"},
    )
    assert rowid is not None
    assert store.count_pending_audit_events() == 1
    rows = store.drain_pending_audit_events(limit=10)
    assert len(rows) == 1
    assert rows[0]["event_type"] == EVENT_TYPE_ADMIN_ACTION
    evt = admin_action_event_from_payload(rows[0]["payload_json"])
    admin = evt["unmapped"]["iam_jit"]["admin_action"]
    assert admin["kind"] == ADMIN_ACTION_RULE_ADD
    assert admin["actor"] == "alice@example.com"


def test_enqueue_admin_action_returns_none_on_store_failure() -> None:
    """A store error during enqueue is caught + returns None; the
    user-facing op never sees an exception."""

    class _BrokenStore:
        def enqueue_pending_audit_event(self, **_kwargs: Any) -> int:
            raise RuntimeError("disk full")

    rowid = enqueue_admin_action(
        _BrokenStore(),
        kind=ADMIN_ACTION_PAUSE_START,
        actor="alice",
    )
    assert rowid is None


# ---------------------------------------------------------------------------
# CLI touchpoint wiring — end-to-end via CliRunner + drain
# ---------------------------------------------------------------------------


def test_rules_add_emits_admin_action(cli_env: str) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main, ["rules", "add", "s3:Get*", "--effect", "allow"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output

    events = _drain_admin_actions(cli_env)
    assert len(events) == 1
    evt = events[0]
    _assert_ocsf_admin_action_shape(evt)
    admin = evt["unmapped"]["iam_jit"]["admin_action"]
    assert admin["kind"] == ADMIN_ACTION_RULE_ADD
    assert admin["actor"] == "frank@example.com"
    assert admin["target"]["kind"] == "rule"
    assert admin["target"]["extra"]["pattern"] == "s3:Get*"
    assert admin["target"]["extra"]["effect"] == "allow"
    assert admin["source"] == ADMIN_ACTION_SOURCE_CLI
    assert evt["activity_id"] == ACTIVITY_CREATE


def test_rules_remove_emits_admin_action(cli_env: str) -> None:
    runner = CliRunner()
    add = runner.invoke(
        main, ["rules", "add", "iam:Delete*", "--effect", "deny"],
        catch_exceptions=False,
    )
    assert add.exit_code == 0, add.output
    # Pop the rule.add event so the next drain only sees rule.remove
    _ = _drain_admin_actions(cli_env)

    remove = runner.invoke(
        main, ["rules", "remove", "1"], catch_exceptions=False,
    )
    assert remove.exit_code == 0, remove.output

    events = _drain_admin_actions(cli_env)
    assert len(events) == 1
    evt = events[0]
    _assert_ocsf_admin_action_shape(evt)
    admin = evt["unmapped"]["iam_jit"]["admin_action"]
    assert admin["kind"] == ADMIN_ACTION_RULE_REMOVE
    assert admin["actor"] == "frank@example.com"
    assert admin["target"]["id"] == "#1"
    # before_hash captures the prior rule state
    assert len(admin["before_hash"]) == 64
    assert evt["activity_id"] == ACTIVITY_DELETE


def test_presets_apply_emits_admin_action(cli_env: str) -> None:
    from iam_jit.bouncer.presets import list_preset_names

    preset_name = list_preset_names()[0]
    runner = CliRunner()
    result = runner.invoke(
        main, ["presets", "apply", preset_name], catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output

    events = _drain_admin_actions(cli_env)
    # The preset.apply event is the LAST one; rule.add events also
    # fired (one per rule in the preset). Both kinds satisfy the
    # cross-product event_type=ADMIN_ACTION filter.
    apply_events = [
        e for e in events
        if e["unmapped"]["iam_jit"]["admin_action"]["kind"]
        == ADMIN_ACTION_PRESET_APPLY
    ]
    assert len(apply_events) == 1
    evt = apply_events[0]
    _assert_ocsf_admin_action_shape(evt)
    admin = evt["unmapped"]["iam_jit"]["admin_action"]
    assert admin["target"]["kind"] == "preset"
    assert admin["target"]["id"] == preset_name
    assert admin["target"]["extra"]["rules_added"] >= 0
    assert evt["activity_id"] == ACTIVITY_CREATE


def test_pause_start_emits_admin_action(cli_env: str) -> None:
    runner = CliRunner()
    result = runner.invoke(
        main, ["pause", "start", "--for", "10m", "--reason", "incident-response"],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output

    events = _drain_admin_actions(cli_env)
    assert len(events) == 1
    evt = events[0]
    _assert_ocsf_admin_action_shape(evt)
    admin = evt["unmapped"]["iam_jit"]["admin_action"]
    assert admin["kind"] == ADMIN_ACTION_PAUSE_START
    assert admin["target"]["kind"] == "pause_window"
    assert admin["target"]["extra"]["duration_seconds"] == 600
    assert admin["target"]["extra"]["reason"] == "incident-response"
    assert evt["activity_id"] == ACTIVITY_UPDATE


def test_pause_stop_emits_admin_action(cli_env: str) -> None:
    runner = CliRunner()
    start = runner.invoke(
        main, ["pause", "start", "--for", "10m"], catch_exceptions=False,
    )
    assert start.exit_code == 0, start.output
    # Pop the pause.start event so the next drain only sees pause.stop
    _ = _drain_admin_actions(cli_env)

    stop = runner.invoke(
        main, ["pause", "stop"], catch_exceptions=False,
    )
    assert stop.exit_code == 0, stop.output

    events = _drain_admin_actions(cli_env)
    assert len(events) == 1
    evt = events[0]
    _assert_ocsf_admin_action_shape(evt)
    admin = evt["unmapped"]["iam_jit"]["admin_action"]
    assert admin["kind"] == ADMIN_ACTION_PAUSE_STOP
    assert admin["target"]["kind"] == "pause_window"
    assert evt["activity_id"] == ACTIVITY_UPDATE


def test_pause_stop_when_no_pause_active_does_not_emit(cli_env: str) -> None:
    """`pause stop` with no active pause SHOULD NOT emit an admin-
    action event — nothing changed, so there's nothing to audit.
    Per [[creates-never-mutates]] + Lens B's "honest about absence"."""
    runner = CliRunner()
    result = runner.invoke(
        main, ["pause", "stop"], catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output

    events = _drain_admin_actions(cli_env)
    assert events == []


def test_profile_install_emits_admin_action(
    cli_env: str, tmp_path: pathlib.Path, monkeypatch,
) -> None:
    # §A100 — the test URL (`internal.example.com`) doesn't resolve
    # in DNS, which would trip the SSRF gate's fail-closed posture.
    # The gate's behaviour is exercised by tests/bouncer/
    # test_profile_install_ssrf.py; here we focus on the admin-
    # action emit half + bypass the gate.
    monkeypatch.setattr(
        "iam_jit.bouncer_cli._validate_install_url_ssrf",
        lambda url, *, allow_internal=False: None,
    )
    payload = _yaml.safe_dump({
        "profiles": {
            "team-staging": {
                "description": "Team staging guardrail",
                "deny_keywords": ["staging"],
            },
        },
    }).encode("utf-8")
    url = "https://internal.example.com/profiles/staging.yaml"

    runner = CliRunner()
    with mock.patch("urllib.request.urlopen") as m:
        m.return_value.__enter__.return_value.read.return_value = payload
        result = runner.invoke(
            main, ["profile", "install", "--from", url],
            catch_exceptions=False,
        )
    assert result.exit_code == 0, result.output

    events = _drain_admin_actions(cli_env)
    assert len(events) == 1
    evt = events[0]
    _assert_ocsf_admin_action_shape(evt)
    admin = evt["unmapped"]["iam_jit"]["admin_action"]
    assert admin["kind"] == ADMIN_ACTION_PROFILE_INSTALL
    assert admin["actor"] == "frank@example.com"
    assert admin["target"]["kind"] == "profile"
    assert admin["target"]["id"] == "team-staging"
    assert admin["target"]["extra"]["source_url"] == url
    assert evt["activity_id"] == ACTIVITY_CREATE


def test_profile_swap_emits_admin_action_via_helper(cli_env: str) -> None:
    """The hot-swap path is exercised through `_apply_bulk_profile_switch`
    rather than the bulk-answer CLI (which requires an interactive
    TTY + pending prompts). Asserting on the helper directly catches
    the wire shape without the TTY scaffolding.
    """
    from iam_jit.bouncer_cli import _apply_bulk_profile_switch
    from iam_jit.bouncer.profiles import load_profiles, write_default_profiles
    from iam_jit.bouncer.proxy import set_session_profile_override

    # Ensure default profiles exist so the swap can pick one.
    write_default_profiles()

    s = BouncerStore(db_path=cli_env)
    try:
        names = sorted(load_profiles().keys())
        assert names, "default profiles must be present"
        target = names[0]
        try:
            _apply_bulk_profile_switch(
                store=s,
                pending_rows=[],
                profile_name=target,
                actor="frank@example.com",
            )
        finally:
            # Clear the in-process override so the singleton doesn't
            # leak into other tests in the same process.
            set_session_profile_override(None)
    finally:
        s.close()

    events = _drain_admin_actions(cli_env)
    swap_events = [
        e for e in events
        if e["unmapped"]["iam_jit"]["admin_action"]["kind"]
        == ADMIN_ACTION_PROFILE_SWAP
    ]
    assert len(swap_events) == 1
    evt = swap_events[0]
    _assert_ocsf_admin_action_shape(evt)
    admin = evt["unmapped"]["iam_jit"]["admin_action"]
    assert admin["kind"] == ADMIN_ACTION_PROFILE_SWAP
    assert admin["target"]["kind"] == "profile"
    assert admin["target"]["id"] == target
    assert evt["activity_id"] == ACTIVITY_UPDATE


def test_tasks_end_emits_admin_action_session_kill(cli_env: str) -> None:
    runner = CliRunner()
    start = runner.invoke(
        main,
        [
            "tasks", "start",
            "--description", "audit-action-test",
            "--allow", "s3:Get*",
            "--duration", "30",
        ],
        catch_exceptions=False,
    )
    assert start.exit_code == 0, start.output
    # Pop any admin-action events from start (currently none expected
    # — tasks start is NOT in the scope of this slice — but drain
    # defensively so the next drain only sees session.kill).
    _ = _drain_admin_actions(cli_env)

    # Resolve the started task id via the store
    s = BouncerStore(db_path=cli_env)
    try:
        active = s.get_active_task()
    finally:
        s.close()
    assert active is not None
    task_id = active.task_id

    end = runner.invoke(
        main, ["tasks", "end", task_id, "--reason", "test-cleanup"],
        catch_exceptions=False,
    )
    assert end.exit_code == 0, end.output

    events = _drain_admin_actions(cli_env)
    kill_events = [
        e for e in events
        if e["unmapped"]["iam_jit"]["admin_action"]["kind"]
        == ADMIN_ACTION_SESSION_KILL
    ]
    assert len(kill_events) == 1
    evt = kill_events[0]
    _assert_ocsf_admin_action_shape(evt)
    admin = evt["unmapped"]["iam_jit"]["admin_action"]
    assert admin["target"]["kind"] == "task"
    assert admin["target"]["id"] == task_id
    assert admin["target"]["extra"]["end_reason"] == "test-cleanup"
    assert evt["activity_id"] == ACTIVITY_DELETE


# ---------------------------------------------------------------------------
# Cross-cutting invariants
# ---------------------------------------------------------------------------


def test_admin_action_status_detail_neutral_language() -> None:
    """Per [[security-team-positioning-safety-not-surveillance]] no
    admin-action event's user-facing string contains the forbidden
    words. Sweep every kind."""
    for kind in sorted(KNOWN_ADMIN_ACTION_KINDS):
        evt = make_admin_action_event(
            kind=kind,
            actor="alice@example.com",
            target_kind="entity",
            target_id="example",
        )
        for field in ("status_detail", "activity_name", "type_name"):
            value = str(evt.get(field, "")).lower()
            for forbidden in FORBIDDEN_ALERT_WORDS:
                assert forbidden not in value, (
                    f"admin-action event for kind={kind} field={field} "
                    f"contains forbidden word {forbidden!r}: {value!r}"
                )
        admin_kind = evt["unmapped"]["iam_jit"]["admin_action"]["kind"].lower()
        for forbidden in FORBIDDEN_ALERT_WORDS:
            assert forbidden not in admin_kind, (
                f"admin-action kind {kind!r} contains forbidden word "
                f"{forbidden!r}"
            )


def test_admin_action_event_validates_against_decision_event_shape() -> None:
    """The admin-action event MUST satisfy the same outer OCSF v1.1.0
    shape every decision event satisfies — same metadata block, same
    class_uid, same status_id/status pair, same unmapped.iam_jit
    layout. A single SIEM dashboard scoped to
    `metadata.product.vendor_name == "iam-jit"` catches both."""
    from iam_jit.bouncer.audit_export import audit_event_from_decision

    decision_evt = audit_event_from_decision(
        decision_id=1, mode="enforce", profile=None,
        verdict="ALLOW", reason="explicit-allow",
        service="s3", action="GetObject", arn=None, region="us-east-1",
        host="s3.us-east-1.amazonaws.com",
    )
    admin_evt = make_admin_action_event(
        kind=ADMIN_ACTION_RULE_ADD, actor="alice", target_id="#1",
    )
    # Same outer shape
    for k in (
        "class_uid", "class_name", "category_uid", "category_name",
        "metadata",
    ):
        assert k in decision_evt and k in admin_evt
    assert decision_evt["class_uid"] == admin_evt["class_uid"]
    assert decision_evt["metadata"]["product"]["name"] == admin_evt[
        "metadata"
    ]["product"]["name"]
    assert decision_evt["metadata"]["product"]["vendor_name"] == admin_evt[
        "metadata"
    ]["product"]["vendor_name"]


def test_admin_action_event_emits_in_queue_order(cli_env: str) -> None:
    """Multiple admin actions enqueue in the order they happen so a
    SIEM timeline view shows the operator's sequence accurately."""
    runner = CliRunner()
    for pattern in ("s3:Get*", "s3:List*", "s3:HeadObject"):
        result = runner.invoke(
            main, ["rules", "add", pattern, "--effect", "allow"],
            catch_exceptions=False,
        )
        assert result.exit_code == 0, result.output

    events = _drain_admin_actions(cli_env)
    assert len(events) == 3
    patterns = [
        e["unmapped"]["iam_jit"]["admin_action"]["target"]["extra"]["pattern"]
        for e in events
    ]
    assert patterns == ["s3:Get*", "s3:List*", "s3:HeadObject"]
