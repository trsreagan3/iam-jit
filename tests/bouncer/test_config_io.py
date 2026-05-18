"""Tests for #275 — `ibounce config export / import` (cross-product
Tier-1 hygiene).

Mirrors the kbounce config_test.go + dbounce config_test.go patterns:

  * round-trip: export -> import into empty store -> re-export matches
    the first bundle (modulo timestamps + hostname_hash)
  * cross-product reject: a kbounce / dbounce export must NOT import
    into ibounce — error message is "value <other> not in enum [ibounce]"
  * schema-version mismatch: refuse with the version-list message
  * --merge collision: existing values retained + a collision note logged
  * --replace: existing config blown away + new bundle in place
  * --dry-run: no mutation, accurate per-section counts printed
  * redaction grep: exported file does NOT contain webhook URLs / tokens /
    license content / env-var values
  * admin-action emission: import / export each enqueue exactly one
    ADMIN_ACTION row with the right kind
  * refuse-if-running: a mock-bound loopback socket triggers the
    stop-first refusal
  * backward compat: a pre-export-feature ibounce install still starts
    cleanly without an export file
  * doc surface lints: every operator-facing string is neutral
    (no "violation" / "infraction" / "unauthorized")

Per [[cross-product-agent-parity]]: every assertion mirrors the
sibling Go tests so a regression in any one product surfaces in the
shared review surface.
"""

from __future__ import annotations

import json
import pathlib
import socket
from contextlib import closing

import pytest
import yaml as _yaml
from click.testing import CliRunner

from iam_jit.bouncer.audit_export import (
    ADMIN_ACTION_CONFIG_EXPORT,
    ADMIN_ACTION_CONFIG_IMPORT,
    EVENT_TYPE_ADMIN_ACTION,
)
from iam_jit.bouncer.config_io import (
    PRODUCT,
    REDACTION_MARKER,
    SCHEMA_VERSION,
    ConfigBundleError,
    apply_import,
    build_export,
    is_ibounce_running,
    load_bundle,
    validate_bundle,
    write_export,
)
from iam_jit.bouncer.rules import Effect, ProxyRule
from iam_jit.bouncer.store import BouncerStore
from iam_jit.bouncer.tasks import build_task_scope
from iam_jit.bouncer_cli import main


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def env(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """Isolated environment: every config path lives under tmp_path
    so a test never touches the operator's real ~/.iam-jit dir."""
    db = tmp_path / "state.db"
    profiles = tmp_path / "profiles.yaml"
    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(db))
    monkeypatch.setenv("IAM_JIT_BOUNCER_PROFILES_PATH", str(profiles))
    monkeypatch.setenv("HOME", str(tmp_path / "home"))
    return {
        "db": str(db),
        "profiles": str(profiles),
        "tmp": str(tmp_path),
    }


@pytest.fixture
def store(env) -> BouncerStore:
    s = BouncerStore(db_path=env["db"])
    yield s
    s.close()


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def seeded_store(env, store) -> BouncerStore:
    """Store seeded with a couple of rules + a task + a preset event."""
    store.add_rule(
        ProxyRule(pattern="s3:GetObject", effect=Effect.ALLOW,
                  arn_scope="arn:aws:s3:::demo-bucket/*", note="dev read"),
        actor="alice",
    )
    store.add_rule(
        ProxyRule(pattern="iam:DeleteRole", effect=Effect.DENY,
                  note="prod guardrail"),
        actor="alice",
    )
    store.record_preset_applied(
        preset_name="admin-minus-sensitive", rules_added=2, actor="alice",
    )
    scope = build_task_scope(
        description="demo upgrade",
        allow_rules=[{"pattern": "eks:*"}],
        deny_rules=[{"pattern": "iam:*"}],
        duration_minutes=30,
        started_by="alice",
    )
    store.add_task(scope, actor="alice")
    return store


# ---------------------------------------------------------------------------
# build_export — projection + redaction
# ---------------------------------------------------------------------------


def test_build_export_shape_minimal(env, store) -> None:
    """Empty store still produces a well-formed bundle with every
    top-level field present."""
    bundle = build_export(db_path=env["db"], profiles_path=env["profiles"])
    assert bundle["schema_version"] == SCHEMA_VERSION
    assert bundle["product"] == PRODUCT
    assert bundle["ibounce_version"]
    assert bundle["exported_at"]
    assert bundle["source_hostname_hash"]
    assert "profiles" in bundle
    assert "rules" in bundle
    assert "tasks" in bundle
    assert "presets" in bundle
    assert "audit_webhook" in bundle
    assert "alert_rules" in bundle
    assert "mcp_install_history" in bundle
    assert "license" in bundle


def test_build_export_carries_seeded_rules(env, seeded_store) -> None:
    bundle = build_export(db_path=env["db"], profiles_path=env["profiles"])
    rule_patterns = {r["pattern"] for r in bundle["rules"]}
    assert "s3:GetObject" in rule_patterns
    assert "iam:DeleteRole" in rule_patterns


def test_build_export_carries_preset_history(env, seeded_store) -> None:
    bundle = build_export(db_path=env["db"], profiles_path=env["profiles"])
    preset_names = [p["preset_name"] for p in bundle["presets"]]
    assert "admin-minus-sensitive" in preset_names


def test_build_export_carries_task_scope_informationally(env, seeded_store) -> None:
    """Tasks ship in the bundle but are NEVER replayed on import. The
    section is informational only."""
    bundle = build_export(db_path=env["db"], profiles_path=env["profiles"])
    assert len(bundle["tasks"]) == 1
    assert bundle["tasks"][0]["description"] == "demo upgrade"


def test_build_export_redacts_webhook_url_and_token(env, store, monkeypatch) -> None:
    monkeypatch.setenv(
        "IAM_JIT_BOUNCER_AUDIT_WEBHOOK_URL",
        "https://splunk.internal.example.com/services/collector",
    )
    monkeypatch.setenv(
        "IAM_JIT_BOUNCER_AUDIT_WEBHOOK_TOKEN",
        "Splunk-very-real-token-12345-NOT-A-SECRET",
    )
    bundle = build_export(db_path=env["db"], profiles_path=env["profiles"])
    assert bundle["audit_webhook"]["webhook_url"] == REDACTION_MARKER
    assert bundle["audit_webhook"]["webhook_token"] == REDACTION_MARKER
    # The KEYS are recorded (informational) but the values are not.
    assert "IAM_JIT_BOUNCER_AUDIT_WEBHOOK_URL" in bundle["audit_webhook"]["env_keys_present"]


def test_build_export_redaction_grep_no_tokens_present(env, store, monkeypatch) -> None:
    """The exported FILE's bytes must not contain any sensitive value
    that the redactor was supposed to mask. This is the load-bearing
    invariant for [[push-policy-public-repo]] — operators check the
    bundle into a config repo."""
    monkeypatch.setenv(
        "IAM_JIT_BOUNCER_AUDIT_WEBHOOK_URL",
        "https://splunk.internal.example.com/services/collector",
    )
    monkeypatch.setenv(
        "IAM_JIT_BOUNCER_AUDIT_WEBHOOK_TOKEN",
        "Splunk-super-secret-do-not-leak",
    )
    bundle = build_export(db_path=env["db"], profiles_path=env["profiles"])
    out_path = pathlib.Path(env["tmp"]) / "bundle.json"
    write_export(bundle, out_path)
    body = out_path.read_text()
    assert "Splunk-super-secret-do-not-leak" not in body
    assert "splunk.internal.example.com" not in body


def test_build_export_alert_rules_inlined(env, store, tmp_path) -> None:
    alerts_yaml = tmp_path / "alerts.yaml"
    alerts_yaml.write_text(_yaml.safe_dump({
        "enabled_rules": ["admin_fallback_burst"],
        "admin_fallback_threshold": 7,
    }))
    bundle = build_export(
        db_path=env["db"], profiles_path=env["profiles"],
        alert_rules_path=str(alerts_yaml),
    )
    assert bundle["alert_rules"]["path"] == str(alerts_yaml)
    assert bundle["alert_rules"]["content"]["admin_fallback_threshold"] == 7


def test_build_export_mcp_install_history_when_entry_present(
    env, store, tmp_path, monkeypatch,
) -> None:
    """Drop a fake .claude.json with an ibounce mcpServers entry +
    confirm the export picks it up."""
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    (home / ".claude.json").write_text(json.dumps({
        "mcpServers": {"ibounce": {"command": "ibounce", "args": ["mcp", "serve"]}},
    }))
    bundle = build_export(db_path=env["db"], profiles_path=env["profiles"])
    clients = [e["client"] for e in bundle["mcp_install_history"]]
    assert "claude-code" in clients


# ---------------------------------------------------------------------------
# Round-trip — the load-bearing parity test
# ---------------------------------------------------------------------------


def test_round_trip_into_empty_store(env, seeded_store, tmp_path) -> None:
    """Export -> wipe -> import -> re-export should match the first
    bundle modulo per-export fields (timestamp, hostname_hash)."""
    bundle1 = build_export(db_path=env["db"], profiles_path=env["profiles"])
    out_path = tmp_path / "bundle.json"
    write_export(bundle1, out_path)

    # Wipe the store + profiles.
    seeded_store.close()
    pathlib.Path(env["db"]).unlink()
    if pathlib.Path(env["profiles"]).exists():
        pathlib.Path(env["profiles"]).unlink()

    # Import the bundle into the fresh store.
    summary = apply_import(
        load_bundle(out_path),
        mode="replace",
        db_path=env["db"],
        profiles_path=env["profiles"],
    )
    assert summary.rules_added > 0

    # Re-export and compare load-bearing sections.
    bundle2 = build_export(db_path=env["db"], profiles_path=env["profiles"])
    assert {r["pattern"] for r in bundle2["rules"]} == {
        r["pattern"] for r in bundle1["rules"]
    }
    # Profile sets match.
    assert {p["name"] for p in bundle2["profiles"]["items"]} == {
        p["name"] for p in bundle1["profiles"]["items"]
    }


# ---------------------------------------------------------------------------
# Cross-product reject
# ---------------------------------------------------------------------------


def test_cross_product_import_refused_kbounce(tmp_path) -> None:
    """A kbounce export must NOT load into ibounce."""
    bundle_path = tmp_path / "kbounce.json"
    bundle_path.write_text(json.dumps({
        "schema_version": SCHEMA_VERSION,
        "product": "kbounce",
        "ibounce_version": "1.0.0",
        "exported_at": "2026-05-18T00:00:00Z",
        "source_hostname_hash": "abcdef012345",
        "profiles": {"active": "", "items": []},
        "rules": [],
    }))
    with pytest.raises(ConfigBundleError) as exc:
        load_bundle(bundle_path)
    msg = str(exc.value)
    assert "'kbounce'" in msg or "kbounce" in msg
    assert "[" in msg and "'ibounce'" in msg or "ibounce" in msg


def test_cross_product_import_refused_dbounce(tmp_path) -> None:
    bundle_path = tmp_path / "dbounce.json"
    bundle_path.write_text(json.dumps({
        "schema_version": SCHEMA_VERSION,
        "product": "dbounce",
        "ibounce_version": "1.0.0",
        "exported_at": "2026-05-18T00:00:00Z",
        "source_hostname_hash": "abcdef012345",
        "profiles": {"active": "", "items": []},
        "rules": [],
    }))
    with pytest.raises(ConfigBundleError):
        load_bundle(bundle_path)


# ---------------------------------------------------------------------------
# Schema-version mismatch
# ---------------------------------------------------------------------------


def test_schema_version_mismatch_refused(tmp_path) -> None:
    bundle_path = tmp_path / "future.json"
    bundle_path.write_text(json.dumps({
        "schema_version": "99.0",
        "product": "ibounce",
        "ibounce_version": "1.0.0",
        "exported_at": "2026-05-18T00:00:00Z",
        "source_hostname_hash": "abcdef012345",
        "profiles": {"active": "", "items": []},
        "rules": [],
    }))
    with pytest.raises(ConfigBundleError) as exc:
        load_bundle(bundle_path)
    msg = str(exc.value)
    assert "schema_version" in msg
    assert "1.0" in msg  # supported version list


def test_validate_bundle_accepts_well_formed() -> None:
    validate_bundle({
        "schema_version": SCHEMA_VERSION,
        "product": PRODUCT,
        "ibounce_version": "1.0.0",
        "exported_at": "2026-05-18T00:00:00Z",
        "source_hostname_hash": "abcdef012345",
        "profiles": {"active": "", "items": []},
        "rules": [],
    })


# ---------------------------------------------------------------------------
# merge / replace / dry-run semantics
# ---------------------------------------------------------------------------


def test_merge_keeps_existing_on_collision(env, seeded_store, tmp_path) -> None:
    bundle = build_export(db_path=env["db"], profiles_path=env["profiles"])
    out_path = tmp_path / "bundle.json"
    write_export(bundle, out_path)

    # Re-import into the SAME store — every rule should collide.
    summary = apply_import(
        load_bundle(out_path),
        mode="merge",
        db_path=env["db"],
        profiles_path=env["profiles"],
    )
    assert summary.rules_added == 0
    assert summary.rules_collided > 0
    assert any("already present" in n for n in summary.collision_notes)


def test_replace_clears_existing_rules(env, seeded_store, tmp_path) -> None:
    """--replace removes pre-existing rules + loads only the bundle's."""
    # First export the seeded state, then add a NEW rule that's not in
    # the bundle. After --replace, only the bundled rules should remain.
    bundle = build_export(db_path=env["db"], profiles_path=env["profiles"])
    out_path = tmp_path / "bundle.json"
    write_export(bundle, out_path)
    seeded_store.add_rule(
        ProxyRule(pattern="ec2:DescribeInstances", effect=Effect.ALLOW),
        actor="alice",
    )
    seeded_store.close()

    summary = apply_import(
        load_bundle(out_path),
        mode="replace",
        db_path=env["db"],
        profiles_path=env["profiles"],
    )
    assert summary.rules_replaced > 0

    s = BouncerStore(db_path=env["db"])
    try:
        patterns = {r.pattern for _, r in s.list_rules()}
        # The extra rule was wiped.
        assert "ec2:DescribeInstances" not in patterns
        # The originally-bundled rules came back.
        assert "s3:GetObject" in patterns
    finally:
        s.close()


def test_dry_run_does_not_mutate(env, seeded_store, tmp_path) -> None:
    bundle = build_export(db_path=env["db"], profiles_path=env["profiles"])
    out_path = tmp_path / "bundle.json"
    write_export(bundle, out_path)

    # Reset store + run dry-run import.
    seeded_store.close()
    pathlib.Path(env["db"]).unlink()
    summary = apply_import(
        load_bundle(out_path),
        mode="dry-run",
        db_path=env["db"],
        profiles_path=env["profiles"],
    )
    assert summary.mode == "dry-run"
    assert summary.rules_added > 0  # counts what WOULD land
    # Confirm zero rules actually wrote.
    s = BouncerStore(db_path=env["db"])
    try:
        assert s.list_rules() == []
    finally:
        s.close()


# ---------------------------------------------------------------------------
# Admin-action emission
# ---------------------------------------------------------------------------


def test_export_emits_admin_action_row(env, store, tmp_path) -> None:
    from iam_jit.bouncer.config_io import emit_export_admin_action

    out_path = tmp_path / "bundle.json"
    out_path.write_text("{}")  # contents irrelevant for the emit test
    emit_export_admin_action(store, out_path=out_path, actor="alice")
    rows = store.drain_pending_audit_events(limit=10)
    assert len(rows) == 1
    assert rows[0]["event_type"] == EVENT_TYPE_ADMIN_ACTION
    payload = json.loads(rows[0]["payload_json"])
    assert payload["kind"] == ADMIN_ACTION_CONFIG_EXPORT
    assert payload["actor"] == "alice"
    assert payload["target_kind"] == "config-bundle"


def test_import_emits_admin_action_row(env, store, tmp_path) -> None:
    from iam_jit.bouncer.config_io import ImportSummary, emit_import_admin_action

    summary = ImportSummary(mode="merge", rules_added=3, profiles_added=1)
    emit_import_admin_action(
        store, in_path=tmp_path / "bundle.json", summary=summary, actor="alice",
    )
    rows = store.drain_pending_audit_events(limit=10)
    assert len(rows) == 1
    payload = json.loads(rows[0]["payload_json"])
    assert payload["kind"] == ADMIN_ACTION_CONFIG_IMPORT
    assert payload["extra"]["mode"] == "merge"
    assert payload["extra"]["rules_added"] == 3
    assert payload["extra"]["result"] == "applied"


def test_import_dry_run_emits_admin_action_with_noop_result(env, store, tmp_path) -> None:
    from iam_jit.bouncer.config_io import ImportSummary, emit_import_admin_action

    summary = ImportSummary(mode="dry-run", rules_added=3)
    emit_import_admin_action(
        store, in_path=tmp_path / "bundle.json", summary=summary, actor="alice",
    )
    rows = store.drain_pending_audit_events(limit=10)
    payload = json.loads(rows[0]["payload_json"])
    assert payload["extra"]["result"] == "noop"


# ---------------------------------------------------------------------------
# Refuse-if-running probe
# ---------------------------------------------------------------------------


def test_is_ibounce_running_false_when_no_listener() -> None:
    """No listener on the probe port = import allowed."""
    # Pick an unused high port (range chosen to avoid the default).
    assert is_ibounce_running(host="127.0.0.1", port=59999) is False


def test_is_ibounce_running_true_when_loopback_bound() -> None:
    """A bound TCP listener on the probe port = import refused."""
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sk:
        sk.bind(("127.0.0.1", 0))
        sk.listen(1)
        bound_port = sk.getsockname()[1]
        assert is_ibounce_running(host="127.0.0.1", port=bound_port) is True


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


def test_cli_export_then_import_round_trip(env, seeded_store, tmp_path, runner) -> None:
    out_path = tmp_path / "bundle.json"
    result = runner.invoke(main, [
        "config", "export",
        "--out", str(out_path),
        "--db", env["db"],
        "--profiles", env["profiles"],
    ])
    assert result.exit_code == 0, result.output
    assert out_path.exists()
    body = json.loads(out_path.read_text())
    assert body["product"] == "ibounce"

    # Drop the store + import.
    seeded_store.close()
    pathlib.Path(env["db"]).unlink()
    pathlib.Path(env["profiles"]).unlink(missing_ok=True)

    result = runner.invoke(main, [
        "config", "import",
        "--in", str(out_path),
        "--replace",
        "--db", env["db"],
        "--profiles", env["profiles"],
    ])
    assert result.exit_code == 0, result.output
    assert "import mode: replace" in result.output


def test_cli_import_refuses_no_redact_secrets_flag(env, runner, tmp_path) -> None:
    out_path = tmp_path / "bundle.json"
    result = runner.invoke(main, [
        "config", "export",
        "--out", str(out_path),
        "--no-redact-secrets",
        "--db", env["db"],
        "--profiles", env["profiles"],
    ])
    assert result.exit_code == 2
    assert "does not support unredacted bundles" in result.output


def test_cli_import_refuses_dual_mode_flags(env, runner, tmp_path) -> None:
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps({
        "schema_version": SCHEMA_VERSION,
        "product": "ibounce",
        "ibounce_version": "1.0.0",
        "exported_at": "2026-05-18T00:00:00Z",
        "source_hostname_hash": "abcdef012345",
        "profiles": {"active": "", "items": []},
        "rules": [],
    }))
    result = runner.invoke(main, [
        "config", "import",
        "--in", str(bundle_path),
        "--merge", "--replace",
        "--db", env["db"],
    ])
    assert result.exit_code == 2
    assert "mutually exclusive" in result.output


def test_cli_import_refuses_when_running(env, runner, tmp_path) -> None:
    bundle_path = tmp_path / "bundle.json"
    bundle_path.write_text(json.dumps({
        "schema_version": SCHEMA_VERSION,
        "product": "ibounce",
        "ibounce_version": "1.0.0",
        "exported_at": "2026-05-18T00:00:00Z",
        "source_hostname_hash": "abcdef012345",
        "profiles": {"active": "", "items": []},
        "rules": [],
    }))
    # Bind a socket on a port + point the probe at it.
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sk:
        sk.bind(("127.0.0.1", 0))
        sk.listen(1)
        bound_port = sk.getsockname()[1]
        result = runner.invoke(
            main,
            [
                "config", "import",
                "--in", str(bundle_path),
                "--db", env["db"],
            ],
            env={"IBOUNCE_PROBE_PORT": str(bound_port)},
        )
    assert result.exit_code == 2
    assert "ibounce appears to be running" in result.output


def test_cli_import_dry_run_emits_no_mutation(env, seeded_store, tmp_path, runner) -> None:
    """--dry-run preserves the existing config state — no rules added /
    removed; counts still printed."""
    out_path = tmp_path / "bundle.json"
    result = runner.invoke(main, [
        "config", "export",
        "--out", str(out_path),
        "--db", env["db"],
        "--profiles", env["profiles"],
    ])
    assert result.exit_code == 0, result.output

    # Drop store, run dry-run, confirm DB still empty.
    seeded_store.close()
    pathlib.Path(env["db"]).unlink()

    result = runner.invoke(main, [
        "config", "import",
        "--in", str(out_path),
        "--dry-run",
        "--db", env["db"],
        "--profiles", env["profiles"],
    ])
    assert result.exit_code == 0, result.output
    assert "import mode: dry-run" in result.output
    s = BouncerStore(db_path=env["db"])
    try:
        assert s.list_rules() == []
    finally:
        s.close()


# ---------------------------------------------------------------------------
# Doc-surface linting: every operator-facing string is neutral.
# ---------------------------------------------------------------------------

_FORBIDDEN_OPERATOR_WORDS = ("violation", "infraction", "unauthorized")


def test_user_facing_strings_are_neutral(env, runner, tmp_path) -> None:
    """Sweep the CLI's actual stdout/stderr output for forbidden words.

    We exercise both the export + import surfaces (success + failure
    paths) and grep the captured output. Per
    [[security-team-positioning-safety-not-surveillance]]: every
    operator-facing string is neutral; a config-bundle import is a
    config artefact, not an accusation.
    """
    captured: list[str] = []

    # Happy path: export.
    out_path = tmp_path / "bundle.json"
    r1 = runner.invoke(main, [
        "config", "export", "--out", str(out_path),
        "--db", env["db"], "--profiles", env["profiles"],
    ])
    captured.append(r1.output)

    # Refusal path: --no-redact-secrets.
    r2 = runner.invoke(main, [
        "config", "export", "--out", str(out_path),
        "--no-redact-secrets",
        "--db", env["db"], "--profiles", env["profiles"],
    ])
    captured.append(r2.output)

    # Refusal path: dual mode flags.
    bundle_path = tmp_path / "bundle.json"
    if not bundle_path.exists():
        bundle_path.write_text(json.dumps({
            "schema_version": SCHEMA_VERSION,
            "product": "ibounce",
            "ibounce_version": "1.0.0",
            "exported_at": "2026-05-18T00:00:00Z",
            "source_hostname_hash": "abcdef012345",
            "profiles": {"active": "", "items": []},
            "rules": [],
        }))
    r3 = runner.invoke(main, [
        "config", "import", "--in", str(bundle_path),
        "--merge", "--replace", "--db", env["db"],
    ])
    captured.append(r3.output)

    # Refusal path: cross-product bundle.
    foreign = tmp_path / "kbounce.json"
    foreign.write_text(json.dumps({
        "schema_version": SCHEMA_VERSION,
        "product": "kbounce",
        "ibounce_version": "1.0.0",
        "exported_at": "2026-05-18T00:00:00Z",
        "source_hostname_hash": "abcdef012345",
        "profiles": {"active": "", "items": []},
        "rules": [],
    }))
    r4 = runner.invoke(main, [
        "config", "import", "--in", str(foreign),
        "--db", env["db"],
    ])
    captured.append(r4.output)

    joined = "\n".join(captured).lower()
    for forbidden in _FORBIDDEN_OPERATOR_WORDS:
        assert forbidden not in joined, (
            f"forbidden operator-facing word {forbidden!r} appeared in "
            "config CLI output; rephrase per "
            "[[security-team-positioning-safety-not-surveillance]]"
        )


# ---------------------------------------------------------------------------
# Backward compatibility — pre-export-feature install still starts
# ---------------------------------------------------------------------------


def test_pre_export_install_starts_without_bundle(env, runner) -> None:
    """A bouncer install that NEVER ran `config export` must still
    operate. Inspect via `init`: no bundle = no error, no warning, no
    behavior change."""
    result = runner.invoke(main, ["init", "--db", env["db"]])
    assert result.exit_code == 0
    assert "bouncer initialized" in result.output
