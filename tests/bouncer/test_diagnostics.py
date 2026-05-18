"""Tests for #277 — `ibounce diagnostics bundle` (cross-product
Tier-1 hygiene).

Mirrors the kbounce + dbounce sibling test suites so a regression in
the shared cross-product contract surfaces in three places:

  * Bundle command exits 0 + writes a valid ZIP on disk
  * Bundle contains every expected section
  * Manifest sha256s match the on-disk entry bytes
  * Sentinel-string sweep: a seeded token + webhook URL + env-value
    + user identifier all appear NOWHERE in the bundle
  * User identifiers stably-hashed (cross-event correlation
    preserved; raw ID never present)
  * /healthz unreachable → bundle exits 0; section reports
    "unreachable"
  * 0-byte audit log + 0-byte panic log handled gracefully
  * --out PATH honored; default path matches
    ./ibounce-diagnostics-{timestamp}.zip
  * --no-audit excludes the audit-tail section
  * Admin-action OCSF event emitted on bundle creation
  * `diag` alias resolves to the same command

Per [[cross-product-agent-parity]]: every assertion mirrors the
sibling kbounce + dbounce tests so the cross-product contract is
enforced uniformly.
Per [[security-team-positioning-safety-not-surveillance]]: a doc-
surface lint sweep confirms every operator-facing string is neutral.
"""

from __future__ import annotations

import json
import pathlib
import re
import socket
import threading
import zipfile
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from click.testing import CliRunner

from iam_jit.bouncer.audit_export import (
    ADMIN_ACTION_DIAGNOSTICS_BUNDLE,
    EVENT_TYPE_ADMIN_ACTION,
)
from iam_jit.bouncer.diagnostics import (
    DIAGNOSTICS_BUNDLE_FORMAT,
    DIAGNOSTICS_BUNDLE_VERSION,
    BundleOptions,
    default_bundle_path,
    hash_user_id,
    write_diagnostics_bundle,
)
from iam_jit.bouncer.store import BouncerStore
from iam_jit.bouncer_cli import main


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def env(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, str]:
    """Isolated environment: every config path lives under tmp_path
    so a test never touches the operator's real ~/.iam-jit dir.
    Also sets HOME so home-path scrubbing has a known target."""
    db = tmp_path / "state.db"
    profiles = tmp_path / "profiles.yaml"
    audit_log = tmp_path / "audit.jsonl"
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(db))
    monkeypatch.setenv("IAM_JIT_BOUNCER_PROFILES_PATH", str(profiles))
    monkeypatch.setenv("HOME", str(home))
    return {
        "db": str(db),
        "profiles": str(profiles),
        "audit_log": str(audit_log),
        "tmp": str(tmp_path),
        "home": str(home),
    }


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def _read_bundle(path: pathlib.Path) -> dict[str, bytes]:
    """Open a ZIP at `path` and return a {name: body} map."""
    out: dict[str, bytes] = {}
    with zipfile.ZipFile(path) as z:
        for name in z.namelist():
            out[name] = z.read(name)
    return out


def _unreachable_healthz() -> str:
    """A URL on a likely-closed loopback port. Used to exercise the
    'graceful degradation' path."""
    return "http://127.0.0.1:1/healthz"


# ---------------------------------------------------------------------------
# Bundle worker — direct (no CLI)
# ---------------------------------------------------------------------------


def test_bundle_writes_valid_zip(env, tmp_path) -> None:
    out_path = tmp_path / "bundle.zip"
    summary = write_diagnostics_bundle(BundleOptions(
        out_path=out_path,
        healthz_url=_unreachable_healthz(),
        audit_log_path=env["audit_log"],
    ))
    assert out_path.exists()
    assert out_path.stat().st_size > 0
    assert summary.file_count == 10
    assert summary.total_bytes > 0


def test_bundle_contains_required_sections(env, tmp_path) -> None:
    out_path = tmp_path / "bundle.zip"
    write_diagnostics_bundle(BundleOptions(
        out_path=out_path,
        healthz_url=_unreachable_healthz(),
        audit_log_path=env["audit_log"],
    ))
    entries = _read_bundle(out_path)
    for want in [
        "00-README.txt",
        "01-version.txt",
        "02-config-redacted.json",
        "03-active-profile.json",
        "04-audit-tail.jsonl",
        "05-healthz.json",
        "06-system.txt",
        "07-listener.json",
        "08-panics.txt",
        "09-manifest.json",
    ]:
        assert want in entries, f"missing section: {want}"


def test_manifest_sha256s_match_entries(env, tmp_path) -> None:
    out_path = tmp_path / "bundle.zip"
    write_diagnostics_bundle(BundleOptions(
        out_path=out_path,
        healthz_url=_unreachable_healthz(),
        audit_log_path=env["audit_log"],
    ))
    entries = _read_bundle(out_path)
    manifest = json.loads(entries["09-manifest.json"].decode("utf-8"))
    assert manifest["bundle_version"] == DIAGNOSTICS_BUNDLE_VERSION
    assert manifest["format"] == DIAGNOSTICS_BUNDLE_FORMAT
    assert manifest["product"] == "ibounce"
    listed = {e["name"]: e for e in manifest["entries"]}
    import hashlib
    for name, body in entries.items():
        if name == "09-manifest.json":
            # The manifest is the only entry NOT listed in itself.
            assert name not in listed
            continue
        e = listed[name]
        assert e["size"] == len(body), f"size mismatch for {name}"
        assert e["sha256"] == hashlib.sha256(body).hexdigest(), (
            f"sha256 mismatch for {name}"
        )


# ---------------------------------------------------------------------------
# Sentinel sweep — no token / no URL / no env value / no user id
# anywhere in the bundle bytes.
# ---------------------------------------------------------------------------


SENTINEL_TOKEN = "sentinel-token-XYZ"
SENTINEL_WEBHOOK = "http://webhook.example.com/secret"
SENTINEL_ENV_VALUE = "IAM_JIT_SECRET_VALUE"
SENTINEL_USER_ID = "alice@operator.example.com"


def test_bundle_redacts_sentinel_strings_everywhere(
    env, tmp_path, monkeypatch,
) -> None:
    """Seed a known token + webhook URL + env-var value + user id
    into the running config, then assert NONE of them appear in any
    bundle file. This is the load-bearing invariant for [[push-
    policy-public-repo]] — operators share the ZIP with support /
    Claude agents.
    """
    # Plant the sentinels everywhere a redactor must catch them.
    monkeypatch.setenv(
        "IAM_JIT_BOUNCER_AUDIT_WEBHOOK_URL", SENTINEL_WEBHOOK,
    )
    monkeypatch.setenv(
        "IAM_JIT_BOUNCER_AUDIT_WEBHOOK_TOKEN", SENTINEL_TOKEN,
    )
    # The sentinel env-value is set on a fake env-var name — the
    # bundle's env-section policy is KEYS only, so the VALUE must
    # never appear.
    monkeypatch.setenv("IAM_JIT_SENTINEL_VAR", SENTINEL_ENV_VALUE)

    # Seed an audit-log line carrying the user id + token + webhook.
    audit_log = pathlib.Path(env["audit_log"])
    line = json.dumps({
        "actor": {"user": {"name": SENTINEL_USER_ID, "uid": SENTINEL_USER_ID}},
        "api": {"request": {"uid": "abc"}},
        "unmapped": {
            "iam_jit": {
                "audit_export": {
                    "webhook_url": SENTINEL_WEBHOOK,
                    "webhook_token": SENTINEL_TOKEN,
                },
            },
        },
    })
    audit_log.write_text(line + "\n")

    # Seed a panic-log carrying a Bearer token + URL.
    panic_log = tmp_path / "panic.log"
    panic_log.write_text(
        f"panic: bearer {SENTINEL_TOKEN} called {SENTINEL_WEBHOOK}\n"
    )

    out_path = tmp_path / "bundle.zip"
    write_diagnostics_bundle(BundleOptions(
        out_path=out_path,
        healthz_url=_unreachable_healthz(),
        audit_log_path=env["audit_log"],
        panic_log_path=str(panic_log),
        include_audit_tail=10,
    ))

    entries = _read_bundle(out_path)
    for name, body in entries.items():
        s = body.decode("utf-8", errors="replace")
        assert SENTINEL_TOKEN not in s, (
            f"token leaked into {name}"
        )
        assert SENTINEL_WEBHOOK not in s, (
            f"webhook URL leaked into {name}"
        )
        assert SENTINEL_ENV_VALUE not in s, (
            f"env-var value leaked into {name}"
        )
        assert SENTINEL_USER_ID not in s, (
            f"user identifier leaked into {name}"
        )


def test_bundle_env_section_lists_keys_not_values(
    env, tmp_path, monkeypatch,
) -> None:
    monkeypatch.setenv("IAM_JIT_BOUNCER_NEUTRAL_KEY", "value-must-not-appear")
    out_path = tmp_path / "bundle.zip"
    write_diagnostics_bundle(BundleOptions(
        out_path=out_path,
        healthz_url=_unreachable_healthz(),
        audit_log_path=env["audit_log"],
    ))
    entries = _read_bundle(out_path)
    sys_section = entries["06-system.txt"].decode("utf-8")
    # KEY must appear.
    assert "IAM_JIT_BOUNCER_NEUTRAL_KEY" in sys_section
    # VALUE must NOT appear (in any section).
    for name, body in entries.items():
        s = body.decode("utf-8", errors="replace")
        assert "value-must-not-appear" not in s, (
            f"env value leaked into {name}"
        )


def test_bundle_hostname_replaced_with_hash(env, tmp_path) -> None:
    """The literal hostname must not appear; the stable hash does."""
    out_path = tmp_path / "bundle.zip"
    write_diagnostics_bundle(BundleOptions(
        out_path=out_path,
        healthz_url=_unreachable_healthz(),
        audit_log_path=env["audit_log"],
    ))
    entries = _read_bundle(out_path)
    sys_section = entries["06-system.txt"].decode("utf-8")
    h = socket.gethostname()
    if h:
        # The hash must be present.
        assert "hostname_hash: sha256:" in sys_section
        # The literal hostname must NOT appear in the system section.
        assert h not in sys_section


# ---------------------------------------------------------------------------
# User-id hashing — stable across events
# ---------------------------------------------------------------------------


def test_user_ids_hashed_stably_across_events(env, tmp_path) -> None:
    id_a = "alice@example.org"
    id_b = "bob@example.org"
    audit_log = pathlib.Path(env["audit_log"])
    audit_log.write_text(
        json.dumps({"actor": {"user": {"name": id_a}}, "seq": 1}) + "\n"
        + json.dumps({"actor": {"user": {"name": id_a}}, "seq": 2}) + "\n"
        + json.dumps({"actor": {"user": {"name": id_b}}, "seq": 3}) + "\n"
    )
    out_path = tmp_path / "bundle.zip"
    write_diagnostics_bundle(BundleOptions(
        out_path=out_path,
        healthz_url=_unreachable_healthz(),
        audit_log_path=env["audit_log"],
        include_audit_tail=10,
    ))
    tail = _read_bundle(out_path)["04-audit-tail.jsonl"].decode("utf-8")
    expect_a = hash_user_id(id_a)
    expect_b = hash_user_id(id_b)
    assert tail.count(expect_a) == 2, (
        "alice's stable hash must appear twice (cross-event correlation)"
    )
    assert tail.count(expect_b) == 1
    assert id_a not in tail
    assert id_b not in tail
    assert expect_a.startswith("sha256:")
    # 12 hex chars per the dbounce convention.
    assert re.fullmatch(r"sha256:[0-9a-f]{12}", expect_a), expect_a


def test_hash_user_id_helper_is_deterministic() -> None:
    """Same input → same output; different inputs → different outputs."""
    a1 = hash_user_id("alice")
    a2 = hash_user_id("alice")
    b = hash_user_id("bob")
    assert a1 == a2
    assert a1 != b
    assert a1.startswith("sha256:")
    assert len(a1) == len("sha256:") + 12


# ---------------------------------------------------------------------------
# /healthz unreachable — graceful degradation
# ---------------------------------------------------------------------------


def test_bundle_handles_unreachable_healthz_gracefully(env, tmp_path) -> None:
    out_path = tmp_path / "bundle.zip"
    summary = write_diagnostics_bundle(BundleOptions(
        out_path=out_path,
        healthz_url=_unreachable_healthz(),
        audit_log_path=env["audit_log"],
    ))
    assert out_path.exists(), "bundle must still land when /healthz is dead"
    assert summary.healthz_ok is False
    body = _read_bundle(out_path)["05-healthz.json"].decode("utf-8")
    assert "unreachable" in body


class _HealthzHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/healthz":
            payload = json.dumps({
                "status": "ok",
                "audit_export": {"degraded": False, "webhook_url_masked": "***"},
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):  # noqa: ARG002 - silence stderr
        pass


def test_bundle_records_healthz_response_when_reachable(env, tmp_path) -> None:
    """A real local listener returning JSON gets embedded under
    `body` with status_code 200."""
    server = HTTPServer(("127.0.0.1", 0), _HealthzHandler)
    port = server.server_address[1]
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        out_path = tmp_path / "bundle.zip"
        summary = write_diagnostics_bundle(BundleOptions(
            out_path=out_path,
            healthz_url=f"http://127.0.0.1:{port}/healthz",
            audit_log_path=env["audit_log"],
        ))
        assert summary.healthz_ok is True
        body = json.loads(
            _read_bundle(out_path)["05-healthz.json"].decode("utf-8")
        )
        assert body["http_status"] == 200
        assert body["body"]["status"] == "ok"
    finally:
        server.shutdown()
        t.join(timeout=2)


# ---------------------------------------------------------------------------
# Empty / missing files — handled gracefully
# ---------------------------------------------------------------------------


def test_bundle_handles_zero_byte_audit_log(env, tmp_path) -> None:
    pathlib.Path(env["audit_log"]).write_bytes(b"")
    out_path = tmp_path / "bundle.zip"
    summary = write_diagnostics_bundle(BundleOptions(
        out_path=out_path,
        healthz_url=_unreachable_healthz(),
        audit_log_path=env["audit_log"],
    ))
    assert summary.audit_lines == 0
    body = _read_bundle(out_path)["04-audit-tail.jsonl"].decode("utf-8")
    assert "empty" in body


def test_bundle_handles_zero_byte_panic_log(env, tmp_path) -> None:
    panic = tmp_path / "panic.log"
    panic.write_bytes(b"")
    out_path = tmp_path / "bundle.zip"
    write_diagnostics_bundle(BundleOptions(
        out_path=out_path,
        healthz_url=_unreachable_healthz(),
        audit_log_path=env["audit_log"],
        panic_log_path=str(panic),
    ))
    body = _read_bundle(out_path)["08-panics.txt"].decode("utf-8")
    assert "empty" in body


def test_bundle_handles_missing_audit_log_path(env, tmp_path) -> None:
    """No audit log + no env var → section emits a placeholder, not
    a crash."""
    out_path = tmp_path / "bundle.zip"
    summary = write_diagnostics_bundle(BundleOptions(
        out_path=out_path,
        healthz_url=_unreachable_healthz(),
        audit_log_path=None,
    ))
    assert summary.audit_lines == 0
    body = _read_bundle(out_path)["04-audit-tail.jsonl"].decode("utf-8")
    assert "no audit log path configured" in body


def test_bundle_handles_nonexistent_panic_log(env, tmp_path) -> None:
    out_path = tmp_path / "bundle.zip"
    write_diagnostics_bundle(BundleOptions(
        out_path=out_path,
        healthz_url=_unreachable_healthz(),
        audit_log_path=env["audit_log"],
        panic_log_path=str(tmp_path / "does-not-exist.log"),
    ))
    body = _read_bundle(out_path)["08-panics.txt"].decode("utf-8")
    assert "not found" in body


# ---------------------------------------------------------------------------
# --no-audit
# ---------------------------------------------------------------------------


def test_no_audit_suppresses_tail(env, tmp_path) -> None:
    telltale = "this-line-must-not-appear-when-no-audit-is-set"
    pathlib.Path(env["audit_log"]).write_text(
        json.dumps({"event": telltale}) + "\n"
    )
    out_path = tmp_path / "bundle.zip"
    write_diagnostics_bundle(BundleOptions(
        out_path=out_path,
        healthz_url=_unreachable_healthz(),
        audit_log_path=env["audit_log"],
        no_audit=True,
    ))
    body = _read_bundle(out_path)["04-audit-tail.jsonl"].decode("utf-8")
    assert telltale not in body
    assert "intentionally omitted" in body


# ---------------------------------------------------------------------------
# Default output path
# ---------------------------------------------------------------------------


def test_default_bundle_path_shape() -> None:
    """./ibounce-diagnostics-{UTC-timestamp}.zip per the brief."""
    p = default_bundle_path()
    assert p.suffix == ".zip"
    assert p.name.startswith("ibounce-diagnostics-")
    # Pattern: 20260518T120000Z
    ts = p.stem[len("ibounce-diagnostics-"):]
    assert re.fullmatch(r"\d{8}T\d{6}Z", ts), ts


# ---------------------------------------------------------------------------
# Admin-action emission
# ---------------------------------------------------------------------------


def test_bundle_command_emits_admin_action(env, runner, tmp_path) -> None:
    out_path = tmp_path / "bundle.zip"
    result = runner.invoke(main, [
        "diagnostics", "bundle",
        "--out", str(out_path),
        "--healthz-url", _unreachable_healthz(),
        "--db", env["db"],
        "--audit-log", env["audit_log"],
    ])
    assert result.exit_code == 0, result.output
    # Read the queued admin-action row from the store.
    s = BouncerStore(db_path=env["db"])
    try:
        rows = s.drain_pending_audit_events(limit=10)
    finally:
        s.close()
    kinds = []
    for r in rows:
        if r["event_type"] == EVENT_TYPE_ADMIN_ACTION:
            payload = json.loads(r["payload_json"])
            kinds.append(payload["kind"])
    assert ADMIN_ACTION_DIAGNOSTICS_BUNDLE in kinds


def test_bundle_admin_action_extra_carries_summary_counts(
    env, runner, tmp_path,
) -> None:
    out_path = tmp_path / "bundle.zip"
    result = runner.invoke(main, [
        "diagnostics", "bundle",
        "--out", str(out_path),
        "--healthz-url", _unreachable_healthz(),
        "--db", env["db"],
        "--audit-log", env["audit_log"],
        "--no-audit",
    ])
    assert result.exit_code == 0, result.output
    s = BouncerStore(db_path=env["db"])
    try:
        rows = s.drain_pending_audit_events(limit=10)
    finally:
        s.close()
    payloads = [
        json.loads(r["payload_json"])
        for r in rows if r["event_type"] == EVENT_TYPE_ADMIN_ACTION
    ]
    diag_payloads = [
        p for p in payloads
        if p["kind"] == ADMIN_ACTION_DIAGNOSTICS_BUNDLE
    ]
    assert len(diag_payloads) == 1
    extra = diag_payloads[0]["extra"]
    assert extra["no_audit"] is True
    assert extra["file_count"] == 10
    assert extra["out_path"] == str(out_path)


# ---------------------------------------------------------------------------
# CLI surface
# ---------------------------------------------------------------------------


def test_cli_bundle_writes_zip(env, runner, tmp_path) -> None:
    out_path = tmp_path / "bundle.zip"
    result = runner.invoke(main, [
        "diagnostics", "bundle",
        "--out", str(out_path),
        "--healthz-url", _unreachable_healthz(),
        "--db", env["db"],
        "--audit-log", env["audit_log"],
    ])
    assert result.exit_code == 0, result.output
    assert out_path.exists()
    assert f"wrote {out_path}" in result.output


def test_cli_diag_alias_resolves(env, runner, tmp_path) -> None:
    """`ibounce diag bundle` is the spec'd alias of
    `ibounce diagnostics bundle`."""
    out_path = tmp_path / "bundle.zip"
    result = runner.invoke(main, [
        "diag", "bundle",
        "--out", str(out_path),
        "--healthz-url", _unreachable_healthz(),
        "--db", env["db"],
        "--audit-log", env["audit_log"],
    ])
    assert result.exit_code == 0, result.output
    assert out_path.exists()


def test_cli_respects_out_path_with_nonexistent_parent(
    env, runner, tmp_path,
) -> None:
    """The brief says `--out PATH` must honor its exact target; if
    the parent dir doesn't exist, the bundler creates it."""
    out_path = tmp_path / "subdir" / "named.zip"
    result = runner.invoke(main, [
        "diagnostics", "bundle",
        "--out", str(out_path),
        "--healthz-url", _unreachable_healthz(),
        "--db", env["db"],
        "--audit-log", env["audit_log"],
    ])
    assert result.exit_code == 0, result.output
    assert out_path.exists()


def test_cli_rejects_negative_audit_tail(env, runner, tmp_path) -> None:
    out_path = tmp_path / "bundle.zip"
    result = runner.invoke(main, [
        "diagnostics", "bundle",
        "--out", str(out_path),
        "--include-audit-tail", "-1",
        "--db", env["db"],
    ])
    assert result.exit_code == 2
    assert ">= 0" in result.output


def test_cli_default_out_path_in_cwd(env, runner, tmp_path, monkeypatch) -> None:
    """No --out → default lands in CWD with ibounce-diagnostics-*.zip
    naming. We chdir to a hermetic tempdir to avoid polluting the
    repo + surprising other tests."""
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(main, [
        "diagnostics", "bundle",
        "--healthz-url", _unreachable_healthz(),
        "--db", env["db"],
        "--audit-log", env["audit_log"],
    ])
    assert result.exit_code == 0, result.output
    matches = list(tmp_path.glob("ibounce-diagnostics-*.zip"))
    assert matches, "default --out must write ibounce-diagnostics-*.zip in CWD"


# ---------------------------------------------------------------------------
# Doc-surface linting — neutral language per
# [[security-team-positioning-safety-not-surveillance]]
# ---------------------------------------------------------------------------


_FORBIDDEN_WORDS = ("violation", "infraction", "unauthorized")


def test_bundle_strings_are_neutral(env, tmp_path) -> None:
    """No operator-facing string in any bundle section uses the
    accusatory words the security-team-positioning memo forbids."""
    out_path = tmp_path / "bundle.zip"
    write_diagnostics_bundle(BundleOptions(
        out_path=out_path,
        healthz_url=_unreachable_healthz(),
        audit_log_path=env["audit_log"],
    ))
    entries = _read_bundle(out_path)
    for name, body in entries.items():
        s = body.decode("utf-8", errors="replace").lower()
        for word in _FORBIDDEN_WORDS:
            assert word not in s, (
                f"bundle entry {name!r} contains forbidden word {word!r}"
            )


def test_cli_help_text_is_neutral(runner) -> None:
    for cmd in (
        ["diagnostics", "--help"],
        ["diagnostics", "bundle", "--help"],
        ["diag", "--help"],
        ["diag", "bundle", "--help"],
    ):
        result = runner.invoke(main, cmd)
        assert result.exit_code == 0, result.output
        lower = result.output.lower()
        for word in _FORBIDDEN_WORDS:
            assert word not in lower, (
                f"`{' '.join(cmd)}` help text contains forbidden word {word!r}"
            )


# ---------------------------------------------------------------------------
# Deterministic ZIP — identical inputs produce identical zip-entry
# metadata (mod-time)
# ---------------------------------------------------------------------------


def test_zip_entries_use_bouncer_suite_epoch(env, tmp_path) -> None:
    """The bounce-suite epoch (2026-05-17) is the deterministic
    mod-time on every entry."""
    out_path = tmp_path / "bundle.zip"
    write_diagnostics_bundle(BundleOptions(
        out_path=out_path,
        healthz_url=_unreachable_healthz(),
        audit_log_path=env["audit_log"],
    ))
    with zipfile.ZipFile(out_path) as z:
        for info in z.infolist():
            assert info.date_time == (2026, 5, 17, 0, 0, 0), (
                f"{info.filename} has non-epoch mod-time {info.date_time}"
            )
