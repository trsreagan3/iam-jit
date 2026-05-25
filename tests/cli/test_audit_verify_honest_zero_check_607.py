"""#607 CRIT — `iam-jit audit verify` must NOT report "verified clean"
when it verified literally nothing.

Per UAT-Admin-CLI 2026-05-25 (Gap C): the command returned
``RESULT: ok — chain verified clean + all manifests valid`` with exit
0 even when ``events_checked == 0`` AND ``files_checked == 0``. Default
``--log-dir`` was ``"."`` (cwd) so any operator running the tool from
a random directory got a green check with zero signal — the exact
silent-degradation shape `[[ibounce-honest-positioning]]` forbids
for security verifiers.

Tests assert OBSERVABLE state per CONTRIBUTING.md: exit code + stderr
content + JSON shape, NOT just function returns.
"""

from __future__ import annotations

import json
import pathlib

import click
import pytest
from click.testing import CliRunner

from iam_jit.bouncer.audit_export import (
    ChainState,
    ManifestSigner,
    stamp_chain_event,
)
from iam_jit.cli_audit_verify import (
    _VERIFY_AUTO_DETECT_CANDIDATES,
    _resolve_verify_log_dir,
    register_audit_retention_command,
    register_audit_verify_command,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _ocsf_event(i: int = 0) -> dict:
    return {
        "metadata": {"version": "1.1.0", "product": {"name": "ibounce"}},
        "class_uid": 6003,
        "activity_name": "Read",
        "time": 1_700_000_000_000 + i,
        "unmapped": {"iam_jit": {"verdict": "ALLOW", "i": i}},
    }


def _seed_clean_chain(log_dir: pathlib.Path, *, count: int = 3) -> None:
    """Write a clean N-event chain to ``log_dir/audit.jsonl``."""
    log_dir.mkdir(parents=True, exist_ok=True)
    state = ChainState(log_dir=str(log_dir))
    events = [_ocsf_event(i) for i in range(count)]
    for e in events:
        stamp_chain_event(e, state)
    with (log_dir / "audit.jsonl").open("w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")


@pytest.fixture
def audit_root():
    """A standalone audit group with verify + retention registered."""
    @click.group()
    def root() -> None:
        pass

    @root.group("audit")
    def audit_group() -> None:
        pass

    register_audit_verify_command(audit_group)
    register_audit_retention_command(audit_group)
    return root


@pytest.fixture(autouse=True)
def _no_env_leak(monkeypatch):
    """Strip $IAM_JIT_AUDIT_LOG_PATH so tests are deterministic
    regardless of the developer's shell."""
    monkeypatch.delenv("IAM_JIT_AUDIT_LOG_PATH", raising=False)


# ---------------------------------------------------------------------------
# Test 1 — empty log dir exits non-zero (the core #607 bug)
# ---------------------------------------------------------------------------


def test_verify_empty_log_dir_exits_three_not_zero(tmp_path, audit_root):
    """An EMPTY directory must NOT report "verified clean". Per #607
    this is the silent-degradation shape — operator gets exit 0 with
    no warning when literally nothing was verified."""
    empty = tmp_path / "empty"
    empty.mkdir()
    runner = CliRunner()
    result = runner.invoke(audit_root, [
        "audit", "verify", "--log-dir", str(empty),
    ])
    # Exit code 3 — distinct from 0 (clean), 1 (findings), 2 (bad args).
    assert result.exit_code == 3, (
        f"expected exit 3 (nothing-checked) for empty log-dir; "
        f"got {result.exit_code}\nstdout: {result.stdout}\n"
        f"stderr: {result.stderr}"
    )
    # Operator-visible text must NOT claim success.
    assert "RESULT: ok" not in result.stdout, (
        "stdout must not say 'RESULT: ok' when 0 events checked"
    )
    assert "verified clean" not in result.stdout, (
        "stdout must not say 'verified clean' when 0 events checked"
    )
    # Affirmative honest message.
    assert (
        "no events checked" in result.stdout
        or "RESULT: warn" in result.stdout
    )
    # Actionable warning on stderr.
    assert "WARN" in result.stderr
    assert "no events" in result.stderr or "no events checked" in result.stderr


def test_verify_empty_log_dir_json_output_marks_not_ok(tmp_path, audit_root):
    """JSON consumers (SOC pipelines, CI) get a machine-readable
    ``ok: false`` + ``nothing_checked: true`` so they don't have to
    text-parse stderr."""
    empty = tmp_path / "empty-json"
    empty.mkdir()
    runner = CliRunner()
    result = runner.invoke(audit_root, [
        "audit", "verify", "--log-dir", str(empty), "--json",
    ])
    assert result.exit_code == 3
    payload = json.loads(result.stdout)
    assert payload["ok"] is False, (
        f"JSON ok must be False on zero-checked; got: {payload}"
    )
    assert payload["nothing_checked"] is True
    assert payload["chain"]["events_checked"] == 0
    assert payload["chain"]["files_checked"] == 0
    assert payload["manifests_checked"] == 0
    assert payload.get("warning"), "must include human-readable warning text"


# ---------------------------------------------------------------------------
# Test 2 — auto-detect default --log-dir (env var)
# ---------------------------------------------------------------------------


def test_verify_no_log_dir_auto_detects_via_env_var(tmp_path, audit_root, monkeypatch):
    """When --log-dir is omitted and $IAM_JIT_AUDIT_LOG_PATH is set,
    the verifier MUST use that directory + verify the events present
    there (returning exit 0 on a clean chain)."""
    log_dir = tmp_path / "envlogs"
    _seed_clean_chain(log_dir, count=3)
    monkeypatch.setenv(
        "IAM_JIT_AUDIT_LOG_PATH", str(log_dir / "audit.jsonl"),
    )
    runner = CliRunner()
    result = runner.invoke(audit_root, ["audit", "verify", "--json"])
    assert result.exit_code == 0, (
        f"env-var resolve + clean chain → exit 0; got {result.exit_code}\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    payload = json.loads(result.stdout)
    assert payload["ok"] is True
    assert payload["nothing_checked"] is False
    assert payload["chain"]["events_checked"] == 3
    assert payload["resolved_via"] == "env_var"


# ---------------------------------------------------------------------------
# Test 3 — no flag + no default found → exit 2 + actionable error
# ---------------------------------------------------------------------------


def test_verify_no_log_dir_no_default_found_errors(tmp_path, audit_root, monkeypatch):
    """When no flag, no env var, and no candidate directory exists,
    the verifier MUST exit 2 with an actionable error — NOT default
    to CWD (which is the #607 silent-degradation root cause)."""
    # Point HOME at a fresh tmp dir so ~/.iam-jit/* candidates don't resolve.
    fake_home = tmp_path / "fake-home"
    fake_home.mkdir()
    monkeypatch.setenv("HOME", str(fake_home))
    # Run from a fresh dir so ./audit-log doesn't exist either.
    work = tmp_path / "work"
    work.mkdir()
    runner = CliRunner()
    with runner.isolation():
        # CliRunner doesn't cd; use a subprocess-style env override via
        # Click's _resolve_verify_log_dir which expands ~ via HOME.
        result = runner.invoke(audit_root, ["audit", "verify"])
    assert result.exit_code == 2, (
        f"expected exit 2 (no default found); got {result.exit_code}\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    # Actionable error on stderr.
    assert "no --log-dir" in result.stderr or "no default" in result.stderr
    # Mentions the candidates so operator knows where to point.
    assert ".iam-jit" in result.stderr


# ---------------------------------------------------------------------------
# Test 4 — real events + empty time window → exit 3 (no events != ok)
# ---------------------------------------------------------------------------


def test_verify_real_dir_empty_time_window_exits_three(tmp_path, audit_root):
    """A populated log-dir filtered by --since to a window with no
    events MUST exit 3 (nothing checked), NOT exit 0. Operators
    running 'verify --since 1m' on a stale log should NOT get a
    green check that hides "your bouncer hasn't written in a month"."""
    log_dir = tmp_path / "stale"
    _seed_clean_chain(log_dir, count=2)
    # The seed events have mtime = now; --since 1s after now would skip
    # all. We rely on --since being a relative duration "in the past".
    # To force zero-events-in-window, age the file backwards.
    import os as _os
    long_ago = 1_500_000_000  # 2017
    audit_file = log_dir / "audit.jsonl"
    _os.utime(audit_file, (long_ago, long_ago))
    runner = CliRunner()
    result = runner.invoke(audit_root, [
        "audit", "verify", "--log-dir", str(log_dir),
        "--since", "1h",  # last hour — file is from 2017
        "--json",
    ])
    assert result.exit_code == 3, (
        f"expected exit 3 (window has no events); got {result.exit_code}\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    payload = json.loads(result.stdout)
    assert payload["nothing_checked"] is True
    assert payload["ok"] is False


# ---------------------------------------------------------------------------
# Test 5 — real events present → exit 0 (regression guard for #607 fix)
# ---------------------------------------------------------------------------


def test_verify_clean_chain_with_real_events_still_exits_zero(tmp_path, audit_root):
    """The #607 fix must NOT break the existing happy path: a real
    chain with events present should still return exit 0 + the OK
    message. Guards against over-correction."""
    log_dir = tmp_path / "real"
    _seed_clean_chain(log_dir, count=5)
    runner = CliRunner()
    result = runner.invoke(audit_root, [
        "audit", "verify", "--log-dir", str(log_dir),
    ])
    assert result.exit_code == 0, (
        f"clean chain with events MUST still exit 0; got {result.exit_code}\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert "RESULT: ok" in result.stdout
    # Negative: must not falsely warn when events were checked.
    assert "no events checked" not in result.stdout


# ---------------------------------------------------------------------------
# Test 6 — tampered chain still exits 1 (distinct from 3)
# ---------------------------------------------------------------------------


def test_verify_tampered_chain_exits_one_not_three(tmp_path, audit_root):
    """Tampered chain MUST exit 1 (findings), NOT 3 (nothing-checked).
    Tampering is a verification FAILURE; nothing-checked is a
    verification NO-OP. Exit codes must distinguish."""
    log_dir = tmp_path / "tampered"
    log_dir.mkdir()
    state = ChainState(log_dir=str(log_dir))
    events = [_ocsf_event(i) for i in range(3)]
    for e in events:
        stamp_chain_event(e, state)
    events[1]["unmapped"]["iam_jit"]["verdict"] = "DENY"
    with (log_dir / "audit.jsonl").open("w") as f:
        for e in events:
            f.write(json.dumps(e) + "\n")
    runner = CliRunner()
    result = runner.invoke(audit_root, [
        "audit", "verify", "--log-dir", str(log_dir),
    ])
    assert result.exit_code == 1, (
        f"tampered chain MUST exit 1 (not 3); got {result.exit_code}\n"
        f"stdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert "RESULT: FAILED" in result.stdout


# ---------------------------------------------------------------------------
# Test 7 — --explain prints scope and does NOT verify
# ---------------------------------------------------------------------------


def test_verify_explain_prints_scope_without_running(tmp_path, audit_root):
    """--explain MUST preview the scope and exit 0 without invoking
    the verifier. Operators use it to confirm auto-detection picked
    the right directory before a long run."""
    log_dir = tmp_path / "explain"
    _seed_clean_chain(log_dir, count=3)
    # Capture a baseline mtime to prove --explain does NOT mutate.
    audit_file = log_dir / "audit.jsonl"
    mtime_before = audit_file.stat().st_mtime
    size_before = audit_file.stat().st_size
    runner = CliRunner()
    result = runner.invoke(audit_root, [
        "audit", "verify", "--log-dir", str(log_dir),
        "--explain", "--json",
    ])
    assert result.exit_code == 0
    payload = json.loads(result.stdout)
    assert payload["explain"] is True
    assert payload["log_dir"] == str(log_dir)
    assert payload["would_run"] is True
    # Reports the file it would scan.
    paths = [f["path"] for f in payload["candidate_files"]]
    assert any("audit.jsonl" in p for p in paths)
    # State verification: file unchanged after --explain (no mutation).
    assert audit_file.stat().st_mtime == mtime_before
    assert audit_file.stat().st_size == size_before


def test_verify_explain_human_output_says_would_verify(tmp_path, audit_root):
    """--explain human output must clearly say it did NOT verify."""
    log_dir = tmp_path / "explain-human"
    _seed_clean_chain(log_dir, count=2)
    runner = CliRunner()
    result = runner.invoke(audit_root, [
        "audit", "verify", "--log-dir", str(log_dir), "--explain",
    ])
    assert result.exit_code == 0
    assert "Will verify" in result.stdout or "will verify" in result.stdout.lower()
    assert "Run without --explain" in result.stdout
    # Critically: must NOT contain the "RESULT: ok" success string —
    # that would conflate explain with verification.
    assert "RESULT: ok" not in result.stdout


# ---------------------------------------------------------------------------
# Test 8 — resolver unit tests (pure functions)
# ---------------------------------------------------------------------------


def test_resolve_verify_log_dir_explicit_wins(tmp_path):
    """Explicit --log-dir takes precedence over env var and candidates."""
    explicit = tmp_path / "explicit"
    explicit.mkdir()
    path, reason = _resolve_verify_log_dir(
        explicit,
        env={"IAM_JIT_AUDIT_LOG_PATH": "/should/not/win"},
    )
    assert path == explicit
    assert reason == "explicit"


def test_resolve_verify_log_dir_env_var_used(tmp_path):
    """When no flag passed, env var resolves to its parent dir."""
    audit_file = tmp_path / "audit.jsonl"
    audit_file.write_text("")
    path, reason = _resolve_verify_log_dir(
        None,
        env={"IAM_JIT_AUDIT_LOG_PATH": str(audit_file)},
    )
    assert path == tmp_path
    assert reason == "env_var"


def test_resolve_verify_log_dir_auto_detect_candidate(tmp_path):
    """When env unset, walk candidates and pick first that exists."""
    candidate = tmp_path / "iamjit-bouncer"
    candidate.mkdir()
    miss = tmp_path / "does-not-exist"
    path, reason = _resolve_verify_log_dir(
        None,
        env={},
        candidates=(str(miss), str(candidate)),
    )
    assert path == candidate
    assert reason.startswith("auto_detect:")


def test_resolve_verify_log_dir_none_found(tmp_path):
    """No flag, no env, no candidate exists → (None, 'none_found').
    The CLI must NOT silently fall back to CWD per #607."""
    miss1 = tmp_path / "miss1"
    miss2 = tmp_path / "miss2"
    path, reason = _resolve_verify_log_dir(
        None,
        env={},
        candidates=(str(miss1), str(miss2)),
    )
    assert path is None
    assert reason == "none_found"


def test_default_candidates_do_not_include_cwd():
    """Sabotage-resistance: per #607 the auto-detect list MUST NOT
    include '.' / './' / '$PWD'. CWD-as-default is the exact silent-
    degradation footgun this CRIT fixes. Any future regression that
    adds CWD back will fail loudly here."""
    for c in _VERIFY_AUTO_DETECT_CANDIDATES:
        assert c not in (".", "./", ""), (
            f"CWD must not be in verify auto-detect candidates; got {c!r}"
        )


# ---------------------------------------------------------------------------
# Sabotage check — proves the new exit-3 logic is load-bearing
# ---------------------------------------------------------------------------


def test_sabotage_check_zero_events_logic_is_load_bearing(
    tmp_path, audit_root, monkeypatch,
):
    """Patch the zero-checked branch to always behave like the old
    code (exit 0 + 'RESULT: ok') and confirm test 1 would FAIL.
    Proves the new logic is what's catching the bug — not some
    incidental change."""
    import iam_jit.cli_audit_verify as mod

    # Save originals.
    real_sys_exit = mod.sys.exit
    real_echo = mod.click.echo

    # Force exit code 0 on every sys.exit (simulate pre-#607 bug).
    captured_codes: list[int] = []

    def _broken_exit(code=0):
        captured_codes.append(code)
        raise SystemExit(0)  # Always 0 — the bug.

    monkeypatch.setattr(mod.sys, "exit", _broken_exit)

    empty = tmp_path / "sabotage-empty"
    empty.mkdir()
    runner = CliRunner()
    result = runner.invoke(audit_root, [
        "audit", "verify", "--log-dir", str(empty),
    ])
    # With sabotage in place, exit code is forced to 0. This MUST be
    # the only way to get exit 0 on an empty dir — confirming the
    # production path of "exit 3 on nothing-checked" is what would
    # otherwise have fired.
    assert result.exit_code == 0  # because sabotage forced it
    # And the code path DID try to exit non-zero before sabotage —
    # we should see 3 in the captured codes.
    assert 3 in captured_codes, (
        f"expected the empty-dir path to attempt sys.exit(3); "
        f"got captured codes {captured_codes}. If 3 is missing the "
        f"new logic is NOT load-bearing and the sabotage check has "
        f"caught a regression."
    )
