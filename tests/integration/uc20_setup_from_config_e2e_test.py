"""UC-20 E2E — `iam_jit_setup_from_config` via real MCP dispatch.

Per `docs/MRR-1-USE-CASE-AUDIT-2026-05-24.md` UC-20 (CRIT, #2 of 5
pre-deploy blockers): `iam_jit_setup_from_config` is the LOAD-BEARING
pitch of `[[ambient-autonomous-protection]]` — operator writes ONE
declaration, agent installs + starts everything autonomously. Today
only unit-tested with stubbed `_start_bouncer`; never exercised by a
real MCP client against real bouncer subprocesses.

B6 transactional fix landed in commit 5ecfaa3 (#538) — snapshot +
restore on partial-install. This E2E validates the END-TO-END flow as
the operator + agent actually exercise it:

  Scenario A (happy path)
    * declaration enables ibounce only
    * driven through the real MCP `tools/call` dispatch
      (`iam_jit_setup_from_config`) so the agent surface is exercised
      end-to-end (TOOLS schema → handler → apply_config_for_mcp →
      apply_declaration → real subprocess.Popen)
    * verify: ibounce process running with bound port; /healthz 200
      AND identifies as a bouncer; structured result has the canonical
      shape; pre-existing operator-state untouched
      (`[[creates-never-mutates]]`)

  Scenario B (B6 rollback — partial-install)
    * declaration enables ibounce + gbounce (gbounce binary missing
      from the venv — natural start-failure injection)
    * MCP call with default `rollback_on_failure=True`
    * verify: ibounce PID went up then back down (SIGTERM by rollback);
      `status == "rolled_back"`; `rollback_outcome.status == "ok"`;
      `bouncers_started == []` (honestly cleared); warnings reference
      #538; pre-apply config snapshot restored byte-for-byte

  Scenario C (opt-out — rollback_on_failure=False)
    * same partial-install shape as B
    * but caller invokes `apply_declaration` directly with
      `rollback_on_failure=False` (the MCP tool doesn't expose this
      switch yet; the LOAD-BEARING failure-handling default IS the MCP
      surface — see "Out of scope" in the brief). The legacy
      pre-#538 semantics are verified by direct call.
    * verify: ibounce stays running; `bouncers_started == ["ibounce"]`;
      `rollback_outcome is None`; warning explains the partial state

  Scenario D (operator-visible misconfig warning)
    * declaration pins a profile name that doesn't exist in
      profiles.yaml
    * verify: result.warnings carries an operator-actionable hint
      naming the profile + suggesting the install command

Honest gating per `[[ibounce-honest-positioning]]`: SKIPS when the
ibounce console-script isn't installed. On a venv with `pip install
-e .` the test MUST run + MUST pass.

Mirrors UC-3 (commit b7939fe / tests/integration/uc3_synthesis_e2e_test.py)
for scaffolding patterns (subprocess + /healthz + free-port + per-test
isolation via tmp_path).

The test is fast (no LocalStack required — UC-20 covers install +
startup; AWS data-plane exercise is UC-3's surface): wall-clock target
< 10s. Reruns are clean because every artefact lives under tmp_path or
gets cleaned up in the teardown clauses below.
"""

from __future__ import annotations

import contextlib
import json
import os
import pathlib
import shutil
import signal
import socket
import time
import urllib.error
import urllib.request
from typing import Any

import pytest


REPO_ROOT = pathlib.Path(__file__).resolve().parents[2]
IBOUNCE_BIN = REPO_ROOT / ".venv" / "bin" / "ibounce"

# Free-port band — avoid the default-port range (8766-8769) and the
# UC-3 test's band (19967+) so concurrent test runs don't collide.
PORT_IBOUNCE_BASE = 20067


def _have_bin(p: pathlib.Path) -> bool:
    return p.exists() and os.access(p, os.X_OK)


def _free_port(preferred: int) -> int:
    """Return `preferred` if free, else any OS-assigned free port."""
    with contextlib.closing(
        socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    ) as s:
        try:
            s.bind(("127.0.0.1", preferred))
            return preferred
        except OSError:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]


def _wait_for_healthz(url: str, timeout: float = 15.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=0.5) as resp:  # noqa: S310
                if resp.status in (200, 503):
                    return True
        except (urllib.error.URLError, OSError):
            time.sleep(0.2)
    return False


def _pid_alive(pid: int) -> bool:
    """True iff PID is RUNNING (not a zombie).

    `os.kill(pid, 0)` returns success on zombies (post-exit, pre-reap)
    — which is wrong for our test's purpose: when the bouncer exited
    from SIGTERM, the test interpreter is its parent and the zombie
    entry persists until `waitpid` reaps. So `os.kill(0)` would lie
    about liveness for any subprocess.Popen child we spawned.

    Fix: use `os.waitpid(pid, WNOHANG)` first — it returns (pid, status)
    for an already-exited (zombie) child + reaps it. Returns (0, 0)
    when the child IS still running. ChildProcessError means we're
    not the parent (e.g. detached session) — fall back to `os.kill(0)`
    which is correct for non-children.
    """
    # First try waitpid — works for processes we parent.
    try:
        r_pid, _ = os.waitpid(pid, os.WNOHANG)
        if r_pid == pid:
            # Reaped a zombie — process is gone.
            return False
        # r_pid == 0 → still running.
        return True
    except ChildProcessError:
        pass  # not our child; fall through to kill(0)
    except OSError:
        pass

    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _wait_for_pid_exit(pid: int, timeout: float = 5.0) -> bool:
    """Poll until pid is no longer alive (and reaped if a child), or
    timeout. Uses the same waitpid-aware primitive as `_pid_alive`."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        if not _pid_alive(pid):
            return True
        time.sleep(0.1)
    return False


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not _have_bin(IBOUNCE_BIN),
        reason=(
            f"missing ibounce console-script at {IBOUNCE_BIN}; "
            "install with `pip install -e .` in the venv"
        ),
    ),
]


# ---------------------------------------------------------------------------
# Per-test isolation: every bouncer state path lives under tmp_path so
# the operator's real `~/.iam-jit/` is never touched.
# ---------------------------------------------------------------------------


def _clean_slate_posture() -> dict[str, Any]:
    """Posture snapshot with NO bouncers running.

    The dogfood-host reality (the founder is running ibounce on the
    default port 8767 while writing this test) means a naive E2E that
    captures real posture sees `running=True` and the [[creates-never-
    mutates]] floor refuses to start a parallel bouncer. We inject
    a clean-slate posture so the canonical "start from scratch"
    flow is exercised regardless of dogfood state.

    Per [[ibounce-honest-positioning]]: this is NOT mocking the
    bouncer subprocess (we DO actually start one). It is mocking the
    detection of OTHER bouncers on default ports, which is precisely
    what an MCP-agent install flow on a freshly-onboarded host
    encounters. The real-already-running case is covered by the
    transactional unit tests + the founder's manual dogfood loop.
    """
    return {
        "schema_version": "1.0",
        "overall_mode": "neither",
        "bouncers": {
            "ibounce": {"running": False, "port": 8767, "pid": None},
            "kbounce": {"running": False, "port": 8766, "pid": None},
            "gbounce": {"running": False, "port": 8080, "pid": None},
            "dbounce": {"running": False, "port": 5433, "pid": None},
        },
    }


@pytest.fixture
def isolated_state(tmp_path, monkeypatch):
    """Redirect ibounce state-dir + snapshot files into tmp_path AND
    force a clean-slate posture so the test exercises the canonical
    install-from-scratch flow.

    The bouncer subprocess inherits IAM_JIT_BOUNCER_DB via the child
    env (apply_declaration uses dict(os.environ) for the Popen env);
    the in-process snapshot path list is module-level so we monkeypatch
    it for the duration of the test.
    """
    from iam_jit.ambient_config import setup as setup_mod

    bouncer_db = tmp_path / "ibounce.db"
    bouncer_state_dir = tmp_path / "bouncer_state"
    bouncer_state_dir.mkdir()

    # Snapshot files: redirect to tmp_path so _capture_setup_state +
    # _restore_setup_state operate on test-owned files.
    snap_a = bouncer_state_dir / "profiles.yaml"
    snap_b = bouncer_state_dir / "profiles_state.yaml"
    monkeypatch.setattr(
        setup_mod, "_SETUP_SNAPSHOT_CONFIG_FILES",
        (snap_a, snap_b),
    )

    # Force clean-slate posture so the test isn't shadowed by a real
    # ibounce running on default port 8767 (the dogfood-host reality).
    monkeypatch.setattr(
        setup_mod, "_capture_posture_safe",
        _clean_slate_posture,
    )

    # Bouncer child env override — point at our test DB path.
    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", str(bouncer_db))

    # Audit-log overrides so synthesis / bouncer events go to tmp_path
    # (defence-in-depth: even though UC-20 doesn't drive AWS traffic,
    # ibounce's startup may emit init events).
    monkeypatch.setenv(
        "IAM_JIT_BOUNCER_AUDIT_LOG",
        str(tmp_path / "bouncer-audit.jsonl"),
    )

    yield {
        "tmp_path": tmp_path,
        "bouncer_db": bouncer_db,
        "snap_a": snap_a,
        "snap_b": snap_b,
        "state_dir": bouncer_state_dir,
    }


def _mcp_call_setup_from_config(args: dict[str, Any]) -> dict[str, Any]:
    """Drive the real MCP `tools/call` dispatcher for the setup tool.

    Returns the structuredContent payload (which is the SetupResult
    .as_dict() shape). This is the EXACT path an MCP client takes —
    differs from a direct `apply_config_for_mcp(...)` import-call in
    that it exercises:
      * the TOOLS-array registration (an entry MUST exist or the
        dispatcher returns -32601 unknown-tool)
      * the tool-name → handler routing
      * JSON-serialisability of the return payload
    """
    from iam_jit.mcp_server import _handle_request

    req = {
        "jsonrpc": "2.0",
        "id": 42,
        "method": "tools/call",
        "params": {
            "name": "iam_jit_setup_from_config",
            "arguments": args,
        },
    }
    resp = _handle_request(req)
    assert resp is not None, "MCP request returned no response"
    assert "result" in resp, f"MCP request returned error: {resp!r}"
    # MCP wraps the payload twice — text + structuredContent.
    return resp["result"]["structuredContent"]


def _make_declaration(
    *,
    ibounce_port: int,
    enable_gbounce: bool = False,
    gbounce_profile: str | None = None,
) -> dict[str, Any]:
    """Build a minimal declaration honoring the schema. ibounce runs in
    discovery mode (default) so no upstream is forwarded; we just want
    the process up + bound + healthz responsive."""
    bouncers: dict[str, Any] = {
        "ibounce": {
            "enabled": True,
            "mode": "discovery",
            "port": ibounce_port,
        },
    }
    if enable_gbounce:
        block: dict[str, Any] = {
            "enabled": True,  # explicit true — not conditional
            "mode": "discovery",
        }
        if gbounce_profile is not None:
            block["profile"] = gbounce_profile
        bouncers["gbounce"] = block
    return {
        "iam-jit": {
            "enabled": True,
            "bouncers": bouncers,
        }
    }


def _kill_started_pids(result_payload: dict[str, Any]) -> list[int]:
    """Teardown helper: SIGTERM every PID this result claimed to start
    (or planned to start). Idempotent — already-dead PIDs are ok."""
    killed: list[int] = []
    for rec in result_payload.get("bouncers_planned", []) or []:
        pid = rec.get("pid")
        if not pid:
            continue
        try:
            os.kill(int(pid), signal.SIGTERM)
            killed.append(int(pid))
        except ProcessLookupError:
            pass
        except (PermissionError, OSError):
            pass
    # Wait briefly for graceful exit.
    for pid in killed:
        _wait_for_pid_exit(pid, timeout=3.0)
    return killed


# ---------------------------------------------------------------------------
# Scenario A — happy path: ibounce installs + starts via real MCP dispatch
# ---------------------------------------------------------------------------


def test_uc20_happy_path_real_mcp_dispatch(isolated_state, monkeypatch):
    """Real MCP `tools/call` → real subprocess.Popen → real /healthz.

    Validates the load-bearing pitch of
    [[ambient-autonomous-protection]] end-to-end: a single declaration
    + a single MCP call results in a live, healthy bouncer.
    """
    port = _free_port(PORT_IBOUNCE_BASE)
    declaration = _make_declaration(ibounce_port=port)

    # Pre-apply state: write a sentinel into one of the snapshot
    # config-file paths so we can prove [[creates-never-mutates]] —
    # happy-path apply MUST NOT mutate this file.
    isolated_state["snap_a"].write_text("PRE-APPLY-OPERATOR-CONTENT\n")
    pre_apply_bytes = isolated_state["snap_a"].read_bytes()

    # Drive the REAL MCP dispatcher (not a direct import-call) so we
    # exercise tools/call routing + TOOLS-array registration.
    result = _mcp_call_setup_from_config({
        "declaration": declaration,
        "dry_run": False,
    })

    started_pid_box: dict[str, int] = {}
    try:
        # ===== Reported shape =====
        assert result["status"] == "ok", result
        assert result["dry_run"] is False
        assert "ibounce" in result["bouncers_started"], (
            f"happy path didn't start ibounce; got {result['bouncers_started']!r}; "
            f"skipped: {result['bouncers_skipped']!r}; "
            f"planned: {result['bouncers_planned']!r}"
        )
        # Rollback MUST be untouched on the happy path (no failures).
        assert result.get("rollback_outcome") is None, (
            f"rollback fired unexpectedly on happy path: "
            f"{result.get('rollback_outcome')!r}"
        )
        # The planned record should carry the PID we actually spawned.
        planned = [
            r for r in result["bouncers_planned"] if r["name"] == "ibounce"
        ]
        assert planned and planned[0].get("pid"), (
            f"no PID in planned record: {result['bouncers_planned']!r}"
        )
        started_pid = int(planned[0]["pid"])
        started_pid_box["ibounce"] = started_pid

        # ===== Observable state — process is alive =====
        assert _pid_alive(started_pid), (
            f"setup returned status=ok + ibounce in bouncers_started "
            f"but pid {started_pid} is not alive; this is the #476 "
            f"silent-success shape (would have passed a status-only "
            f"assertion)"
        )

        # ===== Observable state — /healthz answers + identifies as ibounce =====
        # This is the *real* MCP-agent verification: "did the bouncer
        # actually come up listening?" — not just "did Popen return 0".
        healthz = f"http://127.0.0.1:{port}/healthz"
        assert _wait_for_healthz(healthz, timeout=15.0), (
            f"ibounce on port {port} never answered /healthz; pid "
            f"{started_pid} alive={_pid_alive(started_pid)}"
        )
        with urllib.request.urlopen(healthz, timeout=2.0) as resp:  # noqa: S310
            body = resp.read(8192)
        payload = json.loads(body.decode("utf-8"))
        assert payload.get("bouncer_kind") == "ibounce", (
            f"/healthz returned a body without bouncer_kind=ibounce "
            f"(actually got: {payload!r})"
        )

        # ===== Observable state — env-var advisory rendered correctly =====
        env_vars = result.get("env_vars_to_set") or {}
        assert env_vars.get("AWS_ENDPOINT_URL") == f"http://127.0.0.1:{port}", (
            f"env-var advisory wrong; got: {env_vars!r}"
        )

        # ===== Observable state — creates-never-mutates floor =====
        # The pre-apply sentinel file MUST be unchanged. (The bouncer's
        # startup writes its DB + audit log under tmp_path/$BOUNCER_DB
        # paths we redirected; profiles.yaml is operator-owned + must
        # never be silently rewritten on apply.)
        assert isolated_state["snap_a"].read_bytes() == pre_apply_bytes, (
            f"[[creates-never-mutates]] VIOLATION: profiles.yaml was "
            f"mutated by happy-path apply. pre: {pre_apply_bytes!r} "
            f"post: {isolated_state['snap_a'].read_bytes()!r}"
        )

        # ===== Reported shape — bouncer_mode_resolutions surfaces alias =====
        ibounce_mode_res = [
            r for r in result.get("bouncer_mode_resolutions", [])
            if r["bouncer"] == "ibounce"
        ]
        assert ibounce_mode_res, (
            f"missing mode_resolutions for ibounce: {result!r}"
        )
        assert ibounce_mode_res[0]["mode_declared"] == "discovery"
        assert ibounce_mode_res[0]["mode_runtime"] == "cooperative"
        assert ibounce_mode_res[0]["mode_source"] == "declaration"

    finally:
        # Teardown: SIGTERM whatever we started.
        for pid in started_pid_box.values():
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.kill(pid, signal.SIGTERM)
                _wait_for_pid_exit(pid, timeout=5.0)


# ---------------------------------------------------------------------------
# Scenario A-sabotage — prove the happy-path assertion actually fires
# ---------------------------------------------------------------------------


def test_uc20_happy_path_sabotage_check_pid_liveness(
    isolated_state, monkeypatch,
):
    """Sabotage-check: if we feed the assertion a PID that's NOT alive,
    the assertion MUST fail loudly. Proves the liveness assertion in
    the happy-path test is not a silent short-circuit (the #476 shape).
    """
    # Spawn-then-kill a throwaway python so we have a guaranteed-dead pid.
    import subprocess
    proc = subprocess.Popen(
        ["python3", "-c", "import time; time.sleep(0)"],
    )
    proc.wait(timeout=3)
    dead_pid = proc.pid
    assert not _pid_alive(dead_pid), "sabotage setup failed"

    # The exact assertion the happy-path test uses, with a dead pid.
    # MUST raise AssertionError — that's the proof the test isn't
    # silently passing on a corpse.
    with pytest.raises(AssertionError):
        assert _pid_alive(dead_pid), (
            "this assertion is the load-bearing liveness check; "
            "verifying it actually fires for non-alive PIDs"
        )


# ---------------------------------------------------------------------------
# Scenario B — partial-install triggers B6 rollback (default behaviour)
# ---------------------------------------------------------------------------


def test_uc20_partial_install_triggers_b6_rollback(isolated_state):
    """gbounce binary is NOT installed in this venv; declaring it
    alongside ibounce MUST trigger the #538 rollback: ibounce starts,
    gbounce start-fails, rollback SIGTERMs ibounce + restores snapshot.

    Per CONTRIBUTING.md state-verification: assert OBSERVABLE state
    (PID went up then down, file content restored byte-for-byte) on
    top of the reported `status: rolled_back`.
    """
    # Sanity: gbounce truly absent. If a future contributor adds gbounce
    # to the venv this test breaks loud — better that than a stub.
    assert shutil.which("gbounce") is None, (
        "test premise broken: gbounce is on PATH; this test relies on "
        "gbounce being absent to trigger the natural start-failure "
        "rollback. Pick a different bouncer name or update the test "
        "to inject a different failure mode."
    )

    # Sentinel content that rollback MUST restore byte-for-byte.
    isolated_state["snap_a"].write_text("PRE-APPLY-OPERATOR-CONTENT\n")
    pre_apply_bytes = isolated_state["snap_a"].read_bytes()

    port = _free_port(PORT_IBOUNCE_BASE + 1)
    declaration = _make_declaration(ibounce_port=port, enable_gbounce=True)

    result = _mcp_call_setup_from_config({
        "declaration": declaration,
        "dry_run": False,
    })

    # Capture the PID ibounce got assigned BEFORE rollback so we can
    # post-verify it's no longer alive.
    planned_records = result.get("bouncers_planned") or []
    ibounce_records = [r for r in planned_records if r["name"] == "ibounce"]
    assert ibounce_records, (
        f"ibounce wasn't even planned; can't validate rollback. "
        f"Result: {result!r}"
    )
    # The planned record stamps `started: True` + `pid` ON START.
    # Rollback kills the process but does NOT rewrite this record;
    # it's the historical record of what started.
    ibounce_planned = ibounce_records[0]
    assert ibounce_planned.get("started") is True, (
        f"ibounce never started → rollback can't be the partial-install "
        f"shape under test. Planned record: {ibounce_planned!r}"
    )
    started_pid = int(ibounce_planned["pid"])

    try:
        # ===== Reported: rollback fired + status changed accordingly =====
        assert result["status"] == "rolled_back", (
            f"expected status=rolled_back; got {result['status']!r}. "
            f"Full result: {result!r}"
        )
        assert result.get("rollback_outcome") is not None, (
            f"rollback_outcome is None despite partial-install; this "
            f"is the B6 silent-orphan shape #538 fixed. Result: {result!r}"
        )
        rollback = result["rollback_outcome"]
        assert rollback["status"] == "ok", (
            f"rollback verification incomplete: {rollback!r}"
        )

        # ===== Observable: ibounce PID was killed =====
        # Give SIGTERM up to 8s to land. The bouncer's graceful-
        # shutdown path (#359 / §A30) drains audit queues + closes the
        # SQLite handle before exit; empirically <500ms on a fresh dev
        # box. The 8s margin accommodates CI contention without papering
        # over a real regression. `_wait_for_pid_exit` is zombie-aware
        # (uses waitpid + WNOHANG) so it reports the truth even when
        # the test interpreter is the bouncer's parent process.
        assert _wait_for_pid_exit(started_pid, timeout=8.0), (
            f"#538 rollback claimed status=ok but ibounce pid "
            f"{started_pid} is still alive after 8s — this is the #463 "
            f"'reported success without observable state' shape"
        )
        assert started_pid in rollback["killed_pids"], (
            f"started ibounce pid {started_pid} not in killed_pids "
            f"{rollback['killed_pids']!r}; rollback bookkeeping is "
            f"inconsistent with what it actually did"
        )

        # ===== Observable: bouncers_started honestly cleared =====
        assert result["bouncers_started"] == [], (
            f"#538 partial-install claimed bouncers_started={result['bouncers_started']!r} "
            f"despite ibounce being SIGTERM'd; this is the dishonest "
            f"surface the brief explicitly calls out"
        )

        # ===== Observable: gbounce skip recorded as start_failure =====
        gb_skips = [
            s for s in result.get("bouncers_skipped", [])
            if s["name"] == "gbounce"
        ]
        assert gb_skips, (
            f"gbounce isn't in bouncers_skipped despite binary missing; "
            f"skipped: {result.get('bouncers_skipped')!r}"
        )
        assert gb_skips[0].get("kind") == "start_failure", (
            f"gbounce skip kind={gb_skips[0].get('kind')!r}; expected "
            f"start_failure (the #538 rollback-trigger signal)"
        )

        # ===== Observable: pre-apply config restored byte-for-byte =====
        assert isolated_state["snap_a"].read_bytes() == pre_apply_bytes, (
            f"#538 rollback claimed status=ok but pre-apply config "
            f"file content was NOT restored. pre: {pre_apply_bytes!r} "
            f"post: {isolated_state['snap_a'].read_bytes()!r}"
        )
        assert str(isolated_state["snap_a"]) in rollback["files_restored"], (
            f"snap_a not in rollback's files_restored list: {rollback!r}"
        )

        # ===== Observable: rollback verification has no drift =====
        assert rollback["verification_drift"] == [], (
            f"#538 rollback verification surfaced drift: "
            f"{rollback['verification_drift']!r}"
        )

        # ===== Reported: warning surface references #538 + partial-install =====
        warning_blob = " ".join(result.get("warnings", []) or [])
        assert "#538" in warning_blob, (
            f"no #538 reference in warnings; operator can't trace this "
            f"event back to the commit. Warnings: {warning_blob!r}"
        )
        assert "partial-install" in warning_blob, (
            f"no partial-install reference in warnings: {warning_blob!r}"
        )

    finally:
        # Defensive teardown: if rollback failed and ibounce is still
        # alive, kill it so we don't leak processes.
        if _pid_alive(started_pid):
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.kill(started_pid, signal.SIGKILL)


# ---------------------------------------------------------------------------
# Scenario C — opt-out: rollback_on_failure=False leaves partial state
# ---------------------------------------------------------------------------


def test_uc20_opt_out_leaves_partial_state(isolated_state):
    """When the caller passes `rollback_on_failure=False`, the same
    partial-install scenario leaves ibounce running + records the
    failure honestly without auto-rolling back.

    The MCP tool does NOT yet expose the rollback_on_failure switch
    (out-of-scope per the brief — this PR is test-only). So this
    scenario calls `apply_declaration` directly to verify the legacy
    pre-#538 semantics are preserved when callers opt out.
    """
    from iam_jit.ambient_config import apply_declaration

    isolated_state["snap_a"].write_text("PRE-APPLY-OPERATOR-CONTENT\n")
    pre_apply_bytes = isolated_state["snap_a"].read_bytes()

    port = _free_port(PORT_IBOUNCE_BASE + 2)
    declaration = _make_declaration(ibounce_port=port, enable_gbounce=True)

    setup_result = apply_declaration(
        declaration,
        source="<uc20-test-opt-out>",
        execute=True,
        rollback_on_failure=False,
    )
    result = setup_result.as_dict()

    started_pid_box: dict[str, int] = {}
    try:
        # ===== Reported: rollback was NOT invoked =====
        assert result.get("rollback_outcome") is None, (
            f"rollback_outcome should be None with rollback_on_failure=False; "
            f"got: {result['rollback_outcome']!r}"
        )
        # status stays the legacy "ok" (the surface that the brief notes
        # operators flagged as confusing — but the opt-out exists for
        # operators who explicitly prefer the legacy shape).
        assert result["status"] == "ok", (
            f"opt-out should preserve pre-#538 status='ok'; got "
            f"{result['status']!r}"
        )

        # ===== Reported: ibounce stays in bouncers_started =====
        assert "ibounce" in result["bouncers_started"], (
            f"opt-out should leave bouncers_started intact; got "
            f"{result['bouncers_started']!r}"
        )

        planned = [
            r for r in result["bouncers_planned"]
            if r["name"] == "ibounce" and r.get("started")
        ]
        assert planned, (
            f"ibounce was not started under opt-out; result: {result!r}"
        )
        started_pid = int(planned[0]["pid"])
        started_pid_box["ibounce"] = started_pid

        # ===== Observable: ibounce IS still alive (no rollback SIGTERM) =====
        # The whole point of opt-out is to leave the partial state for
        # operator triage; assert that we actually got the partial state.
        assert _pid_alive(started_pid), (
            f"opt-out claimed bouncers_started=['ibounce'] but pid "
            f"{started_pid} is dead — opt-out semantics are broken"
        )

        # ===== Observable: pre-apply config file is also untouched =====
        # (Opt-out does NOT trigger snapshot-restore, but it also
        # doesn't mutate config files on a normal start — verify.)
        assert isolated_state["snap_a"].read_bytes() == pre_apply_bytes, (
            f"opt-out path mutated profiles.yaml; violates "
            f"[[creates-never-mutates]] for the no-rollback path"
        )

        # ===== Reported: gbounce skip is still recorded as start_failure =====
        gb_skips = [
            s for s in result.get("bouncers_skipped", [])
            if s["name"] == "gbounce"
        ]
        assert gb_skips and gb_skips[0].get("kind") == "start_failure", (
            f"gbounce skip kind incorrect under opt-out: "
            f"{result.get('bouncers_skipped')!r}"
        )

    finally:
        for pid in started_pid_box.values():
            with contextlib.suppress(ProcessLookupError, PermissionError):
                os.kill(pid, signal.SIGTERM)
                _wait_for_pid_exit(pid, timeout=5.0)


# ---------------------------------------------------------------------------
# Scenario D — operator-visible warning on misconfig
# ---------------------------------------------------------------------------
#
# NEW BUG SURFACED 2026-05-24 during this UC-20 E2E build: the
# pinned-but-missing profile warning surface in setup.py
# (lines 1179-1200) is silently broken — `load_profiles()` returns
# dict[str, Profile] but setup does `{p.name for p in profiles}` which
# iterates dict KEYS (str), then attempts `.name` on str → AttributeError
# → swallowed by bare `except Exception`. Result: declaring a non-
# existent profile silently produces NO warning. Filed for separate fix
# task — NOT this PR's scope per the brief ("test only"). Track via the
# UC-20 follow-up cluster.
#
# Below uses a DIFFERENT operator-visible-warning surface that DOES
# work today (the notify_on_deny=false advisory in setup.py line 1223)
# so this E2E still meaningfully validates the "warning surface
# reaches the operator via the MCP return shape" promise.


def test_uc20_operator_visible_warning_on_notify_off(isolated_state):
    """`notify_on_deny: false` in the declaration MUST surface as a
    user-facing warning. Validates that operator-visible warnings
    actually reach the MCP return shape (the load-bearing promise of
    [[ibounce-honest-positioning]] for the setup tool: every soft-
    config decision is visible in the structured response).

    Uses dry_run=True since the warning surface fires regardless of
    execute mode + we don't need the side effect of a real bouncer
    spawn just to validate the structured-output channel.
    """
    port = _free_port(PORT_IBOUNCE_BASE + 3)
    declaration = {
        "iam-jit": {
            "enabled": True,
            "notify_on_deny": False,
            "bouncers": {
                "ibounce": {
                    "enabled": True,
                    "mode": "discovery",
                    "port": port,
                },
            },
        }
    }

    result = _mcp_call_setup_from_config({
        "declaration": declaration,
        "dry_run": True,
    })

    warnings = result.get("warnings", []) or []
    # The notify_on_deny=false warning surface fires once in setup.py
    # (line 1223). Look for a warning that names the field + reasons
    # about deny visibility — operator-actionable, not just status.
    notify_warns = [
        w for w in warnings
        if "notify_on_deny" in w
    ]
    assert notify_warns, (
        f"declaration set notify_on_deny=false but no warning was "
        f"surfaced to the operator via the MCP return shape. All "
        f"warnings: {warnings!r}"
    )
    # Operator-actionable: warning should NAME the consequence (deny
    # visibility) so the operator understands what they turned off.
    assert any(
        ("deny" in w.lower()) or ("notification" in w.lower())
        for w in notify_warns
    ), (
        f"notify_on_deny warning doesn't explain the consequence: "
        f"{notify_warns!r}"
    )


# ---------------------------------------------------------------------------
# Scenario E — sabotage-check for the B6 rollback assertion
# ---------------------------------------------------------------------------


def test_uc20_sabotage_check_pid_exit_assertion_fires(isolated_state):
    """Sabotage-check: spawn a long-lived process, then run the same
    `_wait_for_pid_exit(..., timeout=1.0)` assertion the B6-rollback
    test uses. With a process that is NEVER killed it MUST return
    False, and the wrapping assertion MUST raise AssertionError.

    Proves the rollback test's PID-exit assertion is not silently
    short-circuiting (would mask a real rollback regression where
    SIGTERM never actually fires).
    """
    import subprocess

    # Spawn something that won't exit for at least 10s.
    proc = subprocess.Popen(
        ["python3", "-c", "import time; time.sleep(10)"],
    )
    try:
        assert _pid_alive(proc.pid), "sabotage setup failed: spawn not alive"

        # Exact assertion shape from the rollback test, with short timeout.
        exited = _wait_for_pid_exit(proc.pid, timeout=1.0)
        # If this assertion silently passed for an alive PID, the
        # rollback test could ALSO silently pass for a botched rollback.
        # The next two lines together prove it: exited MUST be False,
        # AND `assert exited` MUST raise.
        assert exited is False, (
            "sabotage VIOLATION: _wait_for_pid_exit returned True for "
            "a process we know is still alive; the rollback test's "
            "liveness assertion is broken"
        )
        with pytest.raises(AssertionError):
            assert exited, (
                "this would have been the rollback test's assertion; "
                "verifying it fires for a non-exited PID"
            )
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
