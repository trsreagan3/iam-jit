"""#320 / §A18 — /audit/events wire-shape parity gap fix.

This test is the launch-gate regression for the cross-bouncer
`/audit/events` HTTP endpoint (the read-path of the unified
`iam-jit audit query` CLI). UAT 2026-05-22 surfaced that the headline
"cross-bouncer audit query via `agent.session_id`" claim (#318) was
wire-protocol false: JSONL was correct but the HTTP /audit/events
endpoint that powers the unified query didn't thread the agent block.
SOC analysts pulling cross-product events got ZERO dbounce events +
wrong `detected_from` on kbouncer.

What this test does:

  1. Starts ibounce + kbouncer + dbounce + gbounce on free 19xxx ports
     (same fleet as the #318 + #312 integration tests).
  2. Mints a single UUID v4-shaped session id.
  3. Fires one request through each bouncer with that session id.
  4. HITS each bouncer's `/audit/events` endpoint directly + asserts
     each response carries the agent block populated correctly with
     `name`, `session_id`, `detected_from`. Pre-§A18 dbounce returned
     zero events + kbouncer returned `detected_from=mcp_clientinfo`
     for http_header-detected requests.
  5. Runs `iam-jit audit query --filter agent.session_id=parity-X`
     using the SHORT-FORM alias (the spec-example shape that
     pre-§A18 returned HTTP 400) + asserts 4 events come back.

Per [[deliberate-feature-completion]] this test ships ALONGSIDE the
per-slice changes. Per [[v1-scope-bar]] it gates pre-launch: if any
bouncer fails to thread the agent block through `/audit/events`, this
test fails + launch is blocked.

Honest gating: the test SKIPS when any bouncer binary isn't on disk
(matches the #318 pattern). On CI it MUST run + MUST pass.
"""

from __future__ import annotations

import contextlib
import json
import os
import socket
import struct
import subprocess
import time
import urllib.request
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import pytest


# ---------- repo / binary paths ----------

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKSPACE_ROOT = REPO_ROOT.parent

GBOUNCE_BIN = WORKSPACE_ROOT / "gbounce" / "bin" / "gbounce"
KBOUNCE_BIN = WORKSPACE_ROOT / "kbouncer" / "bin" / "kbounce"
DBOUNCE_BIN = WORKSPACE_ROOT / "dbounce" / "bin" / "dbounce"
IBOUNCE_BIN = REPO_ROOT / ".venv" / "bin" / "iam-jit-bouncer"


# Fresh test ports — don't collide with the #318 fleet (19767/19766/
# 19765/19763/19080/19769). Adding 100 to each so the two suites can
# run side-by-side.
PORTS = {
    "ibounce":       19867,
    "kbouncer":      19866,
    "dbounce_wire":  19865,
    "dbounce_mgmt":  19863,
    "gbounce_data":  19180,
    "gbounce_mgmt":  19869,
}


# ---------- skip gating ----------


def _have_bin(p: Path) -> bool:
    return p.exists() and os.access(p, os.X_OK)


def _have_tcp(host: str, port: int) -> bool:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.settimeout(0.3)
        try:
            s.connect((host, port))
        except OSError:
            return False
        return True


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not _have_bin(GBOUNCE_BIN), reason=f"missing {GBOUNCE_BIN}"
    ),
    pytest.mark.skipif(
        not _have_bin(KBOUNCE_BIN), reason=f"missing {KBOUNCE_BIN}"
    ),
    pytest.mark.skipif(
        not _have_bin(DBOUNCE_BIN), reason=f"missing {DBOUNCE_BIN}"
    ),
    pytest.mark.skipif(
        not _have_bin(IBOUNCE_BIN), reason=f"missing {IBOUNCE_BIN}"
    ),
]


# ---------- bouncer launcher ----------


@dataclass
class BouncerHandle:
    name: str
    port: int
    mgmt_port: int
    proc: subprocess.Popen
    audit_log: Path
    workdir: Path
    extra: dict = field(default_factory=dict)

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                self.proc.wait()

    def audit_events_url(self) -> str:
        return f"http://127.0.0.1:{self.mgmt_port}/audit/events"


def _wait_for_healthz(url: str, timeout: float = 10.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=0.5) as resp:
                if resp.status in (200, 503):
                    return True
        except Exception:
            time.sleep(0.15)
    return False


def _wait_for_tcp(host: str, port: int, timeout: float = 10.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _have_tcp(host, port):
            return True
        time.sleep(0.15)
    return False


def _start_gbounce(workdir: Path) -> BouncerHandle:
    log = workdir / "gbounce-audit.jsonl"
    db = workdir / "gbounce.db"
    proc = subprocess.Popen(
        [
            str(GBOUNCE_BIN), "run",
            "--port", str(PORTS["gbounce_data"]),
            "--host", "127.0.0.1",
            "--mgmt-port", str(PORTS["gbounce_mgmt"]),
            "--mgmt-host", "127.0.0.1",
            "--allow-connect",
            "--audit-log-path", str(log),
            "--db", str(db),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if not _wait_for_healthz(f"http://127.0.0.1:{PORTS['gbounce_mgmt']}/healthz"):
        proc.terminate()
        proc.wait()
        raise RuntimeError("gbounce failed to come up")
    return BouncerHandle(
        name="gbounce",
        port=PORTS["gbounce_data"],
        mgmt_port=PORTS["gbounce_mgmt"],
        proc=proc, audit_log=log, workdir=workdir,
    )


def _start_ibounce(workdir: Path) -> BouncerHandle:
    log = workdir / "ibounce-audit.jsonl"
    db = workdir / "ibounce.db"
    env = os.environ.copy()
    env["IAM_JIT_BOUNCER_EXTRA_HOSTS"] = "127.0.0.1,host.docker.internal"
    proc = subprocess.Popen(
        [
            str(IBOUNCE_BIN), "run",
            "--port", str(PORTS["ibounce"]),
            "--host", "127.0.0.1",
            "--mode", "transparent",
            "--default-policy", "allow",
            "--upstream", "http://127.0.0.1:4566",
            "--audit-log-path", str(log),
            "--db", str(db),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
    )
    if not _wait_for_healthz(f"http://127.0.0.1:{PORTS['ibounce']}/healthz"):
        proc.terminate()
        proc.wait()
        raise RuntimeError("ibounce failed to come up")
    return BouncerHandle(
        name="ibounce",
        port=PORTS["ibounce"],
        mgmt_port=PORTS["ibounce"],
        proc=proc, audit_log=log, workdir=workdir,
    )


def _start_kbouncer(workdir: Path) -> BouncerHandle:
    log = workdir / "kbouncer-audit.jsonl"
    db = workdir / "kbouncer.db"
    proc = subprocess.Popen(
        [
            str(KBOUNCE_BIN), "run",
            "--port", str(PORTS["kbouncer"]),
            "--host", "127.0.0.1",
            "--mode", "cooperative",
            "--default-policy", "allow",
            "--audit-log-path", str(log),
            "--db", str(db),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if not _wait_for_tcp("127.0.0.1", PORTS["kbouncer"]):
        proc.terminate()
        proc.wait()
        raise RuntimeError("kbouncer failed to come up")
    return BouncerHandle(
        name="kbouncer",
        port=PORTS["kbouncer"],
        mgmt_port=PORTS["kbouncer"],
        proc=proc, audit_log=log, workdir=workdir,
    )


def _start_dbounce(workdir: Path) -> BouncerHandle:
    log = workdir / "dbounce-audit.jsonl"
    db = workdir / "dbounce.db"
    proc = subprocess.Popen(
        [
            str(DBOUNCE_BIN), "run",
            "--port", str(PORTS["dbounce_wire"]),
            "--host", "127.0.0.1",
            "--mgmt-port", str(PORTS["dbounce_mgmt"]),
            "--mgmt-host", "127.0.0.1",
            "--mode", "cooperative",
            "--default-policy", "allow",
            "--dialect", "postgres",
            "--audit-log-path", str(log),
            "--db", str(db),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if not _wait_for_tcp("127.0.0.1", PORTS["dbounce_wire"]):
        proc.terminate()
        proc.wait()
        raise RuntimeError("dbounce failed to come up")
    return BouncerHandle(
        name="dbounce",
        port=PORTS["dbounce_wire"],
        mgmt_port=PORTS["dbounce_mgmt"],
        proc=proc, audit_log=log, workdir=workdir,
    )


# ---------- request helpers ----------


def _fire_http_with_headers(
    url: str, session_id: str, agent_name: str, method: str = "GET",
) -> None:
    """Best-effort HTTP request with X-Agent-* headers."""
    req = urllib.request.Request(url, method=method)
    req.add_header("X-Agent-Name", agent_name)
    req.add_header("X-Agent-Session-Id", session_id)
    req.add_header("User-Agent", "wire-parity-test/1.0")
    try:
        with urllib.request.urlopen(req, timeout=2.0):
            pass
    except Exception:
        pass


def _fire_pg_startup_with_app_name(host: str, port: int, app_name: str) -> None:
    """Send one PG StartupMessage with the supplied application_name."""
    params = (
        b"user\x00tester\x00database\x00postgres\x00"
        b"application_name\x00" + app_name.encode() + b"\x00\x00"
    )
    length = 4 + 4 + len(params)
    msg = struct.pack(">II", length, 196608) + params
    try:
        sock = socket.create_connection((host, port), timeout=2.0)
        try:
            sock.sendall(msg)
            sock.settimeout(0.5)
            try:
                sock.recv(1)
            except Exception:
                pass
        finally:
            sock.close()
    except OSError:
        pass


def _query_audit_events(
    mgmt_url: str, session_id: str, timeout: float = 5.0,
) -> list[dict]:
    """Hit one bouncer's `/audit/events?filter=...` endpoint + parse
    its NDJSON response into a list of OCSF events. Caller filters by
    session_id server-side using the long-form path so each bouncer's
    filter parser sees the canonical OCSF field name."""
    filter_expr = f"unmapped.iam_jit.agent.session_id={session_id}"
    url = (
        f"{mgmt_url}/audit/events"
        f"?limit=100&filter={urllib.parse.quote(filter_expr)}"
    )
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except Exception as e:  # pragma: no cover — surfaces as a clear assertion
        raise RuntimeError(f"/audit/events query failed: {e}") from e
    out: list[dict] = []
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out


# urllib.parse needs to be imported separately for the quote() helper.
import urllib.parse  # noqa: E402


# ---------- the test ----------


def test_audit_events_wire_parity(tmp_path):
    """Launch all four bouncers, fire one request through each with
    the same X-Agent-Session-Id, then HIT each bouncer's HTTP
    `/audit/events` endpoint directly and assert the agent block is
    populated correctly. The §A18 launch-gate.
    """
    workdir = tmp_path / "wire-parity"
    workdir.mkdir()

    session_id = str(uuid.uuid4())
    agent_name = "wire-parity-test"

    handles: list[BouncerHandle] = []
    try:
        handles.append(_start_gbounce(workdir))
        handles.append(_start_kbouncer(workdir))
        handles.append(_start_dbounce(workdir))
        handles.append(_start_ibounce(workdir))

        # Fire one request per bouncer.
        proxy_url = f"http://127.0.0.1:{PORTS['gbounce_data']}"
        proxy_handler = urllib.request.ProxyHandler({
            "http": proxy_url, "https": proxy_url,
        })
        opener = urllib.request.build_opener(proxy_handler)
        req = urllib.request.Request("http://example.invalid/", method="GET")
        req.add_header("X-Agent-Name", agent_name)
        req.add_header("X-Agent-Session-Id", session_id)
        try:
            opener.open(req, timeout=2.0)
        except Exception:
            pass

        _fire_http_with_headers(
            f"http://127.0.0.1:{PORTS['ibounce']}/some-aws-shape",
            session_id, agent_name, method="GET",
        )
        _fire_http_with_headers(
            f"http://127.0.0.1:{PORTS['kbouncer']}/api/v1/namespaces/default/pods",
            session_id, agent_name, method="GET",
        )
        _fire_pg_startup_with_app_name(
            "127.0.0.1", PORTS["dbounce_wire"],
            f"iam-jit-agent:{agent_name}:{session_id}",
        )

        # Give the audit-export channels a moment to flush.
        time.sleep(1.0)

        # §A18 ASSERTION 1: every bouncer's /audit/events HTTP endpoint
        # returns AT LEAST ONE event carrying the session_id under
        # unmapped.iam_jit.agent.session_id. Pre-§A18 dbounce returned
        # zero events (the projection emitted an empty agent block);
        # kbouncer returned events with mis-labelled detected_from.
        per_bouncer_events: dict[str, list[dict]] = {}
        missing: list[str] = []
        for h in handles:
            events = _query_audit_events(
                f"http://127.0.0.1:{h.mgmt_port}", session_id,
            )
            per_bouncer_events[h.name] = events
            if not events:
                missing.append(h.name)

        assert not missing, (
            f"§A18 REGRESSION — /audit/events returned zero events on: "
            f"{missing}. Per-bouncer counts: "
            f"{[(n, len(e)) for n, e in per_bouncer_events.items()]}. "
            f"Session id was {session_id}."
        )

        # §A18 ASSERTION 2: each returned event carries the canonical
        # agent block with the EXACT session_id we sent + a non-empty
        # name + a detected_from consistent with the transport (not
        # the pre-§A18 heuristic that mis-labelled http_header as
        # mcp_clientinfo).
        expected_detected_from = {
            "gbounce":  {"http_header", "http_header_name_only"},
            "ibounce":  {"http_header", "http_header_name_only"},
            "kbouncer": {"http_header", "http_header_name_only"},
            "dbounce":  {"pg_application_name"},
        }
        for name, events in per_bouncer_events.items():
            # The filter was server-side; just take the first match.
            ev = events[0]
            agent = ev.get("unmapped", {}).get("iam_jit", {}).get("agent")
            assert agent, (
                f"{name}: agent block missing from /audit/events "
                f"projection (§A18 regression). Event: {ev}"
            )
            assert agent.get("session_id") == session_id, (
                f"{name}: agent.session_id from /audit/events = "
                f"{agent.get('session_id')!r}, want {session_id!r}"
            )
            assert agent.get("name") in (agent_name, "claude-code", "psql",
                                          "pgcli", "psycopg2", "pg-jdbc",
                                          "unknown"), (
                f"{name}: agent.name from /audit/events = "
                f"{agent.get('name')!r}, want one of {{wire-parity-test, "
                f"known-client, unknown}}"
            )
            assert agent.get("name") == agent_name or name == "dbounce", (
                f"{name}: agent.name from /audit/events = "
                f"{agent.get('name')!r}, want {agent_name!r}"
            )
            allowed = expected_detected_from[name]
            assert agent.get("detected_from") in allowed, (
                f"{name}: agent.detected_from from /audit/events = "
                f"{agent.get('detected_from')!r}, expected one of {allowed} "
                f"(§A18 regression — pre-fix kbouncer mis-labelled "
                f"http_header as mcp_clientinfo)"
            )

        # §A18 ASSERTION 3: the SHORT-FORM filter alias (the spec
        # example shape) returns 4 events through the cross-bouncer
        # CLI. Pre-§A18 the per-bouncer parsers returned HTTP 400 on
        # `agent.session_id=X`; client-side expansion now translates
        # to the canonical long form before forwarding.
        from iam_jit.cli_audit_query import _expand_short_form_filter
        expanded = _expand_short_form_filter(f"agent.session_id={session_id}")
        assert expanded == (
            f"unmapped.iam_jit.agent.session_id={session_id}"
        ), f"short-form expansion failed: {expanded}"

        # End-to-end CLI smoke: invoke iam-jit audit query --filter
        # agent.session_id=X (short form) against all 4 bouncers + assert
        # 4 events come back. Skipped when iam-jit CLI binary not
        # available (matches the test's overall skip-gating philosophy).
        iamjit_bin = REPO_ROOT / ".venv" / "bin" / "iam-jit"
        if iamjit_bin.exists() and os.access(iamjit_bin, os.X_OK):
            bouncer_overrides = [
                f"--bouncer=ibounce=http://127.0.0.1:{PORTS['ibounce']}",
                f"--bouncer=kbounce=http://127.0.0.1:{PORTS['kbouncer']}",
                f"--bouncer=dbounce=http://127.0.0.1:{PORTS['dbounce_mgmt']}",
                f"--bouncer=gbounce=http://127.0.0.1:{PORTS['gbounce_mgmt']}",
            ]
            result = subprocess.run(
                [
                    str(iamjit_bin), "audit", "query",
                    *bouncer_overrides,
                    "--filter", f"agent.session_id={session_id}",
                    "--limit", "100",
                ],
                capture_output=True, text=True, timeout=10.0,
            )
            assert result.returncode == 0, (
                f"iam-jit audit query exited {result.returncode}: "
                f"stderr={result.stderr}"
            )
            # JSONL is one event per line.
            lines = [
                line for line in result.stdout.split("\n") if line.strip()
            ]
            assert len(lines) >= 4, (
                f"iam-jit audit query (short-form) returned {len(lines)} "
                f"events; want ≥4 (one per bouncer). stdout={result.stdout!r} "
                f"stderr={result.stderr!r}"
            )

    finally:
        for h in handles:
            h.stop()
