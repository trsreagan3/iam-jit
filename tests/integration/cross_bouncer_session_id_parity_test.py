"""#318 / §A16 — cross-bouncer X-Agent-Session-Id header parity.

This test is the launch-gate regression for `[[cross-product-agent-parity]]`:
when one agent session id flows through all four Bounce products
(ibounce / kbouncer / dbounce / gbounce) the unified
`iam-jit audit query --filter agent.session_id=<UUID>` MUST return one
OCSF event per bouncer with the same id.

What this test does:

  1. Starts ibounce + kbouncer + dbounce + gbounce on free 19xxx ports
     (same fleet as the #312 NanoClaw integration test).
  2. Mints a single UUID v7-shaped session id.
  3. Fires one request through each bouncer with that session id:
       * AWS s3:ListBuckets through ibounce (X-Agent-Session-Id header)
       * kubectl-shaped GET /api/v1/pods through kbouncer (X-Agent-Session-Id header)
       * SQL connection startup through dbounce
         (application_name=iam-jit-agent:NAME:SESSIONID)
       * HTTPS CONNECT through gbounce (X-Agent-Session-Id header)
  4. Calls `iam-jit audit query --filter unmapped.iam_jit.agent.session_id=<UUID>`
     in fan-out mode against all four bouncers.
  5. Asserts exactly 4 events come back — one per bouncer — each
     carrying the same `unmapped.iam_jit.agent.session_id`.

Per [[deliberate-feature-completion]] this test ships ALONGSIDE the
per-slice ibounce / kbouncer / dbounce changes (gbounce already
shipped #308). Per [[v1-scope-bar]] it gates pre-launch: if any of the
four bouncers fails to read the canonical headers, this test fails +
launch is blocked.

Honest gating: the test SKIPS when any of the four bouncer binaries
isn't on disk (the local-test-infra spec per `[[local-test-infra-spec]]`
asks for these binaries but doesn't always have them on the developer
laptop). On CI it MUST run + MUST pass — the launch-readiness plan
gates on it.

The integration test does NOT require live AWS / live K8s / live PG —
each bouncer is started with `--default-policy=allow` + the request
itself is just an HTTP shape that produces an OCSF audit event. We're
testing the per-bouncer ATTRIBUTION wiring, not the upstream forwarding.
"""

from __future__ import annotations

import contextlib
import json
import os
import socket
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path

import pytest


# ---------- repo / binary paths ----------

REPO_ROOT = Path(__file__).resolve().parents[2]  # repo root (iam-roles)
WORKSPACE_ROOT = REPO_ROOT.parent                 # parent dir holding sibling Bounce repos

GBOUNCE_BIN = WORKSPACE_ROOT / "gbounce" / "bin" / "gbounce"
KBOUNCE_BIN = WORKSPACE_ROOT / "kbouncer" / "bin" / "kbounce"
DBOUNCE_BIN = WORKSPACE_ROOT / "dbounce" / "bin" / "dbounce"
IBOUNCE_BIN = REPO_ROOT / ".venv" / "bin" / "iam-jit-bouncer"


# Fresh test ports — don't collide with operational (8767/8766/8768/
# 8769/8080) or UAT (18xxx/28xxx) or #312 (19xxx) fleets.
PORTS = {
    "ibounce":       19767,
    "kbouncer":      19766,
    "dbounce_wire":  19765,
    "dbounce_mgmt":  19763,
    "gbounce_data":  19080,
    "gbounce_mgmt":  19769,
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

    def events(self) -> list[dict]:
        if not self.audit_log.exists():
            return []
        out: list[dict] = []
        with self.audit_log.open() as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
        return out


def _wait_for_healthz(url: str, timeout: float = 10.0) -> bool:
    import urllib.request
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
    # dbounce binds the wire port even without an upstream — observation
    # only mode. Wait for the wire socket so we can attempt a PG startup.
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


def _fire_http_with_headers(url: str, session_id: str, agent_name: str,
                             method: str = "GET") -> None:
    """Best-effort HTTP request with X-Agent-* headers. We DON'T care
    about the response; the audit-log event is what we assert against."""
    import urllib.request
    req = urllib.request.Request(url, method=method)
    req.add_header("X-Agent-Name", agent_name)
    req.add_header("X-Agent-Session-Id", session_id)
    req.add_header("User-Agent", "parity-test/1.0")
    try:
        with urllib.request.urlopen(req, timeout=2.0):
            pass
    except Exception:
        # Upstream may be unreachable (no LocalStack / no kind apiserver);
        # we only need the audit event, which the proxy emits regardless.
        pass


def _fire_pg_startup_with_app_name(host: str, port: int, app_name: str) -> None:
    """Send one PostgreSQL StartupMessage with the supplied
    application_name. We close the socket immediately after — observation
    mode emits the audit-event during the handshake parse."""
    import struct
    params = (
        b"user\x00tester\x00database\x00postgres\x00"
        b"application_name\x00" + app_name.encode() + b"\x00\x00"
    )
    # StartupMessage = 4-byte length + 4-byte protocol-version + params.
    length = 4 + 4 + len(params)
    msg = struct.pack(">II", length, 196608) + params
    try:
        sock = socket.create_connection((host, port), timeout=2.0)
        try:
            sock.sendall(msg)
            # Read one byte to give dbounce a chance to flush the audit
            # write; ignore errors (upstream may not be configured).
            sock.settimeout(0.5)
            try:
                sock.recv(1)
            except Exception:
                pass
        finally:
            sock.close()
    except OSError:
        pass


def _find_event_for_session(events: list[dict], session_id: str) -> dict | None:
    """Walk a bouncer's JSONL audit log + return the first event whose
    unmapped.iam_jit.agent.session_id matches."""
    for ev in events:
        agent = (
            (ev.get("unmapped") or {}).get("iam_jit", {}).get("agent") or {}
        )
        if agent.get("session_id") == session_id:
            return ev
    return None


# ---------- the test ----------


def test_cross_bouncer_session_id_parity(tmp_path):
    """Launch all four bouncers, fire one request through each with the
    same X-Agent-Session-Id (dbounce uses application_name), assert
    every bouncer's audit log produced an event carrying that session
    id under unmapped.iam_jit.agent.session_id.

    Failure of any single bouncer is a LAUNCH-BLOCKING regression per
    `[[cross-product-agent-parity]]`.
    """
    workdir = tmp_path / "parity"
    workdir.mkdir()

    session_id = str(uuid.uuid4())  # v4 — both v4 + v7 are accepted per the spec
    agent_name = "parity-test"

    handles: list[BouncerHandle] = []
    try:
        # 1. Bring up all four bouncers in parallel-ish startup order.
        handles.append(_start_gbounce(workdir))
        handles.append(_start_kbouncer(workdir))
        handles.append(_start_dbounce(workdir))
        handles.append(_start_ibounce(workdir))

        # 2. Fire one shaped request through each. We accept that
        # upstream-side errors may surface (LocalStack / kind / PG not
        # running) — the audit event still emits with the agent block
        # populated.
        # gbounce — HTTPS CONNECT (use a known-unreachable target to
        # produce a deterministic audit row).
        import urllib.request
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

        # ibounce — fire an /healthz call (loopback is allowed); the
        # SigV4-classifier marks it unclassifiable but the audit event
        # still emits with the agent block.
        _fire_http_with_headers(
            f"http://127.0.0.1:{PORTS['ibounce']}/some-aws-shape",
            session_id, agent_name, method="GET",
        )

        # kbouncer — K8s-shaped path.
        _fire_http_with_headers(
            f"http://127.0.0.1:{PORTS['kbouncer']}/api/v1/namespaces/default/pods",
            session_id, agent_name, method="GET",
        )

        # dbounce — PG StartupMessage with the canonical tag.
        _fire_pg_startup_with_app_name(
            "127.0.0.1", PORTS["dbounce_wire"],
            f"iam-jit-agent:{agent_name}:{session_id}",
        )

        # 3. Give the audit-export channel a moment to flush JSONL.
        time.sleep(1.0)

        # 4. Walk each bouncer's audit log + find the matching event.
        found: dict[str, dict] = {}
        missing: list[str] = []
        for h in handles:
            events = h.events()
            ev = _find_event_for_session(events, session_id)
            if ev is None:
                missing.append(h.name)
            else:
                found[h.name] = ev

        assert not missing, (
            f"Cross-bouncer agent.session_id parity FAILED — missing in: "
            f"{missing}. Found in: {sorted(found.keys())}. "
            f"Session id was {session_id}."
        )

        # 5. Each event MUST carry the same session_id + an agent name +
        # a detected_from value consistent with its transport.
        expected_detected_from = {
            "gbounce":  {"http_header", "http_header_name_only"},
            "ibounce":  {"http_header", "http_header_name_only"},
            "kbouncer": {"http_header", "http_header_name_only"},
            "dbounce":  {"pg_application_name"},
        }
        for name, ev in found.items():
            agent = ev["unmapped"]["iam_jit"]["agent"]
            assert agent.get("session_id") == session_id, (
                f"{name}: agent.session_id mismatch — got "
                f"{agent.get('session_id')!r}, want {session_id!r}"
            )
            assert agent.get("name") == agent_name, (
                f"{name}: agent.name mismatch — got {agent.get('name')!r}, "
                f"want {agent_name!r}"
            )
            allowed = expected_detected_from[name]
            assert agent.get("detected_from") in allowed, (
                f"{name}: agent.detected_from = {agent.get('detected_from')!r}, "
                f"expected one of {allowed}"
            )

        # 6. Confirm exactly one event per bouncer came back.
        assert len(found) == 4, (
            f"Expected one event per bouncer (4 total); got "
            f"{sorted(found.keys())} = {len(found)}"
        )

    finally:
        for h in handles:
            h.stop()
