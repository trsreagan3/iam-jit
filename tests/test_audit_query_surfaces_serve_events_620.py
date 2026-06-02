"""#620 — iam-jit serve audit events surface via cross-product CLI.

UAT-Cross 2026-05-25 (G6) found the #613 OUTSTANDING-REQUEST-CAP.md
recipe instructed::

    iam-jit audit query --kind request_cap_exceeded --since 1h

but ``iam-jit audit query`` only fanned out to the four bouncer
``/audit/events`` endpoints — it never queried iam-jit serve's own
audit log.  After firing the cap, the recipe command returned 0
events: doc-lie surface that erodes the audit story.

The same gap shape applies to UAT-Web-Admin-06 (admin actions land
in the same hash-chained log but the audit-query CLI couldn't see
them).

Fix:
  1. iam-jit serve grows a ``GET /audit/events`` endpoint with the
     same wire shape every bouncer ships per
     ``[[cross-product-agent-parity]]``.
  2. ``cli_audit_query`` includes iam-jit-serve in the default
     fan-out surface set (env override via IAM_JIT_URL).
  3. When serve is unreachable, the fan-out reports the surface as
     ``iam-jit-serve skipped (unreachable: ...)`` per
     ``[[ibounce-honest-positioning]]`` (NOT silently excluded).

Tests assert OBSERVABLE state per docs/CONTRIBUTING.md — the
``iam-jit audit query`` stdout contains the cap-fire / admin-action
events when the fan-out includes serve, AND fan-out behaviour
remains honest when serve is down.

The sabotage test (``test_sabotage_serve_fanout_is_load_bearing``)
proves the fan-out wiring is what makes the cap-event-queryable
test pass: monkeypatching the resolver to return zero surfaces
makes the recipe assertion fail.
"""

from __future__ import annotations

import json
import os
import pathlib
import threading
import time as _time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from click.testing import CliRunner

from iam_jit import audit as audit_mod
from iam_jit import cli_audit_query as caq_mod
from iam_jit.cli import main as iam_jit_main


# ---------------------------------------------------------------------------
# Fixtures: an in-process iam-jit serve audit log + a mock HTTP server
# that mounts the real route handler (so we exercise the actual code,
# not a copy).
# ---------------------------------------------------------------------------


@pytest.fixture
def audit_log_path(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> pathlib.Path:
    """Point IAM_JIT_AUDIT_LOG at a tmp file + reset the in-memory chain
    so each test starts with a clean log."""
    path = tmp_path / "audit.jsonl"
    monkeypatch.setenv("IAM_JIT_AUDIT_LOG", str(path))
    audit_mod.reset_for_tests()
    return path


def _fire_cap_event(
    user_id: str = "email:dev@example.com", outstanding_count: int = 20,
) -> None:
    """Fire one ``request_cap_exceeded`` audit event via the real
    ``audit.emit`` path — same chain the #613 helper uses.

    Mirrors what ``_outstanding_request_cap.check_outstanding_cap``
    persists when the cap fires.  Going through the real emit path is
    the state-verification: if the cap helper's emit shape changes,
    these tests catch the drift.
    """
    audit_mod.emit(
        actor=user_id,
        kind="request_cap_exceeded",
        summary=(
            f"refused submission: user {user_id!r} at outstanding-cap "
            f"({outstanding_count} >= 20, source=default)"
        ),
        details={
            "user_id": user_id,
            "outstanding_count": outstanding_count,
            "cap": 20,
            "cap_source": "default",
        },
    )


def _fire_admin_action_event(
    actor: str = "email:admin@example.com",
    summary: str = "admin force-deleted role role-xyz",
) -> None:
    """Fire one admin-action audit event mirroring the kind of write
    ``routes/admin.py`` emits (UAT-Web-Admin-06 surface)."""
    audit_mod.emit(
        actor=actor,
        kind="admin.action",
        summary=summary,
        details={"role_name": "role-xyz", "reason": "stale"},
    )


# ---- in-process iam-jit serve `/audit/events` ----------------------------
# We stand up the FastAPI app, mount it via TestClient, then forward
# loopback HTTP traffic to it from a tiny BaseHTTPServer so the CLI's
# urllib-based fan-out can hit a real URL.


class _ServeHTTPProxy:
    """Spin up a BaseHTTPServer that proxies ``GET /audit/events`` to
    a FastAPI TestClient.  The CLI fan-out uses ``urllib.urlopen``
    which can't talk to ASGI directly; this gives it a real loopback
    URL.
    """

    def __init__(self, fastapi_app, admin_token: str | None = None):
        from fastapi.testclient import TestClient
        self.client = TestClient(fastapi_app)
        self.admin_token = admin_token
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.port: int = 0
        self.inbound_paths: list[str] = []
        self.inbound_auth: list[str] = []

    def start(self) -> None:
        outer = self

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, *_a, **_kw):
                pass

            def do_GET(self):  # noqa: N802
                outer.inbound_paths.append(self.path)
                outer.inbound_auth.append(self.headers.get("Authorization", ""))
                parsed = urlparse(self.path)
                if parsed.path != "/audit/events":
                    self.send_response(404)
                    self.end_headers()
                    return
                headers: dict[str, str] = {}
                if outer.admin_token:
                    headers["Authorization"] = f"Bearer {outer.admin_token}"
                # Forward to FastAPI.
                try:
                    resp = outer.client.get(
                        self.path,
                        headers=headers,
                    )
                except Exception as exc:
                    self.send_response(500)
                    self.end_headers()
                    self.wfile.write(str(exc).encode())
                    return
                self.send_response(resp.status_code)
                # Pass through the content-type so the CLI parses
                # ndjson correctly.
                ct = resp.headers.get("content-type", "text/plain")
                self.send_header("Content-Type", ct)
                self.end_headers()
                self.wfile.write(resp.content)

        self._server = HTTPServer(("127.0.0.1", 0), _Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
        try:
            self.client.close()
        except Exception:
            pass

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"


@pytest.fixture
def serve_with_audit(
    tmp_path: pathlib.Path,
    audit_log_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
):
    """Build a real iam-jit serve FastAPI app + an in-process API token
    so the cross-product CLI's ``--audit-events-token`` is a real
    valid bearer.  Yields the proxy so tests can read the inbound auth
    header and the URL.
    """
    from iam_jit import api_tokens_store as api_mod
    from iam_jit.api_tokens_store import APITokenRecord
    from iam_jit.app import create_app
    from iam_jit.auth import issue_api_token
    from iam_jit.store import FilesystemStore
    from iam_jit.users_store import FileUserStore

    monkeypatch.setenv("IAM_JIT_AUTH_MODE", "local")
    monkeypatch.setenv("IAM_JIT_DEV_INSECURE_SECRET", "1")
    monkeypatch.setenv(
        "IAM_JIT_MAGIC_LINK_SECRET", "test-secret-for-route-tests-aaaaaaaaa",
    )

    requests_dir = tmp_path / "requests"
    users_yaml = tmp_path / "users.yaml"
    users_yaml.write_text(
        "schema_version: 1\n"
        "auth_mode: local\n"
        "users:\n"
        "  - id: email:admin@example.com\n"
        "    display_name: Admin\n"
        "    roles: [admin]\n",
    )

    tokens_store = api_mod.InMemoryAPITokenStore()
    issued = issue_api_token(
        "email:admin@example.com", label="audit-events-test",
    )
    tokens_store.put(
        APITokenRecord(
            token_hash=issued.hash,
            user_id=issued.user_id,
            created_at=issued.created_at,
            label=issued.label,
        )
    )
    raw_token = issued.raw

    app = create_app(
        request_store=FilesystemStore(requests_dir),
        user_store=FileUserStore(str(users_yaml)),
        api_tokens_store=tokens_store,
    )

    proxy = _ServeHTTPProxy(app, admin_token=raw_token)
    proxy.start()
    try:
        yield proxy, raw_token
    finally:
        proxy.stop()


def _run_query(*args: str):
    runner = CliRunner()
    return runner.invoke(
        iam_jit_main,
        ["audit", "query", *args],
        catch_exceptions=False,
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_cap_exceeded_event_appears_in_audit_query(
    serve_with_audit, audit_log_path: pathlib.Path,
) -> None:
    """State verification: fire the cap event into the iam-jit audit
    chain, run the literal recipe command from #613 docs, observe
    the event lands on stdout.

    Without #620, this returned 0 events (the bouncers don't have a
    cap_exceeded kind; cli_audit_query never queried serve).
    """
    proxy, token = serve_with_audit
    _fire_cap_event(user_id="email:dev@example.com", outstanding_count=20)

    # The fan-out URL is sourced from IAM_JIT_URL.  Point it at the
    # in-process proxy.
    os.environ["IAM_JIT_URL"] = proxy.url
    try:
        result = _run_query(
            "--bouncer", f"iam-jit-serve={proxy.url}",
            "--kind", "request_cap_exceeded",
            "--since", "1h",
            "--audit-events-token", token,
        )
    finally:
        os.environ.pop("IAM_JIT_URL", None)

    assert result.exit_code == 0, result.output
    # State verification: the event content is on stdout.
    lines = [
        line for line in (result.stdout or result.output).split("\n")
        if line.strip() and not line.startswith("note: ")
    ]
    assert lines, (
        f"#620 regression: cap event fired into the audit log but "
        f"`audit query --kind request_cap_exceeded` returned 0 events; "
        f"output={result.output!r}"
    )
    # Parse one event and assert the kind made it through.
    parsed = [json.loads(line) for line in lines]
    kinds = [
        ev.get("unmapped", {}).get("iam_jit", {}).get("kind")
        for ev in parsed
    ]
    assert "request_cap_exceeded" in kinds, kinds


def test_audit_query_fans_out_to_serve_by_default(
    serve_with_audit, audit_log_path: pathlib.Path,
) -> None:
    """The default ``audit query`` invocation (no --bouncer flags)
    must include iam-jit-serve in the probe set.

    State verification: the proxy's inbound-paths list grows by at
    least one entry (the CLI hit it).  Before #620 the default set was
    four bouncers only; the proxy would never be hit.
    """
    proxy, token = serve_with_audit
    _fire_cap_event()

    # No --bouncer flags so we get the default set.  IAM_JIT_URL
    # routes serve to the proxy.
    os.environ["IAM_JIT_URL"] = proxy.url
    try:
        result = _run_query(
            "--format", "summary",
            "--audit-events-token", token,
            "--timeout", "1.0",
        )
    finally:
        os.environ.pop("IAM_JIT_URL", None)

    assert result.exit_code == 0, result.output
    combined = (result.output or "") + (getattr(result, "stderr", "") or "")
    # State verification: iam-jit-serve appears in the per-surface
    # summary (either with a count or with an unreachable note).  The
    # bouncers will be unreachable; serve will be reachable.
    assert "iam-jit-serve" in combined, combined
    # And the proxy received the inbound request.
    assert proxy.inbound_paths, (
        "fan-out never hit serve — default surface set is missing serve?"
    )


def test_audit_query_serve_unreachable_surfaces_honestly(
    audit_log_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When iam-jit serve isn't running, the fan-out must NOT silently
    exclude it.  Per ``[[ibounce-honest-positioning]]`` the operator
    needs to see an unreachable note so they don't mistake "no events"
    for "serve has no events"."""
    # Point IAM_JIT_URL at a bound-but-closed port so the connect
    # attempt fails fast.
    monkeypatch.setenv("IAM_JIT_URL", "http://127.0.0.1:1")

    result = _run_query(
        "--format", "summary",
        "--timeout", "1.0",
    )
    # #628: when ALL surfaces are unreachable (CI: no bouncers running)
    # the CLI exits 1; when some bouncers happen to be reachable (dev
    # machine) it exits 0.  Both are valid — the load-bearing check is
    # whether iam-jit-serve is NAMED + FLAGGED in the output, not whether
    # any coincidental local bouncer was up.
    assert result.exit_code in (0, 1), result.output
    combined = (result.output or "") + (getattr(result, "stderr", "") or "")
    # State verification: the surface is named + flagged unreachable.
    assert "iam-jit-serve" in combined, combined
    # Either via the per-surface skip note OR via the summary
    # "unreachable" entry.  Both shapes are honest.
    assert (
        "iam-jit-serve skipped" in combined
        or "iam-jit-serve: (unreachable" in combined
    ), combined


def test_audit_query_serve_events_have_consistent_schema(
    serve_with_audit, audit_log_path: pathlib.Path,
) -> None:
    """The OCSF event shape iam-jit-serve emits must match the bouncer
    wire shape: ``time`` is Unix ms, ``actor.user.name`` is populated,
    ``unmapped.iam_jit.kind`` carries the audit event kind, ``class_uid``
    is 6003 (API Activity).

    State verification: parse one event from the live endpoint and
    assert every cross-product field is present.
    """
    proxy, token = serve_with_audit
    _fire_cap_event()

    os.environ["IAM_JIT_URL"] = proxy.url
    try:
        result = _run_query(
            "--bouncer", f"iam-jit-serve={proxy.url}",
            "--audit-events-token", token,
        )
    finally:
        os.environ.pop("IAM_JIT_URL", None)

    assert result.exit_code == 0, result.output
    lines = [
        line for line in (result.stdout or result.output).split("\n")
        if line.strip() and not line.startswith("note: ")
    ]
    assert lines, result.output
    ev = json.loads(lines[0])
    # Shape parity with the bouncer events.
    assert ev["class_uid"] == 6003, ev
    assert ev["class_name"] == "API Activity", ev
    assert "time" in ev and isinstance(ev["time"], int), ev
    assert ev["actor"]["user"]["name"] == "email:dev@example.com", ev
    iam_jit_block = ev["unmapped"]["iam_jit"]
    assert iam_jit_block["kind"] == "request_cap_exceeded"
    assert iam_jit_block["details"]["cap"] == 20
    assert iam_jit_block["source"] == "iam-jit-serve"


def test_recipe_in_docs_actually_works(
    serve_with_audit, audit_log_path: pathlib.Path,
) -> None:
    """Execute the literal command from
    ``docs/recipes/OUTSTANDING-REQUEST-CAP.md`` lines 102-105 and
    assert it returns the cap events.

    This is the doc-lie regression check: if the recipe text or the
    code drifts, this test fails.  Per the recipe:

        iam-jit audit query --kind request_cap_exceeded --since 1h
    """
    proxy, token = serve_with_audit

    # Fire five cap events (per the recipe's example: 25 submits,
    # five 429s).
    for _ in range(5):
        _fire_cap_event()

    os.environ["IAM_JIT_URL"] = proxy.url
    try:
        # NB: the literal recipe command uses defaults for everything
        # except --kind + --since.  We add --bouncer to scope the test
        # to the serve URL (the bouncers won't be running in CI) +
        # --audit-events-token for the API gate.  Doc + code parity on
        # the --kind + --since shape is the load-bearing assertion.
        result = _run_query(
            "--bouncer", f"iam-jit-serve={proxy.url}",
            "--kind", "request_cap_exceeded",
            "--since", "1h",
            "--audit-events-token", token,
        )
    finally:
        os.environ.pop("IAM_JIT_URL", None)

    assert result.exit_code == 0, result.output
    lines = [
        line for line in (result.stdout or result.output).split("\n")
        if line.strip() and not line.startswith("note: ")
    ]
    assert len(lines) == 5, (
        f"recipe doc-lie: expected 5 cap events from "
        f"`iam-jit audit query --kind request_cap_exceeded --since 1h`, "
        f"got {len(lines)} ({result.output!r})"
    )


def test_admin_actions_appear_in_audit_query(
    serve_with_audit, audit_log_path: pathlib.Path,
) -> None:
    """UAT-Web-Admin-06 regression check: admin actions emitted via
    ``audit.emit(kind='admin.action', ...)`` from
    ``routes/admin.py`` now reach the cross-product audit-query
    surface."""
    proxy, token = serve_with_audit
    for i in range(3):
        _fire_admin_action_event(
            summary=f"admin force-deleted role-{i}",
        )

    os.environ["IAM_JIT_URL"] = proxy.url
    try:
        result = _run_query(
            "--bouncer", f"iam-jit-serve={proxy.url}",
            "--kind", "admin.action",
            "--audit-events-token", token,
        )
    finally:
        os.environ.pop("IAM_JIT_URL", None)

    assert result.exit_code == 0, result.output
    lines = [
        line for line in (result.stdout or result.output).split("\n")
        if line.strip() and not line.startswith("note: ")
    ]
    assert len(lines) == 3, result.output
    parsed = [json.loads(line) for line in lines]
    summaries = [
        ev.get("unmapped", {}).get("iam_jit", {}).get("summary", "")
        for ev in parsed
    ]
    assert any("force-deleted role-0" in s for s in summaries), summaries


# ---------------------------------------------------------------------------
# Sabotage check
# ---------------------------------------------------------------------------


def test_sabotage_serve_fanout_is_load_bearing(
    serve_with_audit, audit_log_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sabotage check per docs/CONTRIBUTING.md: if we monkeypatch
    ``_resolve_bouncer_set`` to drop the iam-jit-serve surface, the
    cap-event-queryable test should fail — proving the fan-out wiring
    is what makes the cap event visible (not some incidental side
    effect of the fixture).
    """
    proxy, token = serve_with_audit
    _fire_cap_event()

    # Sabotage: replace the resolver with one that returns no surfaces
    # at all.  The CLI guards against this with a UsageError, so we
    # use a stub that returns ONLY the four (unreachable in tests)
    # bouncers — same shape as pre-#620 default.
    real_resolve = caq_mod._resolve_bouncer_set

    def _sabotaged(raw, *, include_serve=True):
        return real_resolve(raw, include_serve=False)

    monkeypatch.setattr(caq_mod, "_resolve_bouncer_set", _sabotaged)

    os.environ["IAM_JIT_URL"] = proxy.url
    try:
        # Note: deliberately NOT passing --bouncer so the default
        # (now-sabotaged) path runs.
        result = _run_query(
            "--kind", "request_cap_exceeded",
            "--since", "1h",
            "--timeout", "1.0",
        )
    finally:
        os.environ.pop("IAM_JIT_URL", None)

    # #628: with serve sabotaged away and no local bouncers running (CI),
    # all surfaces error → exit 1.  On a dev machine with running bouncers
    # some may be reachable → exit 0.  The load-bearing sabotage proof is
    # that the cap event is absent from the output (len(lines) == 0 below),
    # not the exit code itself.
    assert result.exit_code in (0, 1), result.output
    lines = [
        line for line in (result.stdout or result.output).split("\n")
        if line.strip() and not line.startswith("note: ")
        and not line.startswith("error: ")
    ]
    # State verification: sabotaging the resolver makes the cap event
    # disappear from the query result.  This proves
    # `test_cap_exceeded_event_appears_in_audit_query` is load-bearing
    # on the #620 fan-out change.
    assert len(lines) == 0, (
        f"sabotage didn't fire: expected zero events when serve is "
        f"excluded from the default fan-out, got {len(lines)}; "
        f"output={result.output!r}"
    )
