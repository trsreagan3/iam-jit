"""Tests for `bouncer prompts` — synchronous deny-prompt UX (#203 v1.1).

Sync means: agent's request BLOCKS on a transparent-mode DENY until
either the operator answers via `ibounce prompts answer` (the proxy
then forwards to upstream + returns upstream's response on allow, OR
returns the original 403 on deny) OR the configured timeout fires
(the configured `--sync-prompt-default` decision applies).

Per [[ibounce-honest-positioning]]: this is a DETERRENT UX for
legitimate human-in-loop, not adversarial defense. Per
[[creates-never-mutates]]: nothing AWS-side is mutated.

Covers:
- store: `add_sync_pending_prompt` returns (prompt_id, sync_wait_id)
- store: `add_sync_pending_prompt` is idempotent on decision_id
- store: `list_waiting_sync_prompts` filters to in-process registered ids
- proxy registry: `register_sync_wait` / `wake_sync_pending_prompt` /
  `unregister_sync_wait` round-trip
- proxy registry: `wake_sync_pending_prompt` validates decision arg
- proxy registry: wake on unregistered id returns False (no crash)
- proxy sync path: operator answers allow -> upstream response returned
- proxy sync path: operator answers ignore (deny) -> original 403
- proxy sync path: no answer + timeout -> default-deny applied
- proxy sync path: no answer + timeout + --sync-prompt-default=allow ->
  upstream response returned
- proxy sync path: pause active -> sync prompt does NOT fire (already
  bypassed by the existing pause-supersedes-mode logic)
- proxy sync path: cooperative-mode DENY does NOT trigger sync
  (cooperative DENY is advisory; blocking would be nonsense)
- CLI: --sync-prompt-on-deny + --prompt-on-deny rejected at parse time
- CLI: --sync-prompt-timeout out-of-range rejected at parse time
- CLI: prompts answer wakes the registered slot (kind=always -> allow;
  kind=ignore -> deny)
- MCP: bouncer_pending_sync_prompts returns the waiting set
- MCP: ibounce_pending_sync_prompts alias works
- MCP: bouncer_pending_sync_prompts in tools/list
"""

from __future__ import annotations

import asyncio
import socket

import pytest

from iam_jit.bouncer.decisions import DefaultPolicy
from iam_jit.bouncer.proxy import (
    ProxyConfig,
    ProxyMode,
    _registered_sync_wait_ids,
    _reset_sync_wait_registry_for_tests,
    register_sync_wait,
    serve,
    unregister_sync_wait,
    wake_sync_pending_prompt,
)
from iam_jit.bouncer.rules import Effect, ProxyRule
from iam_jit.bouncer.store import BouncerStore


@pytest.fixture(autouse=True)
def _clean_sync_wait_registry():
    """Per-test reset so a leftover slot from one test can't bleed
    into the next + change `_registered_sync_wait_ids()` results."""
    _reset_sync_wait_registry_for_tests()
    yield
    _reset_sync_wait_registry_for_tests()


def _sigv4(*, service: str, region: str) -> str:
    return (
        "AWS4-HMAC-SHA256 "
        f"Credential=AKIAEXAMPLE/20260518/{region}/{service}/aws4_request, "
        "SignedHeaders=host;x-amz-date, "
        "Signature=fake"
    )


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


# ---------------------------------------------------------------------------
# Store unit tests
# ---------------------------------------------------------------------------


def test_add_sync_pending_prompt_returns_id_and_uuid(tmp_path) -> None:
    """The store helper returns both the new row id AND the freshly-
    minted sync_wait_id UUID. The UUID is what the proxy registers in
    its in-process wakeup dict."""
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    try:
        prompt_id, sync_wait_id = store.add_sync_pending_prompt(
            decision_id=42, service="s3", action="GetObject",
            arn="arn:aws:s3:::b/k", region="us-east-1",
            deny_reason="rule denied",
        )
        assert prompt_id > 0
        assert isinstance(sync_wait_id, str)
        # UUID4 hex is 32 chars
        assert len(sync_wait_id) == 32
        row = store.get_pending_prompt(prompt_id)
        assert row is not None
        assert row["sync_wait_id"] == sync_wait_id
        assert row["status"] == "pending"
    finally:
        store.close()


def test_add_sync_pending_prompt_idempotent_on_decision_id(tmp_path) -> None:
    """Calling twice with the same decision_id returns the same
    (prompt_id, sync_wait_id) — matches `add_pending_prompt`'s
    contract so a retried request doesn't enqueue twice."""
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    try:
        a = store.add_sync_pending_prompt(
            decision_id=1, service="s3", action="GetObject",
            arn=None, region=None, deny_reason="t",
        )
        b = store.add_sync_pending_prompt(
            decision_id=1, service="s3", action="GetObject",
            arn=None, region=None, deny_reason="t",
        )
        assert a == b
    finally:
        store.close()


def test_add_sync_pending_prompt_upgrades_existing_async_row(tmp_path) -> None:
    """If an async deny-prompt already exists for a decision_id (no
    sync_wait_id), the sync helper UPDATES it with a fresh UUID
    rather than creating a duplicate. Operationally rare but well-
    defined; without this an operator switching mid-session from
    --prompt-on-deny to --sync-prompt-on-deny would see ghost rows."""
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    try:
        async_pid = store.add_pending_prompt(
            decision_id=7, service="s3", action="GetObject",
            arn=None, region=None, deny_reason="t",
        )
        sync_pid, wait_id = store.add_sync_pending_prompt(
            decision_id=7, service="s3", action="GetObject",
            arn=None, region=None, deny_reason="t",
        )
        assert sync_pid == async_pid  # same row, in-place upgrade
        row = store.get_pending_prompt(sync_pid)
        assert row["sync_wait_id"] == wait_id
    finally:
        store.close()


def test_list_waiting_sync_prompts_filters_to_registered(tmp_path) -> None:
    """The MCP introspection tool surface filters DB rows to those
    whose sync_wait_id is currently registered in the proxy's
    in-process dict — so a stale row from a crashed proxy doesn't
    appear waiting forever."""
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    try:
        _, wid_a = store.add_sync_pending_prompt(
            decision_id=1, service="s3", action="GetObject",
            arn=None, region=None, deny_reason="t",
        )
        _, wid_b = store.add_sync_pending_prompt(
            decision_id=2, service="s3", action="PutObject",
            arn=None, region=None, deny_reason="t",
        )
        # With no filter -> both visible (raw DB query)
        rows = store.list_waiting_sync_prompts()
        wait_ids = {r["sync_wait_id"] for r in rows}
        assert wait_ids == {wid_a, wid_b}
        # With filter to just wid_a -> only that row
        rows = store.list_waiting_sync_prompts(sync_wait_ids=[wid_a])
        assert len(rows) == 1
        assert rows[0]["sync_wait_id"] == wid_a
        # Empty filter -> empty list (no rows match)
        assert store.list_waiting_sync_prompts(sync_wait_ids=[]) == []
    finally:
        store.close()


def test_list_waiting_sync_prompts_excludes_answered(tmp_path) -> None:
    """Once answered, a row drops out of `waiting`."""
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    try:
        pid, _ = store.add_sync_pending_prompt(
            decision_id=1, service="s3", action="GetObject",
            arn=None, region=None, deny_reason="t",
        )
        assert len(store.list_waiting_sync_prompts()) == 1
        store.answer_pending_prompt(
            pid, answer_kind="ignore", answer_target=None, answered_by="t",
        )
        assert store.list_waiting_sync_prompts() == []
    finally:
        store.close()


# ---------------------------------------------------------------------------
# Proxy wakeup registry unit tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_register_and_wake_round_trip() -> None:
    """register_sync_wait + wake_sync_pending_prompt signal the Event +
    surface the decision to the awaiting coroutine."""
    slot = register_sync_wait("test-wid-1")
    try:
        wake_task = asyncio.create_task(
            asyncio.to_thread(
                wake_sync_pending_prompt,
                "test-wid-1",
                decision="allow",
                answered_by="alice",
                answer_kind="always",
            ),
        )
        await asyncio.wait_for(slot.event.wait(), timeout=2.0)
        woken = await wake_task
        assert woken is True
        assert slot.decision == "allow"
        assert slot.answered_by == "alice"
        assert slot.answer_kind == "always"
    finally:
        unregister_sync_wait("test-wid-1")


def test_wake_unregistered_returns_false() -> None:
    """Wake on a slot that was never registered (or already
    unregistered after a timeout) returns False — never crashes."""
    assert wake_sync_pending_prompt(
        "no-such-wid", decision="allow",
    ) is False


def test_wake_validates_decision_arg() -> None:
    register_sync_wait("test-wid-bogus")
    try:
        with pytest.raises(ValueError, match="allow"):
            wake_sync_pending_prompt(
                "test-wid-bogus", decision="maybe",
            )
    finally:
        unregister_sync_wait("test-wid-bogus")


def test_register_idempotent_returns_same_slot() -> None:
    a = register_sync_wait("test-wid-dup")
    b = register_sync_wait("test-wid-dup")
    try:
        assert a is b
    finally:
        unregister_sync_wait("test-wid-dup")


def test_registered_ids_reflects_state() -> None:
    register_sync_wait("a")
    register_sync_wait("b")
    try:
        ids = set(_registered_sync_wait_ids())
        assert ids == {"a", "b"}
    finally:
        unregister_sync_wait("a")
        unregister_sync_wait("b")
    assert _registered_sync_wait_ids() == []


# ---------------------------------------------------------------------------
# Proxy E2E: full HTTP round-trip with sync deny-prompt
# ---------------------------------------------------------------------------


class _MockAWS:
    def __init__(self) -> None:
        self.port = _free_port()
        self.received_requests: list[dict] = []
        self.next_response_status = 200
        self.next_response_body = b'{"status":"ok"}'
        self.next_response_headers: dict[str, str] = {
            "content-type": "application/json",
        }
        self._runner = None

    async def start(self) -> None:
        from aiohttp import web

        async def handler(request):
            body = await request.read()
            self.received_requests.append({
                "method": request.method, "path": request.path_qs,
                "headers": dict(request.headers), "body": body,
            })
            return web.Response(
                body=self.next_response_body,
                status=self.next_response_status,
                headers=self.next_response_headers,
            )

        app = web.Application()
        app.router.add_route("*", "/{tail:.*}", handler)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        site = web.TCPSite(self._runner, "127.0.0.1", self.port)
        await site.start()

    async def stop(self) -> None:
        if self._runner is not None:
            await self._runner.cleanup()


async def _wait_for_listen(host: str, port: int, *, retries: int = 50) -> None:
    for _ in range(retries):
        try:
            reader, writer = await asyncio.open_connection(host, port)
            writer.close()
            await writer.wait_closed()
            return
        except OSError:
            await asyncio.sleep(0.05)
    raise RuntimeError(f"nothing listening on {host}:{port}")


@pytest.mark.asyncio
async def test_sync_deny_prompt_answered_allow_forwards_to_upstream(
    tmp_path,
) -> None:
    """Full HTTP round-trip. Proxy with --sync-prompt-on-deny in
    transparent mode. Client makes a GET that has NO matching rule
    (so verdict = default-deny). Proxy enqueues the sync prompt +
    blocks. Operator answers ALLOW via the store's wake API. Proxy
    forwards to upstream + returns the upstream response verbatim.
    """
    backend = _MockAWS()
    await backend.start()
    backend.next_response_status = 201
    backend.next_response_body = b'{"upstream":"ok"}'
    try:
        store = BouncerStore(db_path=str(tmp_path / "b.db"))
        proxy_port = _free_port()
        config = ProxyConfig(
            host="127.0.0.1", port=proxy_port,
            mode=ProxyMode.TRANSPARENT,
            default_policy=DefaultPolicy.DENY,
            forward_scheme="http",
            sync_prompt_on_deny=True,
            sync_prompt_timeout_seconds=5,
            sync_prompt_default_decision="deny",
        )
        server_task = asyncio.create_task(serve(config, store=store))
        try:
            await _wait_for_listen("127.0.0.1", proxy_port)
            import aiohttp

            async def operator_answers_after_brief_delay():
                # Wait long enough for the proxy to enqueue the row +
                # register the slot, then look up the wait_id from the
                # DB and wake it. Polling-based so we don't race on
                # the exact moment of register.
                for _ in range(50):
                    rows = store.list_waiting_sync_prompts(
                        sync_wait_ids=_registered_sync_wait_ids(),
                    )
                    if rows:
                        wake_sync_pending_prompt(
                            rows[0]["sync_wait_id"],
                            decision="allow",
                            answered_by="alice",
                            answer_kind="always",
                        )
                        store.answer_pending_prompt(
                            rows[0]["id"], answer_kind="always",
                            answer_target=None, answered_by="alice",
                        )
                        return
                    await asyncio.sleep(0.02)
                raise AssertionError(
                    "operator never observed a waiting prompt to answer"
                )

            asyncio.create_task(operator_answers_after_brief_delay())

            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"http://127.0.0.1:{proxy_port}/some/path",
                    headers={
                        "host": f"127.0.0.1:{backend.port}",
                        "authorization": _sigv4(
                            service="s3", region="us-east-1",
                        ),
                    },
                ) as resp:
                    body = await resp.read()
                    resp_headers = dict(resp.headers)
            assert resp.status == 201
            assert body == b'{"upstream":"ok"}'
            assert resp_headers.get("x-iam-jit-bouncer-sync") == "allow"
            assert len(backend.received_requests) == 1
        finally:
            server_task.cancel()
            try:
                await server_task
            except asyncio.CancelledError:
                pass
            store.close()
    finally:
        await backend.stop()


@pytest.mark.asyncio
async def test_sync_deny_prompt_answered_deny_returns_403(tmp_path) -> None:
    """Operator answers IGNORE (deny) -> proxy returns the original
    403 + does NOT forward to upstream."""
    backend = _MockAWS()
    await backend.start()
    try:
        store = BouncerStore(db_path=str(tmp_path / "b.db"))
        proxy_port = _free_port()
        config = ProxyConfig(
            host="127.0.0.1", port=proxy_port,
            mode=ProxyMode.TRANSPARENT,
            default_policy=DefaultPolicy.DENY,
            forward_scheme="http",
            sync_prompt_on_deny=True,
            sync_prompt_timeout_seconds=5,
        )
        server_task = asyncio.create_task(serve(config, store=store))
        try:
            await _wait_for_listen("127.0.0.1", proxy_port)
            import aiohttp

            async def operator_denies():
                for _ in range(50):
                    rows = store.list_waiting_sync_prompts(
                        sync_wait_ids=_registered_sync_wait_ids(),
                    )
                    if rows:
                        wake_sync_pending_prompt(
                            rows[0]["sync_wait_id"],
                            decision="deny",
                            answered_by="alice", answer_kind="ignore",
                        )
                        return
                    await asyncio.sleep(0.02)

            asyncio.create_task(operator_denies())
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"http://127.0.0.1:{proxy_port}/x",
                    headers={
                        "host": f"127.0.0.1:{backend.port}",
                        "authorization": _sigv4(
                            service="s3", region="us-east-1",
                        ),
                    },
                ) as resp:
                    body = await resp.json()
            assert resp.status == 403
            assert body["error"] == "ibounce DENY"
            assert backend.received_requests == []
        finally:
            server_task.cancel()
            try:
                await server_task
            except asyncio.CancelledError:
                pass
            store.close()
    finally:
        await backend.stop()


@pytest.mark.asyncio
async def test_sync_deny_prompt_timeout_applies_default_deny(tmp_path) -> None:
    """No operator answer + timeout fires + --sync-prompt-default=deny
    -> original 403 returned. The timeout window is tiny (1s) so the
    test stays fast."""
    backend = _MockAWS()
    await backend.start()
    try:
        store = BouncerStore(db_path=str(tmp_path / "b.db"))
        proxy_port = _free_port()
        config = ProxyConfig(
            host="127.0.0.1", port=proxy_port,
            mode=ProxyMode.TRANSPARENT,
            default_policy=DefaultPolicy.DENY,
            forward_scheme="http",
            sync_prompt_on_deny=True,
            sync_prompt_timeout_seconds=5,  # CLI floor is 5; matches range
            sync_prompt_default_decision="deny",
        )
        # Override AFTER construction is forbidden (frozen dataclass);
        # but we want a fast timeout. Rebuild with a 1s timeout — the
        # CLI range check is at parse time only; the dataclass itself
        # accepts any int. (This is intentional — tests need short
        # timeouts; production gets the CLI gate.)
        config = ProxyConfig(
            host="127.0.0.1", port=proxy_port,
            mode=ProxyMode.TRANSPARENT,
            default_policy=DefaultPolicy.DENY,
            forward_scheme="http",
            sync_prompt_on_deny=True,
            sync_prompt_timeout_seconds=1,
            sync_prompt_default_decision="deny",
        )
        server_task = asyncio.create_task(serve(config, store=store))
        try:
            await _wait_for_listen("127.0.0.1", proxy_port)
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"http://127.0.0.1:{proxy_port}/x",
                    headers={
                        "host": f"127.0.0.1:{backend.port}",
                        "authorization": _sigv4(
                            service="s3", region="us-east-1",
                        ),
                    },
                ) as resp:
                    body = await resp.json()
            assert resp.status == 403
            assert body["error"] == "ibounce DENY"
            assert backend.received_requests == []
        finally:
            server_task.cancel()
            try:
                await server_task
            except asyncio.CancelledError:
                pass
            store.close()
    finally:
        await backend.stop()


@pytest.mark.asyncio
async def test_sync_deny_prompt_timeout_default_allow_forwards(tmp_path) -> None:
    """No operator answer + timeout fires + --sync-prompt-default=allow
    -> proxy forwards to upstream + returns upstream's response."""
    backend = _MockAWS()
    await backend.start()
    backend.next_response_status = 200
    backend.next_response_body = b'{"fallback":"allow"}'
    try:
        store = BouncerStore(db_path=str(tmp_path / "b.db"))
        proxy_port = _free_port()
        config = ProxyConfig(
            host="127.0.0.1", port=proxy_port,
            mode=ProxyMode.TRANSPARENT,
            default_policy=DefaultPolicy.DENY,
            forward_scheme="http",
            sync_prompt_on_deny=True,
            sync_prompt_timeout_seconds=1,
            sync_prompt_default_decision="allow",
        )
        server_task = asyncio.create_task(serve(config, store=store))
        try:
            await _wait_for_listen("127.0.0.1", proxy_port)
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"http://127.0.0.1:{proxy_port}/x",
                    headers={
                        "host": f"127.0.0.1:{backend.port}",
                        "authorization": _sigv4(
                            service="s3", region="us-east-1",
                        ),
                    },
                ) as resp:
                    body = await resp.read()
                    headers = dict(resp.headers)
            assert resp.status == 200
            assert body == b'{"fallback":"allow"}'
            assert headers.get("x-iam-jit-bouncer-sync") == "allow"
            assert len(backend.received_requests) == 1
        finally:
            server_task.cancel()
            try:
                await server_task
            except asyncio.CancelledError:
                pass
            store.close()
    finally:
        await backend.stop()


@pytest.mark.asyncio
async def test_sync_deny_prompt_does_not_fire_when_paused(tmp_path) -> None:
    """When a pause window is active, the proxy demotes transparent
    -> cooperative (existing #6a behavior). Sync prompt MUST NOT
    fire — the agent's call should pass through to upstream
    advisory-style, with NO sync-prompt header + NO row enqueued."""
    backend = _MockAWS()
    await backend.start()
    backend.next_response_body = b'{"paused":"forwarded"}'
    try:
        store = BouncerStore(db_path=str(tmp_path / "b.db"))
        store.start_pause(
            duration_seconds=600, reason="test", started_by="alice",
        )
        proxy_port = _free_port()
        config = ProxyConfig(
            host="127.0.0.1", port=proxy_port,
            mode=ProxyMode.TRANSPARENT,
            default_policy=DefaultPolicy.DENY,
            forward_scheme="http",
            sync_prompt_on_deny=True,
            sync_prompt_timeout_seconds=1,
        )
        server_task = asyncio.create_task(serve(config, store=store))
        try:
            await _wait_for_listen("127.0.0.1", proxy_port)
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"http://127.0.0.1:{proxy_port}/x",
                    headers={
                        "host": f"127.0.0.1:{backend.port}",
                        "authorization": _sigv4(
                            service="s3", region="us-east-1",
                        ),
                    },
                ) as resp:
                    body = await resp.read()
                    headers = dict(resp.headers)
            # Forwarded through (pause demotes to cooperative)
            assert resp.status == 200
            assert body == b'{"paused":"forwarded"}'
            # NOT a sync-allow — pause superseded entirely
            assert "x-iam-jit-bouncer-sync" not in headers
            # No pending sync prompt was enqueued
            assert store.list_waiting_sync_prompts() == []
        finally:
            server_task.cancel()
            try:
                await server_task
            except asyncio.CancelledError:
                pass
            store.close()
    finally:
        await backend.stop()


@pytest.mark.asyncio
async def test_sync_deny_prompt_does_not_fire_in_cooperative_mode(
    tmp_path,
) -> None:
    """Cooperative mode DENY is advisory — the call forwards. Sync
    prompting here would block traffic that wouldn't have been
    blocked anyway. No row enqueued."""
    backend = _MockAWS()
    await backend.start()
    try:
        store = BouncerStore(db_path=str(tmp_path / "b.db"))
        proxy_port = _free_port()
        config = ProxyConfig(
            host="127.0.0.1", port=proxy_port,
            mode=ProxyMode.COOPERATIVE,
            default_policy=DefaultPolicy.DENY,
            forward_scheme="http",
            sync_prompt_on_deny=True,
            sync_prompt_timeout_seconds=1,
        )
        server_task = asyncio.create_task(serve(config, store=store))
        try:
            await _wait_for_listen("127.0.0.1", proxy_port)
            import aiohttp
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"http://127.0.0.1:{proxy_port}/x",
                    headers={
                        "host": f"127.0.0.1:{backend.port}",
                        "authorization": _sigv4(
                            service="s3", region="us-east-1",
                        ),
                    },
                ) as resp:
                    pass
            # Cooperative forwards regardless
            assert resp.status == 200
            assert store.list_waiting_sync_prompts() == []
        finally:
            server_task.cancel()
            try:
                await server_task
            except asyncio.CancelledError:
                pass
            store.close()
    finally:
        await backend.stop()


# ---------------------------------------------------------------------------
# CLI mutex + range tests
# ---------------------------------------------------------------------------


def test_cli_rejects_both_async_and_sync_prompt_flags() -> None:
    """--prompt-on-deny + --sync-prompt-on-deny on the same invocation
    must be rejected at parse time with a clear error message."""
    from click.testing import CliRunner

    from iam_jit.bouncer_cli import main

    runner = CliRunner()
    result = runner.invoke(
        main, ["run", "--prompt-on-deny", "--sync-prompt-on-deny"],
    )
    assert result.exit_code == 2
    assert "mutually exclusive" in result.output


def test_cli_sync_prompt_timeout_rejected_below_floor() -> None:
    """--sync-prompt-timeout below 5 rejected by Click's IntRange."""
    from click.testing import CliRunner

    from iam_jit.bouncer_cli import main

    runner = CliRunner()
    result = runner.invoke(
        main, [
            "run", "--sync-prompt-on-deny",
            "--sync-prompt-timeout", "2",
        ],
    )
    assert result.exit_code == 2


def test_cli_sync_prompt_timeout_rejected_above_ceiling() -> None:
    """--sync-prompt-timeout above 300 rejected by Click's IntRange."""
    from click.testing import CliRunner

    from iam_jit.bouncer_cli import main

    runner = CliRunner()
    result = runner.invoke(
        main, [
            "run", "--sync-prompt-on-deny",
            "--sync-prompt-timeout", "999",
        ],
    )
    assert result.exit_code == 2


# ---------------------------------------------------------------------------
# CLI prompts-answer wake integration
# ---------------------------------------------------------------------------


def test_cli_answer_wakes_sync_slot_with_allow(tmp_path, monkeypatch) -> None:
    """When the operator answers a sync-deny-prompt via the CLI with
    --kind always, the in-process registry is woken with decision=allow."""
    from click.testing import CliRunner

    from iam_jit.bouncer_cli import main

    db_path = str(tmp_path / "b.db")
    monkeypatch.setenv(
        "IAM_JIT_BOUNCER_PROFILES_FILE", str(tmp_path / "profiles.yaml"),
    )
    store = BouncerStore(db_path=db_path)
    try:
        pid, wid = store.add_sync_pending_prompt(
            decision_id=1, service="s3", action="GetObject",
            arn="arn:aws:s3:::b/k", region="us-east-1",
            deny_reason="t",
        )
    finally:
        store.close()
    slot = register_sync_wait(wid)
    try:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["prompts", "answer", str(pid),
             "--kind", "always", "--db", db_path],
        )
        assert result.exit_code == 0, result.output
        assert slot.event.is_set()
        assert slot.decision == "allow"
        assert slot.answer_kind == "always"
    finally:
        unregister_sync_wait(wid)


def test_cli_answer_wakes_sync_slot_with_deny(tmp_path, monkeypatch) -> None:
    """--kind ignore maps to decision=deny."""
    from click.testing import CliRunner

    from iam_jit.bouncer_cli import main

    db_path = str(tmp_path / "b.db")
    monkeypatch.setenv(
        "IAM_JIT_BOUNCER_PROFILES_FILE", str(tmp_path / "profiles.yaml"),
    )
    store = BouncerStore(db_path=db_path)
    try:
        pid, wid = store.add_sync_pending_prompt(
            decision_id=1, service="s3", action="GetObject",
            arn=None, region=None, deny_reason="t",
        )
    finally:
        store.close()
    slot = register_sync_wait(wid)
    try:
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["prompts", "answer", str(pid),
             "--kind", "ignore", "--db", db_path],
        )
        assert result.exit_code == 0, result.output
        assert slot.event.is_set()
        assert slot.decision == "deny"
        assert slot.answer_kind == "ignore"
    finally:
        unregister_sync_wait(wid)


# ---------------------------------------------------------------------------
# MCP tool tests
# ---------------------------------------------------------------------------


def test_mcp_bouncer_pending_sync_prompts_returns_waiting_set(
    tmp_path, monkeypatch,
) -> None:
    """bouncer_pending_sync_prompts returns the LIVE waiting set
    (filtered by the in-process registry)."""
    db_path = str(tmp_path / "b.db")
    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", db_path)
    store = BouncerStore(db_path=db_path)
    try:
        _, wid = store.add_sync_pending_prompt(
            decision_id=1, service="s3", action="GetObject",
            arn=None, region=None, deny_reason="t",
        )
        # Also a stale row (no register) — must NOT appear
        store.add_sync_pending_prompt(
            decision_id=2, service="s3", action="PutObject",
            arn=None, region=None, deny_reason="t",
        )
    finally:
        store.close()
    register_sync_wait(wid)
    try:
        from iam_jit.mcp_server import _handle_request

        resp = _handle_request({
            "jsonrpc": "2.0", "id": 1, "method": "tools/call",
            "params": {
                "name": "bouncer_pending_sync_prompts",
                "arguments": {},
            },
        })
        payload = resp["result"]["structuredContent"]
        assert payload["count"] == 1
        assert payload["waiting"][0]["sync_wait_id"] == wid
    finally:
        unregister_sync_wait(wid)


def test_mcp_ibounce_pending_sync_prompts_alias(tmp_path, monkeypatch) -> None:
    """ibounce_pending_sync_prompts alias dispatches to the same handler."""
    db_path = str(tmp_path / "b.db")
    monkeypatch.setenv("IAM_JIT_BOUNCER_DB", db_path)
    from iam_jit.mcp_server import _handle_request
    resp = _handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {
            "name": "ibounce_pending_sync_prompts",
            "arguments": {},
        },
    })
    payload = resp["result"]["structuredContent"]
    assert payload == {"waiting": [], "count": 0}


def test_mcp_tools_list_exposes_pending_sync_prompts() -> None:
    """The tool MUST appear in tools/list under both names."""
    from iam_jit.mcp_server import _handle_request
    resp = _handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {},
    })
    names = {t["name"] for t in resp["result"]["tools"]}
    assert "bouncer_pending_sync_prompts" in names
    assert "ibounce_pending_sync_prompts" in names


# ---------------------------------------------------------------------------
# Cross-process poll fallback (#250) — mirrors dbounce d82ded9
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_cross_process_answer_polls_to_decision(tmp_path) -> None:
    """#250 — when the operator answers from a DIFFERENT process than
    `ibounce serve`, the in-process `wake_sync_pending_prompt` never
    fires (the answerer's registry is separate). The proxy's poll
    fallback MUST detect the DB-side status change within ~200ms and
    return the corresponding allow/deny decision.

    Simulated by calling `store.answer_pending_prompt` WITHOUT a
    corresponding `wake_sync_pending_prompt` — the in-process Event
    stays unset, so any decision the proxy returns has to have come
    from the poll path.
    """
    backend = _MockAWS()
    await backend.start()
    backend.next_response_status = 200
    backend.next_response_body = b'{"cross_proc":"allow"}'
    try:
        store = BouncerStore(db_path=str(tmp_path / "b.db"))
        proxy_port = _free_port()
        config = ProxyConfig(
            host="127.0.0.1", port=proxy_port,
            mode=ProxyMode.TRANSPARENT,
            default_policy=DefaultPolicy.DENY,
            forward_scheme="http",
            sync_prompt_on_deny=True,
            sync_prompt_timeout_seconds=5,
            sync_prompt_default_decision="deny",
        )
        server_task = asyncio.create_task(serve(config, store=store))
        try:
            await _wait_for_listen("127.0.0.1", proxy_port)
            import aiohttp

            async def operator_answers_cross_process():
                # Wait until the proxy has enqueued the row + registered
                # the slot, then ONLY call `answer_pending_prompt`. NO
                # `wake_sync_pending_prompt` — simulates the answer
                # coming from a different Python process whose registry
                # the serve process can't see. The proxy must notice via
                # the 200ms poll fallback.
                for _ in range(100):
                    rows = store.list_waiting_sync_prompts()
                    if rows:
                        store.answer_pending_prompt(
                            rows[0]["id"], answer_kind="always",
                            answer_target=None, answered_by="bob",
                        )
                        return
                    await asyncio.sleep(0.01)
                raise AssertionError(
                    "operator never observed a waiting prompt to answer"
                )

            answer_task = asyncio.create_task(
                operator_answers_cross_process(),
            )
            t0 = asyncio.get_event_loop().time()
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"http://127.0.0.1:{proxy_port}/cross/proc",
                    headers={
                        "host": f"127.0.0.1:{backend.port}",
                        "authorization": _sigv4(
                            service="s3", region="us-east-1",
                        ),
                    },
                ) as resp:
                    body = await resp.read()
                    resp_headers = dict(resp.headers)
            elapsed_after_answer = asyncio.get_event_loop().time() - t0
            await answer_task
            # The answer mapped to allow (kind=always) -> forwarded.
            assert resp.status == 200
            assert body == b'{"cross_proc":"allow"}'
            assert resp_headers.get("x-iam-jit-bouncer-sync") == "allow"
            assert len(backend.received_requests) == 1
            # Latency budget: poll fires every 200ms; allow generous
            # headroom for CI jitter + upstream forward, but the test
            # must NOT be just observing the --sync-prompt-default
            # path firing at 5s. End-to-end should land under ~2s.
            assert elapsed_after_answer < 2.0, (
                f"cross-process answer took {elapsed_after_answer:.3f}s; "
                "expected ≤200ms-cadence poll to fire well under 2s"
            )
        finally:
            server_task.cancel()
            try:
                await server_task
            except asyncio.CancelledError:
                pass
            store.close()
    finally:
        await backend.stop()


@pytest.mark.asyncio
async def test_cross_process_poll_respects_timeout(tmp_path) -> None:
    """#250 — the poll fallback must NOT extend the wall-clock timeout.
    With no answer ever, the proxy must return at the configured
    timeout with --sync-prompt-default (here: deny -> 403)."""
    backend = _MockAWS()
    await backend.start()
    try:
        store = BouncerStore(db_path=str(tmp_path / "b.db"))
        proxy_port = _free_port()
        config = ProxyConfig(
            host="127.0.0.1", port=proxy_port,
            mode=ProxyMode.TRANSPARENT,
            default_policy=DefaultPolicy.DENY,
            forward_scheme="http",
            sync_prompt_on_deny=True,
            sync_prompt_timeout_seconds=1,
            sync_prompt_default_decision="deny",
        )
        server_task = asyncio.create_task(serve(config, store=store))
        try:
            await _wait_for_listen("127.0.0.1", proxy_port)
            import aiohttp
            t0 = asyncio.get_event_loop().time()
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    f"http://127.0.0.1:{proxy_port}/no/answer",
                    headers={
                        "host": f"127.0.0.1:{backend.port}",
                        "authorization": _sigv4(
                            service="s3", region="us-east-1",
                        ),
                    },
                ) as resp:
                    body = await resp.json()
            elapsed = asyncio.get_event_loop().time() - t0
            assert resp.status == 403
            assert body["error"] == "ibounce DENY"
            assert backend.received_requests == []
            # Should land near the 1s timeout, NOT extend past it
            # (poll cadence rounds wait_for to remaining when remaining
            # < 200ms, so the wall clock is the floor).
            assert 0.9 <= elapsed < 2.0, (
                f"poll-fallback path took {elapsed:.3f}s; expected ~1s "
                "(the configured --sync-prompt-timeout)"
            )
        finally:
            server_task.cancel()
            try:
                await server_task
            except asyncio.CancelledError:
                pass
            store.close()
    finally:
        await backend.stop()


# ---------------------------------------------------------------------------
# Backward-compat guardrail: async --prompt-on-deny behavior unchanged.
# ---------------------------------------------------------------------------


def test_async_prompt_on_deny_does_not_set_sync_wait_id(tmp_path) -> None:
    """Existing async deny-prompt path MUST NOT touch sync_wait_id.
    Confirms we didn't accidentally tangle the two flows."""
    from iam_jit.bouncer.proxy import evaluate_request

    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    try:
        evaluate_request(
            method="GET", host="s3.us-east-1.amazonaws.com", path="/b/k",
            headers={
                "host": "s3.us-east-1.amazonaws.com",
                "authorization": _sigv4(service="s3", region="us-east-1"),
            },
            body=None, query=None,
            store=store, mode=ProxyMode.TRANSPARENT,
            default_policy=DefaultPolicy.DENY,
            prompt_on_deny=True,
        )
        rows = store.list_pending_prompts()
        assert len(rows) == 1
        assert rows[0]["sync_wait_id"] is None
    finally:
        store.close()


def test_async_allow_rule_path_unchanged(tmp_path) -> None:
    """Sanity: an explicit ALLOW under transparent mode with sync flag
    on does NOT enqueue anything (allow != deny, sync prompt only
    fires on deny)."""
    from iam_jit.bouncer.proxy import evaluate_request

    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    try:
        store.add_rule(
            ProxyRule(
                pattern="s3:GetObject", effect=Effect.ALLOW,
                arn_scope=None, region_scope=None,
                note="t", origin="manual",
            ),
            actor="t",
        )
        obs = evaluate_request(
            method="GET", host="s3.us-east-1.amazonaws.com", path="/b/k",
            headers={
                "host": "s3.us-east-1.amazonaws.com",
                "authorization": _sigv4(service="s3", region="us-east-1"),
            },
            body=None, query=None,
            store=store, mode=ProxyMode.TRANSPARENT,
            default_policy=DefaultPolicy.DENY,
            prompt_on_deny=False,
        )
        assert obs.decision_verdict == "allow"
        assert store.list_waiting_sync_prompts() == []
    finally:
        store.close()
