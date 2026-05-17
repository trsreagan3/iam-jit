"""Tests for the WB32 CRIT closures.

Covers:
- CRIT-32-01: outbound Host allowlist via _is_allowed_forward_host
  + integration test that a non-AWS Host header gets 403 with the
  forward-host-mismatch refusal.
- CRIT-32-02: --host non-loopback is refused without
  --i-know-this-binds-externally; loopback is permitted; explicit
  --i-know-this-binds-externally bypasses the gate.
"""

from __future__ import annotations

import asyncio
import socket

import pytest
from click.testing import CliRunner

from iam_jit.bouncer.decisions import DefaultPolicy
from iam_jit.bouncer.proxy import (
    ProxyConfig,
    ProxyMode,
    _is_allowed_forward_host,
    serve,
)
from iam_jit.bouncer.rules import Effect, ProxyRule
from iam_jit.bouncer.store import BouncerStore
from iam_jit.bouncer_cli import main


def _sigv4(*, service: str, region: str) -> str:
    return (
        "AWS4-HMAC-SHA256 "
        f"Credential=AKIAEXAMPLE/20260517/{region}/{service}/aws4_request, "
        "SignedHeaders=host;x-amz-date, "
        "Signature=fake"
    )


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


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


# ---------------------------------------------------------------------------
# CRIT-32-01: outbound Host allowlist
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("host", [
    "s3.us-east-1.amazonaws.com",
    "iam.amazonaws.com",
    "ec2.eu-west-1.amazonaws.com",
    "S3.us-east-1.amazonaws.com",  # case-insensitive
    "kinesis.us-gov-west-1.amazonaws.us",  # GovCloud
    "s3.cn-north-1.amazonaws.com.cn",  # China
    "lambda.us-east-1.api.aws",
    "127.0.0.1",  # loopback
    "127.0.0.1:9876",  # loopback with port
    "localhost",
    "localhost:8080",
])
def test_allowlist_accepts_aws_endpoints_and_loopback(host) -> None:
    assert _is_allowed_forward_host(host) is True


@pytest.mark.parametrize("host", [
    "attacker.example.com",
    "evil.amazonaws.com.evil.example",  # NOT actually amazonaws.com
    "amazonaws.com.attacker",
    "webhook.site",
    "10.0.0.5",
    "192.168.1.1",
    "1.2.3.4",
    "",
    "amazonaws.com",  # bare TLD, no service.region prefix
])
def test_allowlist_refuses_non_aws_hosts(host) -> None:
    assert _is_allowed_forward_host(host) is False


def test_allowlist_honors_extra_hosts_env(monkeypatch) -> None:
    monkeypatch.setenv("IAM_JIT_BOUNCER_EXTRA_HOSTS",
                       "localstack.test, .internal.acme.com")
    assert _is_allowed_forward_host("localstack.test") is True
    assert _is_allowed_forward_host("api.internal.acme.com") is True
    # Suffix must match with a leading dot — "vil.internal.acme.com"
    # does match because it ENDS with .internal.acme.com
    assert _is_allowed_forward_host("evil.internal.acme.com") is True
    # But this should NOT match (substring vs suffix)
    assert _is_allowed_forward_host("internal.acme.com.attacker.io") is False


def test_allowlist_empty_extras_env_does_not_match_empty(monkeypatch) -> None:
    monkeypatch.setenv("IAM_JIT_BOUNCER_EXTRA_HOSTS", "")
    assert _is_allowed_forward_host("attacker.example.com") is False


@pytest.mark.asyncio
async def test_proxy_refuses_forward_to_non_aws_host(tmp_path) -> None:
    """End-to-end: even with an ALLOW rule for s3:*, a request with
    Host: webhook.attacker.example.com gets 403 with
    forward-host-mismatch refusal headers — proxy doesn't become
    an exfil channel."""
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    store.add_rule(
        ProxyRule(pattern="s3:*", effect=Effect.ALLOW,
                  arn_scope=None, region_scope=None,
                  note="permissive", origin="manual"),
        actor="t",
    )
    port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1", port=port,
        mode=ProxyMode.TRANSPARENT,
        default_policy=DefaultPolicy.DENY,
        forward_scheme="http",
    )
    task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", port)
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"http://127.0.0.1:{port}/some-bucket/x",
                headers={
                    "host": "webhook.attacker.example.com",
                    "authorization": _sigv4(service="s3", region="us-east-1"),
                },
            ) as resp:
                body = await resp.json()
        assert resp.status == 403
        assert resp.headers.get("x-iam-jit-bouncer-refusal") == "forward-host-mismatch"
        assert "attacker" in body["attempted_host"]
        assert "CRIT-32-01" in body["decision_reason"]
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
        store.close()


# ---------------------------------------------------------------------------
# CRIT-32-02: external-bind guard
# ---------------------------------------------------------------------------


def _invoke_run_help() -> object:
    runner = CliRunner()
    return runner.invoke(main, ["run", "--help"], catch_exceptions=False)


def test_run_help_documents_external_bind_acknowledgement() -> None:
    """Sanity check: --i-know-this-binds-externally is exposed."""
    result = _invoke_run_help()
    assert result.exit_code == 0
    assert "--i-know-this-binds-externally" in result.output


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.10", "10.0.0.5"])
def test_run_refuses_external_host_without_ack(tmp_path, host) -> None:
    """`iam-jit-bouncer run --host 0.0.0.0` must exit 2 with a clear
    error. Otherwise an operator silently exposes the credential-
    handling proxy to the network."""
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["run", "--host", host, "--db", str(tmp_path / "b.db")],
        catch_exceptions=False,
    )
    assert result.exit_code == 2
    assert "refusing to bind" in result.output or "credential-handling" in result.output


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1"])
def test_run_accepts_loopback_host_without_ack(tmp_path, host, monkeypatch) -> None:
    """Loopback hosts proceed past the guard. We replace asyncio.run
    with a sentinel raiser so we never actually bind — we just want
    to confirm the guard didn't refuse."""
    sentinel = RuntimeError("REACHED_SERVE")
    def _fake_run(*a, **kw):
        raise sentinel
    monkeypatch.setattr("asyncio.run", _fake_run)

    runner = CliRunner()
    result = runner.invoke(
        main,
        ["run", "--host", host, "--db", str(tmp_path / "b.db")],
        catch_exceptions=True,
    )
    # The guard should NOT have refused. The sentinel will propagate
    # as result.exception OR a non-zero exit code, but critically the
    # "refusing to bind" text must not appear.
    assert "refusing to bind" not in result.output, (
        f"loopback host {host!r} was wrongly rejected by the bind guard"
    )


def test_run_accepts_external_host_with_ack(tmp_path, monkeypatch) -> None:
    """--i-know-this-binds-externally bypasses the guard (operator
    explicitly opted in)."""
    sentinel = RuntimeError("REACHED_SERVE")
    def _fake_run(*a, **kw):
        raise sentinel
    monkeypatch.setattr("asyncio.run", _fake_run)

    runner = CliRunner()
    result = runner.invoke(
        main,
        ["run", "--host", "0.0.0.0",
         "--i-know-this-binds-externally",
         "--db", str(tmp_path / "b.db")],
        catch_exceptions=True,
    )
    assert "refusing to bind" not in result.output
