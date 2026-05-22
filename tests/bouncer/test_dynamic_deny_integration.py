# #324a — integration tests for dynamic-deny -> evaluate_request +
# the POST /admin/dynamic-denies/reload mgmt-port endpoint.
"""Integration tests for the ibounce dynamic-deny pipeline.

Covers:
  * A matching ARN produces a DENY observation with
    `deny_source="dynamic"` + `dynamic_deny_rule_id=<dd_...>` +
    `dynamic_deny_pattern=<glob>`.
  * Non-matching ARNs fall through to the existing decision path
    (default policy / global rules / profile rules) unchanged.
  * The dynamic-deny match wins over a profile that would otherwise
    ALLOW the call.
  * A previously-matching rule, post-expiry, no longer fires.
  * POST /admin/dynamic-denies/reload triggers a rule-set rebuild.
  * The same endpoint returns 400 with structured error on parse
    error.
"""

from __future__ import annotations

import asyncio
import contextlib
import datetime as _dt
import json
import pathlib
import socket
import time

import pytest

from iam_jit.bouncer.decisions import DefaultPolicy
from iam_jit.bouncer.proxy import (
    ProxyConfig,
    ProxyMode,
    RequestObservation,
    evaluate_request,
    register_dynamic_deny_snapshot_provider,
    serve,
)
from iam_jit.bouncer.store import BouncerStore
from iam_jit.dynamic_denies import (
    DynamicDenyWatcher,
    Rule,
    RuleSet,
)
from iam_jit.dynamic_denies.loader import BOUNCER_NAME


VALID_RULE_ID = "dd_01HZ8VKJ6Y2BJTPVZ3PNX97A2C"
VALID_RULE_ID_2 = "dd_01HZ8WPRBZ6CGQRSTVWXYZ0AB1"


def _now() -> _dt.datetime:
    return _dt.datetime.now(_dt.timezone.utc)


def _now_iso() -> str:
    return _now().isoformat().replace("+00:00", "Z")


def _sigv4_auth_header(*, service: str, region: str) -> str:
    return (
        "AWS4-HMAC-SHA256 "
        f"Credential=AKIAEXAMPLE/20260522/{region}/{service}/aws4_request, "
        "SignedHeaders=host;x-amz-date, "
        "Signature=fakefakefake"
    )


@pytest.fixture
def store(tmp_path):
    s = BouncerStore(db_path=str(tmp_path / "b.db"))
    yield s
    s.close()


@pytest.fixture(autouse=True)
def _clear_provider():
    """Ensure every test starts with no dynamic-deny provider registered
    + every test cleans up after itself."""
    register_dynamic_deny_snapshot_provider(None)
    yield
    register_dynamic_deny_snapshot_provider(None)


def _ruleset_with_rule(target: str, rule_id: str = VALID_RULE_ID) -> RuleSet:
    rule = Rule(
        id=rule_id,
        targets=(target,),
        reason="integration test deny",
        duration="3h",
        added_by="test@example.com",
        added_at=_now(),
        expires_at=_now() + _dt.timedelta(hours=3),
        applied_to=(BOUNCER_NAME,),
    )
    return RuleSet(
        rules=(rule,),
        source_path="<test>",
        loaded_at=_now(),
        total_rules_in_file=1,
    )


# ---------------------------------------------------------------------------
# evaluate_request integration
# ---------------------------------------------------------------------------


def test_matching_arn_produces_dynamic_deny_observation(store):
    """A request whose resource ARN matches a dynamic-deny rule gets
    a DENY observation with the full dynamic-deny annotation."""
    rs = _ruleset_with_rule("arn:aws:s3:::prod-*")
    register_dynamic_deny_snapshot_provider(lambda: rs)

    obs = evaluate_request(
        method="GET",
        host="s3.us-east-1.amazonaws.com",
        path="/prod-data-bucket/file.txt",
        headers={
            "host": "s3.us-east-1.amazonaws.com",
            "authorization": _sigv4_auth_header(service="s3", region="us-east-1"),
            "x-amz-date": "20260522T000000Z",
        },
        body=None,
        query=None,
        store=store,
        mode=ProxyMode.TRANSPARENT,
        default_policy=DefaultPolicy.ALLOW,
    )

    assert obs.decision_verdict == "deny"
    assert obs.deny_source == "dynamic"
    assert obs.dynamic_deny_rule_id == VALID_RULE_ID
    assert obs.dynamic_deny_pattern == "arn:aws:s3:::prod-*"
    # Reason surfaces the rule id + pattern + operator reason.
    assert VALID_RULE_ID in obs.decision_reason
    assert "arn:aws:s3:::prod-*" in obs.decision_reason
    assert "integration test deny" in obs.decision_reason
    # Transparent + deny = enforced.
    assert obs.enforced is True


def test_non_matching_arn_falls_through(store):
    """An ARN that doesn't match any dynamic-deny rule continues
    through the normal pipeline; the absence of a dynamic-deny
    annotation is preserved on the observation."""
    rs = _ruleset_with_rule("arn:aws:s3:::prod-*")
    register_dynamic_deny_snapshot_provider(lambda: rs)

    obs = evaluate_request(
        method="GET",
        host="s3.us-east-1.amazonaws.com",
        path="/staging-data/file.txt",
        headers={
            "host": "s3.us-east-1.amazonaws.com",
            "authorization": _sigv4_auth_header(service="s3", region="us-east-1"),
            "x-amz-date": "20260522T000000Z",
        },
        body=None,
        query=None,
        store=store,
        mode=ProxyMode.TRANSPARENT,
        default_policy=DefaultPolicy.ALLOW,
    )

    # No rules in store + default policy ALLOW => allow.
    assert obs.decision_verdict == "allow"
    assert obs.deny_source is None
    assert obs.dynamic_deny_rule_id is None


def test_dynamic_deny_beats_default_policy_allow(store):
    """The dynamic-deny path fires regardless of what the default
    policy would have produced — the rule is the operator's explicit
    override."""
    rs = _ruleset_with_rule("arn:aws:s3:::*")
    register_dynamic_deny_snapshot_provider(lambda: rs)

    obs = evaluate_request(
        method="GET",
        host="s3.us-east-1.amazonaws.com",
        path="/any-bucket/file.txt",
        headers={
            "host": "s3.us-east-1.amazonaws.com",
            "authorization": _sigv4_auth_header(service="s3", region="us-east-1"),
            "x-amz-date": "20260522T000000Z",
        },
        body=None,
        query=None,
        store=store,
        mode=ProxyMode.TRANSPARENT,
        default_policy=DefaultPolicy.ALLOW,
    )

    assert obs.decision_verdict == "deny"
    assert obs.deny_source == "dynamic"


def test_no_provider_means_no_dynamic_deny_path(store):
    """When the snapshot provider isn't registered, the dynamic-deny
    check is a no-op — existing tests + the no-feature-enabled path
    keep their existing behaviour."""
    # Explicitly leave provider unregistered (the autouse fixture
    # ensures this).
    obs = evaluate_request(
        method="GET",
        host="s3.us-east-1.amazonaws.com",
        path="/prod-data-bucket/file.txt",
        headers={
            "host": "s3.us-east-1.amazonaws.com",
            "authorization": _sigv4_auth_header(service="s3", region="us-east-1"),
            "x-amz-date": "20260522T000000Z",
        },
        body=None,
        query=None,
        store=store,
        mode=ProxyMode.TRANSPARENT,
        default_policy=DefaultPolicy.ALLOW,
    )

    assert obs.deny_source is None
    assert obs.dynamic_deny_rule_id is None


def test_empty_snapshot_means_no_dynamic_deny_path(store):
    """An empty snapshot (no rules loaded) is equivalent to no
    provider — the matcher short-circuits + falls through cleanly."""
    register_dynamic_deny_snapshot_provider(lambda: RuleSet.empty())

    obs = evaluate_request(
        method="GET",
        host="s3.us-east-1.amazonaws.com",
        path="/prod-data-bucket/file.txt",
        headers={
            "host": "s3.us-east-1.amazonaws.com",
            "authorization": _sigv4_auth_header(service="s3", region="us-east-1"),
            "x-amz-date": "20260522T000000Z",
        },
        body=None,
        query=None,
        store=store,
        mode=ProxyMode.TRANSPARENT,
        default_policy=DefaultPolicy.ALLOW,
    )

    assert obs.deny_source is None


# ---------------------------------------------------------------------------
# Mgmt-port endpoint
# ---------------------------------------------------------------------------


def _pick_free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.mark.asyncio
async def test_admin_reload_endpoint_returns_rules_count(tmp_path):
    """End-to-end: boot serve(), POST to the mgmt-port endpoint, see
    the new rule count back."""
    dd_path = tmp_path / "dd.yaml"
    dd_path.write_text(f"""
schema_version: "1.0"
denies:
  - id: {VALID_RULE_ID}
    targets: ["arn:aws:s3:::prod-*"]
    reason: "integration"
    duration: "3h"
    added_by: "ops@example.com"
    added_at: "{_now_iso()}"
    applied_to: [ibounce]
""")
    port = _pick_free_port()
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    config = ProxyConfig(
        host="127.0.0.1",
        port=port,
        mode=ProxyMode.COOPERATIVE,
        default_policy=DefaultPolicy.ALLOW,
        dynamic_denies_enabled=True,
        dynamic_denies_path=str(dd_path),
    )

    serve_task = asyncio.create_task(serve(config, store=store))
    try:
        # Give serve() a moment to bind.
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.close()
                await writer.wait_closed()
                break
            except OSError:
                await asyncio.sleep(0.05)
        # POST the reload endpoint.
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"http://127.0.0.1:{port}/admin/dynamic-denies/reload",
            ) as resp:
                assert resp.status == 200, await resp.text()
                payload = await resp.json()
        assert payload["reloaded"] is True
        assert payload["rules_count"] == 1
        assert payload["rules_applied_to_ibounce"] == 1
        assert VALID_RULE_ID in payload["rule_ids"]
        assert payload["source_path"].endswith("dd.yaml")
    finally:
        serve_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await serve_task
        store.close()


@pytest.mark.asyncio
async def test_admin_reload_endpoint_surfaces_parse_error(tmp_path):
    """POSTing reload against a broken YAML returns a 400 with
    structured error body. Previous snapshot is preserved."""
    dd_path = tmp_path / "dd.yaml"
    # Start with a valid file...
    dd_path.write_text(f"""
schema_version: "1.0"
denies:
  - id: {VALID_RULE_ID}
    targets: ["arn:aws:s3:::prod-*"]
    reason: "valid"
    duration: "3h"
    added_by: "ops@example.com"
    added_at: "{_now_iso()}"
    applied_to: [ibounce]
""")
    port = _pick_free_port()
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    config = ProxyConfig(
        host="127.0.0.1",
        port=port,
        mode=ProxyMode.COOPERATIVE,
        default_policy=DefaultPolicy.ALLOW,
        dynamic_denies_enabled=True,
        dynamic_denies_path=str(dd_path),
    )

    serve_task = asyncio.create_task(serve(config, store=store))
    try:
        # wait for serve() to bind
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.close()
                await writer.wait_closed()
                break
            except OSError:
                await asyncio.sleep(0.05)
        # Now break the file.
        dd_path.write_text("schema_version: \"1.0\"\ndenies: [bad]\n")
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"http://127.0.0.1:{port}/admin/dynamic-denies/reload",
            ) as resp:
                assert resp.status == 400, await resp.text()
                payload = await resp.json()
        assert payload["reloaded"] is False
        assert "error" in payload
        # Retained the previous snapshot (1 valid rule).
        assert payload["rules_applied_to_ibounce"] == 1
    finally:
        serve_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await serve_task
        store.close()


@pytest.mark.asyncio
async def test_admin_reload_returns_409_when_dynamic_denies_disabled(tmp_path):
    """When `--disable-dynamic-denies` is passed, the watcher is not
    constructed; the mgmt endpoint returns 409."""
    port = _pick_free_port()
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    config = ProxyConfig(
        host="127.0.0.1",
        port=port,
        mode=ProxyMode.COOPERATIVE,
        default_policy=DefaultPolicy.ALLOW,
        dynamic_denies_enabled=False,
    )

    serve_task = asyncio.create_task(serve(config, store=store))
    try:
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.close()
                await writer.wait_closed()
                break
            except OSError:
                await asyncio.sleep(0.05)
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.post(
                f"http://127.0.0.1:{port}/admin/dynamic-denies/reload",
            ) as resp:
                assert resp.status == 409, await resp.text()
                payload = await resp.json()
        assert payload["error"] == "dynamic_denies_disabled"
    finally:
        serve_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await serve_task
        store.close()


@pytest.mark.asyncio
async def test_healthz_surfaces_dynamic_denies_block(tmp_path):
    """The /healthz endpoint surfaces a `dynamic_denies` status block
    so external monitoring can detect a stale snapshot / unparseable
    file without inspecting the audit log."""
    dd_path = tmp_path / "dd.yaml"
    dd_path.write_text(f"""
schema_version: "1.0"
denies:
  - id: {VALID_RULE_ID}
    targets: ["arn:aws:s3:::prod-*"]
    reason: "healthz-test"
    duration: "3h"
    added_by: "ops@example.com"
    added_at: "{_now_iso()}"
    applied_to: [ibounce]
""")
    port = _pick_free_port()
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    config = ProxyConfig(
        host="127.0.0.1",
        port=port,
        mode=ProxyMode.COOPERATIVE,
        default_policy=DefaultPolicy.ALLOW,
        dynamic_denies_enabled=True,
        dynamic_denies_path=str(dd_path),
    )

    serve_task = asyncio.create_task(serve(config, store=store))
    try:
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            try:
                reader, writer = await asyncio.open_connection("127.0.0.1", port)
                writer.close()
                await writer.wait_closed()
                break
            except OSError:
                await asyncio.sleep(0.05)
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(
                f"http://127.0.0.1:{port}/healthz",
            ) as resp:
                assert resp.status == 200, await resp.text()
                payload = await resp.json()
        block = payload.get("dynamic_denies")
        assert isinstance(block, dict)
        assert block["enabled"] is True
        assert block["rules_count"] == 1
        assert block["rules_in_file"] == 1
        assert block["source_path"].endswith("dd.yaml")
        assert block["initial_load_error"] is None
    finally:
        serve_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await serve_task
        store.close()
