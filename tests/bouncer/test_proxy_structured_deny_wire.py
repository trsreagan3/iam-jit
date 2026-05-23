"""#443 / §A48b — 403 wire body uses build_structured_deny() output.

These tests exercise the proxy's transparent-deny 403 path end-to-end
and assert on the merged shape: legacy ibounce-shape fields PRESERVED
(per [[creates-never-mutates]]) + the structured-deny additive fields
ON every deny (per [[ambient-value-prop-and-friction-framing]]).

Tests required by the brief (#443):
  * test_403_wire_body_uses_structured_deny_shape
  * test_403_wire_body_includes_caught_by_bouncer_field
  * test_403_wire_body_includes_classification_field
  * test_403_wire_body_includes_suggested_allow_command
  * test_403_wire_body_includes_recommended_action
  * test_existing_proxy_behavior_tests_pass_after_wire_swap  (meta-test:
    BEHAVIOR is the same; only wire SHAPE expanded; the legacy keys
    asserted by the rest of the suite remain on the body)
"""

from __future__ import annotations

import asyncio
import socket

import pytest

from iam_jit.bouncer.decisions import DefaultPolicy
from iam_jit.bouncer.proxy import (
    ProxyConfig,
    ProxyMode,
    _map_proxy_deny_source,
    serve,
)
from iam_jit.bouncer.store import BouncerStore


def _sigv4_auth(*, service: str, region: str) -> str:
    return (
        "AWS4-HMAC-SHA256 "
        f"Credential=AKIAEXAMPLE/20260517/{region}/{service}/aws4_request, "
        "SignedHeaders=host;x-amz-date, "
        "Signature=fakesignature"
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


async def _drive_deny(tmp_path) -> tuple[dict, int, dict]:
    """Helper: stand up a default-deny TRANSPARENT proxy, drive one
    SigV4'd request through it (no upstream backend needed because the
    deny short-circuits before forwarding), return (body_json, status,
    resp_headers).
    """
    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    proxy_port = _free_port()
    config = ProxyConfig(
        host="127.0.0.1", port=proxy_port,
        mode=ProxyMode.TRANSPARENT,
        default_policy=DefaultPolicy.DENY,
        forward_scheme="http",
    )
    server_task = asyncio.create_task(serve(config, store=store))
    try:
        await _wait_for_listen("127.0.0.1", proxy_port)
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.delete(
                f"http://127.0.0.1:{proxy_port}/cache-bucket/data.json",
                headers={
                    # Note: real AWS would never see this Host but the
                    # proxy doesn't forward on deny so the backend's
                    # absence is harmless.
                    "host": "s3.amazonaws.com",
                    "authorization": _sigv4_auth(
                        service="s3", region="us-east-1",
                    ),
                    "x-iam-jit-agent-session-id": "sess-test-42",
                },
            ) as resp:
                body = await resp.json()
                headers = dict(resp.headers)
                status = resp.status
        return body, status, headers
    finally:
        server_task.cancel()
        try:
            await server_task
        except asyncio.CancelledError:
            pass
        store.close()


# ---------------------------------------------------------------------------
# Structured-deny field presence
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_403_wire_body_uses_structured_deny_shape(tmp_path) -> None:
    """The deny 403 body MUST carry the structured-deny additive
    fields alongside the legacy fields (merged shape, per the wire-swap
    contract in #443)."""
    body, status, _headers = await _drive_deny(tmp_path)
    assert status == 403
    # All structured-deny fields present.
    for field in (
        "caught_by_bouncer",
        "is_likely_injection_classification",
        "suggested_allow_command",
        "recommended_action",
        "deny_event_id",
        "classifier_hook",
        "deny_source_classified",
        "structured_deny_schema_version",
    ):
        assert field in body, f"missing structured-deny field: {field}"


@pytest.mark.asyncio
async def test_403_wire_body_includes_caught_by_bouncer_field(tmp_path) -> None:
    """caught_by_bouncer MUST identify which bouncer caught the
    request. For the ibounce proxy this is always 'ibounce'."""
    body, _status, _headers = await _drive_deny(tmp_path)
    assert body["caught_by_bouncer"] == "ibounce"


@pytest.mark.asyncio
async def test_403_wire_body_includes_classification_field(tmp_path) -> None:
    """is_likely_injection_classification MUST be one of the three
    structured-deny enum values."""
    body, _status, _headers = await _drive_deny(tmp_path)
    assert body["is_likely_injection_classification"] in (
        "appears_legitimate",
        "ambiguous",
        "appears_adversarial",
    )


@pytest.mark.asyncio
async def test_403_wire_body_includes_suggested_allow_command(tmp_path) -> None:
    """suggested_allow_command MUST be a non-empty string. For a
    destructive verb (s3:DeleteObject in the harness) the structural
    heuristic classifies adversarial → recommended_action halts +
    escalates; the suggested_allow_command field is still populated
    (operator may override; honest framing)."""
    body, _status, _headers = await _drive_deny(tmp_path)
    cmd = body["suggested_allow_command"]
    assert isinstance(cmd, str) and cmd
    # Either a paste-able command OR a `#`-prefixed explanation (the
    # synth_suggested_allow_command contract — see
    # iam_jit.profile_allow.denies). Both are valid; neither is empty.


@pytest.mark.asyncio
async def test_403_wire_body_includes_recommended_action(tmp_path) -> None:
    """recommended_action MUST be one of the three derive_recommended_action enum values."""
    body, _status, _headers = await _drive_deny(tmp_path)
    assert body["recommended_action"] in (
        "easy-allow",
        "halt+escalate",
        "rephrase+retry",
    )


@pytest.mark.asyncio
async def test_403_wire_body_destructive_verb_recommends_halt_escalate(tmp_path) -> None:
    """Driving an s3:DeleteObject through default-deny MUST trip the
    structural-heuristic destructive-verb backstop in the structured
    deny classifier → recommended_action MUST be halt+escalate per
    [[ibounce-honest-positioning]]: adversarial signal ALWAYS escalates.

    The brief is explicit: 'high-confidence-adversarial deny STILL
    ESCALATES; don't soften that.'
    """
    body, _status, _headers = await _drive_deny(tmp_path)
    assert body["is_likely_injection_classification"] == "appears_adversarial"
    assert body["recommended_action"] == "halt+escalate"


# ---------------------------------------------------------------------------
# Behavior preservation (the meta-test from the brief)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_existing_proxy_behavior_tests_pass_after_wire_swap(tmp_path) -> None:
    """Meta-test (per the #443 brief): the BEHAVIOR (HTTP 403, no
    upstream forward, legacy keys, response header) is identical to
    pre-swap. Only the wire SHAPE is enlarged (additive)."""
    body, status, headers = await _drive_deny(tmp_path)
    # HTTP status preserved.
    assert status == 403
    # Legacy keys preserved verbatim.
    assert body["error"] == "ibounce DENY"
    assert body["decision_verdict"] == "deny"
    assert body["mode"] == "transparent"
    assert "decision_reason" in body
    # Service + action surfaced via the parsed fields (the SigV4
    # service in the test header is 's3').
    assert body.get("service") == "s3"
    # Wire-protocol response header preserved.
    assert headers.get("x-iam-jit-bouncer-verdict") == "deny"


# ---------------------------------------------------------------------------
# Helper unit: proxy deny_source -> structured deny_source translation
# ---------------------------------------------------------------------------


def test_map_proxy_deny_source_known_values() -> None:
    """Every short-enum value emitted by the proxy MUST translate to the
    canonical structured_deny enum so derive_recommended_action routes
    deterministically (otherwise a 'profile'-source deny would be
    treated as unknown → easy-allow when the brief expects rephrase+retry
    on org-floor denies)."""
    assert _map_proxy_deny_source("profile") == "static_profile"
    assert _map_proxy_deny_source("dynamic") == "dynamic_deny"
    assert _map_proxy_deny_source("rule") == "global_deny"
    assert _map_proxy_deny_source("task") == "task_deny"
    assert _map_proxy_deny_source("default") == "safe_default"


def test_map_proxy_deny_source_unknown_passthrough() -> None:
    """Unknown values pass through unchanged so structured_deny can
    surface them honestly as 'unknown' (per [[ibounce-honest-positioning]])."""
    assert _map_proxy_deny_source("static_profile") == "static_profile"
    assert _map_proxy_deny_source(None) == ""
    assert _map_proxy_deny_source("") == ""
    assert _map_proxy_deny_source("brand_new_layer") == "brand_new_layer"
