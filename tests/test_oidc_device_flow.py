"""Tests for the RFC 8628 Device Authorization Grant flow (Phase 2
of the MFA-for-agents story).

iam-jit's OIDC integration needs to support browserless agents
(Claude Code / CI / SSH sessions). The device flow lets the agent
print a code, the user completes the dance on their phone, the
agent polls until success.

These tests stub the HTTPClient so we exercise the protocol shape
without depending on real Google/Okta credentials.
"""

from __future__ import annotations

from typing import Any

import pytest

from iam_jit.oidc import (
    OIDCProviderConfig,
    DiscoveredEndpoints,
    DeviceFlowDenied,
    DeviceFlowExpired,
    DeviceFlowPending,
    DeviceFlowSlowDown,
    ConfigError,
    poll_device_flow,
    start_device_flow,
)


def _config() -> OIDCProviderConfig:
    return OIDCProviderConfig(
        provider="generic",
        issuer="https://idp.example.com",
        client_id="iam-jit-test",
        client_secret="secret",
        redirect_uri="https://iam-jit.example.com/callback",
        scopes=("openid", "email", "profile"),
    )


def _endpoints_with_device(uri: str = "https://idp.example.com/device") -> DiscoveredEndpoints:
    return DiscoveredEndpoints(
        authorization_endpoint="https://idp.example.com/authorize",
        token_endpoint="https://idp.example.com/token",
        jwks_uri="https://idp.example.com/.well-known/jwks.json",
        issuer="https://idp.example.com",
        device_authorization_endpoint=uri,
    )


def _endpoints_no_device() -> DiscoveredEndpoints:
    return DiscoveredEndpoints(
        authorization_endpoint="https://idp.example.com/authorize",
        token_endpoint="https://idp.example.com/token",
        jwks_uri="https://idp.example.com/.well-known/jwks.json",
        issuer="https://idp.example.com",
        device_authorization_endpoint=None,
    )


class _StubClient:
    """Programmable HTTPClient: feed it a list of responses, it returns
    them in order. Records the calls for assertion."""

    def __init__(self, responses: list[dict[str, Any]]) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, str, dict]] = []

    def get_json(self, url: str, *, timeout: float = 10.0) -> dict[str, Any]:
        self.calls.append(("GET", url, {}))
        if not self.responses:
            raise RuntimeError("no more stubbed responses")
        return self.responses.pop(0)

    def post_form(self, url: str, body: dict[str, str], *, timeout: float = 10.0) -> dict[str, Any]:
        self.calls.append(("POST", url, body))
        if not self.responses:
            raise RuntimeError("no more stubbed responses")
        return self.responses.pop(0)


# ---------------------------------------------------------------------------
# start_device_flow
# ---------------------------------------------------------------------------


def test_start_device_flow_returns_user_code_and_uri() -> None:
    client = _StubClient([
        {
            "device_code": "DCODE",
            "user_code": "ABCD-EFGH",
            "verification_uri": "https://idp.example.com/activate",
            "verification_uri_complete": "https://idp.example.com/activate?code=ABCD-EFGH",
            "expires_in": 600,
            "interval": 5,
        }
    ])
    start = start_device_flow(_config(), _endpoints_with_device(), client)
    assert start.device_code == "DCODE"
    assert start.user_code == "ABCD-EFGH"
    assert start.verification_uri == "https://idp.example.com/activate"
    assert start.verification_uri_complete is not None
    assert start.expires_in == 600
    assert start.interval == 5
    # Posted to the device-authorization endpoint with client_id + scope.
    _, url, body = client.calls[0]
    assert url == "https://idp.example.com/device"
    assert body["client_id"] == "iam-jit-test"
    assert body["scope"] == "openid email profile"


def test_start_device_flow_raises_when_provider_lacks_endpoint() -> None:
    """A provider that doesn't publish a device_authorization_endpoint
    in its discovery doc → ConfigError. The user / CLI is told to use
    the browser flow."""
    with pytest.raises(ConfigError, match="(?i)device-flow login is unavailable"):
        start_device_flow(_config(), _endpoints_no_device(), _StubClient([]))


def test_start_device_flow_missing_required_field_raises() -> None:
    client = _StubClient([{"device_code": "DCODE"}])  # missing user_code etc.
    with pytest.raises(ConfigError, match="missing required fields"):
        start_device_flow(_config(), _endpoints_with_device(), client)


def test_start_device_flow_falls_back_to_verification_url_alias() -> None:
    """Some IdPs (older OAuth implementations) use `verification_url`
    instead of `verification_uri`. Accept either."""
    client = _StubClient([
        {
            "device_code": "DC",
            "user_code": "UC",
            "verification_url": "https://idp.example.com/v",
            "expires_in": 300,
            "interval": 5,
        }
    ])
    start = start_device_flow(_config(), _endpoints_with_device(), client)
    assert start.verification_uri == "https://idp.example.com/v"


# ---------------------------------------------------------------------------
# poll_device_flow
# ---------------------------------------------------------------------------


def test_poll_device_flow_success_returns_tokens() -> None:
    client = _StubClient([
        {
            "access_token": "AT",
            "id_token": "ID",
            "expires_in": 3600,
            "token_type": "Bearer",
            "refresh_token": "RT",
        }
    ])
    token = poll_device_flow(
        _config(), _endpoints_with_device(), "DCODE", client,
    )
    assert token.access_token == "AT"
    assert token.id_token == "ID"
    assert token.expires_in == 3600
    assert token.token_type == "Bearer"
    assert token.refresh_token == "RT"
    # Posted to the token endpoint with the device_code grant_type.
    _, url, body = client.calls[0]
    assert url == "https://idp.example.com/token"
    assert body["grant_type"] == "urn:ietf:params:oauth:grant-type:device_code"
    assert body["device_code"] == "DCODE"


@pytest.mark.parametrize("error_code,exc", [
    ("authorization_pending", DeviceFlowPending),
    ("slow_down", DeviceFlowSlowDown),
    ("expired_token", DeviceFlowExpired),
    ("access_denied", DeviceFlowDenied),
])
def test_poll_device_flow_raises_correct_exception_for_each_error(
    error_code: str, exc: type[Exception],
) -> None:
    """RFC 8628 defines 4 error codes that the poll loop interprets
    distinctly. Each maps to a typed exception so the caller can
    react correctly (pending → keep polling; slow_down → double the
    interval; expired → give up; denied → tell user)."""
    client = _StubClient([{"error": error_code}])
    with pytest.raises(exc):
        poll_device_flow(
            _config(), _endpoints_with_device(), "DCODE", client,
        )


def test_poll_device_flow_unknown_error_raises_config_error() -> None:
    client = _StubClient([
        {"error": "server_error", "error_description": "internal failure"}
    ])
    with pytest.raises(ConfigError, match="server_error"):
        poll_device_flow(
            _config(), _endpoints_with_device(), "DCODE", client,
        )


def test_poll_device_flow_response_missing_tokens_raises() -> None:
    """A 200 response that lacks the actual tokens (e.g., malformed
    IdP response) → ConfigError, not a silent success."""
    client = _StubClient([{"expires_in": 3600, "token_type": "Bearer"}])
    with pytest.raises(ConfigError, match="missing access_token"):
        poll_device_flow(
            _config(), _endpoints_with_device(), "DCODE", client,
        )
