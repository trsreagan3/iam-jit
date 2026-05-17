"""Integration test #215 / #153: OIDC against a real Keycloak.

The OIDC client code lives in ``src/iam_jit/oidc.py``. Unit tests mock
out the HTTP surface; the "real IdP doctor" path (#153) was previously
blocked on a real OIDC provider being available in the test
environment. With Keycloak in compose.test.yml that block is lifted.

This file ships ONE integration test that exercises the discovery +
JWKS-fetch path against Keycloak's `master` realm — the realm Keycloak
bootstraps automatically on `start-dev`. No realm import / client
creation is required for the discovery + JWKS contracts to be
exercisable, which keeps the test self-contained.

Skipped automatically (NOT failed) when the Keycloak service container
isn't running — see ``keycloak_endpoint`` fixture in conftest.py.

Full OIDC tests (authorization code exchange + ID token signature
verification + claim assertions) require a configured realm + client;
those land as follow-ups per ``[[local-test-infra-spec]]``.
"""

from __future__ import annotations

import time

import pytest

from iam_jit import oidc

pytestmark = pytest.mark.integration


def _wait_for_realm_ready(client: oidc.HttpxClient, discovery_url: str) -> None:
    """Poll discovery until Keycloak's master realm is fully bootstrapped.

    On a cold container start, the readiness endpoint returns 200 before
    the realm's discovery document is fully populated. We give it up to
    60s — empirically <2s when the container's already warm, ~10s on a
    cold start, never near the ceiling on the tested hardware.
    """
    deadline = time.time() + 60.0
    last_err: Exception | None = None
    while time.time() < deadline:
        try:
            doc = client.get_json(discovery_url, timeout=3.0)
            if doc.get("issuer") and doc.get("jwks_uri"):
                return
        except Exception as e:  # noqa: BLE001 — discovery error shape varies
            last_err = e
        time.sleep(1.0)
    raise AssertionError(
        f"Keycloak master realm discovery never became ready at {discovery_url}; "
        f"last error: {last_err!r}"
    )


def test_oidc_discovery_against_keycloak_master_realm(keycloak_endpoint: str) -> None:
    """``oidc.discover()`` returns a valid endpoints bundle from Keycloak.

    Validates the contract every iam-jit OIDC sign-in depends on: the
    discovery document carries the issuer, authorization_endpoint,
    token_endpoint, and jwks_uri — and the issuer the provider returns
    matches the issuer iam-jit was configured to expect.

    The matching issuer check is the security gate that prevents an
    imposter discovery doc from substituting a hostile token endpoint.
    """
    issuer = f"{keycloak_endpoint}/realms/master"
    discovery_url = f"{issuer}/.well-known/openid-configuration"

    client = oidc.HttpxClient()
    _wait_for_realm_ready(client, discovery_url)

    config = oidc.OIDCProviderConfig(
        provider="generic",
        issuer=issuer,
        client_id="placeholder-client-id",
        client_secret="placeholder-client-secret",
        redirect_uri="http://localhost:5000/oidc/callback",
    )

    endpoints = oidc.discover(config, client)

    assert endpoints.issuer.rstrip("/") == issuer.rstrip("/"), (
        "discovery doc issuer must match the configured issuer — this "
        "check is the security gate that blocks imposter discovery docs"
    )
    assert endpoints.authorization_endpoint.startswith(keycloak_endpoint), (
        "authorization_endpoint must live on the Keycloak host we configured"
    )
    assert endpoints.token_endpoint.startswith(keycloak_endpoint)
    assert endpoints.jwks_uri.startswith(keycloak_endpoint)


def test_oidc_jwks_fetch_against_keycloak_master_realm(keycloak_endpoint: str) -> None:
    """The JWKS endpoint Keycloak publishes is parseable + non-empty.

    Validates the JWKS-cache contract: production sign-in fetches the
    JWKS to verify the ID token's signature, so the JWKS endpoint MUST
    return a well-formed `keys` array. An empty `keys` array would
    silently break signature verification at sign-in time.
    """
    issuer = f"{keycloak_endpoint}/realms/master"
    discovery_url = f"{issuer}/.well-known/openid-configuration"

    client = oidc.HttpxClient()
    _wait_for_realm_ready(client, discovery_url)

    config = oidc.OIDCProviderConfig(
        provider="generic",
        issuer=issuer,
        client_id="placeholder-client-id",
        client_secret="placeholder-client-secret",
        redirect_uri="http://localhost:5000/oidc/callback",
    )

    endpoints = oidc.discover(config, client)
    jwks = client.get_json(endpoints.jwks_uri)

    keys = jwks.get("keys")
    assert isinstance(keys, list) and keys, (
        "JWKS keys array must be non-empty — empty would silently break "
        "ID token signature verification at sign-in"
    )
    # Every Keycloak JWK should carry kid + kty + alg at minimum.
    for k in keys:
        assert "kid" in k, "every JWK must have a kid for the cache to key on"
        assert "kty" in k, "every JWK must declare its key type"
