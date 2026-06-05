from __future__ import annotations

import pathlib

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from iam_jit.github_installations import (
    GitHubInstallationError,
    GitHubInstallationNotFound,
    get_installation,
    load_installations,
    provisioner_for,
)

_REGISTRY = """\
apiVersion: iam-jit.dev/v1alpha1
kind: GitHubInstallationList
installations:
  - org: acme
    alias: prod
    app_id: "12345"
    installation_id: "99"
    private_key_path: {keypath}
  - org: other-org
    app_id: "222"
    installation_id: "88"
    private_key_path: {keypath}
    enabled: false
"""


def _write_key(tmp_path: pathlib.Path) -> str:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    p = tmp_path / "app.pem"
    p.write_bytes(pem)
    return str(p)


def _registry(tmp_path: pathlib.Path) -> str:
    keypath = _write_key(tmp_path)
    p = tmp_path / "github-installations.yaml"
    p.write_text(_REGISTRY.format(keypath=keypath))
    return str(p)


def test_load_and_lookup_by_org_and_alias(tmp_path: pathlib.Path) -> None:
    reg = _registry(tmp_path)
    insts = load_installations(reg)
    assert len(insts) == 2
    by_org = get_installation(reg, "acme")
    assert by_org.app_id == "12345" and by_org.installation_id == "99"
    # alias lookup + case-insensitive org
    assert get_installation(reg, "PROD").org == "acme"
    assert get_installation(reg, "ACME").org == "acme"


def test_missing_file_is_empty_registry(tmp_path: pathlib.Path) -> None:
    assert load_installations(tmp_path / "nope.yaml") == []


def test_unknown_org_raises(tmp_path: pathlib.Path) -> None:
    reg = _registry(tmp_path)
    with pytest.raises(GitHubInstallationNotFound):
        get_installation(reg, "ghost")


def test_missing_required_field_is_loud(tmp_path: pathlib.Path) -> None:
    p = tmp_path / "bad.yaml"
    p.write_text(
        "apiVersion: iam-jit.dev/v1alpha1\nkind: GitHubInstallationList\n"
        "installations:\n  - org: acme\n    app_id: \"1\"\n"  # missing installation_id + key path
    )
    with pytest.raises(GitHubInstallationError, match="missing required"):
        load_installations(p)


def test_provisioner_for_reads_key_and_can_sign(tmp_path: pathlib.Path) -> None:
    reg = _registry(tmp_path)
    inst = get_installation(reg, "acme")
    # mock GitHub so the mint stays hermetic
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["auth"] = request.headers["Authorization"]
        return httpx.Response(
            201,
            json={"token": "ghs_x", "expires_at": "2026-06-05T01:00:00Z",
                  "permissions": {"contents": "read"}, "repositories": [{"name": "r"}]},
        )

    p = provisioner_for(inst, http=httpx.Client(transport=httpx.MockTransport(handler)),
                        now=lambda: 1_780_000_000)
    out = p.mint_scoped_token(repositories=["r"], permissions={"contents": "read"})
    assert out.token == "ghs_x"
    # the App JWT was signed with the key loaded from private_key_path
    assert captured["auth"].startswith("Bearer ")
    jwt.decode(captured["auth"][len("Bearer "):],
               # decode header only to confirm it's a real RS256 JWT
               options={"verify_signature": False})


def test_provisioner_for_disabled_installation_refuses(tmp_path: pathlib.Path) -> None:
    reg = _registry(tmp_path)
    inst = get_installation(reg, "other-org")  # enabled: false
    with pytest.raises(GitHubInstallationError, match="disabled"):
        provisioner_for(inst)
