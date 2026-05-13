from __future__ import annotations

import pytest
from itsdangerous import BadSignature

from iam_jit.auth import (
    extract_iam_principal,
    hash_token,
    issue_api_token,
    normalize_iam_id,
    sign_magic_link,
    sign_session,
    verify_magic_link,
    verify_session,
)


_SECRET = "test-secret-32-bytes-long-aaaaaaaaa"


def test_session_round_trip() -> None:
    cookie = sign_session(_SECRET, "email:alice@example.com")
    assert verify_session(_SECRET, cookie) == "email:alice@example.com"


def test_session_wrong_secret_rejected() -> None:
    cookie = sign_session(_SECRET, "email:alice@example.com")
    with pytest.raises(BadSignature):
        verify_session("different-secret", cookie)


def test_session_tampered_rejected() -> None:
    cookie = sign_session(_SECRET, "email:alice@example.com")
    tampered = cookie[:-2] + "ZZ"
    with pytest.raises(BadSignature):
        verify_session(_SECRET, tampered)


def test_magic_link_round_trip() -> None:
    token = sign_magic_link(_SECRET, "alice@example.com")
    assert verify_magic_link(_SECRET, token) == "alice@example.com"


def test_magic_link_wrong_secret() -> None:
    token = sign_magic_link(_SECRET, "alice@example.com")
    with pytest.raises(BadSignature):
        verify_magic_link("different-secret", token)


def test_api_token_format_and_hash() -> None:
    issued = issue_api_token("email:alice@example.com", label="laptop")
    assert issued.raw.startswith("iamjit_")
    assert len(issued.raw) > 30
    assert issued.user_id == "email:alice@example.com"
    assert issued.label == "laptop"
    # Hash is deterministic and one-way.
    assert hash_token(issued.raw) == issued.hash
    assert hash_token(issued.raw + "x") != issued.hash


def test_api_tokens_are_unique() -> None:
    a = issue_api_token("email:x@example.com")
    b = issue_api_token("email:x@example.com")
    assert a.raw != b.raw
    assert a.hash != b.hash


def test_extract_iam_principal_present() -> None:
    event = {
        "requestContext": {
            "authorizer": {"iam": {"userArn": "arn:aws:iam::123:role/Devops"}}
        }
    }
    assert extract_iam_principal(event) == "arn:aws:iam::123:role/Devops"


def test_extract_iam_principal_missing() -> None:
    assert extract_iam_principal({}) is None
    assert extract_iam_principal({"requestContext": {}}) is None


def test_normalize_iam_role_arn() -> None:
    assert (
        normalize_iam_id("arn:aws:iam::123:role/Devops")
        == "iam:arn:aws:iam::123:role/Devops"
    )


def test_normalize_identity_center_session_to_role() -> None:
    arn = "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_DevOps_xyz/alice@example.com"
    expected = "iam:arn:aws:iam::123456789012:role/AWSReservedSSO_DevOps_xyz"
    assert normalize_iam_id(arn) == expected
