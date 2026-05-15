"""Pinned tests for round-7 focused white-box audit closures.

Round-7 WB audit (`docs/security/AUDIT-2026-05-WB-ROUND7-FOCUSED.md`)
landed 8 findings; 6 were in `src/iam_jit/bridge_role.py` and closed
by DELETING that module (it mutated existing customer IAM, which
violates the [[creates-never-mutates]] invariant). The remaining
two real findings — WB7F-07 (MED) and WB7F-08 (LOW) — are pinned
here.
"""

from __future__ import annotations

import ast
import inspect
import os
import textwrap

import pytest

from iam_jit import ddb_utils, trusted_proxy
from iam_jit.routes import feedback as feedback_route
from iam_jit.routes import score as score_route


def _function_body_source(fn) -> str:
    """Return the executable source of `fn`, stripped of the
    docstring so substring assertions don't hit comments."""
    src = textwrap.dedent(inspect.getsource(fn))
    tree = ast.parse(src)
    func = tree.body[0]
    assert isinstance(func, (ast.FunctionDef, ast.AsyncFunctionDef))
    # Drop the docstring node if present.
    body = func.body
    if (
        body
        and isinstance(body[0], ast.Expr)
        and isinstance(body[0].value, ast.Constant)
        and isinstance(body[0].value.value, str)
    ):
        body = body[1:]
    return "\n".join(ast.unparse(node) for node in body)


# ---------------------------------------------------------------------------
# WB7F-07 (MED) FEEDBACK-CLIENT-IP-XFF-BYPASS — sibling-miss closure.
# ---------------------------------------------------------------------------


def test_wb7f_07_feedback_uses_shared_client_ip_helper() -> None:
    """`routes/feedback.py:_submitter_ip` must NOT read
    `request.client.host` raw — it must delegate to
    `trusted_proxy.client_ip`. Round-5 audit closed the score-route
    path via this helper; round-7 caught feedback as the
    sibling-miss."""
    body = _function_body_source(feedback_route._submitter_ip)
    assert "trusted_proxy.client_ip" in body
    # And the raw read pattern is gone from EXECUTABLE code.
    assert "request.client.host" not in body


def test_wb7f_07_score_route_still_uses_shared_helper() -> None:
    """The score-route closure has to keep using the shared helper
    too — verifying the refactor didn't accidentally re-inline."""
    body = _function_body_source(score_route._client_ip)
    assert "trusted_proxy.client_ip" in body
    assert "request.client.host" not in body


def test_wb7f_07_helper_lives_in_one_place() -> None:
    """The shared helper exists and is the single source of truth."""
    assert hasattr(trusted_proxy, "client_ip")
    assert callable(trusted_proxy.client_ip)


def test_wb7f_07_client_ip_returns_socket_peer_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With no trust flag set, the helper returns the socket peer
    even if X-Forwarded-For is present. This is the closure for the
    rate-limit-bypass primitive (attacker rotating XFF to defeat
    the limiter)."""
    monkeypatch.delenv("IAM_JIT_TRUST_FORWARDED_FOR", raising=False)
    monkeypatch.delenv("IAM_JIT_TRUST_FORWARDED_FOR_FOR_SCORE", raising=False)

    class _Client:
        host = "10.0.0.42"

    class _Req:
        client = _Client()
        headers = {"x-forwarded-for": "203.0.113.99"}

    assert trusted_proxy.client_ip(_Req()) == "10.0.0.42"


def test_wb7f_07_client_ip_honors_legacy_score_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Legacy `IAM_JIT_TRUST_FORWARDED_FOR_FOR_SCORE=1` must still
    enable XFF trust for the score route — back-compat with
    deployments that set the old flag."""
    monkeypatch.setenv("IAM_JIT_TRUST_FORWARDED_FOR_FOR_SCORE", "1")
    monkeypatch.setenv("IAM_JIT_TRUSTED_PROXY_CIDRS", "10.0.0.0/8")

    class _Client:
        host = "10.0.0.42"

    class _Req:
        client = _Client()
        headers = {"x-forwarded-for": "203.0.113.99"}

    # With the legacy flag set, the score route accepts XFF.
    assert (
        trusted_proxy.client_ip(
            _Req(),
            legacy_env_flags=("IAM_JIT_TRUST_FORWARDED_FOR_FOR_SCORE",),
        )
        == "203.0.113.99"
    )

    # But the feedback route — which does NOT pass the legacy flag —
    # stays in fail-closed default mode (ignores XFF).
    assert trusted_proxy.client_ip(_Req()) == "10.0.0.42"


# ---------------------------------------------------------------------------
# WB7F-08 (LOW) DDB-UTILS-CCFE-SUBSTRING-MATCH-LOOSE — tightening.
# ---------------------------------------------------------------------------


def test_wb7f_08_ccfe_matches_structured_clienterror() -> None:
    """The structured boto3 ClientError shape still maps to True."""

    class _Fake(Exception):
        pass

    e = _Fake("…")
    e.response = {"Error": {"Code": "ConditionalCheckFailedException"}}
    assert ddb_utils.is_conditional_check_failed(e) is True


def test_wb7f_08_ccfe_matches_botocore_str_form() -> None:
    """Botocore's `ClientError.__str__` wraps the code in parens:
    `An error occurred (ConditionalCheckFailedException) when …`.
    The anchored matcher catches this."""

    class _Fake(Exception):
        pass

    e = _Fake(
        "An error occurred (ConditionalCheckFailedException) when "
        "calling the UpdateItem operation: …"
    )
    assert ddb_utils.is_conditional_check_failed(e) is True


def test_wb7f_08_ccfe_matches_start_anchored_synthetic() -> None:
    """Synthetic test mocks that raise an exception whose `str()`
    STARTS WITH the code name still match — keeps existing audit
    fixtures green."""

    class _Fake(Exception):
        pass

    e = _Fake("ConditionalCheckFailedException encountered in stub")
    assert ddb_utils.is_conditional_check_failed(e) is True


def test_wb7f_08_ccfe_rejects_wrapped_embedded_text() -> None:
    """The closure: a wrapper/chained exception whose `str()` merely
    MENTIONS the code (not anchored, not paren-wrapped) must NOT
    match — that was the WB7F-08 false-positive surface."""

    class _Wrapper(Exception):
        pass

    e = _Wrapper(
        "db update failed; cause: ConditionalCheckFailedException "
        "was raised earlier"
    )
    assert ddb_utils.is_conditional_check_failed(e) is False


def test_wb7f_08_ccfe_matches_class_name() -> None:
    """The modern resource-typed boto3 exception is matched by
    class name even if `str()` is empty / unhelpful."""

    class ConditionalCheckFailedException(Exception):
        pass

    e = ConditionalCheckFailedException()
    assert ddb_utils.is_conditional_check_failed(e) is True


def test_wb7f_08_ccfe_rejects_unrelated_exception() -> None:
    """Unrelated exceptions must not match."""
    assert ddb_utils.is_conditional_check_failed(ValueError("nope")) is False
    assert (
        ddb_utils.is_conditional_check_failed(RuntimeError("throttled"))
        is False
    )
