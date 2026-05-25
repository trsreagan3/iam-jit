"""Access-type vs policy preview-check at form-submit — #605 HIGH.

Founder Q 2026-05-25 (verbatim): "what if someone marks a role as
read-only, but actually puts write privileges in the policy?"

Pre-fix shape: the web paste-form submit handler accepted
`access_type=read-only` even when the policy contained mutating
actions (`s3:PutObject`, `iam:CreateRole`, ...). The mismatch only
surfaced later at scoring time, and could still slip through
auto-approve depending on the scorer's penalty + the deployment's
threshold. The user had lied (intentionally or by mistake) about the
request shape and the system silently moved on.

Post-fix shape: when access_type is "read-only" but the policy
contains write-class actions (as classified by the scorer's
`_action_level` helper — single source of truth per
`[[scorer-is-ground-truth]]`), the form-submit handler refuses inline
with HTTP 403, the user's typed input preserved, and a structured
error that NAMES the specific offending actions (first 5 + "+N more"
truncation). Per `[[ibounce-honest-positioning]]` the rejection is
actionable on its own: the user knows exactly which actions broke
the read-only contract and what to do about them.

These tests follow the state-verification convention in
`docs/CONTRIBUTING.md`: every assertion about the reported status
ALSO asserts the observable side effect — most notably that the
mismatched submission leaves the request store EMPTY (the user has
to fix + resubmit), not "in pending and waiting for an approver."

The sabotage test proves the access-type gate is load-bearing: with
the `_classify_write_actions` helper stubbed to return [], the same
read-only + write-policy submission that the production gate
rejected is now accepted (303 + persisted) — i.e., the production
classifier is the only thing keeping the mismatched submission out
of the store.
"""

from __future__ import annotations

import json
from typing import Any

import pytest
from fastapi.testclient import TestClient

pytest_plugins = ["tests.conftest_routes"]


# -----------------------------------------------------------------------------
# Test fixtures — policy shapes for the access_type matrix.
# -----------------------------------------------------------------------------


def _read_only_policy() -> str:
    """A genuine read-only policy: only IAM-classified Read/List
    actions. Honest pair with access_type=read-only."""
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:ListBucket",
                    ],
                    "Resource": [
                        "arn:aws:s3:::artifacts",
                        "arn:aws:s3:::artifacts/*",
                    ],
                }
            ],
        }
    )


def _write_mixed_policy() -> str:
    """A policy that mixes read + write actions. The write half
    breaks the read-only contract; the gate names s3:PutObject and
    iam:CreateRole as offenders."""
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:GetObject",
                        "s3:PutObject",
                        "iam:CreateRole",
                    ],
                    "Resource": "*",
                }
            ],
        }
    )


def _eight_writes_policy() -> str:
    """8 distinct write-class actions — exercises the "first 5 + (+3
    more)" truncation in the error message."""
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": [
                        "s3:PutObject",
                        "s3:DeleteObject",
                        "iam:CreateRole",
                        "iam:DeleteRole",
                        "iam:AttachRolePolicy",
                        "ec2:RunInstances",
                        "ec2:TerminateInstances",
                        "lambda:CreateFunction",
                    ],
                    "Resource": "*",
                }
            ],
        }
    )


def _form_body(*, policy: str, access_type: str) -> dict[str, str]:
    return {
        "description": "access_type vs policy preview-check — #605",
        "policy": policy,
        "access_type": access_type,
        "accounts": "060392206767",
        "duration_hours": "1",
    }


def _store_request_count(app: Any) -> int:
    """State-verification helper: how many requests are persisted?
    A rejected submission MUST leave this unchanged."""
    store = app.state.request_store
    return len(store.list_ids())


# -----------------------------------------------------------------------------
# Tests.
# -----------------------------------------------------------------------------


def test_read_only_with_read_only_policy_accepted(
    as_dev: TestClient,
) -> None:
    """Regression-pin: a genuine read-only request (read actions only
    + access_type=read-only) MUST still be accepted. The gate fires
    ONLY on the mismatched combination, never on the honest one.

    State-verification: store gains exactly one request after the
    submit; the response redirects to /requests/<id>. Without this
    assertion the test would still pass if the gate over-fired and
    blocked the honest case while returning 303 by accident.
    """
    before = _store_request_count(as_dev.app)
    resp = as_dev.post(
        "/requests/new/paste",
        data=_form_body(
            policy=_read_only_policy(), access_type="read-only"
        ),
        follow_redirects=False,
    )
    assert resp.status_code == 303, (
        f"honest read-only must redirect; got {resp.status_code}: "
        f"{resp.text[:400]}"
    )
    location = resp.headers["location"]
    assert location.startswith("/requests/"), location

    after = _store_request_count(as_dev.app)
    assert after == before + 1, (
        f"honest read-only must persist a request; "
        f"before={before} after={after}"
    )


def test_read_only_with_write_policy_rejected_inline_with_named_actions(
    as_dev: TestClient,
) -> None:
    """Founder's exact question: access_type=read-only + a policy
    that contains write actions MUST be refused inline at form-submit
    with a 403 response that NAMES the specific write actions.

    State-verification (THIS is what makes the test catch the
    regression): the response body contains BOTH offending action
    names (s3:PutObject, iam:CreateRole) AND the literal string
    "read-only" AND a remediation hint that points to either
    "read-write" or "remove the write actions". Without the fix the
    response would be a 303 + the request would land in the store.
    """
    before = _store_request_count(as_dev.app)
    resp = as_dev.post(
        "/requests/new/paste",
        data=_form_body(
            policy=_write_mixed_policy(), access_type="read-only"
        ),
        follow_redirects=False,
    )

    # Claim: 403, NOT 303.
    assert resp.status_code == 403, (
        f"read-only + write-policy must be rejected at the form; "
        f"got status {resp.status_code}; body[:400]={resp.text[:400]}"
    )

    body = resp.text
    # The specific offending actions MUST be named so the user knows
    # what to fix. Per [[ibounce-honest-positioning]] the rejection
    # is actionable on its own.
    assert "s3:PutObject" in body, (
        "rejection must name s3:PutObject so user knows the offender"
    )
    assert "iam:CreateRole" in body, (
        "rejection must name iam:CreateRole so user knows the offender"
    )
    # The user must be told WHICH contract was broken.
    assert "read-only" in body, (
        "rejection must mention 'read-only' so user knows which "
        "access_type was declared"
    )
    # The user must be told HOW to fix it.
    assert "read-write" in body, (
        "rejection must offer 'read-write' as the alternative access_type"
    )

    # Observable state: NO request was persisted.
    after = _store_request_count(as_dev.app)
    assert after == before, (
        f"rejected submission must NOT persist a request; "
        f"before={before} after={after}"
    )


def test_read_write_with_write_policy_accepted(
    as_dev: TestClient,
) -> None:
    """access_type=read-write + a write policy is HONEST about the
    intent — the gate MUST NOT fire here. Distinguishes the gate from
    "any write action is forbidden" (it isn't; only the mismatch is).

    State-verification: store gains exactly one request after the
    submit.
    """
    before = _store_request_count(as_dev.app)
    resp = as_dev.post(
        "/requests/new/paste",
        data=_form_body(
            policy=_write_mixed_policy(), access_type="read-write"
        ),
        follow_redirects=False,
    )
    assert resp.status_code == 303, (
        f"honest read-write + write-policy must succeed; "
        f"got {resp.status_code}: {resp.text[:400]}"
    )
    after = _store_request_count(as_dev.app)
    assert after == before + 1, (
        f"honest read-write must persist a request; "
        f"before={before} after={after}"
    )


def test_read_only_with_eight_writes_truncates_to_first_five(
    as_dev: TestClient,
) -> None:
    """When the policy contains MORE than 5 write actions, the error
    message MUST show the first 5 + "(+N more)" truncation so the
    flash banner doesn't become unbounded. Verifies both halves of
    the bound: the first 5 are named, AND the "+3 more" suffix is
    present.

    State-verification: response is 403, body contains the
    truncation marker, NO request was persisted.
    """
    before = _store_request_count(as_dev.app)
    resp = as_dev.post(
        "/requests/new/paste",
        data=_form_body(
            policy=_eight_writes_policy(), access_type="read-only"
        ),
        follow_redirects=False,
    )
    assert resp.status_code == 403
    body = resp.text

    # First 5 named (order matches the policy's Action list ordering
    # since the helper is order-preserving by first appearance).
    for first in (
        "s3:PutObject",
        "s3:DeleteObject",
        "iam:CreateRole",
        "iam:DeleteRole",
        "iam:AttachRolePolicy",
    ):
        assert first in body, (
            f"truncation must still name the first-5 offender {first}"
        )

    # "+3 more" suffix MUST be present (8 offenders - 5 shown = 3).
    assert "+3 more" in body, (
        f"truncation marker '+3 more' missing; body[:600]={body[:600]}"
    )

    after = _store_request_count(as_dev.app)
    assert after == before, (
        f"rejected submission must NOT persist a request; "
        f"before={before} after={after}"
    )


def test_sabotage_check_classifier_is_load_bearing(
    as_dev: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sabotage check (per [[deliberate-feature-completion]] +
    docs/CONTRIBUTING.md state-verification convention): if we
    monkeypatch `_classify_write_actions` to always return [], the
    same read-only + write-policy submission that the production
    gate rejected MUST now be accepted (303 + stored).

    This proves the classifier is the only thing keeping the
    mismatched submission out of the store — a future refactor that
    silently bypasses the classifier would fail this test loudly,
    not silently regress (which is exactly the #326/#448/#463 shape
    documented in docs/CONTRIBUTING.md).
    """
    from iam_jit.routes import web as web_routes

    monkeypatch.setattr(
        web_routes, "_classify_write_actions", lambda _policy: []
    )

    before = _store_request_count(as_dev.app)
    resp = as_dev.post(
        "/requests/new/paste",
        data=_form_body(
            policy=_write_mixed_policy(), access_type="read-only"
        ),
        follow_redirects=False,
    )

    # With the classifier sabotaged, the form-submit no longer sees
    # any write actions to flag and falls through to store.put +
    # redirect. The presence of this redirect proves the classifier
    # at the form-submit handler is the load-bearing piece — not the
    # schema validator, not the scorer's later analysis, not the
    # auto-approve evaluator.
    assert resp.status_code == 303, (
        f"sabotage check: with _classify_write_actions stubbed to [], "
        f"the same submission that the production gate rejected MUST "
        f"now succeed (303 + persisted). Instead got status "
        f"{resp.status_code}; body[:400]={resp.text[:400]}. If this "
        f"test fails as 403 even with the sabotage, the form-submit "
        f"handler has a SECOND access_type-vs-policy check that the "
        f"#605 fix is not the only thing keeping the request out of "
        f"the store."
    )
    after = _store_request_count(as_dev.app)
    assert after == before + 1, (
        f"sabotage check: store.put must run when the classifier is "
        f"removed; before={before} after={after}"
    )
