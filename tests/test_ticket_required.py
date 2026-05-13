"""Per-deployment ticket-required policy."""

from __future__ import annotations

import os

import pytest

from iam_jit import schema


def _req(ticket: str | None = None) -> dict:
    spec: dict = {
        "description": "test ticket required",
        "accounts": [{"account_id": "060392206767"}],
        "duration": {"duration_hours": 24},
        "policy": {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "arn:aws:s3:::x/y"}
            ],
        },
    }
    if ticket:
        spec["ticket"] = ticket
    return {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "RoleRequest",
        "metadata": {"requester": {"name": "Dev", "email": "dev@example.com"}},
        "spec": spec,
    }


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("IAM_JIT_REQUIRE_TICKET", raising=False)
    monkeypatch.delenv("IAM_JIT_TICKET_HOST_PATTERN", raising=False)


def test_ticket_optional_by_default() -> None:
    assert schema.validate_request(_req()) == []


def test_invalid_ticket_url_fails_schema_validation() -> None:
    errors = schema.validate_request(_req(ticket="not-a-url"))
    assert any("ticket" in e for e in errors)


def test_valid_ticket_passes() -> None:
    assert schema.validate_request(_req(ticket="https://jira.example.com/browse/CHG-1")) == []


def test_required_blocks_when_missing(monkeypatch) -> None:
    monkeypatch.setenv("IAM_JIT_REQUIRE_TICKET", "1")
    errors = schema.validate_request(_req())
    assert any("required by this deployment" in e for e in errors)


def test_required_passes_when_present(monkeypatch) -> None:
    monkeypatch.setenv("IAM_JIT_REQUIRE_TICKET", "1")
    assert schema.validate_request(_req(ticket="https://jira.example.com/browse/CHG-1")) == []


def test_host_pattern_enforced(monkeypatch) -> None:
    monkeypatch.setenv("IAM_JIT_REQUIRE_TICKET", "1")
    monkeypatch.setenv("IAM_JIT_TICKET_HOST_PATTERN", "jira.example.com,github.com/your-org")
    errors = schema.validate_request(_req(ticket="https://otherthing.com/x"))
    assert any("allowed host patterns" in e for e in errors)


def test_host_pattern_allows_match(monkeypatch) -> None:
    monkeypatch.setenv("IAM_JIT_REQUIRE_TICKET", "1")
    monkeypatch.setenv("IAM_JIT_TICKET_HOST_PATTERN", "jira.example.com")
    assert schema.validate_request(_req(ticket="https://jira.example.com/browse/CHG-1")) == []
