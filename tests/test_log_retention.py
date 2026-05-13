"""Log-retention as a compliance / audit control.

Two layers tested here:

  1. The pure-Python validator + setter in iam_jit.log_retention.
  2. The /api/v1/admin/log-retention endpoints in routes/admin.py
     (auth gating, floor enforcement, audit emission).

A fake CloudWatch Logs client is injected via monkeypatching the
admin module's `get_logs_client` reference. This keeps the tests
hermetic (no boto3 / moto needed for behavior that's a thin
wrapper around two CloudWatch APIs).
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from iam_jit import log_retention

pytest_plugins = ["tests.conftest_routes"]


class FakeLogsClient:
    """Stand-in for boto3.client('logs') — records calls + returns
    canned responses. The two APIs touched: describe_log_groups
    and put_retention_policy."""

    def __init__(
        self,
        *,
        log_groups: list[dict[str, Any]] | None = None,
        describe_raises: Exception | None = None,
        put_raises: Exception | None = None,
    ) -> None:
        self._log_groups = log_groups or []
        self._describe_raises = describe_raises
        self._put_raises = put_raises
        self.put_calls: list[dict[str, Any]] = []
        self.describe_calls: list[dict[str, Any]] = []

    def describe_log_groups(self, **kwargs: Any) -> dict[str, Any]:
        self.describe_calls.append(kwargs)
        if self._describe_raises:
            raise self._describe_raises
        return {"logGroups": list(self._log_groups)}

    def put_retention_policy(self, **kwargs: Any) -> dict[str, Any]:
        self.put_calls.append(kwargs)
        if self._put_raises:
            raise self._put_raises
        # Mutate the local cache so subsequent describes reflect the
        # change — matches CloudWatch's read-after-write semantics
        # for retention.
        for lg in self._log_groups:
            if lg.get("logGroupName") == kwargs.get("logGroupName"):
                lg["retentionInDays"] = kwargs.get("retentionInDays")
        return {}


# ---- Pure-Python layer -----------------------------------------------


def test_floor_defaults_match_compliance_baseline() -> None:
    """Default floor is 545 days (~1.5y) — exceeds PCI DSS 1y +
    matches SOC 2 norms. Changing this default is a compliance-
    impacting decision; this test exists to make that explicit."""
    floor = log_retention.RetentionFloor()
    assert floor.min_days == 545
    assert floor.configured_at_deploy_days == 545
    assert floor.log_group_name == "/aws/lambda/iam-jit"


def test_floor_reads_env_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("IAM_JIT_MIN_LOG_RETENTION_DAYS", "731")
    monkeypatch.setenv("IAM_JIT_LOG_RETENTION_DAYS", "1827")
    monkeypatch.setenv("IAM_JIT_LOG_GROUP_NAME", "/custom/log-group")
    f = log_retention.RetentionFloor.from_env()
    assert f.min_days == 731
    assert f.configured_at_deploy_days == 1827
    assert f.log_group_name == "/custom/log-group"


def test_floor_falls_back_on_invalid_env(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An invalid env var should not break startup; falls back to
    the safe default. (A broken floor is a security regression —
    fail-closed at 545 is the right default.)"""
    monkeypatch.setenv("IAM_JIT_MIN_LOG_RETENTION_DAYS", "not-a-number")
    f = log_retention.RetentionFloor.from_env()
    assert f.min_days == 545


def test_validate_rejects_below_floor() -> None:
    floor = log_retention.RetentionFloor(min_days=545)
    errors = log_retention.validate_retention(180, floor)
    assert errors
    assert "180" in errors[0]
    assert "545" in errors[0]


def test_validate_rejects_invalid_window() -> None:
    """200 isn't a CloudWatch retention window — must be from the
    discrete VALID_RETENTION_DAYS set."""
    floor = log_retention.RetentionFloor(min_days=1)
    errors = log_retention.validate_retention(200, floor)
    assert errors
    assert "200" in errors[0]


def test_validate_accepts_at_or_above_floor() -> None:
    floor = log_retention.RetentionFloor(min_days=545)
    assert log_retention.validate_retention(545, floor) == []
    assert log_retention.validate_retention(731, floor) == []
    assert log_retention.validate_retention(1827, floor) == []


def test_get_current_retention_returns_value() -> None:
    fake = FakeLogsClient(
        log_groups=[
            {"logGroupName": "/aws/lambda/iam-jit", "retentionInDays": 545},
            {"logGroupName": "/aws/lambda/other", "retentionInDays": 30},
        ],
    )
    days = log_retention.get_current_retention(fake, "/aws/lambda/iam-jit")
    assert days == 545


def test_get_current_retention_returns_none_for_unset() -> None:
    """Log group with no retentionInDays key = CloudWatch's "never
    expire" mode. Surface as None so the API caller knows the
    difference between "never expire" and "set to 0"."""
    fake = FakeLogsClient(
        log_groups=[{"logGroupName": "/aws/lambda/iam-jit"}],  # no retention key
    )
    days = log_retention.get_current_retention(fake, "/aws/lambda/iam-jit")
    assert days is None


def test_get_current_retention_raises_when_missing() -> None:
    fake = FakeLogsClient(log_groups=[])
    with pytest.raises(log_retention.RetentionError) as excinfo:
        log_retention.get_current_retention(fake, "/aws/lambda/iam-jit")
    assert "not found" in str(excinfo.value).lower()


def test_set_retention_calls_aws_when_valid() -> None:
    fake = FakeLogsClient(
        log_groups=[{"logGroupName": "/aws/lambda/iam-jit", "retentionInDays": 545}],
    )
    floor = log_retention.RetentionFloor(min_days=545)
    log_retention.set_retention(fake, "/aws/lambda/iam-jit", 731, floor)
    assert len(fake.put_calls) == 1
    assert fake.put_calls[0]["retentionInDays"] == 731


def test_set_retention_refuses_below_floor() -> None:
    fake = FakeLogsClient(log_groups=[])
    floor = log_retention.RetentionFloor(min_days=545)
    with pytest.raises(log_retention.RetentionError):
        log_retention.set_retention(fake, "/aws/lambda/iam-jit", 30, floor)
    # No AWS call made — refused at the validator before the API call.
    assert fake.put_calls == []


def test_set_retention_refuses_invalid_window() -> None:
    fake = FakeLogsClient(log_groups=[])
    floor = log_retention.RetentionFloor(min_days=1)
    with pytest.raises(log_retention.RetentionError):
        log_retention.set_retention(fake, "/aws/lambda/iam-jit", 999, floor)
    assert fake.put_calls == []


def test_set_retention_refuses_foreign_log_group() -> None:
    """Defense-in-depth: even with valid retention days, the handler
    must refuse to modify any log group OTHER than iam-jit's own.

    The IAM policy already enforces this at the AWS layer (the
    DenyRetentionOnForeignLogGroups statement), but the handler-side
    check fails earlier with a clearer error and protects against
    accidental IAM policy widening in future template edits.
    """
    fake = FakeLogsClient(
        log_groups=[
            {"logGroupName": "/aws/lambda/iam-jit", "retentionInDays": 545},
            {"logGroupName": "/aws/lambda/other-app", "retentionInDays": 7},
        ],
    )
    floor = log_retention.RetentionFloor(
        min_days=545, log_group_name="/aws/lambda/iam-jit",
    )
    # Try to shorten retention on /aws/lambda/other-app to 1 day —
    # the kind of attack a compromised iam-jit admin might attempt
    # to bury someone else's audit logs.
    with pytest.raises(log_retention.RetentionError) as excinfo:
        log_retention.set_retention(
            fake, "/aws/lambda/other-app", 731, floor,
        )
    msg = str(excinfo.value).lower()
    assert "other-app" in msg or "foreign" in msg or "may only" in msg
    # And critically: no AWS call against the foreign log group.
    assert fake.put_calls == []


def test_patch_log_retention_admin_route_uses_floor_log_group(
    as_admin: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The admin route MUST always pass the floor's log_group_name —
    a malicious payload can't redirect it. We can't easily inject a
    "wrong log group" through the route's PATCH body (the payload
    doesn't take a log_group_name field — by design — the floor is
    the single source of truth), but verify the route is using the
    floor value and not honoring any caller-supplied override."""
    fake = FakeLogsClient(
        log_groups=[
            {"logGroupName": "/aws/lambda/iam-jit-canary",
             "retentionInDays": 545},
        ],
    )
    _inject_fake_logs(monkeypatch, fake)
    # Set the floor's log_group_name to something specific so we can
    # verify the route uses IT, not a default.
    monkeypatch.setenv("IAM_JIT_MIN_LOG_RETENTION_DAYS", "545")
    monkeypatch.setenv("IAM_JIT_LOG_GROUP_NAME", "/aws/lambda/iam-jit-canary")

    # An attacker tries to sneak a log_group_name into the payload —
    # the route ignores it and uses the floor's value.
    r = as_admin.patch(
        "/api/v1/admin/log-retention",
        json={
            "retention_days": 731,
            "log_group_name": "/aws/lambda/some-other-app",  # ignored
            "logGroupName": "/aws/lambda/another-target",  # ignored
        },
    )
    assert r.status_code == 200, r.text
    # The single AWS call hit the floor's log group, not the
    # caller-supplied one.
    assert len(fake.put_calls) == 1
    assert fake.put_calls[0]["logGroupName"] == "/aws/lambda/iam-jit-canary"


# ---- Admin route layer ------------------------------------------------


def _inject_fake_logs(monkeypatch: pytest.MonkeyPatch, fake: FakeLogsClient) -> None:
    """Wire the fake CloudWatch client into the admin module."""
    from iam_jit.routes import admin as admin_mod

    monkeypatch.setattr(admin_mod, "get_logs_client", lambda: fake)


def test_get_log_retention_requires_admin(
    as_dev: TestClient,
    as_approver: TestClient,
    as_admin: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeLogsClient(
        log_groups=[{"logGroupName": "/aws/lambda/iam-jit", "retentionInDays": 545}],
    )
    _inject_fake_logs(monkeypatch, fake)
    assert as_dev.get("/api/v1/admin/log-retention").status_code == 403
    assert as_approver.get("/api/v1/admin/log-retention").status_code == 403
    assert as_admin.get("/api/v1/admin/log-retention").status_code == 200


def test_get_log_retention_returns_current_plus_floor(
    as_admin: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeLogsClient(
        log_groups=[{"logGroupName": "/aws/lambda/iam-jit", "retentionInDays": 545}],
    )
    _inject_fake_logs(monkeypatch, fake)
    monkeypatch.setenv("IAM_JIT_MIN_LOG_RETENTION_DAYS", "545")
    monkeypatch.setenv("IAM_JIT_LOG_RETENTION_DAYS", "545")
    monkeypatch.setenv("IAM_JIT_LOG_GROUP_NAME", "/aws/lambda/iam-jit")

    r = as_admin.get("/api/v1/admin/log-retention")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["current_days"] == 545
    assert body["floor"]["min_days"] == 545
    assert body["floor"]["configured_at_deploy_days"] == 545
    assert 1827 in body["valid_retention_days"]
    # The explainer must reference the evidence-destruction angle
    # so the admin reading the API knows WHY the floor exists.
    assert "evidence" in body["floor_explainer"].lower()


def test_patch_log_retention_extends_successfully(
    as_admin: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeLogsClient(
        log_groups=[{"logGroupName": "/aws/lambda/iam-jit", "retentionInDays": 545}],
    )
    _inject_fake_logs(monkeypatch, fake)
    monkeypatch.setenv("IAM_JIT_MIN_LOG_RETENTION_DAYS", "545")
    monkeypatch.setenv("IAM_JIT_LOG_GROUP_NAME", "/aws/lambda/iam-jit")

    r = as_admin.patch(
        "/api/v1/admin/log-retention",
        json={"retention_days": 731},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["current_days"] == 731
    assert body["previous_days"] == 545
    assert len(fake.put_calls) == 1
    assert fake.put_calls[0]["retentionInDays"] == 731


def test_patch_log_retention_refuses_below_floor(
    as_admin: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeLogsClient(
        log_groups=[{"logGroupName": "/aws/lambda/iam-jit", "retentionInDays": 545}],
    )
    _inject_fake_logs(monkeypatch, fake)
    monkeypatch.setenv("IAM_JIT_MIN_LOG_RETENTION_DAYS", "545")
    monkeypatch.setenv("IAM_JIT_LOG_GROUP_NAME", "/aws/lambda/iam-jit")

    r = as_admin.patch(
        "/api/v1/admin/log-retention",
        json={"retention_days": 30},
    )
    assert r.status_code == 400
    detail = r.json()["detail"]
    assert "rejected" in detail["message"].lower()
    assert any("545" in v for v in detail["violations"])
    # And critically: no AWS mutation occurred — the floor stopped
    # the call BEFORE put_retention_policy ran.
    assert fake.put_calls == []


def test_patch_log_retention_refuses_invalid_window(
    as_admin: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeLogsClient(
        log_groups=[{"logGroupName": "/aws/lambda/iam-jit", "retentionInDays": 545}],
    )
    _inject_fake_logs(monkeypatch, fake)
    monkeypatch.setenv("IAM_JIT_MIN_LOG_RETENTION_DAYS", "1")

    r = as_admin.patch(
        "/api/v1/admin/log-retention",
        json={"retention_days": 200},  # not in VALID_RETENTION_DAYS
    )
    assert r.status_code == 400
    assert fake.put_calls == []


def test_patch_log_retention_refuses_non_integer(
    as_admin: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeLogsClient(log_groups=[])
    _inject_fake_logs(monkeypatch, fake)

    r = as_admin.patch(
        "/api/v1/admin/log-retention",
        json={"retention_days": "545"},  # string, not int
    )
    assert r.status_code == 400


def test_patch_log_retention_requires_admin(
    as_dev: TestClient,
    as_approver: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake = FakeLogsClient(log_groups=[])
    _inject_fake_logs(monkeypatch, fake)
    assert (
        as_dev.patch(
            "/api/v1/admin/log-retention",
            json={"retention_days": 731},
        ).status_code
        == 403
    )
    assert (
        as_approver.patch(
            "/api/v1/admin/log-retention",
            json={"retention_days": 731},
        ).status_code
        == 403
    )


def test_patch_log_retention_emits_audit_event(
    as_admin: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The audit trail is the WHOLE POINT of this endpoint — without
    it, a malicious admin could shorten retention silently. Verify
    the audit emit happens with previous + new days both recorded."""
    fake = FakeLogsClient(
        log_groups=[{"logGroupName": "/aws/lambda/iam-jit", "retentionInDays": 545}],
    )
    _inject_fake_logs(monkeypatch, fake)
    monkeypatch.setenv("IAM_JIT_MIN_LOG_RETENTION_DAYS", "545")
    monkeypatch.setenv("IAM_JIT_LOG_GROUP_NAME", "/aws/lambda/iam-jit")

    emitted: list[dict[str, Any]] = []

    def _capture(**kwargs: Any) -> None:
        emitted.append(kwargs)

    from iam_jit import audit as audit_mod

    monkeypatch.setattr(audit_mod, "emit", _capture)

    r = as_admin.patch(
        "/api/v1/admin/log-retention",
        json={"retention_days": 1827},
    )
    assert r.status_code == 200, r.text
    assert len(emitted) == 1
    ev = emitted[0]
    assert ev["kind"] == "admin.log_retention_updated"
    assert ev["details"]["previous_days"] == 545
    assert ev["details"]["new_days"] == 1827
    assert ev["details"]["floor_min_days"] == 545
