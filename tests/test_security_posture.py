"""Security-posture module + admin endpoints.

Covers the loud-warning bundle the operator + agent see:
  - `/healthz` includes a `security_posture` block
  - `/api/v1/admin/security-posture` returns the posture with
    per-admin dismissals applied
  - `POST /api/v1/admin/dismiss-warning` persists the dismissal
    to `user.notes` and refuses unknown warning_ids
  - The critical "open ALB + HTTP-only" combo trips the right
    severity bucket
"""

from __future__ import annotations

import dataclasses

import pytest
from fastapi.testclient import TestClient

from iam_jit import cidr_store, security_posture


pytest_plugins = ["tests.conftest_routes"]


# ---- pure module ----


def test_posture_ok_when_no_alb(monkeypatch: pytest.MonkeyPatch) -> None:
    """The non-ALB path (Function URL only) returns severity=ok
    because the SCP / network gate is presumed handled externally."""
    monkeypatch.delenv("IAM_JIT_TRUST_FORWARDED_HOST", raising=False)
    monkeypatch.delenv("IAM_JIT_ALB_HAS_CERT", raising=False)
    monkeypatch.delenv("IAM_JIT_ALLOWED_SOURCE_CIDRS", raising=False)
    monkeypatch.delenv("IAM_JIT_SES_SENDER", raising=False)
    cidr_store.reset_default_store_for_tests()

    p = security_posture.compute()
    assert p["severity"] == "ok"
    assert p["alb_in_front"] is False


def test_posture_critical_when_alb_http_only_and_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The combination the user explicitly asked us to flag loudly:
    ALB is in front, no HTTPS cert, no source-IP restriction.
    BootstrapSetupKey form POSTs travel cleartext to any internet
    host. Must surface as `critical`."""
    monkeypatch.setenv("IAM_JIT_TRUST_FORWARDED_HOST", "1")
    monkeypatch.delenv("IAM_JIT_ALB_HAS_CERT", raising=False)
    monkeypatch.delenv("IAM_JIT_ALLOWED_SOURCE_CIDRS", raising=False)
    cidr_store.reset_default_store_for_tests()

    p = security_posture.compute()
    assert p["severity"] == "critical"
    ids = [i["id"] for i in p["issues"]]
    assert "open_alb_http" in ids, (
        f"expected critical 'open_alb_http' issue, got {ids}"
    )
    # The combo issue should NOT also show the constituent warnings
    # (alb_http_only or open_alb) — they'd be redundant noise.
    assert "alb_http_only" not in ids
    assert "open_alb" not in ids


def test_posture_warn_when_alb_https_but_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HTTPS but still open at the SG layer — warn, not critical.
    The cleartext-key risk is gone; only the wide-open network
    surface remains."""
    monkeypatch.setenv("IAM_JIT_TRUST_FORWARDED_HOST", "1")
    monkeypatch.setenv("IAM_JIT_ALB_HAS_CERT", "1")
    monkeypatch.delenv("IAM_JIT_ALLOWED_SOURCE_CIDRS", raising=False)
    cidr_store.reset_default_store_for_tests()

    p = security_posture.compute()
    assert p["severity"] == "warn"
    ids = [i["id"] for i in p["issues"]]
    assert "open_alb" in ids


def test_posture_warn_when_alb_http_only_but_acl_set(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """HTTP-only but app-layer ACL is configured — warn (cleartext
    risk but bounded surface)."""
    monkeypatch.setenv("IAM_JIT_TRUST_FORWARDED_HOST", "1")
    monkeypatch.delenv("IAM_JIT_ALB_HAS_CERT", raising=False)
    monkeypatch.setenv("IAM_JIT_ALLOWED_SOURCE_CIDRS", "10.0.0.0/8")
    cidr_store.reset_default_store_for_tests()

    p = security_posture.compute()
    assert p["severity"] == "warn"
    ids = [i["id"] for i in p["issues"]]
    assert "alb_http_only" in ids
    assert "open_alb_http" not in ids


def test_warning_dismissed_by_marker() -> None:
    notes = "some text\ndismissed_warning:open_alb_http=2026-05-11T00:00:00Z"
    assert security_posture.warning_dismissed_by(notes, "open_alb_http") is True
    assert security_posture.warning_dismissed_by(notes, "open_alb") is False
    assert security_posture.warning_dismissed_by(None, "open_alb_http") is False
    assert security_posture.warning_dismissed_by("", "open_alb_http") is False


def test_append_dismissal_replaces_existing_for_same_id() -> None:
    notes = "dismissed_warning:open_alb_http=2026-05-01T00:00:00Z"
    updated = security_posture.append_dismissal(
        notes, "open_alb_http", "2026-05-11T00:00:00Z"
    )
    # Only one marker for that id; the timestamp is the new one.
    assert updated.count("open_alb_http") == 1
    assert "2026-05-11T00:00:00Z" in updated
    assert "2026-05-01T00:00:00Z" not in updated


# ---- /healthz integration ----


def test_healthz_exposes_security_posture(client: TestClient) -> None:
    """Anonymous /healthz includes the posture so agents can detect
    a degraded deploy without auth."""
    body = client.get("/healthz").json()
    assert "security_posture" in body
    assert body["security_posture"]["severity"] in {"ok", "warn", "critical"}
    assert "issues" in body["security_posture"]


# ---- admin endpoint ----


def test_admin_security_posture_returns_shape(
    as_admin: TestClient,
) -> None:
    """admin GET /security-posture returns the posture envelope plus
    the per-admin-filtered `issues_undismissed` list. The shared test
    fixture uses a read-only FileUserStore so we don't exercise the
    DISMISS write here — that's covered by the pure-module tests
    above (`append_dismissal`, `warning_dismissed_by`)."""
    r = as_admin.get("/api/v1/admin/security-posture")
    assert r.status_code == 200, r.text
    body = r.json()
    assert "severity" in body
    assert "issues" in body
    assert "issues_undismissed" in body


def test_admin_dismiss_warning_refuses_unknown_id(as_admin: TestClient) -> None:
    """Refuse storing arbitrary marker strings via the dismiss
    endpoint — only ids that currently appear in the posture are
    valid. (Test passes regardless of store type because the
    validation happens before any store write.)"""
    r = as_admin.post(
        "/api/v1/admin/dismiss-warning",
        json={"warning_id": "definitely_not_a_real_warning"},
    )
    assert r.status_code == 400


def test_admin_dismiss_warning_admin_only(
    as_dev: TestClient,
    as_approver: TestClient,
) -> None:
    """Approvers and devs cannot dismiss warnings; only admins."""
    body = {"warning_id": "open_alb_http"}
    assert as_dev.post("/api/v1/admin/dismiss-warning", json=body).status_code == 403
    assert as_approver.post("/api/v1/admin/dismiss-warning", json=body).status_code == 403
