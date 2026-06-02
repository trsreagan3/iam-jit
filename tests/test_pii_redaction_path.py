# ADOPT-7 / #721 — custom PII detectors reuse the EXISTING bouncer
# redaction path (audit_export.retention) via the extra_redactor hook.
"""These assert the integration seam: the custom-entity layer plugs into
``redact_event_pii``'s in-place walk rather than re-traversing events in
a parallel system. The credential/PII defaults still run; the custom
redactor is applied additively per string value.

The hook itself is dependency-free (it's just a string->string callable
threaded into the existing walk), so these run WITHOUT presidio by
substituting a trivial redactor. A presidio-backed end-to-end check is
in the importorskip group below.
"""

from __future__ import annotations

from iam_jit.bouncer.audit_export.retention import (
    default_policy,
    redact_event_pii,
)


def _gdpr_policy():
    # default_policy() is PCI (gdpr_pii_purge False); flip the flag so
    # redact_event_pii actually runs.
    import dataclasses

    return dataclasses.replace(default_policy(), gdpr_pii_purge=True)


def test_extra_redactor_runs_over_existing_walk() -> None:
    # A trivial custom redactor uppercases a codename token. Proves the
    # callable reaches every string value via the SAME recursive walk.
    def upper_secret(s: str) -> str:
        return s.replace("bluefin", "[REDACTED:PROJECT_CODE]")

    event = {
        "actor": "alice",
        "nested": {"note": "shipping bluefin today"},
        "list": ["bluefin", "other"],
    }
    out = redact_event_pii(event, _gdpr_policy(), extra_redactor=upper_secret)
    assert out["nested"]["note"] == "shipping [REDACTED:PROJECT_CODE] today"
    assert out["list"][0] == "[REDACTED:PROJECT_CODE]"
    assert out["list"][1] == "other"


def test_builtin_patterns_still_run_alongside_extra() -> None:
    # The built-in credential/PII patterns (email) must STILL fire even
    # when a custom extra_redactor is supplied — additive, not replacing.
    def noop(s: str) -> str:
        return s

    event = {"msg": "contact alice@example.com about EMP-1"}
    redact_event_pii(event, _gdpr_policy(), extra_redactor=noop)
    assert "alice@example.com" not in event["msg"]
    assert "[REDACTED:email]" in event["msg"]


def test_no_extra_redactor_is_backward_compatible() -> None:
    # Omitting extra_redactor preserves prior behaviour exactly.
    event = {"msg": "contact bob@example.com"}
    redact_event_pii(event, _gdpr_policy())
    assert "[REDACTED:email]" in event["msg"]


def test_gdpr_purge_off_noops_even_with_extra() -> None:
    def boom(s: str) -> str:  # would corrupt if called
        return s + "X"

    event = {"msg": "keep me"}
    redact_event_pii(event, default_policy(), extra_redactor=boom)
    assert event["msg"] == "keep me"
