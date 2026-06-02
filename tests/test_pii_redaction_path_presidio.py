# ADOPT-7 / #721 — presidio-backed end-to-end through the EXISTING
# retention redaction path. Requires the optional extra; skipped in CI.
from __future__ import annotations

import dataclasses
import os
import tempfile

import pytest

from iam_jit.bouncer.audit_export.retention import (
    default_policy,
    redact_event_pii,
)

pytest.importorskip("presidio_analyzer")


def _gdpr_policy():
    return dataclasses.replace(default_policy(), gdpr_pii_purge=True)


def test_custom_config_redacts_through_retention_path() -> None:
    from iam_jit.pii.bouncer_hook import build_extra_redactor

    cfg_text = (
        "schema_version: 1\n"
        "entities:\n"
        "  - name: EMP_BADGE\n"
        "    patterns: [\"EMP-\\\\d{5}\"]\n"
        "    score: 0.9\n"
    )
    fd, path = tempfile.mkstemp(suffix=".yaml")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(cfg_text)
        redactor = build_extra_redactor(path)
        assert redactor is not None
        event = {"detail": {"body": "badge EMP-54321 here"}}
        redact_event_pii(event, _gdpr_policy(), extra_redactor=redactor)
        assert "EMP-54321" not in event["detail"]["body"]
        assert "[REDACTED:EMP_BADGE]" in event["detail"]["body"]
    finally:
        os.unlink(path)
