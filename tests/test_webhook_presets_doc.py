"""Sentinel grep test for #259 — docs/WEBHOOK-PRESETS.md.

Verifies the cross-product webhook-presets doc mentions every preset
name (generic / datadog / splunk-hec / sentinel) and carries a sample
request-shape snippet for each. Per [[deliberate-feature-completion]]:
docs ship together with the code they describe; this guard fails the
build if a preset gets added in code without docs catching up.
"""

from __future__ import annotations

import pathlib

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
DOC = REPO_ROOT / "docs" / "WEBHOOK-PRESETS.md"


@pytest.mark.parametrize(
    "preset",
    ["generic", "datadog", "splunk-hec", "sentinel"],
)
def test_doc_mentions_each_preset(preset: str) -> None:
    body = DOC.read_text()
    assert preset in body, f"WEBHOOK-PRESETS.md missing preset: {preset}"


@pytest.mark.parametrize(
    "marker",
    [
        # Each preset's wire-shape section starts with the literal
        # preset name in backticks as the section header.
        "### `generic`",
        "### `datadog`",
        "### `splunk-hec`",
        "### `sentinel`",
    ],
)
def test_doc_has_per_preset_sample(marker: str) -> None:
    body = DOC.read_text()
    assert marker in body, f"WEBHOOK-PRESETS.md missing section: {marker}"


def test_doc_documents_cli_surface() -> None:
    """The doc must call out the operator-facing CLI command + the
    agent-facing MCP tool so both surfaces are discoverable from one
    page."""
    body = DOC.read_text()
    assert "audit-webhook presets list" in body
    assert "list_audit_webhook_presets" in body
