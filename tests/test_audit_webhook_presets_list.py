"""CLI tests for `ibounce audit-webhook presets list` (#259).

Confirms the operator-facing surface enumerates the four presets +
each one's required + optional flags + exits 0 on the happy path.
"""

from __future__ import annotations

import json

from click.testing import CliRunner

from iam_jit.bouncer_cli import (
    audit_webhook_preset_descriptors,
    main,
)


def test_presets_list_human_readable_lists_all_four() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["audit-webhook", "presets", "list"])
    assert result.exit_code == 0, result.output
    for preset in ("generic", "datadog", "splunk-hec", "sentinel"):
        assert preset in result.output, (
            f"preset {preset!r} not present in CLI output:\n{result.output}"
        )
    assert "WEBHOOK-PRESETS.md" in result.output


def test_presets_list_json_payload_shape() -> None:
    runner = CliRunner()
    result = runner.invoke(
        main, ["audit-webhook", "presets", "list", "--json"],
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    assert isinstance(payload, list)
    names = [d["name"] for d in payload]
    assert names == ["generic", "datadog", "splunk-hec", "sentinel"]
    for desc in payload:
        assert "description" in desc
        assert "auth_header" in desc
        assert "body_shape" in desc
        assert "required_flags" in desc
        assert "optional_flags" in desc
        assert "--audit-webhook-url" in desc["required_flags"]
        assert "--audit-webhook-token" in desc["required_flags"]


def test_descriptor_helper_is_pure() -> None:
    """The descriptor helper must be a pure function so the MCP
    tool can reuse it without side effects. Calling it twice returns
    equal payloads."""
    first = audit_webhook_preset_descriptors()
    second = audit_webhook_preset_descriptors()
    assert first == second
    # Mutating the returned list MUST NOT poison the second call
    # (defensive: shared mutable state across CLI + MCP would be a
    # subtle source of cross-request bleed).
    first.append({"name": "poison"})
    third = audit_webhook_preset_descriptors()
    assert [d["name"] for d in third] == [
        "generic", "datadog", "splunk-hec", "sentinel",
    ]


def test_no_user_facing_violation_language() -> None:
    """Per [[security-team-positioning-safety-not-surveillance]]: no
    'violation' / 'infraction' / 'unauthorized' in the operator
    surface."""
    runner = CliRunner()
    result = runner.invoke(main, ["audit-webhook", "presets", "list"])
    forbidden = ("violation", "infraction", "unauthorized")
    out_low = result.output.lower()
    for word in forbidden:
        assert word not in out_low, f"forbidden word {word!r} in output"
