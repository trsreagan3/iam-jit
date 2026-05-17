"""Tests for `iam-jit doctor compatibility` (#166 Slice 4).

Exercises the CLI surface that exposes the applicability framework
to humans / scripts BEFORE submitting a request. Composes with the
WB24 framework (Slices 1+2) and the HTTP gate (Slice 3, see
test_routes_requests.py).
"""

from __future__ import annotations

import json

from click.testing import CliRunner

from iam_jit.cli import main


def test_doctor_compatibility_proceed_exits_zero() -> None:
    """ci_runner / human_cli workloads are PROCEED — iam-jit can
    issue a role; exit 0 so the command composes with `&&` in scripts."""
    runner = CliRunner()
    result = runner.invoke(main, [
        "doctor", "compatibility", "--workload", "ci_runner",
    ])
    assert result.exit_code == 0, result.output
    assert "proceed" in result.output.lower()


def test_doctor_compatibility_use_existing_exits_nonzero() -> None:
    """k8s_pod = USE_EXISTING (IRSA pinned at pod creation) → exit 1
    + next-action hint so the user knows what to do."""
    runner = CliRunner()
    result = runner.invoke(main, [
        "doctor", "compatibility", "--workload", "k8s_pod",
    ])
    assert result.exit_code == 1
    assert "use_existing" in result.output.lower()
    assert "next:" in result.output.lower() or "next " in result.output.lower()


def test_doctor_compatibility_unknown_workload_exits_two() -> None:
    """Unknown workload = exit 2 (input validation), distinct from
    exit 1 (semantic refusal)."""
    runner = CliRunner()
    result = runner.invoke(main, [
        "doctor", "compatibility", "--workload", "definitely_not_a_workload",
    ])
    assert result.exit_code == 2
    assert "unknown workload" in result.output.lower()


def test_doctor_compatibility_invalid_account_id_rejected() -> None:
    """Account ID must be exactly 12 digits."""
    runner = CliRunner()
    result = runner.invoke(main, [
        "doctor", "compatibility",
        "--workload", "ci_runner",
        "--target-account-id", "not-numeric",
    ])
    assert result.exit_code == 2
    assert "12 digits" in result.output


def test_doctor_compatibility_invalid_service_prefix_rejected() -> None:
    """Service prefix must match the lowercase ARN service convention."""
    runner = CliRunner()
    result = runner.invoke(main, [
        "doctor", "compatibility",
        "--workload", "ci_runner",
        "--target-service", "Not Lowercase!",
    ])
    assert result.exit_code == 2


def test_doctor_compatibility_json_output_is_valid_json() -> None:
    """--json mode emits parseable JSON with the verdict + hint."""
    runner = CliRunner()
    result = runner.invoke(main, [
        "doctor", "compatibility",
        "--workload", "lambda_function",
        "--json",
    ])
    # Whether the workload PROCEEDs or yields USE_EXISTING, the JSON
    # body must parse and have the verdict field.
    payload = json.loads(result.output)
    assert "verdict" in payload
    assert payload["verdict"] in (
        "proceed", "use_existing", "use_bouncer", "cannot_help",
    )


def test_doctor_compatibility_passes_services_through() -> None:
    """Multiple --target-service args accumulate into the intent.
    Smoke test that the command doesn't reject repeated flags."""
    runner = CliRunner()
    result = runner.invoke(main, [
        "doctor", "compatibility",
        "--workload", "ci_runner",
        "--target-service", "s3",
        "--target-service", "dynamodb",
        "--json",
    ])
    payload = json.loads(result.output)
    assert "verdict" in payload
