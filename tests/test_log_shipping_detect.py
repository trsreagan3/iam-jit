"""#429 / §A68 — log_shipping detection module tests.

Per ``[[creates-never-mutates]]`` every command in this slice prints
flags; no auto-application of any kind. These tests check that:

  * Each marker (AWS / Datadog / Splunk / K8s) maps to the right
    destination via :func:`detect_destinations`.
  * Opt-in is preserved: the detector NEVER returns an apply-side
    action. The only callable that mutates the operator's
    environment is the bouncer-launch flags they paste themselves.
  * The recommendation flags compose with the existing #257 webhook
    presets + #258 Security Lake + #317 S3 sink surfaces — every
    flag the recommender returns already exists in bouncer_cli.py.
"""

from __future__ import annotations

import json as _json
import pathlib

import pytest
from click.testing import CliRunner

from iam_jit.cli import main as _main_cli
from iam_jit.log_shipping import (
    Destination,
    DetectedDestination,
    DetectionEnv,
    detect_destinations,
    recommend_flags,
)
from iam_jit.log_shipping.detect import capture_env


def _bare_env() -> DetectionEnv:
    """Environment with no SIEM markers at all."""
    return DetectionEnv(
        env={},
        aws_credentials_path_exists=False,
        aws_config_path_exists=False,
        k8s_serviceaccount_token_exists=False,
    )


# ---------------------------------------------------------------------------
# AWS detection — both cloudwatch-logs + security-lake destinations
# ---------------------------------------------------------------------------


def test_logs_ship_to_detects_aws_credentials_and_offers_cloudwatch(tmp_path):
    """An operator with ~/.aws/credentials gets cloudwatch-logs +
    security-lake destinations + the right markers."""
    env = DetectionEnv(
        env={},
        aws_credentials_path_exists=True,
        aws_config_path_exists=False,
        k8s_serviceaccount_token_exists=False,
    )
    detected = detect_destinations(env)
    by_dest = {d.destination: d for d in detected}
    assert Destination.CLOUDWATCH_LOGS in by_dest
    assert Destination.SECURITY_LAKE in by_dest
    cw = by_dest[Destination.CLOUDWATCH_LOGS]
    assert "~/.aws/credentials" in cw.markers


def test_aws_access_key_id_env_triggers_aws_detection():
    env = DetectionEnv(
        env={"AWS_ACCESS_KEY_ID": "AKIATEST"},
        aws_credentials_path_exists=False,
        aws_config_path_exists=False,
        k8s_serviceaccount_token_exists=False,
    )
    detected = detect_destinations(env)
    dests = {d.destination for d in detected}
    assert Destination.CLOUDWATCH_LOGS in dests
    assert Destination.SECURITY_LAKE in dests


def test_aws_profile_env_triggers_aws_detection_with_profile_marker():
    env = DetectionEnv(
        env={"AWS_PROFILE": "production"},
        aws_credentials_path_exists=False,
        aws_config_path_exists=False,
        k8s_serviceaccount_token_exists=False,
    )
    detected = detect_destinations(env)
    cw = [d for d in detected if d.destination == Destination.CLOUDWATCH_LOGS][0]
    assert any("production" in m for m in cw.markers), cw.markers


# ---------------------------------------------------------------------------
# Datadog
# ---------------------------------------------------------------------------


def test_logs_ship_to_detects_datadog_env_offers_preset():
    env = DetectionEnv(
        env={"DD_API_KEY": "deadbeef"},
        aws_credentials_path_exists=False,
        aws_config_path_exists=False,
        k8s_serviceaccount_token_exists=False,
    )
    detected = detect_destinations(env)
    dests = {d.destination for d in detected}
    assert Destination.DATADOG in dests
    assert Destination.CLOUDWATCH_LOGS not in dests
    dd = [d for d in detected if d.destination == Destination.DATADOG][0]
    assert "DD_API_KEY" in dd.markers


def test_datadog_api_key_env_is_recognised_as_alias():
    """DATADOG_API_KEY is the legacy spelling; we accept both."""
    env = DetectionEnv(
        env={"DATADOG_API_KEY": "deadbeef"},
        aws_credentials_path_exists=False,
        aws_config_path_exists=False,
        k8s_serviceaccount_token_exists=False,
    )
    detected = detect_destinations(env)
    assert any(d.destination == Destination.DATADOG for d in detected)


# ---------------------------------------------------------------------------
# Splunk
# ---------------------------------------------------------------------------


def test_logs_ship_to_detects_splunk_env_offers_hec():
    env = DetectionEnv(
        env={
            "SPLUNK_HEC_URL": "https://splunk.example.com:8088",
            "SPLUNK_HEC_TOKEN": "00000000-0000-0000-0000-000000000000",
        },
        aws_credentials_path_exists=False,
        aws_config_path_exists=False,
        k8s_serviceaccount_token_exists=False,
    )
    detected = detect_destinations(env)
    dests = {d.destination for d in detected}
    assert Destination.SPLUNK_HEC in dests
    splunk = [d for d in detected if d.destination == Destination.SPLUNK_HEC][0]
    assert "SPLUNK_HEC_URL" in splunk.markers
    assert "SPLUNK_HEC_TOKEN" in splunk.markers


def test_splunk_url_alone_triggers_detection():
    """Just SPLUNK_HEC_URL (no token yet) should still surface the
    destination so the operator knows what they need to add."""
    env = DetectionEnv(
        env={"SPLUNK_URL": "https://splunk.example.com:8088"},
        aws_credentials_path_exists=False,
        aws_config_path_exists=False,
        k8s_serviceaccount_token_exists=False,
    )
    detected = detect_destinations(env)
    assert any(d.destination == Destination.SPLUNK_HEC for d in detected)


# ---------------------------------------------------------------------------
# Kubernetes
# ---------------------------------------------------------------------------


def test_logs_ship_to_detects_k8s_pod_offers_loki_elk():
    env = DetectionEnv(
        env={
            "KUBERNETES_SERVICE_HOST": "10.96.0.1",
            "KUBERNETES_PORT": "443",
        },
        aws_credentials_path_exists=False,
        aws_config_path_exists=False,
        k8s_serviceaccount_token_exists=False,
    )
    detected = detect_destinations(env)
    dests = {d.destination for d in detected}
    assert Destination.LOKI_ELK in dests
    loki = [d for d in detected if d.destination == Destination.LOKI_ELK][0]
    assert any("KUBERNETES" in m for m in loki.markers)


def test_k8s_serviceaccount_token_alone_triggers_detection():
    env = DetectionEnv(
        env={},
        aws_credentials_path_exists=False,
        aws_config_path_exists=False,
        k8s_serviceaccount_token_exists=True,
    )
    detected = detect_destinations(env)
    assert any(d.destination == Destination.LOKI_ELK for d in detected)


# ---------------------------------------------------------------------------
# Opt-in discipline — detection NEVER triggers side-effects
# ---------------------------------------------------------------------------


def test_logs_ship_to_opt_in_required(tmp_path, monkeypatch):
    """`iam-jit logs ship-to` MUST NOT mutate bouncer config, restart
    a bouncer, or POST anywhere. Detection runs entirely against the
    operator-supplied env snapshot + returns a list of recommendations.

    This test runs the CLI in an isolated environment + asserts that
    no side-effects land on the filesystem outside the expected stdout
    text + the tmp_path home directory."""
    # Pin HOME so capture_env doesn't pick up the test runner's real
    # AWS credentials file.
    monkeypatch.setenv("HOME", str(tmp_path))
    # Clear every marker so detection returns empty (we're verifying
    # the opt-in discipline, not the detection result).
    for key in (
        "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
        "AWS_PROFILE", "DD_API_KEY", "DATADOG_API_KEY", "DD_SITE",
        "SPLUNK_HEC_URL", "SPLUNK_HEC_TOKEN", "SPLUNK_URL",
        "KUBERNETES_SERVICE_HOST", "KUBERNETES_PORT",
    ):
        monkeypatch.delenv(key, raising=False)
    runner = CliRunner()
    result = runner.invoke(_main_cli, ["logs", "ship-to", "--detect"])
    # Empty env → exit 1 ("no-destinations-detected") + no side-effects.
    assert result.exit_code == 1, result.output
    # The CLI MUST NOT have written anything to ~/.iam-jit/ or
    # created an .iam-jit.yaml or restarted any bouncer.
    assert not (tmp_path / ".iam-jit").exists()
    assert not (tmp_path / ".iam-jit.yaml").exists()
    # And the destination catalog is surfaced as guidance, not as an
    # error — per [[ambient-value-prop-and-friction-framing]].
    assert "Available destinations" in result.output


def test_destination_name_without_detect_prints_flags_only(tmp_path, monkeypatch):
    """Pass a destination name without --detect → prints recommended
    flags for THAT destination, regardless of detection state. The
    operator can pre-stage the flag set before configuring env vars."""
    monkeypatch.setenv("HOME", str(tmp_path))
    for key in (
        "AWS_ACCESS_KEY_ID", "AWS_PROFILE", "DD_API_KEY",
        "SPLUNK_HEC_URL", "SPLUNK_HEC_TOKEN",
        "KUBERNETES_SERVICE_HOST",
    ):
        monkeypatch.delenv(key, raising=False)
    runner = CliRunner()
    result = runner.invoke(_main_cli, ["logs", "ship-to", "datadog"])
    assert result.exit_code == 0, result.output
    assert "--audit-webhook-preset=datadog" in result.output
    assert "not detected" in result.output
    # Explicit no-mutate framing surfaces (per [[creates-never-mutates]]).
    low = result.output.lower()
    assert "does not modify" in low or "does not mutate" in low or "no auto-apply" in low
    # No "applying" / "writing config" / "restarting" present-tense leaks.
    assert "applying" not in low
    assert "writing config" not in low
    assert "restarting" not in low


# ---------------------------------------------------------------------------
# Composition with existing #257 webhook presets + #258 Security Lake +
# #317 S3 sink. Every flag the recommender returns MUST be a flag
# bouncer_cli.py already accepts.
# ---------------------------------------------------------------------------


def test_logs_ship_to_composes_with_existing_257_258_317_presets():
    """Every recommended flag for every destination MUST be a known
    bouncer flag (#257 webhook OR #317 object-storage). No invented
    flags; this is the proof of [[v1-scope-bar]] — composition only."""
    bouncer_cli = pathlib.Path(
        "src/iam_jit/bouncer_cli.py",
    ).read_text()
    # Hard-coded webhook flag names from #257 + #317. The recommender
    # MUST stick to these — anything new would be a regression.
    known_flags = {
        "--audit-webhook-url",
        "--audit-webhook-token",
        "--audit-webhook-preset",
        "--audit-object-storage-bucket",
        "--audit-object-storage-endpoint",
        "--audit-object-storage-region",
        "--audit-object-storage-prefix",
    }
    for flag in known_flags:
        assert flag in bouncer_cli, (
            f"sanity: known flag {flag} should appear in bouncer_cli.py"
        )
    for dest in Destination:
        flags = recommend_flags(dest)
        for raw in flags:
            # Each flag is "FLAG=VALUE" — pull the flag name.
            flag_name = raw.split("=", 1)[0]
            assert flag_name in known_flags, (
                f"{dest.value}: invented flag {flag_name!r} — recommender "
                f"must compose with shipped surfaces only per "
                f"[[v1-scope-bar]]"
            )


def test_datadog_recommendation_uses_257_datadog_preset():
    """Verify the Datadog recommendation maps to the #257
    ``Preset.DATADOG`` value."""
    flags = recommend_flags(Destination.DATADOG)
    joined = " ".join(flags)
    assert "--audit-webhook-preset=datadog" in joined


def test_splunk_recommendation_uses_257_splunk_hec_preset():
    flags = recommend_flags(Destination.SPLUNK_HEC)
    joined = " ".join(flags)
    assert "--audit-webhook-preset=splunk-hec" in joined


def test_security_lake_recommendation_uses_317_object_storage_flags():
    flags = recommend_flags(Destination.SECURITY_LAKE)
    joined = " ".join(flags)
    assert "--audit-object-storage-bucket" in joined
    assert "--audit-object-storage-endpoint" in joined
    assert "amazonaws.com" in joined  # Security Lake uses S3 native


# ---------------------------------------------------------------------------
# CLI surface — --detect JSON output is structured + agent-consumable
# ---------------------------------------------------------------------------


def test_cli_detect_json_output_is_parseable(tmp_path, monkeypatch):
    """--detect --json emits parseable JSON the agent surfaces can
    consume directly (same shape as the future MCP tool will return)."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("DD_API_KEY", "test-key")
    for key in (
        "AWS_ACCESS_KEY_ID", "AWS_PROFILE", "SPLUNK_HEC_URL",
        "SPLUNK_HEC_TOKEN", "KUBERNETES_SERVICE_HOST",
    ):
        monkeypatch.delenv(key, raising=False)
    runner = CliRunner()
    result = runner.invoke(
        _main_cli, ["logs", "ship-to", "--detect", "--json"],
    )
    assert result.exit_code == 0, result.output
    payload = _json.loads(result.output)
    assert payload["status"] == "ok"
    assert len(payload["destinations"]) >= 1
    dests = {d["destination"] for d in payload["destinations"]}
    assert "datadog" in dests


def test_cli_destination_json_output_includes_detected_flag(
    tmp_path, monkeypatch,
):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("DD_API_KEY", "test-key")
    for key in (
        "AWS_ACCESS_KEY_ID", "AWS_PROFILE", "SPLUNK_HEC_URL",
        "SPLUNK_HEC_TOKEN", "KUBERNETES_SERVICE_HOST",
    ):
        monkeypatch.delenv(key, raising=False)
    runner = CliRunner()
    result = runner.invoke(
        _main_cli, ["logs", "ship-to", "datadog", "--json"],
    )
    assert result.exit_code == 0, result.output
    payload = _json.loads(result.output)
    assert payload["status"] == "ok"
    assert payload["destination"] == "datadog"
    assert payload["detected"] is True
    assert any("--audit-webhook-preset=datadog" in f for f in payload["flags"])


def test_cli_missing_args_exits_2(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    runner = CliRunner()
    result = runner.invoke(_main_cli, ["logs", "ship-to"])
    # Operator passed neither --detect nor a destination → invalid.
    assert result.exit_code == 2


def test_capture_env_pure_function(tmp_path, monkeypatch):
    """capture_env is a pure read of env vars + filesystem markers
    pointed at the supplied home_dir; never mutates anything."""
    monkeypatch.delenv("DD_API_KEY", raising=False)
    snap = capture_env(env={"DD_API_KEY": "x"}, home_dir=tmp_path)
    assert snap.env["DD_API_KEY"] == "x"
    assert snap.aws_credentials_path_exists is False
    # Confirm tmp_path didn't get an .aws/ directory written.
    assert not (tmp_path / ".aws").exists()


# ---------------------------------------------------------------------------
# Bare-environment detection
# ---------------------------------------------------------------------------


def test_bare_environment_returns_no_destinations():
    detected = detect_destinations(_bare_env())
    assert detected == []
