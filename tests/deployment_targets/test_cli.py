"""#437 / §A71 — tests for `iam-jit deployment-targets {list,show}` CLI."""

from __future__ import annotations

import json
import textwrap

import pytest
from click.testing import CliRunner

from iam_jit.cli import main as iam_jit_main


@pytest.fixture
def declaration_yaml(tmp_path):
    """Write a small .iam-jit.yaml with a couple of declared targets
    and return the path the CLI should consume."""
    body = textwrap.dedent(
        """
        iam-jit:
          enabled: true
          deployment_targets:
            prod-k8s:
              bouncer: kbouncer
              description: production K8s
              classifier:
                clusters: ["prod-east", "prod-west"]
                accounts: ["999988887777"]
            staging-k8s:
              bouncer: kbouncer
              classifier:
                clusters: ["staging-*"]
                accounts: ["111122223333"]
            prod-aws:
              bouncer: ibounce
              classifier:
                accounts: ["999988887777"]
                regions: ["us-east-1", "us-west-2"]
        """
    ).strip() + "\n"
    p = tmp_path / ".iam-jit.yaml"
    p.write_text(body)
    return p


def test_deployment_targets_list_cli_shows_declared(declaration_yaml):
    """The CLI surfaces every declared target name + bouncer + the
    classifier dimensions."""
    runner = CliRunner()
    result = runner.invoke(
        iam_jit_main,
        [
            "deployment-targets", "list",
            "--config", str(declaration_yaml),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    out = result.output
    assert "prod-k8s" in out
    assert "staging-k8s" in out
    assert "prod-aws" in out
    assert "kbouncer" in out
    assert "ibounce" in out
    assert "clusters" in out
    assert "accounts" in out
    assert "regions" in out


def test_deployment_targets_list_json_format(declaration_yaml):
    runner = CliRunner()
    result = runner.invoke(
        iam_jit_main,
        [
            "deployment-targets", "list",
            "--config", str(declaration_yaml),
            "--format", "json",
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    names = {t["name"] for t in payload["targets"]}
    assert names == {"prod-k8s", "staging-k8s", "prod-aws"}
    prod = next(t for t in payload["targets"] if t["name"] == "prod-k8s")
    assert prod["bouncer"] == "kbouncer"
    assert prod["classifier"]["clusters"] == ["prod-east", "prod-west"]


def test_deployment_targets_show_classifier_only_pipes_to_audit_query(
    declaration_yaml,
):
    """The `--classifier-only` flag exists so an agent can pipe the
    classifier dict straight into `iam-jit audit query
    --scope-filter`."""
    runner = CliRunner()
    result = runner.invoke(
        iam_jit_main,
        [
            "deployment-targets", "show", "prod-k8s",
            "--config", str(declaration_yaml),
            "--classifier-only",
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    payload = json.loads(result.output)
    # Pure classifier dict (no envelope), ready to pipe into
    # `--scope-filter` of audit-query.
    assert payload["clusters"] == ["prod-east", "prod-west"]
    assert payload["accounts"] == ["999988887777"]
    # No bouncer / name field at the top level of --classifier-only.
    assert "bouncer" not in payload
    assert "name" not in payload


def test_deployment_targets_show_missing_exits_nonzero(declaration_yaml):
    runner = CliRunner()
    result = runner.invoke(
        iam_jit_main,
        [
            "deployment-targets", "show", "nope-not-a-target",
            "--config", str(declaration_yaml),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code != 0


def test_deployment_targets_list_empty_when_no_targets(tmp_path):
    body = "iam-jit:\n  enabled: true\n"
    p = tmp_path / ".iam-jit.yaml"
    p.write_text(body)
    runner = CliRunner()
    result = runner.invoke(
        iam_jit_main,
        ["deployment-targets", "list", "--config", str(p)],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    assert "(no deployment_targets declared" in result.output
