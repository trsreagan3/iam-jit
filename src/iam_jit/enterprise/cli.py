"""Click subcommand: `iam-jit enterprise bootstrap`.

Registered onto the top-level CLI group in src/iam_jit/cli.py via
`from .enterprise.cli import enterprise_group; main.add_command(...)`.
"""

from __future__ import annotations

import getpass
import logging
import os
import pathlib
import sys

import click

logger = logging.getLogger(__name__)

# One-shot advisory flag per [[oss-only-launch-decision]]. The license
# gate below is a no-op at v1.0 but we still want operators grepping
# log output to find the rationale once per process — not on every CLI
# invocation in a shell loop.
_OSS_LAUNCH_ADVISORY_EMITTED = False


def _default_config_path() -> pathlib.Path:
    env = os.environ.get("IAM_JIT_CONFIG_FILE")
    if env:
        return pathlib.Path(env)
    return pathlib.Path.home() / ".iam-jit" / "config.yaml"


def _default_audit_path() -> pathlib.Path:
    env = os.environ.get("IAM_JIT_BOOTSTRAP_AUDIT_FILE")
    if env:
        return pathlib.Path(env)
    return pathlib.Path.home() / ".iam-jit" / "bootstrap-audit.jsonl"


def _enforce_enterprise_tier() -> None:
    """Per [[enterprise-self-host-only]]: bootstrap was historically
    Enterprise-only and rejected non-Enterprise binaries with sys.exit(3).

    v1.0 update per [[oss-only-launch-decision]]: license enforcement
    is DISABLED at v1.0; `iam-jit enterprise bootstrap` ships FREE in
    the OSS-only launch. The license-load call below is retained (it
    still surfaces a clear error on a malformed-but-present license
    file, which is operator-actionable). License-check infrastructure
    + the `LicenseInvalidError` sentinel remain in the repo for the
    future v1.1+ paid tier (per the memo, "license code stays but
    does NOT enforce"). When that paid tier lands, restore the prior
    sys.exit(3) branches at the marked sites; today they emit a
    one-shot INFO advisory + proceed.

    Bypass-honest: anyone with the source can patch this gate; the
    contract is the legal artifact. Same posture as license.py's
    user-cap gate.
    """
    global _OSS_LAUNCH_ADVISORY_EMITTED

    from .. import license as _license

    try:
        _license.load_license()
    except _license.LicenseInvalidError as e:
        # A present-but-malformed license file is still operator-
        # actionable — surface the error so the operator knows their
        # license file is broken even though we'd otherwise let them
        # through. NOT a sys.exit; we log + continue per
        # [[oss-only-launch-decision]].
        logger.warning(
            "iam-jit enterprise bootstrap: license file present but "
            "failed verification: %s. v1.0 ships FREE per "
            "[[oss-only-launch-decision]] so bootstrap will proceed; "
            "fix the license file to silence this warning.",
            e,
        )

    if not _OSS_LAUNCH_ADVISORY_EMITTED:
        logger.info(
            "iam-jit enterprise bootstrap ships FREE at v1.0 per "
            "[[oss-only-launch-decision]]; license enforcement coming "
            "in v1.1+ when paid tier launches based on adoption signals."
        )
        _OSS_LAUNCH_ADVISORY_EMITTED = True


@click.group("enterprise")
def enterprise_group() -> None:
    """Enterprise-tier self-management subcommands (#102).

    iam-jit's `enterprise` group hosts self-host-only features
    gated behind an Enterprise license (per
    [[enterprise-self-host-only]]). Today it ships one command —
    `bootstrap` — that uses AWS-discovery + the customer's own LLM
    tier to propose an initial iam-jit config.
    """


@enterprise_group.command("bootstrap")
@click.option(
    "--prompt", "operator_prompt",
    default="",
    help="Free-text prompt describing your org's environment / preferences "
         "(e.g. 'two prod accounts pci-tagged; dev sandboxes can use "
         "deterministic_only'). Optional; the proposal is grounded in AWS "
         "discovery either way.",
)
@click.option(
    "--region", default=None,
    help="AWS region to probe for Bedrock + EKS + ECS. Default: boto3 "
         "session region or us-east-1.",
)
@click.option(
    "--config-path",
    type=click.Path(dir_okay=False, path_type=pathlib.Path),
    default=None,
    help="Where to write the accepted config. Default: ~/.iam-jit/config.yaml "
         "(or $IAM_JIT_CONFIG_FILE).",
)
@click.option(
    "--audit-path",
    type=click.Path(dir_okay=False, path_type=pathlib.Path),
    default=None,
    help="Append-only audit log for bootstrap decisions. Default: "
         "~/.iam-jit/bootstrap-audit.jsonl.",
)
@click.option(
    "--yes", "auto_accept", is_flag=True, default=False,
    help="Skip the interactive review and accept the proposal verbatim. "
         "Use only in CI/agent flows where another reviewer has pre-vetted.",
)
@click.option(
    "--dry-run", is_flag=True, default=False,
    help="Run discovery + proposal but do NOT write the config or audit row. "
         "Prints the YAML proposal to stdout.",
)
def bootstrap_cmd(
    operator_prompt: str,
    region: str | None,
    config_path: pathlib.Path | None,
    audit_path: pathlib.Path | None,
    auto_accept: bool,
    dry_run: bool,
) -> None:
    """Discover the customer's AWS environment + propose an initial
    iam-jit config + write it after operator review.

    Three phases (per docs/ENTERPRISE-SELF-BOOTSTRAP.md):

      1. Discovery — read-only AWS API enumeration using the
         current admin session. Never reads source code; never
         calls iam-jit-the-company; never mutates IAM.

      2. Proposal — feeds the discovery + your free-text prompt to
         the customer's own LLM tier (Bedrock / Anthropic / Ollama
         per IAM_JIT_LLM config). iam-jit-the-company never sees
         this traffic.

      3. Review — prints YAML + a diff against the current config
         and prompts y/n/edit. On accept, writes the new config +
         an audit row.
    """
    _enforce_enterprise_tier()

    cfg_path = config_path or _default_config_path()
    aud_path = audit_path or _default_audit_path()

    # Import the modules (not the symbols) so tests can monkeypatch
    # discover / propose on their home modules and the CLI picks up
    # the replacements at call time.
    from . import discovery as _discovery_mod
    from . import proposal as _proposal_mod
    from .review import apply_proposal, review_loop

    click.secho("Phase 1: AWS discovery", fg="cyan", bold=True)
    try:
        env = _discovery_mod.discover(region=region)
    except Exception as e:
        click.secho(f"Discovery failed: {e}", fg="red", err=True)
        sys.exit(2)
    click.echo(f"  caller:        {env.caller_arn}")
    click.echo(f"  caller account:{env.caller_account_id}")
    click.echo(f"  region:        {env.caller_region}")
    click.echo(f"  accounts:      {len(env.accounts)}")
    click.echo(f"  oidc roles:    {len(env.oidc_roles)}")
    click.echo(
        f"  bedrock:       {'reachable' if env.bedrock.bedrock_reachable else 'unreachable'}"
        f" (anthropic models: {len(env.bedrock.anthropic_model_ids)})"
    )
    click.echo(f"  eks clusters:  {len(env.eks_clusters)}")
    click.echo(f"  ecs clusters:  {len(env.ecs_clusters)}")
    if env.errors:
        click.secho(f"  errors:        {len(env.errors)} (see proposal notes)",
                    fg="yellow")
        for err in env.errors[:10]:
            click.echo(f"    - {err}")

    click.secho("\nPhase 2: LLM-augmented proposal", fg="cyan", bold=True)
    proposal = _proposal_mod.propose(env, operator_prompt)
    if not proposal.parser_strict_match:
        click.secho(
            "  warning: LLM response required coercion or fell back to "
            "deterministic config; see notes.",
            fg="yellow",
        )

    if dry_run:
        click.secho("\n[dry-run] would propose:\n", fg="yellow", bold=True)
        click.echo(proposal.to_yaml())
        return

    actor = (
        os.environ.get("IAM_JIT_BOOTSTRAP_ACTOR")
        or _safe_getuser()
    )

    if auto_accept:
        decision = apply_proposal(
            proposal,
            config_path=cfg_path,
            audit_path=aud_path,
            actor=actor,
            edited=False,
        )
        click.secho(
            f"\nAccepted (auto). Wrote {decision.written_config_path}.",
            fg="green", bold=True,
        )
        click.echo(f"Audit: {decision.audit_path}")
        return

    click.secho("\nPhase 3: review", fg="cyan", bold=True)
    decision = review_loop(
        proposal,
        config_path=cfg_path,
        audit_path=aud_path,
        actor=actor,
        prompt=click.prompt,
        echo=click.echo,
    )
    if decision.accepted:
        click.secho(
            f"\nAccepted. Wrote {decision.written_config_path}.",
            fg="green", bold=True,
        )
        click.echo(f"Audit: {decision.audit_path}")
    else:
        click.secho(
            f"\nRejected ({decision.rejection_reason}). No config written.",
            fg="yellow",
        )
        click.echo(f"Audit: {decision.audit_path}")
        sys.exit(4)


def _safe_getuser() -> str:
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"
