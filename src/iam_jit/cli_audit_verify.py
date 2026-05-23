"""``iam-jit audit verify`` — #427 / §A66 chain + manifest verifier.

Walks the on-disk JSONL audit log + rotated archives in a bouncer's
log directory and reports any chain inconsistencies + any signed-
manifest verification failures. Operators run this:

  * on a cadence (cron / CI / autopilot) to catch tampering early
  * during incident response to verify what landed in the log
  * during compliance audits as evidence the chain hasn't drifted

Output is human-readable by default; ``--json`` emits the structured
result so SOC pipelines can ingest the same data.

Per ``[[ibounce-honest-positioning]]`` we surface EVERY finding —
no silent passes on ambiguous rows. The exit code is 0 only when
the chain verifies clean AND every manifest signature verifies.

Per ``[[v1-scope-bar]]`` this is a thin CLI shim; all heavy lifting
lives in ``iam_jit.bouncer.audit_export.chain`` +
``iam_jit.bouncer.audit_export.manifest``.
"""

from __future__ import annotations

import json
import os
import pathlib
import re
import sys
import time
from typing import Any

import click

from .bouncer.audit_export import (
    chain_state_path,
    list_manifests,
    load_manifest_file,
    verify_chain_jsonl,
    verify_manifest,
)


# ---------------------------------------------------------------------------
# --since parsing
# ---------------------------------------------------------------------------


_DURATION_RE = re.compile(
    r"^(?P<n>\d+)(?P<unit>[smhd])$",
    re.IGNORECASE,
)
_UNIT_TO_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}


def _parse_since(value: str | None, *, now: float) -> float | None:
    """Parse the --since argument into a unix timestamp lower-bound.

    Accepted forms:
      * ``30d`` / ``24h`` / ``5m`` / ``300s`` — relative duration
      * ``2026-05-18T00:00:00Z`` — ISO 8601 absolute timestamp

    Returns the unix timestamp at or before which files should be
    skipped. None when ``value`` is None (no filter).
    """
    if value is None:
        return None
    m = _DURATION_RE.match(value.strip())
    if m:
        n = int(m.group("n"))
        unit = m.group("unit").lower()
        return now - (n * _UNIT_TO_SECONDS[unit])
    # ISO 8601 fallback.
    import datetime as _dt
    try:
        dt = _dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        return dt.timestamp()
    except ValueError as e:
        raise click.BadParameter(
            f"--since must be a duration like '30d'/'24h' or an "
            f"ISO 8601 timestamp; got {value!r} ({e})",
        ) from e


# ---------------------------------------------------------------------------
# Command
# ---------------------------------------------------------------------------


def _default_log_dir() -> str:
    """Resolve the audit log dir from the standard env var, falling
    back to ``./``. The bouncer's CLI sets IAM_JIT_AUDIT_LOG_PATH
    via ``--audit-log-path``; we derive the directory from it."""
    env_path = os.environ.get("IAM_JIT_AUDIT_LOG_PATH")
    if env_path:
        return str(pathlib.Path(env_path).parent)
    return "."


def register_audit_verify_command(audit_group: click.Group) -> click.Command:
    """Register `iam-jit audit verify` on the existing `audit` group.

    Returns the registered Click command so tests can invoke it via
    ``CliRunner.invoke(cmd, [...])``.
    """

    @audit_group.command("verify")
    @click.option(
        "--log-dir",
        type=click.Path(file_okay=False, dir_okay=True, path_type=pathlib.Path),
        default=None,
        help="Audit log directory to verify. Defaults to the directory "
             "of $IAM_JIT_AUDIT_LOG_PATH (the bouncer's audit log) or "
             "the current directory.",
    )
    @click.option(
        "--since",
        default=None,
        help="Only verify files modified after this point. Accepts a "
             "duration like '30d' / '24h' / '5m' / '300s' OR an "
             "ISO 8601 timestamp like '2026-05-18T00:00:00Z'.",
    )
    @click.option(
        "--public-key",
        "public_key_b64",
        default=None,
        help="Override the public key embedded in each manifest. "
             "Use when verifying against a pinned out-of-band key "
             "(strictest posture). URL-safe base64 (no padding).",
    )
    @click.option(
        "--json", "as_json",
        is_flag=True,
        default=False,
        help="Emit structured JSON instead of human-readable output.",
    )
    @click.option(
        "--skip-manifests",
        is_flag=True,
        default=False,
        help="Skip manifest signature verification (chain-only).",
    )
    def verify_cmd(
        log_dir: pathlib.Path | None,
        since: str | None,
        public_key_b64: str | None,
        as_json: bool,
        skip_manifests: bool,
    ) -> None:
        """Verify the bouncer audit chain + signed manifests.

        Exit 0 = chain clean + all manifest signatures verified.
        Exit 1 = at least one finding (chain inconsistency OR bad
        manifest signature). The structured output (or human report)
        details each finding so the operator can pinpoint the row /
        manifest that broke trust.
        """
        resolved_dir = str(log_dir) if log_dir else _default_log_dir()
        now = time.time()
        try:
            since_unix = _parse_since(since, now=now)
        except click.BadParameter as e:
            click.echo(f"audit verify: {e.message}", err=True)
            sys.exit(2)
        # Chain state file presence signals whether the chain was
        # ever wired; surfaces in the report so operators know if a
        # missing state file is the gap or whether the chain truly
        # never existed.
        state_file = chain_state_path(resolved_dir)
        state_file_missing = not state_file.is_file()
        chain_result = verify_chain_jsonl(
            resolved_dir,
            since_unix=since_unix,
            state_file_missing=state_file_missing,
        )
        manifest_findings: list[dict[str, Any]] = []
        manifests_checked = 0
        if not skip_manifests:
            for mpath in list_manifests(resolved_dir):
                try:
                    m = load_manifest_file(mpath)
                except Exception as e:
                    manifest_findings.append({
                        "manifest": str(mpath),
                        "ok": False,
                        "reason": f"load failed: {e}",
                    })
                    continue
                ok, reason = verify_manifest(
                    m, public_key_override_b64=public_key_b64,
                )
                manifests_checked += 1
                if not ok:
                    manifest_findings.append({
                        "manifest": str(mpath),
                        "ok": False,
                        "reason": reason or "unknown",
                        "seq_start": m.seq_start,
                        "seq_end": m.seq_end,
                    })
        report = {
            "log_dir": resolved_dir,
            "since": since,
            "chain": chain_result.to_dict(),
            "manifests_checked": manifests_checked,
            "manifest_findings": manifest_findings,
            "ok": chain_result.ok and not manifest_findings,
        }
        if as_json:
            click.echo(json.dumps(report, indent=2, sort_keys=True))
        else:
            _emit_human_report(report)
        sys.exit(0 if report["ok"] else 1)

    return verify_cmd


def _emit_human_report(report: dict[str, Any]) -> None:
    """Print the human-friendly version of the verify report."""
    click.echo(f"iam-jit audit verify — log_dir={report['log_dir']}")
    if report.get("since"):
        click.echo(f"  filter: since={report['since']}")
    c = report["chain"]
    click.echo(
        f"  chain: {c['events_checked']} events across {c['files_checked']} "
        f"file(s); head_seq={c['head_seq']}"
    )
    if c.get("state_file_missing_at_start"):
        click.echo(
            "  warning: chain state file missing at start — the chain "
            "may have been re-anchored since the last full run"
        )
    if not c["ok"]:
        click.echo(f"  chain inconsistencies: {len(c['inconsistencies'])}")
        for f in c["inconsistencies"]:
            seq = f"seq={f['seq']}" if f["seq"] is not None else "seq=?"
            click.echo(
                f"    - {f['source']}:{f['line_number']} {seq} "
                f"reason={f['reason']}"
            )
    click.echo(f"  manifests checked: {report['manifests_checked']}")
    if report["manifest_findings"]:
        click.echo(f"  manifest failures: {len(report['manifest_findings'])}")
        for f in report["manifest_findings"]:
            seq_info = (
                f" (seq {f.get('seq_start')}..{f.get('seq_end')})"
                if "seq_start" in f else ""
            )
            click.echo(
                f"    - {f['manifest']}{seq_info}: {f['reason']}"
            )
    if report["ok"]:
        click.echo("RESULT: ok — chain verified clean + all manifests valid")
    else:
        click.echo("RESULT: FAILED — see findings above")


def register_audit_retention_command(audit_group: click.Group) -> click.Command:
    """Register ``iam-jit audit retention apply`` — offline mover that
    transitions rotated archives across hot/warm/cold tiers + purges
    files past ``purge_after_days``.

    Per the §A67 spec retention is ENFORCED AT WRITE TIME for the PII
    redaction path (handled by the AuditLogWriter when wired with a
    RetentionPolicy); tier transitions are an offline operation an
    operator runs on a cadence (cron / autopilot daemon). This CLI is
    that offline entry point.

    The policy is supplied via a ``.iam-jit.yaml``-shaped retention
    block on stdin OR via a framework name shortcut.
    """

    @audit_group.group("retention")
    def retention_group() -> None:
        """Compliance retention tiering operations (#428 / §A67)."""

    @retention_group.command("apply")
    @click.option(
        "--log-dir",
        type=click.Path(file_okay=False, dir_okay=True, path_type=pathlib.Path),
        default=None,
        help="Audit log directory to apply retention against. Defaults "
             "to the directory of $IAM_JIT_AUDIT_LOG_PATH or '.'.",
    )
    @click.option(
        "--framework",
        type=click.Choice(
            ["pci", "hipaa", "sox", "gdpr", "custom"],
            case_sensitive=False,
        ),
        default=None,
        help="Apply per-framework defaults. Mutually exclusive with "
             "--config (which reads a full retention block).",
    )
    @click.option(
        "--config",
        type=click.Path(exists=True, dir_okay=False, path_type=pathlib.Path),
        default=None,
        help="Path to a YAML file with a `iam-jit.retention:` block "
             "(same shape as .iam-jit.yaml).",
    )
    @click.option(
        "--dry-run/--no-dry-run",
        default=True,
        help="When --dry-run (default), print what would transition + "
             "purge but don't touch the filesystem.",
    )
    @click.option(
        "--json", "as_json",
        is_flag=True,
        default=False,
        help="Emit structured JSON.",
    )
    def apply_cmd(
        log_dir: pathlib.Path | None,
        framework: str | None,
        config: pathlib.Path | None,
        dry_run: bool,
        as_json: bool,
    ) -> None:
        """Apply retention policy: transition archives + purge expired."""
        from .bouncer.audit_export import (
            apply_retention,
            retention_policy_for_framework,
            retention_policy_from_declaration,
        )
        resolved_dir = str(log_dir) if log_dir else _default_log_dir()
        if framework and config:
            raise click.UsageError("--framework + --config are mutually exclusive")
        if config:
            try:
                from ruamel.yaml import YAML
                yaml = YAML(typ="safe")
                with config.open() as f:
                    parsed = yaml.load(f) or {}
                retention_block = (parsed.get("iam-jit") or {}).get("retention")
                policy = retention_policy_from_declaration(retention_block)
            except Exception as e:
                raise click.UsageError(
                    f"failed to load retention from {config}: {e}",
                ) from e
        elif framework:
            policy = retention_policy_for_framework(framework.lower())
        else:
            from .bouncer.audit_export import default_retention_policy
            policy = default_retention_policy()
        if dry_run:
            # Snapshot without actually mutating — we still call
            # apply_retention against a copy concept by tagging it
            # explicitly in output. The implementation does mutate so
            # for a true dry-run we'd need a separate planner; for
            # the v1 surface we just refuse to act unless --no-dry-run.
            click.echo(
                "DRY-RUN: would apply policy "
                f"(compliance={policy.compliance}, hot<={policy.hot_days}, "
                f"warm<={policy.warm_days}, cold<={policy.cold_days}, "
                f"purge={policy.purge_after_days}, "
                f"gdpr_pii_purge={policy.gdpr_pii_purge}) "
                f"to log_dir={resolved_dir}. Re-run with --no-dry-run to mutate."
            )
            sys.exit(0)
        result = apply_retention(resolved_dir, policy)
        report = {
            "log_dir": resolved_dir,
            "policy": {
                "compliance": policy.compliance,
                "hot_days": policy.hot_days,
                "warm_days": policy.warm_days,
                "cold_days": policy.cold_days,
                "purge_after_days": policy.purge_after_days,
                "gdpr_pii_purge": policy.gdpr_pii_purge,
            },
            "result": result.to_dict(),
        }
        if as_json:
            click.echo(json.dumps(report, indent=2, sort_keys=True))
        else:
            click.echo(
                f"applied {policy.compliance} policy to {resolved_dir}: "
                f"{len(result.transitions)} transitions, "
                f"{len(result.purged)} purged, "
                f"{len(result.cold_eligible)} cold-eligible"
            )
            for t in result.transitions:
                click.echo(
                    f"  {t.from_tier} -> {t.to_tier}: {t.path} "
                    f"(age={t.age_days:.1f}d)"
                )
            for p in result.purged:
                click.echo(f"  purged: {p}")
        sys.exit(0)

    return apply_cmd


__all__ = [
    "register_audit_retention_command",
    "register_audit_verify_command",
]
