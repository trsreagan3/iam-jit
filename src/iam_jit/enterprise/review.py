"""Phase 3: operator review + accept.

Prints the YAML diff between the current iam-jit config and the
proposal, then prompts y/n/edit. On accept, writes the new config
+ an audit row recording who-accepted-what (CREATES, never
mutates an existing IAM resource per [[creates-never-mutates]]).
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import difflib
import io
import json
import os
import pathlib
import subprocess
import tempfile
from typing import Any, Callable

from .proposal import ProposedConfig


@dataclasses.dataclass(frozen=True)
class ReviewDecision:
    """What the operator chose at the y/n/edit prompt."""

    accepted: bool
    edited: bool
    final_config: ProposedConfig | None
    written_config_path: pathlib.Path | None
    audit_path: pathlib.Path | None
    rejection_reason: str | None = None


def _now_iso() -> str:
    return _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_current_config(path: pathlib.Path) -> dict[str, Any] | None:
    """Read the existing iam-jit config (if any) so we can diff
    against it. Returns None if the file is absent — this is the
    expected first-bootstrap state."""
    if not path.exists():
        return None
    try:
        from ruamel.yaml import YAML
        y = YAML(typ="safe")
        return y.load(path.read_text()) or {}
    except Exception:
        return None


def diff_against_current(
    proposal: ProposedConfig,
    current_config_path: pathlib.Path,
) -> str:
    """Return a unified-diff string between the current YAML config
    (if any) and the proposal's YAML rendering. Used by the CLI's
    review screen."""
    current = _load_current_config(current_config_path)
    if current is None:
        current_text = "# (no current config; this is a fresh bootstrap)\n"
    else:
        from ruamel.yaml import YAML
        y = YAML()
        y.indent(mapping=2, sequence=4, offset=2)
        buf = io.StringIO()
        y.dump(current, buf)
        current_text = buf.getvalue()
    proposed_text = proposal.to_yaml()
    diff = difflib.unified_diff(
        current_text.splitlines(keepends=True),
        proposed_text.splitlines(keepends=True),
        fromfile=str(current_config_path),
        tofile=str(current_config_path) + ".proposed",
    )
    return "".join(diff)


def _edit_yaml_in_editor(
    initial_yaml: str,
    *,
    editor_cmd: str | None = None,
    spawn: Callable[[list[str]], int] | None = None,
) -> str:
    """Spawn `$EDITOR` (or `editor_cmd`) on a tempfile preloaded
    with `initial_yaml`. Returns the edited text. `spawn` is
    injectable for testing.
    """
    editor = editor_cmd or os.environ.get("EDITOR") or "vi"
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".yaml", delete=False,
    ) as fh:
        fh.write(initial_yaml)
        tmp_path = pathlib.Path(fh.name)
    try:
        runner = spawn or _default_spawn
        runner([editor, str(tmp_path)])
        return tmp_path.read_text()
    finally:
        try:
            tmp_path.unlink()
        except OSError:
            pass


def _default_spawn(argv: list[str]) -> int:
    return subprocess.call(argv)


def _parse_edited_yaml(text: str) -> dict[str, Any] | None:
    """Re-parse YAML that came back from the editor. Returns None
    on parse failure so the caller can re-prompt."""
    try:
        from ruamel.yaml import YAML
        y = YAML(typ="safe")
        return y.load(text)
    except Exception:
        return None


def _proposal_from_edited(text: str, original: ProposedConfig) -> ProposedConfig | None:
    """Re-hydrate a ProposedConfig from edited YAML. Returns None
    on missing required fields — the CLI re-prompts."""
    parsed = _parse_edited_yaml(text)
    if not isinstance(parsed, dict):
        return None
    try:
        from .proposal import AccountLLMPolicyChoice
        policies = tuple(
            AccountLLMPolicyChoice(
                account_id=str(p["account_id"]),
                llm_policy=str(p["llm_policy"]),
                reason=str(p.get("reason") or ""),
            )
            for p in (parsed.get("account_llm_policies") or [])
            if isinstance(p, dict) and "account_id" in p and "llm_policy" in p
        )
        return ProposedConfig(
            org_context_name=str(parsed.get("org_context_name") or original.org_context_name),
            account_llm_policies=policies,
            recommended_cluster_arns=tuple(
                str(x) for x in (parsed.get("recommended_cluster_arns") or [])
            ),
            recommended_profiles=tuple(
                str(x) for x in (parsed.get("recommended_profiles") or [])
            ),
            recommended_bouncer_mode_per_account={
                str(k): str(v)
                for k, v in (parsed.get("recommended_bouncer_mode_per_account") or {}).items()
            },
            notes=str(parsed.get("notes") or ""),
            parser_strict_match=False,
            raw_model_response_sample=original.raw_model_response_sample,
        )
    except Exception:
        return None


def _write_audit_row(
    *,
    audit_path: pathlib.Path,
    actor: str,
    proposal: ProposedConfig,
    accepted: bool,
    edited: bool,
    rejection_reason: str | None,
) -> None:
    """Append one JSONL row to the bootstrap audit log.

    Per [[creates-never-mutates]] this file is APPEND-ONLY; the
    bootstrap never rewrites earlier rows. The line is opaque-keyed
    so downstream audit consumers can pick it up.
    """
    audit_path.parent.mkdir(parents=True, exist_ok=True)
    row = {
        "event": "enterprise_bootstrap_review",
        "timestamp": _now_iso(),
        "actor": actor,
        "accepted": accepted,
        "edited": edited,
        "rejection_reason": rejection_reason,
        "proposal": proposal.to_dict(),
    }
    with audit_path.open("a") as fh:
        fh.write(json.dumps(row, sort_keys=True) + "\n")


def apply_proposal(
    proposal: ProposedConfig,
    *,
    config_path: pathlib.Path,
    audit_path: pathlib.Path,
    actor: str,
    edited: bool = False,
) -> ReviewDecision:
    """Write the accepted proposal to `config_path` (CREATES the
    file; if it exists, it is rewritten WITH a backup at
    `config_path.with_suffix('.bak')`).

    Per [[creates-never-mutates]]: we touch ONLY this config file +
    the audit log; we never reach back into AWS IAM.
    """
    config_path.parent.mkdir(parents=True, exist_ok=True)
    if config_path.exists():
        backup = config_path.with_suffix(config_path.suffix + ".bak")
        backup.write_text(config_path.read_text())
    config_path.write_text(proposal.to_yaml())
    _write_audit_row(
        audit_path=audit_path,
        actor=actor,
        proposal=proposal,
        accepted=True,
        edited=edited,
        rejection_reason=None,
    )
    return ReviewDecision(
        accepted=True,
        edited=edited,
        final_config=proposal,
        written_config_path=config_path,
        audit_path=audit_path,
    )


def review_loop(
    proposal: ProposedConfig,
    *,
    config_path: pathlib.Path,
    audit_path: pathlib.Path,
    actor: str,
    prompt: Callable[[str], str],
    echo: Callable[[str], None],
    editor_spawn: Callable[[list[str]], int] | None = None,
    editor_cmd: str | None = None,
) -> ReviewDecision:
    """Drive the y/n/edit loop. Pure: all I/O is injected via
    `prompt`, `echo`, and `editor_spawn` so the CLI + tests share
    one implementation.

    Returns the final ReviewDecision (accepted/rejected/edited).
    """
    current = proposal
    while True:
        echo("\nProposed iam-jit config (review carefully):\n")
        echo(current.to_yaml())
        echo("\nDiff against current config:\n")
        echo(diff_against_current(current, config_path) or "(no diff)\n")
        echo("")
        answer = (prompt("Accept? [y/n/edit] ") or "").strip().lower()
        if answer in ("y", "yes"):
            return apply_proposal(
                current,
                config_path=config_path,
                audit_path=audit_path,
                actor=actor,
                edited=(current is not proposal),
            )
        if answer in ("n", "no"):
            _write_audit_row(
                audit_path=audit_path,
                actor=actor,
                proposal=current,
                accepted=False,
                edited=(current is not proposal),
                rejection_reason="operator rejected",
            )
            return ReviewDecision(
                accepted=False,
                edited=(current is not proposal),
                final_config=None,
                written_config_path=None,
                audit_path=audit_path,
                rejection_reason="operator rejected",
            )
        if answer in ("e", "edit"):
            edited_text = _edit_yaml_in_editor(
                current.to_yaml(),
                editor_cmd=editor_cmd,
                spawn=editor_spawn,
            )
            new_proposal = _proposal_from_edited(edited_text, current)
            if new_proposal is None:
                echo(
                    "Edited YAML failed to parse or was missing required "
                    "fields. Discarding edit; back to the original proposal.\n"
                )
                continue
            current = new_proposal
            continue
        echo("Answer y, n, or edit.\n")
