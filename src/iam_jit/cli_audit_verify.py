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
    via ``--audit-log-path``; we derive the directory from it.

    Used by the retention command; the verify command uses the
    stricter :func:`_resolve_verify_log_dir` per #607 (CWD default is
    a silent-degradation footgun for a security verifier)."""
    env_path = os.environ.get("IAM_JIT_AUDIT_LOG_PATH")
    if env_path:
        return str(pathlib.Path(env_path).parent)
    return "."


# Default auto-detect candidates the verify command consults when the
# operator passes neither --log-dir nor sets $IAM_JIT_AUDIT_LOG_PATH.
# Listed in priority order. Per #607 we explicitly do NOT fall back to
# CWD — running `iam-jit audit verify` in a random directory and
# getting "ok — chain verified clean" is the silent-degradation bug
# UAT-Admin-CLI 2026-05-25 (Gap C) flagged.
_VERIFY_AUTO_DETECT_CANDIDATES = (
    "~/.iam-jit/bouncer",
    "~/.iam-jit/audit",
    "~/.iam-jit",
    "./audit-log",
)


def _resolve_verify_log_dir(
    log_dir: pathlib.Path | None,
    *,
    env: dict[str, str] | None = None,
    candidates: tuple[str, ...] = _VERIFY_AUTO_DETECT_CANDIDATES,
) -> tuple[pathlib.Path | None, str]:
    """Resolve the verify command's log directory per #607.

    Returns ``(path_or_none, reason)``. ``reason`` is one of:
      * ``"explicit"`` — operator passed --log-dir
      * ``"env_var"`` — derived from $IAM_JIT_AUDIT_LOG_PATH
      * ``"auto_detect:<path>"`` — first existing candidate
      * ``"none_found"`` — no flag, no env var, no candidate exists;
         caller must error out (NOT default to CWD, per #607)
    """
    env = env if env is not None else dict(os.environ)
    if log_dir is not None:
        return pathlib.Path(log_dir), "explicit"
    env_path = env.get("IAM_JIT_AUDIT_LOG_PATH")
    if env_path:
        return pathlib.Path(env_path).parent, "env_var"
    for c in candidates:
        p = pathlib.Path(c).expanduser()
        if p.is_dir():
            return p, f"auto_detect:{p}"
    return None, "none_found"


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
    @click.option(
        "--explain",
        is_flag=True,
        default=False,
        help="Print the scope (resolved --log-dir, files that would "
             "be verified, manifest count) WITHOUT actually verifying. "
             "Useful for confirming auto-detection picked the right "
             "directory before running a long verification.",
    )
    def verify_cmd(
        log_dir: pathlib.Path | None,
        since: str | None,
        public_key_b64: str | None,
        as_json: bool,
        skip_manifests: bool,
        explain: bool,
    ) -> None:
        """Verify the bouncer audit chain + signed manifests.

        Exit codes:
          * 0 — events were checked AND chain clean AND all manifest
                signatures verified.
          * 1 — at least one finding (chain inconsistency OR bad
                manifest signature).
          * 2 — bad arguments (e.g. invalid --since, no --log-dir
                resolvable, --log-dir does not exist).
          * 3 — nothing was checked (zero events, zero files). Per #607
                this is treated as a verification failure: a security
                verifier that returns OK on an empty input has zero
                signal. Specify --log-dir explicitly or check the path.

        Per ``[[ibounce-honest-positioning]]`` the success path
        ("RESULT: ok") fires only when something was actually verified.
        """
        # --- resolve log dir per #607 (no silent CWD fallback) ---
        resolved_path, resolve_reason = _resolve_verify_log_dir(log_dir)
        if resolved_path is None:
            click.echo(
                "audit verify: no --log-dir specified and no default "
                "found. Try:\n"
                "  iam-jit audit verify --log-dir ~/.iam-jit/bouncer\n"
                "Auto-detect candidates (in order):\n"
                + "\n".join(f"  - {c}" for c in _VERIFY_AUTO_DETECT_CANDIDATES),
                err=True,
            )
            sys.exit(2)
        if not resolved_path.is_dir():
            click.echo(
                f"audit verify: --log-dir does not exist: {resolved_path} "
                f"(resolved via {resolve_reason})",
                err=True,
            )
            sys.exit(2)
        resolved_dir = str(resolved_path)
        now = time.time()
        try:
            since_unix = _parse_since(since, now=now)
        except click.BadParameter as e:
            click.echo(f"audit verify: {e.message}", err=True)
            sys.exit(2)
        # --- --explain path: preview scope + exit without verifying ---
        if explain:
            _emit_explain_report(
                resolved_dir=resolved_dir,
                resolve_reason=resolve_reason,
                since=since,
                since_unix=since_unix,
                skip_manifests=skip_manifests,
                as_json=as_json,
            )
            sys.exit(0)
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
        # Per #607: "events_checked == 0 AND files_checked == 0 AND
        # zero manifests checked" means we verified literally nothing.
        # That is NOT a clean-chain result; it is a no-op masquerading
        # as one. Emit a distinct warn + exit 3 so cron / CI / compliance
        # pipelines can distinguish "verified clean" from "verified
        # nothing" without re-parsing human text.
        chain_dict = chain_result.to_dict()
        nothing_checked = (
            chain_dict["events_checked"] == 0
            and chain_dict["files_checked"] == 0
            and manifests_checked == 0
        )
        if nothing_checked:
            warn_reason = (
                f"no events, no files, no manifests checked at "
                f"log-dir={resolved_dir} (resolved via {resolve_reason})"
                + (f" since={since}" if since else "")
                + ". Possible causes: (a) wrong --log-dir, (b) no audit "
                "chain configured at that path, (c) bouncer never wrote "
                "audit logs yet. Common locations to try: "
                + ", ".join(_VERIFY_AUTO_DETECT_CANDIDATES)
                + "."
            )
            report = {
                "log_dir": resolved_dir,
                "resolved_via": resolve_reason,
                "since": since,
                "chain": chain_dict,
                "manifests_checked": manifests_checked,
                "manifest_findings": manifest_findings,
                "ok": False,
                "nothing_checked": True,
                "warning": warn_reason,
            }
            if as_json:
                click.echo(json.dumps(report, indent=2, sort_keys=True))
            else:
                click.echo(
                    f"iam-jit audit verify — log_dir={resolved_dir} "
                    f"(resolved via {resolve_reason})"
                )
                if since:
                    click.echo(f"  filter: since={since}")
                click.echo(
                    "  chain: 0 events across 0 file(s); 0 manifests checked"
                )
                click.echo(
                    "RESULT: warn — no events checked. Specify --log-dir "
                    "or check the location."
                )
            click.echo(f"WARN: {warn_reason}", err=True)
            sys.exit(3)
        report = {
            "log_dir": resolved_dir,
            "resolved_via": resolve_reason,
            "since": since,
            "chain": chain_dict,
            "manifests_checked": manifests_checked,
            "manifest_findings": manifest_findings,
            "ok": chain_result.ok and not manifest_findings,
            "nothing_checked": False,
        }
        if as_json:
            click.echo(json.dumps(report, indent=2, sort_keys=True))
        else:
            _emit_human_report(report)
        sys.exit(0 if report["ok"] else 1)

    return verify_cmd


def register_audit_verify_receipt_command(
    audit_group: click.Group,
) -> click.Command:
    """Register `iam-jit audit verify-receipt <FILE>` — #731 / BUILD-10.

    Offline verifier (no network) for an Ed25519-signed denial receipt.
    Checks the signature; optionally checks nonce freshness against the
    bouncer's persistent nonce store so a REPLAYED receipt (a nonce
    presented twice) is detected even across a bouncer restart.

    Returns the registered command so tests can invoke it directly.
    """

    @audit_group.command("verify-receipt")
    @click.argument(
        "receipt_file",
        type=click.Path(exists=True, dir_okay=False, path_type=pathlib.Path),
    )
    @click.option(
        "--public-key",
        "public_key_b64",
        default=None,
        help="Override the public key embedded in the receipt. Use when "
             "verifying against a pinned out-of-band key (strictest "
             "posture). URL-safe base64 (no padding).",
    )
    @click.option(
        "--nonce-db",
        type=click.Path(dir_okay=False, path_type=pathlib.Path),
        default=None,
        help="Path to the bouncer's persistent nonce store "
             "(denial-receipt-nonces.sqlite3). When given, the receipt's "
             "nonce is checked for freshness: an already-consumed nonce "
             "is reported as a REPLAY; a never-minted nonce as "
             "unrecognised. Omit to verify the signature only.",
    )
    @click.option(
        "--no-consume",
        is_flag=True,
        default=False,
        help="With --nonce-db, do NOT mark the nonce consumed (read-only "
             "freshness peek). Default: verifying consumes the nonce so "
             "the NEXT verify of the same receipt is flagged as a replay.",
    )
    @click.option(
        "--json", "as_json",
        is_flag=True,
        default=False,
        help="Emit structured JSON instead of human-readable output.",
    )
    def verify_receipt_cmd(
        receipt_file: pathlib.Path,
        public_key_b64: str | None,
        nonce_db: pathlib.Path | None,
        no_consume: bool,
        as_json: bool,
    ) -> None:
        """Verify an Ed25519-signed denial receipt offline.

        HONEST FRAMING: a valid receipt proves iam-jit's RECORD that it
        denied this action at this time for this reason. It does NOT
        prove the agent was unable to act through another channel, nor
        (for a cooperative-mode deny) enforcement at the wire.

        Exit codes:
          * 0 — signature verifies AND (if --nonce-db) nonce is fresh.
          * 1 — signature invalid / tampered, OR nonce is a replay /
                unrecognised. Per [[ibounce-honest-positioning]] any
                replay or unrecognised-nonce is a LOUD failure.
          * 2 — bad arguments / unreadable receipt.
        """
        from .receipts import DenialReceipt, open_nonce_store, verify_receipt

        try:
            raw = json.loads(receipt_file.read_text(encoding="utf-8"))
        except Exception as e:  # noqa: BLE001
            click.echo(f"audit verify-receipt: cannot read {receipt_file}: {e}", err=True)
            sys.exit(2)
        try:
            receipt = DenialReceipt.from_dict(raw)
        except Exception as e:  # noqa: BLE001
            click.echo(f"audit verify-receipt: malformed receipt: {e}", err=True)
            sys.exit(2)

        sig_ok, sig_reason = verify_receipt(
            receipt, public_key_override_b64=public_key_b64,
        )

        nonce_status = "not_checked"
        nonce_reason: str | None = None
        if nonce_db is not None:
            try:
                store = open_nonce_store(str(nonce_db))
                if no_consume:
                    # Read-only peek: a check_and_consume would mutate; do
                    # a raw lookup instead. SqliteNonceStore exposes the
                    # consume via check_and_consume only, so for the
                    # read-only peek we re-open and inspect via a direct
                    # query helper.
                    check = _peek_nonce(store, receipt.nonce)
                else:
                    check = store.check_and_consume(receipt.nonce)
                if not check.known:
                    nonce_status = "unrecognised"
                    nonce_reason = (
                        "nonce was never minted by this bouncer (or was "
                        "evicted from the store) — cannot confirm freshness"
                    )
                elif check.replay:
                    nonce_status = "replay"
                    nonce_reason = (
                        f"nonce already consumed (consume_count="
                        f"{check.consume_count}) — this is a REPLAYED receipt"
                    )
                else:
                    nonce_status = "fresh"
            except Exception as e:  # noqa: BLE001
                nonce_status = "error"
                nonce_reason = f"nonce store check failed: {e}"

        overall_ok = sig_ok and nonce_status in ("fresh", "not_checked")

        report = {
            "receipt_file": str(receipt_file),
            "deny_id": receipt.deny_id,
            "action": receipt.action,
            "resource": receipt.resource,
            "reason": receipt.reason,
            "agent_session": receipt.agent_session,
            "timestamp": receipt.timestamp,
            "verdict": receipt.verdict,
            "nonce": receipt.nonce,
            "public_key_fingerprint": receipt.public_key_fingerprint,
            "signature_ok": sig_ok,
            "signature_reason": sig_reason,
            "nonce_status": nonce_status,
            "nonce_reason": nonce_reason,
            "ok": overall_ok,
            "proves": (
                "iam-jit's RECORD that it denied this action at this time "
                "for this reason; NOT that the agent could not act through "
                "another channel"
            ),
        }
        if as_json:
            click.echo(json.dumps(report, indent=2, sort_keys=True))
        else:
            click.echo(f"iam-jit audit verify-receipt — {receipt_file}")
            click.echo(f"  deny_id:   {receipt.deny_id}")
            click.echo(f"  action:    {receipt.action}")
            click.echo(f"  resource:  {receipt.resource or '(none)'}")
            click.echo(f"  reason:    {receipt.reason}")
            click.echo(f"  session:   {receipt.agent_session or '(none)'}")
            click.echo(f"  timestamp: {receipt.timestamp}")
            click.echo(f"  key fp:    {receipt.public_key_fingerprint}")
            if sig_ok:
                click.echo("  signature: OK (Ed25519 verifies)")
            else:
                click.echo(f"  signature: FAILED — {sig_reason}")
            if nonce_status != "not_checked":
                if nonce_status == "fresh":
                    click.echo("  nonce:     FRESH (first presentation)")
                elif nonce_status == "replay":
                    click.echo(f"  nonce:     REPLAY — {nonce_reason}")
                elif nonce_status == "unrecognised":
                    click.echo(f"  nonce:     UNRECOGNISED — {nonce_reason}")
                else:
                    click.echo(f"  nonce:     ERROR — {nonce_reason}")
            click.echo(
                "  proves:    iam-jit's RECORD of this deny (not that the "
                "agent could not act elsewhere)"
            )
            click.echo(
                f"RESULT: {'ok' if overall_ok else 'FAILED'}"
            )
        sys.exit(0 if overall_ok else 1)

    return verify_receipt_cmd


def _peek_nonce(store: Any, nonce: str) -> Any:
    """Read-only freshness peek for --no-consume. Inspects the store
    without mutating consume state. Falls back to a (mutating)
    check_and_consume only if the store exposes no read path."""
    from .receipts.nonce_store import NonceCheck, SqliteNonceStore
    if isinstance(store, SqliteNonceStore):
        with store._lock:  # noqa: SLF001 — sibling module, read-only peek
            row = store._conn.execute(  # noqa: SLF001
                "SELECT minted_ts, consume_count FROM denial_receipt_nonces "
                "WHERE nonce = ?",
                (nonce,),
            ).fetchone()
        if row is None:
            return NonceCheck(nonce=nonce, known=False, replay=False, consume_count=0)
        prior = int(row["consume_count"])
        return NonceCheck(
            nonce=nonce, known=True, replay=prior > 0,
            consume_count=prior, minted_ts=row["minted_ts"] or None,
        )
    # Non-sqlite (in-memory) store: no non-mutating path; do the
    # consume but it's a peek over a volatile store anyway.
    return store.check_and_consume(nonce)


def _emit_explain_report(
    *,
    resolved_dir: str,
    resolve_reason: str,
    since: str | None,
    since_unix: float | None,
    skip_manifests: bool,
    as_json: bool,
) -> None:
    """Preview scope without verifying. Per #607 spec step 4."""
    log_dir_path = pathlib.Path(resolved_dir)
    jsonl_files: list[dict[str, Any]] = []
    if log_dir_path.is_dir():
        for f in sorted(log_dir_path.iterdir()):
            if f.is_file() and (
                f.name.endswith(".jsonl")
                or f.name.endswith(".jsonl.gz")
                or ".ndjson" in f.name
            ):
                try:
                    st = f.stat()
                    jsonl_files.append({
                        "path": str(f),
                        "size_bytes": st.st_size,
                        "mtime": st.st_mtime,
                    })
                except OSError:
                    continue
    manifest_count = 0
    if not skip_manifests:
        try:
            manifest_count = sum(1 for _ in list_manifests(resolved_dir))
        except Exception:
            manifest_count = 0
    state_file = chain_state_path(resolved_dir)
    state_file_present = state_file.is_file()
    payload = {
        "explain": True,
        "log_dir": resolved_dir,
        "resolved_via": resolve_reason,
        "since": since,
        "since_unix": since_unix,
        "candidate_files": jsonl_files,
        "manifest_count": manifest_count,
        "skip_manifests": skip_manifests,
        "state_file_present": state_file_present,
        "would_run": True,
    }
    if as_json:
        click.echo(json.dumps(payload, indent=2, sort_keys=True))
        return
    click.echo(f"iam-jit audit verify --explain")
    click.echo(f"Will verify:")
    click.echo(f"  log-dir: {resolved_dir} (resolved via {resolve_reason})")
    if since:
        click.echo(f"  since: {since}")
    click.echo(f"  state file present: {state_file_present}")
    if jsonl_files:
        click.echo(f"Files found ({len(jsonl_files)}):")
        for f in jsonl_files:
            click.echo(
                f"  - {f['path']} ({f['size_bytes']} bytes)"
            )
    else:
        click.echo("Files found: 0 — verifying this directory would WARN "
                   "(see exit 3 in `iam-jit audit verify --help`).")
    if not skip_manifests:
        click.echo(f"Manifests to verify: {manifest_count}")
    else:
        click.echo("Manifests: skipped (--skip-manifests)")
    click.echo("Run without --explain to actually verify.")


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
            # #502 fix: compute the planned transitions WITHOUT mutating
            # the filesystem, then print a per-file table so operators
            # can preview the retention plan before committing.
            from .bouncer.audit_export import plan_retention, PlannedTransition
            planned = plan_retention(resolved_dir, policy)
            if as_json:
                click.echo(json.dumps({
                    "dry_run": True,
                    "log_dir": resolved_dir,
                    "policy": {
                        "compliance": policy.compliance,
                        "hot_days": policy.hot_days,
                        "warm_days": policy.warm_days,
                        "cold_days": policy.cold_days,
                        "purge_after_days": policy.purge_after_days,
                        "gdpr_pii_purge": policy.gdpr_pii_purge,
                    },
                    "planned": [p.to_dict() for p in planned],
                }, indent=2, sort_keys=True))
            else:
                click.echo(
                    f"DRY-RUN: {policy.compliance} policy against "
                    f"log_dir={resolved_dir} "
                    f"(hot<={policy.hot_days}d, warm<={policy.warm_days}d, "
                    f"cold<={policy.cold_days}d, "
                    f"purge={policy.purge_after_days}, "
                    f"gdpr_pii_purge={policy.gdpr_pii_purge})"
                )
                click.echo(
                    "Re-run with --no-dry-run to apply.\n"
                )
                if not planned:
                    click.echo("  (no rotated archives found in log_dir)")
                else:
                    # Column widths: file basename + fixed-width columns.
                    col_file = max(
                        len("file"),
                        *(len(pathlib.Path(p.path).name) for p in planned),
                    )
                    header = (
                        f"{'file':<{col_file}}  "
                        f"{'current_tier':<13}  "
                        f"{'planned_tier':<13}  "
                        f"{'age_days':>9}  "
                        f"{'action'}"
                    )
                    click.echo(header)
                    click.echo("-" * len(header))
                    for p in planned:
                        fname = pathlib.Path(p.path).name
                        click.echo(
                            f"{fname:<{col_file}}  "
                            f"{p.current_tier:<13}  "
                            f"{p.planned_tier:<13}  "
                            f"{p.age_days:>9.1f}  "
                            f"{p.action}"
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
