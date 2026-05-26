"""#412 / §A56 — Weekly digest data layer.

Aggregates per-bouncer activity over a configurable window from the
ambient telemetry surfaces shipped in #449 / #453 (autopilot status
schema 1.1 + per-bouncer healthz polling + denies-recent count).

Per ``[[ibounce-honest-positioning]]``:

  * unreachable bouncers surface a structured per-bouncer note rather
    than silently going to zero (a missing channel is NOT the same as
    "0 denies");
  * adversarial-classified denies are NEVER hidden by the
    positive-signal lead; they surface in
    ``denies_by_classification.appears_adversarial`` + the
    ``recommendations`` list calls out halt+escalate paths.

Per ``[[ambient-value-prop-and-friction-framing]]`` recommendations
LEAD with positive signal (pattern-generalization suggestions,
quiet-period observations) before surfacing operator-attention items.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import json
import logging
import os
import pathlib
import re
from typing import Any, Iterable

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Errors + dataclass
# ---------------------------------------------------------------------------


class DigestError(RuntimeError):
    """Structured digest error (e.g. invalid `since` spec)."""

    def __init__(self, message: str, *, code: str) -> None:
        super().__init__(message)
        self.code = code


SCHEMA_VERSION = "1.0"


@dataclasses.dataclass
class DigestData:
    """One snapshot of cross-bouncer activity in the requested window.

    Shape mirrors the documented MCP tool response so the wire format
    is identical between the CLI's ``--json`` output and the
    ``bounce_digest_recent`` MCP tool per
    ``[[cross-product-agent-parity]]``.
    """

    schema_version: str = SCHEMA_VERSION
    time_window: dict[str, str] = dataclasses.field(default_factory=dict)
    bouncers: dict[str, dict[str, Any]] = dataclasses.field(default_factory=dict)
    totals: dict[str, int] = dataclasses.field(default_factory=dict)
    recommendations: list[str] = dataclasses.field(default_factory=list)
    notes: list[str] = dataclasses.field(default_factory=list)
    # Per [[ibounce-honest-positioning]] §A56c — high-signal operator
    # warnings that MUST surface visibly (e.g. 401 from a bouncer
    # /audit/events endpoint). Separate from `notes` so JSON consumers
    # can branch on `len(warnings) > 0` without parsing prose.
    warnings: list[str] = dataclasses.field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


# ---------------------------------------------------------------------------
# Window parsing — re-uses the same short-form parser as denies.parse_since
# but returns BOTH lower bound + upper bound (now) for the digest's
# ``time_window`` block.
# ---------------------------------------------------------------------------


_SINCE_RE = re.compile(r"^(\d+)([smhdw])$")


def parse_window(spec: str | None) -> tuple[str, str]:
    """Resolve a ``--since`` short form into (from_iso, to_iso).

    Accepts ``5m`` / ``1h`` / ``2d`` / ``1w`` or an ISO 8601 lower
    bound. Raises :class:`DigestError` for malformed input — unlike
    :func:`iam_jit.profile_allow.denies.parse_since` which pass-throughs.
    The digest can't make sense of bogus windows so we surface explicitly.
    """
    if not spec or not spec.strip():
        spec = "1w"
    s = spec.strip()
    now = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)
    to_iso = now.isoformat().replace("+00:00", "Z")
    # ISO lower bound — let it through as-is iff it actually parses.
    # ("bogus" used to slip through a loose dash-count heuristic.)
    if "T" in s or (len(s) >= 10 and s[:10].count("-") == 2):
        try:
            _parse_iso(s)
            return s, to_iso
        except (ValueError, TypeError):
            raise DigestError(
                f"invalid --since ISO spec {spec!r}: not a valid datetime",
                code="invalid_since",
            )
    m = _SINCE_RE.match(s)
    if not m:
        raise DigestError(
            f"invalid --since spec {spec!r}; use Ns/Nm/Nh/Nd/Nw or ISO 8601",
            code="invalid_since",
        )
    qty, unit = int(m.group(1)), m.group(2)
    delta = {
        "s": _dt.timedelta(seconds=qty),
        "m": _dt.timedelta(minutes=qty),
        "h": _dt.timedelta(hours=qty),
        "d": _dt.timedelta(days=qty),
        "w": _dt.timedelta(weeks=qty),
    }[unit]
    from_iso = (now - delta).isoformat().replace("+00:00", "Z")
    return from_iso, to_iso


# ---------------------------------------------------------------------------
# Autopilot status file loader
# ---------------------------------------------------------------------------


def _autopilot_dir() -> pathlib.Path:
    raw = (os.environ.get("IAM_JIT_AUTOPILOT_DIR") or "").strip()
    if raw:
        return pathlib.Path(raw).expanduser()
    return pathlib.Path.home() / ".iam-jit"


def load_autopilot_status() -> dict[str, Any] | None:
    """Best-effort read ``~/.iam-jit/autopilot.status.json``.

    Returns ``None`` when the file is missing or malformed. Per
    ``[[ibounce-honest-positioning]]`` a missing status file is
    surfaced as a digest note, NOT a fabricated zero.
    """
    p = _autopilot_dir() / "autopilot.status.json"
    if not p.exists():
        return None
    try:
        body = json.loads(p.read_text())
    except (OSError, json.JSONDecodeError) as e:
        logger.debug("digest: autopilot.status.json unreadable: %s", e)
        return None
    if not isinstance(body, dict):
        return None
    return body


# ---------------------------------------------------------------------------
# Pending-approval queue counter
# ---------------------------------------------------------------------------


def fetch_pending_approval_count() -> int:
    """Count rows in ``~/.iam-jit/bouncer/profile-allow-pending.jsonl``.

    Returns ``0`` when the file is missing (no pending items) OR when
    the file is unreadable (degraded but not catastrophic — the
    operator can always check the file directly).
    """
    try:
        from ..profile_allow.operations import resolve_pending_path
    except Exception:
        return 0
    try:
        p = resolve_pending_path()
    except Exception:
        return 0
    if not p.exists():
        return 0
    try:
        with p.open("r", encoding="utf-8") as fh:
            return sum(1 for line in fh if line.strip())
    except OSError as e:
        logger.debug("digest: pending queue unreadable at %s: %s", p, e)
        return 0


# ---------------------------------------------------------------------------
# Per-bouncer aggregation
# ---------------------------------------------------------------------------


# Bouncers we explicitly track in the digest. Mirrors the autopilot
# supervisor's set; absent bouncers don't show up.
_DEFAULT_BOUNCERS = ("ibounce", "kbouncer", "dbounce", "gbounce")


def _empty_bouncer_block() -> dict[str, Any]:
    return {
        "total_requests_audited": 0,
        "total_denies": 0,
        "denies_by_classification": {
            "appears_legitimate": 0,
            "ambiguous": 0,
            "appears_adversarial": 0,
        },
        "pending_approval_count": 0,
        "threat_feed_rules_applied": 0,  # Phase C populates
        "improve_cycles_run": 0,
        "improve_changes_auto_installed": 0,
        "improve_changes_pending": 0,
        "noteworthy_events": [],
        "status": "no_data",
    }


def _classify_deny_rows(rows: Iterable[Any]) -> dict[str, int]:
    """Bucket :class:`DenyRow` instances by injection classification.

    Reuses :mod:`iam_jit.structured_deny` so the digest's per-deny
    classification matches the agent-facing 403 + the
    ``--notify-denies stderr`` output (single source of truth).

    #631 — per-event ``report_skip`` spam fix: ``suppress_skip_report=True``
    is passed to ``classify_injection_likelihood`` for every row so the
    logger doesn't emit one identical "ran deterministic-only" line per
    event (6 lines for 3 events, etc.). A SINGLE aggregated
    ``report_skip`` is emitted ONCE per digest invocation when at least
    one row ran in deterministic-only mode. Mirrors the per-row
    suppression + one-aggregated-emit pattern from
    ``cli_profile_allow.py:_suppress_classify_skip`` (#577).
    """
    counts = {
        "appears_legitimate": 0,
        "ambiguous": 0,
        "appears_adversarial": 0,
    }
    try:
        from ..structured_deny.response import classify_injection_likelihood
    except Exception:
        # Best-effort: if the classifier isn't importable, dump
        # everything to ambiguous so the operator still sees a count.
        for _ in rows:
            counts["ambiguous"] += 1
        return counts
    ran_deterministic_only = False
    for row in rows:
        try:
            # suppress_skip_report=True silences the per-row WARNING;
            # we emit one aggregated report_skip below after the loop.
            cls, _hook = classify_injection_likelihood(
                action=getattr(row, "action", "") or "",
                resource=getattr(row, "resource", "") or "",
                deny_source=getattr(row, "deny_source", "") or "",
                deny_reason=getattr(row, "deny_reason", "") or "",
                agent_session_id=getattr(row, "agent_session_id", "") or "",
                suppress_skip_report=True,
            )
            if cls == "pending_classification":
                ran_deterministic_only = True
                cls = "ambiguous"
        except Exception:
            cls = "ambiguous"
        if cls not in counts:
            cls = "ambiguous"
        counts[cls] += 1
    # #631 — emit at most ONE aggregated skip report per digest invocation.
    if ran_deterministic_only:
        try:
            from ..llm.report_skip import REASON_NO_LLM_BACKEND, report_skip
            report_skip(
                feature="structured_deny.classify",
                reason=REASON_NO_LLM_BACKEND,
                mode_hint=(
                    "digest ran deterministic-only; set IAM_JIT_ENABLE_SIDE_LLM=1 "
                    "+ IAM_JIT_LLM=anthropic|openai|bedrock|ollama for LLM-enriched "
                    "classification, or let your agent call iam_jit_classify_deny "
                    "(MCP) for post-hoc enrichment."
                ),
            )
        except Exception:
            pass
    return counts


def _summarize_improve_results(
    results: list[dict[str, Any]] | None,
) -> tuple[int, int, list[dict[str, Any]]]:
    """Return (auto_installed_count, pending_count, noteworthy_events).

    Reads the autopilot supervisor's preserved ``improve.last_results``
    block (per #453 fix — the supervisor now keeps the last cycle's
    results across ticks instead of clearing to ``[]``).
    """
    if not results:
        return 0, 0, []
    auto_installed = 0
    pending = 0
    noteworthy: list[dict[str, Any]] = []
    for r in results:
        if not isinstance(r, dict):
            continue
        status = str(r.get("status") or "")
        if status == "auto_installed":
            auto_installed += 1
            if r.get("rules_added") or r.get("rules_removed"):
                noteworthy.append({
                    "when": r.get("ran_at") or "",
                    "type": "improve_auto_installed",
                    "description": (
                        f"improve cycle auto-installed "
                        f"{int(r.get('rules_added') or 0)} added / "
                        f"{int(r.get('rules_removed') or 0)} removed rule(s) "
                        f"(change_size={float(r.get('change_size') or 0.0):.2f})"
                    ),
                })
        elif status == "pending_approval":
            pending += 1
            noteworthy.append({
                "when": r.get("ran_at") or "",
                "type": "improve_pending_approval",
                "description": (
                    f"improve cycle queued change for approval "
                    f"(change_size={float(r.get('change_size') or 0.0):.2f} "
                    f"exceeds threshold) — run `iam-jit profile pending` "
                    f"to review"
                ),
            })
        elif status in ("partial_install", "no_install"):
            # MRR-2 F1: surface honest partial/no-install in the
            # digest. The digest is THE operator-visible roll-up;
            # silently dropping these would re-create the #448 shape
            # at the digest layer.
            failed = r.get("failed_rules") or []
            installed = int(r.get("rules_added") or 0)
            noteworthy.append({
                "when": r.get("ran_at") or "",
                "type": f"improve_{status}",
                "description": (
                    f"improve cycle reported {status}: "
                    f"{installed} rule(s) landed, {len(failed)} failed — "
                    f"inspect failed_rules in the cycle output and re-run "
                    f"after addressing each error_code"
                ),
            })
    return auto_installed, pending, noteworthy


# ---------------------------------------------------------------------------
# Recommendation generator — heuristic patterns only (LLM-driven is v1.1)
# ---------------------------------------------------------------------------


# Tunable: a prefix is "generalize-suggestable" once we've added this many
# distinct allows that share a stable prefix. 5 chosen so a few one-off
# allows don't trigger the suggestion but a real pattern does.
_GENERALIZE_PREFIX_THRESHOLD = 5

# Minimum prefix length so "s3:" / "ec2:" don't trigger noise.
_MIN_PREFIX_LEN = 4


def _extract_prefix(target: str) -> str | None:
    """Pull the stable prefix off an ARN target ending in ``*``.

    Examples:
      ``arn:aws:s3:::staging-cache-foo`` → ``arn:aws:s3:::staging-cache-``
      ``arn:aws:s3:::staging-cache-*``   → ``arn:aws:s3:::staging-cache-``
      ``arn:aws:s3:::data.json``         → None (no stable prefix)
    """
    if not target or not isinstance(target, str):
        return None
    t = target.rstrip("*")
    # Need at least one segment + a hyphen/underscore for it to look
    # like a pattern (not just an account-level ARN).
    if "-" not in t and "_" not in t:
        return None
    # Trim back to the last dash/underscore — that's the pattern stem.
    for sep in ("-", "_"):
        idx = t.rfind(sep)
        if idx >= _MIN_PREFIX_LEN:
            return t[: idx + 1]
    return None


def _scan_pending_for_patterns() -> list[str]:
    """Look at the pending-approval queue for prefix-generalize candidates.

    Returns 0..N "you've added N rules matching <prefix>* — generalize?"
    recommendation strings.
    """
    try:
        from ..profile_allow.operations import resolve_pending_path
    except Exception:
        return []
    try:
        p = resolve_pending_path()
    except Exception:
        return []
    if not p.exists():
        return []
    prefix_counts: dict[str, int] = {}
    try:
        with p.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue
                target = entry.get("target") if isinstance(entry, dict) else None
                if not isinstance(target, str):
                    continue
                prefix = _extract_prefix(target)
                if not prefix:
                    continue
                prefix_counts[prefix] = prefix_counts.get(prefix, 0) + 1
    except OSError:
        return []
    out: list[str] = []
    for prefix, n in sorted(prefix_counts.items(), key=lambda kv: -kv[1]):
        if n >= _GENERALIZE_PREFIX_THRESHOLD:
            out.append(
                f"You've added {n} pending allows matching {prefix}* — "
                f"want me to generalize to a single {prefix}* pattern? "
                f"Run `iam-jit profile allow --target '{prefix}*' "
                f"--action '<action>' --reason 'generalized from pending'`"
            )
    return out


def generate_recommendations(
    *,
    bouncers: dict[str, dict[str, Any]],
    window_days: float,
) -> list[str]:
    """Synthesize human-readable recommendations from the aggregated view.

    Heuristics ONLY pre-launch — LLM-driven recommendations are v1.1
    per the brief. Patterns surfaced today:

      1. Prefix-generalization: 5+ pending allows on the same prefix
         → "generalize to <prefix>*?".
      2. Adversarial-deny escalation: any bouncer with
         ``appears_adversarial > 0`` → "halt + escalate (do NOT
         auto-allow) — review when you're back" per
         ``[[ibounce-honest-positioning]]``.
      3. Quiet-bouncer suggestion: a bouncer with 0 denies over a week
         AND >0 audited requests → "consider tighter profile via
         `iam-jit improve-profile`".
      4. Idle bouncer: a bouncer with 0 audited requests AND 0 denies
         AND status != ``no_data`` → "no traffic observed — bouncer
         may not be in path".
    """
    recs: list[str] = []

    # 1. Pattern-generalization scan.
    recs.extend(_scan_pending_for_patterns())

    # 2 + 3 + 4. Per-bouncer signals.
    for name, b in bouncers.items():
        adv = (
            b.get("denies_by_classification", {}) or {}
        ).get("appears_adversarial", 0) or 0
        if adv > 0:
            recs.append(
                f"{name}: {int(adv)} deny(s) classified appears_adversarial "
                f"— halt + escalate. Run `iam-jit denies recent --since 1w` "
                f"for details before auto-allowing."
            )
        audited = int(b.get("total_requests_audited") or 0)
        denies = int(b.get("total_denies") or 0)
        if (
            window_days >= 6.5  # ~weekly window
            and audited > 0
            and denies == 0
        ):
            recs.append(
                f"{name} hasn't observed any denies in the window — "
                f"consider tightening the profile via "
                f"`iam-jit improve-profile --bouncer {name} --apply`."
            )
        if (
            b.get("status") not in ("no_data", "unreachable")
            and audited == 0
            and denies == 0
        ):
            recs.append(
                f"{name} is running but observed 0 requests in the window "
                f"— check that traffic is actually flowing through the "
                f"bouncer (proxy / SDK endpoint config)."
            )

    return recs


# ---------------------------------------------------------------------------
# Public builder
# ---------------------------------------------------------------------------


def build_digest(
    *,
    since: str = "1w",
    bouncer: str | None = None,
    fetch_denies_fn: Any = None,
    limit: int = 500,
    audit_events_token: str | None = None,
) -> DigestData:
    """Aggregate per-bouncer activity in the window into a :class:`DigestData`.

    Args:
      since: window short-form (``5m`` / ``1h`` / ``2d`` / ``1w``) OR ISO
        8601 lower bound. Default ``1w``.
      bouncer: restrict to a single bouncer name (one of ``ibounce`` /
        ``kbouncer`` / ``dbounce`` / ``gbounce``). ``None`` aggregates
        every bouncer the autopilot status file knows about.
      fetch_denies_fn: test hook — defaults to
        :func:`iam_jit.profile_allow.denies.fetch_recent_denies`.
      limit: max deny rows to fetch (per bouncer, NOT per-bouncer
        cumulative — the fetcher caps + returns the most recent).
      audit_events_token: bearer token for the per-bouncer
        ``/audit/events`` endpoints. When set, passed through to
        :func:`fetch_recent_denies`. When unset AND a bouncer responds
        401, a clear warning surfaces in :attr:`DigestData.warnings`
        per ``[[ibounce-honest-positioning]]`` §A56c — silently
        reporting "0 denies" on auth failure is the calibration-drift
        pattern this fix exists to prevent.

    Returns:
      A populated :class:`DigestData`. Errors during data fetch DO NOT
      raise (per ``[[ibounce-honest-positioning]]`` the digest must
      degrade gracefully) — they surface as ``notes`` entries.
    """
    from_iso, to_iso = parse_window(since)

    # Compute window duration in days (used by the recommendation engine
    # to decide whether a "quiet bouncer" suggestion fires).
    window_days: float
    try:
        from_dt = _parse_iso(from_iso)
        to_dt = _parse_iso(to_iso)
        window_days = (to_dt - from_dt).total_seconds() / 86400.0
    except Exception:
        window_days = 7.0  # safe default

    notes: list[str] = []

    # Load autopilot status — primary source of audited-count + improve
    # metadata + healthz blob.
    status = load_autopilot_status()
    if status is None:
        notes.append(
            "autopilot status file not found at "
            "~/.iam-jit/autopilot.status.json — counts may be "
            "incomplete. Start the autopilot to enable full digests: "
            "`iam-jit autopilot start --detach`"
        )
        status = {}

    autopilot_bouncers = status.get("bouncers") or {}
    if not isinstance(autopilot_bouncers, dict):
        autopilot_bouncers = {}

    improve_block = status.get("improve") or {}
    if not isinstance(improve_block, dict):
        improve_block = {}
    last_results = improve_block.get("last_results") or []
    if not isinstance(last_results, list):
        last_results = []

    # Determine the bouncer set to surface.
    if bouncer:
        bouncer_names: tuple[str, ...] = (bouncer,)
    else:
        # Union of (a) autopilot-known bouncers and (b) the default set.
        # Filter to bouncers that show up in autopilot OR have data later.
        seen = set(autopilot_bouncers.keys())
        if not seen:
            seen = set(_DEFAULT_BOUNCERS)
        bouncer_names = tuple(sorted(seen))

    # Fetch the deny rows in window. fetch_recent_denies is the same
    # cross-bouncer fan-out the `iam-jit denies recent` CLI uses.
    if fetch_denies_fn is None:
        try:
            from ..profile_allow.denies import fetch_recent_denies as _fn
            fetch_denies_fn = _fn
        except Exception as e:
            notes.append(f"deny fetcher unavailable: {e}")
            fetch_denies_fn = None

    deny_rows: list[Any] = []
    warnings: list[str] = []
    if fetch_denies_fn is not None:
        try:
            rows, fetch_notes = fetch_denies_fn(
                since=since,
                bouncer_names=bouncer_names if bouncer else None,
                limit=limit,
                audit_events_token=audit_events_token,
            )
            deny_rows = list(rows or [])
            for n in fetch_notes or []:
                notes.append(f"deny-fetch: {n}")
                # Per [[ibounce-honest-positioning]] §A56c: a 401 from a
                # bouncer's /audit/events endpoint means our deny count
                # for THAT bouncer is provably wrong (we got 0 because
                # we couldn't read, not because there were 0). Surface
                # as a structured WARNING the operator can branch on,
                # not a buried prose note.
                n_str = str(n)
                if "401" in n_str or "Unauthorized" in n_str.lower():
                    # Extract bouncer name — fetch notes look like
                    # "ibounce skipped (HTTP 401: ...)".
                    bname = n_str.split(" ", 1)[0] if " " in n_str else "bouncer"
                    if audit_events_token:
                        warnings.append(
                            f"{bname} returned 401 with the supplied "
                            f"--audit-events-token — token may be wrong / "
                            f"expired / for a different bouncer. Deny "
                            f"count for {bname} is INCOMPLETE."
                        )
                    else:
                        warnings.append(
                            f"{bname} returned 401; configure "
                            f"--audit-events-token or set "
                            f"IAM_JIT_AUDIT_EVENTS_TOKEN. Deny count "
                            f"for {bname} is INCOMPLETE (treat the "
                            f"reported zero as 'unknown', not 'clear')."
                        )
        except TypeError:
            # Backwards-compat: a custom fetch_denies_fn (e.g. a test
            # double) may not accept the new audit_events_token kwarg.
            # Retry without it so existing call sites + tests keep
            # working per [[v1-scope-bar]] additive-only constraint.
            try:
                rows, fetch_notes = fetch_denies_fn(
                    since=since,
                    bouncer_names=bouncer_names if bouncer else None,
                    limit=limit,
                )
                deny_rows = list(rows or [])
                for n in fetch_notes or []:
                    notes.append(f"deny-fetch: {n}")
            except Exception as e:
                notes.append(f"deny fetch raised: {e}")
        except Exception as e:
            notes.append(f"deny fetch raised: {e}")

    # Bucket deny rows per bouncer for the classification breakdown.
    by_bouncer_rows: dict[str, list[Any]] = {name: [] for name in bouncer_names}
    for row in deny_rows:
        b_name = getattr(row, "bouncer", None) or "unknown"
        if b_name not in by_bouncer_rows:
            # An unexpected bouncer name (alias, future bouncer) — add it.
            by_bouncer_rows[b_name] = []
        by_bouncer_rows[b_name].append(row)

    # Compute per-bouncer pending — the queue is global (no per-bouncer
    # split today), so we attribute it to ibounce specifically since
    # ibounce is the only bouncer that emits to it in Phase 1 per
    # iam_jit.profile_allow.denies.synth_suggested_allow_command.
    global_pending = fetch_pending_approval_count()

    bouncers_out: dict[str, dict[str, Any]] = {}
    for name in by_bouncer_rows.keys() | set(bouncer_names):
        block = _empty_bouncer_block()
        ap_block = autopilot_bouncers.get(name) or {}
        if ap_block:
            block["status"] = "ok" if ap_block.get("running") else "down"
            healthz = ap_block.get("healthz") or {}
            if isinstance(healthz, dict):
                block["total_requests_audited"] = int(
                    healthz.get("decisions_count") or 0
                )
        rows = by_bouncer_rows.get(name) or []
        block["total_denies"] = len(rows)
        block["denies_by_classification"] = _classify_deny_rows(rows)
        # Surface a per-deny-row noteworthy_events entry for the most
        # recent up-to-3 adversarial denies. Per
        # [[ibounce-honest-positioning]] we don't bury these in
        # friendly aggregate counts.
        for row in rows[:50]:
            try:
                from ..structured_deny import build_structured_deny
                sd = build_structured_deny(
                    bouncer=getattr(row, "bouncer", None) or name,
                    action=getattr(row, "action", "") or "",
                    resource=getattr(row, "resource", "") or "",
                    deny_reason=getattr(row, "deny_reason", "") or "",
                    deny_source=getattr(row, "deny_source", "") or "",
                    rule_id_if_dynamic=getattr(row, "rule_id_if_dynamic", None),
                    suggested_allow_command=getattr(
                        row, "suggested_allow_command", ""
                    ) or "",
                    agent_session_id=getattr(
                        row, "agent_session_id", ""
                    ) or "",
                    when=getattr(row, "when", "") or "",
                )
            except Exception:
                continue
            if sd.is_likely_injection_classification == "appears_adversarial":
                block["noteworthy_events"].append({
                    "when": sd.when or "",
                    "type": "deny_classified_adversarial",
                    "description": (
                        f"{sd.caught_by_bouncer} caught {sd.action or '(unknown)'} "
                        f"on {sd.resource or '(unknown)'} — classified "
                        f"appears_adversarial. Recommended: halt + escalate."
                    ),
                })
        # Per-bouncer improve summary — derive from last_results filtered
        # by bouncer name when present.
        own_results = [
            r for r in last_results
            if isinstance(r, dict) and (r.get("bouncer") == name)
        ]
        auto_installed, pending_count, noteworthy = _summarize_improve_results(
            own_results,
        )
        block["improve_cycles_run"] = len(own_results)
        block["improve_changes_auto_installed"] = auto_installed
        block["improve_changes_pending"] = pending_count
        block["noteworthy_events"].extend(noteworthy)
        if name == "ibounce":
            block["pending_approval_count"] = global_pending
        bouncers_out[name] = block

    # If a single-bouncer filter was applied, drop the others.
    if bouncer:
        bouncers_out = {bouncer: bouncers_out.get(bouncer, _empty_bouncer_block())}

    # Totals.
    totals = {
        "total_requests_audited": sum(
            int(b.get("total_requests_audited") or 0) for b in bouncers_out.values()
        ),
        "total_denies": sum(
            int(b.get("total_denies") or 0) for b in bouncers_out.values()
        ),
        "total_appears_legitimate": sum(
            int((b.get("denies_by_classification") or {}).get("appears_legitimate") or 0)
            for b in bouncers_out.values()
        ),
        "total_appears_adversarial": sum(
            int((b.get("denies_by_classification") or {}).get("appears_adversarial") or 0)
            for b in bouncers_out.values()
        ),
        "total_ambiguous": sum(
            int((b.get("denies_by_classification") or {}).get("ambiguous") or 0)
            for b in bouncers_out.values()
        ),
        "pending_approval_count": global_pending,
        "improve_cycles_run": sum(
            int(b.get("improve_cycles_run") or 0) for b in bouncers_out.values()
        ),
        "improve_changes_auto_installed": sum(
            int(b.get("improve_changes_auto_installed") or 0)
            for b in bouncers_out.values()
        ),
        "improve_changes_pending": sum(
            int(b.get("improve_changes_pending") or 0)
            for b in bouncers_out.values()
        ),
    }

    recommendations = generate_recommendations(
        bouncers=bouncers_out,
        window_days=window_days,
    )

    return DigestData(
        schema_version=SCHEMA_VERSION,
        time_window={"from": from_iso, "to": to_iso},
        bouncers=bouncers_out,
        totals=totals,
        recommendations=recommendations,
        notes=notes,
        warnings=warnings,
    )


# ---------------------------------------------------------------------------
# Local helper — ISO parse that tolerates the trailing 'Z'.
# ---------------------------------------------------------------------------


def _parse_iso(s: str) -> _dt.datetime:
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    return _dt.datetime.fromisoformat(s)
