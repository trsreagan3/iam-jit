"""Profile auto-naming helpers (issue #226).

Per the `feedback_profile_auto_naming` memo (2026-05-17) — any
profile-creation surface (`ibounce recommend --save-as-profile`,
`ibounce prompts answer --kind profile --target`, future agent-
driven profile creation) MUST make the NAME argument optional. If
unset + interactive TTY: prompt with a context-suggested default.
If unset + non-interactive: auto-generate from context (timestamp +
services + the originating action). Cross-product parity: same
convention on ibounce, kbounce, dbounce.

Mirrors kbounce's `SuggestProfileName` / `AvoidNameCollision` /
`ResolveProfileName` shape (kbounce commit cd0b1f7, file
`internal/cli/recommend.go`). Same name format, same suffix rules.

Constraints on auto-generated names (from the memo):
- Max 63 chars (K8s label limit; safe upper bound across all surfaces)
- Lowercase alphanumeric + hyphen only; no spaces, slashes, dots
- Date in ISO-8601 short form (YYYY-MM-DD) so chronological sort works
- Collision avoidance: if name exists, append -2, -3, etc.
"""

from __future__ import annotations

import datetime as _dt
import re
import sys
from collections.abc import Iterable
from typing import Any

import click

# Click's "optional value for flag" sentinel. When the user writes
# `--save-as-profile` (or `--target`) with NO value, Click substitutes
# this. When they write `--save-as-profile=NAME`, Click passes NAME.
# When they omit the flag entirely, Click passes None.
AUTO_NAME_SENTINEL = "__iam_jit_auto_name__"

# Profile-name label cap. Matches K8s label limit (kbounce uses the same)
# so a profile name fits in any cross-product context.
_MAX_NAME_LEN = 63

# Allowed chars for the auto-name slug. Mirrors kbounce's `sanitizeForName`.
_SLUG_BAD = re.compile(r"[^a-z0-9-]+")


# ---------------------------------------------------------------------------
# Slug helpers
# ---------------------------------------------------------------------------


def _slugify(s: str) -> str:
    """Lowercase + replace non-[a-z0-9-] with hyphens + collapse runs +
    strip leading/trailing hyphens. Mirrors kbounce's sanitizeForName."""
    s = (s or "").lower().strip()
    s = _SLUG_BAD.sub("-", s)
    s = re.sub(r"-{2,}", "-", s)
    s = s.strip("-")
    return s


def _clamp(s: str, n: int = _MAX_NAME_LEN) -> str:
    """Clamp to n chars; strip a trailing hyphen left behind by the
    cut (otherwise the name reads like a typo). Mirrors kbounce's
    `clampLabel`."""
    if len(s) <= n:
        return s
    return s[:n].rstrip("-")


def _today_utc() -> str:
    """ISO-8601 short-form date in UTC. Wrapped so tests can monkeypatch."""
    return _dt.datetime.now(_dt.timezone.utc).strftime("%Y-%m-%d")


# ---------------------------------------------------------------------------
# Context-aware suggesters (one per surface)
# ---------------------------------------------------------------------------


def suggest_profile_name_for_recommender(
    recs: list[Any] | None,
    summary: dict[str, Any] | None = None,
) -> str:
    """Auto-name shape for `recommend --save-as-profile`:

        auto-{YYYY-MM-DD}-{top-1-2-services}-{shape}

    The date prefers `summary["window_end"]` (the last observed call)
    so the name labels the captured window, not the moment of save.
    Falls back to today if the window has no events.

    Top services come from the recommendations' patterns (`s3:Get*` →
    `s3`), sorted by support DESC then service name ASC for
    determinism. We take up to 2 — beyond that the name becomes
    unreadable + close to the 63-char cap.

    Shape: "readonly" if every recommendation's pattern is in a
    read-shaped verb set (Get*/List*/Describe*/Head*), else "session".
    Audit-cadence note (c): the name uses SERVICE name only — never
    ARN values from observed decisions — so sensitive resource ids
    can't leak into a profile name an operator later shares.
    """
    summary = summary or {}
    recs = list(recs or [])

    date = _date_from_window_end(summary) or _today_utc()

    counts: dict[str, int] = {}
    for r in recs:
        svc = _service_of(r)
        if not svc or svc == "*":
            continue
        counts[svc] = counts.get(svc, 0) + _support_of(r)
    ranked = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))
    tops = [_slugify(svc) for svc, _c in ranked[:2] if _slugify(svc)]
    resource_part = "-".join(tops) or "mixed"

    shape = "readonly" if _all_recs_are_reads(recs) else "session"

    name = f"auto-{date}-{resource_part}-{shape}"
    return _clamp(_slugify(name))


def suggest_profile_name_for_prompts_answer(prompt: dict[str, Any]) -> str:
    """Auto-name shape for `prompts answer --kind profile --target`:

        auto-{YYYY-MM-DD}-prompt-{ID}-{service}-{action}

    Date = today (the prompt is being ANSWERED now; the answer is
    the event we're labeling, not the original prompt time).

    Service + action come straight from the pending-prompt row.
    Audit-cadence note (c): no ARN content, no headers, no body —
    only the (service, action) pair the audit-log already shows.
    """
    date = _today_utc()
    pid = prompt.get("id", "0")
    svc = _slugify(str(prompt.get("service") or "svc"))
    act = _slugify(str(prompt.get("action") or "act"))
    base = f"auto-{date}-prompt-{pid}-{svc}-{act}"
    return _clamp(_slugify(base))


# ---------------------------------------------------------------------------
# Resolution + collision-avoidance
# ---------------------------------------------------------------------------


def avoid_name_collision(name: str, taken: Iterable[str]) -> str:
    """Suffix `name` with -2, -3, ... until it's not in `taken`.

    Applied UNIVERSALLY — even an explicitly-typed name gets
    collision-avoided (audit-cadence (b)). Otherwise an operator who
    types a name that happens to clash with a prior profile would
    either overwrite-by-accident (data loss) or hit a confusing
    "name taken" error after the recommender has already done its
    work. Suffixing is the friendlier middle ground."""
    taken_set = set(taken)
    if name not in taken_set:
        return name
    for i in range(2, 1000):
        candidate = f"{name}-{i}"
        if candidate not in taken_set:
            return candidate
    raise ValueError(
        f"profile auto-naming: too many collisions on {name!r} "
        f"(tried -2 through -999); pick a name explicitly."
    )


def _is_interactive() -> bool:
    """TTY-detect for resolve_profile_name. We require BOTH stdout AND
    stdin to be a TTY before prompting (audit-cadence (a)):

    - stdout-only TTY (e.g. running under `tee log.txt`) means the
      prompt would print but `input()` would block waiting for a
      stdin no human is typing into.
    - stdin-only TTY (e.g. piped into a logger) means the prompt
      itself would land in the pipe, not in front of a human.

    Only when BOTH are TTYs is there a human at both ends; in every
    other case the non-TTY auto-gen branch is correct."""
    try:
        return sys.stdout.isatty() and sys.stdin.isatty()
    except Exception:
        return False


def resolve_profile_name(
    explicit: str | None,
    suggested: str,
    *,
    taken: Iterable[str] = (),
    is_interactive: callable | None = None,
    input_fn: callable = input,
) -> str:
    """Three-step resolution per the auto-naming memo + kbounce parity:

      1. explicit arg present + not the sentinel → use it (collision-avoid)
      2. TTY (stdout + stdin) → prompt with `suggested` default
      3. non-TTY → use `suggested` + print to stderr

    Returns a collision-avoided name guaranteed not to clash with
    `taken`. Side effect: prints the chosen name to stderr in the
    non-TTY branch so the operator can see it post-hoc (per the
    memo's "Don't auto-name without printing the chosen name" rule).

    Test seams: `is_interactive` + `input_fn` are injectable so tests
    can simulate both branches without touching real TTY state.
    """
    is_tty = (is_interactive or _is_interactive)()

    if explicit and explicit != AUTO_NAME_SENTINEL:
        chosen = explicit
    elif is_tty:
        try:
            raw = input_fn(
                f"name your profile [default: {suggested}]: "
            )
        except EOFError:
            raw = ""
        chosen = (raw or "").strip() or suggested
    else:
        chosen = suggested
        click.echo(
            f"ibounce: using auto-generated profile name: {chosen}",
            err=True,
        )

    return avoid_name_collision(chosen, taken)


# ---------------------------------------------------------------------------
# internals
# ---------------------------------------------------------------------------


def _service_of(rec: Any) -> str | None:
    """Extract the service token (`s3` in `s3:GetObject`) from a
    RuleRecommendation-like object. Tolerates plain dicts so the MCP
    tool surface can call us without instantiating the dataclass."""
    pr = getattr(rec, "proposed_rule", None) or (
        rec.get("proposed_rule") if isinstance(rec, dict) else None
    )
    if pr is None:
        return None
    pat = getattr(pr, "pattern", None) or (
        pr.get("pattern") if isinstance(pr, dict) else None
    )
    if not pat or ":" not in pat:
        return None
    return pat.split(":", 1)[0]


def _support_of(rec: Any) -> int:
    """Recommendation support count; defaults to 1 so a recommendation
    without an explicit count still contributes to ranking."""
    n = getattr(rec, "support_count", None)
    if n is None and isinstance(rec, dict):
        n = rec.get("support_count")
    try:
        return int(n) if n is not None else 1
    except (TypeError, ValueError):
        return 1


_READ_VERB_PREFIXES = ("get", "list", "describe", "head", "batchget", "scan")


def _all_recs_are_reads(recs: list[Any]) -> bool:
    """True iff every recommendation's action looks read-shaped. Used
    for the `-readonly` vs `-session` suffix. Conservative: empty
    list → False (no signal → don't claim readonly)."""
    if not recs:
        return False
    for r in recs:
        pr = getattr(r, "proposed_rule", None) or (
            r.get("proposed_rule") if isinstance(r, dict) else None
        )
        if pr is None:
            return False
        pat = getattr(pr, "pattern", None) or (
            pr.get("pattern") if isinstance(pr, dict) else None
        )
        if not pat or ":" not in pat:
            return False
        action = pat.split(":", 1)[1].lower()
        if not any(action.startswith(p) for p in _READ_VERB_PREFIXES):
            return False
    return True


def _date_from_window_end(summary: dict[str, Any]) -> str | None:
    """Pull the YYYY-MM-DD prefix off summary['window_end'] (an ISO
    timestamp). Returns None on any parse failure — caller falls
    back to today."""
    raw = summary.get("window_end") if summary else None
    if not raw or not isinstance(raw, str):
        return None
    # window_end is "YYYY-MM-DDTHH:MM:SSZ" or similar. We only want
    # the date prefix; parsing the rest is risk we don't need.
    m = re.match(r"^(\d{4}-\d{2}-\d{2})", raw)
    return m.group(1) if m else None
