"""#271 — `iam-jit audit query` cross-bouncer audit-query CLI.

Composes on top of #268 (per-product `audit tail` with filters) +
#271 A (per-bouncer GET /audit/events HTTP endpoint) by giving the
operator ONE command that queries multiple bouncers at once:

    iam-jit audit query [--bouncer ibounce,kbounce,dbounce,gbounce]
                        [--since ISO8601] [--until ISO8601]
                        [--filter EXPR ...]
                        [--limit N]
                        [--format jsonl|ocsf-bundle|csv|summary]
                        [--audit-events-token TOKEN]

Default behavior:

  * Probe localhost for all 4 bouncers' management ports (skip
    unreachable ones with a stderr note)
  * Query each reachable bouncer's `/audit/events` in parallel
  * Merge results, sort by timestamp
  * Apply the requested format

Per ``[[cross-product-agent-parity]]`` every Bounce-suite product
ships the same `/audit/events` endpoint shape, so this CLI is product-
agnostic — adding a new bouncer to the suite is one entry in the
DEFAULT_BOUNCERS dict.

Per ``[[creates-never-mutates]]`` read-only.
Per ``[[self-host-zero-billing-dependency]]`` no phone-home; the CLI
only ever talks to operator-controlled localhost mgmt ports.
Per ``[[security-team-positioning-safety-not-surveillance]]`` the
user-facing strings stay in neutral framing (no surveillance-vocab
language; the audit-query surface is for "events selected for
review", not blame-assigning incident framing).
"""

from __future__ import annotations

import csv as _csv
import datetime as _dt
import io
import json
import os as _os
import re as _re
import sys
import time as _time
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, NamedTuple
from urllib import parse as _urlparse
from urllib import request as _urlrequest
from urllib.error import HTTPError, URLError

import click


# #436 / §A70 — long-range audit-query support.
# Windows >= LONG_RANGE_WARN_DAYS surface a stderr warning so the
# operator knows a cold-tier query may be slow + costly. The threshold
# tracks the boundary where typical hot/warm storage gives way to
# cold-tier object storage (S3 + #428 retention tiering); a smaller
# default keeps the warning honest for operators who haven't yet
# wired #428.
LONG_RANGE_WARN_DAYS = 90

# Maximum lookback `_parse_since_long_range` will honor before
# clamping. Years-back queries are intentional; we just refuse
# nonsense like "100y" so accidental typos don't cascade into
# absurd cold-tier scans.
LONG_RANGE_MAX_YEARS = 10


_LONG_RANGE_TOKEN_RE = _re.compile(r"^(\d+)([smhdwMy])$")
"""Short-form duration tokens accepted by --since/--until on the
long-range path. Calendar units (`y`, `M`) are added on top of the
existing s/m/h/d/w set so operators can write `--since 2y` directly
instead of `--since 730d`."""

_VALID_SINCE_UNITS = frozenset("smhdwMy")


def _validate_since_spec(spec: str | None, flag: str = "--since") -> None:
    """#628 — pre-fan-out gate for ``--since`` / ``--until`` values.

    Raises :class:`click.UsageError` (exit 2) when ``spec`` is non-empty
    AND doesn't look like:

      * a short/long-form duration token: ``5m`` / ``1h`` / ``2d`` /
        ``90d`` / ``6M`` / ``2y`` (units: s/m/h/d/w/M/y)
      * an ISO 8601 / RFC 3339 timestamp: ``2026-05-25T10:00:00Z``

    Per [[ibounce-honest-positioning]]: an invalid ``--since`` that
    passes through to the fan-out causes every bouncer to return HTTP 400;
    the CLI previously tucked those into "skipped" notes and exited 0,
    silently claiming "no events found". That is a lie. This gate turns
    the lie into an honest exit 2 before a single network call is made.

    Mirrors the pattern from ``cli_profile_allow.py:676`` (#606 Gap A /
    #623 Gap B) so the validate-then-fan-out discipline is consistent
    across every CLI that fans out to bouncers.
    """
    if not spec:
        return
    s = spec.strip()
    if not s:
        return
    # Short/long-form duration: <digits><unit>
    if _LONG_RANGE_TOKEN_RE.match(s):
        return
    # ISO 8601 / RFC 3339 shape: contains 'T' OR starts with a date
    # (YYYY-MM-DD prefix). Actually parse it — pure heuristic match
    # was the pre-#606 gap that let junk like "2026-bad" slip through.
    if "T" in s or "-" in s[:10]:
        norm = s
        if norm.endswith("Z"):
            norm = norm[:-1] + "+00:00"
        try:
            _dt.datetime.fromisoformat(norm)
            return
        except ValueError:
            pass  # fall through to the error below
    valid_units = "/".join(sorted(_VALID_SINCE_UNITS))
    raise click.UsageError(
        f"{flag} {spec!r} is not a valid duration or timestamp.\n"
        f"  Duration examples: 5m, 1h, 2d, 90d, 6M, 2y  (units: {valid_units})\n"
        f"  Timestamp example: 2026-05-25T10:00:00Z  (ISO 8601 / RFC 3339)\n"
        f"  Fix {flag} and re-run."
    )


def _parse_since_long_range(spec: str | None) -> str | None:
    """Convert a long-form `--since` shorthand (`2y`, `6M`, `90d`,
    etc.) to an ISO 8601 UTC lower bound.

    Pass-through for already-ISO strings and for empty / None values
    so callers can mix shorthand + explicit timestamps freely.

    Years use a 365-day approximation (calendar-month-boundary
    accuracy isn't load-bearing for an audit-query lookback bound);
    Months use 30 days.
    """
    if not spec:
        return None
    s = spec.strip()
    if not s:
        return None
    # ISO-ish strings pass straight through; the bouncer parses them.
    if "T" in s or "-" in s[:10]:
        return s
    m = _LONG_RANGE_TOKEN_RE.match(s)
    if not m:
        # Unknown shape — let the bouncer reject it rather than guess.
        return s
    qty = int(m.group(1))
    unit = m.group(2)
    if qty < 0:
        return s
    seconds_by_unit = {
        "s": 1,
        "m": 60,
        "h": 3600,
        "d": 86400,
        "w": 7 * 86400,
        "M": 30 * 86400,
        "y": 365 * 86400,
    }
    delta_seconds = qty * seconds_by_unit[unit]
    # Cap absurd values per LONG_RANGE_MAX_YEARS.
    max_seconds = LONG_RANGE_MAX_YEARS * 365 * 86400
    if delta_seconds > max_seconds:
        delta_seconds = max_seconds
    lower = (
        _dt.datetime.now(_dt.timezone.utc)
        - _dt.timedelta(seconds=delta_seconds)
    )
    return lower.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _since_window_days(spec: str | None) -> float | None:
    """Best-effort: parse `--since` into an approximate "how many days
    back" used for the cold-tier warning threshold. Returns None when
    the shorthand can't be reduced to a numeric window.

    Accepts both short-form tokens (`2y`, `90d`) and ISO 8601
    timestamps (the latter parsed with datetime).
    """
    if not spec:
        return None
    s = spec.strip()
    if not s:
        return None
    m = _LONG_RANGE_TOKEN_RE.match(s)
    if m:
        qty = int(m.group(1))
        unit = m.group(2)
        seconds_by_unit = {
            "s": 1, "m": 60, "h": 3600, "d": 86400,
            "w": 7 * 86400, "M": 30 * 86400, "y": 365 * 86400,
        }
        return qty * seconds_by_unit[unit] / 86400.0
    # Fall back to ISO parse.
    try:
        # Tolerate trailing Z.
        cleaned = s.replace("Z", "+00:00") if s.endswith("Z") else s
        parsed = _dt.datetime.fromisoformat(cleaned)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=_dt.timezone.utc)
        delta = _dt.datetime.now(_dt.timezone.utc) - parsed
        return max(delta.total_seconds() / 86400.0, 0.0)
    except (ValueError, TypeError):
        return None


def _parse_scope_filter(raw: str | None) -> dict[str, list[str]] | None:
    """Parse a JSON-encoded scope-filter classifier into the dict
    shape the deployment-target taxonomy emits.

    Accepts the exact wire shape produced by `iam-jit
    deployment-targets show <NAME> --classifier-only` so an agent can
    pipe between the two commands without re-serialising.
    """
    if raw is None:
        return None
    s = raw.strip()
    if not s:
        return None
    try:
        parsed = json.loads(s)
    except json.JSONDecodeError as e:
        raise click.BadParameter(
            f"--scope-filter must be JSON (e.g. "
            f'\'{{"clusters":["prod-*"]}}\'); got: {e}',
        ) from e
    if not isinstance(parsed, dict):
        raise click.BadParameter(
            "--scope-filter must be a JSON object mapping dimension "
            "names (clusters/accounts/regions/namespaces/hosts/"
            "databases) to lists of strings.",
        )
    out: dict[str, list[str]] = {}
    for k, v in parsed.items():
        if not isinstance(v, list) or not all(
            isinstance(x, str) for x in v
        ):
            raise click.BadParameter(
                f"--scope-filter dimension {k!r} must be a list of "
                "strings.",
            )
        out[str(k)] = list(v)
    return out


class BouncerEndpoint(NamedTuple):
    """One configured bouncer probe target."""

    name: str
    """The bouncer's short name (e.g. ``ibounce``)."""

    mgmt_url: str
    """The base URL of the bouncer's management port (no trailing
    slash). ``/audit/events`` is appended at query time."""


DEFAULT_BOUNCERS: dict[str, BouncerEndpoint] = {
    "ibounce": BouncerEndpoint(name="ibounce", mgmt_url="http://127.0.0.1:8767"),
    "kbounce": BouncerEndpoint(name="kbounce", mgmt_url="http://127.0.0.1:8766"),
    "dbounce": BouncerEndpoint(name="dbounce", mgmt_url="http://127.0.0.1:8768"),
    "gbounce": BouncerEndpoint(name="gbounce", mgmt_url="http://127.0.0.1:8769"),
}
"""Default-probe set per ``[[cross-product-agent-parity]]``: every
Bounce-suite product ships a known mgmt port.

  * ibounce — 8767 (legacy iam-jit-bouncer port)
  * kbounce — 8766
  * dbounce — 8768
  * gbounce — 8769 (mgmt; proxy on 8080)

Operators with non-default ports pass ``--bouncer
name=http://host:port`` to override one entry."""


# #620 — iam-jit serve is the FIFTH surface in the fan-out.  Per
# ``[[cross-product-agent-parity]]`` it ships the same /audit/events
# wire shape so the fan-out + merge layer treats it identically to
# the four bouncers.  Its audit log (cap-fire events from #613, admin
# actions per UAT-Web-Admin-06, context-change events, etc.) was
# unreachable from the cross-product query before this; the literal
# recipe in docs/recipes/OUTSTANDING-REQUEST-CAP.md
# (`iam-jit audit query --kind request_cap_exceeded --since 1h`)
# returned 0 events even after the cap fired.  This entry closes
# that doc-lie surface.
IAM_JIT_SERVE_DEFAULT_URL = "http://127.0.0.1:8000"
"""Default iam-jit serve URL when ``IAM_JIT_URL`` is unset.  Matches
the default uvicorn port used by ``iam-jit serve``."""


def _resolve_serve_endpoint() -> BouncerEndpoint:
    """Build the iam-jit serve endpoint for the cross-product fan-out.

    The URL comes from ``IAM_JIT_URL`` (the same env var
    ``cli_remote.py`` and ``mcp_server.py`` already read), falling
    back to the local-dev default.  Operators who run iam-jit serve
    on a non-default host/port set ``IAM_JIT_URL`` and the fan-out
    follows.
    """
    url = (_os.environ.get("IAM_JIT_URL") or IAM_JIT_SERVE_DEFAULT_URL).rstrip("/")
    return BouncerEndpoint(name="iam-jit-serve", mgmt_url=url)


# Module-level so tests can monkeypatch — gives a hook to swap out the
# real urlopen for a mock without threading kwargs everywhere.
_urlopen = _urlrequest.urlopen
_DEFAULT_TIMEOUT_SECONDS = 5.0
"""Per-bouncer HTTP request timeout. 5s is long enough for the slow-
network case (a remote bouncer over a VPN, say) and short enough that
one unreachable bouncer doesn't pin the cross-bouncer query."""


# #320 / §A18 — short-form filter alias map. UAT 2026-05-22 surfaced
# that the headline cross-bouncer query example uses the short form
# `agent.session_id=X` (copy-pasted from the IAM-JIT-AUDIT-QUERY.md
# spec) but the per-bouncer parsers only accept the canonical long
# form `unmapped.iam_jit.agent.session_id=X` — every copy-paste
# returned HTTP 400. The fix is to expand short forms to their
# canonical long forms CLIENT-SIDE before forwarding so each bouncer
# still sees a fully-qualified field path. Documented in CLI help +
# docs/INTEGRATION-OPENCLAW-NANOCLAW.md.
#
# Per [[cross-product-agent-parity]] the canonical fields are the
# same across all four bouncers — the short-form alias map is one
# shared catalog. Future short-forms (verdict, severity, etc.) land
# here.
_SHORT_FORM_ALIASES: dict[str, str] = {
    "agent.session_id": "unmapped.iam_jit.agent.session_id",
    "agent.name": "unmapped.iam_jit.agent.name",
    "agent.detected_from": "unmapped.iam_jit.agent.detected_from",
}


def _expand_short_form_filter(expr: str) -> str:
    """Expand a short-form filter expression to its canonical OCSF
    long form. Pass-through for anything that doesn't match a known
    short-form prefix — preserves the existing exact-match behavior
    for callers that already pass the canonical path.

    Supports the four filter operators the per-bouncer parsers
    accept: `=`, `~`, `>=`, `<=`. The split is on the FIRST operator
    occurrence so a value containing `=` (e.g. base64) round-trips
    correctly.

    Examples:
        agent.session_id=01968d6a-...     → unmapped.iam_jit.agent.session_id=01968d6a-...
        agent.name~claude                  → unmapped.iam_jit.agent.name~claude
        unmapped.iam_jit.agent.name=psql  → unmapped.iam_jit.agent.name=psql   (no change)
        api.service.name=mysql             → api.service.name=mysql             (no change)
    """
    # Order matters: `>=` and `<=` are 2-char operators; split on them
    # first so the single-char `=` / `~` don't false-match.
    for op in (">=", "<=", "=", "~"):
        idx = expr.find(op)
        if idx <= 0:
            continue
        field = expr[:idx]
        rest = expr[idx:]
        canonical = _SHORT_FORM_ALIASES.get(field)
        if canonical is None:
            return expr
        return canonical + rest
    return expr


def _expand_short_form_filters(filters: tuple[str, ...]) -> tuple[str, ...]:
    """Apply _expand_short_form_filter to every entry in a tuple of
    filter expressions. Tuple-in / tuple-out so the call site can
    swap the click multi-option output directly."""
    return tuple(_expand_short_form_filter(f) for f in filters)


class _BouncerQueryResult(NamedTuple):
    """One bouncer's result of the parallel fan-out. Either ``events``
    is populated (success) or ``error`` is non-empty (probe-failed /
    HTTP-failed / parse-failed)."""

    bouncer: str
    events: list[dict[str, Any]]
    error: str


def _query_one_bouncer(
    endpoint: BouncerEndpoint,
    *,
    since: str | None,
    until: str | None,
    filters: tuple[str, ...],
    limit: int,
    bearer_token: str | None,
    timeout: float = _DEFAULT_TIMEOUT_SECONDS,
) -> _BouncerQueryResult:
    """Run one GET /audit/events against one bouncer + return its
    events. Translates each bouncer's NDJSON response into a
    ``[dict, ...]``. The OCSF wire shape is identical across bouncers
    per ``[[cross-product-agent-parity]]`` so the merge layer treats
    them uniformly."""
    query_params: list[tuple[str, str]] = [("limit", str(limit))]
    if since:
        query_params.append(("since", since))
    if until:
        query_params.append(("until", until))
    for f in filters:
        query_params.append(("filter", f))
    qs = _urlparse.urlencode(query_params)
    url = f"{endpoint.mgmt_url}/audit/events?{qs}"

    headers = {}
    if bearer_token:
        headers["Authorization"] = f"Bearer {bearer_token}"

    req = _urlrequest.Request(url, headers=headers)
    try:
        with _urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except HTTPError as e:
        try:
            err_body = e.read().decode("utf-8", errors="replace")
            err_msg = json.loads(err_body).get("error") or err_body
        except Exception:
            err_msg = str(e)
        return _BouncerQueryResult(
            bouncer=endpoint.name, events=[],
            error=f"HTTP {e.code}: {err_msg}",
        )
    except URLError as e:
        return _BouncerQueryResult(
            bouncer=endpoint.name, events=[],
            error=f"unreachable: {e.reason}",
        )
    except Exception as e:  # pragma: no cover — defensive
        return _BouncerQueryResult(
            bouncer=endpoint.name, events=[],
            error=f"{type(e).__name__}: {e}",
        )

    events: list[dict[str, Any]] = []
    for line in body.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError as e:
            return _BouncerQueryResult(
                bouncer=endpoint.name, events=[],
                error=f"NDJSON parse: {e}",
            )
        # Stamp the source bouncer so cross-product correlation later
        # can group by bouncer without re-walking metadata.product.name.
        ev.setdefault("_bouncer", endpoint.name)
        events.append(ev)
    return _BouncerQueryResult(
        bouncer=endpoint.name, events=events, error="",
    )


def _glob_to_pattern(glob: str) -> _re.Pattern[str]:
    """Compile a simple ``*``-glob into a regex used by the scope-
    filter classifier. Cached at module level so a long-range query
    over thousands of events doesn't re-compile per match."""
    parts: list[str] = ["^"]
    for ch in glob:
        if ch == "*":
            parts.append(".*")
        else:
            parts.append(_re.escape(ch))
    parts.append("$")
    return _re.compile("".join(parts))


_GLOB_CACHE: dict[str, _re.Pattern[str]] = {}


def _glob_match(value: str, glob: str) -> bool:
    """Glob match with module-local cache; treats `*` as the only
    wildcard (other regex meta-chars are escaped)."""
    if "*" not in glob:
        return value == glob
    pat = _GLOB_CACHE.get(glob)
    if pat is None:
        pat = _glob_to_pattern(glob)
        _GLOB_CACHE[glob] = pat
    return pat.match(value) is not None


def _event_field(ev: dict[str, Any], path: str) -> Any:
    """Walk a dotted path through nested dicts; None on missing."""
    cur: Any = ev
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
        if cur is None:
            return None
    return cur


# Map from classifier dimension → OCSF field-paths to check. An event
# matches a classifier value when ANY of the listed paths' values
# matches the glob. This is intentionally lenient: bouncers vary in
# WHICH OCSF path they populate (e.g. kbouncer puts the cluster in
# `unmapped.iam_jit.cluster`; ibounce puts the account in
# `cloud.account.uid`). The fan-out is the same dimension-name set
# every bouncer accepts via the deployment-target taxonomy.
_CLASSIFIER_FIELD_PATHS: dict[str, tuple[str, ...]] = {
    "clusters": (
        "unmapped.iam_jit.cluster",
        "cloud.zone",
    ),
    "accounts": (
        "cloud.account.uid",
        "unmapped.iam_jit.account_id",
    ),
    "regions": (
        "cloud.region",
        "unmapped.iam_jit.region",
    ),
    "namespaces": (
        "unmapped.iam_jit.namespace",
        "resources.0.namespace",
    ),
    "hosts": (
        "dst_endpoint.hostname",
        "unmapped.iam_jit.host",
    ),
    "databases": (
        "unmapped.iam_jit.database",
        "dst_endpoint.svc_name",
    ),
}


def _event_matches_classifier(
    ev: dict[str, Any],
    classifier: dict[str, list[str]],
) -> bool:
    """Return True iff the event matches EVERY declared dimension.

    Each dimension's globs are OR'd; dimensions are AND'd. An empty
    classifier matches everything (so callers can disable filtering by
    passing `{}`). A dimension whose value list is empty also matches
    — we treat "the operator declared zero globs" as "no filter for
    this dimension" rather than "match nothing".
    """
    if not classifier:
        return True
    for dim, globs in classifier.items():
        if not globs:
            continue
        paths = _CLASSIFIER_FIELD_PATHS.get(dim, ())
        if not paths:
            # Unknown dimension — skip (forward-compat with future
            # schema additions).
            continue
        found_match = False
        for path in paths:
            value = _event_field(ev, path)
            if value is None:
                continue
            if not isinstance(value, str):
                value = str(value)
            for g in globs:
                if _glob_match(value, g):
                    found_match = True
                    break
            if found_match:
                break
        if not found_match:
            return False
    return True


def _event_time_key(ev: dict[str, Any]) -> int:
    """Sort key: OCSF ``time`` (Unix ms). Missing or non-numeric
    sorts to 0 so a malformed event still appears in the merged
    stream rather than crashing the sort."""
    t = ev.get("time")
    if isinstance(t, int):
        return t
    if isinstance(t, float):
        return int(t)
    if isinstance(t, str):
        try:
            return int(float(t))
        except ValueError:
            return 0
    return 0


def _format_summary(results: list[_BouncerQueryResult]) -> str:
    """Per-bouncer + total counts. Stable order matches the
    DEFAULT_BOUNCERS dict + suite naming order."""
    lines = []
    total = 0
    for r in results:
        if r.error:
            lines.append(f"{r.bouncer}: (unreachable: {r.error})")
            continue
        lines.append(f"{r.bouncer}: {len(r.events)} events")
        total += len(r.events)
    lines.append(f"total: {total} events")
    return "\n".join(lines) + "\n"


# OCSF Detection Finding constants for the cross-bouncer bundle.
_DETECTION_FINDING_CLASS_UID = 2004
_DETECTION_FINDING_CLASS_NAME = "Detection Finding"
_DETECTION_FINDING_CATEGORY_UID = 2
_DETECTION_FINDING_CATEGORY_NAME = "Findings"


def _format_ocsf_bundle(events: list[dict[str, Any]]) -> str:
    """Wrap all events from all bouncers in ONE Detection Finding so
    a SIEM batch import sees the cross-product correlation as a single
    artifact. Useful for #273 investigate-with-claude — the bundle is
    the single file the operator drops into their Claude client."""
    now_ms = int(_time.time() * 1000)
    bouncers = sorted({ev.get("_bouncer", "unknown") for ev in events})
    bundle = {
        "metadata": {
            "version": "1.1.0",
            "product": {
                "name": "iam-jit audit query",
                "vendor_name": "iam-jit",
            },
        },
        "time": now_ms,
        "class_uid": _DETECTION_FINDING_CLASS_UID,
        "class_name": _DETECTION_FINDING_CLASS_NAME,
        "category_uid": _DETECTION_FINDING_CATEGORY_UID,
        "category_name": _DETECTION_FINDING_CATEGORY_NAME,
        "activity_id": 1,
        "activity_name": "Create",
        "type_uid": _DETECTION_FINDING_CLASS_UID * 100 + 1,
        "type_name": f"{_DETECTION_FINDING_CLASS_NAME}: Create",
        "severity_id": 1,
        "severity": "Informational",
        "status_id": 1,
        "status": "Success",
        "message": (
            f"Cross-bouncer audit query: {len(events)} event(s) "
            f"from {len(bouncers)} bouncer(s) "
            f"({', '.join(bouncers) or 'none'})"
        ),
        "finding": {
            "uid": f"iam-jit-audit-query-{now_ms}",
            "title": "iam-jit cross-bouncer audit query",
            "types": ["cross-bouncer-correlation"],
            "evidence": {
                "events": events,
                "bouncers": bouncers,
            },
        },
        "unmapped": {
            "iam_jit": {
                "event_type": "AUDIT_QUERY_BUNDLE",
                "bundle_count": len(events),
                "bouncers": bouncers,
            },
        },
    }
    return json.dumps(bundle, indent=2) + "\n"


# CSV column order. Matches the default cross-product set per the
# kbounce/dbounce/gbounce CSV-export conventions; adds `bouncer` as
# the first column so a cross-product CSV is immediately groupable.
_DEFAULT_CSV_COLUMNS = (
    "bouncer",
    "time",
    "severity_id",
    "activity_name",
    "actor.user.name",
    "api.operation",
    "verdict",
)


def _csv_cell(ev: dict[str, Any], col: str) -> str:
    """Project one OCSF event field for the CSV exporter. Special-cases
    the `bouncer` column (sourced from the synthetic ``_bouncer`` field
    stamped at query time) and the convenience aliases
    (``verdict`` -> ``unmapped.iam_jit.verdict``)."""
    if col == "bouncer":
        return str(ev.get("_bouncer") or "")
    if col == "verdict":
        ext = (
            ev.get("unmapped", {}).get("iam_jit", {}).get("verdict")
        )
        return str(ext or "")
    cur: Any = ev
    for part in col.split("."):
        if not isinstance(cur, dict):
            return ""
        cur = cur.get(part)
        if cur is None:
            return ""
    return str(cur)


def _format_csv(events: list[dict[str, Any]]) -> str:
    """Emit RFC 4180 CSV with the default column order."""
    buf = io.StringIO()
    w = _csv.writer(buf)
    w.writerow(_DEFAULT_CSV_COLUMNS)
    for ev in events:
        w.writerow([_csv_cell(ev, c) for c in _DEFAULT_CSV_COLUMNS])
    return buf.getvalue()


def _format_jsonl(events: list[dict[str, Any]]) -> str:
    """Emit one JSON-encoded event per line. Default format."""
    return "".join(
        json.dumps(ev, default=str, separators=(",", ":")) + "\n"
        for ev in events
    )


def _parse_bouncer_override(raw: str) -> BouncerEndpoint:
    """Parse a `--bouncer name=URL` override into a BouncerEndpoint.

    Two forms accepted:

      * ``ibounce``                → use DEFAULT_BOUNCERS["ibounce"]
      * ``ibounce=http://host:N`` → use the given URL

    Unknown name forms (e.g. ``mybounce=...``) are accepted too — the
    CLI is product-agnostic; the name is just a label in the summary.
    """
    if "=" in raw:
        name, url = raw.split("=", 1)
        name = name.strip()
        url = url.strip().rstrip("/")
        if not name or not url:
            raise click.BadParameter(
                f"--bouncer {raw!r}: expected name=URL with non-empty parts",
            )
        return BouncerEndpoint(name=name, mgmt_url=url)
    name = raw.strip()
    if name in DEFAULT_BOUNCERS:
        return DEFAULT_BOUNCERS[name]
    raise click.BadParameter(
        f"--bouncer {raw!r}: unknown bouncer name; "
        f"use one of {sorted(DEFAULT_BOUNCERS)} or pass name=URL explicitly",
    )


def _resolve_bouncer_set(
    raw: tuple[str, ...] | None,
    *,
    include_serve: bool = True,
) -> list[BouncerEndpoint]:
    """Resolve the operator's ``--bouncer`` flags into the probe set.
    Empty input = probe all four DEFAULT_BOUNCERS PLUS the iam-jit
    serve endpoint (#620).

    ``include_serve=False`` is the test-only escape hatch — the
    standard CLI path keeps serve in the probe set unconditionally.
    Per ``[[ibounce-honest-positioning]]`` if serve isn't running
    the fan-out surfaces it as an "unreachable" note rather than
    silently excluding the surface.
    """
    if not raw:
        out_default: list[BouncerEndpoint] = list(DEFAULT_BOUNCERS.values())
        if include_serve:
            out_default.append(_resolve_serve_endpoint())
        return out_default
    out: list[BouncerEndpoint] = []
    for one in raw:
        # Allow comma-separated within one flag value:
        # `--bouncer ibounce,kbounce`.
        for part in one.split(","):
            part = part.strip()
            if not part:
                continue
            out.append(_parse_bouncer_override(part))
    return out


def register_audit_query_group(parent_group: click.Group) -> click.Group:
    """Register the `audit` subcommand-group on the iam-jit CLI.

    Called from :func:`iam_jit.cli.main` at import time so the existing
    ``iam-jit`` CLI surfaces ``iam-jit audit query`` without disturbing
    the existing top-level commands.

    Returns the newly-registered ``audit`` Click group so callers
    (e.g. ``register_audit_stream_command`` from #272) can hang
    additional subcommands off it without re-declaring the parent
    group.
    """

    @parent_group.group("audit")
    def audit_group() -> None:
        """Cross-bouncer audit queries + live streaming (#271, #272).

        Composes per-bouncer GET /audit/events endpoints into one
        merged + sorted stream. See :doc:`docs/IAM-JIT-AUDIT-QUERY.md`
        and :doc:`docs/AUDIT-STREAM-TUI.md` for the full guides.
        """

    @audit_group.command("query")
    @click.option(
        "--bouncer", "bouncers_raw",
        multiple=True,
        help="Which bouncer(s) to query. Repeatable; comma-separated "
             "also accepted. Default: probe all four default bouncers "
             "on their standard mgmt ports (ibounce 8767, kbounce 8766, "
             "dbounce 8768, gbounce 8769). Override one entry with "
             "`name=URL` (e.g. `kbounce=http://10.0.0.5:8766`).",
    )
    @click.option(
        "--since",
        default=None,
        help="ISO 8601 / RFC 3339 lower time bound. Forwarded to each "
             "bouncer verbatim. Example: `--since 2026-05-18T00:00:00Z`. "
             "Also accepts short-form tokens (`2y`, `6M`, `30d`, `24h`, "
             "`60m`, `30s`) — years use a 365-day approximation + months "
             "use 30-day (not calendar-boundary). (#498)",
    )
    @click.option(
        "--until",
        default=None,
        help="ISO 8601 / RFC 3339 upper time bound. Forwarded to each "
             "bouncer verbatim. Example: `--until 2026-05-18T23:59:59Z`.",
    )
    @click.option(
        "--filter", "filter_exprs",
        multiple=True,
        metavar="EXPR",
        help="Filter expression (repeatable; AND semantics). Forms: "
             "field=value | field~regex | field>=N | field<=N. "
             "Short-form aliases for the agent block (#320 / §A18): "
             "`agent.session_id=X` / `agent.name=X` / "
             "`agent.detected_from=X` expand to their canonical "
             "`unmapped.iam_jit.agent.*` paths client-side before "
             "forwarding. Forwarded to each bouncer's "
             "/audit/events?filter= so the filter runs server-side. "
             "See each product's docs/QUERYING-AUDIT-LOGS.md for the "
             "full supported field catalog.",
    )
    @click.option(
        "--kind", "kind",
        default=None,
        metavar="KIND",
        help="#620 — short-form for the iam-jit serve audit log's "
             "`kind` field (e.g. `--kind request_cap_exceeded` for the "
             "#613 cap-fire recipe).  Expands client-side to "
             "`--filter unmapped.iam_jit.kind=KIND` and is forwarded "
             "verbatim to every fan-out surface; bouncers ignore it "
             "(they have no `kind` field) while iam-jit serve uses it.",
    )
    @click.option(
        "--limit",
        type=int,
        default=100,
        show_default=True,
        help="Per-bouncer response cap. Each bouncer returns up to "
             "this many events; the merged stream is the union, "
             "sorted by timestamp.",
    )
    @click.option(
        "--format", "fmt",
        type=click.Choice(
            ["jsonl", "ocsf-bundle", "csv", "summary"],
            case_sensitive=False,
        ),
        default="jsonl",
        show_default=True,
        help="Output format. `jsonl` = one merged + sorted OCSF event "
             "per line. `ocsf-bundle` = ONE Detection Finding wrapping "
             "events from all bouncers (cross-product correlation in a "
             "single SIEM-ingestible artifact). `csv` = tabular with "
             "the per-bouncer column. `summary` = per-bouncer + total "
             "counts (no event bodies). `--json` is a convenience alias "
             "for `--format jsonl` (#496).",
    )
    @click.option(
        "--json", "json_alias",
        is_flag=True,
        default=False,
        help="Convenience alias for `--format jsonl` (#496). Mutually "
             "exclusive with `--format` set to anything other than `jsonl`.",
    )
    @click.option(
        "--audit-events-token",
        "audit_events_token",
        default=None,
        help="Bearer token sent to every bouncer's /audit/events. "
             "Required when ANY of the queried bouncers is bound off-"
             "loopback (the per-bouncer mgmt port refuses external "
             "binds without an --audit-events-token at run time). "
             "Loopback queries don't need this.",
    )
    @click.option(
        "--timeout",
        type=float,
        default=_DEFAULT_TIMEOUT_SECONDS,
        show_default=True,
        help="Per-bouncer HTTP timeout in seconds. One slow bouncer "
             "won't pin the cross-bouncer query — each runs in a "
             "thread + the merge layer drops late responders.",
    )
    @click.option(
        "--extract-permissions",
        "extract_permissions",
        is_flag=True,
        default=False,
        help="#419 / §A58 — instead of returning OCSF events, project "
             "the window into a structured permission set "
             "({action, resources, count}+observed_scope) ready for "
             "`iam_jit_request_role_from_synthesis`. Phase E of "
             "[[bouncer-informs-agent-informs-iam-jit]]. Implies "
             "single-bouncer scope — pass exactly one --bouncer.",
    )
    @click.option(
        "--scope-filter",
        "scope_filter_raw",
        default=None,
        metavar="JSON",
        help="#436 / §A70 — JSON-encoded scope-filter classifier "
             "(deployment-target taxonomy shape). Filters the merged "
             "event stream client-side by ANY of: clusters / accounts "
             "/ regions / namespaces / hosts / databases. Globs `*` "
             "supported. Pipe from `iam-jit deployment-targets show "
             "<NAME> --classifier-only`. Example: "
             "`--scope-filter '{\"clusters\":[\"prod-*\"],"
             "\"accounts\":[\"999988887777\"]}'`.",
    )
    @click.option(
        "--output",
        "output_path",
        type=click.Path(
            dir_okay=False,
            writable=True,
            allow_dash=True,
        ),
        default=None,
        help="#436 / §A70 — stream events to FILE instead of stdout. "
             "Critical for year+ queries that may return 100K+ events "
             "— the stream writes incrementally rather than loading "
             "everything into memory at once. Use `-` for stdout "
             "(default behavior).",
    )
    @click.option(
        "--cold-tier-warn-days",
        "cold_tier_warn_days",
        type=int,
        default=LONG_RANGE_WARN_DAYS,
        show_default=True,
        help="#436 / §A70 — emit a stderr warning when the lookback "
             "window crosses this many days. Operator signal that the "
             "query is reaching into cold-tier object storage which "
             "may be slow + costly. Set to 0 to disable the warning.",
    )
    def audit_query_cmd(
        bouncers_raw: tuple[str, ...],
        since: str | None,
        until: str | None,
        filter_exprs: tuple[str, ...],
        kind: str | None,
        limit: int,
        fmt: str,
        json_alias: bool,
        audit_events_token: str | None,
        timeout: float,
        extract_permissions: bool,
        scope_filter_raw: str | None,
        output_path: str | None,
        cold_tier_warn_days: int,
    ) -> None:
        """Query audit events across every reachable bouncer in
        parallel. Default probes ibounce/kbounce/dbounce/gbounce on
        loopback and merges the per-bouncer response streams into one
        sorted OCSF NDJSON output.

        \b
        Examples:
          # Latest 50 events across all four default bouncers.
          iam-jit audit query --limit 50

          # Cross-product correlation for one agent session (short form;
          # the CLI expands `agent.session_id` to the canonical
          # `unmapped.iam_jit.agent.session_id` before forwarding).
          iam-jit audit query \\
              --filter agent.session_id=019687ef-... \\
              --format ocsf-bundle > session-bundle.json

          # Same query in canonical long form (always supported).
          iam-jit audit query \\
              --filter unmapped.iam_jit.agent.session_id=019687ef-...

          # Counts only.
          iam-jit audit query --format summary

          # Override one bouncer's URL (rest = defaults).
          iam-jit audit query --bouncer kbounce=http://10.0.0.5:8766
        """
        if limit < 1 or limit > 10_000:
            raise click.BadParameter("--limit must be in 1..10000")

        # #620 — `--kind X` is shorthand for
        # `--filter unmapped.iam_jit.kind=X`.  The expansion has to
        # happen BEFORE the short-form alias map so bouncers see a
        # canonical OCSF path (they ignore the `kind` field; iam-jit
        # serve consumes it).  This closes the docs/recipes/
        # OUTSTANDING-REQUEST-CAP.md command shape.
        if kind:
            filter_exprs = filter_exprs + (
                f"unmapped.iam_jit.kind={kind}",
            )

        # #320 / §A18: expand short-form filter aliases (e.g.
        # `agent.session_id=X` → `unmapped.iam_jit.agent.session_id=X`)
        # CLIENT-SIDE before forwarding so each bouncer's per-product
        # filter parser still sees the canonical OCSF long-form path.
        # UAT verified the spec-example copy-pasted short-form crashed
        # per-bouncer parsers with HTTP 400; this expansion closes the
        # gap without requiring per-bouncer changes.
        filter_exprs = _expand_short_form_filters(filter_exprs)

        # #496 §A72b — `--json` is a convenience alias for `--format jsonl`.
        # Bare `--json` (default fmt='jsonl') is a no-op. `--json` combined
        # with a non-jsonl explicit `--format` is a contradiction; reject
        # rather than silently picking one (operator must clarify intent).
        if json_alias:
            if fmt != "jsonl":
                raise click.UsageError(
                    f"--json is a convenience alias for `--format jsonl`; "
                    f"do not combine it with `--format {fmt}`. Drop "
                    f"`--json` or change `--format` to `jsonl`.",
                )
            # fmt is already 'jsonl' (default or explicit) — alias is a no-op
            # other than signaling intent in --help.

        # #436 / §A70 — parse the scope-filter classifier (None when
        # not provided so the existing call sites behave unchanged).
        scope_filter = _parse_scope_filter(scope_filter_raw)

        # #628 — validate --since / --until BEFORE the fan-out.
        # Pre-#628: an invalid value passed through to every bouncer,
        # each returned HTTP 400, the CLI tucked the error into "skipped"
        # notes, and exited 0 — silently claiming "no events found" when
        # the query was malformed. Per [[ibounce-honest-positioning]] this
        # gate turns that lie into an honest exit 2. Mirrors the
        # validate-then-fan-out pattern from cli_profile_allow.py:676
        # (#606 Gap A / #623 Gap B).
        _validate_since_spec(since, "--since")
        _validate_since_spec(until, "--until")

        # #436 / §A70 — long-range `--since` shorthand (`2y`, `6M`)
        # expansion. The bouncer's `/audit/events` accepts ISO 8601
        # so we reduce calendar units locally before forwarding.
        if since:
            since = _parse_since_long_range(since)
        if until:
            until = _parse_since_long_range(until)

        # #436 / §A70 — operator-visible cold-tier warning. Long
        # lookbacks may hit cold-tier object storage which is slow +
        # costly; surfacing the warning early lets the operator
        # confirm before the query blocks for minutes.
        window_days = _since_window_days(since)
        if (
            cold_tier_warn_days > 0
            and window_days is not None
            and window_days >= cold_tier_warn_days
        ):
            click.echo(
                f"warning: --since window is ~{window_days:.0f} days "
                f"(threshold {cold_tier_warn_days}d). Long-range "
                f"queries may hit cold-tier object storage and take "
                f"minutes to complete. See #436 cold-tier guidance.",
                err=True,
            )

        bouncers = _resolve_bouncer_set(bouncers_raw)
        if not bouncers:
            raise click.UsageError(
                "no bouncers to query; pass --bouncer name (or name=URL)",
            )

        # Parallel fan-out. ThreadPoolExecutor (NOT asyncio) keeps the
        # CLI dependency-light + lets us reuse urllib without an
        # async-HTTP package. One worker per bouncer is the natural
        # ceiling — bumping the pool wouldn't help since each future
        # blocks on one I/O call.
        results: list[_BouncerQueryResult] = []
        with ThreadPoolExecutor(max_workers=len(bouncers)) as pool:
            futures = {
                pool.submit(
                    _query_one_bouncer,
                    e,
                    since=since,
                    until=until,
                    filters=filter_exprs,
                    limit=limit,
                    bearer_token=audit_events_token,
                    timeout=timeout,
                ): e
                for e in bouncers
            }
            for fut in as_completed(futures):
                results.append(fut.result())

        # Stable stderr-noting for unreachable bouncers — per the spec:
        # "Skip unreachable ones with a stderr note." Reachable bouncers
        # that returned an HTTP error also surface here so the operator
        # sees auth failures + bad filter syntax without staring at an
        # empty stdout.
        for r in sorted(results, key=lambda x: x.bouncer):
            if r.error:
                click.echo(
                    f"note: {r.bouncer} skipped ({r.error})",
                    err=True,
                )

        # #628 — post-fan-out: if ALL bouncers errored AND we got zero
        # events, exit 1 (not 0). Pre-#628 the CLI exited 0 here with
        # empty output — indistinguishable from "no events in range", so
        # the operator had no $? signal that the query totally failed.
        # Per [[ibounce-honest-positioning]] zero events from a totally-
        # failed fan-out is NOT the same as a healthy "nothing found".
        all_failed = bool(results) and all(r.error for r in results)
        total_events = sum(len(r.events) for r in results)
        if all_failed and total_events == 0:
            click.echo(
                "error: all bouncers returned errors; 0 events retrieved. "
                "Check stderr notes above for per-bouncer error details.",
                err=True,
            )
            sys.exit(1)

        if fmt == "summary":
            # Stable name order for predictable output across runs.
            ordered = sorted(results, key=lambda x: x.bouncer)
            click.echo(_format_summary(ordered), nl=False)
            return

        # Merge + sort. ``_event_time_key`` puts oldest-first so the
        # merged stream reads chronologically (matches `audit tail`
        # default which is newest-first reversed for the live tail).
        merged: list[dict[str, Any]] = []
        for r in results:
            merged.extend(r.events)
        merged.sort(key=_event_time_key)

        # #436 / §A70 — client-side scope-filter classifier match.
        # Applied AFTER the merge so the per-bouncer servers don't
        # need to grow the scope-filter shape. As more bouncers learn
        # to honor the classifier server-side this can move upstream
        # to drop bytes earlier on the wire.
        if scope_filter:
            before = len(merged)
            merged = [
                ev for ev in merged
                if _event_matches_classifier(ev, scope_filter)
            ]
            if before > 0 and not merged:
                click.echo(
                    f"note: --scope-filter matched 0/{before} events; "
                    "verify the classifier dimensions match the "
                    "events' OCSF fields (kbouncer cluster, "
                    "ibounce cloud.account.uid + cloud.region, "
                    "gbounce dst_endpoint.hostname, etc.).",
                    err=True,
                )

        # #419 / §A58 — `--extract-permissions` reshapes the merged
        # event stream into the structured permission-set shape used
        # by `iam_jit_request_role_from_synthesis`. We delegate to the
        # audit_extract module so the same projection is shared with
        # the MCP tool. Single-bouncer semantics — the agent
        # synthesises ROLES from ONE bouncer's window, never a merged
        # cross-bouncer set (mixing kbouncer activity into an iam-jit
        # AWS role request would be a category error).
        if extract_permissions:
            if len(bouncers) != 1:
                raise click.UsageError(
                    "--extract-permissions requires exactly one "
                    "--bouncer (the source of the permission set); "
                    f"got {len(bouncers)} bouncer(s).",
                )
            from .audit_extract import extract_permissions_from_events
            window = {"from": since or "", "to": until or ""}
            extracted = extract_permissions_from_events(
                merged,
                bouncer=bouncers[0].name,
                time_window=window,
                notes=tuple(
                    f"{r.bouncer} skipped ({r.error})"
                    for r in results if r.error
                ),
            )
            _write_output(
                output_path,
                json.dumps(extracted.as_dict(), indent=2) + "\n",
            )
            return

        if fmt == "ocsf-bundle":
            _write_output(
                output_path,
                _format_ocsf_bundle(merged),
            )
            return
        if fmt == "csv":
            _write_output(output_path, _format_csv(merged))
            return
        # jsonl (default) — streaming when --output is set so the
        # whole result set isn't held in memory at once (long-range
        # queries can return tens of thousands of events).
        if output_path and output_path != "-":
            with open(output_path, "w", encoding="utf-8") as fh:
                for ev in merged:
                    fh.write(_format_jsonl_one(ev))
        else:
            click.echo(_format_jsonl(merged), nl=False)

    return audit_group


def _write_output(
    output_path: str | None,
    body: str,
) -> None:
    """Write ``body`` to ``output_path`` (or stdout when None / `-`).
    Used by the non-streaming formats (csv / ocsf-bundle /
    extract-permissions) where the whole rendered body fits in
    memory naturally. The jsonl path uses a per-event streaming
    writer instead to keep memory bounded for year+ queries.
    """
    if output_path and output_path != "-":
        with open(output_path, "w", encoding="utf-8") as fh:
            fh.write(body)
    else:
        click.echo(body, nl=False)


def _format_jsonl_one(ev: dict[str, Any]) -> str:
    """Render a single event as one JSONL line (newline-terminated).
    Used by the streaming jsonl writer so the per-event encoding is
    identical to the in-memory variant."""
    return json.dumps(ev, default=str, separators=(",", ":")) + "\n"


# Silence "imported but unused" warnings when `sys` is only used at
# module-import diagnostic time (debug helper retained for symmetry
# with the cross-product CLI siblings that emit to stderr).
_ = sys
