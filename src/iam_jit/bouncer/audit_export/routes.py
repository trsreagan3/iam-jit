"""Per-org notification routing — #280.

Per [[per-org-notification-routing]]: the single `--audit-webhook-url`
shape works for one team / one collector. At org scale customers want
multi-destination routing with severity / team / product filters:

  - SOC team's Splunk gets every Medium+ event
  - dev team's Datadog gets only their own events
  - on-call gets Critical -> PagerDuty + Slack
  - everything also archives to a central S3 (fan-out)

This module ships the deterministic routes engine that does that. A
single YAML file describes the routes; each route has a match block,
a list of destinations, and an `on_match` mode (`stop` default;
`continue` for fan-out). Secrets live in env vars via `${ENV}`
interpolation; the YAML never carries plaintext tokens.

Per [[enterprise-self-host-only]]: this is Enterprise-tier; the
license gate is the same shape as the existing webhook gate (see
`webhook.gate_webhook_license` + `alerts.gate_alerts_license`).

Per [[security-team-positioning-safety-not-surveillance]]: route /
destination strings use NEUTRAL language. Match conditions never
imply a verdict; they're SHIPPING filters, not GATING rules.

Per [[scorer-is-ground-truth]] + the memo's "Don't make the routes
engine LLM-augmented": this is a pure deterministic match engine.
No LLM, no scoring, no I/O on the hot path beyond the destination
HTTP POST.

Per [[creates-never-mutates]]: routes are ADDITIVE; the engine
never modifies the event it dispatches.

Per [[no-hosted-saas]] + [[self-host-zero-billing-dependency]]: every
destination is operator-configured; iam-jit-the-company never receives
the routed traffic.
"""

from __future__ import annotations

import asyncio
import dataclasses
import fnmatch
import json
import logging
import os
import re
import time
from collections.abc import Iterable
from typing import Any

from .presets import Preset, build_request
from .webhook import (
    DEFAULT_WEBHOOK_QUEUE_MAXSIZE,
    SSRFRejectedError,
    mask_token,
    mask_url_userinfo,
    validate_webhook_url,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Errors
# ---------------------------------------------------------------------------


class RoutesConfigError(ValueError):
    """Raised when an --alert-routes YAML file is invalid (bad
    structure, unknown destination type, missing required field,
    unresolved ${ENV} secret, etc.). Surfaced to the operator at CLI
    parse time so a typo doesn't ship a silent no-op."""


class RoutesLicenseError(Exception):
    """Raised when --alert-routes is set without a valid Enterprise
    license. Mirrors WebhookLicenseError / AlertsLicenseError so the
    CLI's error-handling branch treats all three uniformly."""


# ---------------------------------------------------------------------------
# Match-condition operators
# ---------------------------------------------------------------------------


_OPERATOR_KEYS = ("equals", "gte", "lte", "gt", "lt", "in", "match", "glob")


def _walk_path(event: Any, path: str) -> Iterable[Any]:
    """Walk a dotted path through `event`, yielding every value found.

    Supports:
      - dotted access:        ``a.b.c``
      - list-of-dicts walk:   ``resources[].uid``

    Returns every value found along the path (zero, one, or many).
    A missing intermediate key yields nothing (the caller treats
    "no values" as "no match"). The function NEVER raises on a
    missing field — operator config is allowed to reference fields
    that don't exist on every event shape (e.g. ``actor.user.
    attribute.team`` doesn't exist on AUDIT_DROPPED synthetics).
    """
    parts = path.split(".")
    stack: list[Any] = [event]
    for part in parts:
        next_stack: list[Any] = []
        list_walk = False
        if part.endswith("[]"):
            list_walk = True
            part = part[:-2]
        for cur in stack:
            if isinstance(cur, dict) and part in cur:
                val = cur[part]
                if list_walk and isinstance(val, list):
                    next_stack.extend(val)
                else:
                    next_stack.append(val)
        stack = next_stack
        if not stack:
            return
    for v in stack:
        yield v


def _coerce_int(v: Any) -> int | None:
    """Best-effort int coerce — returns None if `v` cannot be a number
    (so the comparison operator falls through to "no match" rather
    than raising). Accepts int + numeric strings; refuses bool
    explicitly (Python's `int(True)==1` would otherwise let
    `severity_id: {gte: 0}` match every event)."""
    if isinstance(v, bool):
        return None
    if isinstance(v, int):
        return v
    if isinstance(v, float):
        return int(v)
    if isinstance(v, str):
        try:
            return int(v)
        except (TypeError, ValueError):
            return None
    return None


def _match_one(value: Any, condition: Any) -> bool:
    """Match a single resolved value against a condition spec.

    Conditions:
      - scalar  (str/int/bool/float): equals
      - {equals: V}                 : explicit equals
      - {gte: N}  / {lte: N}        : numeric >= / <=
      - {gt:  N}  / {lt:  N}        : numeric >  / <
      - {in:  [V1, V2, ...]}        : value is in the set
      - {match: "regex"}            : full-match regex (re.fullmatch)
      - {glob:  "g*lob"}            : case-insensitive glob via fnmatch

    Multiple operator keys in one condition dict AND together (so
    ``{gte: 3, lte: 5}`` matches values 3..5 inclusive).
    """
    if isinstance(condition, dict):
        # Empty {} is an explicit "match everything" — caller's empty
        # match block resolves to {} (no conditions => all match) but
        # an empty *condition* on a single field is allowed too.
        if not condition:
            return True
        ok = True
        for op, target in condition.items():
            ok = ok and _apply_operator(value, op, target)
            if not ok:
                return False
        return True
    # Scalar shorthand = equals.
    return value == condition


def _apply_operator(value: Any, op: str, target: Any) -> bool:
    """Single (op, target) check. Unknown operators return False — the
    YAML loader has already warned on unknown operators, so this is
    the runtime fail-soft."""
    if op == "equals":
        return value == target
    if op in ("gte", "lte", "gt", "lt"):
        v_int = _coerce_int(value)
        t_int = _coerce_int(target)
        if v_int is None or t_int is None:
            return False
        if op == "gte":
            return v_int >= t_int
        if op == "lte":
            return v_int <= t_int
        if op == "gt":
            return v_int > t_int
        return v_int < t_int  # lt
    if op == "in":
        if not isinstance(target, list):
            return False
        return value in target
    if op == "match":
        if not isinstance(value, str) or not isinstance(target, str):
            return False
        try:
            return re.fullmatch(target, value) is not None
        except re.error:
            return False
    if op == "glob":
        if not isinstance(value, str) or not isinstance(target, str):
            return False
        # Case-insensitive: lowercase both sides for the fnmatch.
        return fnmatch.fnmatchcase(value.lower(), target.lower())
    return False


def _field_matches(event: dict, path: str, condition: Any) -> bool:
    """True if ANY value along `path` matches `condition`. Empty
    walk (missing field) is a non-match."""
    found = False
    for value in _walk_path(event, path):
        found = True
        if _match_one(value, condition):
            return True
    if not found:
        return False
    return False


def evaluate_match(event: dict, match: dict) -> bool:
    """AND across every (path, condition) pair in `match`. Empty
    `match` block = matches everything (the fallback-route shape)."""
    if not match:
        return True
    for path, condition in match.items():
        if not _field_matches(event, path, condition):
            return False
    return True


# ---------------------------------------------------------------------------
# Destination shapes
# ---------------------------------------------------------------------------


_ALLOWED_DESTINATION_TYPES = ("webhook", "pagerduty", "slack")


@dataclasses.dataclass(frozen=True)
class WebhookDestination:
    """An HTTPS webhook destination. Reuses the per-vendor preset
    adapters from #257 so the existing Datadog / Splunk HEC /
    Sentinel one-click overlays work for routed sends too."""

    url: str
    token: str
    preset: Preset = Preset.GENERIC
    allow_internal: bool = False
    tags: str = ""
    sentinel_table: str = "IamJitBouncer"
    product: str = "ibounce"

    def kind(self) -> str:
        return "webhook"

    def masked(self) -> dict[str, Any]:
        return {
            "type": "webhook",
            "url": mask_url_userinfo(self.url),
            "token": mask_token(self.token),
            "preset": self.preset.value,
            "allow_internal": self.allow_internal,
        }


@dataclasses.dataclass(frozen=True)
class PagerDutyDestination:
    """PagerDuty Events API v2. Raw HTTP POST against the documented
    endpoint — no SDK dep needed. See:
    https://developer.pagerduty.com/docs/events-api-v2/overview/"""

    integration_key: str
    severity: str = "warning"  # info / warning / error / critical

    def kind(self) -> str:
        return "pagerduty"

    def masked(self) -> dict[str, Any]:
        return {
            "type": "pagerduty",
            "integration_key": mask_token(self.integration_key),
            "severity": self.severity,
        }


@dataclasses.dataclass(frozen=True)
class SlackDestination:
    """Slack incoming webhook. Raw HTTP POST against the workspace's
    incoming-webhook URL — no SDK dep needed. See:
    https://api.slack.com/messaging/webhooks"""

    webhook_url: str

    def kind(self) -> str:
        return "slack"

    def masked(self) -> dict[str, Any]:
        # Slack incoming-webhook URLs embed a path token (the per-channel
        # secret is the trailing path segments). Anything beyond the
        # workspace host is privileged; render only the host so the
        # status surface confirms "yes, a Slack destination is wired"
        # without leaking the secret.
        try:
            import urllib.parse
            parsed = urllib.parse.urlparse(self.webhook_url)
            host = parsed.hostname or ""
            return {"type": "slack", "webhook_url": f"https://{host}/***"}
        except Exception:
            return {"type": "slack", "webhook_url": "***"}


Destination = WebhookDestination | PagerDutyDestination | SlackDestination


# ---------------------------------------------------------------------------
# Route shape
# ---------------------------------------------------------------------------


_VALID_ON_MATCH = ("stop", "continue")


@dataclasses.dataclass(frozen=True)
class Route:
    """One routing decision. `match` is the dict-of-(path, condition)
    block; `destinations` are evaluated in order on a match. `on_match`
    is `stop` (default; first-match-wins) or `continue` (fan-out)."""

    name: str
    match: dict[str, Any]
    destinations: tuple[Destination, ...]
    on_match: str = "stop"


@dataclasses.dataclass(frozen=True)
class RoutesConfig:
    """Parsed routes file. Frozen so a misbehaving destination can't
    mutate the operator's intent at runtime."""

    routes: tuple[Route, ...]

    def secrets_used(self) -> list[tuple[str, str]]:
        """Return a list of (env_var_name, masked_value_prefix) tuples
        for the startup banner. `masked_value_prefix` is the first 8
        characters of the resolved secret followed by `***` — enough
        for an operator to confirm "yes, the right secret is loaded"
        without ever printing the full value to logs.

        Walks every destination's secret-bearing field once; dedupes
        by env-var name (the same env var can appear in multiple
        routes / destinations)."""
        out: dict[str, str] = {}
        for route in self.routes:
            for dest in route.destinations:
                for env_name, secret_val in _secret_fields(dest):
                    if env_name and env_name not in out:
                        # Masked rendering: first 8 chars + ***. Empty
                        # secret (somehow resolved to "") renders as
                        # the bare mask "***" so empties still show up.
                        out[env_name] = _mask_secret_prefix(secret_val)
        return sorted(out.items())


def _secret_fields(dest: Destination) -> Iterable[tuple[str, str]]:
    """Yield (env_var_name, resolved_secret_value) pairs for the
    destination. Used by the banner masking + by the secret-leak
    test."""
    if isinstance(dest, WebhookDestination):
        yield (_origin_env_var(dest, "token"), dest.token)
    elif isinstance(dest, PagerDutyDestination):
        yield (_origin_env_var(dest, "integration_key"), dest.integration_key)
    elif isinstance(dest, SlackDestination):
        # Slack URL is itself the secret (anyone with the URL can
        # post). Show the URL host masked + treat the path token as
        # the secret prefix.
        yield (_origin_env_var(dest, "webhook_url"), dest.webhook_url)


# Map from id(destination) -> {field_name -> originating env-var name}.
# Populated by the loader so the banner / status can name the env var
# the operator set. (Lives off-instance so the dataclass stays
# frozen + hashable.)
_DEST_FIELD_ORIGIN: dict[int, dict[str, str]] = {}


def _origin_env_var(dest: Destination, field: str) -> str:
    return _DEST_FIELD_ORIGIN.get(id(dest), {}).get(field, "")


def _mask_secret_prefix(secret: str) -> str:
    """Mask a secret as `<first-8-chars>***`. Empty input renders as
    just `***` so empties still show in the banner."""
    if not secret:
        return "***"
    prefix = secret[:8]
    return f"{prefix}***"


# ---------------------------------------------------------------------------
# YAML loader
# ---------------------------------------------------------------------------


_ENV_VAR_RE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _resolve_secret(value: Any, *, field_path: str) -> tuple[str, str]:
    """Resolve a YAML-supplied secret string. Returns (resolved_value,
    origin_env_var_name).

    The supported shape is ``${ENV_VAR}`` — the entire value must be
    one env-var reference (no concatenation; that would invite leaks
    via shell-style command substitution). A bare literal (no `${...}`)
    is REFUSED at load time per the memo's "DON'T expose tokens in
    routes YAML" rule.
    """
    if not isinstance(value, str):
        raise RoutesConfigError(
            f"{field_path}: must be a string of the form '${{ENV_VAR}}'; "
            f"got {type(value).__name__}"
        )
    m = _ENV_VAR_RE.fullmatch(value)
    if m is None:
        raise RoutesConfigError(
            f"{field_path}: secrets must be passed as '${{ENV_VAR}}' "
            f"(env-var interpolation only). Bare literal tokens are "
            f"refused — keep secrets out of the YAML file. Got: {value!r}"
        )
    env_name = m.group(1)
    resolved = os.environ.get(env_name)
    if resolved is None or resolved == "":
        raise RoutesConfigError(
            f"{field_path}: env-var {env_name!r} is not set in the "
            f"environment (referenced as '${{{env_name}}}'). Export "
            f"it before starting the proxy."
        )
    return resolved, env_name


def _resolve_optional_string(value: Any, *, field_path: str) -> str:
    """Resolve a YAML-supplied non-secret string (URL etc.). Supports
    ``${ENV_VAR}`` interpolation just like secrets, but a bare literal
    is ALSO permitted (URLs are not secrets — Slack webhook URLs are
    the exception + they go through the secret path)."""
    if value is None:
        return ""
    if not isinstance(value, str):
        raise RoutesConfigError(
            f"{field_path}: must be a string; got {type(value).__name__}"
        )
    m = _ENV_VAR_RE.fullmatch(value)
    if m is not None:
        env_name = m.group(1)
        resolved = os.environ.get(env_name)
        if resolved is None:
            raise RoutesConfigError(
                f"{field_path}: env-var {env_name!r} is not set "
                f"(referenced as '${{{env_name}}}'). Export it before "
                f"starting the proxy."
            )
        return resolved
    return value


def _validate_match_block(match: Any, *, route_name: str) -> dict[str, Any]:
    """Validate the `match` block shape. Empty mapping is allowed (the
    fallback-route shape). Each value is either a scalar or a dict
    using exactly the supported operator keys."""
    if match is None:
        return {}
    if not isinstance(match, dict):
        raise RoutesConfigError(
            f"route {route_name!r}: 'match' must be a mapping; "
            f"got {type(match).__name__}"
        )
    for path, condition in match.items():
        if not isinstance(path, str) or not path:
            raise RoutesConfigError(
                f"route {route_name!r}: match keys must be non-empty "
                f"strings; got {path!r}"
            )
        if isinstance(condition, dict):
            for op in condition:
                if op not in _OPERATOR_KEYS:
                    raise RoutesConfigError(
                        f"route {route_name!r}: unknown operator {op!r} "
                        f"on field {path!r}. Supported operators: "
                        f"{', '.join(_OPERATOR_KEYS)}."
                    )
    return match


def _load_destination(
    raw: dict, *, route_name: str, idx: int, product: str,
) -> Destination:
    """Parse one destination entry. Each entry is a single-key dict
    keyed by the destination type (webhook / pagerduty / slack)."""
    if not isinstance(raw, dict) or len(raw) != 1:
        raise RoutesConfigError(
            f"route {route_name!r}: destination[{idx}] must be a "
            f"single-key mapping like '{{webhook: {{...}}}}'; got {raw!r}"
        )
    (dest_type, body), = raw.items()
    if dest_type not in _ALLOWED_DESTINATION_TYPES:
        raise RoutesConfigError(
            f"route {route_name!r}: unknown destination type "
            f"{dest_type!r}; supported types: "
            f"{', '.join(_ALLOWED_DESTINATION_TYPES)}."
        )
    if not isinstance(body, dict):
        raise RoutesConfigError(
            f"route {route_name!r}: destination[{idx}] body must be a "
            f"mapping; got {type(body).__name__}"
        )
    field_origins: dict[str, str] = {}
    if dest_type == "webhook":
        url = _resolve_optional_string(
            body.get("url"), field_path=f"route {route_name!r}.destinations[{idx}].webhook.url",
        )
        if not url:
            raise RoutesConfigError(
                f"route {route_name!r}: webhook destination requires a 'url'."
            )
        token_val = body.get("token")
        if token_val is None:
            raise RoutesConfigError(
                f"route {route_name!r}: webhook destination requires a 'token' "
                f"(env-var interpolation: token: ${{ENV_NAME}})."
            )
        token, env_name = _resolve_secret(
            token_val,
            field_path=f"route {route_name!r}.destinations[{idx}].webhook.token",
        )
        field_origins["token"] = env_name
        preset_name = str(body.get("preset", "generic")).lower()
        try:
            preset = Preset(preset_name)
        except ValueError as e:
            raise RoutesConfigError(
                f"route {route_name!r}: unknown webhook preset "
                f"{preset_name!r}; supported: "
                f"{', '.join(p.value for p in Preset)}."
            ) from e
        dest = WebhookDestination(
            url=url,
            token=token,
            preset=preset,
            allow_internal=bool(body.get("allow_internal", False)),
            tags=str(body.get("tags", "")),
            sentinel_table=str(body.get("sentinel_table", "IamJitBouncer")),
            product=product,
        )
    elif dest_type == "pagerduty":
        key_val = body.get("integration_key")
        if key_val is None:
            raise RoutesConfigError(
                f"route {route_name!r}: pagerduty destination requires an "
                f"'integration_key' (env-var interpolation: "
                f"integration_key: ${{ENV_NAME}})."
            )
        key, env_name = _resolve_secret(
            key_val,
            field_path=(
                f"route {route_name!r}.destinations[{idx}].pagerduty."
                f"integration_key"
            ),
        )
        field_origins["integration_key"] = env_name
        severity = str(body.get("severity", "warning")).lower()
        if severity not in ("info", "warning", "error", "critical"):
            raise RoutesConfigError(
                f"route {route_name!r}: pagerduty severity must be one of "
                f"info / warning / error / critical; got {severity!r}."
            )
        dest = PagerDutyDestination(
            integration_key=key, severity=severity,
        )
    else:  # slack
        url_val = body.get("webhook_url")
        if url_val is None:
            raise RoutesConfigError(
                f"route {route_name!r}: slack destination requires a "
                f"'webhook_url' (env-var interpolation: "
                f"webhook_url: ${{ENV_NAME}})."
            )
        url, env_name = _resolve_secret(
            url_val,
            field_path=(
                f"route {route_name!r}.destinations[{idx}].slack.webhook_url"
            ),
        )
        field_origins["webhook_url"] = env_name
        dest = SlackDestination(webhook_url=url)
    _DEST_FIELD_ORIGIN[id(dest)] = field_origins
    return dest


def load_routes_config(path: str, *, product: str = "ibounce") -> RoutesConfig:
    """Load + validate an `--alert-routes` YAML file.

    See the per-org-notification-routing memo for the full schema. The
    loader fails-fast on any structural problem; the operator gets a
    clear error pointing at the offending route + field.
    """
    from ruamel.yaml import YAML

    yaml = YAML(typ="safe", pure=True)
    try:
        with open(path, encoding="utf-8") as f:
            raw = yaml.load(f) or {}
    except OSError as e:
        raise RoutesConfigError(
            f"could not read --alert-routes file {path!r}: {e}"
        ) from e
    if not isinstance(raw, dict):
        raise RoutesConfigError(
            f"--alert-routes YAML at {path!r}: top level must be a "
            f"mapping with a 'routes' key; got {type(raw).__name__}."
        )
    routes_raw = raw.get("routes")
    if routes_raw is None:
        raise RoutesConfigError(
            f"--alert-routes YAML at {path!r}: top-level 'routes' key "
            f"is required (a list of route definitions)."
        )
    if not isinstance(routes_raw, list):
        raise RoutesConfigError(
            f"--alert-routes YAML at {path!r}: 'routes' must be a list; "
            f"got {type(routes_raw).__name__}."
        )
    parsed: list[Route] = []
    seen_names: set[str] = set()
    for idx, route_raw in enumerate(routes_raw):
        if not isinstance(route_raw, dict):
            raise RoutesConfigError(
                f"--alert-routes YAML at {path!r}: routes[{idx}] must "
                f"be a mapping; got {type(route_raw).__name__}."
            )
        name = route_raw.get("name")
        if not isinstance(name, str) or not name:
            raise RoutesConfigError(
                f"--alert-routes YAML at {path!r}: routes[{idx}].name "
                f"must be a non-empty string."
            )
        if name in seen_names:
            raise RoutesConfigError(
                f"--alert-routes YAML at {path!r}: duplicate route name "
                f"{name!r}."
            )
        seen_names.add(name)
        match = _validate_match_block(route_raw.get("match"), route_name=name)
        dests_raw = route_raw.get("destinations")
        if not isinstance(dests_raw, list) or not dests_raw:
            raise RoutesConfigError(
                f"route {name!r}: 'destinations' must be a non-empty list."
            )
        destinations = tuple(
            _load_destination(d, route_name=name, idx=i, product=product)
            for i, d in enumerate(dests_raw)
        )
        on_match = str(route_raw.get("on_match", "stop")).lower()
        if on_match not in _VALID_ON_MATCH:
            raise RoutesConfigError(
                f"route {name!r}: on_match must be 'stop' (default) or "
                f"'continue'; got {on_match!r}."
            )
        parsed.append(
            Route(
                name=name,
                match=match,
                destinations=destinations,
                on_match=on_match,
            )
        )
    return RoutesConfig(routes=tuple(parsed))


# ---------------------------------------------------------------------------
# License gate
# ---------------------------------------------------------------------------


def gate_routes_license(license_obj: Any) -> None:
    """Refuse if --alert-routes is set without an Enterprise license.
    Same load-license path as the webhook + alerts gates (per
    [[enterprise-self-host-only]]).

    Raises RoutesLicenseError on a refusal; returns None on success.
    Defense in depth: the CLI fires this at parse time AND serve()
    fires it again at start, so a license file that disappeared
    between parse + start doesn't quietly grant routing capability.
    """
    from ... import license as license_mod

    if license_obj is None:
        try:
            license_obj = license_mod.load_license()
        except license_mod.LicenseInvalidError as e:
            raise RoutesLicenseError(
                f"--alert-routes requires a valid Enterprise license. "
                f"The license file at the configured path failed "
                f"verification: {e}. See docs/LICENSE.md."
            ) from e
    if license_obj is None or license_obj.tier != "enterprise":
        tier = license_obj.tier if license_obj is not None else "free"
        raise RoutesLicenseError(
            f"--alert-routes requires an Enterprise license; current "
            f"tier is {tier!r}. The single-destination "
            f"--audit-webhook-url channel stays available on all tiers. "
            f"See docs/LICENSE.md to obtain an Enterprise license."
        )


# ---------------------------------------------------------------------------
# Dispatcher — picks routes + dispatches via raw HTTP POST
# ---------------------------------------------------------------------------


# Default in-flight cap per destination type. Mirrors the existing
# WebhookPusher default; the per-destination cap is a back-pressure
# safety so one slow vendor doesn't pile up memory.
_DEFAULT_DEST_QUEUE_MAXSIZE = DEFAULT_WEBHOOK_QUEUE_MAXSIZE


def select_routes(event: dict, routes: tuple[Route, ...]) -> list[Route]:
    """Pure function. Returns the ordered list of routes the event
    matches, honouring `on_match` semantics. Exposed for the dry-run
    preview + the test surface."""
    out: list[Route] = []
    for route in routes:
        if evaluate_match(event, route.match):
            out.append(route)
            if route.on_match == "stop":
                break
    return out


class RoutesEngine:
    """The runtime that the proxy's audit-export emitter dispatches
    events to. Holds the parsed config + a per-route worker pipeline.

    Lifecycle::

        engine = RoutesEngine(config=cfg)
        await engine.start()
        engine.push(event)        # never blocks the hot path
        await engine.stop()

    Failure isolation: each destination's send runs in its own
    try/except inside the worker; a 500 from PagerDuty does NOT stop
    Slack from receiving the same event, and a route returning a
    transient error does NOT stop subsequent routes for the same event.

    Backward compat with the single-webhook surface: when --alert-routes
    is set the CLI ignores --audit-webhook-url (with a warning); the
    JSONL log channel + Security Lake adapter stay unchanged + run
    alongside.
    """

    def __init__(
        self,
        *,
        config: RoutesConfig,
        queue_maxsize: int = _DEFAULT_DEST_QUEUE_MAXSIZE,
        timeout_seconds: float = 10.0,
        product: str = "ibounce",
        _session_factory: Any | None = None,
        _sleep: Any | None = None,
    ) -> None:
        self.config = config
        self.queue_maxsize = queue_maxsize
        self.timeout_seconds = timeout_seconds
        self.product = product
        self._session_factory = _session_factory
        self._sleep = _sleep or asyncio.sleep
        self._queue: asyncio.Queue[dict | None] | None = None
        self._worker_task: asyncio.Task | None = None
        self._session: Any | None = None
        self._owns_session = False
        self._started = False
        # Per-destination stats: keyed by (route_name, dest_index).
        self._stats: dict[tuple[str, int], dict[str, Any]] = {}
        for route in config.routes:
            for i, _dest in enumerate(route.destinations):
                self._stats[(route.name, i)] = {
                    "total_sent": 0,
                    "total_failed": 0,
                    "last_error": "",
                    "last_status_code": None,
                    "last_attempt_unix": None,
                    "last_success_unix": None,
                }
        # Total drops on the engine-side queue. Bounded to keep memory
        # safe under sustained burst.
        self._engine_dropped = 0

    async def start(self) -> None:
        if self._started:
            return
        # Up-front SSRF gate for each webhook destination so a bad
        # URL surfaces at startup rather than on the first matching
        # event.
        for route in self.config.routes:
            for dest in route.destinations:
                if isinstance(dest, WebhookDestination):
                    validate_webhook_url(
                        dest.url, allow_internal=dest.allow_internal,
                    )
                # PagerDuty + Slack endpoints are public + well-known;
                # we don't run the SSRF gate against them. The operator
                # gets a clear error from the upstream if the integration
                # key / webhook URL is wrong.
        self._queue = asyncio.Queue(maxsize=self.queue_maxsize)
        if self._session_factory is None:
            import aiohttp  # local import so the audit_export package
            self._session = aiohttp.ClientSession()
            self._owns_session = True
        else:
            self._session = self._session_factory()
            self._owns_session = False
        self._worker_task = asyncio.create_task(
            self._worker(), name=f"{self.product}-audit-routes-engine",
        )
        self._started = True

    async def stop(self) -> None:
        if not self._started:
            return
        try:
            await self._queue.put(None)  # sentinel
        except Exception:
            pass
        if self._worker_task is not None:
            try:
                await self._worker_task
            except Exception as e:
                logger.warning("routes engine worker exited with %s", e)
        if self._owns_session and self._session is not None:
            try:
                await self._session.close()
            except Exception:
                pass
        self._session = None
        self._started = False

    def push(self, event: dict) -> None:
        """Enqueue one event. NEVER blocks; NEVER raises. Drops on
        overflow + bumps a counter (the JSONL log channel + Security
        Lake adapter still record the dropped event)."""
        if not self._started or self._queue is None:
            return
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            self._engine_dropped += 1

    async def _worker(self) -> None:
        assert self._queue is not None
        while True:
            event = await self._queue.get()
            if event is None:
                return
            # Pick routes deterministically.
            try:
                hits = select_routes(event, self.config.routes)
            except Exception as e:
                logger.warning("routes engine select failed: %s", e)
                continue
            for route in hits:
                for idx, dest in enumerate(route.destinations):
                    try:
                        await self._dispatch(route, idx, dest, event)
                    except Exception as e:
                        # Failure isolation: one destination's error
                        # MUST NOT stop the next destination / next
                        # route. We bump the per-dest counter + log
                        # with the masked URL only.
                        key = (route.name, idx)
                        stats = self._stats.setdefault(key, {})
                        stats["total_failed"] = stats.get("total_failed", 0) + 1
                        stats["last_error"] = _mask_str(str(e))
                        logger.warning(
                            "routes engine dispatch failed for "
                            "route=%r dest[%d] (%s): %s",
                            route.name, idx, dest.kind(), stats["last_error"],
                        )

    async def _dispatch(
        self, route: Route, idx: int, dest: Destination, event: dict,
    ) -> None:
        """Build + send one POST. Per-destination request shape:

          - webhook   -> reuse #257 build_request + the preset adapter
          - pagerduty -> Events API v2 enqueue payload
          - slack     -> incoming-webhook JSON payload

        No SDK deps; raw HTTP POST against the documented endpoints.
        """
        assert self._session is not None
        key = (route.name, idx)
        stats = self._stats[key]
        stats["last_attempt_unix"] = time.time()
        if isinstance(dest, WebhookDestination):
            url, headers, body = build_request(
                dest.preset, dest.url, dest.token, [event],
                tags=dest.tags,
                sentinel_table=dest.sentinel_table,
                product=dest.product,
            )
            await self._post(url, headers, body, key, dest)
        elif isinstance(dest, PagerDutyDestination):
            url = "https://events.pagerduty.com/v2/enqueue"
            payload = _pagerduty_payload(event, dest, product=self.product)
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            headers = {
                "Content-Type": "application/json",
                "User-Agent": f"{self.product}-audit-export/1.0",
            }
            await self._post(url, headers, body, key, dest)
        elif isinstance(dest, SlackDestination):
            payload = _slack_payload(event, product=self.product)
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            headers = {
                "Content-Type": "application/json",
                "User-Agent": f"{self.product}-audit-export/1.0",
            }
            await self._post(dest.webhook_url, headers, body, key, dest)
        else:
            raise RoutesConfigError(
                f"unknown destination kind: {type(dest).__name__}"
            )

    async def _post(
        self,
        url: str,
        headers: dict[str, str],
        body: bytes,
        key: tuple[str, int],
        dest: Destination,
    ) -> None:
        assert self._session is not None
        stats = self._stats[key]
        async with self._session.post(
            url, data=body, headers=headers, timeout=self.timeout_seconds,
        ) as resp:
            status = resp.status
            stats["last_status_code"] = status
            await resp.read()
            if 200 <= status < 300:
                stats["total_sent"] = stats.get("total_sent", 0) + 1
                stats["last_success_unix"] = time.time()
                return
            # 4xx + 5xx alike: bump failure counter, raise the masked
            # error so the outer try/except records it. No retry in
            # the v1.0 routes engine (per memo: routes engine + dry-run
            # ship first; sophisticated retry per-dest is post-launch
            # if customers ask).
            stats["total_failed"] = stats.get("total_failed", 0) + 1
            masked = mask_url_userinfo(url)
            raise RuntimeError(f"upstream HTTP {status} from {masked}")

    def status(self) -> dict[str, Any]:
        """Snapshot for the MCP / banner. NEVER includes any secret."""
        return {
            "configured": True,
            "route_count": len(self.config.routes),
            "engine_dropped": self._engine_dropped,
            "queue_depth": self._queue.qsize() if self._queue else 0,
            "routes": [
                {
                    "name": r.name,
                    "on_match": r.on_match,
                    "destinations": [d.masked() for d in r.destinations],
                    "destination_stats": [
                        self._stats.get((r.name, i), {})
                        for i in range(len(r.destinations))
                    ],
                }
                for r in self.config.routes
            ],
        }


def _mask_str(s: str) -> str:
    """Cheap defense — never let a stray "${SECRET}" or a bare token
    that crept into an error message leak. Conservative: replace any
    long high-entropy-looking token (>16 chars of [A-Za-z0-9_-]) with
    `<masked>`. Used only on error-message text we hand to the logger.
    """
    return re.sub(r"[A-Za-z0-9_\-]{16,}", "<masked>", s)


# ---------------------------------------------------------------------------
# PagerDuty / Slack payload builders
# ---------------------------------------------------------------------------


def _pagerduty_payload(
    event: dict, dest: PagerDutyDestination, *, product: str,
) -> dict[str, Any]:
    """Events API v2 enqueue payload. Documented at:
    https://developer.pagerduty.com/docs/events-api-v2/trigger-events/

    `routing_key` = integration key. `event_action` = trigger for now
    (the routes engine fires per-event; sophisticated dedup keys are
    a post-launch concern). Custom details carry the full OCSF event
    so the on-call engineer can drill in from the PagerDuty UI.
    """
    unmapped = event.get("unmapped") or {}
    iam_jit = unmapped.get("iam_jit") if isinstance(unmapped, dict) else None
    api = event.get("api") or {}
    operation = api.get("operation") if isinstance(api, dict) else ""
    severity = dest.severity
    summary_parts = [f"iam-jit {product}"]
    if isinstance(iam_jit, dict):
        evt_type = iam_jit.get("event_type")
        if evt_type:
            summary_parts.append(str(evt_type))
    if operation:
        summary_parts.append(str(operation))
    summary = " — ".join(summary_parts) or f"iam-jit {product} event"
    return {
        "routing_key": dest.integration_key,
        "event_action": "trigger",
        "payload": {
            "summary": summary[:1024],  # PagerDuty caps at 1024 chars.
            "source": f"iam-jit/{product}",
            "severity": severity,
            "custom_details": event,
        },
    }


def _slack_payload(event: dict, *, product: str) -> dict[str, Any]:
    """Incoming-webhook JSON payload. Documented at:
    https://api.slack.com/messaging/webhooks#posting_with_webhooks

    Per [[security-team-positioning-safety-not-surveillance]]: the
    one-line summary uses neutral language. Detail goes in the
    attachment fields so the Slack channel preview is operator-friendly
    without being alarmist.
    """
    unmapped = event.get("unmapped") or {}
    iam_jit = unmapped.get("iam_jit") if isinstance(unmapped, dict) else None
    api = event.get("api") or {}
    operation = api.get("operation") if isinstance(api, dict) else ""
    actor = event.get("actor") or {}
    user = actor.get("user") if isinstance(actor, dict) else None
    user_name = ""
    if isinstance(user, dict):
        user_name = user.get("name") or ""
    summary_parts = [f"iam-jit {product}"]
    if isinstance(iam_jit, dict):
        evt_type = iam_jit.get("event_type")
        if evt_type:
            summary_parts.append(str(evt_type))
    if operation:
        summary_parts.append(operation)
    if user_name:
        summary_parts.append(f"actor={user_name}")
    text = " — ".join(summary_parts) or f"iam-jit {product} event"
    return {"text": text}
