# ADOPT-1 / #715 — CycloneDX 1.6 ABOM builder (pure functions).
"""Project a merged OCSF event stream for ONE session into a CycloneDX
1.6 JSON "Agent Bill of Materials".

No I/O, no LLM, no inference. Every component in the output is
countable off the input event stream. The event-walking helpers
mirror :mod:`iam_jit.agent_diff.diff` and the classifier field-path
map in :mod:`iam_jit.cli_audit_query` so the ABOM's notion of a
"resource" / "namespace" / "database" / "endpoint" matches what the
rest of the audit surfaces already report (no divergent extraction).
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import hashlib
import re
import typing
import uuid

# CycloneDX 1.6 constants.
CYCLONEDX_SPEC_VERSION = "1.6"
_BOM_FORMAT = "CycloneDX"

# All iam-jit-specific component + metadata properties live under this
# namespace so a generic CycloneDX consumer (Dependency-Track, the
# cyclonedx-cli validator) ignores them cleanly while an iam-jit-aware
# reader can pull the IAM / K8s / DB / endpoint specifics back out.
ABOM_PROPERTY_NS = "iam-jit"

# Tool metadata stamped into the BOM so a consumer can attribute the
# artifact. Component reference (bom-ref) for the agent session root.
_TOOL_VENDOR = "iam-jit"
_TOOL_NAME = "iam-jit abom"


# ---------------------------------------------------------------------------
# Event-walking helpers (mirror agent_diff.diff + cli_audit_query
# classifier paths so the ABOM extraction does not drift from the rest
# of the audit surface).
# ---------------------------------------------------------------------------


def _walk(ev: dict[str, typing.Any], path: str) -> typing.Any:
    cur: typing.Any = ev
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
        if cur is None:
            return None
    return cur


def _first_str(ev: dict[str, typing.Any], paths: typing.Sequence[str]) -> str | None:
    """Return the first non-empty string value among ``paths``."""
    for p in paths:
        v = _walk(ev, p)
        if v is None:
            continue
        if not isinstance(v, str):
            v = str(v)
        v = v.strip()
        if v:
            return v
    return None


# Field-path catalogs. These intentionally overlap with
# ``cli_audit_query._CLASSIFIER_FIELD_PATHS`` — bouncers vary in WHICH
# OCSF path they populate, so we probe several and take the first hit.
_ROLE_PATHS = (
    "unmapped.iam_jit.role_arn",
    "unmapped.iam_jit.role",
    "unmapped.iam_jit.role_name",
    "actor.session.uid",
)
_PROFILE_PATHS = ("unmapped.iam_jit.profile",)
_SERVICE_PATHS = ("api.service.name",)
_OPERATION_PATHS = ("api.operation",)
_NAMESPACE_PATHS = (
    "unmapped.iam_jit.namespace",
    "resources.0.namespace",
)
_DATABASE_PATHS = (
    "unmapped.iam_jit.database",
    "dst_endpoint.svc_name",
)
_HOST_PATHS = (
    "dst_endpoint.hostname",
    "unmapped.iam_jit.host",
)
_MCP_TOOL_PATHS = (
    "unmapped.iam_jit.mcp.tool",
    "unmapped.iam_jit.tool_name",
)
_ACCOUNT_PATHS = ("cloud.account.uid", "unmapped.iam_jit.account_id")
_REGION_PATHS = ("cloud.region", "unmapped.iam_jit.region")
_CLUSTER_PATHS = ("unmapped.iam_jit.cluster", "cloud.zone")


def _event_action(ev: dict[str, typing.Any]) -> str | None:
    """``service:Action`` form. Mirrors agent_diff.diff._event_action."""
    op = _first_str(ev, _OPERATION_PATHS)
    if op and ":" in op:
        return op
    service = _first_str(ev, _SERVICE_PATHS)
    if op and service:
        return f"{service}:{op}"
    return op


def _event_resources(ev: dict[str, typing.Any]) -> list[str]:
    """Best-effort resource (ARN/uid/name) extraction. Mirrors
    agent_diff.diff._event_resources."""
    out: list[str] = []
    for container in ("resources", None):
        seq = ev.get(container) if container else _walk(ev, "api.resources")
        if isinstance(seq, list):
            for r in seq:
                if not isinstance(r, dict):
                    continue
                cand = r.get("uid") or r.get("name")
                if isinstance(cand, str) and cand.strip():
                    out.append(cand.strip())
        if out:
            return out
    return out


def _event_verdict(ev: dict[str, typing.Any]) -> str | None:
    v = _walk(ev, "unmapped.iam_jit.verdict")
    if isinstance(v, str):
        v = v.strip().lower()
        if v in ("allow", "deny"):
            return v
    return None


def _event_bouncer(ev: dict[str, typing.Any]) -> str | None:
    b = ev.get("_bouncer")
    if isinstance(b, str) and b.strip():
        return b.strip()
    name = _walk(ev, "metadata.product.name")
    if isinstance(name, str) and name.strip():
        return name.strip()
    return None


def _event_time_ms(ev: dict[str, typing.Any]) -> int | None:
    """OCSF ``time`` (Unix ms) as int, or ``None`` when the field is
    absent / non-numeric. A ``None`` here is NOT a swallowed error: the
    sole caller filters Nones out of the observed-window computation
    and a missing timestamp simply doesn't contribute a window bound.
    Parsing is done with a guard (no try/except positive-return) so the
    intent is explicit rather than hidden in an exception handler."""
    t = ev.get("time")
    if isinstance(t, bool):
        return None
    if isinstance(t, (int, float)):
        return int(t)
    if isinstance(t, str):
        s = t.strip()
        # Accept an int or float literal only; reject anything else
        # without throwing (a malformed time string is data, not a
        # program error).
        cleaned = s.lstrip("+-").replace(".", "", 1)
        if cleaned.isdigit():
            return int(float(s))
        return None
    return None


# ---------------------------------------------------------------------------
# Aggregation
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class _Agg:
    """Mutable accumulator for one ``(component_type, key)`` group."""

    name: str
    count: int = 0
    verdicts: typing.Counter[str] = dataclasses.field(
        default_factory=lambda: typing.Counter()
    )
    bouncers: set[str] = dataclasses.field(default_factory=set)
    actions: set[str] = dataclasses.field(default_factory=set)
    resources: set[str] = dataclasses.field(default_factory=set)
    extra: dict[str, str] = dataclasses.field(default_factory=dict)

    def observe(self, ev: dict[str, typing.Any]) -> None:
        self.count += 1
        v = _event_verdict(ev)
        if v:
            self.verdicts[v] += 1
        b = _event_bouncer(ev)
        if b:
            self.bouncers.add(b)


@dataclasses.dataclass(frozen=True)
class AbomResult:
    """The built ABOM plus the honesty signals the caller surfaces."""

    document: dict[str, typing.Any]
    """The CycloneDX 1.6 JSON document (ready for json.dumps)."""

    component_count: int
    """Total entities enumerated = ``components[]`` + ``services[]``.

    Named ``component_count`` for backwards compatibility; it counts
    every distinct thing the session touched regardless of which
    CycloneDX array it landed in (data components vs network services).
    """
    events_analyzed: int
    is_partial: bool
    partial_reasons: tuple[str, ...]

    def as_dict(self) -> dict[str, typing.Any]:
        return dict(self.document)


def _prop(name: str, value: str) -> dict[str, str]:
    return {"name": f"{ABOM_PROPERTY_NS}:{name}", "value": value}


def _bom_ref(kind: str, key: str) -> str:
    """Deterministic, collision-resistant bom-ref. CycloneDX requires
    bom-ref uniqueness within a document; a hash of (kind, key) keeps
    refs stable across runs for the same session input."""
    h = hashlib.sha256(f"{kind}|{key}".encode("utf-8")).hexdigest()[:16]
    return f"{kind}:{h}"


def _agg_props(iam_jit_kind: str, agg: _Agg) -> list[dict[str, str]]:
    """Shared ``iam-jit:*`` property list for a component OR service.

    Identical for both representations — the only difference between a
    ``data`` component and a ``services[]`` entry is the envelope, not
    the observed-activity properties.
    """
    props: list[dict[str, str]] = [
        _prop("component.kind", iam_jit_kind),
        _prop("observed.event_count", str(agg.count)),
    ]
    if agg.verdicts:
        props.append(_prop("observed.allow_count", str(agg.verdicts.get("allow", 0))))
        props.append(_prop("observed.deny_count", str(agg.verdicts.get("deny", 0))))
    if agg.bouncers:
        props.append(
            _prop("observed.bouncers", ",".join(sorted(agg.bouncers)))
        )
    if agg.actions:
        props.append(_prop("observed.actions", ",".join(sorted(agg.actions))))
    if agg.resources:
        props.append(
            _prop("observed.resources", ",".join(sorted(agg.resources)))
        )
    for k, v in sorted(agg.extra.items()):
        props.append(_prop(k, v))
    return props


def _component(
    *,
    ctype: str,
    name: str,
    bom_ref: str,
    iam_jit_kind: str,
    agg: _Agg,
) -> dict[str, typing.Any]:
    """Build one CycloneDX ``component`` dict.

    Components here are credential/config/resource artifacts the agent
    session touched: the IAM role/profile it ran under, AWS resource
    ARNs, K8s namespaces, and databases. Per CycloneDX 1.6 these are
    NOT software and have no native ``type``; we use ``data`` (a legal
    ``component.type`` enum value) and disambiguate the iam-jit notion
    via ``iam-jit:component.kind``.

    Things the agent *calls over a network* — AWS service APIs, HTTP
    endpoints, MCP tools — are NOT components: CycloneDX models those
    in the top-level ``services[]`` array (see :func:`_service`), since
    ``service`` is deliberately absent from the ``component.type`` enum.
    """
    comp: dict[str, typing.Any] = {
        "type": ctype,
        "bom-ref": bom_ref,
        "name": name,
        "properties": _agg_props(iam_jit_kind, agg),
    }
    return comp


def _service(
    *,
    name: str,
    bom_ref: str,
    iam_jit_kind: str,
    agg: _Agg,
) -> dict[str, typing.Any]:
    """Build one CycloneDX 1.6 ``service`` dict (top-level ``services[]``).

    Per the CycloneDX 1.6 ``#/definitions/service`` schema, a service
    entry has NO ``type`` field (``additionalProperties: false``); the
    only required key is ``name``. We carry the same ``iam-jit:*``
    observed-activity properties as the data components so an
    iam-jit-aware reader sees identical signal regardless of envelope,
    while a generic consumer (Dependency-Track / cyclonedx-cli) treats
    these as the network services the agent invoked.
    """
    return {
        "bom-ref": bom_ref,
        "name": name,
        "properties": _agg_props(iam_jit_kind, agg),
    }


_LOOPBACK_RE = re.compile(
    r"^(127\.\d+\.\d+\.\d+|localhost|::1)(:\d+)?$",
    re.IGNORECASE,
)


def _is_proxy_own_host(host: str) -> bool:
    """Return True when ``host`` is a loopback address (the bouncer's own
    listen socket), so it is NOT emitted as an upstream service in the ABOM.

    ibounce listens on ``127.0.0.1:<port>`` by default. When an agent
    sends a request to the proxy itself (e.g. a plan-capture or ghost-run
    synthetic) the ``dst_endpoint.hostname`` in the resulting audit event
    carries the proxy's OWN listen host — not a real upstream AWS service.
    Emitting that as a ``services[]`` entry would misclassify the proxy's
    own socket as an external dependency. The filter covers:
      - ``127.x.x.x``  (IPv4 loopback range)
      - ``localhost``   (canonical loopback hostname, case-insensitive)
      - ``::1``         (IPv6 loopback)
    each optionally suffixed by ``:<port>``. Genuine upstream AWS service
    hostnames (``s3.us-east-1.amazonaws.com``, ``ec2.eu-west-1.amazonaws.com``,
    etc.) never match these patterns.
    """
    return bool(_LOOPBACK_RE.match(host.strip()))


def _aggregate(
    events: typing.Sequence[dict[str, typing.Any]],
) -> dict[str, dict[str, _Agg]]:
    """Group events by component type then by component key.

    Returns ``{component_kind: {key: _Agg}}`` where component_kind is
    one of: ``iam_role`` / ``iam_profile`` / ``aws_service`` /
    ``aws_resource`` / ``k8s_namespace`` / ``database`` /
    ``http_endpoint`` / ``mcp_tool``.
    """
    groups: dict[str, dict[str, _Agg]] = {
        "iam_role": {},
        "iam_profile": {},
        "aws_service": {},
        "aws_resource": {},
        "k8s_namespace": {},
        "database": {},
        "http_endpoint": {},
        "mcp_tool": {},
    }

    def _bump(kind: str, key: str, ev: dict[str, typing.Any]) -> _Agg:
        bucket = groups[kind]
        agg = bucket.get(key)
        if agg is None:
            agg = _Agg(name=key)
            bucket[key] = agg
        agg.observe(ev)
        return agg

    for ev in events:
        if not isinstance(ev, dict):
            continue
        action = _event_action(ev)
        service = _first_str(ev, _SERVICE_PATHS)
        resources = _event_resources(ev)

        role = _first_str(ev, _ROLE_PATHS)
        if role:
            agg = _bump("iam_role", role, ev)
            if action:
                agg.actions.add(action)
            for r in resources:
                agg.resources.add(r)

        profile = _first_str(ev, _PROFILE_PATHS)
        if profile:
            _bump("iam_profile", profile, ev)

        if service:
            agg = _bump("aws_service", service, ev)
            if action:
                agg.actions.add(action)

        for r in resources:
            # Only ARN-shaped resources count as AWS resource
            # components; bare hostnames flow through the endpoint
            # bucket instead.
            if r.startswith("arn:"):
                _bump("aws_resource", r, ev)

        ns = _first_str(ev, _NAMESPACE_PATHS)
        if ns:
            agg = _bump("k8s_namespace", ns, ev)
            cluster = _first_str(ev, _CLUSTER_PATHS)
            if cluster:
                agg.extra["k8s.cluster"] = cluster

        db = _first_str(ev, _DATABASE_PATHS)
        if db:
            agg = _bump("database", db, ev)
            host = _first_str(ev, _HOST_PATHS)
            if host:
                agg.extra["db.host"] = host
            if action:
                agg.actions.add(action)

        # HTTP endpoint: a destination host that is NOT also a DB
        # service name (gbounce L7 egress). A bare hostname with no
        # database field is treated as an external endpoint.
        # Exclude loopback addresses (127.x.x.x / localhost / ::1) —
        # those are the bouncer's OWN listen socket, not an upstream
        # service. See _is_proxy_own_host().
        host = _first_str(ev, _HOST_PATHS)
        if host and not db and not _is_proxy_own_host(host):
            agg = _bump("http_endpoint", host, ev)
            method = _first_str(ev, ("http_request.http_method",))
            if method:
                agg.actions.add(method)

        tool = _first_str(ev, _MCP_TOOL_PATHS)
        if tool:
            _bump("mcp_tool", tool, ev)

    return groups


# Map iam-jit kind -> (CycloneDX envelope, ref-prefix). The envelope
# is either a legal ``component.type`` enum value ("data") for
# credential/config/resource artifacts, or the sentinel
# ``_SERVICE_ENVELOPE`` for the three network-service kinds (AWS
# service APIs, HTTP endpoints, MCP tools). CycloneDX 1.6 deliberately
# omits "service" from the ``component.type`` enum — services belong in
# the top-level ``services[]`` array (#/definitions/service) — so those
# three kinds are emitted there, NOT as components. (This is the bug
# the original map carried: it set component.type="service", which is
# not schema-valid and made Dependency-Track / cyclonedx-cli reject the
# doc.)
_SERVICE_ENVELOPE = "__service__"
_KIND_TO_CYCLONEDX: dict[str, tuple[str, str]] = {
    "iam_role": ("data", "iam-role"),
    "iam_profile": ("data", "iam-profile"),
    "aws_service": (_SERVICE_ENVELOPE, "aws-service"),
    "aws_resource": ("data", "aws-resource"),
    "k8s_namespace": ("data", "k8s-namespace"),
    "database": ("data", "database"),
    "http_endpoint": (_SERVICE_ENVELOPE, "http-endpoint"),
    "mcp_tool": (_SERVICE_ENVELOPE, "mcp-tool"),
}


def _iso_now() -> str:
    return (
        _dt.datetime.now(_dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _ms_to_iso(ms: int) -> str:
    return (
        _dt.datetime.fromtimestamp(ms / 1000.0, tz=_dt.timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def build_abom(
    *,
    session_id: str,
    events: typing.Sequence[dict[str, typing.Any]],
    requested_window: dict[str, str] | None = None,
    notes: typing.Sequence[str] = (),
    bouncers_queried: typing.Sequence[str] = (),
    generated_at: str | None = None,
) -> AbomResult:
    """Build a CycloneDX 1.6 ABOM for ``session_id`` from ``events``.

    Pure function — ``events`` is the already-merged OCSF stream from
    the cross-bouncer fan-out. ``notes`` carries per-bouncer fan-out
    notes (unreachable bouncers, etc.) so the partial-data signal is
    honest. ``requested_window`` is the operator's ``{from, to}`` so
    the document can say what window was *asked for* vs what was
    observed.

    Returns an :class:`AbomResult`. The CycloneDX document always has
    the required top-level fields (``bomFormat``, ``specVersion``,
    ``serialNumber``, ``metadata``, ``components``) even for an empty
    session — an empty session is a valid ABOM with zero components,
    explicitly flagged partial.
    """
    ts = generated_at or _iso_now()

    groups = _aggregate(events)

    components: list[dict[str, typing.Any]] = []
    services: list[dict[str, typing.Any]] = []
    # Deterministic order: by kind (stable map order) then by name.
    for kind, (envelope, ref_prefix) in _KIND_TO_CYCLONEDX.items():
        bucket = groups.get(kind, {})
        for key in sorted(bucket):
            agg = bucket[key]
            bom_ref = _bom_ref(ref_prefix, key)
            if envelope == _SERVICE_ENVELOPE:
                services.append(
                    _service(
                        name=key,
                        bom_ref=bom_ref,
                        iam_jit_kind=kind,
                        agg=agg,
                    )
                )
            else:
                components.append(
                    _component(
                        ctype=envelope,
                        name=key,
                        bom_ref=bom_ref,
                        iam_jit_kind=kind,
                        agg=agg,
                    )
                )

    # Operator-facing count = everything enumerated, regardless of which
    # CycloneDX array it lands in (components vs services). This keeps
    # the "how many things did this session touch" number honest and
    # stable across the spec-correctness refactor.
    entity_count = len(components) + len(services)

    events_analyzed = sum(1 for ev in events if isinstance(ev, dict))

    # Observed time window (off the events themselves) — distinct from
    # the requested window so a reader can see if the data only covers
    # part of the asked-for range.
    times = [
        t
        for t in (
            _event_time_ms(ev) for ev in events if isinstance(ev, dict)
        )
        if t is not None
    ]
    observed_from = _ms_to_iso(min(times)) if times else None
    observed_to = _ms_to_iso(max(times)) if times else None

    # ---- Honesty / partial-data determination -------------------
    partial_reasons: list[str] = []
    if events_analyzed == 0:
        partial_reasons.append(
            "no_events_observed: the audit log returned zero events for "
            "this session in the queried window — this ABOM enumerates "
            "nothing observed, NOT a proof the agent did nothing"
        )
    # Fan-out notes that name an unreachable / errored bouncer mean the
    # picture is missing whatever that bouncer would have contributed.
    note_list = [n for n in notes if isinstance(n, str) and n.strip()]
    if note_list:
        partial_reasons.append(
            "bouncer_gaps: one or more bouncers were unreachable or "
            "errored during the query; their activity (if any) is "
            "absent from this ABOM. See iam-jit:observed.notes"
        )
    is_partial = bool(partial_reasons)

    serial_number = "urn:uuid:" + str(
        uuid.uuid5(
            uuid.NAMESPACE_URL,
            f"iam-jit-abom:{session_id}:{ts}",
        )
    )

    # ---- metadata.properties (iam-jit namespace) ----------------
    meta_props: list[dict[str, str]] = [
        _prop("session.id", session_id),
        _prop("observed.events_analyzed", str(events_analyzed)),
        _prop("observed.component_count", str(entity_count)),
        _prop("observed.complete", "false" if is_partial else "true"),
    ]
    if requested_window:
        if requested_window.get("from"):
            meta_props.append(
                _prop("requested.window.from", str(requested_window["from"]))
            )
        if requested_window.get("to"):
            meta_props.append(
                _prop("requested.window.to", str(requested_window["to"]))
            )
    if observed_from:
        meta_props.append(_prop("observed.window.from", observed_from))
    if observed_to:
        meta_props.append(_prop("observed.window.to", observed_to))
    if bouncers_queried:
        meta_props.append(
            _prop(
                "observed.bouncers_queried",
                ",".join(str(b) for b in bouncers_queried),
            )
        )
    for n in note_list:
        meta_props.append(_prop("observed.notes", n))
    # Always-present human-readable disclaimer per
    # [[ibounce-honest-positioning]] — never imply completeness.
    meta_props.append(
        _prop(
            "observed.disclaimer",
            "This ABOM enumerates ONLY activity observed in the iam-jit "
            "audit log for this session within the queried window. It is "
            "evidence of what was seen, not a proof of completeness; "
            "audit gaps, short windows, or unreachable bouncers can omit "
            "real activity. Check iam-jit:observed.complete.",
        )
    )

    document: dict[str, typing.Any] = {
        "bomFormat": _BOM_FORMAT,
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "serialNumber": serial_number,
        "version": 1,
        "metadata": {
            "timestamp": ts,
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": _TOOL_NAME,
                        "publisher": _TOOL_VENDOR,
                    }
                ]
            },
            # The "subject" of this BOM is the agent session itself.
            "component": {
                "type": "application",
                "bom-ref": _bom_ref("agent-session", session_id),
                "name": f"agent-session:{session_id}",
                "properties": [
                    _prop("component.kind", "agent_session"),
                    _prop("session.id", session_id),
                ],
            },
            "properties": meta_props,
        },
        "components": components,
    }
    # Only emit ``services`` when non-empty: an empty list is legal
    # under the schema but the array is optional, and omitting it keeps
    # the empty-session ABOM minimal.
    if services:
        document["services"] = services

    return AbomResult(
        document=document,
        component_count=entity_count,
        events_analyzed=events_analyzed,
        is_partial=is_partial,
        partial_reasons=tuple(partial_reasons),
    )
