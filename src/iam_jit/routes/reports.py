"""Admin-only reporting endpoints.

GET /api/v1/reports/grants              All requests in any state, filterable
GET /api/v1/reports/activity            Per-user action timeline
GET /api/v1/reports/approvals           Per-approver decision log
GET /api/v1/reports/risk-distribution   Histogram of risk scores
GET /api/v1/reports/users               Current user list with last_action

All endpoints support `format=json` (default) or `format=csv`. CSV column
shape is stable across versions so audit tooling can be built against it.
"""

from __future__ import annotations

import csv
import io
import json
import os
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query, Response

from .. import audit
from ..middleware import get_request_store, get_user_store, require_admin
from ..store import RequestStore
from ..users_store import User, UserStore

router = APIRouter(prefix="/api/v1/reports", tags=["reports"])


def _parse_iso(s: str | None) -> str | None:
    return s


def _csv_response(rows: list[dict[str, Any]], columns: list[str]) -> Response:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=columns, extrasaction="ignore")
    writer.writeheader()
    for row in rows:
        writer.writerow({c: row.get(c) for c in columns})
    return Response(content=buf.getvalue(), media_type="text/csv")


def _all_requests(store: RequestStore) -> list[dict[str, Any]]:
    out = []
    for rid in store.list_ids():
        try:
            out.append(store.get(rid))
        except Exception:
            continue
    return out


def _flatten_grant(req: dict[str, Any]) -> dict[str, Any]:
    spec = req.get("spec") or {}
    metadata = req.get("metadata") or {}
    status_block = req.get("status") or {}
    review = status_block.get("review") or {}
    return {
        "id": metadata.get("id"),
        "owner": status_block.get("owner"),
        "state": status_block.get("state"),
        "access_type": spec.get("access_type"),
        "submitted_at": status_block.get("submitted_at"),
        "last_updated_at": status_block.get("last_updated_at"),
        "duration_hours": (spec.get("duration") or {}).get("duration_hours"),
        "not_after": (spec.get("duration") or {}).get("not_after"),
        "accounts": ",".join(
            a.get("account_id", "") for a in spec.get("accounts") or []
        ),
        "risk_score": review.get("risk_score"),
        "description_preview": (spec.get("description") or "")[:140],
    }


@router.get("/grants")
def grants_report(
    store: Annotated[RequestStore, Depends(get_request_store)],
    _: Annotated[User, Depends(require_admin)],
    state: str | None = None,
    since: str | None = None,
    until: str | None = None,
    account_id: str | None = None,
    requester_id: str | None = None,
    format: Annotated[str, Query(pattern="^(json|csv)$")] = "json",
) -> Any:
    rows: list[dict[str, Any]] = []
    for req in _all_requests(store):
        flat = _flatten_grant(req)
        if state and flat["state"] != state:
            continue
        if since and (flat.get("submitted_at") or "") < since:
            continue
        if until and (flat.get("submitted_at") or "") > until:
            continue
        if account_id and account_id not in (flat.get("accounts") or ""):
            continue
        if requester_id and flat.get("owner") != requester_id:
            continue
        rows.append(flat)
    columns = [
        "id",
        "owner",
        "state",
        "access_type",
        "submitted_at",
        "last_updated_at",
        "duration_hours",
        "not_after",
        "accounts",
        "risk_score",
        "description_preview",
    ]
    if format == "csv":
        return _csv_response(rows, columns)
    return {"rows": rows, "count": len(rows)}


@router.get("/activity")
def activity_report(
    store: Annotated[RequestStore, Depends(get_request_store)],
    _: Annotated[User, Depends(require_admin)],
    user_id: str,
    since: str | None = None,
    format: Annotated[str, Query(pattern="^(json|csv)$")] = "json",
) -> Any:
    rows: list[dict[str, Any]] = []
    for req in _all_requests(store):
        history = (req.get("status") or {}).get("history") or []
        comments = (req.get("status") or {}).get("comments") or []
        request_id = (req.get("metadata") or {}).get("id")
        for ev in history:
            if ev.get("by") != user_id:
                continue
            if since and (ev.get("at") or "") < since:
                continue
            rows.append(
                {
                    "request_id": request_id,
                    "kind": "history",
                    "action": ev.get("action"),
                    "from": ev.get("from"),
                    "to": ev.get("to"),
                    "at": ev.get("at"),
                    "reason": ev.get("reason"),
                }
            )
        for c in comments:
            if c.get("author") != user_id:
                continue
            if since and (c.get("posted_at") or "") < since:
                continue
            rows.append(
                {
                    "request_id": request_id,
                    "kind": "comment",
                    "action": "comment",
                    "from": None,
                    "to": None,
                    "at": c.get("posted_at"),
                    "reason": (c.get("message") or "")[:200],
                }
            )
    rows.sort(key=lambda r: r.get("at") or "")
    columns = ["request_id", "kind", "action", "from", "to", "at", "reason"]
    if format == "csv":
        return _csv_response(rows, columns)
    return {"rows": rows, "count": len(rows)}


@router.get("/approvals")
def approvals_report(
    store: Annotated[RequestStore, Depends(get_request_store)],
    _: Annotated[User, Depends(require_admin)],
    approver_id: str | None = None,
    since: str | None = None,
    format: Annotated[str, Query(pattern="^(json|csv)$")] = "json",
) -> Any:
    rows: list[dict[str, Any]] = []
    for req in _all_requests(store):
        history = (req.get("status") or {}).get("history") or []
        request_id = (req.get("metadata") or {}).get("id")
        submitted_at = (req.get("status") or {}).get("submitted_at")
        for ev in history:
            if ev.get("action") not in {"approve", "reject", "request_changes"}:
                continue
            if approver_id and ev.get("by") != approver_id:
                continue
            if since and (ev.get("at") or "") < since:
                continue
            rows.append(
                {
                    "request_id": request_id,
                    "approver": ev.get("by"),
                    "action": ev.get("action"),
                    "at": ev.get("at"),
                    "submitted_at": submitted_at,
                    "latency_seconds": _seconds_between(submitted_at, ev.get("at")),
                    "reason": ev.get("reason"),
                }
            )
    rows.sort(key=lambda r: r.get("at") or "")
    columns = ["request_id", "approver", "action", "at", "submitted_at", "latency_seconds", "reason"]
    if format == "csv":
        return _csv_response(rows, columns)
    return {"rows": rows, "count": len(rows)}


@router.get("/risk-distribution")
def risk_distribution(
    store: Annotated[RequestStore, Depends(get_request_store)],
    _: Annotated[User, Depends(require_admin)],
    since: str | None = None,
    format: Annotated[str, Query(pattern="^(json|csv)$")] = "json",
) -> Any:
    counts: dict[int, int] = {i: 0 for i in range(1, 11)}
    for req in _all_requests(store):
        review = ((req.get("status") or {}).get("review")) or {}
        if since and ((req.get("status") or {}).get("submitted_at") or "") < since:
            continue
        score = review.get("risk_score")
        if isinstance(score, int) and 1 <= score <= 10:
            counts[score] += 1
    rows = [{"risk_score": k, "count": v} for k, v in sorted(counts.items())]
    if format == "csv":
        return _csv_response(rows, ["risk_score", "count"])
    return {"rows": rows, "total": sum(counts.values())}


@router.get("/users")
def users_report(
    user_store: Annotated[UserStore, Depends(get_user_store)],
    _: Annotated[User, Depends(require_admin)],
    include_disabled: bool = False,
    format: Annotated[str, Query(pattern="^(json|csv)$")] = "json",
) -> Any:
    rows = [
        {
            "id": u.id,
            "display_name": u.display_name,
            "roles": ",".join(u.roles),
            "enabled": u.enabled,
        }
        for u in user_store.list(include_disabled=include_disabled)
    ]
    if format == "csv":
        return _csv_response(rows, ["id", "display_name", "roles", "enabled"])
    return {"rows": rows, "count": len(rows)}


@router.get("/audit-log")
def audit_log_report(
    _: Annotated[User, Depends(require_admin)],
    limit: int = 1000,
    kind: str | None = None,
    actor: str | None = None,
    format: Annotated[str, Query(pattern="^(json|csv)$")] = "json",
) -> Any:
    """Tail the hash-chained audit log, with optional filters.

    Each entry includes its sha256 chain hash. The `verified` field reports
    whether the chain re-hashed cleanly end-to-end — `false` (or a
    `first_bad_index`) means an entry was tampered with after write.
    """
    path = os.environ.get("IAM_JIT_AUDIT_LOG")
    events: list[dict[str, Any]] = []
    if path and os.path.exists(path):
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    events.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    ok, bad, reason = audit.verify_chain(events)
    filtered = events
    if kind:
        filtered = [e for e in filtered if e.get("kind") == kind]
    if actor:
        filtered = [e for e in filtered if e.get("actor") == actor]
    filtered = filtered[-limit:]
    if format == "csv":
        rows = [
            {
                "timestamp": e.get("timestamp"),
                "actor": e.get("actor"),
                "kind": e.get("kind"),
                "summary": e.get("summary"),
                "hash": e.get("hash"),
            }
            for e in filtered
        ]
        return _csv_response(rows, ["timestamp", "actor", "kind", "summary", "hash"])
    return {
        "events": filtered,
        "count": len(filtered),
        "verified": ok,
        "first_bad_index": bad,
        "verify_failure_reason": reason,
        "context_fingerprints_at_boot": dict(audit._BOOT_FINGERPRINTS),
        "context_drift": audit.detect_context_drift(),
    }


def _seconds_between(start: str | None, end: str | None) -> int | None:
    if not start or not end:
        return None
    try:
        import datetime as _dt

        s = _dt.datetime.fromisoformat(start.rstrip("Z"))
        e = _dt.datetime.fromisoformat(end.rstrip("Z"))
        return int((e - s).total_seconds())
    except Exception:
        return None
