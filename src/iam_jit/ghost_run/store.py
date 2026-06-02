"""Ghost-run persistence: the captured "would-mutate" diff on disk.

Layout (per the #728 spec):

    ~/.iam-jit/ghost-runs/<SID>/
        meta.json       # session header (started_by, started_at, upstream)
        actions.jsonl   # one JSON record per captured would-be mutation

Each line in ``actions.jsonl`` is one structured would-mutate record:
the service, action, IAM-projected access type, target (ARN / resource
hint), the request params we could parse, and the synthetic response we
handed back to the agent so it kept going. NOTHING here was forwarded
to AWS — that is the load-bearing invariant of ghost mode.

This is deliberately a FLAT-FILE store (not SQLite) so the module is
fully self-contained and conflict-free against the rest of the bouncer:
ghost mode never touches the shared BouncerStore schema. It mirrors the
plan-capture JSONL contract (see ``iam_jit.plan_capture``) in spirit —
one append-only line per call — so existing tooling habits transfer.

Per [[creates-never-mutates]] + [[ibounce-honest-positioning]]: the
synthetic response shapes are FAKE. We record ``synthetic: true`` and a
``honesty`` note on every record so a reviewer is never misled into
thinking a real resource id exists. ``apply`` is intentionally a manual,
operator-driven surface (#728 ``shadow apply``) — ghost mode itself
never mutates anything.
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import json
import os
import pathlib
from typing import Any, Iterator


SCHEMA_VERSION = "iam-jit.dev/ghost-run/v1"

# Same defensive ceilings as plan_capture's reader: a single captured
# API call should never need megabytes; reject pathological lines so a
# corrupted / hostile transcript can't OOM the review surface.
_MAX_LINE_BYTES = 1 * 1024 * 1024            # 1 MB per JSONL line
_MAX_FILE_BYTES = 256 * 1024 * 1024          # 256 MB total per actions file


class GhostRunError(Exception):
    """Raised when a ghost-run file fails validation or IO."""


@dataclasses.dataclass(frozen=True)
class GhostAction:
    """One captured would-be mutation. Mirrors the on-disk JSONL shape.

    ``action_id`` is a stable, per-session monotonic id (``act-0001``,
    ``act-0002``, ...) so ``shadow apply SID --action act-0003`` can name
    a single intended mutation. ``synthetic`` is always True in ghost
    mode (the response we handed the agent was fabricated, never from
    AWS); the field exists so the wire format stays explicit per
    [[ibounce-honest-positioning]]."""

    action_id: str
    ts: str
    method: str
    service: str
    action: str
    access_type: str
    region: str | None
    target: str | None
    params: dict[str, Any]
    synthetic_response: dict[str, Any]
    synthetic: bool = True
    honesty: str = (
        "GHOST: this mutation was NOT executed against AWS. The "
        "synthetic_response is fabricated — any resource id in it is "
        "fake. Review + apply manually if intended."
    )


def runs_root() -> pathlib.Path:
    """Root directory for all ghost-run transcripts.

    Resolution order (mirrors the rest of iam-jit's path conventions):
      1. ``IAM_JIT_GHOST_RUNS_DIR`` — explicit override (tests + ops).
      2. ``IAM_JIT_DATA_DIR``/ghost-runs — the shared data-dir override
         the doctor + other modules already honor.
      3. ``~/.iam-jit/ghost-runs`` — the documented default per spec.
    """
    explicit = os.environ.get("IAM_JIT_GHOST_RUNS_DIR")
    if explicit:
        return pathlib.Path(explicit)
    data_dir = os.environ.get("IAM_JIT_DATA_DIR")
    base = (
        pathlib.Path(data_dir)
        if data_dir
        else pathlib.Path.home() / ".iam-jit"
    )
    return base / "ghost-runs"


def session_dir(session_id: str) -> pathlib.Path:
    """Directory for one ghost-run session.

    Defends against path traversal: ``session_id`` must be a single
    safe path component (the sessions module enforces the same charset
    when minting / pinning ids, but we re-check here because the store
    is callable independently, e.g. by the review CLI passing an
    operator-typed id)."""
    if session_id in (".", "..") or any(
        c in session_id for c in ("/", "\\", "\x00")
    ):
        raise GhostRunError(
            f"unsafe ghost-run session id {session_id!r}"
        )
    return runs_root() / session_id


class GhostRunStore:
    """Append-only filesystem store for one or more ghost-run sessions.

    Thread-safety: the proxy hot-path calls :meth:`capture` from a
    single asyncio event loop, so appends are serialized by the loop.
    We still open + close the file per append (O_APPEND) rather than
    holding a handle, which keeps the store stateless + robust to a
    crashed proxy (no half-written buffered lines)."""

    def ensure_session(
        self,
        session_id: str,
        *,
        started_by: str = "local",
        upstream: str | None = None,
        read_only: bool = True,
        note: str = "",
    ) -> pathlib.Path:
        """Create the session directory + write meta.json if absent.

        Idempotent — re-calling for an existing session leaves the
        existing meta.json untouched (so the original ``started_at`` is
        preserved across proxy restarts that resume the same id)."""
        d = session_dir(session_id)
        d.mkdir(parents=True, exist_ok=True)
        meta_path = d / "meta.json"
        if not meta_path.exists():
            meta = {
                "schema": SCHEMA_VERSION,
                "session_id": session_id,
                "started_by": started_by,
                "started_at": _now_iso(),
                "upstream": upstream,
                "read_only": read_only,
                "note": note,
                "mode": "ghost",
            }
            _atomic_write_json(meta_path, meta)
        return d

    def capture(
        self,
        session_id: str,
        *,
        method: str,
        service: str,
        action: str,
        access_type: str,
        region: str | None,
        target: str | None,
        params: dict[str, Any] | None,
        synthetic_response: dict[str, Any] | None,
    ) -> GhostAction:
        """Append one captured would-be mutation. Returns the record.

        The caller is responsible for having decided this is a WRITE
        (or unknown-treated-as-write) call; ``capture`` does not
        classify. It assigns the next ``action_id`` and appends a JSONL
        line. It NEVER forwards anything — persistence only."""
        d = self.ensure_session(session_id)
        actions_path = d / "actions.jsonl"
        next_n = self._next_action_number(actions_path)
        rec = GhostAction(
            action_id=f"act-{next_n:04d}",
            ts=_now_iso(),
            method=method,
            service=service,
            action=action,
            access_type=access_type,
            region=region,
            target=target,
            params=dict(params or {}),
            synthetic_response=dict(synthetic_response or {}),
        )
        line = json.dumps(_action_to_dict(rec), separators=(",", ":")) + "\n"
        # O_APPEND single write — atomic on POSIX for sub-PIPE_BUF
        # payloads, and even for larger ones the worst case is a
        # trailing partial line the reader skips (it validates JSON).
        with open(actions_path, "a", encoding="utf-8") as f:
            f.write(line)
        return rec

    def read_actions(self, session_id: str) -> list[GhostAction]:
        """Read all captured actions for a session, in capture order.

        Skips blank/trailing lines. Raises GhostRunError on an
        oversized line or a malformed (non-skippable) record so a
        corrupted transcript surfaces loudly rather than silently
        dropping intended mutations."""
        d = session_dir(session_id)
        actions_path = d / "actions.jsonl"
        if not actions_path.exists():
            return []
        out: list[GhostAction] = []
        total = 0
        with open(actions_path, "r", encoding="utf-8") as f:
            for lineno, line in enumerate(f, start=1):
                if not line.strip():
                    continue
                line_bytes = len(line.encode("utf-8"))
                if line_bytes > _MAX_LINE_BYTES:
                    raise GhostRunError(
                        f"{actions_path}: line {lineno} exceeds "
                        f"{_MAX_LINE_BYTES} bytes; transcript looks "
                        f"corrupted/hostile"
                    )
                total += line_bytes
                if total > _MAX_FILE_BYTES:
                    raise GhostRunError(
                        f"{actions_path}: exceeds {_MAX_FILE_BYTES} "
                        f"bytes; refusing to load"
                    )
                out.append(_action_from_line(line, lineno=lineno))
        return out

    def read_meta(self, session_id: str) -> dict[str, Any]:
        """Return the session header dict, or {} when no meta exists."""
        meta_path = session_dir(session_id) / "meta.json"
        if not meta_path.exists():
            return {}
        try:
            return json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as e:
            raise GhostRunError(f"{meta_path}: unreadable meta ({e})")

    def list_sessions(self) -> list[dict[str, Any]]:
        """List recorded ghost-run sessions with per-session roll-ups.

        Returns newest-first (ids are time-sortable). Each entry:
        ``{session_id, started_at, started_by, upstream, captured_writes}``.
        """
        root = runs_root()
        if not root.exists():
            return []
        rows: list[dict[str, Any]] = []
        for child in root.iterdir():
            if not child.is_dir():
                continue
            sid = child.name
            try:
                meta = self.read_meta(sid)
                n = len(self.read_actions(sid))
            except GhostRunError:
                # A corrupt session shouldn't hide the rest of the
                # list; surface it with an explicit error marker.
                meta = {}
                n = -1
            rows.append(
                {
                    "session_id": sid,
                    "started_at": meta.get("started_at", ""),
                    "started_by": meta.get("started_by", ""),
                    "upstream": meta.get("upstream"),
                    "captured_writes": n,
                }
            )
        rows.sort(key=lambda r: r["session_id"], reverse=True)
        return rows

    def diff(self, session_id: str) -> dict[str, Any]:
        """Build a review-friendly diff summary for one session.

        Returns the session meta plus the full ordered action list and
        small roll-ups (count, by_service, by_action). This is the
        single shape the ``shadow diff`` CLI + the MCP tool both
        render, so operators + agents see identical data."""
        meta = self.read_meta(session_id)
        actions = self.read_actions(session_id)
        by_service: dict[str, int] = {}
        by_action: dict[str, int] = {}
        for a in actions:
            by_service[a.service] = by_service.get(a.service, 0) + 1
            key = f"{a.service}:{a.action}"
            by_action[key] = by_action.get(key, 0) + 1
        return {
            "session_id": session_id,
            "meta": meta,
            "captured_writes": len(actions),
            "by_service": by_service,
            "by_action": by_action,
            "actions": [_action_to_dict(a) for a in actions],
            "honesty": (
                "None of these mutations were executed against AWS. "
                "Synthetic responses are fabricated."
            ),
        }

    def get_action(
        self, session_id: str, action_id: str
    ) -> GhostAction | None:
        """Return a single captured action by id, or None."""
        for a in self.read_actions(session_id):
            if a.action_id == action_id:
                return a
        return None

    @staticmethod
    def _next_action_number(actions_path: pathlib.Path) -> int:
        """Next 1-based action number = (#existing non-blank lines)+1."""
        if not actions_path.exists():
            return 1
        n = 0
        with open(actions_path, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    n += 1
        return n + 1


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------
def _action_to_dict(a: GhostAction) -> dict[str, Any]:
    return {
        "schema": SCHEMA_VERSION,
        "action_id": a.action_id,
        "ts": a.ts,
        "method": a.method,
        "service": a.service,
        "action": a.action,
        "access_type": a.access_type,
        "region": a.region,
        "target": a.target,
        "params": a.params,
        "synthetic": a.synthetic,
        "synthetic_response": a.synthetic_response,
        "honesty": a.honesty,
    }


def _action_from_line(line: str, *, lineno: int) -> GhostAction:
    try:
        data = json.loads(line)
    except json.JSONDecodeError as e:
        raise GhostRunError(f"line {lineno}: invalid JSON ({e})")
    if data.get("schema") != SCHEMA_VERSION:
        raise GhostRunError(
            f"line {lineno}: unsupported schema {data.get('schema')!r}"
        )
    try:
        return GhostAction(
            action_id=data["action_id"],
            ts=data["ts"],
            method=data.get("method", ""),
            service=data["service"],
            action=data["action"],
            access_type=data.get("access_type", "unknown"),
            region=data.get("region"),
            target=data.get("target"),
            params=data.get("params", {}),
            synthetic_response=data.get("synthetic_response", {}),
            synthetic=data.get("synthetic", True),
            honesty=data.get("honesty", GhostAction.honesty),
        )
    except KeyError as e:
        raise GhostRunError(f"line {lineno}: missing field {e}")


def _now_iso() -> str:
    return _dt.datetime.now(_dt.UTC).isoformat().replace("+00:00", "Z")


def _atomic_write_json(path: pathlib.Path, obj: dict[str, Any]) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2), encoding="utf-8")
    os.replace(tmp, path)


def read_actions(session_id: str) -> list[GhostAction]:
    """Module-level convenience wrapper around GhostRunStore.read_actions."""
    return GhostRunStore().read_actions(session_id)


def list_sessions() -> list[dict[str, Any]]:
    """Module-level convenience wrapper around GhostRunStore.list_sessions."""
    return GhostRunStore().list_sessions()


def diff(session_id: str) -> dict[str, Any]:
    """Module-level convenience wrapper around GhostRunStore.diff."""
    return GhostRunStore().diff(session_id)
