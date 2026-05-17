"""SQLite-backed store for bouncer rules + decision audit log.

Schema (versioned via `schema_version` table — manual additive
migrations only, no ORM, no Alembic):

    schema_version(version INTEGER PRIMARY KEY)
    rules(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        pattern TEXT NOT NULL,
        effect TEXT NOT NULL,          -- 'allow' | 'deny'
        arn_scope TEXT,
        region_scope TEXT,
        note TEXT,
        origin TEXT NOT NULL DEFAULT 'user',
        created_at TEXT NOT NULL       -- ISO-8601 UTC
    )
    decisions(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        at TEXT NOT NULL,              -- ISO-8601 UTC
        decision TEXT NOT NULL,        -- 'allow' | 'deny' | 'prompt'
        mode TEXT NOT NULL,            -- 'learn' | 'enforce' | 'prompt'
        service TEXT NOT NULL,
        action TEXT NOT NULL,
        arn TEXT,
        region TEXT,
        matched_rule_id INTEGER,       -- nullable; FK to rules.id (soft FK)
        reason TEXT NOT NULL
    )

Per [[creates-never-mutates]]: this store mutates ONLY the bouncer's
own local SQLite DB. Nothing AWS-side, nothing user-IAM-side.

Per [[local-only-safety-mode]] + [[no-hosted-saas]]: defaults to
`~/.iam-jit/bouncer/state.db`. No phone-home; no telemetry.

Concurrency: SQLite handles intra-process serialization. The
foundation-slice's CLI is single-process; the Stage 2 HTTP proxy
server is also single-process. If a future Enterprise daemon adds
multi-process, switch to WAL + retry-on-busy (TODO when that lands).
"""

from __future__ import annotations

import datetime as _dt
import os
import pathlib
import sqlite3
import threading
from typing import Any

from .decisions import Decision, DecisionRecord, Mode
from .rules import Effect, ProxyRule, parse_pattern


class InvalidRuleError(ValueError):
    """Raised when add_rule() is given a pattern that can't be parsed.

    WB23 MED-23-02 closure: rules with malformed patterns silently
    never match anything, so a user who typos `s3-GetObject` (dash
    instead of colon) sees the rule in `rules list` but the rule
    never fires. Reject at insert time so the user sees the error
    immediately and isn't confused at decision time.
    """

SCHEMA_VERSION = 3  # v3: adds tasks table + task_id column on decisions for [[proxy-smart-defaults-and-task-scope]] Slice B


def default_db_path() -> pathlib.Path:
    """`~/.iam-jit/bouncer/state.db` unless `IAM_JIT_BOUNCER_DB` overrides."""
    override = os.environ.get("IAM_JIT_BOUNCER_DB")
    if override:
        return pathlib.Path(override)
    return pathlib.Path.home() / ".iam-jit" / "bouncer" / "state.db"


def _isoformat_z(dt: _dt.datetime) -> str:
    return dt.astimezone(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


class BouncerStore:
    """SQLite-backed persistence for rules + decisions."""

    def __init__(self, db_path: pathlib.Path | str | None = None) -> None:
        self.db_path = pathlib.Path(db_path) if db_path else default_db_path()
        # WB23 LOW-23-03 closure: `mkdir(mode=...)` only sets the leaf
        # dir's mode; intermediate parents (e.g. `~/.iam-jit/` if it
        # didn't already exist) stay at the OS umask default. Walk
        # the chain and chmod each segment we created.
        existed_before = self.db_path.parent.exists()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        if not existed_before:
            # Climb from leaf upward setting 0o700 on segments under
            # the user's HOME. We stop at HOME so we don't try to
            # chmod /Users/<x>/ or /home/<x>/ (the user owns those
            # but the OS may not want them touched).
            try:
                home = pathlib.Path.home().resolve()
                p = self.db_path.parent.resolve()
                while p != p.parent and p != home and home in p.parents:
                    p.chmod(0o700)
                    p = p.parent
            except (OSError, RuntimeError):
                # Best-effort: if we can't chmod (e.g. running on a
                # filesystem that ignores POSIX modes, or HOME
                # weirdness in tests), don't crash store init.
                pass
        self._lock = threading.Lock()
        self._conn = sqlite3.connect(
            str(self.db_path), check_same_thread=False, isolation_level=None
        )
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=OFF")  # soft FKs only
        self._migrate()

    # -----------------------------------------------------------------
    # Schema
    # -----------------------------------------------------------------

    def _migrate(self) -> None:
        with self._lock:
            self._conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS schema_version (
                    version INTEGER PRIMARY KEY
                );
                CREATE TABLE IF NOT EXISTS rules (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    pattern TEXT NOT NULL,
                    effect TEXT NOT NULL,
                    arn_scope TEXT,
                    region_scope TEXT,
                    note TEXT,
                    origin TEXT NOT NULL DEFAULT 'user',
                    created_at TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS decisions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    at TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    mode TEXT NOT NULL,
                    service TEXT NOT NULL,
                    action TEXT NOT NULL,
                    arn TEXT,
                    region TEXT,
                    matched_rule_id INTEGER,
                    reason TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_decisions_at ON decisions(at);
                CREATE INDEX IF NOT EXISTS idx_decisions_decision ON decisions(decision);
                -- v2: config_events log per [[agent-friendly-not-bypassable]] Lens B.
                -- Every config change (rule add/remove, mode switch, preset
                -- apply) writes a row here so the audit chain has no holes.
                -- There is intentionally NO "off switch" — even a future
                -- "disable" config knob would still write its enable/disable
                -- transitions here.
                CREATE TABLE IF NOT EXISTS config_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    at TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    kind TEXT NOT NULL,          -- 'rule_added' / 'rule_removed' / 'mode_changed' / 'preset_applied'
                    target_id INTEGER,           -- nullable; rule id when kind references a rule
                    summary TEXT NOT NULL,       -- short human description (kept in audit log forever)
                    detail_json TEXT             -- nullable; structured payload (pattern, old/new mode, etc.)
                );
                CREATE INDEX IF NOT EXISTS idx_config_events_at ON config_events(at);
                CREATE INDEX IF NOT EXISTS idx_config_events_kind ON config_events(kind);
                -- v3: tasks table for [[proxy-smart-defaults-and-task-scope]]
                -- Slice B. Agent declares a scoped task at start; bouncer
                -- enforces task allow + task deny rules for the duration;
                -- task lifecycle audit-logged via config_events too
                -- (kind=task_started / task_ended). Status moves
                -- active -> completed / expired / replaced.
                CREATE TABLE IF NOT EXISTS tasks (
                    task_id TEXT PRIMARY KEY,
                    description TEXT NOT NULL,
                    allow_rules_json TEXT NOT NULL,
                    deny_rules_json TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    started_by TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active',
                    ended_at TEXT,
                    ended_by TEXT,
                    end_reason TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
                CREATE INDEX IF NOT EXISTS idx_tasks_started_at ON tasks(started_at);
                """
            )
            # v3 additive migration: add task_id column to existing
            # decisions table if it's missing. ALTER TABLE ADD COLUMN
            # is idempotent-safe via try/except (SQLite raises on
            # duplicate column).
            try:
                self._conn.execute("ALTER TABLE decisions ADD COLUMN task_id TEXT")
            except sqlite3.OperationalError:
                pass
            cur = self._conn.execute("SELECT version FROM schema_version LIMIT 1")
            row = cur.fetchone()
            if row is None:
                self._conn.execute(
                    "INSERT INTO schema_version(version) VALUES (?)", (SCHEMA_VERSION,)
                )
            else:
                # Additive migration: bump the version if we're past it.
                # No DDL needed here since CREATE TABLE IF NOT EXISTS
                # handled the v2 addition above.
                if int(row[0]) < SCHEMA_VERSION:
                    self._conn.execute(
                        "UPDATE schema_version SET version = ?", (SCHEMA_VERSION,)
                    )

    # -----------------------------------------------------------------
    # Rules
    # -----------------------------------------------------------------

    def add_rule(self, rule: ProxyRule, *, actor: str = "cli") -> int:
        """Insert a rule. Returns the assigned id.

        WB23 MED-23-02 closure: validates `pattern` via parse_pattern
        before insert; raises InvalidRuleError on malformed input so
        the rule doesn't silently never-match.

        Per [[agent-friendly-not-bypassable]] Lens B: also writes a
        config_event row so the audit chain captures who added what
        rule when — even if the rule is later removed.
        """
        if parse_pattern(rule.pattern) is None:
            raise InvalidRuleError(
                f"invalid rule pattern {rule.pattern!r}: "
                "must be in 'service:action_glob' form, e.g. "
                "'s3:GetObject' or 's3:Put*'. Service must be a bare "
                "prefix (no wildcards); action may include '*'."
            )
        with self._lock:
            cur = self._conn.execute(
                """
                INSERT INTO rules(pattern, effect, arn_scope, region_scope, note, origin, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    rule.pattern,
                    rule.effect.value,
                    rule.arn_scope,
                    rule.region_scope,
                    rule.note,
                    rule.origin,
                    _isoformat_z(_dt.datetime.now(_dt.UTC)),
                ),
            )
            rid = int(cur.lastrowid or 0)
        self._record_config_event_locked(
            actor=actor,
            kind="rule_added",
            target_id=rid,
            summary=f"added rule #{rid}: {rule.effect.value} {rule.pattern}",
            detail=rule.to_dict(),
        )
        return rid

    def remove_rule(self, rule_id: int, *, actor: str = "cli") -> bool:
        """Delete a rule by id. Returns True if a row was removed.

        Per [[agent-friendly-not-bypassable]] Lens B: the audit chain
        records BOTH the deletion event AND the full content of the
        deleted rule, so post-incident review can answer 'what rule
        existed at time T'. Without this, an agent could
        rules-add-then-remove to cover its tracks.
        """
        # Capture the rule BEFORE deleting so the audit event is complete.
        prior = self.get_rule(rule_id)
        with self._lock:
            cur = self._conn.execute("DELETE FROM rules WHERE id = ?", (rule_id,))
            removed = cur.rowcount > 0
        if removed:
            self._record_config_event_locked(
                actor=actor,
                kind="rule_removed",
                target_id=rule_id,
                summary=(
                    f"removed rule #{rule_id}: "
                    f"{prior.effect.value} {prior.pattern}" if prior else
                    f"removed rule #{rule_id} (prior content unavailable)"
                ),
                detail=prior.to_dict() if prior else None,
            )
        return removed

    # -----------------------------------------------------------------
    # Config-event audit log (Lens B: nothing changes silently)
    # -----------------------------------------------------------------

    def _record_config_event_locked(
        self,
        *,
        actor: str,
        kind: str,
        summary: str,
        target_id: int | None = None,
        detail: dict[str, Any] | None = None,
    ) -> int:
        """Append a config-change event. Internal; called from
        add_rule / remove_rule / record_mode_change / etc. Holds the
        store lock itself; do NOT call from inside another locked
        section."""
        import json

        with self._lock:
            cur = self._conn.execute(
                """
                INSERT INTO config_events(at, actor, kind, target_id, summary, detail_json)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    _isoformat_z(_dt.datetime.now(_dt.UTC)),
                    actor,
                    kind,
                    target_id,
                    summary,
                    json.dumps(detail) if detail is not None else None,
                ),
            )
            return int(cur.lastrowid or 0)

    def record_mode_change(
        self, *, old_mode: str, new_mode: str, actor: str, reason: str | None = None
    ) -> int:
        """Record a mode-switch event. Per [[agent-friendly-not-bypassable]]
        Lens B: mode is a state transition, not a config knob. Callers
        flipping LEARN↔ENFORCE↔PROMPT MUST call this so the audit chain
        sees the transition."""
        return self._record_config_event_locked(
            actor=actor,
            kind="mode_changed",
            summary=f"mode: {old_mode} -> {new_mode}" + (f" ({reason})" if reason else ""),
            detail={"old_mode": old_mode, "new_mode": new_mode, "reason": reason},
        )

    def record_preset_applied(
        self, *, preset_name: str, rules_added: int, actor: str
    ) -> int:
        """Record that a preset baseline was applied (added N rules)."""
        return self._record_config_event_locked(
            actor=actor,
            kind="preset_applied",
            summary=f"preset '{preset_name}' applied ({rules_added} rules added)",
            detail={"preset_name": preset_name, "rules_added": rules_added},
        )

    def list_config_events(
        self, *, limit: int = 100, kind_filter: str | None = None
    ) -> list[dict[str, Any]]:
        """Return recent config events, newest first. Hard-cap mirrors
        list_decisions to keep CLI tails bounded."""
        import json

        capped_limit = max(1, min(int(limit), 10_000))
        sql = (
            "SELECT id, at, actor, kind, target_id, summary, detail_json "
            "FROM config_events"
        )
        params: tuple[Any, ...]
        if kind_filter is not None:
            sql += " WHERE kind = ?"
            params = (kind_filter,)
        else:
            params = ()
        sql += " ORDER BY id DESC LIMIT ?"
        params = params + (capped_limit,)
        with self._lock:
            cur = self._conn.execute(sql, params)
            rows = cur.fetchall()
        out: list[dict[str, Any]] = []
        for r in rows:
            rid, at, actor, kind, target_id, summary, detail_json = r
            detail = None
            if detail_json:
                try:
                    detail = json.loads(detail_json)
                except (ValueError, TypeError):
                    detail = None
            out.append({
                "id": int(rid),
                "at": at,
                "actor": actor,
                "kind": kind,
                "target_id": int(target_id) if target_id is not None else None,
                "summary": summary,
                "detail": detail,
            })
        return out

    def list_rules(self) -> list[tuple[int, ProxyRule]]:
        """Return all rules, skipping any with corrupt effect values.

        WB23 MED-23-01 closure: one bad row (e.g. `effect='foo'`
        inserted via a future migration that doesn't validate) used
        to crash the entire listing via `Effect("foo")` ValueError —
        making ALL rules invisible. Now: skip the bad row and log a
        warning so the operator notices via decision-log scan, but
        the rest of the ruleset stays usable. Caller code never
        depends on "every row in DB is loadable."
        """
        import logging

        logger = logging.getLogger(__name__)

        with self._lock:
            cur = self._conn.execute(
                "SELECT id, pattern, effect, arn_scope, region_scope, note, origin "
                "FROM rules ORDER BY id"
            )
            rows = cur.fetchall()
        out: list[tuple[int, ProxyRule]] = []
        for r in rows:
            rid, pattern, effect, arn_scope, region_scope, note, origin = r
            try:
                effect_enum = Effect(effect)
            except ValueError:
                logger.warning(
                    "skipping rule id=%s with malformed effect=%r; remove via "
                    "`iam-jit-bouncer rules remove %s` to clear the warning",
                    rid, effect, rid,
                )
                continue
            out.append((
                int(rid),
                ProxyRule(
                    pattern=pattern,
                    effect=effect_enum,
                    arn_scope=arn_scope,
                    region_scope=region_scope,
                    note=note,
                    origin=origin or "user",
                ),
            ))
        return out

    def get_rule(self, rule_id: int) -> ProxyRule | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT pattern, effect, arn_scope, region_scope, note, origin "
                "FROM rules WHERE id = ?",
                (rule_id,),
            )
            row = cur.fetchone()
        if row is None:
            return None
        pattern, effect, arn_scope, region_scope, note, origin = row
        return ProxyRule(
            pattern=pattern,
            effect=Effect(effect),
            arn_scope=arn_scope,
            region_scope=region_scope,
            note=note,
            origin=origin or "user",
        )

    # -----------------------------------------------------------------
    # Decisions / audit log
    # -----------------------------------------------------------------

    def record_decision(
        self,
        dec: DecisionRecord,
        *,
        matched_rule_id: int | None = None,
        task_id: str | None = None,
    ) -> int:
        """Persist a decision row.

        `task_id` is the active task at the time of the decision (per
        Slice B), or None if no task was active. Lets post-incident
        review answer "during task X, what calls were attempted and
        what were the outcomes?"
        """
        with self._lock:
            cur = self._conn.execute(
                """
                INSERT INTO decisions(at, decision, mode, service, action, arn, region, matched_rule_id, reason, task_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    _isoformat_z(_dt.datetime.now(_dt.UTC)),
                    dec.decision.value,
                    dec.mode.value,
                    dec.service,
                    dec.action,
                    dec.arn,
                    dec.region,
                    matched_rule_id,
                    dec.reason,
                    task_id,
                ),
            )
            return int(cur.lastrowid or 0)

    def list_decisions(
        self,
        *,
        limit: int = 100,
        decision_filter: Decision | None = None,
    ) -> list[dict[str, Any]]:
        """Return recent decisions, newest first. `limit` is hard-
        capped at 10_000 to keep the CLI tail bounded."""
        capped_limit = max(1, min(int(limit), 10_000))
        sql = (
            "SELECT id, at, decision, mode, service, action, arn, region, "
            "matched_rule_id, reason, task_id FROM decisions"
        )
        params: tuple[Any, ...]
        if decision_filter is not None:
            sql += " WHERE decision = ?"
            params = (decision_filter.value,)
        else:
            params = ()
        sql += " ORDER BY id DESC LIMIT ?"
        params = params + (capped_limit,)
        with self._lock:
            cur = self._conn.execute(sql, params)
            rows = cur.fetchall()
        out: list[dict[str, Any]] = []
        for r in rows:
            (rid, at, decision, mode, service, action, arn, region, matched_id, reason, task_id) = r
            out.append({
                "id": int(rid),
                "at": at,
                "decision": decision,
                "mode": mode,
                "service": service,
                "action": action,
                "arn": arn,
                "region": region,
                "matched_rule_id": int(matched_id) if matched_id is not None else None,
                "reason": reason,
                "task_id": task_id,
            })
        return out

    def count_decisions(self) -> int:
        with self._lock:
            cur = self._conn.execute("SELECT COUNT(*) FROM decisions")
            row = cur.fetchone()
        return int(row[0] if row else 0)

    # -----------------------------------------------------------------
    # Tasks (Slice B of [[proxy-smart-defaults-and-task-scope]])
    # -----------------------------------------------------------------

    def add_task(self, scope: Any, *, actor: str | None = None) -> str:
        """Persist a new task scope as ACTIVE.

        Caller responsibility: end any previously active task before
        calling add_task — concurrency is single-active-task in Slice B
        (Slice C may add per-PID concurrent tasks). This method does
        NOT check for active conflicts; the higher-level
        `start_task` flow does that.

        Also writes a `task_started` config_event so the audit chain
        captures the lifecycle.
        """
        import json as _json

        with self._lock:
            self._conn.execute(
                """
                INSERT INTO tasks(
                    task_id, description, allow_rules_json, deny_rules_json,
                    started_at, expires_at, started_by, status,
                    ended_at, ended_by, end_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    scope.task_id,
                    scope.description,
                    _json.dumps([r.to_dict() for r in scope.allow_rules]),
                    _json.dumps([r.to_dict() for r in scope.deny_rules]),
                    scope.started_at,
                    scope.expires_at,
                    scope.started_by,
                    scope.status.value,
                    scope.ended_at,
                    scope.ended_by,
                    scope.end_reason,
                ),
            )
        self._record_config_event_locked(
            actor=actor or scope.started_by,
            kind="task_started",
            target_id=None,
            summary=f"task {scope.task_id} started: {scope.description[:80]}",
            detail={
                "task_id": scope.task_id,
                "description": scope.description,
                "duration_until": scope.expires_at,
                "allow_rule_count": len(scope.allow_rules),
                "deny_rule_count": len(scope.deny_rules),
            },
        )
        return scope.task_id

    def get_active_task(self) -> Any | None:
        """Return the currently-active task scope, or None if no task
        is active. Auto-expires (writes back status='expired' + logs
        the event) if the wall-clock expiry has passed."""
        from .tasks import TaskScope, TaskStatus

        with self._lock:
            cur = self._conn.execute(
                """
                SELECT task_id, description, allow_rules_json, deny_rules_json,
                       started_at, expires_at, started_by, status,
                       ended_at, ended_by, end_reason
                FROM tasks
                WHERE status = 'active'
                ORDER BY started_at DESC
                LIMIT 1
                """
            )
            row = cur.fetchone()
        if row is None:
            return None
        scope = _row_to_task_scope(row)
        if scope.is_expired():
            # Auto-expire: write back + log + return None (caller sees
            # "no active task" rather than a stale one). Done OUTSIDE
            # the lock above so the _record_config_event re-acquires
            # cleanly.
            self._end_task_internal(
                scope.task_id,
                actor="auto-expire",
                end_reason="timeout",
                new_status=TaskStatus.EXPIRED,
            )
            return None
        return scope

    def get_task(self, task_id: str) -> Any | None:
        with self._lock:
            cur = self._conn.execute(
                """
                SELECT task_id, description, allow_rules_json, deny_rules_json,
                       started_at, expires_at, started_by, status,
                       ended_at, ended_by, end_reason
                FROM tasks WHERE task_id = ?
                """,
                (task_id,),
            )
            row = cur.fetchone()
        return _row_to_task_scope(row) if row is not None else None

    def list_tasks(
        self,
        *,
        limit: int = 50,
        status_filter: str | None = None,
    ) -> list[Any]:
        capped_limit = max(1, min(int(limit), 10_000))
        sql = (
            "SELECT task_id, description, allow_rules_json, deny_rules_json, "
            "started_at, expires_at, started_by, status, ended_at, ended_by, "
            "end_reason FROM tasks"
        )
        params: tuple[Any, ...]
        if status_filter is not None:
            sql += " WHERE status = ?"
            params = (status_filter,)
        else:
            params = ()
        sql += " ORDER BY started_at DESC LIMIT ?"
        params = params + (capped_limit,)
        with self._lock:
            cur = self._conn.execute(sql, params)
            rows = cur.fetchall()
        return [_row_to_task_scope(r) for r in rows]

    def end_task(
        self,
        task_id: str,
        *,
        actor: str,
        end_reason: str | None = None,
    ) -> bool:
        """End the named task (status -> completed). Returns True if a
        row was updated; False if the task didn't exist or was already
        ended."""
        from .tasks import TaskStatus

        return self._end_task_internal(
            task_id, actor=actor, end_reason=end_reason or "completed",
            new_status=TaskStatus.COMPLETED,
        )

    def _end_task_internal(
        self,
        task_id: str,
        *,
        actor: str,
        end_reason: str,
        new_status: Any,  # TaskStatus
    ) -> bool:
        ended_at = _isoformat_z(_dt.datetime.now(_dt.UTC))
        with self._lock:
            cur = self._conn.execute(
                """
                UPDATE tasks
                SET status = ?, ended_at = ?, ended_by = ?, end_reason = ?
                WHERE task_id = ? AND status = 'active'
                """,
                (new_status.value, ended_at, actor, end_reason, task_id),
            )
            updated = cur.rowcount > 0
        if updated:
            self._record_config_event_locked(
                actor=actor,
                kind="task_ended",
                target_id=None,
                summary=f"task {task_id} ended: {end_reason}",
                detail={
                    "task_id": task_id,
                    "status": new_status.value,
                    "end_reason": end_reason,
                    "ended_at": ended_at,
                },
            )
        return updated

    # -----------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def _row_to_task_scope(row) -> Any:
    """Reconstruct a TaskScope from a SQLite row. Lazy import keeps
    `tasks.py` and `store.py` independent at module load."""
    import json as _json
    from .tasks import TaskScope, TaskStatus
    from .rules import Effect, ProxyRule

    (
        task_id, description, allow_json, deny_json,
        started_at, expires_at, started_by, status,
        ended_at, ended_by, end_reason,
    ) = row

    def _decode_rules(blob: str, effect: Effect) -> tuple[ProxyRule, ...]:
        try:
            entries = _json.loads(blob) if blob else []
        except (ValueError, TypeError):
            return ()
        out: list[ProxyRule] = []
        for e in entries:
            if not isinstance(e, dict):
                continue
            out.append(ProxyRule(
                pattern=str(e.get("pattern") or ""),
                effect=effect,
                arn_scope=e.get("arn_scope"),
                region_scope=e.get("region_scope"),
                note=e.get("note"),
                origin=e.get("origin") or "task",
            ))
        return tuple(out)

    return TaskScope(
        task_id=task_id,
        description=description,
        allow_rules=_decode_rules(allow_json, Effect.ALLOW),
        deny_rules=_decode_rules(deny_json, Effect.DENY),
        started_at=started_at,
        expires_at=expires_at,
        started_by=started_by,
        status=TaskStatus(status),
        ended_at=ended_at,
        ended_by=ended_by,
        end_reason=end_reason,
    )
