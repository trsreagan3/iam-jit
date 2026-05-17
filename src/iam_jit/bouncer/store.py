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


class ActiveTaskExistsError(Exception):
    """WB26 HIGH-26-02 closure: raised by add_task when another task
    is already active. Caller decides whether to end the existing
    task first or surface the conflict to the agent."""

SCHEMA_VERSION = 5  # v5: adds pause_events table + decisions.pause_id for #6a timed-bypass audit linkage


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
                    end_reason TEXT,
                    owner TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_tasks_status ON tasks(status);
                CREATE INDEX IF NOT EXISTS idx_tasks_started_at ON tasks(started_at);
                -- v5: pause_events table for #6a `bouncer pause --for 30m`.
                -- Pauses are operator-controlled timed escape hatches that
                -- demote the proxy to COOPERATIVE mode for a window. Each
                -- pause is its OWN audit row (intentionally a separate
                -- table from decisions/config_events so reviewers can
                -- find "what windows did the operator open" with a
                -- single query). Per safety-mode-lean-permissive: the
                -- audit trail is doing the work; the bypass is fine
                -- precisely because every call during it is logged with
                -- pause_id linkage.
                CREATE TABLE IF NOT EXISTS pause_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    started_at TEXT NOT NULL,
                    ends_at TEXT NOT NULL,        -- expiry (UTC ISO)
                    reason TEXT NOT NULL DEFAULT '',
                    started_by TEXT NOT NULL,
                    -- Set when an operator explicitly `resume`s before
                    -- expiry. NULL until then.
                    ended_at_actual TEXT,
                    end_kind TEXT                 -- 'expired' / 'resumed_early' / NULL while live
                );
                CREATE INDEX IF NOT EXISTS idx_pause_events_ends_at ON pause_events(ends_at);
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
            # v4 additive migration: add owner column to tasks for
            # per-owner concurrent task scopes (Slice C of
            # [[proxy-smart-defaults-and-task-scope]]). Existing rows
            # get NULL owner — treated as "default owner" by the
            # match logic for backwards compat.
            #
            # WB27 HIGH-27-01 closure: ALTER and CREATE INDEX are in
            # SEPARATE try/except blocks. On a fresh DB, the inline
            # CREATE TABLE above already created the owner column;
            # ALTER then raises `duplicate column name`; if the index
            # statement were in the same except, the index would
            # silently never be created and every per-owner lookup
            # would degrade to a full table scan.
            try:
                self._conn.execute("ALTER TABLE tasks ADD COLUMN owner TEXT")
            except sqlite3.OperationalError:
                pass  # column already exists (fresh DB or re-migration)
            try:
                self._conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_tasks_owner_status ON tasks(owner, status)"
                )
            except sqlite3.OperationalError:
                pass
            # v5 additive migration: link each decision to the pause
            # event that was active at decision time (if any). Lets
            # post-hoc review answer "which decisions happened inside
            # pause N?" with a single JOIN. NULL when no pause active.
            try:
                self._conn.execute("ALTER TABLE decisions ADD COLUMN pause_id INTEGER")
            except sqlite3.OperationalError:
                pass
            try:
                self._conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_decisions_pause_id ON decisions(pause_id)"
                )
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

    def rule_exists(self, rule: ProxyRule) -> bool:
        """WB28 MED-28-02 closure: True iff an identical
        (pattern, effect, arn_scope, region_scope) row already exists.

        Callers (`bouncer_cli._apply_recommendations_via_cli` and
        `mcp_server._bouncer_apply_recommendation_for_mcp`) consult this
        before `add_rule` so re-running `recommend --apply` against
        unchanged traffic doesn't accumulate duplicate rule rows in
        the table over time.

        NULL-safe comparison: SQLite `IS` operator handles None
        (vs `= NULL` which is always-False).
        """
        with self._lock:
            cur = self._conn.execute(
                """
                SELECT 1 FROM rules
                WHERE pattern = ?
                  AND effect = ?
                  AND (arn_scope IS ? OR arn_scope = ?)
                  AND (region_scope IS ? OR region_scope = ?)
                LIMIT 1
                """,
                (
                    rule.pattern,
                    rule.effect.value,
                    rule.arn_scope, rule.arn_scope,
                    rule.region_scope, rule.region_scope,
                ),
            )
            return cur.fetchone() is not None

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
        pause_id: int | None = None,
    ) -> int:
        """Persist a decision row.

        `task_id` is the active task at the time of the decision (per
        Slice B), or None if no task was active.

        `pause_id` is the active pause window at decision time, or
        None if no pause is active. Lets reviewers ask "what calls
        happened inside the 30-minute pause window the operator
        opened at 14:32?" with a single SQL filter.

        WB26 MED-26-05 closure: if `task_id` is provided, we re-check
        atomically that the task is still status='active' at insert
        time. If it ended between the caller's `get_active_task` and
        this insert, we NULL out the task_id so the audit log doesn't
        falsely claim the call was "during task X" when X had already
        ended.
        """
        with self._lock:
            effective_task_id: str | None = task_id
            if task_id is not None:
                cur = self._conn.execute(
                    "SELECT status FROM tasks WHERE task_id = ?", (task_id,)
                )
                row = cur.fetchone()
                if row is None or row[0] != "active":
                    # Task was ended between get_active_task and the
                    # insert — don't lie in the audit log.
                    effective_task_id = None
            cur = self._conn.execute(
                """
                INSERT INTO decisions(at, decision, mode, service, action, arn, region, matched_rule_id, reason, task_id, pause_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    effective_task_id,
                    pause_id,
                ),
            )
            return int(cur.lastrowid or 0)

    # -----------------------------------------------------------------
    # Pauses (#6a — timed bypass / escape hatch)
    # -----------------------------------------------------------------

    def start_pause(
        self,
        *,
        duration_seconds: int,
        reason: str,
        started_by: str,
    ) -> int:
        """Open a new pause window. Returns the new pause id.

        Raises ValueError if another pause is already active —
        nested pauses are deliberately rejected so the audit trail
        always has a clean "started at X, ended at Y" pairing. To
        extend, resume + start a new one (each extension is its own
        row).
        """
        if duration_seconds <= 0:
            raise ValueError("pause duration must be > 0 seconds")
        if duration_seconds > 24 * 3600:
            # Cap at 24h. Per safety-mode-lean-permissive: short
            # windows + audit trail does the work. A 7-day pause is
            # an "I don't want the proxy" signal — they should
            # stop it instead.
            raise ValueError(
                "pause duration cannot exceed 24h; for longer windows "
                "stop the proxy and restart later"
            )
        now = _dt.datetime.now(_dt.UTC)
        ends = now + _dt.timedelta(seconds=duration_seconds)
        with self._lock:
            active = self._active_pause_locked()
            if active is not None:
                raise ValueError(
                    f"a pause is already active (id={active['id']}, "
                    f"ends_at={active['ends_at']}); resume first to "
                    f"start a new one"
                )
            cur = self._conn.execute(
                """
                INSERT INTO pause_events(started_at, ends_at, reason, started_by)
                VALUES (?, ?, ?, ?)
                """,
                (
                    _isoformat_z(now),
                    _isoformat_z(ends),
                    reason,
                    started_by,
                ),
            )
            return int(cur.lastrowid or 0)

    def end_pause(self, *, pause_id: int | None = None, ended_by: str = "cli") -> int | None:
        """Close the currently-active pause (or a specific pause by
        id if provided). Returns the pause id that was ended, or
        None if none was active. Sets end_kind = 'resumed_early' so
        post-hoc review can tell the difference between expirations
        and operator-initiated ends."""
        with self._lock:
            if pause_id is None:
                row = self._active_pause_locked()
                if row is None:
                    return None
                pause_id = int(row["id"])
            self._conn.execute(
                "UPDATE pause_events SET ended_at_actual = ?, end_kind = ? WHERE id = ? "
                "AND ended_at_actual IS NULL",
                (
                    _isoformat_z(_dt.datetime.now(_dt.UTC)),
                    "resumed_early",
                    pause_id,
                ),
            )
            return pause_id

    def get_active_pause(self) -> dict[str, Any] | None:
        """Return the live pause row if one is currently active
        (started, not yet expired, not yet manually ended). Returns
        a plain dict so callers don't need to import a dataclass.
        Also lazily marks expired-but-unended pauses as 'expired'
        so the audit log accurately records when each pause ended."""
        with self._lock:
            return self._active_pause_locked()

    def _active_pause_locked(self) -> dict[str, Any] | None:
        now_str = _isoformat_z(_dt.datetime.now(_dt.UTC))
        # Lazy garbage-collect: mark any not-explicitly-ended pause
        # whose ends_at is past as 'expired'. This is the only
        # mechanism that fires the auto-revert; no background timer
        # is required (works in tests, in serverless, anywhere).
        self._conn.execute(
            "UPDATE pause_events SET ended_at_actual = ends_at, "
            "end_kind = 'expired' "
            "WHERE ended_at_actual IS NULL AND ends_at <= ?",
            (now_str,),
        )
        cur = self._conn.execute(
            "SELECT id, started_at, ends_at, reason, started_by, "
            "ended_at_actual, end_kind "
            "FROM pause_events "
            "WHERE ended_at_actual IS NULL "
            "ORDER BY id DESC LIMIT 1"
        )
        row = cur.fetchone()
        if row is None:
            return None
        return {
            "id": int(row[0]),
            "started_at": row[1],
            "ends_at": row[2],
            "reason": row[3],
            "started_by": row[4],
            "ended_at_actual": row[5],
            "end_kind": row[6],
        }

    def list_recent_pauses(self, *, limit: int = 20) -> list[dict[str, Any]]:
        """Return the N most recent pause rows for `bouncer pause history`."""
        with self._lock:
            cur = self._conn.execute(
                "SELECT id, started_at, ends_at, reason, started_by, "
                "ended_at_actual, end_kind "
                "FROM pause_events ORDER BY id DESC LIMIT ?",
                (limit,),
            )
            rows = cur.fetchall()
        return [
            {
                "id": int(r[0]), "started_at": r[1], "ends_at": r[2],
                "reason": r[3], "started_by": r[4],
                "ended_at_actual": r[5], "end_kind": r[6],
            }
            for r in rows
        ]

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

        WB26 HIGH-26-02 closure: enforces the single-active-task
        invariant ATOMICALLY at the store layer. Previously the check
        lived only in the MCP / CLI wrappers (both non-atomic — a
        concurrent add could race past the check). Now: the INSERT
        and the active-conflict check happen under the same lock, so
        racing callers can't both succeed.

        Raises `ActiveTaskExistsError` if another task is already
        active (caller decides whether to end it + retry or surface
        the conflict to the agent).

        Also writes a `task_started` config_event so the audit chain
        captures the lifecycle.
        """
        import json as _json

        # Slice C: per-owner uniqueness. owner=None means
        # "default-owner slot" (Slice B compat — single-active task
        # on this machine when nobody declares owner explicitly).
        # Multiple concurrent tasks require declaring distinct
        # non-NULL owners.
        owner = scope.owner
        with self._lock:
            # Atomic per-OWNER single-active check — same lock as
            # INSERT below. Multiple concurrent tasks are now
            # allowed AS LONG AS each is for a different owner;
            # within a single owner, single-active still holds
            # (Slice B's invariant preserved at the per-owner
            # granularity).
            cur = self._conn.execute(
                "SELECT task_id FROM tasks WHERE status = 'active' "
                "AND (owner = ? OR (owner IS NULL AND ? IS NULL)) LIMIT 1",
                (owner, owner),
            )
            existing = cur.fetchone()
            if existing is not None:
                raise ActiveTaskExistsError(
                    f"another task is already active for owner {owner!r} "
                    f"({existing[0]}); end it before starting a new one"
                )
            self._conn.execute(
                """
                INSERT INTO tasks(
                    task_id, description, allow_rules_json, deny_rules_json,
                    started_at, expires_at, started_by, status,
                    ended_at, ended_by, end_reason, owner
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                    owner,
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

    def get_active_task(self, *, owner: str | None = None) -> Any | None:
        """Return the currently-active task scope for `owner`, or None
        if no task is active for that owner. Auto-expires (writes
        back status='expired' + logs the event) if the wall-clock
        expiry has passed.

        Slice C of [[proxy-smart-defaults-and-task-scope]]: `owner`
        filter lets multiple concurrent agent sessions each have
        their own task scope. `owner=None` means "match the default
        owner" (existing Slice B callers; preserves the single-active
        invariant for the default owner). To enumerate ALL active
        tasks regardless of owner, use `list_tasks(status_filter='active')`.
        """
        from .tasks import TaskScope, TaskStatus

        with self._lock:
            if owner is None:
                # Default-owner lookup: matches rows where owner IS NULL.
                cur = self._conn.execute(
                    """
                    SELECT task_id, description, allow_rules_json, deny_rules_json,
                           started_at, expires_at, started_by, status,
                           ended_at, ended_by, end_reason, owner
                    FROM tasks
                    WHERE status = 'active' AND owner IS NULL
                    ORDER BY started_at DESC
                    LIMIT 1
                    """
                )
            else:
                cur = self._conn.execute(
                    """
                    SELECT task_id, description, allow_rules_json, deny_rules_json,
                           started_at, expires_at, started_by, status,
                           ended_at, ended_by, end_reason, owner
                    FROM tasks
                    WHERE status = 'active' AND owner = ?
                    ORDER BY started_at DESC
                    LIMIT 1
                    """,
                    (owner,),
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
                       ended_at, ended_by, end_reason, owner
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
        owner: str | None = None,
    ) -> list[Any]:
        """List tasks. Slice C: `owner` filter narrows to a specific
        owner's tasks. If owner is None, returns all owners' tasks."""
        capped_limit = max(1, min(int(limit), 10_000))
        sql = (
            "SELECT task_id, description, allow_rules_json, deny_rules_json, "
            "started_at, expires_at, started_by, status, ended_at, ended_by, "
            "end_reason, owner FROM tasks"
        )
        where_clauses: list[str] = []
        params: list[Any] = []
        if status_filter is not None:
            where_clauses.append("status = ?")
            params.append(status_filter)
        if owner is not None:
            where_clauses.append("owner = ?")
            params.append(owner)
        if where_clauses:
            sql += " WHERE " + " AND ".join(where_clauses)
        sql += " ORDER BY started_at DESC LIMIT ?"
        params.append(capped_limit)
        with self._lock:
            cur = self._conn.execute(sql, tuple(params))
            rows = cur.fetchall()
        return [_row_to_task_scope(r) for r in rows]

    def end_task(
        self,
        task_id: str,
        *,
        actor: str,
        end_reason: str | None = None,
        requesting_owner: str | None = None,
        require_owner_match: bool = False,
    ) -> bool:
        """End the named task (status -> completed). Returns True if a
        row was updated; False if the task didn't exist, was already
        ended, OR `require_owner_match=True` and the task's owner
        doesn't match `requesting_owner`.

        WB27 HIGH-27-02 closure: when `require_owner_match=True`, the
        caller (typically MCP, passing the agent's claimed owner)
        must own the task to end it. Prevents cross-owner end-task
        in multi-session deployments. Single-laptop deployments
        keep using require_owner_match=False so the local CLI / admin
        flow stays simple.
        """
        from .tasks import TaskStatus

        if require_owner_match:
            existing = self.get_task(task_id)
            if existing is None:
                return False
            # NULL owner can only be ended by NULL-owner callers
            # (preserves default-owner slot's Slice B semantics).
            if existing.owner != requesting_owner:
                raise PermissionError(
                    f"task {task_id} is owned by {existing.owner!r}; "
                    f"caller owner is {requesting_owner!r}"
                )

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
    # Per-task review (Slice C of [[proxy-smart-defaults-and-task-scope]])
    # -----------------------------------------------------------------

    REVIEW_DENIED_CALL_CAP = 1000  # WB27 MED-27-01: bound the denied-calls list

    def task_review_summary(
        self,
        task_id: str,
        *,
        requesting_owner: str | None = None,
        require_owner_match: bool = False,
    ) -> dict[str, Any]:
        """Aggregate decisions made during a specific task into a
        review summary: total calls, allow/deny breakdown, denied
        action list, time range. Returns {} if the task doesn't
        exist or no decisions were recorded under it.

        Per Slice C: admins run `iam-jit-bouncer tasks review <id>`
        post-task to see what the agent actually attempted. This is
        the "after-action report" for a task scope — shows whether
        the scope was right-sized (lots of denies = too narrow; lots
        of allows but no use = too broad).

        WB27 HIGH-27-02 closure: when `require_owner_match=True`
        (MCP path passes the agent's claimed owner), only the task's
        own owner can review it. Cross-owner access raises
        PermissionError. Single-laptop / CLI flow keeps False.

        WB27 MED-27-01 closure: the denied_calls list is capped at
        REVIEW_DENIED_CALL_CAP (1000) entries with a `denied_calls_truncated`
        flag so a runaway task can't produce a multi-megabyte response.
        Total counts (allow/deny/prompt) are still accurate; only
        the per-call detail list is bounded.
        """
        scope = self.get_task(task_id)
        if scope is None:
            return {}
        if require_owner_match and scope.owner != requesting_owner:
            raise PermissionError(
                f"task {task_id} is owned by {scope.owner!r}; "
                f"caller owner is {requesting_owner!r}"
            )
        with self._lock:
            cur = self._conn.execute(
                "SELECT decision, service, action, arn, reason, at "
                "FROM decisions WHERE task_id = ? ORDER BY id",
                (task_id,),
            )
            rows = cur.fetchall()
        total = len(rows)
        allow = sum(1 for r in rows if r[0] == "allow")
        deny = sum(1 for r in rows if r[0] == "deny")
        prompt = sum(1 for r in rows if r[0] == "prompt")
        denied: list[dict[str, Any]] = []
        for r in rows:
            if r[0] == "deny":
                denied.append({
                    "service": r[1], "action": r[2], "arn": r[3],
                    "reason": r[4], "at": r[5],
                })
        first_at = rows[0][5] if rows else None
        last_at = rows[-1][5] if rows else None
        # WB27 MED-27-01: cap the denied_calls list; preserve total counts.
        denied_truncated = len(denied) > self.REVIEW_DENIED_CALL_CAP
        if denied_truncated:
            denied = denied[: self.REVIEW_DENIED_CALL_CAP]
        return {
            "task_id": task_id,
            "description": scope.description,
            "status": scope.status.value,
            "started_at": scope.started_at,
            "expires_at": scope.expires_at,
            "ended_at": scope.ended_at,
            "end_reason": scope.end_reason,
            "owner": scope.owner,
            "decision_count": total,
            "allow_count": allow,
            "deny_count": deny,
            "prompt_count": prompt,
            "first_decision_at": first_at,
            "last_decision_at": last_at,
            "denied_calls": denied,
            "denied_calls_truncated": denied_truncated,
            "denied_calls_cap": self.REVIEW_DENIED_CALL_CAP,
        }

    # -----------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------

    def close(self) -> None:
        with self._lock:
            self._conn.close()


def _row_to_task_scope(row) -> Any:
    """Reconstruct a TaskScope from a SQLite row. Lazy import keeps
    `tasks.py` and `store.py` independent at module load.

    Row tuple shape (Slice C): adds trailing `owner` column.
    Backwards-compat: if the row is 11 elements (pre-v4 stored
    schema cached in some test fixtures), default owner to None.
    """
    import json as _json
    from .tasks import TaskScope, TaskStatus
    from .rules import Effect, ProxyRule

    if len(row) == 12:
        (
            task_id, description, allow_json, deny_json,
            started_at, expires_at, started_by, status,
            ended_at, ended_by, end_reason, owner,
        ) = row
    else:
        (
            task_id, description, allow_json, deny_json,
            started_at, expires_at, started_by, status,
            ended_at, ended_by, end_reason,
        ) = row
        owner = None

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
        owner=owner,
    )
