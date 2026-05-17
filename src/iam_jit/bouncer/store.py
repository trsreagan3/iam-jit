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

SCHEMA_VERSION = 9  # v9: adds sync_wait_id to pending_prompts for #203 sync deny-prompt UX


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
                -- v6: pending_prompts for #5 async deny-prompt UX.
                -- When transparent-mode DENY fires and the operator
                -- opted into prompt_on_deny, the deny is also written
                -- here so the operator can later answer (allow always
                -- / add to profile / ignore). The async v1.0 flow:
                -- agent gets denied immediately; operator sees the
                -- queue + answers; future calls use the new rule.
                -- The sync v1.1 flow will REUSE this table by having
                -- the proxy poll status briefly before returning.
                CREATE TABLE IF NOT EXISTS pending_prompts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    decision_id INTEGER NOT NULL,
                    service TEXT NOT NULL,
                    action TEXT NOT NULL,
                    arn TEXT,
                    region TEXT,
                    deny_reason TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'pending',  -- pending|answered|ignored
                    answer_kind TEXT,                         -- always|profile|ignore
                    answer_target TEXT,                       -- profile name when kind=profile
                    answered_by TEXT,
                    answered_at TEXT
                );
                CREATE INDEX IF NOT EXISTS idx_pending_prompts_status ON pending_prompts(status);
                CREATE INDEX IF NOT EXISTS idx_pending_prompts_created_at ON pending_prompts(created_at);
                -- v7: plan-capture mode (#132). plan_sessions is the
                -- header table — one row per `ibounce serve --mode
                -- plan-capture` invocation (or per --plan-session-id).
                -- plan_calls records every intercepted SDK call (with
                -- the verdict the bouncer assigned + the synthetic
                -- shape it returned). Sessions live forever in the
                -- store; `ibounce plan list` / `show` / `export` read
                -- from these tables. Per [[ibounce-honest-positioning]]:
                -- the transcript is for OPERATOR PREVIEW, not security
                -- (an adversarial agent can detect plan-capture).
                CREATE TABLE IF NOT EXISTS plan_sessions (
                    session_id TEXT PRIMARY KEY,
                    started_at TEXT NOT NULL,
                    started_by TEXT NOT NULL,
                    note TEXT NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_plan_sessions_started_at ON plan_sessions(started_at);
                CREATE TABLE IF NOT EXISTS plan_calls (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    at TEXT NOT NULL,                 -- ISO-8601 UTC
                    decision_id INTEGER,              -- soft FK -> decisions.id
                    method TEXT NOT NULL,
                    host TEXT NOT NULL,
                    path TEXT NOT NULL,
                    service TEXT NOT NULL,
                    action TEXT NOT NULL,
                    region TEXT,
                    arn TEXT,
                    verdict TEXT NOT NULL,            -- allow|deny|prompt|unsupported
                    would_have_called TEXT NOT NULL,  -- canonical "service:Action"
                    would_have_returned_json TEXT,    -- nullable; structured synthetic summary
                    supported INTEGER NOT NULL DEFAULT 1
                );
                CREATE INDEX IF NOT EXISTS idx_plan_calls_session ON plan_calls(session_id, id);
                CREATE INDEX IF NOT EXISTS idx_plan_calls_verdict ON plan_calls(session_id, verdict);
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
            # v8 additive migrations (#145 plan-capture read->write switch):
            #
            # plan_sessions gains a `phase` column tracking the session's
            # write-switch state machine:
            #   read_only        — initial state; no write call observed yet
            #   write_pending    — first write call seen + operator notified
            #                      (manual mode); awaiting prompt answer
            #   writes_approved  — operator explicitly approved further writes,
            #                      OR --write-switch-notify=auto-approve flipped
            #                      on first write
            #   writes_rejected  — operator rejected, OR
            #                      --write-switch-notify=reject flipped
            #                      on first write
            # We also persist when the first write was observed (for `plan
            # show` + JSON export), which notify mode the session uses (so
            # post-hoc readers can see what UX was active), and the answer
            # context (decision + answered_at + answered_by).
            for col_ddl in (
                "ALTER TABLE plan_sessions ADD COLUMN phase TEXT NOT NULL DEFAULT 'read_only'",
                "ALTER TABLE plan_sessions ADD COLUMN write_switch_notify TEXT NOT NULL DEFAULT 'manual'",
                "ALTER TABLE plan_sessions ADD COLUMN first_write_at TEXT",
                "ALTER TABLE plan_sessions ADD COLUMN write_decision TEXT",
                "ALTER TABLE plan_sessions ADD COLUMN write_decision_at TEXT",
                "ALTER TABLE plan_sessions ADD COLUMN write_decision_by TEXT",
            ):
                try:
                    self._conn.execute(col_ddl)
                except sqlite3.OperationalError:
                    pass
            # pending_prompts gains a `kind` discriminator + a `session_id`
            # so plan-write prompts (#145) share the same queue + answer
            # surface as deny-prompts (#5) but are distinguishable.
            # decision_id is nullable for plan-write prompts (they have a
            # session_id instead of a decision_id) so we relax the schema
            # on existing DBs by leaving NOT NULL on the column but adding
            # a soft convention: store the synthetic value -1 when a
            # plan-write prompt is added (decision_id is still indexed +
            # used by deny-prompts' idempotency check; for plan-write we
            # use the session_id + status combination instead).
            for col_ddl in (
                "ALTER TABLE pending_prompts ADD COLUMN kind TEXT NOT NULL DEFAULT 'deny-prompt'",
                "ALTER TABLE pending_prompts ADD COLUMN session_id TEXT",
            ):
                try:
                    self._conn.execute(col_ddl)
                except sqlite3.OperationalError:
                    pass
            try:
                self._conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_pending_prompts_kind "
                    "ON pending_prompts(kind, status)"
                )
            except sqlite3.OperationalError:
                pass
            try:
                self._conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_pending_prompts_session "
                    "ON pending_prompts(session_id, status)"
                )
            except sqlite3.OperationalError:
                pass
            # v9 additive migration (#203 — synchronous deny-prompt UX):
            #
            # pending_prompts gains a `sync_wait_id` TEXT column. When the
            # proxy enqueues a deny-prompt in SYNC mode (--sync-prompt-on-
            # deny), it mints a UUID, stores it on the row, and registers
            # an in-process asyncio.Event keyed by that UUID before
            # blocking the request. The `prompts answer` CLI looks up the
            # sync_wait_id on the row at answer time + signals the Event
            # so the proxy coroutine wakes up + returns the operator's
            # decision.
            #
            # NULL on every existing row (async deny-prompts + plan-write
            # prompts never enqueue with a sync_wait_id). The column is
            # also indexed for the by-id lookup the wake path needs.
            try:
                self._conn.execute(
                    "ALTER TABLE pending_prompts ADD COLUMN sync_wait_id TEXT"
                )
            except sqlite3.OperationalError:
                pass
            try:
                self._conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_pending_prompts_sync_wait "
                    "ON pending_prompts(sync_wait_id)"
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
                    "`ibounce rules remove %s` to clear the warning",
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
        # MED-33-06 closure: reason is operator-supplied free text;
        # cap length + strip control chars so a misbehaving caller
        # can't bloat the audit row or sneak newlines through into
        # monitor parsers.
        reason = "".join(
            ch for ch in (reason or "")
            if ch == " " or (32 <= ord(ch) < 127)
        )[:500]
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

    # -----------------------------------------------------------------
    # Pending prompts (#5 — async deny-prompt UX, v1.0 subset)
    # -----------------------------------------------------------------

    def add_pending_prompt(
        self,
        *,
        decision_id: int,
        service: str,
        action: str,
        arn: str | None,
        region: str | None,
        deny_reason: str,
    ) -> int:
        """Insert a pending-prompt row for a transparent-mode DENY
        the operator has opted in to be notified about. Returns the
        new prompt id. Idempotent on (decision_id) — re-calling with
        the same decision_id is a no-op + returns the existing id."""
        with self._lock:
            cur = self._conn.execute(
                "SELECT id FROM pending_prompts WHERE decision_id = ?",
                (decision_id,),
            )
            prior = cur.fetchone()
            if prior is not None:
                return int(prior[0])
            cur = self._conn.execute(
                """
                INSERT INTO pending_prompts(
                    created_at, decision_id, service, action, arn, region,
                    deny_reason
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    _isoformat_z(_dt.datetime.now(_dt.UTC)),
                    decision_id, service, action, arn, region, deny_reason,
                ),
            )
            return int(cur.lastrowid or 0)

    def list_pending_prompts(self, *, status: str = "pending",
                              limit: int = 50,
                              kind: str | None = None) -> list[dict[str, Any]]:
        """Return prompts in the given status; newest first.

        #145: when `kind` is supplied, filter to that prompt-kind
        (`deny-prompt` or `plan-write`). Omitting `kind` returns BOTH
        kinds — `ibounce prompts list` uses this to render a unified
        queue with kind labels per row.
        """
        with self._lock:
            if kind is None:
                cur = self._conn.execute(
                    "SELECT id, created_at, decision_id, service, action, "
                    "arn, region, deny_reason, status, answer_kind, "
                    "answer_target, answered_by, answered_at, "
                    "kind, session_id, sync_wait_id "
                    "FROM pending_prompts WHERE status = ? "
                    "ORDER BY id DESC LIMIT ?",
                    (status, limit),
                )
            else:
                cur = self._conn.execute(
                    "SELECT id, created_at, decision_id, service, action, "
                    "arn, region, deny_reason, status, answer_kind, "
                    "answer_target, answered_by, answered_at, "
                    "kind, session_id, sync_wait_id "
                    "FROM pending_prompts WHERE status = ? AND kind = ? "
                    "ORDER BY id DESC LIMIT ?",
                    (status, kind, limit),
                )
            rows = cur.fetchall()
        return [
            {
                "id": int(r[0]), "created_at": r[1], "decision_id": int(r[2]),
                "service": r[3], "action": r[4], "arn": r[5], "region": r[6],
                "deny_reason": r[7], "status": r[8], "answer_kind": r[9],
                "answer_target": r[10], "answered_by": r[11], "answered_at": r[12],
                "kind": r[13] or "deny-prompt", "session_id": r[14],
                "sync_wait_id": r[15],
            }
            for r in rows
        ]

    def get_pending_prompt(self, prompt_id: int) -> dict[str, Any] | None:
        with self._lock:
            cur = self._conn.execute(
                "SELECT id, created_at, decision_id, service, action, "
                "arn, region, deny_reason, status, answer_kind, "
                "answer_target, answered_by, answered_at, "
                "kind, session_id, sync_wait_id "
                "FROM pending_prompts WHERE id = ?",
                (prompt_id,),
            )
            r = cur.fetchone()
        if r is None:
            return None
        return {
            "id": int(r[0]), "created_at": r[1], "decision_id": int(r[2]),
            "service": r[3], "action": r[4], "arn": r[5], "region": r[6],
            "deny_reason": r[7], "status": r[8], "answer_kind": r[9],
            "answer_target": r[10], "answered_by": r[11], "answered_at": r[12],
            "kind": r[13] or "deny-prompt", "session_id": r[14],
            "sync_wait_id": r[15],
        }

    def answer_pending_prompt(
        self,
        prompt_id: int,
        *,
        answer_kind: str,
        answer_target: str | None,
        answered_by: str,
    ) -> bool:
        """Record an answer on a pending prompt. Returns True if the
        prompt was found + pending; False if it was already answered
        or doesn't exist. Side-effects (rule add / profile edit) are
        the CLI's responsibility — store just records intent."""
        if answer_kind not in ("always", "profile", "ignore"):
            raise ValueError(
                f"answer_kind must be one of: always, profile, ignore "
                f"(got {answer_kind!r})"
            )
        with self._lock:
            cur = self._conn.execute(
                "UPDATE pending_prompts SET status = 'answered', "
                "answer_kind = ?, answer_target = ?, answered_by = ?, "
                "answered_at = ? "
                "WHERE id = ? AND status = 'pending'",
                (
                    answer_kind, answer_target, answered_by,
                    _isoformat_z(_dt.datetime.now(_dt.UTC)),
                    prompt_id,
                ),
            )
            return cur.rowcount > 0

    # -----------------------------------------------------------------
    # Synchronous deny-prompt support (#203 — v1.1)
    #
    # When the proxy runs under --sync-prompt-on-deny, each transparent-
    # mode DENY mints a sync_wait_id UUID, persists it on the
    # pending_prompts row, and blocks the request on an in-process
    # asyncio.Event keyed by that UUID (see proxy._sync_wait_registry).
    # The CLI `prompts answer` path looks up the sync_wait_id at answer
    # time + wakes the waiter so the proxy can return ALLOW (forward to
    # upstream) or DENY (return original 403) per the operator's choice.
    #
    # Per [[ibounce-honest-positioning]]: this is a DETERRENT UX for
    # legitimate human-in-loop, not adversarial defense — an
    # adversarial agent can detect the blocking + behave differently.
    # Per [[creates-never-mutates]]: this only appends to the audit
    # tables; never mutates customer-owned IAM.
    # -----------------------------------------------------------------

    def add_sync_pending_prompt(
        self,
        *,
        decision_id: int,
        service: str,
        action: str,
        arn: str | None,
        region: str | None,
        deny_reason: str,
    ) -> tuple[int, str]:
        """Insert a SYNC pending-prompt row + return (prompt_id,
        sync_wait_id). Idempotent per `decision_id` like
        `add_pending_prompt`: if a prior row exists for this decision,
        return its id + sync_wait_id (the existing waiter, if any, is
        the one that wins — we never mint a second sync_wait_id for
        the same decision).

        Mints a fresh UUID4 sync_wait_id when the row is new. Caller
        (the proxy) is expected to register that id in
        `proxy._sync_wait_registry` BEFORE awaiting, so an answer
        racing in between insert + register doesn't miss the wake.
        """
        import uuid

        with self._lock:
            cur = self._conn.execute(
                "SELECT id, sync_wait_id FROM pending_prompts "
                "WHERE decision_id = ?",
                (decision_id,),
            )
            prior = cur.fetchone()
            if prior is not None:
                # Existing row may or may not have had a sync_wait_id
                # (if the original was an async deny-prompt). If it
                # didn't, mint one in-place so the proxy can register
                # + wait. If it did, return the existing id verbatim.
                existing_sync_id = prior[1]
                if existing_sync_id:
                    return int(prior[0]), str(existing_sync_id)
                fresh = uuid.uuid4().hex
                self._conn.execute(
                    "UPDATE pending_prompts SET sync_wait_id = ? "
                    "WHERE id = ?",
                    (fresh, int(prior[0])),
                )
                return int(prior[0]), fresh
            sync_wait_id = uuid.uuid4().hex
            cur = self._conn.execute(
                """
                INSERT INTO pending_prompts(
                    created_at, decision_id, service, action, arn, region,
                    deny_reason, sync_wait_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    _isoformat_z(_dt.datetime.now(_dt.UTC)),
                    decision_id, service, action, arn, region, deny_reason,
                    sync_wait_id,
                ),
            )
            return int(cur.lastrowid or 0), sync_wait_id

    def get_pending_prompt_by_sync_wait_id(
        self, sync_wait_id: str,
    ) -> dict[str, Any] | None:
        """Return the pending_prompts row matching `sync_wait_id`, or None.

        Used by the proxy's #250 cross-process poll fallback in
        `_await_sync_deny_decision`: when the operator answers from a
        DIFFERENT process than `ibounce serve`, the in-process
        `wake_sync_pending_prompt` Event never fires (the registry is
        per-process). The proxy polls this method on a 200ms cadence
        to detect the DB-side status change + read out the recorded
        answer kind so it can resolve to allow/deny without needing
        the cross-process wake. Mirrors the dbounce d82ded9 fix.

        Same row shape as `get_pending_prompt`; sync_wait_id has a
        partial index so the SELECT is O(log n) even with many
        historical rows.
        """
        with self._lock:
            cur = self._conn.execute(
                "SELECT id, created_at, decision_id, service, action, "
                "arn, region, deny_reason, status, answer_kind, "
                "answer_target, answered_by, answered_at, "
                "kind, session_id, sync_wait_id "
                "FROM pending_prompts WHERE sync_wait_id = ?",
                (sync_wait_id,),
            )
            r = cur.fetchone()
        if r is None:
            return None
        return {
            "id": int(r[0]), "created_at": r[1], "decision_id": int(r[2]),
            "service": r[3], "action": r[4], "arn": r[5], "region": r[6],
            "deny_reason": r[7], "status": r[8], "answer_kind": r[9],
            "answer_target": r[10], "answered_by": r[11], "answered_at": r[12],
            "kind": r[13] or "deny-prompt", "session_id": r[14],
            "sync_wait_id": r[15],
        }

    def list_waiting_sync_prompts(
        self, *, sync_wait_ids: list[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Return the set of currently-PENDING sync-deny prompts.

        DETERMINISTIC: pure SQL — filters pending_prompts rows where
        sync_wait_id IS NOT NULL AND status = 'pending'. When
        `sync_wait_ids` is supplied, further restricts to rows whose
        sync_wait_id is in that set — used by the MCP tool
        `bouncer_pending_sync_prompts` to return only the prompts the
        in-process proxy is ACTUALLY waiting on (the union of all
        registered Events) rather than every sync-prompt-shaped row in
        the DB. Without that filter, a row left behind by a crashed
        proxy would appear waiting forever.
        """
        sql = (
            "SELECT id, created_at, decision_id, service, action, "
            "arn, region, deny_reason, status, answer_kind, "
            "answer_target, answered_by, answered_at, "
            "kind, session_id, sync_wait_id "
            "FROM pending_prompts "
            "WHERE status = 'pending' AND sync_wait_id IS NOT NULL"
        )
        params: tuple[Any, ...] = ()
        if sync_wait_ids is not None:
            if not sync_wait_ids:
                return []
            placeholders = ",".join(["?"] * len(sync_wait_ids))
            sql += f" AND sync_wait_id IN ({placeholders})"
            params = tuple(sync_wait_ids)
        sql += " ORDER BY id DESC"
        with self._lock:
            cur = self._conn.execute(sql, params)
            rows = cur.fetchall()
        return [
            {
                "id": int(r[0]), "created_at": r[1], "decision_id": int(r[2]),
                "service": r[3], "action": r[4], "arn": r[5], "region": r[6],
                "deny_reason": r[7], "status": r[8], "answer_kind": r[9],
                "answer_target": r[10], "answered_by": r[11], "answered_at": r[12],
                "kind": r[13] or "deny-prompt", "session_id": r[14],
                "sync_wait_id": r[15],
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

        Per Slice C: admins run `ibounce tasks review <id>`
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
    # Plan-capture sessions + calls (#132)
    # -----------------------------------------------------------------

    def ensure_plan_session(
        self,
        *,
        session_id: str,
        started_by: str,
        note: str = "",
    ) -> bool:
        """Insert a plan session row if one doesn't already exist.

        Returns True if a row was inserted, False if a row with the
        same session_id was already present (callers should treat
        either as success). Idempotent so the proxy can call this
        on every intercepted call without thinking about ordering.

        The `note` is operator-supplied free text (cap 200 chars +
        control-char strip) — used by `ibounce plan show` so an
        operator can label a session ("trying out the X agent
        workflow") without separately tracking it.
        """
        if not session_id or not isinstance(session_id, str):
            raise ValueError("ensure_plan_session: session_id required")
        # Bound + sanitize note the same way #6a pause reasons are
        # bounded — operator-supplied free text is a known abuse
        # surface for monitor parsers.
        clean_note = "".join(
            ch for ch in (note or "")
            if ch == " " or (32 <= ord(ch) < 127)
        )[:200]
        with self._lock:
            cur = self._conn.execute(
                "SELECT 1 FROM plan_sessions WHERE session_id = ?",
                (session_id,),
            )
            if cur.fetchone() is not None:
                return False
            self._conn.execute(
                """
                INSERT INTO plan_sessions(session_id, started_at, started_by, note)
                VALUES (?, ?, ?, ?)
                """,
                (
                    session_id,
                    _isoformat_z(_dt.datetime.now(_dt.UTC)),
                    started_by,
                    clean_note,
                ),
            )
            return True

    def record_plan_call(
        self,
        *,
        session_id: str,
        method: str,
        host: str,
        path: str,
        service: str,
        action: str,
        region: str | None,
        arn: str | None,
        verdict: str,
        would_have_called: str,
        would_have_returned: dict[str, Any] | None,
        supported: bool,
        decision_id: int | None = None,
    ) -> int:
        """Persist one plan-capture intercepted call. Returns the new
        plan_calls.id. The caller (proxy handler) supplies the
        verdict (`allow`/`deny`/`prompt`/`unsupported`) + the
        synthetic-shape summary already produced by the synthetics
        registry. No defaulting here so the proxy stays the single
        place that knows what `would_have_returned` means."""
        import json as _json

        if not session_id:
            raise ValueError("record_plan_call: session_id required")
        body_json = (
            _json.dumps(would_have_returned)
            if would_have_returned is not None else None
        )
        with self._lock:
            cur = self._conn.execute(
                """
                INSERT INTO plan_calls(
                    session_id, at, decision_id, method, host, path,
                    service, action, region, arn, verdict,
                    would_have_called, would_have_returned_json, supported
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    session_id,
                    _isoformat_z(_dt.datetime.now(_dt.UTC)),
                    decision_id,
                    method,
                    host,
                    path,
                    service,
                    action,
                    region,
                    arn,
                    verdict,
                    would_have_called,
                    body_json,
                    1 if supported else 0,
                ),
            )
            return int(cur.lastrowid or 0)

    # -----------------------------------------------------------------
    # #145 — plan-capture read->write switch UX
    #
    # The proxy calls these helpers in `_plan_capture_response` to drive
    # the per-session phase state machine when a write call is observed.
    # Phase transitions are deliberate (no side effects on the IAM/AWS
    # surface per [[creates-never-mutates]]); they only update the
    # plan_sessions row + may enqueue a plan-write prompt in
    # pending_prompts. Per [[ibounce-honest-positioning]]: this is a
    # deterrent UX helper for the operator, NOT a security boundary —
    # an adversarial agent can call writes WITHOUT preceding reads,
    # which would still flip the phase but doesn't prevent the
    # synthetic-success response.
    # -----------------------------------------------------------------

    _VALID_PLAN_PHASES = (
        "read_only", "write_pending", "writes_approved", "writes_rejected",
    )
    _VALID_WRITE_NOTIFY = ("manual", "auto-approve", "reject")

    def set_plan_session_write_switch_notify(
        self, session_id: str, notify_mode: str,
    ) -> bool:
        """Pin the `--write-switch-notify` mode for a session.

        Called by `serve()` once at startup (before any calls land) so
        the per-call phase-transition code can read it. Idempotent:
        re-calling with the same value is a no-op. Returns True if
        the row was updated.

        We validate the mode here rather than in the proxy so a future
        new entry point that bypasses the CLI flag can't silently
        write an invalid value into the DB.
        """
        if notify_mode not in self._VALID_WRITE_NOTIFY:
            raise ValueError(
                f"set_plan_session_write_switch_notify: notify_mode "
                f"{notify_mode!r} must be one of "
                f"{', '.join(self._VALID_WRITE_NOTIFY)}"
            )
        if not session_id:
            raise ValueError(
                "set_plan_session_write_switch_notify: session_id required"
            )
        with self._lock:
            cur = self._conn.execute(
                "UPDATE plan_sessions SET write_switch_notify = ? "
                "WHERE session_id = ?",
                (notify_mode, session_id),
            )
            return cur.rowcount > 0

    def get_plan_session_phase(self, session_id: str) -> dict[str, Any] | None:
        """Read just the phase fields for a session (no roll-up cost).

        Returns None when the session doesn't exist. Used by the proxy
        per-call hook because plan_session_summary() walks every call
        row to compute counts — overkill for the hot path that only
        needs the current phase + notify mode.
        """
        if not session_id:
            return None
        with self._lock:
            cur = self._conn.execute(
                "SELECT phase, write_switch_notify, first_write_at, "
                "write_decision, write_decision_at, write_decision_by "
                "FROM plan_sessions WHERE session_id = ?",
                (session_id,),
            )
            row = cur.fetchone()
        if row is None:
            return None
        return {
            "phase": row[0] or "read_only",
            "write_switch_notify": row[1] or "manual",
            "first_write_at": row[2],
            "write_decision": row[3],
            "write_decision_at": row[4],
            "write_decision_by": row[5],
        }

    def transition_plan_session_phase(
        self,
        session_id: str,
        *,
        new_phase: str,
        decision: str | None = None,
        decided_by: str | None = None,
        first_write_at: str | None = None,
    ) -> bool:
        """Move the session into a new phase. Validates the new value.

        `decision` is recorded for the writes_approved / writes_rejected
        terminal phases (caller passes 'approve' or 'reject'). For the
        write_pending transition we set first_write_at (if not already
        set) so post-hoc readers can see WHEN the agent crossed the
        boundary, independent of when the operator answered.

        Returns True if any row changed.
        """
        if new_phase not in self._VALID_PLAN_PHASES:
            raise ValueError(
                f"transition_plan_session_phase: new_phase {new_phase!r} "
                f"must be one of {', '.join(self._VALID_PLAN_PHASES)}"
            )
        if not session_id:
            raise ValueError(
                "transition_plan_session_phase: session_id required"
            )
        now = _isoformat_z(_dt.datetime.now(_dt.UTC))
        # Build the UPDATE dynamically so we don't clobber existing
        # first_write_at on a phase re-entry (e.g. write_pending ->
        # writes_approved keeps the original first_write_at).
        sets: list[str] = ["phase = ?"]
        params: list[Any] = [new_phase]
        if first_write_at is not None:
            # COALESCE preserves the first-write timestamp if the
            # session already has one — the FIRST write is what matters,
            # not the most recent.
            sets.append("first_write_at = COALESCE(first_write_at, ?)")
            params.append(first_write_at or now)
        if decision is not None:
            sets.append("write_decision = ?")
            params.append(decision)
            sets.append("write_decision_at = ?")
            params.append(now)
            if decided_by is not None:
                sets.append("write_decision_by = ?")
                params.append(decided_by)
        sql = (
            "UPDATE plan_sessions SET " + ", ".join(sets)
            + " WHERE session_id = ?"
        )
        params.append(session_id)
        with self._lock:
            cur = self._conn.execute(sql, tuple(params))
            return cur.rowcount > 0

    def add_plan_write_prompt(
        self,
        *,
        session_id: str,
        service: str,
        action: str,
        arn: str | None,
        region: str | None,
    ) -> int:
        """Enqueue a plan-write prompt for the operator.

        Plan-write prompts share the pending_prompts table with the
        existing deny-prompts (#5) so `ibounce prompts list/answer`
        is one queue. Discriminated by `kind='plan-write'`.

        Idempotent per (session_id) — if there's already a pending
        plan-write prompt for this session, returns its id rather than
        enqueuing a second one. A given session has at most ONE
        pending plan-write prompt at a time (until answered) because
        we only enqueue on the read_only -> write_pending transition.

        decision_id is set to 0 (synthetic) since plan-write prompts
        don't link to a single decisions row — they're per-session.
        """
        if not session_id:
            raise ValueError("add_plan_write_prompt: session_id required")
        with self._lock:
            cur = self._conn.execute(
                "SELECT id FROM pending_prompts "
                "WHERE kind = 'plan-write' AND session_id = ? "
                "AND status = 'pending'",
                (session_id,),
            )
            prior = cur.fetchone()
            if prior is not None:
                return int(prior[0])
            reason = (
                f"plan-capture session {session_id!r} agent transitioned "
                f"from read-only to first write call: {service}:{action}"
            )
            cur = self._conn.execute(
                """
                INSERT INTO pending_prompts(
                    created_at, decision_id, service, action, arn, region,
                    deny_reason, kind, session_id
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    _isoformat_z(_dt.datetime.now(_dt.UTC)),
                    0,  # synthetic — plan-write prompts have no decisions row
                    service, action, arn, region, reason,
                    "plan-write", session_id,
                ),
            )
            return int(cur.lastrowid or 0)

    def get_pending_plan_write_prompt(
        self, session_id: str,
    ) -> dict[str, Any] | None:
        """Return the pending plan-write prompt for a session (if any).

        Used by the proxy hot path + the MCP introspection tool
        (bouncer_plan_pending_write_prompt) so an agent can check
        "should I wait for approval before continuing?". Returns None
        when there is none — either because no write has happened yet,
        or because the operator already answered.
        """
        if not session_id:
            return None
        with self._lock:
            cur = self._conn.execute(
                "SELECT id, created_at, decision_id, service, action, "
                "arn, region, deny_reason, status, answer_kind, "
                "answer_target, answered_by, answered_at, kind, session_id, "
                "sync_wait_id "
                "FROM pending_prompts "
                "WHERE kind = 'plan-write' AND session_id = ? "
                "AND status = 'pending' "
                "ORDER BY id DESC LIMIT 1",
                (session_id,),
            )
            r = cur.fetchone()
        if r is None:
            return None
        return {
            "id": int(r[0]), "created_at": r[1], "decision_id": int(r[2]),
            "service": r[3], "action": r[4], "arn": r[5], "region": r[6],
            "deny_reason": r[7], "status": r[8], "answer_kind": r[9],
            "answer_target": r[10], "answered_by": r[11], "answered_at": r[12],
            "kind": r[13], "session_id": r[14], "sync_wait_id": r[15],
        }

    def answer_plan_write_prompt(
        self,
        prompt_id: int,
        *,
        decision: str,
        answered_by: str,
    ) -> dict[str, Any] | None:
        """Record an approve/reject answer on a plan-write prompt.

        Returns the answered prompt row on success (so the CLI can
        transition the session phase from it), or None if the prompt
        isn't pending / isn't a plan-write prompt / doesn't exist.

        Validates `decision` upfront — only approve/reject are valid
        here (vs always/profile/ignore on deny-prompts). Mirrors
        answer_pending_prompt's contract.
        """
        if decision not in ("approve", "reject"):
            raise ValueError(
                f"answer_plan_write_prompt: decision {decision!r} must be "
                f"'approve' or 'reject'"
            )
        with self._lock:
            cur = self._conn.execute(
                "SELECT id, kind, session_id, status FROM pending_prompts "
                "WHERE id = ?",
                (prompt_id,),
            )
            row = cur.fetchone()
            if row is None:
                return None
            if row[1] != "plan-write":
                return None
            if row[3] != "pending":
                return None
            session_id = row[2]
            cur = self._conn.execute(
                "UPDATE pending_prompts SET status = 'answered', "
                "answer_kind = ?, answered_by = ?, answered_at = ? "
                "WHERE id = ? AND status = 'pending'",
                (
                    decision, answered_by,
                    _isoformat_z(_dt.datetime.now(_dt.UTC)),
                    prompt_id,
                ),
            )
            if cur.rowcount == 0:
                return None
        return {
            "id": prompt_id,
            "session_id": session_id,
            "decision": decision,
            "answered_by": answered_by,
        }

    def list_plan_sessions(self, *, limit: int = 50) -> list[dict[str, Any]]:
        """Return recent plan sessions (newest first) with per-session
        roll-up counts. Powers `ibounce plan list`.

        #145: also returns the session's write-switch state machine
        (phase / write_switch_notify / first_write_at / write_decision
        + answer context) so `plan list` / JSON consumers can render
        "did this session contain a write transition + how was it
        handled?" without a second query.
        """
        capped = max(1, min(int(limit), 10_000))
        with self._lock:
            cur = self._conn.execute(
                """
                SELECT ps.session_id, ps.started_at, ps.started_by, ps.note,
                       ps.phase, ps.write_switch_notify, ps.first_write_at,
                       ps.write_decision, ps.write_decision_at, ps.write_decision_by,
                       COUNT(pc.id) AS call_count,
                       SUM(CASE WHEN pc.verdict = 'allow' THEN 1 ELSE 0 END) AS allow_count,
                       SUM(CASE WHEN pc.verdict = 'deny' THEN 1 ELSE 0 END) AS deny_count,
                       SUM(CASE WHEN pc.verdict = 'prompt' THEN 1 ELSE 0 END) AS prompt_count,
                       SUM(CASE WHEN pc.verdict = 'unsupported' THEN 1 ELSE 0 END) AS unsupported_count,
                       MAX(pc.at) AS last_call_at
                FROM plan_sessions ps
                LEFT JOIN plan_calls pc ON pc.session_id = ps.session_id
                GROUP BY ps.session_id
                ORDER BY ps.started_at DESC
                LIMIT ?
                """,
                (capped,),
            )
            rows = cur.fetchall()
        return [
            {
                "session_id": r[0],
                "started_at": r[1],
                "started_by": r[2],
                "note": r[3] or "",
                "phase": r[4] or "read_only",
                "write_switch_notify": r[5] or "manual",
                "first_write_at": r[6],
                "write_decision": r[7],
                "write_decision_at": r[8],
                "write_decision_by": r[9],
                "call_count": int(r[10] or 0),
                "allow_count": int(r[11] or 0),
                "deny_count": int(r[12] or 0),
                "prompt_count": int(r[13] or 0),
                "unsupported_count": int(r[14] or 0),
                "last_call_at": r[15],
            }
            for r in rows
        ]

    def get_plan_session(self, session_id: str) -> dict[str, Any] | None:
        """Return the session row + counts for a single session, or
        None if no such session exists.

        #145: surfaces the phase + write-switch state machine fields
        (write_switch_notify / first_write_at / write_decision +
        answer context) alongside the per-verdict roll-up + the
        read/write split. Plan-show + JSON export read this directly.
        """
        if not session_id:
            return None
        with self._lock:
            cur = self._conn.execute(
                "SELECT session_id, started_at, started_by, note, "
                "phase, write_switch_notify, first_write_at, "
                "write_decision, write_decision_at, write_decision_by "
                "FROM plan_sessions WHERE session_id = ?",
                (session_id,),
            )
            row = cur.fetchone()
        if row is None:
            return None
        summary = self.plan_session_summary(session_id)
        return {
            "session_id": row[0],
            "started_at": row[1],
            "started_by": row[2],
            "note": row[3] or "",
            "phase": row[4] or "read_only",
            "write_switch_notify": row[5] or "manual",
            "first_write_at": row[6],
            "write_decision": row[7],
            "write_decision_at": row[8],
            "write_decision_by": row[9],
            **summary,
        }

    def plan_session_summary(self, session_id: str) -> dict[str, Any]:
        """Aggregate counts for one plan session — total + per-verdict
        + sets of services / actions touched. Used by the MCP
        `bouncer_plan_session_summary` tool + the CLI `plan show`
        header. Returns zero-count shape (not error) for unknown
        sessions so callers can distinguish 'session exists, no
        calls yet' from 'session id is wrong' via the membership
        check on `list_plan_sessions`.

        #145 also includes a read/write classification roll-up
        (`read_count` / `write_count`) computed via the same
        plan_capture.classifier the proxy uses for phase
        transitions, so post-hoc consumers can answer "did the
        agent actually try to write anything?" without re-walking
        the calls."""
        with self._lock:
            cur = self._conn.execute(
                """
                SELECT verdict, COUNT(*),
                       SUM(CASE WHEN supported = 0 THEN 1 ELSE 0 END)
                FROM plan_calls
                WHERE session_id = ?
                GROUP BY verdict
                """,
                (session_id,),
            )
            verdict_rows = cur.fetchall()
            cur = self._conn.execute(
                "SELECT DISTINCT service FROM plan_calls "
                "WHERE session_id = ? ORDER BY service",
                (session_id,),
            )
            services = [r[0] for r in cur.fetchall()]
            cur = self._conn.execute(
                "SELECT DISTINCT service || ':' || action FROM plan_calls "
                "WHERE session_id = ? ORDER BY 1",
                (session_id,),
            )
            actions = [r[0] for r in cur.fetchall()]
            cur = self._conn.execute(
                "SELECT MIN(at), MAX(at), COUNT(*) FROM plan_calls "
                "WHERE session_id = ?",
                (session_id,),
            )
            mm = cur.fetchone() or (None, None, 0)
        counts = {
            "allow_count": 0, "deny_count": 0, "prompt_count": 0,
            "unsupported_count": 0,
        }
        unsupported_total = 0
        for verdict, total, unsupported in verdict_rows:
            key = f"{verdict}_count"
            if key in counts:
                counts[key] = int(total)
            unsupported_total += int(unsupported or 0)
        # #145: read/write split. Done outside the SQL above because the
        # classifier is a Python predicate (policy_sentry-backed +
        # heuristic fallback), not a single CASE we can express in SQL.
        # Pull the per-(service,action) frequency so we classify each
        # unique pair once instead of re-classifying duplicates.
        with self._lock:
            cur = self._conn.execute(
                "SELECT service, action, COUNT(*) FROM plan_calls "
                "WHERE session_id = ? GROUP BY service, action",
                (session_id,),
            )
            pair_counts = cur.fetchall()
        # Lazy import to avoid pulling policy_sentry at module load.
        from .plan_capture.classifier import classify_action
        read_count = 0
        write_count = 0
        for service, action, n in pair_counts:
            n = int(n or 0)
            klass = classify_action(service or "", action or "")
            if klass == "write":
                write_count += n
            elif klass == "read":
                read_count += n
            # Unknown/unclassifiable calls are intentionally counted in
            # NEITHER bucket — the operator sees call_count - (read +
            # write) > 0 as a hint that some calls couldn't be classified
            # (e.g. unsupported synthetic op, missing service name).
        return {
            "session_id": session_id,
            "call_count": int(mm[2] or 0),
            "first_call_at": mm[0],
            "last_call_at": mm[1],
            "services": services,
            "would_have_called": actions,
            "unsupported_total": unsupported_total,
            "read_count": read_count,
            "write_count": write_count,
            **counts,
        }

    def list_plan_calls(
        self, session_id: str, *, limit: int = 10_000,
    ) -> list[dict[str, Any]]:
        """Return the ordered call graph for one session (oldest
        first — call order is the natural reading order). The cap
        is high (10k) because export consumers want everything in
        one read; CLI `show` paginates separately."""
        capped = max(1, min(int(limit), 100_000))
        with self._lock:
            cur = self._conn.execute(
                """
                SELECT id, at, decision_id, method, host, path,
                       service, action, region, arn, verdict,
                       would_have_called, would_have_returned_json,
                       supported
                FROM plan_calls
                WHERE session_id = ?
                ORDER BY id ASC
                LIMIT ?
                """,
                (session_id, capped),
            )
            rows = cur.fetchall()
        import json as _json
        out: list[dict[str, Any]] = []
        for r in rows:
            (
                rid, at, decision_id, method, host, path,
                service, action, region, arn, verdict,
                would_have_called, would_have_returned_json, supported,
            ) = r
            try:
                wh = _json.loads(would_have_returned_json) if would_have_returned_json else None
            except (ValueError, TypeError):
                wh = None
            out.append({
                "id": int(rid),
                "at": at,
                "decision_id": int(decision_id) if decision_id is not None else None,
                "method": method,
                "host": host,
                "path": path,
                "service": service,
                "action": action,
                "region": region,
                "arn": arn,
                "verdict": verdict,
                "would_have_called": would_have_called,
                "would_have_returned": wh,
                "supported": bool(supported),
            })
        return out

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
