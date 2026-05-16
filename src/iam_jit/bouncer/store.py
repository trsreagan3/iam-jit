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

SCHEMA_VERSION = 2  # v2: adds config_events table for [[agent-friendly-not-bypassable]] Lens B


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
                """
            )
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

    def record_decision(self, dec: DecisionRecord, *, matched_rule_id: int | None = None) -> int:
        with self._lock:
            cur = self._conn.execute(
                """
                INSERT INTO decisions(at, decision, mode, service, action, arn, region, matched_rule_id, reason)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
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
            "matched_rule_id, reason FROM decisions"
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
            (rid, at, decision, mode, service, action, arn, region, matched_id, reason) = r
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
            })
        return out

    def count_decisions(self) -> int:
        with self._lock:
            cur = self._conn.execute("SELECT COUNT(*) FROM decisions")
            row = cur.fetchone()
        return int(row[0] if row else 0)

    # -----------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------

    def close(self) -> None:
        with self._lock:
            self._conn.close()
