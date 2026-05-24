# Phase 1 — dbounce (SQL) statement tables.
"""dbounce action classification.

The bouncer's audit event surfaces SQL via either the bare statement
type (``SELECT`` / ``INSERT`` / ``UPDATE`` / ``DELETE`` / ``DROP`` /
...) or a prefixed form (``psql:Select``, ``mysql:Select``). The
classifier handles both — :func:`classify_action` strips the prefix.

Per `docs/PROFILE-GENERATION-DESIGN.md` §2.1:

* READ: SELECT
* WRITE_DATA: INSERT, UPDATE
* ADMIN: GRANT, REVOKE, ALTER USER, CREATE USER, DROP USER
* DESTRUCTIVE_DATA: DELETE FROM, DROP TABLE, TRUNCATE
"""

from __future__ import annotations


# SQL statement classifications. Keys are uppercase canonical form.
READ_STATEMENTS: frozenset[str] = frozenset({
    "SELECT",
    "SHOW",
    "DESCRIBE",
    "DESC",
    "EXPLAIN",
    "WITH",  # CTE — typically read; write CTEs are rare and re-classify
})


WRITE_STATEMENTS: frozenset[str] = frozenset({
    "INSERT",
    "UPDATE",
    "MERGE",
    "UPSERT",
    "COPY",  # bulk-write in Postgres
    "LOAD",  # MySQL LOAD DATA
    "REPLACE",
    "CALL",  # stored proc — could mutate; classify as write-data
})


# Admin / privilege / catalog-management — narrow scope required.
ADMIN_STATEMENTS: frozenset[str] = frozenset({
    "GRANT",
    "REVOKE",
    "CREATE",  # CREATE USER / ROLE / SCHEMA — all admin
    "ALTER",   # ALTER USER / ROLE
    "SET",     # SET ROLE / SESSION AUTHORIZATION
    "RESET",
    "LOCK",
    "UNLOCK",
    "COMMENT",
    "ANALYZE",
    "VACUUM",
    "REINDEX",
    "CLUSTER",
})


# Destructive-data — high blast even single-statement.
DESTRUCTIVE_STATEMENTS: frozenset[str] = frozenset({
    "DELETE",
    "DROP",
    "TRUNCATE",
    "RENAME",
    "DISCARD",
})


# Common bouncer-prefix forms (``psql:Select``) — the prefix is the
# SQL dialect name. Strip these in classify.py.
_KNOWN_DIALECT_PREFIXES: tuple[str, ...] = (
    "psql",
    "postgres",
    "postgresql",
    "mysql",
    "mariadb",
    "snowflake",
    "bigquery",
    "redshift",
    "sql",
)


def strip_dialect_prefix(statement: str) -> str:
    """Return the bare SQL statement type. Handles ``psql:Select`` →
    ``SELECT`` and bare ``SELECT`` → ``SELECT``."""
    if not statement:
        return ""
    s = statement.strip()
    if ":" in s:
        prefix, _, tail = s.partition(":")
        if prefix.lower() in _KNOWN_DIALECT_PREFIXES:
            s = tail
    # First whitespace-separated token is the statement type.
    s = s.strip().split()[0] if s.strip() else ""
    return s.upper()


__all__ = [
    "READ_STATEMENTS",
    "WRITE_STATEMENTS",
    "ADMIN_STATEMENTS",
    "DESTRUCTIVE_STATEMENTS",
    "strip_dialect_prefix",
]
