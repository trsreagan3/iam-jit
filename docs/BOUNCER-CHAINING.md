# Bouncer Chaining (#724 / BUILD-3) — Design + Go porting contract

> **Status:** Python (ibounce) side SHIPPED. The shared signal-store
> wire format, the declarative chain-rule grammar, and the ibounce
> producer/consumer + tightening hook are live and tested. The Go
> bouncers (gbounce / kbounce / dbounce) adopt the **same on-disk wire
> format** via the porting contract below — that is a documented
> follow-up, not implemented here. This document is the canonical
> contract those implementations converge against; **do not diverge
> from the wire shapes below without updating this doc first.**

## TL;DR

One bouncer's session-scoped observation can **tighten** another
bouncer's posture for the **same agent session** — cross-protocol
defense-in-depth. The canonical chain:

```
dbounce observes PII in a SQL result
  -> writes a `pii_observed` signal keyed on the agent session
  -> ibounce (HTTP egress) reads that signal on its next decision and
     TIGHTENS exfil-shaped egress (write/PUT/POST) for that session
```

This is only possible because the Bounce suite has multiple
protocol-aware bouncers that can share a same-host signal channel.

## Honest scope

This is **same-host, session-scoped** signal sharing via a shared
on-disk signal store (SQLite in a shared directory). It is **not** a
distributed or real-time bus, and we do not claim that. Producers and
consumers run on the same host and key on the canonical
`X-Agent-Session-Id` (see `docs/AGENT-ATTRIBUTION.md`). The
"sub-second" reaction is achieved because the consumer reads the store
on its **very next decision** — there is no polling delay on the hot
path.

## Three load-bearing invariants (the security review scrutinises these)

1. **Default OFF / opt-in.** Chaining is disabled unless the operator
   sets `iam-jit.bouncer_chaining.enabled: true`. With it off, the
   consumer never reads the store and behaviour is unchanged.
2. **Independence preserved / fail-soft.** Each bouncer remains fully
   functional standalone. If the signal store is missing, corrupt, or
   unreadable, the consumer **fails soft** — it decides against its own
   policy. A down signal channel can **never** stop a bouncer or flip a
   deny into an allow. Independence is itself a security property
   (`[[independence-as-security-property]]`).
3. **Tightening-only.** A chained signal may only ever **tighten**
   (ALLOW → DENY). It can **never** loosen another bouncer's decision.
   The consumer is only consulted when the floor verdict was **not**
   already a deny, and it can only add a deny. A forged or replayed
   signal is therefore, at worst, a denial-of-service against the
   attacker's **own** exfil path — it can never grant access. There is
   intentionally **no `loosen` action verb** in the chain grammar.

## Signal store — the shared wire format (v1)

A single SQLite file in a shared directory. Default path:
`~/.iam-jit/chaining/signals.db` (override via
`iam-jit.bouncer_chaining.signal_db` or the
`IAM_JIT_CHAINING_SIGNAL_DB` env var). **Every bouncer on the host MUST
resolve the same path.**

```sql
CREATE TABLE IF NOT EXISTS signals (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT NOT NULL,   -- canonical X-Agent-Session-Id
    kind        TEXT NOT NULL,   -- e.g. "pii_observed"
    source      TEXT NOT NULL,   -- producing bouncer: "dbounce"
    created_at  REAL NOT NULL,   -- unix epoch seconds (producer clock)
    expires_at  REAL NOT NULL,   -- created_at + ttl_seconds
    detail      TEXT             -- optional JSON blob, redacted by producer
);
CREATE INDEX IF NOT EXISTS idx_signals_session ON signals(session_id, expires_at);

CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
-- meta('version', '1')   -- SIGNAL_STORE_VERSION; pin to this.
```

Rules:

- **Append-only.** Signals are never updated. Use `PRAGMA
  journal_mode=WAL` + a short `busy_timeout` so a Go writer in another
  process never blocks the Python reader for long.
- **Expiry is read-time.** A consumer MUST filter `expires_at > now`.
  Producers SHOULD also `DELETE FROM signals WHERE expires_at < now -
  60` on write (best-effort housekeeping; read-time filtering is
  authoritative).
- **Detail is advisory.** It is metadata only, never load-bearing for
  the tighten decision, and the **producer** is responsible for
  redacting any sensitive content before writing it (cap ~4 KB). A
  dbounce PII signal should record column names / a category, never the
  PII values themselves.

### Signal-store trust & permissions

The store is created **0600 (file) / 0700 (dir)** — owner-only — and
the WAL/SHM siblings are tightened to 0600 too. This is the same
permission contract as the dynamic-deny store. The **threat model is
same-host trust**: any process running as the owning user can read and
write the signal DB by design (that is the whole point of cross-bouncer
chaining). An attacker who already has local **write** to the signal DB
is largely game-over on this host regardless — so the owner-only mode is
a tightening-only measure that caps the worst case at a self/cross-session
DoS (forged or spammed signals tightening the owner's own sessions) and
closes the activity side-channel (session_ids + signal kinds) to *other,
less-privileged local users*. A Go bouncer porting the writer MUST apply
the same 0600/0700 perms.

### Canonical signal kinds

| kind              | meaning                                   |
|-------------------|-------------------------------------------|
| `pii_observed`    | producer saw PII in a result/payload      |
| `secret_observed` | producer saw a credential/secret          |

New kinds are additive — an unknown kind is simply unmatched by any
rule (forward-compatible). Use these exact strings on the wire.

## Declarative chain rules

YAML files in `~/.iam-jit/chains/` (override via
`iam-jit.bouncer_chaining.chains_dir` or `IAM_JIT_CHAINS_DIR`). Each
file is one rule dict or a list of them:

```yaml
# ~/.iam-jit/chains/pii-egress.yaml
- trigger: dbounce.pii_detected      # <source_bouncer>.<event>
  scope: agent_session               # only supported scope today
  action: ibounce.tighten_egress     # <action_bouncer>.<verb>
  ttl: 1h                            # how long the tightening lasts
```

- **trigger** — `<source>.<event>`. The event maps to a canonical
  signal kind: both the human-facing `pii_detected` and the on-wire
  `pii_observed` resolve to `pii_observed` (likewise `secret_*`).
- **action** — `<bouncer>.<verb>`. The only implemented verb is
  `tighten_egress`. `ibounce.tighten_egress` and
  `gbounce.tighten_egress` are equivalent on the egress (HTTP) bouncer
  family.
- **scope** — `agent_session` only (the signal is keyed on
  `X-Agent-Session-Id`).
- **ttl** — `1h` / `30m` / `90s` / `1d` / integer seconds. Default 1h.
- A malformed rule file is a **loud error** at load, never a silent
  skip — an operator's typo must not silently disable protection.

## Config

```yaml
iam-jit:
  enabled: true
  bouncer_chaining:
    enabled: true          # default false (opt-in)
    mode: block            # block | alert (default block once enabled)
    chains_dir: ~/.iam-jit/chains          # optional override
    signal_db: ~/.iam-jit/chaining/signals.db  # optional override
```

- `block` — a triggered rule tightens ALLOW → DENY (real enforcement).
- `alert` — the consumer emits the `CHAIN_TIGHTENED` audit event but
  does **not** change the verdict (observe-before-enforce).

## Audit

A chain-driven tightening emits an OCSF v1.1.0 class-6003
`CHAIN_TIGHTENED` event (neutral, safety-framed language) that
**attributes the source bouncer**:

```jsonc
"unmapped": { "iam_jit": {
  "event_type": "CHAIN_TIGHTENED",
  "ext": {
    "session_id": "...",
    "chain_source_bouncer": "dbounce",   // who raised the signal
    "chain_trigger_kind": "pii_observed",
    "chain_action_bouncer": "ibounce",
    "chain_action_verb": "tighten_egress",
    "chain_mode": "block",
    "chain_enforced": true,
    "chain_signal_ttl_seconds": 3600
  }
}}
```

In `block` mode the consumer also re-emits the decision audit row with
`decision_source = "bouncer_chaining"` so a reviewer can trace the
final tightened verdict back to the originating cross-protocol signal.

## Go-bouncer porting contract (follow-up)

To make a Go bouncer (gbounce / kbounce / dbounce) participate, it must:

**As a PRODUCER** (e.g. dbounce after detecting PII in a SQL result):

1. Resolve the same `signals.db` path (same default + the
   `IAM_JIT_CHAINING_SIGNAL_DB` env override).
2. Open the DB with WAL + a short busy timeout; ensure the schema above
   (idempotent `CREATE TABLE IF NOT EXISTS`).
3. `INSERT` one row: `session_id` = the validated `X-Agent-Session-Id`
   for the call, `kind` = a canonical kind, `source` = the bouncer's
   own name, `created_at` = now, `expires_at` = now + ttl, `detail` =
   redacted JSON (or NULL).
4. Best-effort `DELETE` of rows older than `now - 60`.
5. A write failure MUST be logged and swallowed — the producing bouncer
   continues standalone (chaining is best-effort, never a hard dep).

**As a CONSUMER** (e.g. gbounce HTTP egress):

1. Load the chain rules from `chains_dir` with the grammar above.
2. On a non-deny floor verdict for an attributed session, `SELECT ...
   WHERE session_id = ? AND expires_at > ? AND kind IN (...)`.
3. If a rule's `(source, kind)` matches an active signal **and** the
   request is exfil-shaped (a write / non-read), tighten ALLOW → DENY
   in `block` mode (or just emit the audit event in `alert` mode).
4. Emit the `CHAIN_TIGHTENED` OCSF event attributing the source bouncer
   (same `unmapped.iam_jit.ext` shape).
5. **Fail soft:** any store error → no-op (decide standalone). **Never
   loosen.** Only ever consult the store when the floor was not already
   a deny, and only ever add a deny.

Pin to `SIGNAL_STORE_VERSION = 1`. Any wire change bumps the `meta`
version and updates this document first.

## What this is NOT

- Not a distributed / cross-host bus. Same host only.
- Not real-time push — consumers read on their next decision.
- Not a way to widen access. Tightening-only, by construction.
- Not a hard dependency. Default off; fail-soft; independence preserved.
