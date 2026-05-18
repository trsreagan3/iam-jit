# Querying audit logs

iam-jit's audit-export channel emits OCSF v1.1.0 class 6003 (API Activity)
events with an `unmapped.iam_jit.agent` block carrying the AI agent that
made the call (#266). This doc shows worked examples per SIEM for the
question security teams actually ask: **"which agent did this, months
later?"**

For the local-operator workflow — no SIEM in the loop, just an
operator at a terminal — jump to **[Live tail + filtering + summary +
export](#live-tail--filtering--summary--export)** below. That section
documents `ibounce audit tail`, the read surface the FREE tier ships
out of the box.

## What's in every event

Every event ibounce emits carries the standard OCSF v1.1.0 class 6003
shape plus an iam-jit extension block:

```json
{
  "metadata": {
    "version": "1.1.0",
    "product": {
      "name": "ibounce",            // or kbounce / dbounce
      "vendor_name": "iam-jit",
      "version": "..."
    }
  },
  "time": 1716163200000,
  "class_uid": 6003,
  "activity_id": 2,                 // 1=Create 2=Read 3=Update 4=Delete 99=Other
  "actor": {"user": {"name": "alice@example.com"}},
  "api": {"operation": "s3:GetObject"},
  "status_id": 1,                   // 1=Success 2=Failure 99=Other
  "unmapped": {
    "iam_jit": {
      "mode": "transparent",
      "verdict": "allow",
      "decision_id": 42,
      "enforced": false,
      "agent": {                    // #266 — present when detected
        "name": "claude-code",
        "version": "1.5.0",
        "session_id": "01968d6a-...",
        "detected_from": "mcp_clientinfo"
      }
    }
  }
}
```

The `agent` block is **omitted** when no detection signal fires (e.g.
a raw boto3 script with no MCP connection and no recognisable
User-Agent). That's intentional per [[scorer-is-ground-truth]] — we
don't invent identity we don't have.

### Detection sources (in priority order)

| `detected_from`     | Source                                       | Carries `session_id`? |
|---------------------|----------------------------------------------|-----------------------|
| `mcp_clientinfo`    | MCP `initialize` params.clientInfo           | Yes (UUID v7)         |
| `user_agent`        | Inbound HTTP User-Agent matches known table  | No                    |
| `user_agent_raw`    | UA present but unknown; surfaced verbatim    | No                    |
| `process_tree`      | Parent-process walk found agent binary       | No                    |

A SESSION_ENDED synthetic event fires when the MCP connection closes
(`unmapped.iam_jit.event_type == "SESSION_ENDED"`) so reviewers see a
clean open/close bookend for any agent session.

---

## Splunk (SPL)

```spl
# Every event from a specific agent session
index=iam_jit_bouncer
  unmapped.iam_jit.agent.session_id="01968d6a-2a4f-7d1e-bf52-9a3c..."
| sort time

# All claude-code activity in May 2026
index=iam_jit_bouncer
  unmapped.iam_jit.agent.name="claude-code"
  _time>="2026-05-01" _time<"2026-06-01"
| stats count by activity_name status

# Every DENY for s3:DeleteBucket regardless of agent
index=iam_jit_bouncer
  api.operation="s3:DeleteBucket"
  status_id=2
| stats count by actor.user.name unmapped.iam_jit.agent.name

# Sessions that triggered more than 10 denies (anomaly hunt)
index=iam_jit_bouncer
  status_id=2
  unmapped.iam_jit.agent.session_id=*
| stats count as denies by unmapped.iam_jit.agent.session_id
                            unmapped.iam_jit.agent.name
| where denies > 10
```

## Datadog Logs

```
# Single-session view
service:ibounce
  @unmapped.iam_jit.agent.session_id:"01968d6a-2a4f-7d1e-bf52-..."

# Agent name + time range
service:ibounce
  @unmapped.iam_jit.agent.name:"claude-code"
  @timestamp:[2026-05-01T00:00:00 TO 2026-06-01T00:00:00]

# Group all bouncer products' events for the same agent
service:(ibounce OR kbounce OR dbounce)
  @unmapped.iam_jit.agent.name:"cursor"
```

## Microsoft Sentinel (KQL)

```kusto
// All events from a session
IamJitBouncer
| where unmapped_iam_jit.agent.session_id == "01968d6a-2a4f-7d1e-bf52-..."
| sort by TimeGenerated asc

// Agent name breakdown
IamJitBouncer
| where TimeGenerated >= datetime(2026-05-01)
       and TimeGenerated <  datetime(2026-06-01)
| where unmapped_iam_jit.agent.name == "claude-code"
| summarize count() by activity_name, status_id

// SESSION_ENDED bookends (find sessions that ended in the last day)
IamJitBouncer
| where TimeGenerated > ago(1d)
| where unmapped_iam_jit.event_type == "SESSION_ENDED"
| project TimeGenerated,
          unmapped_iam_jit.agent.name,
          unmapped_iam_jit.agent.session_id,
          status_detail
```

## AWS Security Lake (Athena)

```sql
-- Single session, all activity
SELECT time, activity_name, status, api.operation
FROM ocsf_iam_jit_bouncer
WHERE eventday BETWEEN '20260501' AND '20260531'
  AND unmapped.iam_jit.agent.session_id =
      '01968d6a-2a4f-7d1e-bf52-9a3c-...';

-- Per-agent failure rate
SELECT unmapped.iam_jit.agent.name AS agent,
       SUM(CASE WHEN status_id = 2 THEN 1 ELSE 0 END) AS failures,
       COUNT(*)                                       AS total
FROM ocsf_iam_jit_bouncer
WHERE eventday BETWEEN '20260501' AND '20260531'
  AND unmapped.iam_jit.agent.name IS NOT NULL
GROUP BY unmapped.iam_jit.agent.name
ORDER BY failures DESC;

-- "Which agent did this?" — start from a CloudTrail event timestamp
-- and find the matching bouncer event within a 60s window.
SELECT b.time, b.unmapped.iam_jit.agent.name, b.api.operation
FROM ocsf_iam_jit_bouncer b
WHERE b.eventday = '20260517'
  AND b.actor.user.name = 'alice@example.com'
  AND b.api.operation   = 's3:DeleteObject'
  AND b.time BETWEEN 1716163200000 AND 1716163260000;
```

## Local DuckDB (JSONL log, no SIEM)

When there's no central collector — the FREE-tier shape per
[[local-only-safety-mode]] — events live in a JSONL file the
operator owns. DuckDB reads JSONL natively:

```bash
# Every event from one session, oldest first
duckdb -c "
SELECT time, activity_name, status, api->>'operation' AS op
FROM read_json_auto('~/.iam-jit/audit.jsonl')
WHERE json_extract_string(unmapped, '\$.iam_jit.agent.session_id') =
      '01968d6a-2a4f-7d1e-bf52-...'
ORDER BY time ASC;"

# Top operations per agent in the last 7 days
duckdb -c "
SELECT json_extract_string(unmapped, '\$.iam_jit.agent.name') AS agent,
       api->>'operation' AS op,
       COUNT(*) AS calls
FROM read_json_auto('~/.iam-jit/audit.jsonl')
WHERE time > (epoch_ms(now()) - 7 * 24 * 3600 * 1000)
GROUP BY agent, op
ORDER BY calls DESC
LIMIT 20;"

# Find DENY events that have no agent identity (raw scripts /
# bypass attempts per [[script-bypass-threat-model]])
duckdb -c "
SELECT time, actor->'user'->>'name' AS principal,
       api->>'operation' AS op, status_detail
FROM read_json_auto('~/.iam-jit/audit.jsonl')
WHERE status_id = 2
  AND json_extract(unmapped, '\$.iam_jit.agent') IS NULL
ORDER BY time DESC;"
```

## Live tail + filtering + summary + export

For local-operator workflows (no SIEM, no central collector — the FREE
tier per [[local-only-safety-mode]]), `ibounce audit tail` is the
read surface. Same JSONL log the DuckDB recipes above read from, just
wrapped in a terminal-friendly CLI with filtering, summary, and
export.

The flag shape is shared with `kbounce audit tail` + `dbounce audit
tail` per [[cross-product-agent-parity]]; muscle memory transfers
across the Bounce suite.

```
ibounce audit tail [--path PATH] [--follow] [--filter EXPR ...]
                   [--summary] [--export FORMAT --out PATH]
                   [--csv-columns "a,b,c"] [--limit N]
```

### Default behaviour

```bash
# Print every event in the audit log, oldest first
ibounce audit tail
# 2026-05-18T00:00:00+00:00  sev=1  DECISION  alice@example.com  s3:GetObject  allow
# 2026-05-18T00:00:01+00:00  sev=1  DECISION  alice@example.com  s3:GetObject  allow
# 2026-05-18T00:00:02+00:00  sev=3  DECISION  bob@example.com    s3:PutObject  deny
# 2026-05-18T00:00:03+00:00  sev=1  HEARTBEAT -                  s3:GetObject

# Newest N events
ibounce audit tail --limit 200
```

The audit log path defaults to `$IAM_JIT_BOUNCER_AUDIT_LOG` or
`~/.iam-jit/audit.jsonl`. Pass `--path /custom/path.jsonl` to override
(use the same value you passed to `ibounce run --audit-log-path`).

### Live tail (`--follow`)

```bash
# Stream new events as they arrive; Ctrl-C to exit
ibounce audit tail --follow

# Live-tail one agent at severity >= 3
ibounce audit tail --follow \
    --filter unmapped.iam_jit.agent.name=claude-code \
    --filter severity_id>=3
```

Polls the JSONL log every 500ms. Survives log rotation (re-opens on
inode change or truncate, matches `tail -F` semantics). Exits cleanly
on SIGINT.

### Filters (`--filter`, repeatable; AND-combined)

Four operators against any OCSF dotted-path field:

| Form               | Meaning                                          |
|--------------------|--------------------------------------------------|
| `field=value`      | String equality                                  |
| `field~regex`      | Regex (Python `re.search`)                       |
| `field>=N`         | Numeric greater-or-equal                         |
| `field<=N`         | Numeric less-or-equal                            |

Supported fields (cross-product subset — same across ibounce, kbounce,
dbounce):

- `severity_id` — OCSF severity (1=Informational, 3=Medium, 4=High, ...)
- `activity_id` — OCSF CRUD class (1=Create, 2=Read, 3=Update, 4=Delete, 99=Other)
- `status_id`   — 1=Success, 2=Failure, 99=Other
- `actor.user.name`
- `api.operation`
- `unmapped.iam_jit.agent.name`
- `unmapped.iam_jit.agent.session_id`
- `unmapped.iam_jit.event_type` (or `event_type` shortcut; `DECISION`
  is the implicit value for plain decision events)

ibounce-specific fields (also filterable; not present on kbounce / dbounce):

- `unmapped.iam_jit.ext.aws_region`
- `unmapped.iam_jit.ext.sigv4_credential_kid`

Examples:

```bash
# Every claude-code event in the log
ibounce audit tail --filter unmapped.iam_jit.agent.name=claude-code

# Every DENY for an S3 write
ibounce audit tail \
    --filter api.operation~^s3:Delete \
    --filter verdict=deny

# Everything from one session
ibounce audit tail \
    --filter unmapped.iam_jit.agent.session_id=01968d6a-2a4f-7d1e-...
```

### Summary (`--summary`)

Replaces the row-by-row view with a count-summary by event_type,
severity, actor, and operation:

```bash
ibounce audit tail --summary
# event_type counts:
#   DECISION                  142
#   ADMIN_ACTION                8
#   HEARTBEAT                  60
# severity_id counts:
#   1 (Informational)         200
#   3 (Medium)                  6
#   4 (High)                    4
# actor counts:
#   alice@example.com         180
#   bob@example.com            30
# operation counts:
#   s3:GetObject              140
#   s3:PutObject               40
#   iam:ListRoles              30
```

Combine with `--filter` to summarise a subset (e.g. "what did
claude-code do today?").

`--follow` + `--summary` is a clash; pick one (one streams, the other
aggregates a closed set).

### Export (`--export FORMAT --out PATH`)

Materialise the current view (after `--filter`) to a file. Three
formats:

| `--export` value | Output shape                                          |
|------------------|-------------------------------------------------------|
| `jsonl`          | One OCSF event per line (matches the audit log shape) |
| `csv`            | Tabular; default columns omit PII-shaped fields       |
| `ocsf-bundle`    | Single OCSF v1.1.0 class 2004 Detection Finding       |

Examples:

```bash
# JSONL for jq / DuckDB pipelines
ibounce audit tail \
    --filter unmapped.iam_jit.agent.name=claude-code \
    --export jsonl --out claude-code.jsonl
jq -c '.api.operation' claude-code.jsonl | sort | uniq -c

# CSV for a spreadsheet (default columns; PII excluded)
ibounce audit tail \
    --filter severity_id>=3 \
    --export csv --out incidents.csv

# CSV with custom columns (opt in to PII explicitly)
ibounce audit tail \
    --export csv --out export.csv \
    --csv-columns "time,actor.user.name,api.operation,verdict"

# Detection Finding bundle for SIEM batch import
ibounce audit tail \
    --filter unmapped.iam_jit.agent.session_id=01968d6a-... \
    --export ocsf-bundle --out finding.json
```

The Detection Finding bundle's `severity_id` is the MAX severity
across the wrapped events; the events themselves stay verbatim under
`finding.evidence.events`. A SIEM that already speaks OCSF class 2004
ingests it as one investigation.

### PII guard for `--export csv`

The default CSV column set deliberately excludes PII-shaped fields
(anything containing `email`, `phone`, `address`, `credential`,
`secret`, `token` in its dotted path). To include a PII-shaped
field, name it in `--csv-columns`:

```bash
# Opt-in: the CLI prints a stderr note when --csv-columns includes
# a PII-shaped field, so the choice shows up in the run log.
ibounce audit tail \
    --export csv --out export.csv \
    --csv-columns "time,actor.user.name,actor.user.email"
# note: --csv-columns includes PII-shaped field(s): actor.user.email
#       — these are not in the default column set.
```

### Cross-product muscle memory

The same flag set + supported fields + summary groupings ship in
`kbounce audit tail` (K8s admission) and `dbounce audit tail` (SQL
gateway). A customer scanning the audit shape across the suite uses
identical recipes:

```bash
# Same recipe across three products
ibounce  audit tail --filter unmapped.iam_jit.agent.name=claude-code --summary
kbounce  audit tail --filter unmapped.iam_jit.agent.name=claude-code --summary
dbounce  audit tail --filter unmapped.iam_jit.agent.name=claude-code --summary
```

See the equivalent docs in the kbounce + dbounce repos
(`docs/QUERYING-AUDIT-LOGS.md` in each).

## Admin actions (who changed what, when)

The audit-export channel also carries **admin-action events**: a
distinct OCSF v1.1.0 class 6003 event every time an operator changes
ibounce's enforcement posture. Decisions answer "what did the agent
try to do"; admin-action events answer "who installed this profile /
swapped this rule in / paused enforcement", from the same stream.

Every admin action carries `unmapped.iam_jit.event_type ==
"ADMIN_ACTION"` plus an `unmapped.iam_jit.admin_action` block:

```json
{
  "metadata": {
    "version": "1.1.0",
    "product": {"name": "ibounce", "vendor_name": "iam-jit"}
  },
  "time": 1716163200000,
  "class_uid": 6003,
  "activity_id": 1,                   // 1=Create 3=Update 4=Delete 99=Other
  "activity_name": "profile.install",
  "severity_id": 1,                   // 1=Informational; 4=High for license.install / profile.assign
  "status_id": 1,
  "status_detail": "admin action profile.install on profile 'team-staging' by frank@example.com",
  "actor": {"user": {"name": "frank@example.com", "uid": "frank@example.com"}},
  "unmapped": {
    "iam_jit": {
      "event_type": "ADMIN_ACTION",
      "admin_action": {
        "kind": "profile.install",
        "source": "cli",
        "actor": "frank@example.com",
        "target": {
          "kind": "profile",
          "id": "team-staging",
          "extra": {
            "source_url": "https://internal.example.com/profiles/staging.yaml",
            "sha256": "a3f5...c812"
          }
        },
        "after_hash": "9b2a...d3f1"
      }
    }
  }
}
```

### Canonical action list

| `kind`              | `activity_id` | Touchpoint                                       |
|---------------------|---------------|--------------------------------------------------|
| `profile.install`   | 1 Create      | `ibounce profile install --from URL`             |
| `profile.swap`      | 3 Update      | `ibounce prompts bulk-answer` option 1 (hot-swap)|
| `rule.add`          | 1 Create      | `ibounce rules add ...`                          |
| `rule.remove`       | 4 Delete      | `ibounce rules remove <id>`                      |
| `pause.start`       | 3 Update      | `ibounce pause start --for ...`                  |
| `pause.stop`        | 3 Update      | `ibounce pause stop` (no-op when no pause active)|
| `preset.apply`      | 1 Create      | `ibounce presets apply <name>`                   |
| `session.kill`      | 4 Delete      | `ibounce tasks end <selector>`                   |
| `config.import`     | 1 Create      | reserved; emit-helper ships, surface TBD         |
| `config.export`     | 99 Other      | reserved; emit-helper ships, surface TBD         |
| `license.install`   | 1 Create      | reserved; severity 4 High                        |
| `profile.assign`    | 3 Update      | reserved; severity 4 High                        |

### Operator identity

The `actor.user.name` field is discovered in this order:

1. **`IAM_JIT_BOUNCER_ACTOR` env var** — agents / CI runners / wrappers
   identify themselves explicitly. Set this in the agent's launcher
   so the audit row carries the agent's identity, not the OS user
   the agent's container happens to run as.
2. **OS username** via `getpass.getuser()` — the default for a
   developer running `ibounce` from their shell.
3. **`local-operator`** — honest fallback when neither signal fires
   (e.g. a container with no `/etc/passwd` entry for the runtime UID).
   Every admin-action event carries a non-empty actor; there is no
   "anonymous admin action" path.

### Querying

The same SIEM queries that pivot on decision events work on admin-
action events; filter by `event_type` to scope:

```spl
# Splunk — every config change in the last 24h
index=iam_jit_bouncer
  unmapped.iam_jit.event_type="ADMIN_ACTION"
  _time>=relative_time(now(), "-24h")
| table _time actor.user.name unmapped.iam_jit.admin_action.kind
        unmapped.iam_jit.admin_action.target.id
| sort _time desc

# Datadog — admin actions by a specific operator
service:ibounce
  @unmapped.iam_jit.event_type:ADMIN_ACTION
  @actor.user.name:"frank@example.com"

# Athena (AWS Security Lake) — who installed each profile
SELECT time, actor.user.name AS who,
       unmapped.iam_jit.admin_action.target.id AS profile_name,
       unmapped.iam_jit.admin_action.target.extra.source_url AS source
FROM ocsf_iam_jit_bouncer
WHERE unmapped.iam_jit.admin_action.kind = 'profile.install'
ORDER BY time DESC;
```

### Cross-product parity

kbounce + dbounce ship the same admin-action shape — same
`event_type == "ADMIN_ACTION"` marker, same `kind` vocabulary, same
`actor.user` layout. A single SIEM rule keyed on
`unmapped.iam_jit.event_type == "ADMIN_ACTION"` across all three
products catches every config change without per-product mapping:

```spl
# Splunk — every config change across the whole Bounce suite
index=iam_jit_bouncer
  unmapped.iam_jit.event_type="ADMIN_ACTION"
  metadata.product.vendor_name="iam-jit"
| stats count by metadata.product.name
                 unmapped.iam_jit.admin_action.kind
                 actor.user.name
```

The shared shape lives at kbounce commit `55e364d` and dbounce commit
`1200a8a`; ibounce wires it under issue #278.

## Cross-bouncer filtering

When kbounce (K8s admission) and dbounce (SQL gateway) ship alongside
ibounce, the events all share the OCSF shape and the `iam-jit` vendor
name. Filter across products in one query:

```spl
# Splunk — all iam-jit-bouncer DENYs across products
index=iam_jit_bouncer
  metadata.product.vendor_name="iam-jit"
  metadata.product.name IN ("ibounce", "kbounce", "dbounce")
  status_id=2
| stats count by metadata.product.name unmapped.iam_jit.agent.name
```

```sql
-- Athena — per-product traffic from one agent
SELECT metadata.product.name AS product,
       activity_name,
       COUNT(*) AS calls
FROM ocsf_iam_jit_bouncer
WHERE eventday = '20260517'
  AND unmapped.iam_jit.agent.session_id =
      '01968d6a-2a4f-7d1e-bf52-...'
GROUP BY metadata.product.name, activity_name;
```

This is the workflow the memo's "single SIEM dashboard scoped to
`metadata.product.vendor_name == 'iam-jit'` catches everything"
contract enables (per [[cross-product-agent-parity]] and #271).

## HTTP `GET /audit/events` endpoint (`#271`)

ibounce exposes the same query surface as a headless HTTP endpoint on
its existing port (`8767`):

```
GET /audit/events?since=ISO8601&until=ISO8601&filter=field=value&filter=...&limit=N&format=jsonl|ocsf-bundle
```

Same filter language as `ibounce audit tail --filter`, same supported
field catalog. Defaults: `limit=100` (max `1000`), `format=jsonl` (one
OCSF event per line). Pass `format=ocsf-bundle` for a single OCSF v1.1.0
class 2004 Detection Finding wrapping the matched events.

The endpoint reads the same JSONL file `ibounce audit tail` reads, so
it returns nothing until `ibounce run --audit-log-path PATH` has been
set and the writer has produced at least one event.

### Sample invocations

```bash
# Loopback bind (default): no auth required.
curl 'http://127.0.0.1:8767/audit/events?limit=10'

# Filter to one agent + last hour, NDJSON.
curl 'http://127.0.0.1:8767/audit/events?filter=unmapped.iam_jit.agent.name=claude-code&since=2026-05-18T00:00:00Z'

# OCSF Detection Finding bundle for SIEM batch import.
curl 'http://127.0.0.1:8767/audit/events?format=ocsf-bundle&limit=100'
```

### Auth model

- **Loopback bind (default)**: no `Authorization` header required.
  ibounce refuses to bind off-loopback without
  `--i-know-this-binds-externally`.
- **External bind**: `ibounce run --i-know-this-binds-externally
  --host 0.0.0.0 --audit-events-token <TOKEN>` is required. Requests
  must carry `Authorization: Bearer <TOKEN>`. Missing header → 401;
  wrong token → 403. ibounce refuses to start in external-bind mode
  without `--audit-events-token`.

### Cross-bouncer query

The `iam-jit audit query` CLI calls this endpoint on every reachable
bouncer (ibounce / kbounce / dbounce / gbounce) in parallel and merges
the results. See [`docs/IAM-JIT-AUDIT-QUERY.md`](IAM-JIT-AUDIT-QUERY.md)
for the cross-product correlation workflow.

## Live web UI at `GET /` (`#272`)

ibounce also serves a minimal vanilla-JS web UI on the same port
that hosts `/healthz` and `/audit/events`. The page is a single
self-contained HTML+CSS+JS file (no build step, no CDN, no Google
Fonts, no analytics, no telemetry) that long-polls
`/audit/events?since=<cursor>` every two seconds and renders a
live-updating colour-coded table.

### How to access

```bash
# Loopback default (no auth needed).
ibounce run --audit-log-path /var/lib/ibounce/audit.jsonl
# Then open in a browser:
open http://127.0.0.1:8767/

# Quick smoke test from curl.
curl -s http://127.0.0.1:8767/ | head
```

External-bind operators pass the bearer token through the URL
fragment (the page extracts it client-side and never embeds it in
the rendered HTML — per the no-secret-shape constraint):

```
https://ibounce.example.com:8767/#token=YOUR_AUDIT_EVENTS_TOKEN
```

### Visual conventions

- **DENIED** rows tinted red; **ALLOWED** rows untinted green
  verdict pill; **ADMIN_*** rows tinted blue; **HEARTBEAT** rows
  greyed out. Matches the cross-bouncer TUI shipped alongside this
  UI (see below).
- Top bar shows total event count + per-class breakdown (allow /
  deny / admin / heartbeat).
- Filter input forwards to the same `/audit/events?filter=` server-
  side syntax documented above.
- Pause / clear buttons; mobile-responsive layout.

### Read-only

Per `[[creates-never-mutates]]` the web UI is a **viewer**. There
are no buttons that mutate ibounce state — no "kill session", no
"pause profile". Operators run the existing `ibounce` CLI for
actions. The HTML response carries a strict `Content-Security-
Policy` header (`default-src 'self'; frame-ancestors 'none'; ...`).

### Cross-bouncer TUI sibling

For a single merged view across ibounce / kbounce / dbounce /
gbounce, see
[`docs/AUDIT-STREAM-TUI.md`](AUDIT-STREAM-TUI.md) — `iam-jit audit
stream` is the terminal-UI sibling of the per-bouncer web pages.

## Retention

iam-jit doesn't hold your logs — your collector does. Typical defaults:

- Splunk: 90 days hot (configurable)
- Datadog: 15 days (paid tiers up to 15 months)
- Sentinel: 90 days (extendable up to 12 years)
- AWS Security Lake: indefinite with S3 Glacier lifecycle
- Local DuckDB / JSONL: append-only since install; rotate via
  `logrotate`, `Fluent Bit`, or `Vector` (operator's choice)

Per [[no-hosted-saas]] iam-jit-the-company never sees a copy.
