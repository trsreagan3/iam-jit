# `iam-jit audit query` — cross-bouncer audit-query CLI

`iam-jit audit query` queries the audit logs of every reachable Bounce-
suite bouncer in parallel and merges the results into one OCSF
v1.1.0-compliant stream. One command, four products, one merged
timeline — useful for cross-product correlation (e.g. "what did this
agent session do across AWS + Kubernetes + Postgres?").

```
iam-jit audit query [--bouncer ibounce,kbounce,dbounce,gbounce]
                    [--since ISO8601] [--until ISO8601]
                    [--filter EXPR ...]
                    [--limit N]
                    [--format jsonl|ocsf-bundle|csv|summary]
                    [--audit-events-token TOKEN]
                    [--timeout SECONDS]
```

The default invocation probes localhost for all four bouncers on their
standard management ports:

| Bouncer  | Default mgmt port |
| -------- | ----------------- |
| ibounce  | `8767`            |
| kbounce  | `8766`            |
| dbounce  | `8768`            |
| gbounce  | `8769`            |

Unreachable bouncers are skipped with a stderr note; the rest produce
output. The endpoint each bouncer serves is the `GET /audit/events`
endpoint (#271 A) — same filter language, same OCSF wire shape, same
supported field catalog as each product's `audit tail --filter`.

## Quick start

```bash
# Latest 100 events across every reachable bouncer (default).
iam-jit audit query

# Counts only.
iam-jit audit query --format summary
# ibounce: 142 events
# kbounce: 88 events
# dbounce: 1 events
# gbounce: 60 events
# total: 291 events

# Filter to one agent session, cross-product correlation.
iam-jit audit query \
    --filter unmapped.iam_jit.agent.session_id=019687ef-... \
    --format ocsf-bundle > session-bundle.json

# Time-window query.
iam-jit audit query \
    --since 2026-05-18T00:00:00Z \
    --until 2026-05-18T01:00:00Z \
    --limit 500
```

## Cross-product correlation: one agent session, three products

The killer use case: a single AI-agent session may touch IAM (via
ibounce), Kubernetes (via kbounce), AND Postgres (via dbounce). Each
event carries `unmapped.iam_jit.agent.session_id` so a single query
across all three bouncers reconstructs the full timeline:

```bash
SESSION=$(ibounce audit tail --limit 1 --json | jq -r '.unmapped.iam_jit.agent.session_id')
iam-jit audit query \
    --filter "unmapped.iam_jit.agent.session_id=$SESSION" \
    --format ocsf-bundle > investigation.json
```

The resulting bundle is a single OCSF Detection Finding wrapping every
event from every bouncer. Drop it into Claude (or any LLM tool) and
ask "what did this agent do?" — see
[`INVESTIGATE-WITH-CLAUDE.md`](../../iam-roles/docs/QUERYING-AUDIT-LOGS.md)
for the investigation workflow.

## Output formats

### `jsonl` (default)

One JSON-encoded OCSF event per line, merged + sorted by `time`
(oldest first). Pipe into `jq` / DuckDB / Vector for downstream
processing:

```bash
iam-jit audit query --since 2026-05-18T00:00:00Z |
    jq -r 'select(.severity_id >= 3) | .api.operation'
```

Each event carries a synthetic `_bouncer` field identifying its source
(so the merged stream stays groupable without re-walking
`metadata.product.name`).

### `ocsf-bundle`

One OCSF v1.1.0 class 2004 (Detection Finding) wrapping ALL events
from ALL queried bouncers as inline evidence. The shape matches the
per-bouncer `audit tail --export ocsf-bundle` output but joins across
bouncers:

```json
{
  "metadata": {"version": "1.1.0", "product": {"name": "iam-jit audit query", "vendor_name": "iam-jit"}},
  "class_uid": 2004,
  "class_name": "Detection Finding",
  "message": "Cross-bouncer audit query: 291 event(s) from 4 bouncer(s) (dbounce, gbounce, ibounce, kbounce)",
  "finding": {
    "uid": "iam-jit-audit-query-1747591239000",
    "title": "iam-jit cross-bouncer audit query",
    "types": ["cross-bouncer-correlation"],
    "evidence": {
      "events": [...],
      "bouncers": ["dbounce", "gbounce", "ibounce", "kbounce"]
    }
  }
}
```

SIEMs that ingest Detection Findings (Splunk, Sentinel, AWS Security
Lake) accept the bundle without product-specific mapping.

### `csv`

Tabular cross-bouncer dump with the per-bouncer column as the first
field. Useful for spreadsheet review:

```
bouncer,time,severity_id,activity_name,actor.user.name,api.operation,verdict
ibounce,1747591100000,1,Read,alice,iam:GetRole,ALLOW
kbounce,1747591110000,1,Read,alice,list pods,ALLOW
dbounce,1747591120000,1,Read,alice,SELECT,ALLOW
gbounce,1747591130000,1,Read,alice,GET /v1/x,ALLOW
```

### `summary`

Per-bouncer + total event counts. Stable name order across runs:

```
dbounce: 1 events
gbounce: 60 events
ibounce: 142 events
kbounce: 88 events
total: 291 events
```

Unreachable bouncers print `(unreachable: <reason>)` in their row.

## Filter language

The `--filter EXPR` flag forwards verbatim to each bouncer's
`/audit/events?filter=...` query parameter. The bouncer evaluates the
filter server-side against the OCSF event shape; the CLI doesn't
re-evaluate. AND semantics for repeated `--filter`.

Grammar (per [[cross-product-agent-parity]]):

| Form              | Meaning                          |
| ----------------- | -------------------------------- |
| `field=value`     | String equality                  |
| `field~regex`     | Go RE2 / Python `re` match       |
| `field>=N`        | Numeric greater-or-equal         |
| `field<=N`        | Numeric less-or-equal            |

Cross-product OCSF fields supported on every bouncer:

- `severity_id` / `activity_id` / `status_id`
- `actor.user.name`
- `api.operation`
- `unmapped.iam_jit.agent.name`
- `unmapped.iam_jit.agent.session_id`
- `unmapped.iam_jit.event_type`

Product-specific extension fields (filterable on their respective
bouncer; ignored on others):

| Product  | Extra fields                                              |
| -------- | --------------------------------------------------------- |
| kbounce  | `resource.namespace`, `resource.name`, `resource.type`    |
| dbounce  | `unmapped.iam_jit.ext.*` (statement_type, dialect, ...)   |
| gbounce  | `upstream_host`, `path`, `method`, `http_status`          |

See each product's `docs/QUERYING-AUDIT-LOGS.md` for the full per-
product catalog.

## Authentication

The default loopback probe needs no auth — each bouncer's mgmt port
refuses to bind off-loopback without `--i-know-this-binds-externally`.

When one or more bouncers is bound externally (operator deployed the
bouncer on a separate host), pass `--audit-events-token TOKEN` to the
CLI. The token is sent as `Authorization: Bearer <TOKEN>` to every
bouncer; bouncers that don't require auth ignore the header.

Per-bouncer auth-mode rejection:

| Bouncer response | CLI behavior                                          |
| ---------------- | ----------------------------------------------------- |
| 401 (no token)   | stderr note: `note: ibounce skipped (HTTP 401: ...)` |
| 403 (bad token)  | stderr note: `note: ibounce skipped (HTTP 403: ...)` |
| 200              | events merged into the output                          |

## Bouncer overrides

By default the CLI probes `127.0.0.1:<port>` for each bouncer. Override
one entry with `--bouncer name=URL`:

```bash
# kbounce running on a remote host; everything else loopback.
iam-jit audit query --bouncer kbounce=http://10.0.0.5:8766
```

`--bouncer` is repeatable; comma-separated values also accepted:

```bash
# Only ibounce + kbounce.
iam-jit audit query --bouncer ibounce,kbounce
```

## Parallel fan-out

Each bouncer is queried in its own thread (`ThreadPoolExecutor`). One
slow / unreachable bouncer doesn't pin the cross-bouncer query — the
others return their events independently. The `--timeout SECONDS`
flag caps each per-bouncer HTTP call (default 5s).

## See also

- Per-product `/audit/events` docs:
  - [`iam-roles/docs/QUERYING-AUDIT-LOGS.md`](QUERYING-AUDIT-LOGS.md) — ibounce
  - [`kbouncer/docs/QUERYING-AUDIT-LOGS.md`](https://github.com/trsreagan3/kbouncer/blob/main/docs/QUERYING-AUDIT-LOGS.md)
  - [`dbounce/docs/AUDIT-TAIL.md`](https://github.com/trsreagan3/dbounce/blob/main/docs/AUDIT-TAIL.md)
  - [`gbounce/docs/AUDIT.md`](https://github.com/trsreagan3/gbounce/blob/main/docs/AUDIT.md)
- Per-product `audit tail` CLIs (#268) — same filter language; local-
  operator workflows
- `iam-jit serve` — runs the iam-jit scorer; orthogonal surface to
  this audit-query CLI
