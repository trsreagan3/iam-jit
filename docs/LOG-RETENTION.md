# Audit Log Retention — Cross-Product Runbook

Status: shipped 2026-05-22 (#311 / §A10) — cross-product launch-blocker resolved.

Every Bounce product (ibounce, kbounce, dbounce, gbounce) writes a JSONL
audit log + SQLite audit DB per [[security-team-audit-export]]. Without
rotation the active files grow unbounded and silently fill the host disk.
Per [[self-host-zero-billing-dependency]] the audit log IS the compliance
value — silent failure isn't an option. This doc is the single source of
truth for retention behaviour across the four products.

## Behaviour overview

| Trigger | Behaviour | Default |
|---|---|---|
| Size | When `audit.jsonl` exceeds N MB → rotate + gzip | 100 MB |
| Age | When `audit.jsonl` mtime is older than N days → rotate + gzip | 7 days |
| Daily SQLite roll | At 00:00 UTC rename `audit.db` to `audit-{YYYY-MM-DD}.db` + gzip; reopen fresh `audit.db` | enabled |
| JSONL retention | Rotated `audit-*.jsonl.gz` older than N days are purged | 7 days |
| DB retention | Rotated `audit-*.db.gz` older than N days are purged | 30 days |
| Disk degraded | `/healthz audit_log.status == "degraded"` at >N% disk | 85 % |
| Disk critical | `/healthz audit_log.status == "critical"` at >N% disk | 95 % |

Rotation is ADDITIVE per [[creates-never-mutates]]: rotated files are
gzip'd into the same directory and remain until an explicit `*bounce logs
purge` invocation reaps them. The active `audit.jsonl` / `audit.db` are
never destroyed by any automatic path; only `*bounce logs purge` can.

## CLI flags + env-var overrides

Each product accepts the same flag names on its `run` subcommand:

```
--audit-log-max-size-mb     N    # 0 disables size trigger
--audit-log-max-age-days    N    # 0 disables age trigger
--audit-db-retention-days   N    # 0 disables DB retention
```

Same names, same defaults across products per [[cross-product-agent-parity]].

## CLI: `*bounce logs` subcommands

The same surface ships on every Bounce CLI:

```sh
ibounce logs tail                                    # existing — read recent decisions
ibounce logs purge --older-than 7d --yes             # reap archives ≥ 7 days old
ibounce logs archive --out /tmp/audit-bundle.tar.gz  # bundle for hand-off
ibounce logs verify                                  # integrity check (gzip + JSONL)

# same shape:
kbounce logs purge --older-than 7d --yes
dbounce logs archive --out /tmp/audit-bundle.tar.gz
gbounce logs verify --json
```

`--older-than` accepts `7d`, `24h`, `30m`, `60s`, or a bare integer (interpreted as days). The `--yes` flag is required for non-interactive purge.

## CLI: `*bounce doctor logs`

The cross-product health-check command. Exits non-zero on any failure.

```sh
ibounce doctor logs --max-age-days 7 --warn-pct 85 --crit-pct 95
kbounce doctor logs --json
dbounce doctor logs
gbounce doctor logs
```

Sample output on a healthy deployment:

```
doctor logs — /home/operator/.kbouncer/audit
========================================
  [      OK] integrity: {"files_checked":3,"ok":true,"failures":null}
  [      OK] freshness: {"ok":true,"most_recent":"/home/operator/.kbouncer/audit/audit-2026-05-22-091500.jsonl.gz","age_days":0.5,"threshold_days":7}
  [      OK] disk: {"status":"ok","reason":"disk usage within thresholds","used_pct":62.3,"path":"/home/operator/.kbouncer/audit"}
========================================
OVERALL: OK
```

Sample output on a degraded deployment (disk pressure):

```
doctor logs — /home/operator/.kbouncer/audit
========================================
  [      OK] integrity: {"files_checked":3,"ok":true,"failures":null}
  [      OK] freshness: {"ok":true,"most_recent":"/home/operator/.kbouncer/audit/audit-2026-05-22-091500.jsonl.gz","age_days":0.5,"threshold_days":7}
  [DEGRADED] disk: {"status":"degraded","reason":"disk usage 92.4% >= warn threshold 85%","used_pct":92.4,"path":"/home/operator/.kbouncer/audit"}
========================================
OVERALL: OK
```

`OVERALL: OK` on `degraded` (the disk has headroom but is trending). `OVERALL: FAIL` (exit 1) only on `critical` disk OR any integrity / freshness failure.

## `/healthz` integration

Each product's `/healthz` payload includes an `audit_log` block:

```json
{
  "audit_log": {
    "status": "degraded",
    "reason": "disk usage 88.2% >= warn threshold 85%",
    "used_pct": 88.2,
    "path": "/home/operator/.ibounce/audit"
  }
}
```

`status` is one of `ok` / `degraded` / `critical`. `critical` flips the
HTTP response to 503 so a k8s liveness probe / external monitor reacts
deterministically. `degraded` keeps HTTP 200 + lets the SIEM rule decide.

`--stop-on-disk-critical` (default OFF) makes the proxy refuse new
requests when `audit_log.status == "critical"`. Default behaviour is
log+continue so a transient disk-full doesn't kill the bouncer.

## Admin-action audit events

Each lifecycle transition emits an admin-action audit event so a
downstream SIEM can answer "did rotation happen / why did the dir
change?":

| `action` field | Fires when |
|---|---|
| `audit.log.rotated` | A successful rotation (size OR age trigger) completed |
| `audit.log.rotation_failed` | Rotation was attempted but failed mid-way; active log keeps growing |
| `audit.log.recovered_partial` | On startup, a partial trailing JSONL line was truncated |
| `audit.log.purged` | An operator ran `*bounce logs purge --older-than ...` |
| `audit.log.archived` | An operator ran `*bounce logs archive --out ...` |

All five share the cross-product wire-name convention so one SIEM rule
keyed on `action == "audit.log.rotated"` catches the lifecycle event
across all four products.

## Crash recovery — partial-write tail

On startup each writer validates the last JSONL line. If it isn't a
complete JSON document we truncate to the last newline before opening for
append. This prevents a corrupt mixed-line from a previous `kill -9` from
poisoning the next write. The trimmed byte count is surfaced as an
`audit.log.recovered_partial` admin-action so the operator sees the
partial-write happened.

Per [[creates-never-mutates]]: this is the ONE place the writer modifies
existing audit bytes. The bytes trimmed are the unrecoverable bytes the
OS failed to fully persist — no information is lost (the partial line is
incomplete and unparseable by definition).

## Long-term archive — Security Lake (#258)

For longer retention than the rotated-archive window, point the
ENTERPRISE Security Lake adapter at the same directory:

```
ibounce run \
  --audit-log-path     /var/log/ibounce/audit.jsonl \
  --security-lake-path /var/log/ibounce \
  --security-lake-bucket s3://my-org-security-lake/iam-jit
```

The adapter ingests rotated `audit-*.jsonl.gz` into the OCSF parquet
schema + uploads to S3. Once the upload succeeds the local archive is
eligible for purge.

## Operator runbook — "audit log degraded" alert

When a monitoring rule fires on `/healthz audit_log.status == "degraded"`:

1. **Triage** — `*bounce doctor logs` (any of the four) tells you which
   check tripped (disk, freshness, integrity).
2. **If disk** — check the log directory size with `du -sh
   ~/.{product}/audit`. The largest contributors are usually old
   `audit-*.jsonl.gz` archives. Purge the ones older than your retention
   window: `*bounce logs purge --older-than 30d --yes`.
3. **If freshness** — the writer hasn't rotated in N days. Check
   `*bounce audit-export health` for write-pipeline errors; the writer
   may be wedged on a downstream operation.
4. **If integrity** — `*bounce logs verify` lists the corrupt files. A
   gzip checksum failure typically means a disk-full event mid-rotation;
   the file can be discarded (the SQLite decision-row is the canonical
   source of truth). Archive the rest of the dir first with `*bounce
   logs archive --out /tmp/before-cleanup.tar.gz` for forensics.

When the alert fires on `audit_log.status == "critical"`:

5. **Immediate** — the disk is >95 % full. The bouncer is still serving
   (default behaviour is log+continue) but every new event risks a
   disk-full write error. Clear space NOW (purge old archives, move the
   bundle off-host via `*bounce logs archive`, etc.).
6. **Optional escalation** — if you set `--stop-on-disk-critical=true`
   the bouncer is currently refusing new requests until disk clears.
   Decide between liveness vs audit-integrity per the
   [[ibounce-honest-positioning]] tradeoff.

## Cross-product parity matrix

| Feature | ibounce | kbounce | dbounce | gbounce |
|---|---|---|---|---|
| Rotation primitives (size, age, gzip) | yes | yes | yes | yes |
| `RecoverPartialTail` | yes (writer-wired) | yes (writer-wired) | yes (writer-wired) | yes (primitive only) |
| `*bounce logs purge / archive / verify` | yes | yes | yes | yes |
| `*bounce doctor logs` | yes | yes | yes | yes |
| `/healthz` disk degraded/critical | yes | yes | yes | yes |
| LogWriter rotation guard | yes | yes | yes | deferred — parallel-agent conflict on `internal/audit/log.go`; re-attempt after parallel work settles |

The gbounce LogWriter-level wiring is the only gap; the primitives + CLI
+ doctor surface all ship on gbounce. Once the concurrent
parallel-agent work on `gbounce/internal/audit/log.go` lands, the same
8-line rotation hook from `dbounce/internal/audit/log.go` ports cleanly.

## Status references

- [[security-team-audit-export]]
- [[self-host-zero-billing-dependency]]
- [[creates-never-mutates]]
- [[cross-product-agent-parity]]
- [[deliberate-feature-completion]]
- [[ibounce-honest-positioning]]
