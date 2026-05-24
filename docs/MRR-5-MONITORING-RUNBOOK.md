# MRR-5 — In-flight monitoring runbook (2026-05-24)

Phase 5 of the Mission Readiness Review (`[[mrr-flight-readiness-program]]`)
before the founder's work-machine deploy. Companion to:

- [`MRR-1-USE-CASE-AUDIT-2026-05-24.md`](MRR-1-USE-CASE-AUDIT-2026-05-24.md) — use-case gap inventory
- [`MRR-2-ERROR-PATH-AUDIT-2026-05-24.md`](MRR-2-ERROR-PATH-AUDIT-2026-05-24.md) — error-shape catalog
- [`MRR-4-HALT-CONDITIONS.md`](MRR-4-HALT-CONDITIONS.md) — halt-condition catalog
- [`MRR-4-ROLLBACK-RUNBOOK.md`](MRR-4-ROLLBACK-RUNBOOK.md) — per halt: recovery
- [`MRR-4-UNINSTALL.md`](MRR-4-UNINSTALL.md) — clean uninstall

Per founder direction 2026-05-24 ("space shuttle launch" discipline + the
1-week+ dogfood window per `[[no-announce-until-founder-validates]]`): the
operator must KNOW the system is degraded vs healthy without reading source.
This runbook catalogs the monitoring signals + thresholds + response
procedures + cross-references to MRR-4 halt conditions.

Per `[[ibounce-honest-positioning]]` — every "GAP" footer below is honest:
if a signal is not surfaced reliably today (e.g. `iam-jit audit verify` is
on-demand, NOT continuous; canary `denies_24h` is read but never written),
the gap is documented + a fix-task is proposed in §6.

## How to use this runbook

1. Operator (or agent) suspects something is off OR runs the composite
   monitor on a cadence.
2. Match the symptom to one of the signals in §1. Each signal carries its
   own source + healthy / WARNING / CRIT thresholds + response procedure.
3. CRIT-threshold signals cross-reference a MRR-4 halt condition; follow
   the rollback runbook before re-running anything.
4. WARNING-threshold signals don't trigger halt — they're "watch for the
   next tick" + an opportunity to investigate before CRIT.
5. After response: file an `issues.jsonl` entry (`iam-jit canary file-issue`)
   so the canary loop captures the pattern + the founder's dogfood-window
   triage sees it.

## 1. The 11 monitoring signals

### Signal 1 — Disk pressure (audit-log storage)

| Field | Value |
|---|---|
| **Source** | `GET /healthz` → `.audit_log.status` + `.audit_log.disk_free_pct` (per bouncer) |
| **CLI mirror** | `iam-jit audit-export health --healthz-url http://127.0.0.1:8767/healthz` (ibounce-shaped helper at `bouncer_cli.py:6519`) |
| **Healthy** | `status == "ok"`, `disk_free_pct >= warn_pct` (default ~15% free) |
| **WARNING** | `status == "warn"` OR `disk_free_pct` between `warn_pct` (15%) and `crit_pct` (5%) |
| **CRIT** | `status` in `("critical", "emergency")` — bouncer returns HTTP 503 from /healthz; `refuse_requests: true` may be set |
| **Response** | RB-C1 in `MRR-4-ROLLBACK-RUNBOOK.md`. Options: archive-and-purge (set `disk_pressure_mode: archive_and_purge`), enable retention tiering (`iam-jit audit retention apply --framework <pci\|hipaa\|sox\|gdpr>`), or migrate `~/.iam-jit` to a higher-capacity volume. |
| **MRR-4 cross-ref** | C1 (Disk pressure CRITICAL). The Phase F circuit breaker (`src/iam_jit/bouncer/audit_export/disk_pressure.py:504`) populates the block; bouncer returns 503 when state is `critical` / `emergency` (`bouncer/proxy.py:3795-3798`). |
| **Default thresholds** | `warn_pct=15`, `crit_pct=5`, `emergency_pct` default 98% used (see `DEFAULT_DISK_EMERGENCY_PCT`). Overridable via `--disk-warn-pct` / `--disk-crit-pct` / `--disk-emergency-pct` per `bouncer_cli.py:4076-4100`. |
| **Surface status** | SURFACED-RELIABLY — the disk-pressure check is wired into the request loop + /healthz; circuit breaker is tested (`tests/test_disk_pressure_circuit_breaker.py`). |

### Signal 2 — Bouncer process health

| Field | Value |
|---|---|
| **Source** | `iam-jit canary verify-setup --json` exit code + status.json `.pids` |
| **CLI mirror** | `iam-jit canary status --json \| jq '.pids'`; per-bouncer `curl -fsS http://127.0.0.1:<port>/healthz` |
| **Healthy** | Every declared bouncer has a live PID, /healthz returns 200, cmdline matches recorded `daemon_args` |
| **WARNING** | Any bouncer's cmdline diverges from recorded `daemon_args` (e.g. operator-drift; `--upstream` leak per §A102 bug #18) |
| **CRIT** | Any bouncer's PID is missing / not alive / /healthz unreachable; `verify-setup` returns exit 2 |
| **Response** | RB-C3 in `MRR-4-ROLLBACK-RUNBOOK.md`. Inspect last 100 lines of bouncer log (`~/.iam-jit/canary/<bouncer>.log`); restart via `iam-jit canary update` OR manual `_restart_bouncers`. If crash within 60s of restart → file CRIT issue + STOP (do not retry-loop). |
| **MRR-4 cross-ref** | C3 (Bouncer process death) + A2 (port conflict on restart). |
| **Surface status** | SURFACED-RELIABLY — `verify-setup` per `cli_canary.py:953-1050` returns exit 2 with structured JSON; PID liveness + cmdline + /healthz all checked. |

### Signal 3 — Audit chain continuity

| Field | Value |
|---|---|
| **Source** | `iam-jit audit verify --since 24h` exit code |
| **CLI mirror** | `iam-jit audit verify --json --since 24h \| jq .ok` |
| **Healthy** | Exit 0 — chain verifies clean + all manifest signatures verified |
| **WARNING** | `chain.state_file_missing_at_start: true` — chain may have been re-anchored since last full run (per `cli_audit_verify.py:228-232`) |
| **CRIT** | Exit 1 — any `chain.inconsistencies[]` OR any `manifest_findings[]` non-empty |
| **Response** | RB-C2 in `MRR-4-ROLLBACK-RUNBOOK.md` — DATA INTEGRITY HALT. Per `[[creates-never-mutates]]` do NOT modify the broken chain — snapshot DB first (forensic preservation), file CRIT issue, investigate before any further use. |
| **MRR-4 cross-ref** | C2 (Audit chain break detected). |
| **Surface status** | **GAP — on-demand only.** No scheduler runs `audit verify` continuously. Healthz `audit_export.degraded` flag flips on writer failures but does NOT detect mid-chain seq gaps. Per `[[ibounce-honest-positioning]]`: this is operator-driven today; should be a periodic check in the composite monitor. See §6 gap-task M1. |

### Signal 4 — Audit-export queue depth (webhook channel)

| Field | Value |
|---|---|
| **Source** | `GET /healthz` → `.audit_export.queue_depth` + `.audit_export.queue_capacity` + `.audit_export.dropped_count_since_start` (per bouncer) |
| **CLI mirror** | `iam-jit audit-export health` |
| **Healthy** | `queue_depth < queue_capacity * 0.5` AND `dropped_count_since_start == 0` |
| **WARNING** | `queue_depth >= queue_capacity * 0.5` (>50% capacity) |
| **CRIT** | `dropped_count_since_start > 0` (any drops = lost audit events, compliance impact) — also `audit_export.degraded: true` flips bouncer to /healthz 503 per `bouncer/proxy.py:3737-3740` |
| **Response** | Investigate downstream webhook health (Signal 5). Consider `--audit-export-queue-maxsize` tuning. If drops correlate with workload spikes: increase queue size; if drops correlate with webhook failures: fix the destination. |
| **MRR-4 cross-ref** | Not directly halt-listed but compounds with C4 (`/healthz` degraded). |
| **Surface status** | SURFACED-RELIABLY — fields per `audit_export_health_section()` in `bouncer/proxy.py:798-887`. |

### Signal 5 — Webhook health

| Field | Value |
|---|---|
| **Source** | `GET /healthz` → `.audit_export.webhook_consecutive_failures` + `.webhook_last_status_code` + `.webhook_last_success_seconds_ago` |
| **CLI mirror** | `iam-jit audit-export health` |
| **Healthy** | `webhook_consecutive_failures == 0` AND (`webhook_configured == false` OR `webhook_last_success_seconds_ago < 300`) |
| **WARNING** | `webhook_consecutive_failures >= 3` AND `< 5` |
| **CRIT** | `webhook_consecutive_failures > 5` OR (`webhook_configured: true` AND `webhook_last_success_seconds_ago > 300` per `HEALTHZ_AUDIT_WEBHOOK_SILENCE_SECONDS_THRESHOLD`) — bouncer returns /healthz 503 |
| **Response** | Check destination URL connectivity (`curl -fsSI <destination>`); verify auth token still valid; consider rotating webhook URL or temporarily disabling (drops Signal 4 dropped_count_since_start to zero baseline). |
| **MRR-4 cross-ref** | Compounds C4. Vendor-shape verification per `[[vendor-integration-claim-qualifier]]` — Datadog/Splunk/Sentinel/Security Lake are wire-shape compatible but NOT live-tenant tested; founder may need to debug their specific tenant on first wire-up. |
| **Surface status** | SURFACED-RELIABLY — thresholds `HEALTHZ_AUDIT_WEBHOOK_CONSECUTIVE_FAILURE_THRESHOLD=3` and `HEALTHZ_AUDIT_WEBHOOK_SILENCE_SECONDS_THRESHOLD=300` per `bouncer/proxy.py:794-795`. |

### Signal 6 — Anomaly detection alert rate (Phase H ibounce-only)

| Field | Value |
|---|---|
| **Source** | `GET /healthz` → `.anomaly_detection.alerts_emitted_total` + `.anomaly_detection.last_alert_at_unix` (per ibounce; null on kbouncer/dbounce/gbounce — Phase H is ibounce-only per `[[anomaly-detection-mode-phase-h]]`) |
| **CLI mirror** | `iam-jit anomaly status --format json` (baseline DB inspection; does NOT show alert rate over time) |
| **Healthy** | `alerts_emitted_total` baseline derived from operator's normal workload (no fixed default — anomaly is per-deployment) |
| **WARNING** | `alerts_emitted_total` delta over 1 minute > 10 — possible storm or adversarial probing |
| **CRIT** | delta > 100/min — alert flood (likely scoring miscalibration OR genuine adversarial activity) |
| **Response** | Review `iam-jit anomaly status` baseline stats; consider lowering `sensitivity` (`high` → `medium` → `low` preset); if genuine adversarial: investigate via `iam-jit audit query --since 1h`. If miscalibration: file LOW issue (category `calibration_drift`). Anomaly is ADVISORY-only by default (`mode: alert`); deny-mode is opt-in. |
| **MRR-4 cross-ref** | Not directly halt-listed; flooding compounds Signal 9 (decision-rate spike). |
| **Surface status** | **PARTIAL** — counter is surfaced (`/healthz.anomaly_detection.alerts_emitted_total`) per `proxy.py:443-451` but the operator-facing "rate over time" requires composite monitor sampling (see §2). `anomaly status` CLI shows baseline + agents but not alert rate. |

### Signal 7 — Threat-feed subscription health

| Field | Value |
|---|---|
| **Source** | `iam-jit updates last-fetch --json` — per-feed `.last_fetch_at` + `.last_fetch_status` + `.http_status` |
| **CLI mirror** | `iam-jit updates list --show-refused --json` for ledger detail; `iam-jit updates dry-run <feed_url>` for active validation |
| **Healthy** | All declared feeds: `last_fetch_at` within 24h, `last_fetch_status == "ok"`, `http_status == 200` |
| **WARNING** | Any feed: `last_fetch_at` older than 24h, OR `last_fetch_status` non-ok with retry-shape (transient) |
| **CRIT** | `last_fetch_status == "refused_verification"` (signature failure — possible publisher compromise per `[[signed-audit-receipts-v11]]`); OR no successful fetch in >72h (stale threat data) |
| **Response** | For refused_verification: per RB-C6 in MRR-4 — do NOT auto-revert prior denies (they remain valid); inspect publisher key state; if compromised: incident response per `[[signed-audit-receipts-v11]]`. For stale fetch: check publisher availability + operator's egress for the feed URL. |
| **MRR-4 cross-ref** | C5 (Manifest signature verification fails) + C6 (Threat-feed signature verification fails). |
| **Surface status** | SURFACED-RELIABLY — `last-fetch` per `cli_updates.py:522-571`; meta written by fetcher on every attempt. |

### Signal 8 — LLM skip counter (Phase 2/3 silent-degradation visibility)

| Field | Value |
|---|---|
| **Source** | `GET /healthz` → `.llm_skips` block (per bouncer); also surfaced in `autopilot.status.json` `.llm_skips` per `daemon.py:147-154` |
| **CLI mirror** | `iam-jit autopilot status --json \| jq .llm_skips` (when autopilot is running) |
| **Healthy** | `total > 0` is EXPECTED in local-dev / agent-in-loop mode (per `[[bouncer-zero-llm-when-agent-in-loop]]` — bouncers deferring to agent is correct). What matters: ratio + `mode_hint`. |
| **WARNING** | Ramp-up in `total` without corresponding agent activity = possible misconfiguration (agent not calling the MCP tool the bouncer is deferring to) |
| **CRIT** | Operator set `--enable-side-llm` AND `total` is climbing (signals credentials missing / backend unreachable — standalone-mode bouncer is silently deterministic-only) |
| **Response** | Verify `IAM_JIT_LLM` env var is set + provider credentials present (per `autopilot/daemon.py:_validate_side_llm_creds_or_raise`); check `last_skips` ring buffer (last 20 entries with `feature`/`reason`) for the failing site; per `[[ibounce-honest-positioning]]` the skip-counter IS the visibility surface — read it, don't infer. |
| **MRR-4 cross-ref** | None directly — silent-degradation visibility is its OWN halt category per `[[ibounce-honest-positioning]]`. |
| **Surface status** | SURFACED-RELIABLY — `skip_counter_snapshot()` per `llm/report_skip.py:188`; ring buffer caps at 20 (`_MAX_LAST`); logged at WARNING level (NOT debug, per the brief). |

### Signal 9 — Per-bouncer decision rate

| Field | Value |
|---|---|
| **Source** | `GET /healthz` → `.decisions_count` (per bouncer; cumulative since process start) |
| **CLI mirror** | `iam-jit canary status --json` reads `decisions_count` from each bouncer's healthz; autopilot status `bouncers[name].healthz.decisions_count` |
| **Healthy** | Rate matches operator's normal workload (no fixed default; per-deployment baseline) |
| **WARNING** | Sudden spike (>5x recent baseline over 1m) OR sudden drop (<10% of recent baseline) |
| **CRIT** | Decisions stop entirely while process is alive (`decisions_count` flat across multiple polls but bouncer responds /healthz 200) — possible workload-flow broken silently (proxy bypass, port conflict on client side) |
| **Response** | For spike: investigate workload change (CI run? agent unbounded loop?); cross-reference Signal 6 (anomaly). For flat: check client-side `AWS_ENDPOINT_URL` / `HTTPS_PROXY` env vars are still pointing at the bouncer; verify with `iam-jit audit tail --since 5m` (no events = client not routing). |
| **MRR-4 cross-ref** | None directly; compounds with C3 if rate flat AND PID dies. |
| **Surface status** | SURFACED-RELIABLY — `decisions_count` per `proxy.py:3651` + `3854`. Counter is from `store.count_decisions()`; degraded counters flip status to `"degraded"`. |

### Signal 10 — Dynamic-deny rule count

| Field | Value |
|---|---|
| **Source** | `GET /healthz` → `.dynamic_denies` block: `.enabled` + `.rules_count` + `.rules_in_file` + `.total_reloads` + `.total_parse_errors` + `.initial_load_error` |
| **CLI mirror** | `iam-jit deny list` (cross-bouncer fan-out); per-bouncer `iam-jit deny list --bouncer <name>` |
| **Healthy** | `rules_count == rules_in_file` (no parse failures masking rules); `initial_load_error == null`; `total_parse_errors` matches operator's known config-edit count |
| **WARNING** | `rules_count < rules_in_file` (some rules in file did not load — silent partial config); `total_parse_errors` grew without operator edit (possible upstream-pushed dynamic-deny rule with bad shape) |
| **CRIT** | `enabled: true` but `rules_count: 0` AND `initial_load_error != null` — bouncer is enforcing zero rules where operator expected denies |
| **Response** | Inspect dynamic-deny YAML (path in `.dynamic_denies.source_path`); run `iam-jit deny list --json` to see what's actually applied; for parse failures: fix YAML + POST `/admin/dynamic-denies/reload` (per `proxy.py:3875`). |
| **MRR-4 cross-ref** | Compounds with the LOW-bypass risk per `[[ibounce-honest-positioning]]` (deterrent, not boundary). |
| **Surface status** | SURFACED-RELIABLY — `dynamic_denies_block` per `proxy.py:3754-3775`. |

### Signal 11 — Heartbeat gap detection

| Field | Value |
|---|---|
| **Source** | `GET /healthz` → `.heartbeat` block: `.enabled` + `.interval_seconds` + `.last_emit_seconds_ago` + `.gap_detected` |
| **CLI mirror** | `iam-jit audit-export health` |
| **Healthy** | `enabled: false` (default — heartbeat opt-in) OR `gap_detected: false` AND `last_emit_seconds_ago < interval_seconds * alert_heartbeat_missing_count` (default count=2) |
| **WARNING** | `last_emit_seconds_ago >= interval_seconds` but `< interval_seconds * 2` (heartbeat late, not yet gap) |
| **CRIT** | `gap_detected: true` — bouncer flips /healthz to 503 per `proxy.py:3720-3728`; audit-export channel itself is broken (rule may not observe events) |
| **Response** | Check audit-export config (`--audit-webhook-url` / `--audit-log-path` reachable); if webhook destination is down: heartbeats fail until restored. Heartbeat is the canary for the audit channel itself, so this is the "audit channel is silent" alarm. |
| **MRR-4 cross-ref** | Compounds C4 (/healthz degraded) — heartbeat gap is one of the 503-flip triggers alongside disk-pressure + audit_export.degraded. |
| **Surface status** | SURFACED-RELIABLY when enabled; opt-in per `--heartbeat-interval-seconds` flag — the default-disabled posture means an operator who hasn't enabled heartbeats has NO heartbeat visibility. Per `[[ibounce-honest-positioning]]`: heartbeat opt-in is correct (audit-channel-down is rare) but operators in compliance-heavy deployments should enable it. |

## 2. Composite monitoring command (NEW SUBCOMMAND SPEC)

Implementation TBD as a separate fix task — this section is the spec the
implementer follows. Lives in `src/iam_jit/cli_canary.py` alongside
`verify-setup` (shares the bouncer-iteration scaffold).

### `iam-jit canary monitor`

```
Usage: iam-jit canary monitor [OPTIONS]

  §A102+ — composite monitoring snapshot across all canary-running
  bouncers. Aggregates the 11 MRR-5 signals + maps each to an MRR-4
  halt condition for response procedure cross-reference.

Options:
  --json              Emit structured JSON (per-signal {status, value,
                      threshold, ref}). Suitable for cron + jq.
  --since DURATION    Window for rate-based signals (anomaly, decision
                      rate). Defaults to 5m.
  --verbose           Include full /healthz body per bouncer.

Exit codes:
  0  All signals GREEN
  1  At least one WARNING (no CRIT)
  2  At least one CRIT
```

#### Output shape (`--json`)

```json
{
  "schema_version": "1.0",
  "captured_at": "2026-05-24T18:00:00Z",
  "overall_status": "ok|warning|crit",
  "exit_code": 0,
  "bouncers_checked": ["ibounce", "gbounce", "kbouncer", "dbounce"],
  "signals": {
    "disk_pressure": {
      "status": "ok|warning|crit",
      "per_bouncer": {
        "ibounce": {"status": "ok", "disk_free_pct": 87.3,
                    "warn_pct": 15, "crit_pct": 5}
      },
      "mrr5_signal": 1,
      "mrr4_halt_ref": "C1",
      "response_procedure": "docs/MRR-5-MONITORING-RUNBOOK.md#signal-1-disk-pressure-audit-log-storage"
    },
    "bouncer_process_health": { ... mrr5_signal: 2, mrr4_halt_ref: "C3" ... },
    "audit_chain_continuity": { ... mrr5_signal: 3, mrr4_halt_ref: "C2",
                                  "gap_today": "on-demand only" ... },
    "audit_export_queue": { ... mrr5_signal: 4 ... },
    "webhook_health": { ... mrr5_signal: 5, mrr4_halt_ref: "C4" ... },
    "anomaly_alert_rate": { ... mrr5_signal: 6 ... },
    "threat_feed": { ... mrr5_signal: 7, mrr4_halt_ref: "C5+C6" ... },
    "llm_skips": { ... mrr5_signal: 8 ... },
    "decision_rate": { ... mrr5_signal: 9 ... },
    "dynamic_denies": { ... mrr5_signal: 10 ... },
    "heartbeat": { ... mrr5_signal: 11, mrr4_halt_ref: "C4" ... }
  },
  "crit_count": 0,
  "warning_count": 0,
  "ok_count": 11
}
```

#### Implementation notes

- Reuse `_curl_responsive` from `cli_canary.py:251` for /healthz polling.
- Iterate `status.get("ports")` (skip `*_mgmt` sub-ports for proxy-bouncer
  list; use them for the auxiliary /healthz fetches per `cli_canary.py:981`).
- For Signal 3 (audit chain): invoke `cli_audit_verify.verify_chain_jsonl`
  directly (don't shell out to `iam-jit audit verify`) — it's a thin call.
- For Signal 9 (decision rate): cache previous tick's `decisions_count` in
  `~/.iam-jit/canary/monitor.state.json` so rate can be computed without
  needing a SIEM. Reset on bouncer restart (compare PID).
- For Signal 7 (threat-feed): invoke `cli_updates._do_last_fetch` with
  `as_json=True` against an in-memory click context.
- Color-coded human output uses `click.secho` with green / yellow / red.
- Cross-bouncer aggregation: if Signal X is CRIT on ibounce + OK on
  kbouncer, overall_status = CRIT (worst wins).

### Cron-friendly invocation

```cron
# Poll every minute; alert on degraded (exit 1 or 2)
* * * * * cd ~/repos/iam-roles && iam-jit canary monitor --json \
  | jq -e '.overall_status == "ok"' >/dev/null \
  || /usr/local/bin/pushover-send "iam-jit degraded — run \`iam-jit canary monitor\`"
```

For ops who want richer alerting:

```cron
*/5 * * * * iam-jit canary monitor --json > ~/.iam-jit/canary/last-monitor.json \
  && python3 ~/bin/iam-jit-alert-router.py < ~/.iam-jit/canary/last-monitor.json
```

`iam-jit-alert-router.py` is operator-supplied (Pushover / PagerDuty / OpsGenie
shim). The runbook intentionally does NOT prescribe an alerting backend per
`[[no-hosted-saas]]` — operator's existing on-call infra owns notification
routing.

### `iam-jit canary monitor --watch` (followup)

Long-running mode: re-poll every N seconds (default 60), emit deltas only
(new CRIT/WARNING transitions). Useful for the founder's dogfood window —
keeps a terminal tab dedicated to monitoring without sysadmin tooling.

Implementation is straightforward: wrap the once-only flow in
`while True: ... sleep(N)` with transition-detection state in memory.
Spec NOT separately filed — implementer can add as `--watch` flag in the
same task.

## 3. Long-running dogfood signals (founder's 1-week+ window)

Per `[[no-announce-until-founder-validates]]` the founder will personally
use iam-jit on the work machine for ≥1 week of real dev work. Beyond the
real-time monitoring above, the dogfood window benefits from DAILY +
WEEKLY aggregation:

### Daily summary (NEW SUBCOMMAND SPEC)

```
iam-jit canary dogfood-report --since 24h [--json]
```

Aggregates issues.jsonl + canary status.json + threat-feed ledger + audit
events into a single daily digest. Lives next to `iam-jit canary report`
(`cli_canary.py:746-822`) which already does most of this; `dogfood-report`
is the founder-shaped extension.

Daily metrics:
- **Denies count**: from `iam-jit audit query --since 24h --status deny`
  cross-bouncer aggregate
- **Anomalies count**: from `/healthz.anomaly_detection.alerts_emitted_total`
  delta (start-of-day vs end-of-day; persisted by the monitor's state file)
- **False-positive denies** (operator-flagged): from
  `iam-jit canary file-issue --category deny_surprise` count
- **LLM skips**: from `/healthz.llm_skips.total` delta
- **Profile-iteration count**: how many times `iam_jit_improve_profile` was
  called (from autopilot.status.json `improve.improve_count_since_startup`)
- **Disk usage trend**: today's `disk_free_pct` vs 7-day average (alert if
  trending toward Signal 1 thresholds)

Output shape mirrors `canary report --json`:

```json
{
  "since": "24h",
  "denies_count": 23,
  "anomalies_count": 0,
  "false_positives": 1,
  "llm_skips_delta": 47,
  "improve_cycles": 3,
  "disk_trend": {"now_pct_free": 87.3, "7d_avg": 88.1, "trend": "stable"},
  "issues_by_category": {"deny_surprise": 1, "operator_friction": 2}
}
```

### Weekly retention check

```
iam-jit audit retention apply --framework <op-choice> --dry-run
```

Run weekly during dogfood. Confirms `~/.iam-jit` isn't ballooning AND
isn't aggressively pruning beyond operator's compliance window.

Pair with `du -sh ~/.iam-jit/{bouncer,canary,audit-archive}` for raw size.

### Pre-filed dogfood-window questions

These are the questions the founder per `[[no-announce-until-founder-validates]]`
will want answers to at end-of-week:

| Question | Answered by signal |
|---|---|
| "Did anything break that I didn't notice?" | Signal 3 (chain), 4 (drops), 5 (webhook fails), 8 (LLM skip ramp) |
| "Did I see false-positive denies?" | issues.jsonl `category: deny_surprise` count |
| "Did the bouncers stay up all week?" | Signal 2 (process health); look for restart-events in autopilot.status.json |
| "Is the audit log filling my disk?" | Signal 1 trend |
| "Did anomaly detection alert on real things?" | Signal 6 — review per-alert reasoning in audit tail |
| "Would I be comfortable having a colleague install this?" | Composite — sum of issues.jsonl with severity >= MED |

## 4. Cross-reference with MRR-4

Every MRR-4 halt condition must map to at least one MRR-5 monitoring signal.
If a halt condition can fire WITHOUT a monitoring signal surfacing it, that
is a CRIT gap (operator hits the halt with no warning).

| MRR-4 halt | MRR-5 signal | Coverage |
|---|---|---|
| A1 — Disk full at install time | Signal 1 (pre-install variant) | PARTIAL — operator runs `df -h` manually; no `iam-jit doctor preflight` (MRR-4 gap) |
| A2 — Port conflict | Signal 2 (verify-setup catches via /healthz unreachable) | RELIABLE |
| A3..A9 — install prerequisites | None — pre-install only | OK (install commands self-report) |
| B1 — Bouncer startup config-parse | Signal 2 (/healthz unreachable) | RELIABLE |
| B2 — /healthz never reaches 200 in 30s | Signal 2 | RELIABLE |
| B3 — Audit chain initialization fails | Signal 3 (on-demand) + Signal 11 (gap) | **PARTIAL — chain init failure surfaces in bouncer log but not /healthz until first event tries to write** |
| B4 — Permission denied on ~/.iam-jit | Signal 2 (/healthz won't start) | RELIABLE |
| B5 — Anomaly baseline DB | Signal 6 (alerts_emitted_total stays 0; degraded-not-halt) | RELIABLE-as-degraded |
| B6 — Partial install (UC-20 load-bearing) | Signal 2 (verify-setup detects mismatch) | RELIABLE — `verify-setup` exit 2 catches missing PID per declared bouncer |
| B7..B8 — wheel / go build failures | None at runtime | OK (install-time) |
| **C1 — Disk pressure CRITICAL** | **Signal 1** | RELIABLE |
| **C2 — Audit chain break** | **Signal 3** | **GAP — on-demand only; composite monitor must invoke periodically** |
| **C3 — Bouncer process death** | **Signal 2** | RELIABLE |
| **C4 — /healthz degraded** | **Signals 1 + 4 + 5 + 11 (all 503-flip triggers)** | RELIABLE |
| **C5 — Manifest signature fails** | **Signal 7 (`refused_verification` status)** | RELIABLE |
| **C6 — Threat-feed signature fails** | **Signal 7** | RELIABLE |
| C7 — LLM cost-cap breach | None — autopilot logs `llm_budget_exhausted` to its own alerts list, surfaced via `iam-jit autopilot status` | **GAP — composite monitor should read `autopilot.status.json` `.alerts`** |
| C8 — SQLite corruption | Signal 2 (/healthz crashes/degrades) | RELIABLE-as-degraded |
| D1..D8 — Update halt conditions | issues.jsonl `category: update_failure` | RELIABLE — `_fail` per `cli_canary.py:1206` always logs |

### CRIT gaps (must be closed before deploy OR documented as known-deferred)

1. **Audit chain continuity check is on-demand only.** Signal 3 has no
   continuous scheduler today. The composite `canary monitor` spec above
   closes this by invoking `verify_chain_jsonl` per-poll. File as gap-task
   M1.
2. **Audit chain init failure (B3) doesn't surface to /healthz until first
   event.** If the chain state file fails to initialize at bouncer cold-
   start, the bouncer logs an error but the `/healthz.audit_export` block
   shows `configured: true, log_writes_ok: true` until the first write
   attempt. File as gap-task M2.
3. **LLM cost-cap breach (C7) is not in any /healthz block.** Only surface
   is `iam-jit autopilot status` `.alerts` array. Composite monitor must
   include this. File as gap-task M3.

## 5. Cron-friendly invocation patterns

### Minimal — single check, alert on degraded

```bash
* * * * * iam-jit canary monitor --json \
  | jq -e '.overall_status == "ok"' >/dev/null \
  || notify-send "iam-jit DEGRADED"
```

### Tiered — separate alerts per severity

```bash
* * * * * out=$(iam-jit canary monitor --json); \
  echo "$out" | jq -e '.crit_count == 0' >/dev/null \
  || pushover-send -p2 "iam-jit CRIT: $(echo "$out" | jq -r '.signals | to_entries[] | select(.value.status==\"crit\") | .key' | paste -sd ',')"; \
  echo "$out" | jq -e '.warning_count == 0' >/dev/null \
  || pushover-send -p0 "iam-jit WARN: $(echo "$out" | jq -r '.signals | to_entries[] | select(.value.status==\"warning\") | .key' | paste -sd ',')"
```

### Daily dogfood digest

```bash
0 9 * * * iam-jit canary dogfood-report --since 24h --json \
  > ~/Documents/iam-jit-dogfood/$(date +\%F).json
```

Founder's `~/Documents/iam-jit-dogfood/` becomes the evidence corpus the
end-of-week validation review reads.

## 6. Gap-tasks to file (parent agent)

These are the implementation tasks the runbook surfaces; they are the
implementations of the SPEC sections above + the CRIT-gap closures.

### Pre-deploy (BLOCK)

| # | Task | Severity | Effort |
|---|---|---|---|
| **M1** | Implement `iam-jit canary monitor` subcommand per §2 spec; map all 11 signals to /healthz + CLI sources; cross-reference MRR-4 halt conditions in output. Include `--watch` flag. | **CRIT** (composite is the single-pane-of-glass without which operator must read source) | 1-2 days |
| **M2** | Add `audit_export.chain_initialized` field to /healthz so cold-start chain-init failure surfaces immediately (closes B3 gap noted in §4). | HIGH | 0.5 day |
| **M3** | Add `autopilot.status.json` `.alerts` to composite monitor input set OR mirror `llm_budget_exhausted` to `/healthz.llm_budget` block on each bouncer (closes C7 gap noted in §4). | HIGH | 0.5 day |
| **M4** | Wire `denies_24h` / `intervention_count_24h` / `improvement_cycles` in canary status.json — these fields are read by `cli_canary.py:707-712` but NEVER WRITTEN (found via grep — only test files reference them as readers). Composite monitor will produce hollow output otherwise. | **CRIT** (claimed-but-not-produced data is the [[scorer-is-ground-truth]]-shape violation) | 0.5 day |

### Pre-promotion (HIGH; can land in dogfood week)

| # | Task | Severity | Effort |
|---|---|---|---|
| M5 | Implement `iam-jit canary dogfood-report` subcommand per §3 spec; reuses `canary report` aggregator. | HIGH | 0.5 day |
| M6 | Document in `docs/MONITORING.md` (operator-facing) the composite monitor command + thresholds; link to MRR-5 for the threshold-rationale. | HIGH | 0.5 day |
| M7 | Make heartbeat opt-in default-on under `iam-jit.canary: true` YAML (closes Signal 11 gap — operators in canary mode get heartbeat coverage by default). | MED | 0.5 day |

### Post-deploy (LOW; quality-of-life)

| # | Task | Severity | Effort |
|---|---|---|---|
| M8 | Cross-bouncer threshold rationale doc in `docs/THRESHOLDS.md` — explain why `webhook_consecutive_failures > 3` flips /healthz to 503 vs `> 5` flips the rule (the "operator-action signal vs monitoring probe" distinction per `bouncer/proxy.py:790-793`). | LOW | 0.25 day |
| M9 | Vendor-shape monitoring integration recipes (Datadog/Splunk/PagerDuty/OpsGenie) — show the operator how to ingest `/healthz` JSON per the standard exporter shape. Per `[[vendor-integration-claim-qualifier]]` — wire-shape only, not live-tested. | LOW | 1 day |

## 7. Cross-cutting findings

1. **Composite monitoring is the single most-impactful missing surface.**
   Every individual signal is reliably surfaced today; the operator
   currently must `curl` /healthz on each bouncer + jq fields + cross-
   reference. The `canary monitor` spec above is THE operator-side single-
   pane-of-glass. Without it the operator must read source to know
   "is everything ok right now?" — which violates the MRR-5 acceptance
   criterion from `[[mrr-flight-readiness-program]]`.

2. **Audit chain verification is on-demand only.** `iam-jit audit verify`
   is the canonical chain-integrity check; nothing runs it on a cadence.
   Per `[[ibounce-honest-positioning]]`: this is documented honestly as
   a GAP. Composite monitor must invoke `verify_chain_jsonl` directly
   per poll OR a separate scheduler must run on a cron (M1 covers the
   former).

3. **`denies_24h` / `intervention_count_24h` / `improvement_cycles` are
   read but never written.** `cli_canary.py:707-712` reads these fields
   from `status.json`; grep across the repo shows NO writer. This is the
   exact #475 shape (status-claimed-without-state) the convention was
   written to prevent. M4 closes this.

4. **Heartbeat is opt-in by default.** Operators in compliance-heavy
   deployments (founder's work AWS account, per `[[founder-success-criteria]]`)
   should enable it so the "audit-channel-itself-broken" alarm fires.
   M7 makes this default-on under `canary: true`.

5. **LLM-skips are surfaced correctly per `[[bouncer-zero-llm-when-agent-in-loop]]`.**
   `total > 0` is the EXPECTED state — bouncer deferring to agent IS
   right. The monitoring distinction is ratio + `mode_hint`, not raw count.
   Signal 8 documents this correctly; operator confusion would be the
   real risk and `docs/MONITORING.md` (M6) should lead with this.

6. **Threat-feed `refused_verification` is the ONLY signal that maps to
   a compromise-shaped event (Signal 7 → C5/C6).** Per `[[signed-audit-receipts-v11]]`
   this is the load-bearing security claim. Composite monitor must
   surface this at CRIT, never WARNING — the threshold matrix in §1
   above is explicit on this.

7. **No alerting backend prescribed.** Per `[[no-hosted-saas]]` we don't
   ship a SaaS alert routing service. The cron snippets in §5 are
   operator templates; M9 documents the wire-shape for self-rolled
   integrations. This is the right shape but worth noting: a fresh
   operator runs `monitor` once, then has to wire their own notification
   path. MRR-6 operator runbook should call this out as a day-1 setup
   step.

---

End of MRR-5 in-flight monitoring runbook.
