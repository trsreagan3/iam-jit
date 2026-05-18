# iam-jit Bounce — Datadog content pack

Pipelines, dashboards, monitors, and tag rules for OCSF v1.1.0
class 6003 events emitted by the iam-jit Bounce suite (ibounce /
kbounce / dbounce).

## Overview

| Asset                     | Path                                                    |
|---------------------------|---------------------------------------------------------|
| Manifest                  | `manifest.json`                                         |
| Log pipeline              | `pipelines/iam_jit_bounce.json`                         |
| Overview dashboard        | `dashboards/iam_jit_overview.json` (8 widgets)          |
| Monitors                  | `monitors/iam_jit_*.json` (5 monitors)                  |
| Tag rules                 | `tags/iam_jit_bounce.json`                              |

All assets filter on Datadog `source:iam-jit-bounce`. Configure your
log forwarder (or ibounce's HTTPS webhook) to tag events with that
source.

## Configuration

### Wiring ibounce to send to Datadog

Use the `datadog` webhook preset shipped in ibounce #257:

```
ibounce audit-export configure \
    --webhook-url https://http-intake.logs.datadoghq.com/api/v2/logs \
    --webhook-preset datadog \
    --webhook-auth-header "DD-API-KEY: <YOUR-DD-API-KEY>"
```

The preset adds the required `ddsource=iam-jit-bounce` query
parameter; you don't need to set it manually.

### Pipeline order

After install, the pipeline lands in Logs > Configuration > Pipelines.
**Re-order it above any catch-all JSON pipelines** so attribute
remapping happens before generic processors clobber the iam_jit
fields.

### Monitors

The 5 included monitors target operationally meaningful patterns:

- `iam_jit_admin_action_burst` — >10 ADMIN_ACTION events in 5min
- `iam_jit_heartbeat_gap` — `heartbeat_gap` rule fired
- `iam_jit_burst_detected` — admin-fallback or high-risk-action burst
- `iam_jit_audit_export_failure` — channel health degraded
- `iam_jit_unusual_high_risk` — deny on the high-risk action watchlist

Each monitor's `message` field contains a `@your-team-here` placeholder
— edit to route to your Datadog notification channel (Slack, PagerDuty,
email, etc.) after install.

## Install (manual)

1. Import `manifest.json` via the Datadog Integrations API
   (`POST /api/v2/integrations/custom_packs`).
2. The dashboard, monitors, and pipeline import in one shot; tag
   rules apply to incoming logs immediately.

## Install (Datadog Marketplace, once published)

1. In Datadog: Integrations > Marketplace > search "iam-jit Bounce".
2. Click Install. The pack ships pipeline + dashboard + monitors +
   tag rules together.
3. Configure ibounce's webhook (above) to start sending events.

## Sample event

Every event lands as OCSF v1.1.0 class 6003. The full schema doc
lives at `docs/QUERYING-AUDIT-LOGS.md` in the iam-jit repo; this
pack's pipeline flattens the load-bearing nested fields onto
top-level attributes (`@iam_jit.verdict`, `@iam_jit.event_type`,
`@iam_jit.agent.name`, etc.).

## Support

- Documentation: `docs/QUERYING-AUDIT-LOGS.md` in the iam-jit repo
- Issues: file against the upstream `iam-jit` repo on GitHub
- Publishing runbook: `docs/MARKETPLACE-PUBLISHING.md` in the iam-jit repo

## Privacy + telemetry

This pack contains no agents, no exporters, and no phone-home. The
pipeline runs inside your Datadog tenant; tag rules apply to logs
you ingest. Nothing about your events leaves Datadog.
