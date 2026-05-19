# Per-org notification routing (#280)

**Status:** Shipped 2026-05-19. Enterprise-tier; license-gated.

This is the canonical reference for the per-org notification routing
engine. kbouncer + dbounce link back to this document for cross-product
consistency.

## What it does

Today's `--audit-webhook-url` flag wires the bouncer to ONE collector
per deployment. That works for a single team / single SIEM. It breaks
at org scale where:

- the SOC team wants every Medium+ event in their Splunk;
- the dev team wants only their own events in Datadog;
- on-call should be paged on Critical-only via PagerDuty + Slack;
- everything should also archive to a central S3 bucket (fan-out).

The routing engine takes one YAML file + matches each event against
multiple routes + dispatches to per-route destinations. It does NOT
mutate the event (per `[[creates-never-mutates]]`); routes are
deterministic SHIPPING filters, never policy verdicts.

## Quick start

```bash
$ export SOC_SPLUNK_HEC_TOKEN=...
$ export PD_INTEGRATION_KEY=...
$ export SLACK_ONCALL_WEBHOOK=https://hooks.slack.com/services/T1/B2/secret
$ export CENTRAL_ARCHIVE_TOKEN=...
$ ibounce config preview-routes \
      --routes ~/.iam-jit/ibounce-routes.yaml \
      --event sample-event.json
$ ibounce run --alert-routes ~/.iam-jit/ibounce-routes.yaml
```

The dry-run is **mandatory** pre-deploy validation per
`[[per-org-notification-routing]]` — YAML routing is dense + error-prone.

## YAML schema

```yaml
routes:
  # 1. SOC team — every Medium+ event to their Splunk.
  - name: soc-high-severity
    match:
      severity_id: { gte: 3 }
    destinations:
      - webhook:
          url: https://splunk-soc.internal/services/collector/event
          token: ${SOC_SPLUNK_HEC_TOKEN}
          preset: splunk-hec

  # 2. Dev team — events tagged with their team claim go to Datadog.
  - name: dev-team-own-events
    match:
      actor.user.attribute.team: dev
    destinations:
      - webhook:
          url: https://datadog-dev.internal/api/v2/logs
          token: ${DEV_DATADOG_API_KEY}
          preset: datadog

  # 3. On-call — Critical-only, fan out to PagerDuty + Slack.
  - name: on-call-critical
    match:
      severity_id: 5
    destinations:
      - pagerduty:
          integration_key: ${PD_INTEGRATION_KEY}
      - slack:
          webhook_url: ${SLACK_ONCALL_WEBHOOK}

  # 4. Central archive — everything (fan-out alongside the routes above).
  - name: central-archive
    match: {}
    destinations:
      - webhook:
          url: https://archive-collector/api/v1/audit
          token: ${CENTRAL_ARCHIVE_TOKEN}
          preset: generic
    on_match: continue
```

### Match operators

Each route's `match:` block is an AND of `(path, condition)` pairs.

| Operator | Shape                       | Example                                  |
|----------|-----------------------------|------------------------------------------|
| equals   | scalar (default)            | `severity_id: 3`                         |
| equals   | `{equals: V}`               | `severity_id: {equals: 3}`               |
| gte      | `{gte: N}` (numeric)        | `severity_id: {gte: 3}`                  |
| lte      | `{lte: N}` (numeric)        | `severity_id: {lte: 3}`                  |
| gt       | `{gt: N}`                   | `severity_id: {gt: 2}`                   |
| lt       | `{lt: N}`                   | `severity_id: {lt: 5}`                   |
| in       | `{in: [V1, V2, ...]}`       | `severity_id: {in: [3, 4, 5]}`           |
| match    | `{match: "regex"}`          | `api.operation: {match: "iam:Create.*"}` |
| glob     | `{glob: "g*lob"}` (icase)   | `api.operation: {glob: "iam:create*"}`   |

Dotted paths walk nested dicts (`actor.user.attribute.team`). The
suffix `[]` walks a list-of-dicts at that point in the path
(`resources[].uid`).

### `on_match`

- `stop` (**default**) — if this route matches, do NOT evaluate
  subsequent routes for this event. Most customers want explicit
  first-match-wins.
- `continue` — evaluate subsequent routes too. Use for fan-out (e.g.
  "central archive gets everything in addition to whatever else
  matched").

### Destination types

- `webhook` — same shape as `--audit-webhook-url`; supports the
  per-vendor presets from #257 (`generic` / `datadog` / `splunk-hec` /
  `sentinel`). Per-destination `allow_internal: true` opts that
  destination's SSRF gate out for intranet collectors.
- `pagerduty` — Events API v2 enqueue against
  `https://events.pagerduty.com/v2/enqueue`. Body uses the documented
  PD shape (`routing_key` + `event_action: trigger` + `payload` with
  `severity` / `source` / `summary` / `custom_details=<OCSF event>`).
  Optional `severity: info|warning|error|critical` (default
  `warning`).
- `slack` — POST against the incoming-webhook URL. Body is `{text: ...}`
  using neutral language per
  `[[security-team-positioning-safety-not-surveillance]]`.

No SDK dependencies — both PagerDuty + Slack are raw HTTP POSTs against
their documented endpoints. Future destinations (`email`, `kafka`,
`s3`, `serviceNow`) are deferred per the memo until customer asks.

## Secret handling

Secrets MUST be passed as `${ENV_VAR}`. Bare literal tokens in the YAML
are refused at parse time. The engine reads the resolved value at
startup; if the env var is unset, the proxy refuses to start with a
clear error pointing at the offending field.

Startup banner masks each resolved secret as
`ENV_NAME (first-8-char-prefix***)`:

```
audit-export per-org routing engine enabled: routes=4 destinations=5
  secret CENTRAL_ARCHIVE_TOKEN (archivet***)
  secret DEV_DATADOG_API_KEY (dd-api-k***)
  secret PD_INTEGRATION_KEY (pdkey123***)
  secret SLACK_ONCALL_WEBHOOK (https://***)
  secret SOC_SPLUNK_HEC_TOKEN (splunkto***)
```

The full secret value NEVER appears in any log line, status surface,
error message, or the routes YAML file itself.

Best practices:

- store secrets in your secret manager (Vault, AWS Secrets Manager,
  CyberArk Conjur, etc.) and export them into the bouncer's process
  env at start;
- rotate secrets out-of-band; restart the bouncer to pick up the new
  values (a HUP-based reload is on the roadmap);
- never commit a routes YAML with hard-coded tokens — the loader
  refuses them, but the YAML itself should also be reviewable by a
  human without secret-handling concerns.

## Backward compatibility

When `--alert-routes` is unset, the existing single-webhook path
(`--audit-webhook-url` + `--audit-webhook-token` + `--audit-webhook-preset`
+ ...) stays EXACTLY as today. Zero regression for current deployments.

When BOTH `--alert-routes` and `--audit-webhook-url` are set, the
routing engine wins + the single-webhook flag is ignored with a
warning at CLI parse time and at startup. Pick one shape per
deployment.

## Dry-run / preview

```bash
$ ibounce config preview-routes \
      --routes ~/.iam-jit/ibounce-routes.yaml \
      --event ./sample-event.json
routes config: /home/op/.iam-jit/ibounce-routes.yaml
event: ./sample-event.json
total routes defined: 4
secrets resolved (env-var name + masked prefix):
  CENTRAL_ARCHIVE_TOKEN (archivet***)
  PD_INTEGRATION_KEY (pdkey123***)
  SLACK_ONCALL_WEBHOOK (https://***)
  SOC_SPLUNK_HEC_TOKEN (splunkto***)
matched 1 route(s):
  - soc-high-severity (on_match=stop)
      destination: type=webhook, url=https://splunk-soc.internal/..., token=***, preset=splunk-hec, allow_internal=False
```

No HTTP traffic is sent. The output never prints any secret value.

## License gating

`--alert-routes` requires an Enterprise license. The single-destination
`--audit-webhook-url` channel + the JSONL log file + Security Lake
adapter stay available on every tier. The license gate fires at CLI
parse AND at `serve()` start (defense in depth) so a license file that
disappeared between parse + start cannot quietly grant routing
capability.

## Composition

- Each route's `webhook` destination supports the per-vendor presets
  from [#257 (audit-webhook-presets)](AUDIT-WEBHOOK-PRESETS.md), so the
  same one-click SIEM ingest works under multi-destination routing.
- The AWS Security Lake adapter (#258) writes parquet to S3
  alongside the routes engine; you can also point a `webhook`
  destination at a Lambda that ingests into Security Lake if you want
  a per-route Security Lake fan-out.
- Routes can match on agent-identity fields (`unmapped.iam_jit.agent.
  name`) for per-agent routing — useful when one team's automated
  Claude instance should route to a different collector than a
  human-driven session.

## Constraints + don'ts

Per `[[per-org-notification-routing]]`:

- Don't expose tokens in the routes YAML — always use `${ENV_VAR}`.
- Don't make `on_match: continue` the default; most customers want
  first-match-wins. Operators opt INTO fan-out per route.
- Don't add Kafka / SMTP / ServiceNow destinations pre-launch.
  Webhook + PagerDuty + Slack covers the v1.0 demand surface.
- Don't make the routes engine LLM-augmented. Deterministic
  match-engine only.
