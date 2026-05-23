# Audit-Webhook Presets

Cross-product reference for the `--audit-webhook-preset` flag shipped
by every audit-export Bounce product (ibounce, kbounce, dbounce). The
preset selects a per-vendor wire shape so an operator pointing
`*bounce` at their existing SIEM gets auto-categorisation without
writing a custom ingest mapping.

Per [[audit-webhook-presets]]: the canonical OCSF event written to
the JSONL log file is UNCHANGED regardless of preset. Presets only
affect what gets sent over the HTTPS webhook (headers + body).

Per [[cross-product-agent-parity]]: same preset names, same overlay
semantics, same flag set across all three audit-export Bounce
products. A SIEM consuming events from the whole suite gets identical
vendor-native shapes — pivot by `metadata.product.name` to
distinguish.

Per [[scorer-is-ground-truth]] + [[security-team-positioning-safety-not-surveillance]]:
adapters are pure data transformation. They never re-evaluate severity
or verdict. Overlay language stays neutral — no
"violation"/"unauthorized"/"infraction" framing.

## The four presets

> **Vendor-integration qualifier** (per `[[vendor-integration-claim-qualifier]]`):
> wire shape verified against each vendor's published intake spec
> (commit `1020c73` ships 9 schema-conformance tests). Live-tenant
> ingestion has NOT been performed against a paid Datadog org /
> Splunk Cloud tenant / Azure Sentinel workspace / AWS Security Lake
> instance — that is a ~60-second exercise the operator runs on
> first install. Do NOT claim "tested with Datadog" or "live-validated"
> in downstream copy until your tenant has actually exercised the
> integration.

| Preset       | When to use                                                                                              | Auth                                                              | Body                       |
|--------------|----------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------|----------------------------|
| `generic`    | Default. Existing webhook consumers + custom ingest scripts. Pre-#257 byte-identical wire shape.         | `Authorization: Bearer <token>`                                   | NDJSON (or JSON array for kbounce — see "Per-product wire shapes") |
| `datadog`    | Datadog Logs HTTP intake.                                                                                | `DD-API-KEY: <api_key>`                                           | JSON array of OCSF events overlaid with DD-native fields (`ddsource`, `service`, `ddtags`, `status`, `message`) |
| `splunk-hec` | Splunk HTTP Event Collector.                                                                             | `Authorization: Splunk <hec_token>`                               | NDJSON, each line wraps the OCSF event under HEC's `event` envelope |
| `sentinel`   | Microsoft Sentinel / Log Analytics Workspace.                                                            | `Authorization: SharedKey <workspace-id>:<HMAC-SHA256>` (computed) | JSON array — one row per element in the Log-Type custom table |

## Choosing the right preset

1. Pick the preset that matches your existing SIEM.
2. If your SIEM isn't one of the named ones (Splunk Cloud, IBM QRadar,
   Sumo Logic, ...), stay on `generic` + write a thin custom ingest
   mapping against the OCSF v1.1.0 class 6003 shape (the same OCSF
   event the named presets also carry).
3. If you're shipping to multiple SIEMs, run multiple bouncer
   processes (or, future #258, the Security Lake S3+parquet adapter).

## Per-vendor token acquisition

### Splunk HEC token

1. Splunk Web → **Settings → Data Inputs → HTTP Event Collector**.
2. **Global Settings**: enable HEC, take note of the port (default
   `8088`).
3. **New Token**: name it `iam-jit`, source type `iam_jit:bouncer:<product>`
   (or leave blank — the preset overrides it per-event), assign the
   index you want (e.g. `security`).
4. Save. Copy the **Token Value** (UUID-shaped) — that's the value
   for `--audit-webhook-token`.
5. The URL is `https://<your-splunk-host>:8088/services/collector/event`.

### Datadog API key

1. Datadog → **Organization Settings → API Keys**.
2. **New Key** → name `iam-jit`. Copy the key — that's
   `--audit-webhook-token`.
3. The URL depends on your DD site. US1:
   `https://http-intake.logs.datadoghq.com/api/v2/logs`.
   Other sites: `https://http-intake.logs.<site>` (eu / us3 / us5 / ap1).

### Microsoft Sentinel shared key

1. Azure portal → your Log Analytics Workspace → **Agents → Log
   Analytics agent instructions**.
2. Copy the **Workspace ID** + the **Primary Key** (or Secondary Key).
3. Pass the Primary Key (base64-encoded already) as
   `--audit-webhook-token`.
4. The URL is
   `https://<workspace-id>.ods.opinsights.azure.com/api/logs?api-version=2016-04-01`.
5. The custom-log table name defaults to `IamJitBouncer`; override
   with `--audit-webhook-sentinel-table`.

### Generic Bearer token

Any value your endpoint expects in `Authorization: Bearer <X>`.
Self-hosted collectors typically generate one out-of-band.

## Per-product wire shapes

### `generic`

ibounce + dbounce emit NDJSON (newline-delimited). kbounce emits a
JSON array (the Slice-1 pre-#257 wire shape — preserved verbatim
for backward compatibility).

Example body (NDJSON, batch_size=2):

```
{"metadata":{"version":"1.1.0",...},"activity_id":2,...}
{"metadata":{"version":"1.1.0",...},"activity_id":1,...}
```

Headers:

```
Authorization: Bearer <token>
Content-Type: application/json
User-Agent: <product>-audit-export/1.0
```

### `datadog`

Headers:

```
DD-API-KEY: <key>
Content-Type: application/json
User-Agent: <product>-audit-export/1.0
```

Body (JSON array; one element per OCSF event with vendor overlay
fields layered on):

```json
[
  {
    "metadata": {"version": "1.1.0", ...},
    "activity_id": 4,
    "status_id": 2,
    "status": "Failure",
    "unmapped": {"iam_jit": {"verdict": "DENY", "enforced": true, ...}},
    "ocsf": {"status": "Failure"},
    "ddsource": "iam-jit",
    "service": "ibounce",
    "host": "s3.us-east-1.amazonaws.com",
    "ddtags": "product:iam-jit,bouncer:ibounce",
    "status": "error",
    "message": "DENY DeleteObject on report.csv (transparent enforced)"
  }
]
```

OCSF field-overlap policy: when DD reserves a field name (`status`,
`host`) the OCSF original is preserved under `ocsf.<name>`.

### `splunk-hec`

Headers:

```
Authorization: Splunk <hec_token>
Content-Type: application/json
User-Agent: <product>-audit-export/1.0
```

Body (NDJSON; each line one HEC envelope):

```
{"event":{"metadata":{"version":"1.1.0",...},...},"sourcetype":"iam_jit:bouncer:ibounce","source":"iam-jit","host":"s3.us-east-1.amazonaws.com","time":1715990000.0}
```

OCSF `time` (Unix milliseconds) is converted to HEC's fractional
Unix seconds.

### `sentinel`

Headers:

```
Authorization: SharedKey <workspace-id>:<base64-HMAC-SHA256>
Log-Type: IamJitBouncer
x-ms-date: Sat, 18 May 2026 12:00:00 GMT
Content-Type: application/json
User-Agent: <product>-audit-export/1.0
```

Body (JSON array of OCSF events; one row per element in the
`Log-Type` custom table):

```json
[
  {"metadata":{"version":"1.1.0",...},"activity_id":2,...}
]
```

The `SharedKey` HMAC is computed per Microsoft's Data Collector API
spec over `POST\n<content-length>\napplication/json\nx-ms-date:<date>\n/api/logs`,
keyed by the base64-decoded workspace shared key.

## Marketplace assets (#283)

Pre-built Splunk app + Datadog content pack ship under
the in-repo `marketplace-assets/` directory. Both consume the
preset-shaped wire bytes documented above; an operator who's already
on the `splunk-hec` or `datadog` preset gets dashboards + saved
searches with zero extra config.

## Operator surface

```
*bounce audit-webhook presets list
```

Prints a human-readable table of the four presets, the config keys
each requires, and the default values. Available on ibounce, kbounce,
and dbounce.

Example:

```
$ kbounce audit-webhook presets list
NAME         REQUIRES                                                  OPTIONAL
generic      --audit-webhook-url, --audit-webhook-token                --audit-webhook-batch-size
datadog      --audit-webhook-url, --audit-webhook-token                --audit-webhook-tags
splunk-hec   --audit-webhook-url, --audit-webhook-token                (none)
sentinel     --audit-webhook-url, --audit-webhook-token (base64 key)   --audit-webhook-sentinel-table (default IamJitBouncer)
```

## Agent surface

Each product's MCP server exposes a `list_audit_webhook_presets` tool
that returns the same information programmatically. An agent can ask
"what presets are available?" and get a structured JSON answer
without poking the operator-facing CLI.

Per [[cross-product-agent-parity]]: the tool returns the same JSON
shape across products.

## See also

- `schemas/INDEX.md` — schema registry (OCSF audit-event shape that
  every preset wraps)
- `marketplace-assets/` — Splunk app + Datadog content pack (#283)
- The per-product audit-export docs section (mentions
  `[[audit-webhook-presets]]` + links here)
