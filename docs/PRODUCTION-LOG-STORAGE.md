# Production Log Storage Runbook

**Operator decision tree:** where do your audit logs go in production, by
deployment context. Covers all four Bounce products (ibounce, kbounce,
dbounce, gbounce) under one runbook — the flag names are harmonised per
`[[cross-product-agent-parity]]` so a single mental model carries across
products.

Per `[[security-team-positioning-safety-not-surveillance]]` this doc is
framed as **audit for safety + investigation**, not surveillance. The
audit log is the artifact a future security investigation needs to
reconstruct what an agent (or human) did; pick destinations that your
team can actually query when something goes sideways.

Per `[[self-host-zero-billing-dependency]]`: every destination below is
operated by you (the operator) — iam-jit-the-company does not run any
of them, does not see your audit data, and is not on the billing path.
We ship the **exporters that integrate with your existing
infrastructure**, not the destinations themselves.

Per `[[don't-tailor-to-lighthouse]]`: the recommendations below serve
all operator types. No section is shaped for any one customer; pick the
row that matches your context.

---

## 1. TL;DR — pick by deployment context

| Deployment context                          | Recommended primary exporter                       | Sample CLI snippet                                                                                                                                              |
|---------------------------------------------|----------------------------------------------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------|
| Single-host dev / solo founder laptop       | JSONL file (`--audit-log-path`)                    | `ibounce run --audit-log-path ~/.iam-jit/audit/ibounce.jsonl`                                                                                                   |
| Multi-host on-prem (Splunk / Datadog / Sentinel) | HTTPS webhook with preset (`--audit-webhook-preset`) | `kbounce run --audit-webhook-url https://splunk.internal:8088/services/collector/event --audit-webhook-token $HEC_TOKEN --audit-webhook-preset splunk-hec`     |
| AWS-heavy traffic (SDK / kubectl / SQL all in AWS) | AWS Security Lake (parquet on S3 + Athena)         | `ibounce run --security-lake-bucket iam-jit-bounce-lake --security-lake-region us-east-1`                                                                       |
| AWS deployment, simple "dump to S3"         | Webhook → operator-owned Lambda → S3 PutObject     | `dbounce run --audit-webhook-url https://api.execute-api.us-east-1.amazonaws.com/prod/audit --audit-webhook-token $LAMBDA_BEARER`                               |
| Cloud-neutral S3-compat (GCS/R2/B2/MinIO/Azure-via-S3-compat) | Native NDJSON sink (`--audit-object-storage-*`, #317) | `kbounce run --audit-object-storage-endpoint https://<id>.r2.cloudflarestorage.com --audit-object-storage-bucket bounce-audit --audit-object-storage-prefix prod --audit-object-storage-region auto` |
| GCP deployment                              | NDJSON sink against GCS S3-interop OR webhook → Cloud Run shim | `gbounce run --audit-object-storage-endpoint https://storage.googleapis.com --audit-object-storage-bucket gs-bounce-audit --audit-object-storage-region us-central1` |
| Azure deployment                            | Webhook with `sentinel` preset OR operator-owned Function | `ibounce run --audit-webhook-url https://workspace.ods.opinsights.azure.com/api/logs?api-version=2016-04-01 --audit-webhook-token $SHARED_KEY --audit-webhook-preset sentinel` |
| CI/CD ephemeral runner                      | Webhook + SIGTERM-triggered graceful drain         | `kbounce run --audit-webhook-url $SIEM_URL --audit-webhook-token $TOKEN --audit-webhook-batch-size 1`                                                            |
| Enterprise fan-out (multi-destination)      | `--alert-routes` YAML (per `[[per-org-notification-routing]]`, #280) | `ibounce run --alert-routes ~/.iam-jit/ibounce-routes.yaml`                                                                                                     |

All exporters can be **combined**. The JSONL hot path is always
available (default `--audit-log-path` if you set it) and runs
independently of any push exporter; a SIEM credential outage doesn't
stop the local file from accumulating events.

---

## 2. Per-context detail

### 2.1 Single-host dev / solo founder laptop

**Recommended:** JSONL file via `--audit-log-path`.

**Why:** Local-only. No external dependencies. Audit log lives next to
the bouncer. Trivially `grep`-able. Survives without network. Matches
`[[local-only-safety-mode]]` — zero phone-home.

**Setup:**

```bash
mkdir -p ~/.iam-jit/audit
ibounce run --audit-log-path ~/.iam-jit/audit/ibounce.jsonl
kbounce run --audit-log-path ~/.kbouncer/audit/kbounce.jsonl
dbounce run --audit-log-path ~/.dbounce/audit/dbounce.jsonl
gbounce run --audit-log-path ~/.gbounce/audit/gbounce.jsonl
```

**Reading events:**

```bash
ibounce audit tail --follow                       # live tail
kbounce audit tail --filter severity_id=4         # high-severity only
dbounce audit tail --export jsonl --out hits.json # bulk dump
```

**Rotation + retention:** see #311 (in flight). Pre-#311, operator-side
`logrotate` on the JSONL file is the recommended workaround. The
SQLite audit DB is separate and unrotated in v1.0 — keep an eye on
disk usage.

### 2.2 Multi-host on-prem (Splunk / Datadog / Sentinel)

**Recommended:** HTTPS webhook with the matching preset.

**Why:** Your security team already has a SIEM. Don't run a second.
The four `--audit-webhook-preset` choices (`generic`, `splunk-hec`,
`datadog`, `sentinel`) shape the wire bytes so the SIEM auto-categorises
the events with zero custom ingest mapping. See
[WEBHOOK-PRESETS.md](WEBHOOK-PRESETS.md) for the full per-vendor
breakdown (token acquisition, header shapes, body layouts).

**Setup:** Splunk HEC example.

```bash
# 1. Obtain HEC token from Splunk Web (see WEBHOOK-PRESETS.md §Splunk HEC token).
export HEC_TOKEN=...
# 2. Wire the bouncer.
ibounce run \
    --audit-webhook-url https://splunk.internal:8088/services/collector/event \
    --audit-webhook-token $HEC_TOKEN \
    --audit-webhook-preset splunk-hec \
    --audit-webhook-batch-size 50
```

Same flag shape across kbounce / dbounce. gbounce ships webhook export
in G-Slice 6 (post-launch); pre-launch, gbounce uses JSONL +
operator-shipped Vector / Fluent Bit as the interim path.

**Multi-host:** every host runs its own bouncer; every bouncer posts
into the same SIEM. Cross-host correlation pivots on
`unmapped.iam_jit.agent.session_id` per `[[agent-identity-in-audit]]`.

### 2.3 AWS deployment + heavy AWS-shaped traffic

**Recommended:** AWS Security Lake adapter (`--security-lake-*`).

**Why:** Events land as OCSF v1.1.0 class 6003 parquet files in an S3
bucket Security Lake auto-ingests. Athena queries the result directly;
no extra ingest pipeline. Per `[[creates-never-mutates]]` the adapter
is `PutObject`-only — never overwrites, never deletes. Full setup
runbook lives at [SECURITY-LAKE-INTEGRATION.md](SECURITY-LAKE-INTEGRATION.md).

**Setup outline:**

1. Create an S3 bucket with `PutObject`-only policy (sample bucket
   policy in SECURITY-LAKE-INTEGRATION.md §2).
2. Grant the bouncer's IAM identity `s3:PutObject` on the bucket.
3. Wire flags:

   ```bash
   ibounce run \
       --security-lake-bucket iam-jit-bounce-security-lake \
       --security-lake-region us-east-1 \
       --security-lake-role-arn arn:aws:iam::123456789012:role/iam-jit-writer \
       --security-lake-rotation-seconds 60
   ```

4. Register the bucket as a Security Lake custom source.
5. Query from Athena:

   ```sql
   SELECT actor.user.name, activity_name, status, time
   FROM security_lake.iam_jit_bounce
   WHERE severity_id >= 4
     AND time > to_unixtime(current_date - interval '7' day) * 1000
   ORDER BY time DESC;
   ```

Same flag shape across kbounce / dbounce. gbounce is **skipped** for
Security Lake in v1.0 (its webhook export ships in G-Slice 6); use the
JSONL + Vector path for gbounce events into the same bucket.

### 2.4 AWS deployment + simple "dump to S3"

**Recommended:** Webhook → operator-owned Lambda → S3 PutObject. Use
when you don't need full Security Lake parquet partitioning but want
events in S3 for cold storage.

**Why:** Cheaper than Security Lake for low-volume deployments
(Security Lake charges per-GB ingest). Lambda runs in your account,
under your IAM. Lambda code is yours, not ours — we ship the webhook,
you ship the receiver.

**Sample Lambda receiver (Python, ~30 lines):**

```python
import base64
import gzip
import hmac
import json
import os
import time
import uuid

import boto3

s3 = boto3.client("s3")
BUCKET = os.environ["AUDIT_BUCKET"]
EXPECTED_TOKEN = os.environ["AUDIT_BEARER_TOKEN"]


def lambda_handler(event, _ctx):
    # 1. Auth.
    auth = event["headers"].get("authorization", "")
    if not auth.startswith("Bearer "):
        return {"statusCode": 401, "body": "missing bearer"}
    if not hmac.compare_digest(auth.removeprefix("Bearer "), EXPECTED_TOKEN):
        return {"statusCode": 401, "body": "bad bearer"}

    # 2. Body — NDJSON (one OCSF event per line).
    body = event["body"]
    if event.get("isBase64Encoded"):
        body = base64.b64decode(body).decode("utf-8")

    # 3. Validate at least one valid OCSF line.
    lines = [ln for ln in body.splitlines() if ln.strip()]
    if not lines:
        return {"statusCode": 400, "body": "empty body"}
    for ln in lines:
        json.loads(ln)  # raises on malformed — Lambda returns 500

    # 4. Compress + PutObject to a time-partitioned key.
    now = time.gmtime()
    key = (
        f"year={now.tm_year}/month={now.tm_mon:02d}/day={now.tm_mday:02d}/"
        f"hour={now.tm_hour:02d}/{uuid.uuid4().hex}.jsonl.gz"
    )
    s3.put_object(
        Bucket=BUCKET,
        Key=key,
        Body=gzip.compress(body.encode("utf-8")),
        ContentType="application/x-ndjson",
        ContentEncoding="gzip",
    )
    return {"statusCode": 200, "body": "ok"}
```

Front the Lambda with API Gateway (HTTP API) and feed `kbounce` /
`dbounce` / `ibounce`:

```bash
ibounce run \
    --audit-webhook-url https://api.execute-api.us-east-1.amazonaws.com/prod/audit \
    --audit-webhook-token $LAMBDA_BEARER \
    --audit-webhook-preset generic \
    --audit-webhook-batch-size 50
```

**Even simpler (recommended for new deployments, #317):** skip the
Lambda entirely; use the cloud-neutral S3-compat NDJSON sink to
write directly to your S3 bucket. Same Hive-partitioned NDJSON.gz
shape, no API Gateway / Lambda IAM to maintain.

```bash
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
ibounce run \
    --audit-object-storage-endpoint https://s3.us-east-1.amazonaws.com \
    --audit-object-storage-bucket bounce-audit-cold \
    --audit-object-storage-prefix prod \
    --audit-object-storage-region us-east-1
```

When to keep the Lambda shape: HMAC-based path is fine, but if your
security policy requires API Gateway-fronted ingestion (e.g. for
WAF integration, custom auth, or downstream Lambda-routed
fan-out), the Lambda recipe stays valid.

### 2.4b Cloud-neutral S3-compatible NDJSON sink (#317)

**Recommended:** every cloud-neutral deployment (GCS / Azure
Blob-S3-compat / MinIO / R2 / B2 / DigitalOcean Spaces). Also the
simplest path for AWS-only deployments not already using Security
Lake.

**Why:** Direct write from the bouncer to any S3-compatible bucket.
No intermediary Lambda / Cloud Function / Vector to maintain. Per
[[don't-tailor-to-lighthouse]] the same flag shape works across
every vendor. Per [[self-host-zero-billing-dependency]] the bucket
is operator-owned; iam-jit-the-company never receives the data.

**Output layout:** NDJSON (one OCSF event per line), gzip-compressed,
Hive-partitioned:

```
s3://<bucket>/<prefix>/year=YYYY/month=MM/day=DD/hour=HH/
    {product}-{instance_id}-{timestamp}.jsonl.gz
```

Athena / BigQuery / Spark / Trino auto-discover the partitions.
SIEM collectors `LIST + GET` against the prefix.

**Rotation:** files rotate every
`--audit-object-storage-rotation-minutes` (default 5) OR
`--audit-object-storage-max-size-mb` (default 16), whichever caps
first. Lower values mean smaller files + faster collector
visibility; higher values mean fewer / larger files (better
Athena / BigQuery scan efficiency).

**Authentication:** AWS-style env vars or explicit credentials
file:

```bash
# Option 1: env vars (works for AWS S3 directly OR via the
# vendor's S3-interop key pair — GCS HMAC keys, R2 API tokens,
# etc.)
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...

# Option 2: explicit file (YAML or INI; file overrides env when both set)
cat > ~/.iam-jit/object-storage-creds.yaml <<'EOF'
access_key_id: AKIA...
secret_access_key: ...
session_token: ...    # optional
EOF
chmod 0600 ~/.iam-jit/object-storage-creds.yaml

kbounce run \
    --audit-object-storage-endpoint https://<id>.r2.cloudflarestorage.com \
    --audit-object-storage-bucket bounce-audit \
    --audit-object-storage-prefix prod \
    --audit-object-storage-region auto \
    --audit-object-storage-credentials-file ~/.iam-jit/object-storage-creds.yaml
```

**Multi-cloud endpoint reference:**

| Vendor                  | `--audit-object-storage-endpoint`                       | `--audit-object-storage-region` |
|-------------------------|---------------------------------------------------------|---------------------------------|
| AWS S3                  | `https://s3.us-east-1.amazonaws.com` (region-specific)  | real region                     |
| Cloudflare R2           | `https://<account-id>.r2.cloudflarestorage.com`         | `auto`                          |
| Backblaze B2            | `https://s3.us-west-002.backblazeb2.com`                | vendor region                   |
| DigitalOcean Spaces     | `https://nyc3.digitaloceanspaces.com` (datacenter)      | datacenter id                   |
| MinIO                   | `https://minio.internal:9000` (your install)            | any (must match server config)  |
| Google Cloud Storage    | `https://storage.googleapis.com` (S3 interop / HMAC)    | GCS region                      |
| Azure Blob (S3 compat)  | `https://<account>.blob.core.windows.net` (via S3-compat layer) | Azure region            |

**Refuse-to-start:** `Start()` issues a HeadBucket probe against the
endpoint + bucket so credential / endpoint / bucket-name
misconfigurations surface at startup, not deep in the proxy hot
path. Same posture as the Security Lake adapter.

**Composability:** works alongside JSONL + webhook + Security Lake.
Per [[creates-never-mutates]] the sinks are additive; an operator
can run all four simultaneously.

**Per-instance file naming:** the `instance_id` segment is auto-
generated from `hostname-pid` so multiple bouncer instances writing
the same bucket get collision-free paths. Override with
`--audit-object-storage-instance-id ID` for ephemeral-hostname
deployments (containers / k8s pods) where you want the path stable
across restarts.

**v1.1 deferred:** native GCS auth (Workload Identity) + native
Azure Blob auth (Managed Identity). S3 interop covers ~95% of
operators today; the friction-reducing native paths land post-v1.0.

### 2.5 GCP deployment

**Recommended (preferred, #317):** Cloud-neutral S3-compat NDJSON
sink targeting GCS via the S3-interop endpoint.

**Why:** Direct write to GCS — no Cloud Run / Cloud Functions shim
to maintain. Per [[self-host-zero-billing-dependency]] the bucket
is operator-owned; per [[don't-tailor-to-lighthouse]] the sink is
generic S3-compat so the same flag shape works for GCS, R2, B2,
MinIO, etc.

**Setup:** Enable S3 interop on your GCS project (Cloud Storage
Settings → Interoperability → Create HMAC key). Export the HMAC
access-key + secret-key as `AWS_ACCESS_KEY_ID` /
`AWS_SECRET_ACCESS_KEY`. Then:

```bash
export AWS_ACCESS_KEY_ID=GOOGTS...    # GCS HMAC access key
export AWS_SECRET_ACCESS_KEY=...      # GCS HMAC secret
gbounce run \
    --audit-object-storage-endpoint https://storage.googleapis.com \
    --audit-object-storage-bucket gs-bounce-audit \
    --audit-object-storage-prefix prod \
    --audit-object-storage-region us-central1
```

NDJSON.gz files land at `gs://gs-bounce-audit/prod/year=YYYY/month=MM/day=DD/hour=HH/gbounce-{instance_id}-{timestamp}.jsonl.gz`. BigQuery + Dataproc + Athena-via-Federated-Query auto-discover the Hive partitions.

**Pub/Sub fan-out (alternative):** for multi-subscriber pipelines,
point the webhook at a Cloud Run shim that publishes to a Pub/Sub
topic. Subscribers (BigQuery, Cloud Logging, third-party SIEMs)
attach to the topic.

```bash
gbounce run \
    --audit-webhook-url https://audit-collector-xxx-uc.a.run.app/audit \
    --audit-webhook-token $BEARER
```

**v1.1 deferred:** native GCS auth (Workload Identity / Service
Account) per [[don't-tailor-to-lighthouse]]; S3 interop covers
~95% of operators today.

### 2.6 Azure deployment

**Recommended (search + dashboards):** `sentinel` preset (for Log
Analytics Workspace).

**Recommended (cold-store / Blob archive):** Cloud-neutral S3-compat
NDJSON sink (#317) targeting Blob via an S3-compat layer (e.g.
[MinIO Gateway for Azure Blob](https://min.io/docs/minio/linux/integrations/aws-cli-with-minio.html)
or Azure's S3 Protocol preview). The same flag shape that works for
AWS S3 + GCS interop + R2 + B2 works against the operator-fronted
Blob endpoint.

**Why:** Sentinel's HTTP Data Collector is a first-class supported
preset (per [WEBHOOK-PRESETS.md](WEBHOOK-PRESETS.md)); Blob Storage
cold-archive uses the same generic S3-compat sink as every other
cloud-neutral target — no Azure Function shim to maintain.

**Sentinel path:**

```bash
# Get workspace-id + primary key from Azure portal → Log Analytics
# Workspace → Agents.
export WORKSPACE_ID=...
export SHARED_KEY=...
ibounce run \
    --audit-webhook-url "https://${WORKSPACE_ID}.ods.opinsights.azure.com/api/logs?api-version=2016-04-01" \
    --audit-webhook-token "$SHARED_KEY" \
    --audit-webhook-preset sentinel \
    --audit-webhook-sentinel-table IamJitBouncer
```

Sentinel's `IamJitBouncer_CL` custom-log table appears within ~5
minutes of the first event.

**Blob path:** an Azure Function with an HTTP trigger receives the
webhook, validates the bearer, and writes to Blob with a date-bucketed
prefix. Same 30-line shape as the AWS Lambda recipe; the Azure SDK
substitutes for boto3.

### 2.7 CI/CD ephemeral runners

**Recommended:** Webhook with `--audit-webhook-batch-size 1` + the
bouncer's graceful-shutdown drain on `SIGTERM`. NO explicit `flush`
subcommand is needed (or available) — the bouncer drains the audit
pipeline automatically when it receives SIGTERM.

**Why:** Ephemeral runners die. Any events buffered in the bouncer at
exit are lost unless flushed. Batch-size-1 reduces (but does not
eliminate) the window. The bouncer's signal handler (Python: aiohttp
`runner.cleanup()` → audit-channel `.stop()` chain; Go: cobra
`signal.NotifyContext` → `s.Shutdown(ctx)` → audit-channel close)
drains every in-flight webhook send, in-memory NDJSON queue, and
SQLite write before returning. The `wait $PID` line below blocks
until the drain finishes; nothing else is needed.

Per `[[creates-never-mutates]]`: the drain is naturally graceful — no
audit event is ever destroyed during shutdown; the bouncer waits for
each channel's worker to finish in-flight work, then closes the file
descriptor / HTTP session cleanly.

**Setup:**

```bash
# In your CI step:
ibounce run \
    --audit-webhook-url $SIEM_URL \
    --audit-webhook-token $TOKEN \
    --audit-webhook-batch-size 1 \
    --audit-log-path /tmp/ibounce-fallback.jsonl &
IBOUNCE_PID=$!

# ... do agent work that routes through ibounce ...

# Trigger the graceful drain. SIGTERM (default kill signal) walks the
# audit-channel teardown chain: pending webhook sends complete or
# error-out via the existing retry/backoff path; in-memory NDJSON
# queue drains to disk; SQLite checkpoint flushes; file descriptors
# close. `wait` blocks until the drain finishes.
kill -TERM $IBOUNCE_PID
wait $IBOUNCE_PID
```

Same shape works for kbounce / dbounce / gbounce. In GitHub Actions /
GitLab CI, wrap the `kill -TERM` + `wait` in an `always()` /
`after_script` block so it runs even on test failure. Belt-and-braces:
set `--audit-log-path` in addition to the webhook so a webhook outage
during shutdown still leaves a local file the post-job step can
upload as an artifact.

**Why not `flush --wait`?** No bouncer ships an explicit `audit-export
flush` subcommand: the drain ALREADY happens on SIGTERM (the
graceful-shutdown handler is the implementation). An explicit flush
RPC would duplicate the signal-handler logic with a new failure mode
(an HTTP call to the bouncer's mgmt port that might itself fail
mid-CI). Per `[[deliberate-feature-completion]]` we keep the existing
signal-handler drain as the single source of truth.

### 2.8 Enterprise fan-out (multi-destination per severity)

**Recommended:** `--alert-routes` YAML (per `[[per-org-notification-routing]]`,
#280).

**Why:** SOC team wants Medium+ events in Splunk. Dev team wants their
own events in Datadog. On-call wants Critical-only paged to PagerDuty +
Slack. Everything archives to S3. A single bouncer can fan out to all
four destinations via one YAML file. Full reference:
[PER-ORG-NOTIFICATION-ROUTING.md](PER-ORG-NOTIFICATION-ROUTING.md).

**Setup:**

```bash
ibounce config preview-routes \
    --routes ~/.iam-jit/ibounce-routes.yaml \
    --event sample-event.json
ibounce run --alert-routes ~/.iam-jit/ibounce-routes.yaml
```

The dry-run (`preview-routes`) is **mandatory** pre-deploy. Routing
YAML is dense + error-prone; the dry-run shows which route each
sample event would hit. Enterprise-tier, license-gated; see the doc
above for the YAML schema + per-destination authentication.

---

## 3. What we don't ship (honest gaps)

Per `[[self-host-zero-billing-dependency]]` we do not operate destinations
for operators. We ship **exporters that integrate with your existing
infrastructure**; the following destinations have **explicit gaps** that
operators close with a thin shim:

| Gap                          | Operator workaround                                                                                          |
|------------------------------|--------------------------------------------------------------------------------------------------------------|
| No native GCS sink           | Webhook → operator-owned Cloud Run / Cloud Function → GCS PutObject (recipe in §2.5).                        |
| No native Azure Blob sink    | Webhook → operator-owned Azure Function → Blob PutBlob (same shape as GCS).                                  |
| No native Kafka sink         | Webhook → Kafka REST Proxy (Confluent) OR webhook → thin Go/Python shim using a Kafka client library.        |
| No native syslog / RFC 5424  | JSONL file (`--audit-log-path`) + Fluent Bit or Vector with a syslog output filter on the operator side.     |
| No native Elasticsearch sink | Webhook → Logstash with an HTTP input filter, OR JSONL + Filebeat.                                           |
| No native ClickHouse sink    | Webhook → Vector (operator-side) with a ClickHouse sink configured.                                          |
| No multi-tenant managed SaaS | Per `[[no-hosted-saas]]`: there is no iam-jit-hosted audit destination. Pick something you operate.          |

**Why we won't close these gaps natively:** every additional native
sink is an SDK we vendor, a credential model we own, and a regression
surface we maintain. Vector / Fluent Bit / Logstash already do this
work and operators already run them. Our job is to emit a clean OCSF
stream that drops into your pipeline.

---

## 4. Sample webhook receivers

The four most-common platforms below — same OCSF v1.1.0 class 6003
event on the wire regardless. The preset only changes the wrapper.

### 4.1 Splunk HEC

Built into Splunk. No code on your side. Settings → Data Inputs →
HTTP Event Collector → enable + generate token. Use `--audit-webhook-preset
splunk-hec`. See [WEBHOOK-PRESETS.md §Splunk HEC token](WEBHOOK-PRESETS.md#splunk-hec-token).

### 4.2 Datadog Logs HTTP intake

Built into Datadog. No code on your side. Organization Settings → API
Keys → new key. Use `--audit-webhook-preset datadog`. URL depends on
your DD site (US1 / EU / US3 / US5 / AP1) — see
[WEBHOOK-PRESETS.md §Datadog API key](WEBHOOK-PRESETS.md#datadog-api-key).

### 4.3 Microsoft Sentinel HTTP Data Collector

Built into Sentinel. No code on your side. Log Analytics Workspace →
Agents → copy workspace ID + primary key. Use `--audit-webhook-preset
sentinel`. See [WEBHOOK-PRESETS.md §Microsoft Sentinel shared key](WEBHOOK-PRESETS.md#microsoft-sentinel-shared-key).

### 4.4 Vector / Cribl as intermediaries

If your destination isn't one of the named presets (Splunk Cloud,
QRadar, Sumo Logic, ClickHouse, OpenSearch, ...) put **Vector** or
**Cribl Stream** in the middle. Both accept HTTP input and write to
~everywhere.

**Minimum Vector config (`vector.toml`):**

```toml
[sources.iam_jit_in]
type = "http_server"
address = "0.0.0.0:8686"
encoding = "ndjson"
auth.username = "iam-jit"
auth.password = "${IAM_JIT_BEARER}"

[transforms.passthrough]
type = "remap"
inputs = ["iam_jit_in"]
source = '''
# OCSF events pass through untouched. Optionally enrich here.
'''

[sinks.your_destination]
type = "..."  # elasticsearch / clickhouse / loki / kafka / s3 / gcs / ...
inputs = ["passthrough"]
# ... per-destination config ...
```

Point the bouncer at Vector:

```bash
kbounce run \
    --audit-webhook-url http://vector.internal:8686/ \
    --audit-webhook-token $IAM_JIT_BEARER \
    --audit-webhook-preset generic
```

**Cribl Stream** has equivalent setup; use a "HTTP" source and any of
Cribl's destinations.

---

## 5. Audit log retention policy considerations

Disk fills silently if you don't think about retention. The full
retention surface (automatic JSONL rotation, SQLite archive-rotate,
`/healthz` disk-degraded signal, `*bounce doctor logs` integrity
checks, crash-recovery for partial-write JSONL tails, the
`*bounce logs {tail,purge,archive,verify}` subcommand) ships under
task #311. See [docs/LOG-RETENTION.md](LOG-RETENTION.md) once #311
lands.

**Pre-#311 interim guidance:**

- Cron a daily `logrotate` on the JSONL files. Gzip on rotate; keep
  30-90 days depending on your compliance posture.
- Monitor disk usage at the OS level. Set an alert at 80%.
- For SQLite audit DBs: vacuum monthly. The DB grows ~1KB per event;
  a 100-events/sec deployment hits ~250MB / month.
- For Security Lake parquet files: configure S3 lifecycle rules to
  transition objects to S3 Glacier Deep Archive after 90 days,
  delete after your compliance retention window.
- For SIEM-destination events: retention is whatever your SIEM
  enforces; configure indexer / log-storage retention there.

---

## 6. Validating the pipeline works

Sanity check after wiring any of the above. Three layers:

### 6.1 Bouncer-side: events being generated

```bash
# Live tail confirms events are being captured locally.
ibounce audit tail --follow --limit 10
kbounce audit tail --follow --limit 10
dbounce audit tail --follow --limit 10
gbounce audit tail --follow --limit 10
```

If this returns nothing, the bouncer isn't intercepting traffic — fix
that before debugging the export channel.

### 6.2 Export-channel health

Each bouncer exposes `/healthz` with an `audit_export` block reporting
the last successful flush + any consecutive failure count:

```bash
curl -s http://localhost:8770/healthz | jq .audit_export
```

Expected output (healthy):

```json
{
  "configured": true,
  "channel": "webhook",
  "preset": "splunk-hec",
  "last_successful_flush_unix": 1716367200,
  "consecutive_failures": 0,
  "events_pending": 0,
  "events_exported_total": 12847
}
```

If `consecutive_failures > 0` the bouncer has a connectivity / auth
problem to the destination. Per `[[audit-export-failure-visibility]]`
the 30-second heartbeat-gap rule fires in the SIEM when the channel
silences — you'll get an alert from the SIEM side too.

### 6.3 SIEM-side: events arriving

**Splunk SPL:**

```spl
index=security sourcetype="iam_jit:bouncer:*"
| stats count by metadata.product.name, activity_name, status
| sort -count
```

**Datadog query:**

```
source:iam-jit @metadata.product.name:*
| group by [@metadata.product.name, @activity_name, @status]
```

**Sentinel KQL:**

```kql
IamJitBouncer_CL
| where TimeGenerated > ago(1h)
| summarize count() by metadata_product_name_s, activity_name_s, status_s
| order by count_ desc
```

**Security Lake Athena:**

```sql
SELECT metadata.product.name AS product, activity_name, status, COUNT(*) AS n
FROM security_lake.iam_jit_bounce
WHERE time > to_unixtime(current_timestamp - interval '1' hour) * 1000
GROUP BY metadata.product.name, activity_name, status
ORDER BY n DESC;
```

If the bouncer says "exported_total=12847" but the SIEM says "count=0":
auth / URL / preset misconfigured. Check `/healthz.audit_export.last_error`.

---

## 7. What this doc does NOT do

- **No "the recommended SIEM is X."** Pick the SIEM your security team
  already operates. We don't have a horse in that race.
- **No GCS / Azure-Blob-native shipping promise.** Those are explicit
  gaps with workarounds (§3).
- **No "compliant" claim.** Compliance (SOC 2 / HIPAA / PCI / FedRAMP)
  is a property of the **destination** your operator configures and
  the surrounding controls (encryption at rest, access logging,
  retention, etc.), not of our exporter. We ship a clean OCSF stream;
  what your team does with it determines what compliance frameworks
  it satisfies.

---

## Per-product surface

Same flag names + same semantics across all four bouncers per
`[[cross-product-agent-parity]]`:

| Flag                           | ibounce | kbounce | dbounce | gbounce |
|--------------------------------|---------|---------|---------|---------|
| `--audit-log-path`             | ✓       | ✓       | ✓       | ✓       |
| `--audit-log-fsync`            | ✓       | ✓       | ✓       | ✓       |
| `--audit-log-max-size-mb` (#311) | ✓       | ✓       | ✓       | ✓ (flag accepted; writer-level rotation deferred per LOG-RETENTION.md parity matrix) |
| `--audit-log-max-age-days` (#311) | ✓       | ✓       | ✓       | ✓ (same caveat) |
| `--audit-db-retention-days` (#311) | ✓       | ✓       | ✓       | ✓ (purge-only path; same caveat) |
| `--audit-webhook-url`          | ✓       | ✓       | ✓       | G-Slice 6 (v1.1; use JSONL + Fluent Bit/Vector for v1.0) |
| `--audit-webhook-token`        | ✓       | ✓       | ✓       | G-Slice 6 |
| `--audit-webhook-preset`       | ✓       | ✓       | ✓       | G-Slice 6 |
| `--audit-webhook-batch-size`   | ✓       | ✓       | ✓       | G-Slice 6 |
| `--audit-webhook-tags`         | ✓ (datadog) | ✓ (datadog) | ✓ (datadog) | G-Slice 6 |
| `--audit-webhook-sentinel-table` | ✓ (sentinel) | ✓ (sentinel) | ✓ (sentinel) | G-Slice 6 |
| `--security-lake-bucket`       | ✓       | ✓       | ✓       | G-Slice 6 |
| `--security-lake-region`       | ✓       | ✓       | ✓       | G-Slice 6 |
| `--security-lake-role-arn`     | ✓       | ✓       | ✓       | G-Slice 6 |
| `--security-lake-rotation-seconds` | ✓   | ✓       | ✓       | G-Slice 6 |
| `--alert-routes`               | ✓ (Enterprise) | ✓ (Enterprise) | ✓ (Enterprise) | G-Slice 6 |

Exporter implementations live in:

- ibounce: `src/iam_jit/bouncer/audit_export/` (Python; webhook + Security Lake + routing)
- kbounce: `internal/audit/` (Go; webhook + Security Lake + routing)
- dbounce: `internal/audit/` (Go; webhook + Security Lake + routing)
- gbounce: `internal/audit/` (Go; JSONL + SQLite in G-Slice 1; webhook + Security Lake in G-Slice 6)

---

## See also

- [WEBHOOK-PRESETS.md](WEBHOOK-PRESETS.md) — full per-vendor preset
  reference (Splunk HEC, Datadog, Sentinel, generic)
- [SECURITY-LAKE-INTEGRATION.md](SECURITY-LAKE-INTEGRATION.md) — full
  Security Lake adapter runbook (#258)
- [PER-ORG-NOTIFICATION-ROUTING.md](PER-ORG-NOTIFICATION-ROUTING.md) —
  per-org / per-severity fan-out routing engine (#280)
- [QUERYING-AUDIT-LOGS.md](QUERYING-AUDIT-LOGS.md) — local `*bounce
  audit tail` filter + export catalog
- `docs/LOG-RETENTION.md` — rotation + retention + disk monitoring
  (in flight, #311)
- [KNOWN-CAVEATS.md](KNOWN-CAVEATS.md) — known gaps + workarounds,
  including §A10 (local audit-log retention) and §A14 (this doc)
