# iam-jit Bounce — Splunk app

Dashboards, saved searches, and parsers for OCSF v1.1.0 class 6003
events emitted by the iam-jit Bounce suite (ibounce / kbounce /
dbounce).

## What you get

| Asset                     | Path                                                       |
|---------------------------|------------------------------------------------------------|
| Sourcetype + field aliases| `default/props.conf`                                       |
| ARN extraction transforms | `default/transforms.conf`                                  |
| Event-type definitions    | `default/eventtypes.conf`                                  |
| 10 saved searches         | `default/savedsearches.conf`                               |
| Overview dashboard        | `default/data/ui/views/iam_jit_overview.xml`               |
| Sample HEC + filemon input| `samples/inputs.conf.example`                              |

All saved searches are visible but **not scheduled** by default. Flip
the ones you want running by toggling `enableSched = 1` per stanza
(or via Splunk Web > Searches, Reports, and Alerts).

## Install (manual)

1. From the parent directory of `iam_jit_bounce/`, run
   `tar -czf iam_jit_bounce.spl iam_jit_bounce/`. Splunk requires the
   package root to be the app directory itself (matches the `id`
   in `default/app.conf`).
2. In Splunk Web: Apps > Manage Apps > Install app from file > upload the `.spl`.
3. Restart Splunk when prompted.
4. Copy `samples/inputs.conf.example` to `$SPLUNK_HOME/etc/apps/iam_jit_bounce/local/inputs.conf`
   and edit for your environment (HEC token or log path). Reload inputs.
   (The `local/` directory is operator-owned and created on first edit.)

## Install (Splunkbase, once published)

1. Splunk Web > Apps > Find More Apps > search "iam-jit Bounce".
2. Click Install. Splunk handles the rest.
3. Configure inputs as above.

## Wiring ibounce to send to Splunk

Use the `splunk-hec` webhook preset shipped in ibounce #257:

```
ibounce audit-export configure \
    --webhook-url https://splunk.example.com:8088/services/collector/event \
    --webhook-preset splunk-hec \
    --webhook-auth-header "Authorization: Splunk <YOUR-HEC-TOKEN>"
```

The HEC token in Splunk must be bound to sourcetype
`iam_jit:bounce:ocsf` (the sourcetype this app defines in
`default/props.conf`). The app's parsers + dashboards key off that
exact sourcetype name.

## Sample event

Every event lands as OCSF v1.1.0 class 6003. The full schema doc
lives at `docs/QUERYING-AUDIT-LOGS.md` in the iam-jit repo; here's
the minimal shape this app expects:

```json
{
  "metadata": {
    "version": "1.1.0",
    "product": {"name": "ibounce", "vendor_name": "iam-jit", "version": "1.0.0"}
  },
  "time": 1716163200000,
  "class_uid": 6003,
  "activity_id": 2,
  "actor": {"user": {"name": "alice@example.com"}, "session": {"uid": "req-42"}},
  "api": {"operation": "s3:GetObject", "service": {"name": "s3"}},
  "status_id": 1,
  "unmapped": {
    "iam_jit": {
      "mode": "transparent",
      "verdict": "allow",
      "decision_id": 42,
      "enforced": false,
      "agent": {"name": "claude-code", "version": "1.5.0", "session_id": "01968d6a-..."}
    }
  }
}
```

## Privacy + telemetry

This app contains no scheduled scripts, no `bin/` Python, and no
phone-home. Every saved search runs in your Splunk; nothing leaves
your indexer. The app is static configuration only.

## License + support

- App is shipped under the same license as iam-jit itself (MIT).
- File issues against the upstream repo (`iam-jit` on GitHub).
- See `docs/MARKETPLACE-PUBLISHING.md` in the upstream repo for the
  publishing runbook + version cadence.
