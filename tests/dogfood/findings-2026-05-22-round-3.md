# Dogfood UAT Round 3 — 2026-05-22

Repo HEAD at sweep time: `9a8606c` (after #319 + #320 + #317 + #298 fix cycle on top of round-2 / round-1 closures).

## Severity counts

| Severity | Count |
|----------|-------|
| CRIT     | 2     |
| HIGH     | 0     |
| MED      | 0     |
| LOW      | 0     |
| INFO     | 1     |

## Per-section pass/fail

| Section | Result | Notes |
|---|---|---|
| #319 §A17.1 logs subcommands | PASS | All 4 products expose `logs archive`/`purge`/`verify` |
| #319 §A17.2 `--audit-log-max-size-mb` | **FAIL** | Flag exists on all 4; ibounce crashes — see R3-01 |
| #319 §A17.3 doctor caveats | PASS | All 4 return §B entries with link-back URLs |
| #319 §A17.4 startup caveat banners | PASS | gbounce 2x, kbounce 1x, dbounce 2x, ibounce N/A (crash) |
| #319 §A17.5 §2.7 doc rewrite | PASS | `PRODUCTION-LOG-STORAGE.md` §2.7 uses graceful SIGTERM drain; `flush --wait` only appears in the "why-not" rationale |
| #319 §A17.6 archive custom-log | PASS | Loud error `no audit-shaped files matched...` on bad path; correct archive on valid path |
| #319 §A17.7 rejection breadcrumb | PASS | Stamped on gbounce + kbounce (enum: `invalid_name_charset`, `invalid_name_length`, `invalid_session_id_format`) |
| #320 §A18.1 dbounce wire shape | PASS | `/audit/events` threads `agent.{name,session_id,detected_from=pg_application_name}` |
| #320 §A18.2 kbouncer wire shape | PASS | `detected_from=http_header` when X-Agent-* headers present; not heuristic |
| #320 §A18.3 short-form filter alias | PARTIAL | Works on dbounce + kbounce; gbounce always 0 hits (consequence of R3-02) |
| #320 §A18.4 breadcrumb enum | PASS | At `unmapped.iam_jit.ext.agent_header_rejection`; field/reason/value_redacted_length |
| #317 §A15.1-4 S3-compat sink | PASS | moto S3 on :19090, gbounce wrote Hive-partitioned NDJSON.gz with OCSF v1.1.0 class 6003 payload + threaded agent block |
| #298 /suite link page | PASS | gbounce serves HTML; 4 cards (ibounce/kbouncer/dbounce/gbounce); CLI hint footer present; no "single pane of glass" copy |

---

## R3-01 (CRIT, [REGRESSION] of #319 / §A17): `ibounce run` crashes on every invocation

**What I did**
```bash
/Users/reagan/repos/iam-roles/.venv/bin/iam-jit-bouncer run \
    --port 19087 --audit-log-path /tmp/uat-r3/ibounce/audit.jsonl
```
Tried with and without `--audit-log-max-size-mb` — same crash either way.

**What I expected (per the #319 commit message)**
> "New fields on ProxyConfig preserve None-means-default semantics; 0 = explicitly disabled."

ibounce starts cleanly, listens on the port, emits caveat lines.

**What happened**
```
File "/Users/reagan/repos/iam-roles/src/iam_jit/bouncer_cli.py", line 4147, in run_cmd
    config = ProxyConfig(
TypeError: ProxyConfig.__init__() got an unexpected keyword argument 'audit_log_max_size_mb'
```

`src/iam_jit/bouncer_cli.py` accepts the click option (line 3400), takes it as a function arg (line 3796), and passes it into `ProxyConfig(...)` (line 4165). But `src/iam_jit/bouncer/proxy.py:952` (`class ProxyConfig`) NEVER declares any of `audit_log_max_size_mb`, `audit_log_max_age_days`, `audit_db_retention_days`. Grep confirms zero hits across `src/iam_jit/bouncer/`. The dataclass rejects the unknown kwarg → ibounce run is broken out of the box on this commit.

**Severity**: CRIT [REGRESSION]. ibounce run worked in round 2; the #319 fix itself broke it. The CLI half landed; the ProxyConfig half did not.

**Suggested fix**: Add the three fields to `ProxyConfig` in `src/iam_jit/bouncer/proxy.py` with `None`/`0` semantics matching the Go bouncers' rotation defaults, then wire them through to `AuditLogWriter`.

---

## R3-02 (CRIT, [REGRESSION] of #320 / §A18 on gbounce): `/audit/events` strips agent block

**What I did**
```bash
SESS=d156eb5f-fec1-46a2-8f30-062e175054cf
curl -s -x http://127.0.0.1:19081 \
     -H "X-Agent-Name: r3-cross" \
     -H "X-Agent-Session-Id: $SESS" \
     -o /dev/null http://127.0.0.1:19084/healthz

# JSONL audit log — correct:
tail -1 /tmp/uat-r3/test-gbounce/audit.jsonl
# ..."agent":{"name":"r3-cross","session_id":"d156eb5f-...","detected_from":"http_header"}

# /audit/events HTTP endpoint — BROKEN:
curl -s "http://127.0.0.1:19084/audit/events?limit=20"
# every event: {"agent":{"name":"anonymous","detected_from":"unknown"}}
```

**What I expected**
Per #320 / §A18 + `[[cross-product-agent-parity]]`, `/audit/events` on every bouncer threads the agent block — same shape as the JSONL writer. The round-2 dbounce CRIT was the exact same defect; #320 was supposed to close it cross-product.

**What happened**
gbounce's `/audit/events` reconstructs events from SQLite via `rowsToAuditEvents` in `/Users/reagan/repos/gbounce/internal/proxy/audit_events.go:270`. The `store.DecisionRow` does carry `AgentSessionID` + `AgentName` (`internal/store/store.go:216-217`) — they get persisted on insert and selected by `RecentDecisions` — but the reconstruction never copies them into `RequestInput`:

```go
in := audit.RequestInput{
    At: r.At, DecisionID: r.ID, Mode: r.Mode, Method: r.Method,
    Path: r.Path, UpstreamHost: r.UpstreamHost, ...
    Verdict: r.Verdict,
    // AgentSessionID + AgentName never assigned
}
audit.ReconstructOverridesFromRow(&in)
out = append(out, audit.FromRequest(in))
```

Downstream impact, same as round 2:
```
iam-jit audit query \
  --bouncer dbounce=http://127.0.0.1:8768 \
  --bouncer kbounce=http://127.0.0.1:19082 \
  --bouncer gbounce=http://127.0.0.1:19084 \
  --filter agent.session_id=d156eb5f-... --format summary
# dbounce: 1 events
# gbounce: 0 events   ← JSONL has it; /audit/events does not
# kbounce: 1 events
```

**Severity**: CRIT [REGRESSION]. #320 closed dbounce + kbouncer but skipped gbounce. Identical defect, identical launch-blocker bar.

**Suggested fix**: In `gbounce/internal/proxy/audit_events.go` `rowsToAuditEvents`, copy `AgentSessionID: r.AgentSessionID, AgentName: r.AgentName` into the `RequestInput`. `audit.FromRequest` already validates + populates the OCSFAgent block from those fields (`event.go:419-458`).

---

## INFO: dbounce silently regenerates session_id on malformed application_name

When `application_name=iam-jit-agent:test:bad session w/ spaces` is sent (deliberately malformed session_id), dbounce parses the prefix, drops the invalid session_id silently, and stamps a fresh ULID-shaped session_id with `detected_from=pg_application_name`. No `agent_header_rejection` breadcrumb. Diverges from gbounce + kbounce which DO stamp the breadcrumb on invalid input. Out of scope; flagging for cross-product consistency tracking.

---

## Health summary (3 sentences)

The launch-blocker bar is FARTHER OUT after round 3, not closer: round 3 surfaced two CRITs of equal severity to the round-2 CRITs they were meant to close. #319 broke `ibounce run` outright (the click flag landed but the matching `ProxyConfig` field did not — the commit message claims a complete fix that the code does not implement), and #320's cross-product wire-shape parity fix skipped gbounce entirely (the same SQLite-row-to-event reconstruction gap that closed for dbounce in round 2 still ships on gbounce, with the identical downstream `iam-jit audit query` under-count). Newly-shipped #317 (cloud-neutral S3-compat sink) and #298 (link page) both PASS without findings — the wins from this cycle were the additive features, not the regression fixes.
