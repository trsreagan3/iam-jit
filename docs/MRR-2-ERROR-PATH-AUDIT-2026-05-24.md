# MRR-2 — Error-path actionability audit (2026-05-24)

Phase 2 of the Mission Readiness Review (`[[mrr-flight-readiness-program]]`)
before the founder's work-machine deploy. Audited starting against
`iam-roles` HEAD `7d69e68` (MRR-1 landed); concurrent agents working on
UAT-LIFECYCLE + MRR-4-HALT-CONDITIONS in parallel (no scope conflict).
This document catalogs every representative operator-visible error
surface against the 4-question rubric: WHAT failed / WHY / WHAT TO DO
NEXT / agent-actionable.

Per founder direction 2026-05-24: *"robust error handling that agents
and users can understand efficiently."* Method per
`[[ibounce-honest-positioning]]`: be honest, not generous. A
technically-informative message that doesn't tell the operator what
to do is PARTIAL, not WELL-FORMED.

Per MRR-1: the 5 CRITs all share root cause "state claimed without
observable verification." MRR-2 catalogs the OPERATOR-side of that
same shape: a green status string that doesn't carry recovery
information is dishonest in the same way a green banner masking a 401
is.

## 1. Executive summary

Audited 194 Python modules under `src/iam_jit/`. Sampled
representatively across CLI, MCP, HTTP, config, audit/state, and the
calibration-drift surfaces that MRR-1 flagged. Total operator-visible
error sites surveyed: **~120**. Score distribution against the 4/4
rubric:

| Score | Count | % | Headline |
|---|---|---|---|
| **WELL-FORMED (4/4)** | ~55 | 46% | Structured fields + WHAT-TO-DO hint + agent-actionable code |
| **PARTIAL (2-3/4)** | ~52 | 43% | Names WHAT + WHY but no recovery hint, OR no structured code |
| **CRYPTIC (0-1/4)** | ~13 | 11% | Bare string from raised exception; opaque to operator |

The repo has STRONG error-shape discipline in places where it was
deliberately built (synthesis-flow validation, structured-deny
response, threat-feed updates `revoke`, license verification, dynamic-
deny operations, ambient-config setup, backup/restore). But there are
**3 recurring systemic gaps**:

1. **The `f"ERROR: {e}"` / `f"internal error: {e}"` shape** at ~13
   sites that re-raises the bare exception text with no recovery path.
2. **Silent-degradation via `logger.warning` / `logger.debug`** at
   ~10 sites where the operator never sees the warning because they
   never tail the log — most pernicious in the autopilot-loop bodies
   and the synthesis env-var fallback (`request_from_synthesis.py:89`).
3. **`status: "auto_installed"` / `status: "ok"` shapes where the
   wrapped operation silently swallows partial failure** (the #448
   shape reproduced in `improve/pipeline.py:680-690` for AT LEAST 2
   surfaces).

The most-important finding for deploy: **the CRYPTIC errors cluster
on the LEAST-tested CRIT surfaces (synthesis flow, improve_profile,
setup_from_config)** — exactly the surfaces MRR-1 flagged as
COMPOSITION-NEVER-TESTED. Same root cause: state-claimed-without-
verification, surfaced from the operator's vantage as
"degraded-but-claims-OK."

### Top 5 most-blocking operator-side error gaps

1. **`improve/pipeline.py:680-690`** — `except ProfileAllowError ... continue` swallows individual rule-add failures and returns `status: "auto_installed"` + `rules_added=len(added)` regardless of how many actually persisted. This is the **#448 shape** reproduced post-convention. CRIT for any operator running `iam_jit_improve_profile` (UC-19 in MRR-1).
2. **`autopilot/daemon.py:566-569`** — `self.alerts.append(f"improve cycle for {name} raised: {e}")` — generic, no code, no recovery; only surface is `/healthz` polling. An operator who runs autopilot will see "improve cycle for ibounce raised: KeyError" with no indication of WHAT to do.
3. **`app.py:458-461`** — `JSONResponse({"detail": "internal server error"}, status_code=500)` is the global catch-all in the iam-jit FastAPI server middleware. No request id, no error code, no recovery hint; stack trace goes to a log the operator never reads.
4. **`mcp_server.py:6475`** — `_err(req.get("id"), -32603, f"internal error: {e}")` leaks raw Python exception text directly into the MCP-RPC stream; agents pattern-match on `"internal error:"` and have no `code` field to disambiguate.
5. **`routes/requests.py:1547`** — `raise HTTPException(status_code=500, detail=f"unexpected error during revoke: {e}")` — leaks exception text into HTTP response body (info-disclosure risk for the work-machine deploy where compliance teams will see this) AND has no recovery action.

## 2. Per-surface audit

### 2.1 CLI error paths

| Surface | Score | Notes |
|---|---|---|
| `cli_canary.py:693-700` (status — no canary status yet) | **4/4** | WHAT (no status), WHY (no deploy), WHAT (run deploy script + bootstrap path), exit 1 |
| `cli_canary.py:1041-1047` (verify-setup divergence) | **4/4** | WHAT (mismatch), WHY (per-bouncer), WHAT (`canary update` OR edit YAML), structured JSON |
| `cli_canary.py:1213` (`_fail` — update failure) | **3/4** | WHAT/WHY OK (subprocess output truncated to 500 chars); WHAT-TO-DO weak — rollback notes follow but no "try X" guidance |
| `cli_canary.py:1133` (`pip install -e .` failed) | **2/4** | WHAT/WHY OK but truncated output; no "try fresh venv / check pip"; CalledProcessError-shape pattern |
| `cli_updates.py:454-465` (revoke aborted — bouncer-side fail) | **4/4** | WHAT (revoke aborted) + WHY (bouncer-side failed) + WHAT (inspect bouncer + retry) + exit 2 |
| `cli_apply_config.py:128-138` (config load failure) | **4/4** | structured `{status:error, code, message, source, details}` + per-error path rendering |
| `cli_apply_config.py:184` (apply result — partial success) | **3/4** | Result dict surfaces warnings list but exit code is 0 even with `bouncers_skipped`; an agent can pattern-match but a human reading exit code thinks "all good" |
| `bouncer_cli.py:7160-7167` (import while ibounce running) | **4/4** | WHAT/WHY/WHAT-TO-DO ("pkill ibounce or set IBOUNCE_PROBE_PORT") + exit 2 |
| `bouncer_cli.py:7173` (`ERROR: {e}` for ConfigBundleError) | **3/4** | Relies on the exception text being good (it is, per backup.py) but no code field for agent matching |
| `bouncer_cli.py:7836` (`ERROR: {e}` for version mismatch) | **3/4** | Same shape — message is good ("pass --force") but no code |
| `bouncer_cli.py:7716/7839` (ERROR: {e} for backup failures) | **3/4** | Same shape |
| `cli_canary.py:160-163` (ValueError in YAML loader) | **3/4** | Message-only ValueError; CLI shows it but no `code` |
| `cli_canary.py:228` (`raise click.BadParameter`) | **4/4** | Click renders with usage hint |
| `cli_canary.py:1410` (`raise click.BadParameter`) | **4/4** | Same |
| `bouncer_cli.py:3679-3693` (duration BadParameter) | **4/4** | Specific msg per failure mode |
| `bouncer_cli.py:421` ("no preset named ... try `presets list`") | **4/4** | Explicit next command |
| `bouncer_cli.py:601/1485` (`rejected: {e}`) | **2/4** | WHAT only — no WHY/WHAT-TO-DO from this site (depends on inner exception) |
| `bouncer_cli.py:673` (`no rule with id #{rule_id}`) | **2/4** | WHAT only; no "run `ibounce rules list` to see ids" |
| `bouncer_cli.py:796/849` (`no audit dir at {log_dir}`) | **3/4** | WHAT + WHY (path); missing WHAT-TO-DO (run init?) |
| `bouncer_cli.py:1304/1336` (`no task with id {task_id!r}`) | **2/4** | WHAT only |

### 2.2 MCP tool error responses

| Surface | Score | Notes |
|---|---|---|
| `mcp_server.py:3158-3162` (score_iam_policy invalid policy) | **4/4** | "policy is required and must be a JSON object with `Version` and `Statement` keys" |
| `mcp_server.py:3175-3178` (scoring engine failed) | **2/4** | `f"scoring engine failed: {e}"` — leaks raw exception; no code, no recovery |
| `mcp_server.py:3241/3268/3274/3316-3325/3364-3382/3444-3483/3562-3570` (compatibility/template input validators) | **4/4** | Structured `{error, ...defaults}` per-field validation messages |
| `mcp_server.py:3206-3224` (NL-policy deprecation block) | **4/4** | Has `replacement_tools` + `agent_guidance` — agent-actionable |
| `mcp_server.py:5638-5657` (dynamic-deny add — DenyOperationError) | **4/4** | `{status:error, code:e.code, message, details}` — fully structured |
| `mcp_server.py:5645-5651` (dynamic-deny write error) | **4/4** | Structured with `code` synthesized from `e.stage` |
| `mcp_server.py:5652-5657` (dynamic-deny bad input) | **4/4** | Structured with `code: "bad_input"` |
| `mcp_server.py:6467` (JSON-RPC parse error) | **3/4** | Standard JSON-RPC -32700; no recovery hint but standard-shape |
| `mcp_server.py:6475` (catch-all `internal error: {e}`) | **1/4** | **CRYPTIC** — JSON-RPC -32603 with raw exception text; no code, no recovery, leaks internals |
| `structured_deny/response.py:106-206` (StructuredDenyResponse) | **4/4** | **GOLD STANDARD** — caught_by_bouncer, deny_reason, deny_source, is_likely_injection_classification, suggested_allow_command, recommended_action, deny_event_id, human_summary(); agent-perfect |
| `improve/pipeline.py:1062` (improve `status: error`) | **3/4** | Has `status: "error"` but message-only payload; lacks `code` for the failure mode |
| `improve/pipeline.py:680-690` (silently swallowing rule-add fail) | **0/4** | **CRIT** — no operator-visible signal; `logger.warning` only; `status: "auto_installed"` still returned — this is the #448 shape |
| `request_from_synthesis.py:154-282` (SynthesisRequestError raises) | **4/4** | **GOLD STANDARD** — `SynthesisRequestError(message, code=..., details={...})`; per-field paths; OCSF-friendly codes (`missing_evidence_block`, `invalid_audit_window_iso_format`, etc.) |

### 2.3 HTTP surface errors

| Surface | Score | Notes |
|---|---|---|
| `app.py:458-461` (global 500 catch-all) | **0/4** | **CRIT** — `{"detail": "internal server error"}` — no id, no code, no path; stack trace logged but operator never reads it |
| `routes/requests.py:1547` (revoke unexpected 500) | **1/4** | Leaks `f"unexpected error during revoke: {e}"`; no code, no recovery; info-disclosure risk |
| `routes/requests.py:1542-1544` (revoke 502 ProvisioningError) | **2/4** | Leaks exception text via `f"revoke failed: {e}"`; relies on the ProvisioningError carrying a useful msg |
| `routes/requests.py:1563` (409 IllegalTransition) | **3/4** | Honest HTTP code; message is `str(e)` so depends on the lifecycle exception text |
| `middleware.py:27-260` (multiple HTTPException raises) | **3/4** | Bulk uses standard HTTP codes with `detail` strings; no structured code field for agent pattern-matching |
| `bouncer/proxy.py:3140-3153` (502 upstream forward fail) | **3/4** | Has `error`, `upstream_error`, `service`, `action`; missing `code` + WHAT-TO-DO ("retry" / "check IAM" / "check region") |
| `bouncer/proxy.py:3470-3483` (502 same shape) | **3/4** | Same as above |
| `bouncer/proxy.py:3643-3760+` (/healthz handler) | **4/4** | Rich structured response with `status`, `degraded`, per-subsystem blocks (audit_export, dynamic_denies, heartbeat, pause); 503 on degradation; agent + monitor friendly |
| 403 structured-deny (built via `structured_deny.response`) | **4/4** | Inherits the GOLD STANDARD shape from §2.2 |

### 2.4 Configuration error paths

| Surface | Score | Notes |
|---|---|---|
| `dynamic_denies/loader.py:240-244` (schema violation) | **4/4** | Surfaces the FIRST error verbatim with `field_path`; explicit "one actionable message" comment |
| `dynamic_denies/loader.py:295-321` (read/parse/structure errors) | **4/4** | Stage-tagged: `stage="read"|"parse"|"structure"` + path + cause |
| `bouncer/profiles.py:292-619` (parse validators) | **3/4** | Strong WHAT/WHY ("profile X: allow_rules[i].pattern is required + must be a string") but ValueError-only (no structured code); operator gets it via `bouncer_cli.py:7173 ERROR: {e}` wrapping |
| `ambient_config/setup.py:679-682` (master switch disabled) | **4/4** | "iam-jit.enabled is false; setup is a no-op. Flip to true to install + start bouncers." |
| `ambient_config/setup.py:725-729` (conditional-resolved-false skip) | **4/4** | Transparent skip with evidence |
| `ambient_config/setup.py:792-834` (port-conflict resolution) | **4/4** | "port X is in use by a process that does NOT identify as an iam-jit bouncer. The setup will NOT start Y on this port. Either stop the existing process or set `bouncers.Y.port:` to a free port in your declaration." |
| `ambient_config/setup.py:871-883` (already-running with mismatch) | **4/4** | Surfaces declared + runtime modes side-by-side; explicit "Stop manually and re-run" |
| `ambient_config/setup.py:930-937` (profile pinned but not in profiles.yaml) | **4/4** | Names the file + the fix command |
| `ambient_config/setup.py:535-538` (subprocess.Popen failed) | **2/4** | `f"subprocess.Popen failed: {e}"` — message-only, no WHAT-TO-DO; the caller may surface it but the inner site is bare |
| `threat_feed/signing.py:117-172` (Ed25519 verify failures) | **3/4** | WHAT/WHY good ("failed to base64-decode public key", "must be 32 bytes, got N") but no recovery hint (operator doesn't know if they need to regenerate, re-download, switch trust anchor) |
| `license.py:211-321` (LicenseInvalidError sites) | **3/4** | WHAT/WHY excellent ("unknown envelope fields: [kid]", "max_users must be an integer in [1, 1_000_000]"); WHAT-TO-DO weak — "signature does not verify against embedded public key" doesn't tell operator if it's the wrong file vs the wrong build vs the wrong tier |
| `license.py:211-216` (zero-sentinel public key) | **4/4** | Explicit "This build cannot verify any license; running on Free tier only. Install a build with the real production key embedded." |
| `bouncer/backup.py:293-296/300-303` (source-missing / overwrite-refuse) | **4/4** | "source DB does not exist at X. Did you `ibounce init` first?" / "already exists; remove it first or pick a different --out path" |

### 2.5 Audit + state error paths

| Surface | Score | Notes |
|---|---|---|
| `bouncer/store.py:519-524` (InvalidRuleError) | **4/4** | "invalid rule pattern X: must be in 'service:action_glob' form, e.g. 's3:GetObject' or 's3:Put*'. Service must be a bare prefix (no wildcards); action may include '*'." |
| `bouncer/audit_export/disk_pressure.py` circuit breaker | **3/4** | Triggers state flip but operator-facing surface is the `/healthz` `audit_export.degraded` block — well-structured but doesn't include "run X to remediate" |
| audit chain break detection | **3/4** | Surfaces via `audit_export_degraded` /healthz flag; missing operator-facing "run `iam-jit audit verify` to diagnose" hint |
| sqlite locked / busy errors | **2/4** | `bouncer/backup.py` retries with backoff (`_exec_with_busy_retry`); on final failure, surface is "drop {table}: {sqlite.OperationalError}" — operator-friendly but no "stop ibounce + retry" guidance |

### 2.6 Calibration-drift error paths (per MRR-1 finding #2)

These are the surfaces where "state claimed without observable
verification" appears AS AN ERROR-SHAPE PROBLEM (not just a test-
discipline problem):

| Surface | Score | Notes — the SHAPE that MRR-1 flagged |
|---|---|---|
| `improve/pipeline.py:680-690` (rule-add silent swallow) | **0/4** | `status: "auto_installed"` with `rules_added=len(added)` — but if individual `add_rule` calls raised `ProfileAllowError` they were silently `continue`d. This IS the **#448 shape** reproduced post-convention. Catastrophic for `iam_jit_improve_profile`. |
| `autopilot/daemon.py:566-569` (improve-cycle alert) | **1/4** | `self.alerts.append(f"improve cycle for X raised: {e}")` — generic, no code, only surface is `/healthz` polling |
| `autopilot/daemon.py:594-598` (threat-feed sub load fail) | **0/4** | `logger.debug(...)` + `return []` — operator gets no signal; threat-feed silently inactive |
| `request_from_synthesis.py:88-94` (env-var fallback) | **0/4** | `_logger.warning(...)` — fallback message only goes to logs; the function happily returns the default. This is the **#5 silent-degradation** MRR-1 noted. |
| `routes/requests.py:944-959` (self-approve eval bare-except) | **1/4** | Wrapping `try: ... except Exception: pass` means the gate silently goes inert; `_self_approve_audit` stays `{"self_approve_evaluated": False}` and the response carries no diagnostic |
| `bouncer/proxy.py:3653-3655` (healthz decision-count fail) | **3/4** | Flips `status_str="degraded"` — visible to operator polling /healthz; missing "run X to recover" |
| `structured_deny/response.py:244-246` (classifier hook load fail) | **2/4** | `logger.debug(...)` — silently falls back to ambiguous classification; this is the documented intent per `[[ibounce-honest-positioning]]` but the operator never sees the hook is broken |
| `mcp_server.py:5680-5682` (admin-action audit emit fail) | **1/4** | Bare `except Exception: pass` — the deny was recorded but the audit-trail emit silently failed; operator has no signal |
| `mcp_server.py:4233/4949/5297/5363` (other bare except: passes) | **1/4** | Multiple sites silently swallow audit-emit failures; collectively this is the same shape as #475 ("audit_event_ids returned but events were write-only") |

## 3. Pattern catalog — the recurring bad-error-handling shapes

### Pattern A — `f"ERROR: {e}"` / `f"internal error: {e}"` (CRYPTIC)

```python
except Exception as e:
    click.echo(f"ERROR: {e}", err=True)
    sys.exit(1)
```

Found at: `bouncer_cli.py:7173`, `7716`, `7836`, `7839`, `7172`,
`mcp_server.py:6475`, `routes/requests.py:1544`, `1547`. **13 sites.**

The bare `{e}` relies on the upstream exception to carry actionable
text; sometimes it does (LicenseInvalidError, BackupError) and the
score is PARTIAL-3/4; sometimes it doesn't (any generic Exception
caught after a `raise from None` chain) and the operator sees
something like `KeyError: 'foo'` with no context.

**Fix sketch**: introduce a `_render_error(exc, *, code, hint)` helper
that takes the exception + a known code + a one-line WHAT-TO-DO hint
and emits a structured payload (JSON in `--json` mode, formatted
text otherwise). Wrap every `except Exception` in CLI command bodies
with this helper.

### Pattern B — Silent-degradation via `logger.warning` / `logger.debug`

```python
try:
    ...
except Exception as e:
    logger.warning("X failed: %s", e)
    # ...fall back to default behaviour...
```

Found at: `request_from_synthesis.py:89`, `autopilot/daemon.py:594-598`,
`structured_deny/response.py:244-246`, `mcp_server.py:5680-5682`,
`improve/pipeline.py:688-690`, multiple bare `except Exception: pass`
in admin-action emit sites. **~10 sites.**

The operator never tails the log; the only visible signal is
"feature isn't working." MRR-1 caught this as silent-degradation #5
in the LLM-call-site audit. The fix is NOT "raise instead" (the
fallback IS the right behaviour per `[[ibounce-honest-positioning]]`
when the alternative is bouncer downtime). The fix is **emit a
structured `report_skip` / `degraded_capability` event** to the
audit channel so `/healthz` + posture + the operator's status views
surface the degradation.

The `llm/report_skip.py` module already does this for LLM backend
degradation; the pattern should be lifted to a generic
`degraded_capability.emit(feature=..., reason=..., extra={...})` and
applied to all bare-except sites.

### Pattern C — `status: "ok"` / `status: "auto_installed"` shapes with silently swallowed partial failures

```python
for rule in proposed:
    try:
        result = add_rule(...)
        added.append(...)
    except ProfileAllowError as e:
        logger.warning("rule add refused: %s", e)
        continue
return ImproveProfileResult(status="auto_installed", rules_added=len(added))
```

Found at: `improve/pipeline.py:680-690` definitively; the shape may
exist elsewhere in the improve cycle, threat-feed apply, and any
loop that aggregates per-item results into a top-level success
status. **At least 1 confirmed; needs sweep.**

This is THE #448 shape (`status:auto_installed` with zero rules
persisted) and the convention in `docs/CONTRIBUTING.md` was written
specifically to catch it. The convention is on the TEST side; the
runtime side has no equivalent assertion. The fix: **never return
`auto_installed` if ANY rule failed to add**; either return
`partial_install` with a `failed_rules: [...]` list, or hard-fail
and roll back the partial state.

## 4. Top 20 worst-offending sites

Ranked by deploy impact (calibration-drift / silent-degradation
weighted heavier than CLI papercuts):

1. `src/iam_jit/improve/pipeline.py:680-690` — silent rule-add swallow; `status: auto_installed` lies about `rules_added`. **CRIT**. **#448 shape**.
2. `src/iam_jit/app.py:458-461` — global 500 catch-all returns `{detail:"internal server error"}` with no id/code/path. **CRIT for HTTP surface debuggability.**
3. `src/iam_jit/mcp_server.py:6475` — JSON-RPC catch-all `f"internal error: {e}"` with no code, leaks exception text. **CRIT for agent debuggability.**
4. `src/iam_jit/routes/requests.py:1547` — revoke 500 leaks `f"unexpected error during revoke: {e}"`. Info-disclosure for work-AWS deploy. **HIGH.**
5. `src/iam_jit/autopilot/daemon.py:566-569` — `improve cycle for X raised: {e}` alert with no code, only-surface is /healthz. **HIGH.**
6. `src/iam_jit/autopilot/daemon.py:594-598` — threat-feed sub load: `logger.debug` + `return []`; silent inactive. **HIGH.**
7. `src/iam_jit/request_from_synthesis.py:88-94` — env-var fallback `_logger.warning` only; operator never sees IAM_JIT_SYNTHESIS_MAX_LOOKBACK_DAYS typo. **HIGH** — flagged in MRR-1 §5.
8. `src/iam_jit/routes/requests.py:944-959` — `try: sar_decision = sar.evaluate(...) except Exception: pass` — self-approve evaluation silently inert. **HIGH.**
9. `src/iam_jit/mcp_server.py:5680-5682` and ~10 other admin-action audit-emit `bare except: pass` sites — audit-trail emits silently fail. **HIGH** — collectively the #475 shape ("audit_event_ids returned but write-only").
10. `src/iam_jit/structured_deny/response.py:244-246` — classifier hook load `logger.debug` + return None; hook silently disabled. **MED** (documented per ibounce-honest-positioning but no operator-visible status).
11. `src/iam_jit/routes/requests.py:1542-1544` — revoke 502 leaks `f"revoke failed: {e}"`. **MED.**
12. `src/iam_jit/bouncer/proxy.py:3140-3153` and `3470-3483` — upstream-forward 502 lacks `code` + WHAT-TO-DO. **MED** (relevant for agent retry decisions).
13. `src/iam_jit/bouncer_cli.py:7173/7716/7836/7839` — `ERROR: {e}` pattern; rescue depends on inner exception text. **MED** (mostly works because backup.py exceptions are good).
14. `src/iam_jit/ambient_config/setup.py:535-538` — subprocess.Popen failed: `record["reason"] = f"subprocess.Popen failed: {e}"`. The caller surfaces it but the inner site is bare. **MED.**
15. `src/iam_jit/bouncer_cli.py:601/1485` — bare `rejected: {e}` for InvalidRuleError. **MED** (the inner message IS actionable, but no `code` for agent).
16. `src/iam_jit/bouncer_cli.py:673/1304/1336` — `no rule/task with id X` — WHAT only, no "run `... list` to see ids" hint. **LOW.**
17. `src/iam_jit/bouncer_cli.py:796/849` — `(no audit dir at X)` — missing "run `ibounce init` to create it" hint. **LOW.**
18. `src/iam_jit/threat_feed/signing.py:117-172` — Ed25519 verify errors — strong WHAT/WHY, weak WHAT-TO-DO ("install cryptography library" vs "fetch updated trust anchor" not differentiated). **LOW.**
19. `src/iam_jit/license.py:272` — "signature does not verify against embedded public key" — doesn't tell operator if it's the wrong file vs the wrong build. **LOW.**
20. `src/iam_jit/cli_apply_config.py:184` — apply result exits 0 even with `bouncers_skipped`; an exit-code-checking script doesn't see partial failure. **LOW** (the JSON is structured so agents are fine).

## 5. Systemic recommendations

### R1 — Introduce `iam_jit.errors.OperatorError`

A common exception base carrying `(message, code, hint, details)`.
Every CLI/MCP/HTTP catch site renders via a single `_render_error()`
helper that emits a structured `{status:"error", code, message,
hint, details}` payload in JSON mode and a 4-line human format
otherwise:

```
ERROR (code=license.signature_invalid): signature does not verify
  against the embedded public key.
HINT: this usually means the license was generated for a different
  build of iam-jit. Run `iam-jit version` to see your build id and
  contact support with the license_id.
DETAILS: license_id=lic-foo, embedded_key_fingerprint=abc123
```

Replaces all `f"ERROR: {e}"` sites + the global 500 catch-all + the
JSON-RPC catch-all.

### R2 — Generalise `llm.report_skip` to `degraded_capability`

Promote the `report_skip(feature, reason, extra)` pattern from the
LLM-call-site refactor into a generic `degraded_capability.emit()`
applied to EVERY silent-fallback site. The capability shows up on
/healthz, in posture, and in the operator's audit-tail. Closes
Pattern B silent-degradation.

### R3 — Outlaw `status: "auto_installed"` with hidden partial-failure

Add a runtime invariant to `ImproveProfileResult`: if `rules_added <
len(proposed_allows)` then `status` MUST be `"partial_install"` not
`"auto_installed"`. Add the same invariant wherever a top-level
aggregator returns a green status; the convention in
`docs/CONTRIBUTING.md` already covers the test side — this is the
runtime mirror. **The MRR-3 UAT framework should exercise this
explicitly for `iam_jit_improve_profile` (UC-19 in MRR-1).**

### R4 — Add a `next_action` field to 5xx structured responses

The bouncer `/proxy` 502 forward-failure payloads have `error`,
`upstream_error`, `service`, `action` but no `next_action` (retry?
retry with backoff? open a support ticket? check IAM creds?).
Add a `recommended_action` field analogous to the
StructuredDenyResponse pattern. Agents will pattern-match on it for
auto-retry vs escalate decisions.

### R5 — Sweep bare-except admin-action emits

The ~10 sites with `try: ... except Exception: pass` around
`emit_admin_action_direct(...)` are the cumulative root of the
#475 shape (audit_event_ids returned but events were write-only).
Each site should at minimum increment a counter that /healthz
reads, so the operator sees `admin_action_emit_failures: N` if any
fired. Better: emit the failure itself as a `meta` audit row so
the audit-chain is self-witnessing.

### R6 — Re-audit the 5 MRR-1 CRIT surfaces with the rubric

MRR-1 found 5 composition-untested CRITs. The error-paths of those
exact surfaces have the highest "shape divergence between claimed
status and operator-visible state" risk. The MRR-3 UAT framework
should test the error-paths of UC-3 (synthesis), UC-17 (audit→
profile→install), UC-20 (setup-from-config), UC-19 (improve_profile),
and UC-30 (init) explicitly — feed a poisoned/malformed input at
every layer and assert the resulting error message scores 4/4.

## 6. Agent-actionability assessment

Which surfaces give an agent enough structure to pattern-match and
recover vs. requiring it to parse free-form text?

| Surface family | Agent-actionable? | Notes |
|---|---|---|
| StructuredDenyResponse (403 deny) | **YES (gold)** | Every field has known shape; `recommended_action` is enum; `deny_event_id` is stable handle |
| Dynamic-deny MCP responses (add/remove/list) | **YES** | `{status:error, code, message, details}` |
| Compatibility-check / template / score MCP tools | **YES** | Structured `{error: "...", ...defaults}` |
| Synthesis SynthesisRequestError | **YES (gold)** | OCSF-friendly `code` + `details` |
| Apply-config result | **YES** | SetupResult dataclass; warnings list; per-bouncer breakdown |
| Healthz JSON | **YES (gold)** | Per-subsystem `degraded` flags |
| Threat-feed updates revoke | **YES** | Structured payload with `bouncer_remove`, `fanout_failures`, `ledger_updated` |
| App 500 / HTTPException catch-alls | **NO** | Bare `{detail: "X"}` — no `code` field |
| MCP -32603 internal error | **NO** | Raw exception text only |
| `ERROR: {e}` CLI shapes | **PARTIAL** | Depends on inner exception text |
| Profile YAML ValueError shapes | **PARTIAL** | Good message, no code |
| Bouncer 502 upstream-forward | **PARTIAL** | Has `service`/`action`/`upstream_error` but no `code`/`next_action` |
| `logger.warning` silent fallbacks | **NO** | Agent only sees that the feature didn't work |

**Overall**: where the team deliberately built structured-error
shapes (5 modules: structured_deny, dynamic_denies, synthesis,
ambient_config, threat_feed updates), agents have everything they
need. Where errors are catch-all wraps or `f"ERROR: {e}"` shapes,
agents have to LLM-parse free-form text — which is exactly the
brittleness the structured shapes were introduced to avoid.

## 7. Fix-task proposals (parent agent to file as tasks)

### Pre-deploy (BLOCK)

| # | File:line | Severity | Fix sketch |
|---|---|---|---|
| F1 | `src/iam_jit/improve/pipeline.py:680-690` | **CRIT** | Add `failed_rules: list[dict]` to ImproveProfileResult; if non-empty, status → `partial_install`; surface in result dict. This closes the #448-shape regression on UC-19. |
| F2 | `src/iam_jit/app.py:458-461` | **CRIT** | Build `OperatorError` helper per R1; 500 catch-all returns `{status:"error", code:"server.internal", request_id: <uuid>, hint: "Check server logs grep request_id=X for details", path: <request.url.path>}`. |
| F3 | `src/iam_jit/mcp_server.py:6475` | **CRIT** | Same — JSON-RPC -32603 should return structured `{code, message, hint, request_id}` not raw `f"internal error: {e}"`. |
| F4 | `src/iam_jit/routes/requests.py:1547` | **HIGH** | Stop leaking exception text in `detail`. Return `{code: "revoke.internal_error", request_id: ..., hint: "Re-attempt or contact support with request_id"}`. |
| F5 | `src/iam_jit/autopilot/daemon.py:566-598` | **HIGH** | Use `degraded_capability.emit()` per R2 for the improve-cycle + threat-feed sub-load failures; surface as `/healthz` `autopilot.degraded` block. |
| F6 | `src/iam_jit/request_from_synthesis.py:88-94` | **HIGH** | Replace `_logger.warning(...)` with `degraded_capability.emit(feature="synthesis.max_lookback_env", reason="bad_env_var_value", extra={"value": raw})`. |
| F7 | `src/iam_jit/routes/requests.py:944-959` | **HIGH** | Replace bare-except with `degraded_capability.emit(feature="self_approve.eval", reason="eval_raised")`; response carries `self_approve_evaluated: false, reason: "evaluation_error"`. |
| F8 | ~10 admin-action emit sites | **HIGH** | Sweep; replace bare-except with `degraded_capability.emit("admin_action.emit_failed", reason=...)`; increment /healthz counter. |

### Pre-promotion (HIGH; can land in dogfood week)

| # | File:line | Severity | Fix sketch |
|---|---|---|---|
| F9 | `src/iam_jit/bouncer/proxy.py:3140-3153 + 3470-3483` | **MED** | Add `code: "upstream.forward_failed"` + `recommended_action: "retry|escalate|check_iam"` based on the upstream-error type. |
| F10 | `src/iam_jit/bouncer_cli.py:7173/7716/7836/7839` | **MED** | Refactor `f"ERROR: {e}"` sites to `_render_error(exc, code=..., hint=...)`. |
| F11 | `src/iam_jit/structured_deny/response.py:244-246` | **MED** | `degraded_capability.emit("classifier_hook.load_failed", ...)`; honest visibility on hook health. |
| F12 | `src/iam_jit/license.py:272` | **MED** | Add `hint` to the InvalidSignature branch: "this usually means the license was generated for a different iam-jit build; run `iam-jit version` to see your build id." |
| F13 | `src/iam_jit/threat_feed/signing.py` failures | **MED** | Add hint per error code: "key rotation may have occurred — re-fetch trust anchor with `iam-jit updates trust refresh`." |
| F14 | `src/iam_jit/bouncer/profiles.py:292-619` ValueError sites | **MED** | Wrap in `ProfileSyntaxError(ValueError)` with structured `code` field per validation rule; bouncer_cli wrapper renders structured. |
| F15 | `src/iam_jit/cli_apply_config.py:184` | **LOW** | Exit 3 if any `bouncers_skipped` in apply mode (not dry-run); 0 stays "fully clean apply." |

### Post-deploy (LOW; quality-of-life)

| # | File:line | Severity | Fix sketch |
|---|---|---|---|
| F16 | `bouncer_cli.py:673/1304/1336` | **LOW** | Append "(run `ibounce rules list` to see ids)" hints to "no rule/task with id X" |
| F17 | `bouncer_cli.py:796/849` | **LOW** | Append "(run `ibounce init` to create it)" to "no audit dir at X" |
| F18 | `cli_canary.py:1133-1156` (subprocess fail truncation) | **LOW** | Save full stdout/stderr to issues.jsonl + tell operator "full output saved to ~/.iam-jit/canary/issues.jsonl" |

## 8. Cross-cutting with MRR-1

The 5 MRR-1 CRITs each have an error-handling component that COMPOUNDS the composition gap:

| MRR-1 CRIT | Error-path component |
|---|---|
| #1 (audit→profile→install→iterate composition untested) | If `iam_jit_improve_profile` returns `auto_installed` with `rules_added` wrong (F1), the agent thinks the loop succeeded; the bouncer's behaviour doesn't change; operator hits the dogfood-variant-A "every legitimate write denied" shape. |
| #2 (iam_jit_setup_from_config never E2E via MCP agent) | If a partial install hits `ambient_config/setup.py:535` (subprocess.Popen failed), the SetupResult includes `bouncers_skipped` BUT the MCP wrapper returns `status: "ok"` (apply_config_for_mcp:353); agent thinks setup succeeded; operator's posture is split-brain. |
| #3 (synthesis flow only mock-tested) | If the env-var fallback (F6) fires silently, the operator's intended-90-day window silently truncates to 7 days; subsequent synthesis-derived role requests get rejected with `invalid_audit_window_too_old` for events the operator THOUGHT were in scope. |
| #4 (dbounce H3 unfixed) | Bypass + missing-audit means the operator-visible surface is "looks fine" — no error to render. The error-path problem here is REVERSE: the absence of any deny/log event when one was warranted. dbounce is a separate Go repo so out of MRR-2 scope for iam-roles. |
| #5 (`iam-jit init` not shipped) | The current onboarding hits `init-solo` + manual YAML + `iam-jit doctor apply-config`; each leg has its own error surface, and a typo in the YAML hits `cli_apply_config.py:128-138` (which IS well-formed, 4/4). So the error-path component here is COMPLEXITY not bad shape — the operator has 3 places to look when something fails. |

The biggest error-path multiplier on MRR-1's CRITs is #1 — the
`improve_profile` partial-install silent-swallow is the single most
likely place for the deploy-day "ambient autonomous protection
promise broken" experience. **F1 is the highest-priority MRR-2 fix.**

## 9. Recommended fix-task batching

### One-line fixes (~30 minutes total)
- F12, F13, F16, F17 — append hint strings
- F15 — change exit code in one place

### Local-refactor fixes (~2-4 hours each)
- F1 — `ImproveProfileResult` partial-install handling + propagation
- F2, F3, F4 — global catch-all → structured `OperatorError` helper
- F9, F14 — wrap existing exceptions in structured types

### Cross-cutting (1 day each)
- R1 — `iam_jit.errors.OperatorError` helper + sweep ~13 `ERROR: {e}` sites
- R2 — `degraded_capability.emit()` generalisation + sweep ~10 silent-fallback sites
- R5 — admin-action emit hardening (~10 sites + /healthz counter)

### Design discussion needed
- R3 — runtime invariant on `status:auto_installed`. The contract change ripples to MCP-tool consumers; needs an agent-facing migration note.
- R4 — `recommended_action` on 5xx. Requires taxonomy of recoverable vs non-recoverable upstream errors per AWS service surface (boto3-shape).
- R6 — MRR-3 should add error-path scenarios to every CRIT UAT.

---

End of MRR-2. Input for MRR-3 (UAT framework) + the immediate fix-
task batch (F1-F18 + R1-R6).
