# WB Audit Round 11 — Delta since Round 10 (local-mode + safety-mode + plan-capture + Slack-mock + MFA gate)

Scope: code in the round-11 changelist (commits `41c6910`, `8375fcd`, `125cac2`).
Specifically:

- `src/iam_jit/local_server.py` (new — `iam-jit serve --local` bootstrap + token mint)
- `src/iam_jit/safety_mode.py` (new — `read_write_swap` vs `strict` resolver)
- `src/iam_jit/auto_approve.py` (WB10-02/04 fixes — floor clamp + strict-mode toggles)
- `src/iam_jit/routes/requests.py` (safety-mode wiring at /preview + /submit)
- `src/iam_jit/accounts_store.py` (WB10-01 DDB roundtrip fix)
- `src/iam_jit/mfa_gate.py` (new — Layer C MFA freshness verifier)
- `src/iam_jit/self_approve_reductions.py` (new — admin self-approve gate)
- `src/iam_jit/plan_capture.py` (new — JSONL reader + writer)
- `src/iam_jit/_test_support/slack_mock.py` (new — in-process Slack mock)
- `src/iam_jit/cli.py` (new commands: `serve --local`, `init-solo`, `dev-slack-mock`, `doctor *`)

Findings keyed `WB11-NN`.

---

## WB11-01 — HIGH — Per-account `safety_mode_override` can DOWNGRADE a strict deployment default

**Location**: `safety_mode.py` `resolve_mode` lines 92–134; `accounts_store.py` `Account.safety_mode_override` (line 63); `schemas/accounts.schema.json` (`enum: ["strict", "read_write_swap", null]`).

`resolve_mode` priority is documented and implemented as:
1. session_override
2. **account.safety_mode_override** (always wins over deployment default)
3. deployment IAM_JIT_SAFETY_MODE
4. fallback `read_write_swap`

This means a deployment that sets `IAM_JIT_SAFETY_MODE=strict` (the customer's compliance posture) is silently **loosened to read_write_swap** for any single account whose YAML carries `safety_mode_override: read_write_swap`. The multi-account resolver (`resolve_mode_for_accounts`) takes max-strictness, but for the common SINGLE-account request path the per-account override wins unconditionally.

This is the inverse of the Floors-vs-Settings model documented in `[[settings-vs-floors]]` and the strict-mode promise in `[[safety-mode-two-modes]]`. Per the platform-team-floor model, a deployment-wide STRICT must be a **floor** that account-owners cannot loosen below — only TIGHTEN above. The current resolver lets it be loosened.

Concrete exploit: a customer deploys `IAM_JIT_SAFETY_MODE=strict` (PCI-scoped). An admin who can edit `accounts.yaml` (likely a different person from the platform team) sets `safety_mode_override: read_write_swap` on a non-PCI account, expecting "this one account is more lax." Effect: thresholds for that account become read=9 / write=4 (vs strict's 5/2), action wildcards become allowed, admin-fallback becomes allowed. The account-owner has just opt-out of the deploy-time compliance posture without anyone noticing.

**Fix**: clamp the per-account override to be **at least as strict as** the deployment default. Use `_MODE_STRICTNESS` to enforce: `max(deployment_default_rank, account_override_rank)`. Same shape as `resolve_mode_for_accounts` already does for multi-account — apply it to single-account too.

---

## WB11-02 — HIGH — Strict-mode wildcard gate ignores `NotAction` (escalation primitive)

**Location**: `auto_approve.py` `_statement_has_action_wildcard` lines 59–77.

The strict-mode wildcard gate scans only `Action`. `NotAction` is not checked anywhere in the gate, but `NotAction` is a complete escalation primitive: `Effect: Allow, NotAction: "iam:*", Resource: "*"` grants everything except IAM. The strict-mode docstring promises wildcard actions are forbidden in synthesized policies; that promise is broken for `NotAction`, which is functionally MORE dangerous than `Action: "*"` because most reviewers don't reason about it correctly.

The submission schema (`schemas/request.schema.json`) explicitly allows `NotAction` (`"NotAction": {}`), so it's a reachable input shape. `review.py` does walk `NotAction` for malformed-shape detection (lines 1980, 2000), so the field IS in flight — only the strict-mode gate is missing it.

**Fix**: in `_statement_has_action_wildcard`, also walk `stmt.get("NotAction")`. Or — stricter — in strict mode, refuse `NotAction` entirely (it has no legitimate JIT-grant use).

---

## WB11-03 — HIGH — `serve --local` writes the bearer token, then chmods it (race window)

**Location**: `local_server.py` `_ensure_local_cli_token` lines 232–236.

```python
config.cli_token_file.write_text(raw + "\n")
try:
    config.cli_token_file.chmod(0o600)
```

`write_text` creates the file with the process's current umask (typically 0o022 → resulting mode 0o644). The `chmod(0o600)` runs immediately after, but on a multi-user machine the race window between create and chmod allows another local user to `cat ~/<dataDir>/cli-token` and grab the bearer that grants admin to the local iam-jit (which holds AWS-via-default-chain creds).

The token grants admin on a server that, by design, can call `sts:AssumeRole` against the user's AWS default credentials → chain into the customer's AWS environment. So the local race window is not "leaks an iam-jit token"; it's **"leaks a credential that bridges to AWS."**

**Fix**: open atomically with `os.open(path, O_WRONLY | O_CREAT | O_EXCL, 0o600)` then write. Same fix for `users.yaml` and `accounts.yaml` (lines 155, 198) — they also have the same write_text-then-chmod race and contain sensitive identity / account-id data.

---

## WB11-04 — HIGH — `serve --local` prints the raw bearer token to stdout

**Location**: `local_server.py` `run()` line 363.

```python
print(f"  curl -H 'Authorization: Bearer {raw_token}' \\")
```

The startup banner echoes the raw token on stdout in the curl example. Common laptop deployment paths leak this:
- `iam-jit serve --local 2>&1 | tee log.txt` → token in plaintext log file
- `screen` / `tmux` scrollback retention (default ~10000 lines on macOS)
- Container-shipped logs via `docker logs` / launchd / systemd journal
- Screen-share / pair-programming session recordings

Combined with WB11-03, the token has multiple persistence-after-process-death surfaces it shouldn't. The token file path is also a sufficient hint in the banner; the raw value should never appear.

**Fix**: replace the example with `cat $(<token-path>)` substitution form only — never inline the raw token in startup output. The follow-up `init-solo` flow already does this correctly (line 717: `cat {token_file}`); `serve --local` should mirror it.

---

## WB11-05 — MED — `mfa_gate.verify` exists but no route consumes it; high-risk grants currently bypass MFA step-up

**Location**: `mfa_gate.py` (entire module); `routes/*` (full grep — no consumer).

The Layer C MFA-freshness module is implemented, unit-tested, and correctly binds the cookie payload to `expected_user_id` (line 119, defending WB9-01). However, no route in `routes/requests.py`, `routes/score.py`, `provision.py`, or `lifecycle.py` calls `mfa_gate.verify` or checks `is_high_risk(score)`. Effect: every "Layer C" promise the docstring + `[[mfa-compliance-strategy]]` memo make is currently a no-op. Score-9 and score-10 grants flow through without an MFA freshness check.

This is the same shape as WB10-06 (defended cookie that nothing reads). The compliance mapping (`docs/compliance/COMPLIANCE-MAPPING.md`) lists Layer C as part of the PCI 8.x answer; until a consumer wires `verify()`, the answer is incomplete.

**Fix**: thread `mfa_gate.verify(...)` into `submit_request` and `_transition_endpoint("approve", ...)`. When `is_high_risk(score)` is True and `verify().present` is False, return 403 with a structured body telling the client to redirect through fresh OIDC. Add a regression test that asserts a score-7 submission with no/stale MFA cookie returns 403.

---

## WB11-06 — MED — `self_approve_reductions.evaluate` exists but no route consumes it

**Location**: `self_approve_reductions.py` (entire module); `routes/requests.py` (full grep — no consumer).

Same shape as WB11-05. `evaluate()` is implemented and unit-tested, but `submit_request` does not call it. Effect: solo-mode admins still go through the auto-approve threshold gate; the documented "skip approval not audit" reduction shortcut is a no-op. The local-mode banner (`local_server.py` line 17 `└─ self_approve_reductions=true by default`) promises behavior the wired code does not deliver.

**Fix**: in `submit_request`, BEFORE the auto_approve.evaluate() call, run `self_approve_reductions.evaluate(...)`. On `self_approved=True`, mark the request approved with actor `audit_actor_for(user.id)` and SKIP the auto-approve scoring gate (but not the audit emit). Audit-log the self-approve event with kind `request.self_approved`. Add a regression test against the solo-mode + admin + own-request happy path AND against the not_owner / not_admin / service_blocked rejection paths.

---

## WB11-07 — MED — `IAM_JIT_MFA_STEP_UP_AT_SCORE` accepts any int; can be set to 999 to disable the gate

**Location**: `mfa_gate.py` `_high_risk_score_floor` lines 141–146.

The env-var override accepts any int parseable by `int()`. An operator (or compromised env) setting `IAM_JIT_MFA_STEP_UP_AT_SCORE=999` makes `is_high_risk(score)` return False for any 1–10 score, silently disabling the entire Layer C MFA gate. Negative values trigger MFA on every request (DoS). Zero means MFA on every request including score=0 reads.

The audit-and-compliance promise is "high-risk grants require fresh MFA"; runtime should not silently honor a value that disables that promise. Operator sets-and-forgets are exactly the failure mode this should be hardened against.

**Fix**: clamp to `1..10` at read time. Log a WARNING on out-of-band values. If the operator wants to disable the gate, force them to set a separate explicit `IAM_JIT_MFA_STEP_UP_DISABLED=1` flag — the disable path should be loud, not "set the threshold to a number IAM scores can't reach."

---

## WB11-08 — MED — `--host` accepts arbitrary bind address; `serve --local 0.0.0.0` exposes admin API to LAN with insecure cookies

**Location**: `cli.py` `serve` line 566–569 (`--host` default `127.0.0.1`, NO validation); `local_server._set_local_env_defaults` line 305 (`IAM_JIT_DEV_INSECURE_SECRET=1`).

The `--host` flag is free-form. A user running `iam-jit serve --local --host 0.0.0.0` (or `--host 192.168.x.x`) exposes:
- The admin-tier bearer token (anyone on LAN can guess/sniff and present it)
- Insecure session cookies (`IAM_JIT_DEV_INSECURE_SECRET=1` is unconditionally set in `_set_local_env_defaults`)
- The boto3 default-chain AWS credentials (chained via the assume-role provisioning path)

The local mode is documented as "trust the binary on your laptop" — but the moment `--host` leaves `127.0.0.1`, the trust model silently broadens to "trust everyone on the same subnet." Coffee-shop wifi, LAN-shared dev, container with bridged networking all fail this.

**Fix options**: (a) refuse non-loopback `--host` unless an explicit `--bind-non-loopback` opt-in is also given, with a banner that explains the risk + suggests using `iam-jit serve` (non-local production mode) instead; (b) when `--host != 127.0.0.1`, refuse to set `IAM_JIT_DEV_INSECURE_SECRET=1` and require a real signing secret. Option (a) is louder and matches the "loud disable" pattern from WB11-07.

---

## WB11-09 — MED — `plan_capture.parse_line` silently normalises `iam_resource: null` to `"*"`

**Location**: `plan_capture.py` lines 129–131.

```python
elif iam_resource is None:
    iam_resource_normalized = "*"
```

A malicious capture file that writes `"iam_resource": null` (or omits the field — `iam_jit_block.get("iam_resource")` returns None) gets silently converted to a wildcard. The `summarize` function (line 192) then adds `"*"` to `resources_touched`. A future recommender consumer that uses `summarize`'s output to set `Resource: [...]` on a synthesized policy would emit `Resource: ["*"]` — silent escalation from "no resource info" to "any resource."

The producer side (terraform/cdk plan-time HTTP proxy) is per the changelog still being written (#132 producer pending). A producer that fails to capture the resource ARN should emit a structured "unknown" sentinel that the consumer must consciously handle, not be silently widened to `"*"`.

This is a future-consumer landmine: the reader is the durable contract. If it normalizes None → "*" today, every future consumer inherits the silent escalation. No consumers exist yet, so the impact today is zero — but the bug is in a contract surface that's hard to change later.

**Fix**: raise `PlanCaptureError` on missing `iam_resource`, OR represent the missing case as a sentinel `"_unknown_"` string (not the wildcard) so consumers must handle it explicitly.

---

## WB11-10 — MED — `plan_capture` reader has no size limits (zip-bomb / large-file DoS)

**Location**: `plan_capture._open_capture` lines 63–73; `read_capture` lines 149–161.

The reader uses `gzip.open(...)` and `open(...)` with no size cap. Attack surface:
1. **Decompression bomb**: a 10KB `.jsonl.gz` decompressing to 100GB consumes all RAM/disk on the host (Lambda → OOM kill).
2. **Single huge line**: `for line in f:` reads up to a newline; a multi-GB no-newline file causes a single massive str allocation.
3. **Generator-with-context-manager leak**: `_open_capture` opens the file inside a `with` then yields from inside — if the generator is partially consumed and GC'd, the file is closed eventually but the iteration leaks until then.

The reader is a public API (per docstring); the producer is untrusted (per `[[recommender-context-boundary]]` — captures come from customer infra). A customer-supplied or attacker-controlled capture file can DoS the recommender host.

**Fix**: cap decompressed bytes (e.g., 100MB) by tracking byte count in the iterator and raising `PlanCaptureError` when exceeded. Cap line length at e.g. 1MB by reading bounded chunks. Document the caps in `PLAN-CAPTURE-FORMAT.md` so producers know the contract.

---

## WB11-11 — LOW — Strict-mode wildcard gate misses Unicode lookalike `＊` (FULLWIDTH ASTERISK U+FF0A) and `？` (U+FF1F)

**Location**: `auto_approve.py` `_statement_has_action_wildcard` line 75.

```python
if "*" in action or "?" in action:
```

The check is ASCII-only. An `Action: "s3:Get＊"` (full-width asterisk) does NOT match. AWS IAM does not honor non-ASCII wildcards either, so the DOWNSTREAM effect is "permission grants nothing" — but the gate is a SAFETY check, not a functional check. The risk is asymmetric: a strict-mode customer gets a false sense of security ("strict mode rejects wildcards") when in fact the gate is bypassable by a Unicode trick that the deterministic scorer also doesn't catch (it walks the same string check pattern).

In practice the request also wouldn't function (AWS won't grant), so this is LOW. Flag because it's the kind of thing that's free to fix and shows up in penetration tests.

**Fix**: NFKC-normalize the action string BEFORE the wildcard scan: `import unicodedata; action_norm = unicodedata.normalize("NFKC", action)`. NFKC folds full-width chars to ASCII so `＊` → `*`. Then the existing `"*" in` check catches it.

---

## WB11-12 — LOW — `_seed_local_user` writes admin email straight into YAML f-string (YAML injection if `$USER` is poisoned)

**Location**: `local_server._seed_local_user` lines 142–155.

```python
contents = f"""\
...
  - id: {user_id}
    display_name: "Local admin ({admin_email})"
"""
```

If `$USER` env contains a `"` or newline (unusual on conventional Unix but reachable in container env / Windows / `env USER='evil"\nfoo' iam-jit init-solo`), the produced YAML can be malformed or, worse, inject an extra YAML key. The downstream FileUserStore validates against `users.schema.json`, so the poisoned YAML would fail-closed at load (no RCE), but the symptom for the user is "iam-jit serve --local crashes for no reason."

**Fix**: use a YAML emitter (ruamel.yaml — already a dep) instead of an f-string. That's also more readable. Same fix for `_seed_local_accounts` (line 184, lower risk because boto3 returns a 12-digit account_id which is digits-only).

---

## WB11-13 — LOW — `_seed_local_accounts` placeholder `account_id="000000000000"` lands in real provisioner ARN

**Location**: `local_server._seed_local_accounts` lines 172–197.

When boto3 fails (offline laptop, no AWS creds, expired session), the function logs a warning and writes `account_id: "000000000000"` plus `provisioner_role_arn: "arn:aws:iam::000000000000:role/iam-jit-local-provisioner"` into accounts.yaml. The user might never re-run `init-solo` after fixing their AWS creds — the placeholder stays. Subsequent grants would target account `000000000000`, which provisioning rejects (`AccountNotFound`-equivalent at AWS side), but the request can still be accepted, scored, and (depending on score + threshold) auto-approved. Audit chain shows a "successfully auto-approved" event for an account that doesn't exist.

LOW because provisioning will fail-closed at AWS, but the muddied audit chain hurts operations triage.

**Fix**: when boto3 fails, write the accounts.yaml with `enabled: false` and a banner `notes: "Edit account_id before enabling — boto3 could not auto-detect."` Also: print a louder warning at startup if any account has `account_id == "000000000000"`.

---

## WB11-14 — LOW — `cli.py` defines `serve` twice; the first definition (with `--users-file --reload`) is dead code

**Location**: `cli.py` lines 198–244 (first `serve`) and lines 556–610 (second `serve`).

Click overrides command registration by name. The second `@main.command("serve")` (the local-mode wrapper) silently shadows the first. Effect: the older `--users-file` and `--reload` flags are unreachable. Users following older docs (`iam-jit serve --users-file users.yaml`) hit a "no such option" error.

This is a maintenance bug, not a security finding — except that **the `--users-file` flag was the documented escape hatch for local-dev users to point at a file-mode user store**. Losing it means every local-dev install now goes through `init-solo` / `serve --local`'s auto-bootstrap, which carries the WB11-03/04 risks above.

**Fix**: rename the new command to `@main.command("serve-local")` (matching the `serve --local` UX it replaces, but as its own subcommand — no shadow). Or fold the `--local` flag into the existing `serve` definition and keep `--users-file` / `--reload`.

---

## WB11-15 — INFO — `slack_mock` retains `bot_token` in `SlackCall.bot_token`; logging the calls list leaks the token

**Location**: `_test_support/slack_mock.py` `_record` lines 83–96; `SlackCall` dataclass line 41.

The mock records the raw bearer token from the inbound `Authorization` header into `SlackCall.bot_token` and keeps it in `server.calls`. If a test logs `server.calls` or asserts on a `SlackCall` repr, the token lands in test output / CI logs.

The mock is `_test_support/`-prefixed and not mounted by `app.py` (verified by full-repo grep). The standalone runner (`dev-slack-mock`) defaults to `127.0.0.1`. The risk is exclusively "test output of an iam-jit dev who points the bot at the mock with a real-shaped bot token." INFO because it's a dev-time-only, opt-in surface.

**Fix**: store a hash of the token (`sha256(token)[:16]`) instead of the raw value. Tests can still assert "saw a token" and "the same bot was used across calls" without retaining the raw value.

---

## WB11-16 — INFO — `dev-slack-mock` `--host` accepts arbitrary bind address (same shape as WB11-08, but with a mock server)

**Location**: `cli.py` `dev_slack_mock` lines 729–732.

Same `--host` foot-gun as WB11-08, but for the mock. Risk is much smaller — the mock has no AWS creds, no admin token, and accepts ALL bot tokens (line 27 of slack_mock.py: "any bot_token is accepted"). The worst outcome is a network attacker can post forged "Slack" responses to a victim's iam-jit-bot-pointed-at-the-mock — which only matters if the victim is testing real bot behavior against the mock, in which case they are intentionally pointing at it.

**Fix**: same as WB11-08 — refuse non-loopback `--host` unless explicit opt-in.

---

## WB11-17 — INFO — `auto_approve.evaluate` raises `TypeError` if `effective_threshold=None` and `settings.auto_approve_risk_below=None`

**Location**: `auto_approve.py` lines 168–189.

```python
threshold = (
    effective_threshold
    if effective_threshold is not None
    else settings.auto_approve_risk_below
)
...
if analysis_score >= threshold:
```

If both are None (auto-approve disabled at deployment AND caller doesn't pass `effective_threshold`), `threshold` is None and `analysis_score >= None` raises `TypeError`. In practice the routes always pass a non-None `effective_threshold` (from `auto_approve_threshold_for(...)` which returns ints 2/4/5/9), so this is unreachable today. Flagging because a future direct caller of `auto_approve.evaluate` could trip it.

**Fix**: explicit guard at line 188 — `if threshold is None: return AutoApproveDecision(False, "feature_disabled", {...})`. Defense-in-depth.

---

## WB11-18 — INFO — `safety_mode.resolve_mode` accepts `session_override` parameter but no route plumbs it from API params

**Location**: `safety_mode.py` lines 92–134; `routes/requests.py` lines 319, 524 (calls `resolve_mode_for_accounts` without `session_override`).

The resolver supports `session_override` as the highest-priority knob for "CLI flag / API param" mode selection per the docstring. No route passes it. Effect: a feature documented in the resolver is not user-reachable. Not a security finding (the absence of the knob is fail-safe), but a doc/code drift to be aware of.

**Fix**: either remove `session_override` until a route consumes it (avoid documenting unbuilt features), OR add a `safety_mode` body field to `/preview` + `/submit` that's passed through. If added, server must clamp it to be at-least-as-strict as the deployment + per-account (the WB11-01 fix applies here too).

---

## Summary

Eighteen findings against the round-11 delta. The headline regressions: (a) the per-account `safety_mode_override` resolver lets account owners DOWNGRADE a strict deployment default (WB11-01) — breaks the platform-team-floor model in the inverse direction of the WB10-02 floor-clamp fix; (b) the strict-mode wildcard gate ignores `NotAction`, leaving the more-dangerous escalation primitive uncovered (WB11-02); (c) the local-mode bearer token has both a write-then-chmod race AND is echoed to stdout (WB11-03 + WB11-04), giving a credential that bridges to AWS multiple persistence-after-process-death surfaces; (d) the new `mfa_gate` and `self_approve_reductions` modules are implemented + tested but not wired into any route (WB11-05 + WB11-06), so the documented Layer C MFA promise + the solo-mode admin-shortcut promise are both no-ops today. Priority ship order: WB11-03/04 (token leakage on default `iam-jit serve --local`), WB11-01 (silent strict downgrade), WB11-02 (NotAction escalation), then wire up the no-op gates (WB11-05/06). The remaining MEDs (WB11-07/08/09/10) and LOWs (WB11-11/12/13/14) are smaller blast-radius but cheap to close before the launch-week traffic spike. WB11-15/16/17/18 are documentation-or-future-consumer landmines that should be addressed but don't block launch.
