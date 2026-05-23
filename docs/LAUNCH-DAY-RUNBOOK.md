# Launch-day runbook

> **SUPERSEDED tier framing 2026-05-23**: per
> `project_oss_only_launch_decision.md`, v1.0 ships fully free + open
> source. References below to "Pro-tier LLM" / "free-tier" are
> HISTORICAL DESIGN CONTEXT only — any LLM behavior at v1.0 is
> agent-delegated per `[[bouncer-zero-llm-when-agent-in-loop]]` (the
> agent in the loop uses its own credentials).

What to watch for and what to do in the first 72 hours after a
public launch. Pairs with `LAUNCH-PLAN.md` (strategic sequencing)
and `PRODUCTION-READINESS.md` (deployment posture).

## The dashboard you tail for the first 48 hours

In rough order of "what would actually break first":

1. **Lambda concurrent executions** (CloudWatch metric
   `AWS/Lambda ConcurrentExecutions` on the iam-jit function).
   - Default account quota: 1,000 concurrent. Burst limit varies
     by region but typically 500–3,000 from zero.
   - **Trigger:** if concurrent execution > 80% of quota for 5+
     min, raise an account-quota increase request *now* (Service
     Quotas Console; takes 1-24h depending on region).
   - **Symptom upstream:** API consumers see 429 / 503; CI Action
     jobs time out.

2. **Lambda throttles** (`AWS/Lambda Throttles`).
   - Should be 0. Non-zero = you crossed the burst limit.
   - **Action:** increase reserved concurrency, OR
     `aws lambda put-function-concurrency` to raise the cap.

3. **DynamoDB ThrottledRequests** per iam-jit table.
   - Most relevant tables under launch traffic:
     `iam-jit-magic-link-nonces-*` (every magic-link consume),
     `iam-jit-session-revocation-*` (every authenticated request),
     `iam-jit-bans-*` (every authenticated request).
   - **Trigger:** any non-zero count for 5+ min.
   - **Action:** they're on-demand mode by default — switch to
     provisioned with auto-scaling if throttles persist past the
     warm-up period (DDB's adaptive capacity learns within 15min).

4. **SES bounce / complaint rate** (SES Reputation dashboard).
   - **Hard cap:** 5% bounce rate, 0.1% complaint rate. Hit
     either and AWS suspends sending.
   - **Watch:** every signup spike means magic-link emails. If
     bot signups are hitting iam-jit with random emails, you'll
     bounce them all to the void → reputation tanks fast.
   - **Action if rising:** tighten the magic-link per-IP rate
     limit (`IAM_JIT_MAGIC_LINK_IP_SOFT_CAP=3` instead of 5);
     consider a Cloudflare Turnstile / hCaptcha in front of the
     magic-link form. Pre-pre-launch: keep the SES sender in
     sandbox mode and only allow-list verified addresses.

5. **CloudWatch log ingestion** (`AWS/Logs IncomingBytes` on the
   Lambda log group).
   - CloudWatch ingest is the most expensive AWS line item on a
     verbose-logging deployment. At launch verbose paths
     (signature failure, prompt-injection detection, audit
     events) can ingest faster than you expect.
   - **Trigger:** ingest > $X/day where X is your comfort
     threshold.
   - **Action:** filter `INFO`-level logs at the source via
     `IAM_JIT_LOG_LEVEL=WARNING` and rely on alarms to surface
     errors.

6. **Stripe webhook failure rate** (Stripe Dashboard → Developers
   → Webhooks).
   - A pile of `signature verification failed` 400s = either
     someone is probing the endpoint OR your webhook secret
     rotated and a deploy wasn't propagated.
   - **Action:** rotate the webhook secret + redeploy if you
     suspect it leaked; double-check the route in Stripe matches
     the deployed Function URL / ALB host.

## The runbook for "the site went down"

Step 0: don't panic. iam-jit is stateless except for DynamoDB; the
worst-case is a 10-minute downtime, not data loss.

1. **`aws logs tail /aws/lambda/iam-jit --follow`** — find the
   actual error class.

2. **If it's a Python `ImportError` or startup `Exception`** — a
   bad deploy. Roll back: `aws lambda update-function-code
   --function-name iam-jit --s3-bucket ... --s3-key
   <previous-version>`. The S3 deploy bucket has versioning by
   default; the previous version is one CLI call away.

3. **If it's `ProvisionedThroughputExceededException`** — DDB
   throttle. Wait 15 min (adaptive capacity), or flip the table
   to provisioned: `aws dynamodb update-table --table-name X
   --billing-mode PROVISIONED --provisioned-throughput
   ReadCapacityUnits=100,WriteCapacityUnits=50`.

4. **If it's `TooManyRequestsException` on Stripe API** — Stripe
   rate-limited. Implement exponential backoff (round-3 BB3-05
   surface fixed the upstream replay loop; this is the same
   class). For now: reduce webhook retry storm by ensuring the
   route returns 200 on duplicate (already does).

5. **If it's `ThrottlingException` on Bedrock** — the standalone-
   mode LLM path is rate-limited. Per-model RPM is the hard ceiling.
   Drop to deterministic-only for affected requests via
   `IAM_JIT_LLM=none` until the throttle clears. (Local-dev mode is
   agent-delegated per `[[bouncer-zero-llm-when-agent-in-loop]]` —
   this throttle only affects standalone deployments.)

6. **If you can't tell what's wrong** — the security_posture
   admin endpoint at `/api/v1/admin/security-posture` returns a
   posture report including a `recent_errors` field with the
   last 20 unique exception classes. Faster than CloudWatch
   Insights for the first triage pass.

## The "we're being attacked" decision tree

iam-jit's launch surface has been adversarially audited (rounds
1-4 BB+WB). The defenses below are real. But sudden traffic that
doesn't match expected shapes is the signal:

- **Sudden spike of /api/v1/auth/magic-link** — the round-3 fix
  caps at 5 req/min/IP (`IAM_JIT_MAGIC_LINK_IP_SOFT_CAP`).
  Verify the spike is hitting that cap; if so, the limiter is
  working and there's nothing to do except keep watching.
  Tighten to 2/min if SES bounces start rising.

- **Sudden spike of /api/v1/score from one ASN** — the limiter
  caps at 30 req/min/IP. Same logic: if it's hitting 429, the
  limiter is working. If it's somehow getting past the limiter,
  check the trusted-proxy CIDR config (`IAM_JIT_TRUSTED_PROXY_
  CIDRS`) — wrong config can make the limiter key on the proxy
  IP not the real client.

- **Stripe webhook with weird signatures** — somebody is
  probing for the secret. The round-3 BB3-04 closure means they
  can't fingerprint the failure mode; they'll go away. If
  persistent, rotate the webhook secret (Stripe Dashboard →
  Webhooks → Roll Signing Secret) and redeploy.

- **POST /tokens flood from one authenticated user** — the per-
  user token cap (`IAM_JIT_API_TOKEN_CAP_PER_USER`, default 50)
  returns 429 after the cap. Check that the cap is actually
  configured. If they're a paying customer who legitimately needs
  more, raise the cap for the deployment.

- **`/logout` followed by continued auth from a saved cookie** —
  the round-3 session-revocation closure should refuse. If a
  cookie is still working after logout, the revocation store is
  broken; check `IAM_JIT_SESSION_REVOCATION_TABLE` is set and the
  Lambda role has `dynamodb:PutItem` + `GetItem` on the table.

## When to file a customer-bug-bounty payout

iam-jit doesn't have a paid bug bounty yet (post-launch goal),
but the disclosure path matters from day 1. A real bypass should:

1. Get fixed within 72h of confirmation.
2. Become a new pinned audit test in `tests/test_appsec_audit_
   round{N}_{bb,wb}.py`.
3. Get its own commit in the audit-closure log.
4. Get credited in `docs/security/AUDIT-2026-05-*.md`.

If the reporter wants a payout, mark them as priority #1 in the
informal-bounty rolodex until the funded program ships.

## The "we shipped" social-media checklist

Once the launch traffic stabilizes (~6h post-go-live):

1. Tail the dashboards above; if green for 6h, you're stable.
2. Post the Show HN thread.
3. Post the LinkedIn announcement.
4. Send the prepared DM to the 10 friendly devs from the
   LAUNCH-PLAN list.
5. Bank a stress-test screenshot for the post-launch blog post.

Do all of these as separate actions; if step 2 breaks something,
step 5 stays cancelable.
