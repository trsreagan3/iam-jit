# UX deep-test: iam-jit local mode (round 2)
Date: 2026-05-16
Round 1 reference: docs/UX-FEEDBACK-LOCAL-MODE-2026-05-16.md
Simulated by: round-11-uxsim agent

## Did the round-1 fixes hold?

- **S1: `POST /api/v1/requests` returned 500 "user_store is not configured" — FIXED.**
  With the bearer token from `cli-token`, `GET /api/v1/users/me` now returns
  the admin profile cleanly, and a properly-shaped `POST /api/v1/requests`
  succeeds with HTTP 201, scores=1, and a server-stamped id. The flagship
  demo path is no longer broken at first contact.

- **S1: audit-log promise vs reality — FIXED in the banner.**
  The new banner no longer says "Audit log: .../audit.db (when SQLite store
  ships)". The misleading promise is gone. The recipe-side promises (247-grant
  weekly summary, `~/.iam-jit/audit.db`) were not re-checked here but the
  banner-side gap is closed.

- **S2: MCP transport contradiction — FIXED.**
  Banner now reads `To connect Claude Code via MCP (stdio transport):
  iam-jit mcp install-claude-code`. Single transport story, no parenthetical
  cross-reference. Clean.

- **S2: admin email format (`email:reagan@reagans-MacBook-Air.local`) — NOT FIXED.**
  Same hostname-derived id appears in `/users/me`, in the banner, and in
  request metadata after submission. Still cosmetically odd; still a
  migration footgun if the user later moves to hosted SaaS. Round-1
  recommendation (default to `local-admin@iam-jit.local`) still stands.

- **WB11-08 (refuse `--host 0.0.0.0`) — HOLDS.**
  `serve --local --host 0.0.0.0` exits 1 with the right reason: names the
  bearer-token + AWS-bridging exposure, names the alternatives (127.0.0.1,
  ::1, localhost), points multi-machine users at hosted mode. This is one
  of the cleanest CLI refusals I saw across this whole test.

- **`init-solo` flow — SHIPPED + WORKS.**
  Bootstraps `users.yaml` (363B, 0600), `accounts.yaml` (570B, 0600),
  `cli-token` (51B, 0600), and an empty `requests/` dir. Banner is
  identity-aware, walks the next 3 steps, prints the MCP config block
  inline. Good.

- **WB11-10 (capture-file size caps) — SHIPPED.**
  `plan_capture._open_capture` enforces 1 MB / line and 256 MB total
  uncompressed; defensive against bombed `.jsonl.gz` captures.

- **WB11-09 (iam_resource null promotion to `*`) — FIXED.**
  Reader now hard-rejects null/missing iam_resource with a helpful error.
  Confirmed in code; not exercised here because hand-authored capture was
  well-formed.

## What works smoothly

The end-to-end path *exists* now. From `init-solo` to `serve --local`
to `curl /healthz` to `curl /users/me` to scoring a curated dangerous
policy at exactly its expected score (9 in [9,10]) to scoring a curated
safe policy at exactly its expected score (1 in [1,2]) — every step
responded in well under a second, every response shape was JSON, every
authentication failure (no token / malformed token / wrong-case header)
returned a sensible 401 with no traceback leak. The whole loop felt
shipped, in a way it didn't in round 1.

The plan-capture format is a particular bright spot. The spec
(docs/specs/PLAN-CAPTURE-FORMAT.md) is short, has a worked example,
explains the producer/consumer split, and even pre-explains *why*
the iam_jit projection is a sub-block (downstream tools like Datadog
can consume the raw call data without parsing iam-jit's vocabulary).
Hand-authoring 3 lines and feeding them through `read_capture` +
`summarize` worked first try and produced a roll-up that's obviously
the right shape for a recommender to consume. Versioning is explicit
(`iam-jit.dev/plan-capture/v1alpha1`) and the reader checks it.

The auth surface was also surprisingly thoughtful. `/users/me`
returns an `agent_hints` block embedded in the user response —
literally a self-describing API for an agent landing on the server
for the first time. The hints include endpoints for token mint,
structured request submission, conversational intake, list-my-requests,
and assume-role instructions. That's the kind of self-explanatory
surface that lets an agent (Claude Code, etc.) actually wire itself
up without the human having to copy-paste a how-to.

## Rough edges (severity-tagged)

### S1 — high

- **NEW: `POST /api/v1/requests` 500s when `spec.duration` is sent
  as an ISO 8601 string** (e.g. `"PT15M"`). The schema requires
  `duration` to be an object (`{duration_hours: int}` or
  `{not_after: <date-time>}`), but the route handler calls
  `_auto_name(req)` at line 440 BEFORE `_validate_or_400(req)` at
  line 462, and `_auto_name` does
  `(spec.get("duration") or {}).get("duration_hours")` on the
  unvalidated input. With a string, that's `"PT15M".get(...)` →
  `AttributeError: 'str' object has no attribute 'get'` →
  uncaught → generic 500 `{"detail":"internal server error"}`.

  Two distinct sub-bugs:
  1. **Validation order is wrong.** Schema validation must run before
     any handler logic that touches the body, otherwise *any* shape
     the schema disallows can panic the handler. Fix: move
     `_validate_or_400(req)` ABOVE `_auto_name(req)`.
  2. **`_auto_name` should be defensive.** Even after a fix, helper
     functions that reach into nested fields should not crash on a
     non-dict — they should either type-check or wrap in try/except.

  Repro:
  ```
  POST /api/v1/requests
  {"apiVersion":"iam-jit.dev/v1alpha1","kind":"RoleRequest",
   "metadata":{"requester":{"name":"x","email":"x@example.com"}},
   "spec":{"accounts":[{"account_id":"000000000000"}],
           "duration":"PT15M","access_type":"read-only",
           "policy":{"Version":"2012-10-17","Statement":[
             {"Effect":"Allow","Action":"s3:GetObject",
              "Resource":"arn:aws:s3:::x/y"}]}}}
  → 500 {"detail":"internal server error"}
  ```

  Severity rationale: this is the *exact same shape* as the round-1
  bug — a 500 on the canonical demo path, with no actionable user-
  facing message. An agent that reads `agent_hints.submit_request_structured`
  and tries the most-natural human shape for "duration" (an ISO 8601
  string, which is what every other AWS-adjacent API uses) gets a 500.
  The 4xx-vs-500 distinction matters because agents and humans both
  retry-with-different-input on 4xx and bug-report on 5xx.

### S2 — medium

- **Schema vs ergonomics: `spec.duration` is a 1-key object.** Even
  when shaped correctly (`{"duration_hours": 1}`), it's surprising
  that there's no flat `duration_hours` int at the top of `spec`.
  Most operators reading the schema would write `duration: 1` or
  `duration: "PT1H"`; both fail. Consider accepting a string ISO 8601
  duration *as well* (`PT15M`, `P1D`) and normalising server-side —
  the spec already explains its choice but operators won't read the
  spec, they'll read the error.

- **Schema vs ergonomics: `spec.accounts` requires
  `[{"account_id":"..."}]` not `["..."]`.** Same shape surprise:
  even after the apiVersion/kind/metadata/spec envelope is right,
  the natural `["000000000000"]` returns a schema error. Combined
  with the above, getting from "I have a bearer token and a policy
  document" to "I have a successful POST" took four iterations on
  the body shape — and I had access to the schema file. An agent
  without the schema in context will spin.

- **Bearer-header parsing is case-sensitive on the scheme but not
  the header name.** `Authorization: bearer <tok>` (lowercase `bearer`)
  works. `Authorization: Bearer <tok>` works. So does
  `authorization: bearer <tok>`. That's correct per RFC 7235 §2.1
  (scheme is case-insensitive) but it's worth a noting that the
  server's "invalid bearer token format" message for a junk token
  could be more specific (the message is the same for "this isn't
  a valid token format" and "this token doesn't exist"; an attacker
  doesn't need that distinction either way, but a debugger does).

- **`/api/v1/users` (the LIST endpoint) returns the full admin
  user record to any authenticated caller.** Not a real leak in
  local mode (one user, one operator, that operator is also the
  caller) but if local mode ever grows multi-user the listing
  shouldn't include role information by default — a lower-privileged
  requester shouldn't trivially see who the approvers are.

### S3 — low

- **`GET /` still returns 303 with no body** (round-1 finding,
  not addressed). A user pokes `/` to see if there's a landing
  page; gets nothing visible. Two-line plain-text "/" landing
  with "see /docs for API" would close it.

- **Strict-mode flag on `/api/v1/score` is silently accepted but
  invisible in the response.** Sending `safety_mode: "strict"`
  alongside the policy doesn't error and doesn't change any
  response field — strict-mode enforcement fires at request
  *submission*, not at scoring. That's documented behavior, but
  the score response could include an `evaluated_under_safety_mode`
  echo so an operator can confirm the field was at least *seen*.
  As-is, an operator who sets `safety_mode: "strict"` and gets
  back the same score they'd have gotten with `safety_mode:
  "lean_permissive"` will reasonably wonder if the field did
  anything.

- **`POST /api/v1/score` with a 100KB-long ARN trips the
  prompt-injection guard** with HTTP 400 and message
  "Submitted content contains patterns that look like
  prompt-injection attempts." That's actually a *good* outcome
  in isolation — defense-in-depth against capture-via-policy-body
  injection — but the heuristic is firing on raw length, which
  is going to produce false positives (large CloudFormation
  templates, real production policies with many resource ARNs).
  Worth verifying the rule's calibration corpus has examples of
  large-but-benign policies.

- **`/api/v1/users/<some-id>` returns 405 Method Not Allowed
  rather than 404.** The route doesn't exist (only `/users/me`
  and `/users` collection ship), but 405 says "this method
  isn't allowed on this URL" which implies the URL is real.
  404 would be more honest.

- **Server log mixes uvicorn-default single-line `INFO:` lines
  with the multi-line iam-jit banner** (round-1 finding, not
  addressed; cosmetic).

## New issues found

1. **Validation-ordering bug in `submit_request` (high)** — see S1
   above. `routes/requests.py:440` calls `_auto_name` on unvalidated
   input. Code reads:
   ```
   metadata["id"] = _generate_id()
   if not metadata.get("name"):
       metadata["name"] = _auto_name(req)        # ← line 440, pre-validation
   # ... requester stamping ...
   _validate_or_400(req)                         # ← line 462, too late
   ```
   The fix is one line of reordering plus a defensive type-check inside
   `_auto_name`; both should land together so the next handler that
   adds pre-validation logic doesn't reintroduce the same class of bug.

2. **Two surprising schema shapes in a row** (medium) — `accounts: [{"account_id":...}]`
   and `duration: {"duration_hours": ...}`. Either accept the natural
   flat shapes server-side and normalise, OR add a `agent_hints.example_request_body`
   field to `/users/me` showing a complete worked example. Right now
   the agent_hints block tells an agent the URL but not the wire shape.

3. **`/users` LIST endpoint exposes role information by default**
   (low for local mode, medium if/when multi-user lands) — see S2.

4. **Strict-mode field on /score is a no-op** (low) — see S3.

5. **Prompt-injection guard fires on long-but-benign policy bodies**
   (low) — see S3. Likely calibration drift.

## Plan-capture format experience

Hand-authoring three lines (one read, one read, one suspicious
AssumeRole into an admin role) and feeding them through
`read_capture` + `summarize` worked first try, returned exactly
the expected roll-up:

```
{
  "total": 3,
  "by_service": {"s3":1,"ec2":1,"sts":1},
  "by_access_type": {"read-only":2,"admin":1},
  "iam_actions": ["ec2:DescribeInstances","s3:ListBuckets","sts:AssumeRole"],
  "resources_touched": ["*","arn:aws:iam::123456789012:role/admin-emergency"]
}
```

The spec doc (`docs/specs/PLAN-CAPTURE-FORMAT.md`) is short, has a
worked example, names every required field, calls out the privacy
constraints (scrub SecretString/Password/UserData; truncate 4KB+;
never include raw responses for secretsmanager/kms/ssm-securestring),
and is explicit that hand-authoring is sanctioned for tests.
Versioning is explicit. The split between the raw call shape and
the `iam_jit` projection is justified inline. This is one of the
better design specs in the repo.

The reader (`src/iam_jit/plan_capture.py`) is well-commented, has
WB11-09 + WB11-10 closures inline as comments tying back to audit
findings, and the `CapturedCall` dataclass exposes the iam_jit
projection fields directly while keeping the raw dict under `.raw`
for callers that need it. That dataclass shape is exactly what a
recommender wants.

Two rough edges:

- **No producer ships yet, and the spec promises three.** The
  `## Producing a capture file` section names `iam-jit plan-capture`
  HTTP proxy, `iam-jit plan-capture from-boto3`, and hand-authored.
  Only the third works today. A first-time reader of the spec will
  reasonably try `iam-jit plan-capture --help` and find nothing.
  Add a "(coming in #118 / #132)" tag like the round-1 audit log
  recommendation, OR ship a stub that prints "not yet implemented;
  see issue #132".

- **Version negotiation is `v1alpha1` only and the reader's set
  is hardcoded.** That's correct for now but means every published
  capture file from v1alpha1 will need to be re-emitted at v1
  (the spec promises "v1 will follow after the first two production
  captures"). A migration helper that rewrites v1alpha1 → v1 in
  place will be needed; worth flagging now so it's not a surprise.

## Verdict

**Yes — I would use this end-to-end with real Claude + real AWS,
with one precondition: fix the validation-ordering bug.**

Round 1's verdict was "not yet, but very close." Round 2's verdict
is "yes, with one fix." The change is real:

- The flagship `POST /api/v1/requests` path is wired and works.
- The init-solo flow makes "first 90 seconds" actually 90 seconds.
- The 0.0.0.0 refusal is correctly hostile in the right way.
- Auth surface is sensible (401s with sensible messages, no traceback
  leaks, case-insensitive header scheme per RFC).
- Calibrated example policies score exactly where their sidecars
  predict (9 for PassRole-on-star, 1 for s3:GetObject on a
  fully-qualified key). That's the strongest possible signal that
  the scorer's calibration discipline is working.
- agent_hints in `/users/me` is a genuinely novel idea and the
  right one — it's the thing that lets an agent self-bootstrap
  against this server.

What stops me from saying "yes, no caveats":

- The duration-string 500 is the *exact same class of bug* as
  round 1's `user_store is not configured` — an unvalidated input
  reaching a handler that assumes a shape and panicking. If round
  10's audit caught one and round 11's caught more, this is a
  recurring failure mode and probably wants a single test pattern
  ("for every POST endpoint, fuzz the body against the schema and
  assert no 5xx") rather than a one-off fix.

- The schema-shape surprises (`accounts` requires objects, `duration`
  requires an object with one key) cost me four iterations to get
  a successful submission, with the schema file open. An agent
  without the schema in context will fail repeatedly. The agent_hints
  block is so close to solving this — one more field
  (`example_request_body`) would close it.

Net: round-1's bug is closed. Round-2 found one new bug of the same
class and a few cosmetic / ergonomics gaps. The fundamentals are
right. Ship it after the validation fix and a worked-example body
in agent_hints; everything else is polish.
