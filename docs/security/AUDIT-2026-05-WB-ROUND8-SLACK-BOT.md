# iam-jit white-box appsec audit — round 8 (Slack approval bot, 2026-05-15)

Scope: the freshly landed Slack approval-bot surface and ONLY that surface.

In scope:

- `src/iam_jit/slack_bot.py`
- `src/iam_jit/routes/slack.py`
- `infrastructure/slack/iam-jit-slack-app-manifest.yaml`
- `docs/recipes/SLACK-APP-SETUP.md`
- The fire-and-forget `slack_bot.post_approval_message(...)` hook in
  `src/iam_jit/routes/requests.py` (lines 590–609).

Findings keyed `WB8-NN`.

**Headline: 1 HIGH, 3 MED, 2 LOW, 1 INFO (7 total).**

The signature-verification primitive itself is solid (raw-body HMAC,
`hmac.compare_digest`, 300s replay window, explicit timestamp parse,
explicit empty-signature reject). All HIGH/CRIT-class probes against
that primitive came back clean (see "Probes that came back clean" at
the end).

The HIGH is **WB8-01: Block Kit injection via `spec.description`**.
The user-controlled `description` is interpolated raw into a Slack
`mrkdwn` block, which means the requester can inject `<@USLACKBOT>`,
`<!channel>`, `<!here>`, `<!subteam^…>`, and fake-URL forms
`<https://attacker.example/|Approve in iam-jit>` into the approval
card that approvers see. This is a social-engineering primitive
aimed at the people whose clicks are the *entire* authorization
boundary of the bot. Worth fixing before launch.

---

## Findings

### WB8-01 — Block Kit / mrkdwn injection via `spec.description` (HIGH)

**File:** `src/iam_jit/slack_bot.py:163,187` (and 197 for `risk_factors`)

`render_approval_message` does:

```python
description = spec.get("description") or "(no description)"
...
{"type": "section", "text": {"type": "mrkdwn", "text": f"*Reason*\n{description}"}},
```

`description` is user-supplied (the requester's free-text "why I need
this access" field) and is interpolated into a `mrkdwn` block with
zero sanitization. Slack `mrkdwn` parses several control sequences
that an attacker can use to influence approvers visually and
behaviorally:

| Sequence | Effect |
|---|---|
| `<@USLACKBOT>` / `<@U…>` | Renders as `@SlackBot` (or another user) and **pings them** (notification) |
| `<!channel>` / `<!here>` | Pings the whole channel / online members |
| `<!subteam^S012ABC\|@oncall>` | Pings a user group, e.g. `@oncall` |
| `<https://evil.example\|Click here to APPROVE>` | Renders as the link text only; approver sees a trusted-looking label that points to an attacker site |
| `*text*`, `_text_`, `` `text` `` | Bold / italic / code |

`risk_factors` (line 191) has the same shape — each factor is rendered
as `• {f}` into mrkdwn. `risk_factors` is produced by the iam-jit
scorer (not directly user-supplied), but it can echo strings derived
from the policy (action names, resource ARNs, statement IDs). If any
of those can carry attacker-influenced text (e.g. a customer-managed
policy with an action like `<!channel>:*`), the same injection
applies.

**Attack scenario A (social engineering with fake link):**
Requester submits a request with
`description = "Need read access. <https://attacker.example/approve?req=XYZ|Click to approve in iam-jit>"`.
Slack renders only the link text "Click to approve in iam-jit", which
is indistinguishable from the legitimate "View in iam-jit" button.
Approver clicks the rendered hyperlink, lands on attacker site, which
phishes their iam-jit creds OR launches a same-session approval via
an open browser tab.

**Attack scenario B (channel-storm):**
`description = "Routine prod debug. <!channel>"`. The approval card
pings everyone in the approval channel — abuse of approvers' attention,
and effectively a "is anyone actually reading these" probe. Repeated
enough times, approvers will rubber-stamp future requests.

**Attack scenario C (impersonate Slackbot):**
`description = "<@USLACKBOT> approves this request automatically."`
Slack renders the bot's user mention with its real name, and a hurried
approver may infer that something already cleared the request.

**Repro hint:**

```python
from iam_jit.slack_bot import render_approval_message
msg = render_approval_message({
    "id": "req-test",
    "spec": {
        "description": "<!channel> URGENT — <https://attacker.example|Approve here>",
        "access_type": "rw",
        "duration": {"duration_hours": 1},
        "accounts": ["123456789012"],
    },
    "status": {"owner": "mallory@example.com"},
    "review": {"risk_score": 7, "risk_factors": []},
})
# The mrkdwn block for *Reason* now contains the raw control sequences,
# which Slack will render as a @channel ping and a hyperlinked label.
```

**Suggested fix:** Either (a) escape mrkdwn control characters in any
user-derived string before interpolation — replace `<`, `>`, `&`
with their HTML-entity equivalents (Slack's documented sanitization
rule), OR (b) render `description` as `plain_text` instead of
`mrkdwn` (a `section.text` block can be `plain_text`). Plain-text
escaping is the safer default because it also handles `*`/`_`/`` ` ``.
Apply the same fix to each `risk_factor` line.

Add a unit test that asserts a description containing `<!channel>`
and `<@U123>` renders to a block whose `text.text` does NOT contain
those raw sequences.

---

### WB8-02 — Ambiguous `slack_user_id` explicit mapping resolves to first-match (MED)

**File:** `src/iam_jit/slack_bot.py:634–647`

`ApproverResolver._try_explicit_mapping` iterates `users_store.list()`
and returns the FIRST user whose `slack_user_id` attr equals the
clicker's Slack user ID. There is no uniqueness check and no
deterministic ordering — `users_store.list()` ordering is
storage-backend-dependent (DDB scan: arbitrary; in-memory: insertion).

**Attack scenario:** A deployment admin (or an attacker who has
compromised the admin's session enough to edit a user record but not
enough to add an approver role) sets `slack_user_id = "U_TARGET"` on
their OWN user record that happens to carry the `approver` role. Now
every Slack click from `U_TARGET` resolves to the attacker's iam-jit
user, not the legitimate one — silent identity hijack of clicks.

Sister scenario: a careless admin sets the same `slack_user_id` on
two user records (e.g. while migrating). Whichever the store returns
first wins, with no warning logged.

**Repro hint:** Create two `User` objects, both carrying the same
`slack_user_id = "UABC"`, only one has `approver` role. Wire them
into a store with both orderings. Call `resolver.resolve("UABC")`.
The result differs based on order — and silently picks the
non-approver in one of the orderings, raising `UserNotApprover` even
though a legitimate approver exists.

**Suggested fix:** In `_try_explicit_mapping`, collect ALL matches
into a list. If more than one matches, log an error and `raise
UserNotApprover("ambiguous slack_user_id mapping")` — refusing the
action is safer than picking arbitrarily. Document this constraint in
the User-store schema docs.

---

### WB8-03 — No `team_id` / workspace binding on interactive payload (MED)

**File:** `src/iam_jit/routes/slack.py:67–78`; `src/iam_jit/slack_bot.py:98–137`

The signature verifier authenticates "this body was HMAC'd with our
signing secret" but does not bind to a Slack workspace ID. The
interactive payload includes `team.id` and `enterprise.id` (when
Enterprise Grid), but the route never compares those to a configured
workspace ID.

**Attack scenario:** The signing secret is reused (intentionally or by
accident) across two Slack workspaces of the same customer (e.g.
"dev" and "prod" Slack workspaces, or a fork-of-the-app). A user in
workspace A — who is NOT an approver in workspace B — can have their
clicks accepted as if they came from workspace B, **as long as their
Slack user ID happens to match an approver mapping in iam-jit**.
The first failure mode is mostly a misconfiguration risk; the more
realistic risk is that during workspace migration the operator runs
both workspaces in parallel for a window.

This is also defense-in-depth against the (theoretical) case where
Slack ever exposes the signing secret to multiple apps in a workspace.

**Suggested fix:** Add `IAM_JIT_SLACK_TEAM_ID` (optional). When set,
`slack_interactive` must reject any payload whose top-level
`team.id` doesn't match. Same applies to `view_submission`. This
also closes the hypothetical "attacker forwards our signed payload to
a different workspace install of the bot" loop.

---

### WB8-04 — No verification that the click originated from the configured approval channel (MED)

**File:** `src/iam_jit/routes/slack.py` (entire `slack_interactive` flow)

The route never inspects `payload.channel.id`. The bot posts approval
cards only to `IAM_JIT_SLACK_APPROVAL_CHANNEL`, so legitimate clicks
should only come from that channel. A click from any OTHER channel
indicates one of:

- Someone forwarded/copied the message structure to another channel
  via a manual `chat.postMessage` (requires admin/bot-token-equiv).
- A workspace admin copy-pasted Block Kit JSON into Block Kit
  Builder, posted it manually with our `action_id`s, and a non-
  approver in that channel clicked it.
- A future feature accidentally posts to additional channels.

In none of these is iam-jit's authorization actually bypassed (the
approver-role check still runs), but accepting clicks from arbitrary
channels widens the attack surface for social engineering, narrows
the audit trail's value ("the approval came from #wrong-channel"),
and breaks the operator's mental model.

**Suggested fix:** Add a strict-mode env var
`IAM_JIT_SLACK_STRICT_CHANNEL=true` that rejects clicks whose
`payload.channel.id` does not equal `approval_channel`. Log a
warning when it doesn't match even in non-strict mode. Add the
channel ID to the audit `extra` dict on success.

---

### WB8-05 — Synchronous `httpx.post` inside async submit-request handler (LOW)

**File:** `src/iam_jit/routes/requests.py:600`; `src/iam_jit/slack_bot.py:494–501`

`post_approval_message` is called inside the async `submit_request`
handler. `HttpxSlackClient.post_json` uses synchronous `httpx.post`
with `timeout=10.0`. Under Lambda this is fine (single concurrent
request per container), but under a long-running ASGI server (the
self-hosted path) every submit blocks an event-loop worker for up
to 10s on Slack-side slowness. This is not exploitable as a DoS
amplifier (the attacker would need to already have submit-request
permission), but it is a self-DoS waiting to happen the first time
Slack has a regional incident.

**Suggested fix:** Either (a) move the post off the request path
(e.g. enqueue, post in background task), or (b) make
`post_approval_message` `async` and use `httpx.AsyncClient`. Document
the Lambda-only assumption if (a)/(b) are deferred.

---

### WB8-06 — Slack-profile-email trust assumes verified workspace emails (LOW)

**File:** `src/iam_jit/slack_bot.py:559–584` + `649–659`

`resolve_slack_user_to_email` returns the `profile.email` from
`users.info` without any "is this email verified?" check. In
mainstream Slack workspaces, profile emails are verified by Slack at
account-creation time, so this is safe in the common case. Two edge
cases weaken that assumption:

1. **Single-channel / multi-channel guests and Slack Connect users**:
   admins can set arbitrary profile emails for guests in some plans.
   If a guest's email is set to `alice@company.com` and Alice is an
   iam-jit approver, the guest can approve as Alice (the explicit
   `slack_user_id` mapping path is not used in this scenario).

2. **Email aliasing**: `Alice@example.com` vs `alice@example.com`
   are normalized via `.lower()` on the Slack-side string, but the
   iam-jit `User.id` is `email:<email>` — if the user-store key was
   created with mixed case, the lookup misses. Not exploitable but
   fragile.

**Attack scenario:** Workspace admin (or compromised workspace admin
account) onboards a Slack Connect guest with `profile.email` set to
an iam-jit approver's email. The guest clicks Approve. The bot
treats them as the approver. Slack does not require email
verification for externally-shared / guest accounts in all tiers.

**Suggested fix:** Document in `SLACK-APP-SETUP.md` that the
deployment SHOULD prefer the explicit `slack_user_id` mapping for
approvers and SHOULD NOT rely on email-only resolution in workspaces
with guests or Slack Connect. Optionally: check
`profile.email_verified` if Slack exposes it (it does on Business+
plans via `users.info`), and fall through to "unresolvable" when
absent or false.

---

### WB8-07 — `private_metadata` is only as trusted as the signing secret (INFO)

**File:** `src/iam_jit/slack_bot.py:336–394`

`parse_view_submission` reads `view.private_metadata` as the
`request_id`. The current model trusts this because the entire
payload is HMAC-signed by Slack with our signing secret. That trust
is correct *given* the signature check, but two notes worth pinning:

1. If the signing secret is ever rotated incorrectly (e.g. old + new
   accepted simultaneously to ease rotation), an attacker with the
   old secret can forge a `view_submission` with any
   `private_metadata` and trigger `request_changes` on any
   request_id whose state allows the transition.

2. `private_metadata` is not bound to the clicker — there is no
   `(clicker_slack_user_id, request_id)` pair signed at modal-open
   time. So an attacker who can submit modals (i.e. who has the
   signing secret) can submit a modal "as if" they were any Slack
   user. Mitigated entirely by the signing-secret confidentiality
   and by the downstream approver check.

**Suggested fix:** (defense-in-depth) include a short HMAC-tagged
binding in `private_metadata` like `{request_id}.{hmac(request_id +
clicker_user_id, modal_secret)}` so that even a leaked signing
secret can't be used to submit a modal as someone else without ALSO
guessing the clicker_user_id. This is a luxury hardening — track but
don't ship pre-launch.

---

## Probes that came back clean (and why)

These are the items the prompt asked me to specifically probe. None
warranted a finding:

- **Signature-verify primitive itself (`slack_bot.py:98–137`)** — uses
  `hmac.compare_digest` over the full digest, raw-body bytes are
  taken before any decoding, empty/missing signature is explicitly
  rejected, non-integer timestamp is rejected, the replay window
  uses `abs(current - ts_int)` which closes both future and past
  skew. No length-extension applicable (HMAC, not raw SHA). No
  prefix-length check that could leak structure before
  `compare_digest`. **CLEAN.**

- **Raw body integrity through Starlette** — `await request.body()`
  returns the original bytes (Starlette does not decode/re-encode
  for form-urlencoded content unless `request.form()` is called,
  which we never do until AFTER signature verify). **CLEAN.**

- **Multiple `X-Slack-Signature` headers** — Starlette's
  `Headers.get()` returns the first value. Slack only sends one.
  An attacker could send two headers but the verifier sees only the
  first, which must validly HMAC the body. **CLEAN.**

- **Replay-within-window across different request_ids** — replays
  within 300s ARE possible, but each replay carries the same
  `payload` (same `request_id`, same `verb`). The lifecycle state
  machine rejects the second transition (already approved/rejected),
  and downstream `request_store.put` is idempotent. The audit log
  will record the duplicate attempt. **CLEAN.**

- **Modal `callback_id` smuggling from a different Slack app** — a
  different Slack app's modal submission is signed with that app's
  signing secret, not ours. The HMAC check rejects it before
  `callback_id` is ever read. **CLEAN.**

- **Modal `callback_id` smuggling within our own app** — only our
  code calls `views.open` with `callback_id =
  iamjit_request_changes_modal`. We have no other modal type. Even
  if we add one later, the strict equality check on `callback_id`
  is the right guard. **CLEAN (for now — keep the check strict).**

- **TOCTOU between `request_store.get` and `request_store.put`** —
  the lifecycle state machine inside `apply_transition` is the
  authority on legal transitions. If two approvers click at the same
  time, the second `apply_transition` raises `IllegalTransition`,
  which the route handles cleanly via `_ephemeral_reply`. If two
  approvers race PAST `apply_transition` and both call
  `request_store.put`, last-writer-wins on the persisted blob, but
  the in-memory `req` carries the appended audit history from
  whichever `apply_transition` ran second — i.e. the loss is
  bounded to "we forget one of the two duplicate transition
  attempts," which is the same behavior the web API has. Not a
  Slack-bot-specific issue. **CLEAN.**

- **Stale `trigger_id`** — `views.open` returns `{ok: false, error:
  "expired_trigger_id"}` after 3s. The route wraps `open_modal` in
  try/except and surfaces an ephemeral "Slack rejected our
  views.open call" reply. No state mutation, no leaked detail.
  **CLEAN.**

- **Fire-and-forget post in `routes/requests.py`** — the broad
  `except Exception` swallows any failure with a warning log. The
  request was already persisted at `store.put(metadata["id"], req)`
  on line 588, so a Slack failure cannot leave the request in an
  inconsistent state. The only risk is observability (the requester
  has no in-product signal that approvers weren't notified), but
  that is a UX bug not a security finding. **CLEAN.**

---

## Blast-radius reference: leaked credentials

Included because the prompt asked for it (item 10).

**`IAM_JIT_SLACK_SIGNING_SECRET` leaked, bot token intact:**
attacker can forge ANY interactive payload, including button clicks
and view-submissions, as any Slack user ID they choose. They cannot
post messages or read user info. Authorization gate is then the
iam-jit user store: if the attacker can pick a `slack_user_id` whose
mapped iam-jit user has the `approver` role, they get approver
power. **CATASTROPHIC.** This is the single most important secret
in the bot surface — protect it like a root API key.

**`IAM_JIT_SLACK_BOT_TOKEN` leaked, signing secret intact:**
attacker can post arbitrary messages as the bot (impersonate the bot
in any channel it's in) and call `users.info` (PII exposure: every
Slack user's email). They CANNOT forge interactive callbacks (the
signature secret is separate). **HIGH** for spoofing and PII;
**not directly catastrophic** for IAM authorization.

**Both leaked:** full control — can post a fake approval card,
forge clicks on it, get any iam-jit request approved as any
approver. **CATASTROPHIC.**

**Recommended mitigations:**

1. Store both secrets in AWS Secrets Manager (not env), with rotation
   playbooks documented in `SLACK-APP-SETUP.md`.
2. Add a runtime KMS-encrypted env wrapper if Secrets Manager is too
   heavy for the customer (already an option for other iam-jit
   secrets).
3. Document that if EITHER secret is suspected leaked, the operator
   should rotate it in Slack's app-config immediately AND audit all
   transitions made via `channel: slack` in the audit log for the
   leak window.
4. Add an operator alert (Phase-2 follow-up) that fires on
   `verify_signature` failure rate > N/min — a brute-force attempt
   should show up as 401s.

---

End of round 8.
