# Slack Approval Bot — setup runbook

Wire the iam-jit approval flow into a Slack channel so approvers can
click Approve / Reject inline (no separate web UI required for the
common case). Setup is **~10 minutes** end-to-end.

## What you'll have when this is done

- iam-jit posts a Block Kit approval card to a configured Slack
  channel whenever a request needs human review
- Approvers click Approve / Reject in the channel — clicks are
  signed-request authenticated and only members of iam-jit's
  `approver` (or `admin`) role can act
- The channel message updates in-place to show who acted
- Audit row records `channel=slack` + the approver's Slack user_id

## Prerequisites

- Slack workspace where you can install Apps (Workspace Admin or a
  user the admin granted "Install App" permission)
- iam-jit deployed at a stable HTTPS URL (Slack rejects HTTP / IPs)
- iam-jit Users registered with the same emails as the Slack users
  who will be approving — the bot resolves Slack-user → email →
  iam-jit User

---

## Step 1 — create the Slack App from the manifest

1. Open https://api.slack.com/apps and click **Create New App**
2. Choose **From an app manifest**
3. Pick your workspace
4. Paste the contents of
   [`infrastructure/slack/iam-jit-slack-app-manifest.yaml`](../../infrastructure/slack/iam-jit-slack-app-manifest.yaml)
5. **Edit the manifest before submitting** — replace `YOUR_IAM_JIT_HOST`
   with your actual iam-jit hostname (e.g. `iam-jit.internal.acme.com`)
6. Click **Create**

You now have an App with the right scopes, bot user, and
interactivity config. The remaining manual steps are the bits Slack
doesn't let manifests automate.

## Step 2 — install the App to your workspace

1. In the App config sidebar, click **Install App**
2. Click **Install to Workspace**
3. Approve the OAuth scopes prompt
4. **Copy the "Bot User OAuth Token"** (starts with `xoxb-…`) — this
   is `IAM_JIT_SLACK_BOT_TOKEN`

## Step 3 — copy the Signing Secret

1. In the App config sidebar, click **Basic Information**
2. Under **App Credentials**, click **Show** next to "Signing Secret"
3. **Copy the Signing Secret** — this is `IAM_JIT_SLACK_SIGNING_SECRET`

## Step 4 — pick (or create) the approval channel

In Slack: pick the channel where approvals will be posted. Common
names: `#access-approvals`, `#iam-jit`, `#access-requests`.

Then:

1. In Slack, type `/invite @iam-jit` in that channel (replace
   `@iam-jit` with whatever display name you gave the bot in the
   manifest)
2. Right-click the channel name and **Copy link** — the channel ID
   is the bit after `/archives/`, looks like `C0A1B2C3D4E`
3. That channel ID is `IAM_JIT_SLACK_APPROVAL_CHANNEL`

(Optional — if you set `chat:write.public` in the manifest, the bot
can post to any public channel without being invited. We still
recommend inviting it so the bot's presence is visible to channel
members.)

## Step 5 — set iam-jit env vars

Add to your SAM deployment parameters (or whatever config layer your
self-host uses):

```bash
sam deploy \
  --parameter-overrides \
      SlackBotToken=xoxb-YOUR-TOKEN-HERE \
      SlackSigningSecret=YOUR-SIGNING-SECRET-HERE \
      SlackApprovalChannel=C0A1B2C3D4E \
      # … your other params …
```

Or, equivalently, in the Lambda environment:

```
IAM_JIT_SLACK_BOT_TOKEN=xoxb-…
IAM_JIT_SLACK_SIGNING_SECRET=…
IAM_JIT_SLACK_APPROVAL_CHANNEL=C0A1B2C3D4E
```

**Treat both the bot token and the signing secret as secrets** — they
should live in AWS Secrets Manager / your secrets-management tool
of choice, not in plaintext env vars committed to git. The SAM
template references them via `SecretsManager:secret-arn:SecretString:key`
syntax.

## Step 6 — smoke test

Submit a request that you know will route to approval (score over
the auto-approve threshold).

Expected:

1. Approval card appears in `#access-approvals` within a second or
   two of the request hitting `pending` state
2. Click **Approve** as a user whose email matches a registered
   iam-jit User with `approver` role
3. The channel message updates in-place: "Request rq-… approved by
   <@U…>"
4. iam-jit's web UI shows the request moved to `provisioning` (then
   `active` once the role provisions)

If you don't see the approval card:

- Confirm the bot is in the channel (`/invite @iam-jit`)
- Confirm `IAM_JIT_SLACK_APPROVAL_CHANNEL` matches the channel ID,
  not the channel name
- Check the Lambda logs for `iam_jit.slack_bot` and
  `iam_jit.notifications` messages

If a click returns "You don't have the approver role":

- Confirm the clicking Slack user's email matches an iam-jit User
- Confirm that iam-jit User has `approver` (or `admin`) in their
  `roles` list
- Confirm the bot has `users:read.email` scope (manifest does set
  it, but re-check in the OAuth & Permissions page if you edited
  the manifest)

If a click returns 401 or "invalid signature":

- The signing secret on iam-jit doesn't match what Slack signs with.
  Re-copy from the App's Basic Information page; re-deploy.

If Slack itself says "didn't get a 200 from your endpoint":

- iam-jit's Interactive Components URL is wrong. Slack will surface
  the failed request in the App's **Interactive Components**
  diagnostics page

## Security notes

- **Signing-secret leak** is the worst case: an attacker who has it
  can forge approval clicks. Treat it like an admin password.
  Rotate at least annually (Slack supports rotation under Basic
  Information → App Credentials).
- **Bot-token leak** lets an attacker post messages as the bot.
  They cannot approve their own requests (the click verification
  comes from the SLACK USER, not the bot). Still, rotate if leaked.
- **Slack User authentication** is the load-bearing piece — anyone
  who can convince Slack they're user X can act as user X in
  iam-jit. Make sure your Slack workspace has 2FA enforced for
  approvers.
- **Replay window**: iam-jit accepts signed requests up to 300
  seconds old (Slack's documented max). Older clicks are rejected
  with 401.
- **Authorization gate**: the same `lifecycle.apply_transition` the
  web UI uses runs for Slack clicks. There is no parallel approval
  code path. State-machine rules, self-approval ban, and audit
  emission are all single-sourced.

## Optional: per-route channel routing

For deployments with high approval volume, route different request
types to different channels via the per-account LLM policy mechanism
(see DEPLOYMENT.md Step 5.6) — same idea, but for routing instead
of LLM toggling. Implementation lives in `slack_bot.post_approval_message`
which accepts a `channel=` override per call.

## Health check

iam-jit ships `iam-jit doctor slack` (when available) — runs through
the Slack config end-to-end:

```bash
iam-jit doctor slack
# Output (happy path):
#   ✓ IAM_JIT_SLACK_BOT_TOKEN present
#   ✓ IAM_JIT_SLACK_SIGNING_SECRET present
#   ✓ IAM_JIT_SLACK_APPROVAL_CHANNEL present
#   ✓ auth.test → workspace iam-jit-ws
#   ✓ chat.postMessage to C0A1B2C3D4E → OK
#   ✓ users:read.email scope present
```

If the doctor command isn't available yet, smoke-test by submitting
a real request as described in Step 6.

## Related docs

- `docs/DEPLOYMENT.md` — Step 5.6 covers Slack config alongside the
  pilot deployment profile
- `docs/recipes/AGENT-IAMJIT-HOOP-EXAMPLES.md` — Slack approval bot
  integrates seamlessly with the Hoop session-credential-rotation
  recipe; engineers see iam-jit approval cards in the same channel
  Hoop's own approvals go to today
