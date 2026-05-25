# Per-user outstanding-request cap (#613)

*Recipe for tuning the per-user outstanding-request cap that prevents
a rogue or buggy agent from filling the approver queue with
hundreds of pending requests in a tight loop.*

Founder direction 2026-05-25: "each user shouldn't be able to have
more than 20 outstanding submissions/requests at any given time. we
don't want one agent to ddos the whole system."

## What it does

Every `POST /api/v1/requests` and `POST /requests/new/paste` call
checks how many of the caller's requests are currently in `pending`
or `provisioning` state. If the count is at-or-over the cap, the
submission is refused with HTTP 429:

```json
{
  "detail": "user has reached outstanding-request limit",
  "user_id": "email:agent@example.com",
  "outstanding_count": 20,
  "cap": 20,
  "cap_source": "default",
  "recovery_hint": "Wait for some requests to complete or cancel ...",
  "current_outstanding": [
    {"request_id": "abcd1234efgh", "state": "pending", "age_seconds": 42.1},
    ...
  ]
}
```

Terminal states (`active`, `rejected`, `cancelled`, `expired`,
`revoked`, `provisioning_failed`, `needs_changes`) do **not** count.

When the cap fires, iam-jit emits a `request_cap_exceeded` audit
event so the operator-facing audit log surfaces "your iam-jit caught
a runaway agent" as a positive signal.

## Default behavior

Default cap = **20**. No configuration required.

## Knob 1: deployment-wide env var

For deployments that need a different cap globally:

```bash
export IAM_JIT_MAX_OUTSTANDING_PER_USER=50
```

A typo (non-integer, negative) falls through to the default with a
WARN-level log line — never silently disables the cap.

## Knob 2: per-user override in `users.yaml`

For one-off raises (e.g. a CI service-account that legitimately
batches submissions):

```yaml
schema_version: 1
users:
  - id: email:ci-bot@example.com
    roles: [requester]
    outstanding_request_cap: 100   # raise the cap for this user
```

Per-user override wins over the env var. Set to `0` to refuse all
new submissions from a user without disabling them outright (useful
for incident-response: pause a compromised agent without touching
its existing in-flight requests).

## Knob 3: temporary debug-by-env

For incident response, set the env var to a low value to
immediately throttle every user:

```bash
export IAM_JIT_MAX_OUTSTANDING_PER_USER=5
systemctl restart iam-jit  # or your deployment's reload mechanism
```

Per-user overrides still apply on top — so a service account with
`outstanding_request_cap: 100` keeps its cap.

## Verifying the cap is active

```bash
# Submit 25 requests as a test user; the first 20 succeed (201);
# the next 5 return 429.
for i in {1..25}; do
  curl -X POST https://your-iam-jit/api/v1/requests \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" \
    -d @minimal-request.json \
    -o /dev/null -w "%{http_code}\n"
done
```

Then check the audit log:

```bash
iam-jit audit query --kind request_cap_exceeded --since 1h
```

Expected: five `request_cap_exceeded` events with the test user's
ID and `outstanding_count: 20, cap: 20, cap_source: "default"` in
the details.

## Limitations

- The cap is a **denial-of-service guard**, not a security
  boundary. It fails open (returns count=0, allows submission) if
  the request-store backend is unreachable — the store outage will
  surface in the subsequent `store.put()` call regardless.
- The cap is **per-user**, not per-IP or per-account. An attacker
  with multiple user credentials can submit up to `cap × users`
  outstanding requests. Layer this with HTTP-level rate limiting
  at your load balancer / reverse proxy for IP-level guards.
- The cap does not gate edits or comments to existing pending
  requests — only fresh submissions.
