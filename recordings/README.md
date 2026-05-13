# iam-jit walkthrough recordings

Every video in `output/` is the corresponding script in `scripts/`,
captured against a freshly-booted `iam-jit serve` with seed users
(admin, approver, dev) and one registered destination account.

## Generate / regenerate

```bash
.venv/bin/python recordings/run_all.py
# or
make recordings
```

The runner boots iam-jit on a free port, runs every scenario in the
order below, then tears down and converts each `.webm` to `.mp4`
using Playwright's bundled ffmpeg.

## What's recorded (in playback order)

| # | File | Feature |
|---|------|---------|
| 01 | `01-matrix-theme-tour.{webm,mp4}` | Matrix UI theme — dashboard, /all, network posture, provisioned grants, rediscover, tokens |
| 02 | `02-submit-request-paste-mode.{webm,mp4}` | Dev pastes a JSON policy, submits |
| 03 | `03-all-requests-page.{webm,mp4}` | The previously-broken /all link, now showing every state |
| 04 | `04-approver-approves.{webm,mp4}` | Approver opens queue, reviews, approves → state=active |
| 05 | `05-admin-provisioned-grants.{webm,mp4}` | Admin sees the active IAM grant in the local store |
| 06 | `06-admin-revoke-active-grant.{webm,mp4}` | Admin force-revokes an active grant before expiry |
| 07 | `07-admin-cross-account-rediscover.{webm,mp4}` | Cross-account scan + reconciliation report |
| 08 | `08-admin-add-user.{webm,mp4}` | POST /api/v1/users (json-api surface — no dedicated UI yet) |
| 09 | `09-admin-disable-user.{webm,mp4}` | PATCH a user to enabled=false |
| 10 | `10-admin-network-posture.{webm,mp4}` | Source-IP allowlist status + recommendations |
| 11 | `11-admin-bans-and-unban.{webm,mp4}` | List current bans + the unban call shape |
| 12 | `12-prompt-injection-auto-ban.{webm,mp4}` | Bad-actor submits an injection-laden request, auto-banned |
| 13 | `13-api-token-lifecycle.{webm,mp4}` | Mint a bearer token from the UI, then revoke it |

## Watching them

```bash
# Pick one to open immediately
open recordings/output/01-matrix-theme-tour.mp4

# Or batch-play every mp4 in order
ls recordings/output/*.mp4 | sort | xargs -I {} open {}
```

The mp4 versions are H.264 + yuv420p so they play in QuickTime,
Slack drag-drop, browser, and most other places. The webm originals
are kept alongside; mp4 is just the convenience copy.

## Why scripts and not pre-recorded mp4s in git

iam-jit's UI evolves; pre-recorded videos go stale fast. The scripts
ARE in git; the videos are gitignored. After any UI change, re-run
the runner to refresh.

## Troubleshooting

- **A script fails / shows blank video**: open the relevant `.webm`
  to see what state the page was in. The library catches
  exceptions and writes the error to `document.title` so the title
  bar in the recording shows the diagnostic.
- **`Couldn't connect to 127.0.0.1`**: the runner picks a free port
  but if iam-jit fails to start, the scripts fail one-by-one. Check
  the runner's stderr for the uvicorn error.
- **Empty videos**: ensure `IAM_JIT_LLM=none` is set (default in the
  runner) so the chat surface doesn't try to hit a non-existent LLM.
