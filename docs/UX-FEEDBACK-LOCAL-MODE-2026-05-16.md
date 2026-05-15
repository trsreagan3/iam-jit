# UX Feedback: iam-jit local mode — first-time install
Date: 2026-05-16
Simulated by: round-10-uxsim agent

## First impressions (README + recipe)

The README pitch is strong. "Don't give Claude your AWS keys" is a real
fear for anyone who has thought about agents + AWS, and it's the first
line. The three-mode table makes the "local" lane explicit and gives a
clear "is this the one I want?" answer in ~10 seconds. The
read-only-by-default framing in the "Why this exists" block is the
single best sentence for converting a skeptic, and it's above the fold.

The "90 seconds" claim is bold. I'd believe it from the README — `pip
install` + one `serve --local` + one `mcp install-claude-code` reads
like genuinely two minutes including the pip download.

The admin-safety recipe is well-organized: who-it's-for at the top,
what-you'll-have, install, behavioral contract, example flow, audit
log, attack table, an unusually honest "what it does NOT protect
against" section. The "what it does NOT protect against" section is
*the* trust unlock — naming standing-credentials and prompt-injection
limits up front makes the rest believable.

Two things that would make a skeptic continue rather than bounce: the
attack table (Without iam-jit / With iam-jit), and the 247-grants
audit-log mockup that distinguishes reads from writes. Both make the
abstract value concrete.

Confusing bits I noticed:
- "MCP endpoint: http://localhost:8765/mcp" in the recipe and README
  vs the server's own log line which says "stdio-based; see iam-jit
  mcp-server". Two different transport stories in two different
  places — am I getting an HTTP MCP endpoint or a stdio bridge? As a
  new user I cannot tell.
- The recipe references `iam-jit mcp install-claude-code`,
  `iam-jit audit tail`, `iam-jit mcp list`, `iam-jit account set`,
  and a config file at `~/.iam-jit/config.yaml` — none of these are
  verified in this test. If any are missing on the real CLI, the "90
  second" walkthrough quietly breaks at step 3.
- The recipe's audit log path is `~/.iam-jit/audit.db` but the actual
  local-mode boot logs `Audit log: <data-dir>/audit.db (when SQLite
  store ships)` — i.e. it doesn't exist yet. That's a meaningful gap
  between doc-promise and shipped-behavior.

## Install + first run

What the user actually executed:

```
.venv/bin/python -m iam_jit.cli serve --local \
  --data-dir /tmp/iam-jit-test-uxsim --port 8770
curl http://127.0.0.1:8770/healthz
# -> {"status":"ok","version":"0.0.1"}
```

Time from "start command" to "200 on /healthz": ~5 seconds. Genuinely
fast. The 90-second pitch survives.

The startup banner is good:

```
iam-jit local mode
  Data dir: /tmp/iam-jit-test-uxsim
  Admin user: email:reagan@reagans-MacBook-Air.local
  Audit log: /tmp/iam-jit-test-uxsim/audit.db (when SQLite store ships)
  Requests:  /tmp/iam-jit-test-uxsim/requests

  Listening on http://127.0.0.1:8770
  MCP endpoint: http://127.0.0.1:8770/mcp (stdio-based; see iam-jit mcp-server)
```

Filesystem layout after boot is tidy:

```
/tmp/iam-jit-test-uxsim/
  accounts.yaml      (528 bytes, mode 600)
  users.yaml         (363 bytes, mode 600)
  requests/          (empty dir)
```

Files are mode-600. Good. YAML is human-readable and has a header
comment naming its purpose. A solo dev can `cat` either file and
understand it. That's a strong signal that the local-mode mental model
is "this is a normal directory you own", not "magic SaaS that happens
to live on localhost".

The score API works as advertised:

```
POST /api/v1/score  {s3:GetObject *}      -> score 7 (high)
POST /api/v1/score  {s3:DeleteObject *}   -> score 8 (high)
```

Risk factors and suggestions are returned with actionable text. Sub-
100ms responses. This part of the product *feels* shipped.

## What worked

- **`pip install` → server up → healthz green** is a real ~5-second
  flow. The 90-second promise survives even including reading the
  banner.
- **The startup banner**. Tells me where my data lives, what user I
  am, where to look for the audit log, and how to stop the server.
  Four of the five questions a first-time admin has.
- **Filesystem layout is unsurprising**. Two YAMLs and a requests
  dir; both YAMLs have inline comments explaining themselves. Mode
  600. I can `cat` and `vim` everything; nothing is in a binary blob
  or SQLite store I'd need a separate tool to read.
- **boto3 fallback was graceful**. The empty-credentials case did
  not crash — the banner printed one clean warning ("Could not
  resolve AWS account from default credentials: ... Accounts file
  will use a placeholder") and the server came up with a placeholder
  `000000000000` account. As a tire-kicker without real AWS keys, I
  could still exercise the scoring path. Big UX win.
- **`/api/v1/score` is fully usable with no setup**. Returned scores,
  factors, suggestions, the policy_fingerprint, and the
  llm_skip_reason. That last field is unusual — most APIs hide that
  the LLM lane was skipped; iam-jit telling me "tier_does_not_use_llm"
  is the kind of plumbing-honesty that builds trust.
- **`/docs` (FastAPI auto-OpenAPI) returns 200**. A casual user can
  browse the whole API surface without grepping source.
- **The recipe's honesty section** (what it does NOT protect against)
  is the single most trust-building paragraph in the whole doc set.

## What didn't (with severity)

### S1 — high

- **`POST /api/v1/requests` returns 500 with body
  `{"detail":"user_store is not configured"}`.** The flagship action
  in local mode — issue a per-task grant — does not work end-to-end
  out of the box. `/healthz` and `/score` are green, but the actual
  "give me scoped creds" path 500s on the first call. As a first-
  time user following the recipe's "example flow" I would think I
  had installed it wrong, then look harder, then maybe bounce.
  - The error message is also confusing: I *am* the user
    (`users.yaml` was auto-created with me in it as admin), so
    "user_store is not configured" looks like an internal
    consistency error, not a user-actionable one. A solo dev cannot
    self-diagnose this.
  - Suggested fix: either (a) wire up the user_store on
    `serve --local` boot so the obvious-happy-path works, or (b)
    return a 4xx with a clear "local mode does not yet support
    /api/v1/requests; use MCP via `iam-jit mcp install-claude-code`"
    message.

- **Audit log doesn't exist yet but the banner and the recipe both
  promise it.** Banner says "Audit log: .../audit.db (when SQLite
  store ships)". The recipe shows `open http://localhost:8765/admin`
  for browsing the audit log, plus a 247-grant weekly summary
  mockup. None of that exists. A first-time user who reads the recipe
  and then can't find any of it will lose trust fast — even though
  the rest of the product is honest.
  - Suggested fix: gate the recipe sections behind a "(coming in
    v0.1)" tag, OR add a `--no-audit` flag that explicitly disables
    the feature with a banner line, OR ship the minimum SQLite
    writer for grants. "Honest about not-yet-shipped" beats "promise
    in docs, missing at runtime" every time.

### S2 — medium

- **Admin email `email:reagan@reagans-MacBook-Air.local` is weird.**
  It's auto-generated from the macOS hostname. As a UX line it works
  for "you are admin of your own machine", but it doesn't feel like
  an email — it's a contrived `local` TLD. Two concerns:
  - Looks unprofessional in a log a teammate might read over my
    shoulder.
  - If I later upgrade to hosted SaaS and want to migrate this user
    record, the email format won't match anything real.
  - Suggested fix: default to `local-admin@iam-jit.local` (cleaner
    canonical form) and surface a one-line "If you'd like to set a
    real email for cross-mode migration, edit users.yaml or run
    `iam-jit user set-email ...`".

- **MCP endpoint story is contradictory.** Banner: "MCP endpoint:
  http://127.0.0.1:8770/mcp (stdio-based; see iam-jit mcp-server)".
  Both transports in one sentence. The recipe and README also mention
  the HTTP-style URL. A new user cannot tell if they need to point
  Claude Code at the HTTP URL or run a separate stdio bridge.
  - Suggested fix: pick one. If stdio, drop the HTTP URL entirely
    and print `MCP transport: stdio (run iam-jit mcp-server)`. If
    HTTP, drop the parenthetical. The combination teaches no one.

- **Recipe references CLI commands not tested here**: `iam-jit
  mcp install-claude-code`, `iam-jit mcp list`, `iam-jit audit
  tail`, `iam-jit account set ... --safety-mode strict`. If any are
  unshipped, the "90 second" walkthrough silently breaks at step 3
  with a `command not found` and a user has no recovery path.
  - Suggested fix: a single `iam-jit --check` command that verifies
    all CLI commands referenced by the canonical recipe actually
    exist + prints status. CI gate on the recipe.

### S3 — low

- **`GET /` returns 303 with no body.** I'm redirected to who-knows-
  where; a first-time user pokes `/` to see if there's a landing
  page and gets nothing visible.
- **`GET /admin` 404s.** The recipe says `open
  http://localhost:8765/admin`. Same audit-log-doesn't-ship problem,
  but specifically a broken link a user *will* try.
- **No `/api/v1/` index.** A user exploring the API has to find
  `/docs` (FastAPI Swagger) or `/openapi.json` themselves. A two-
  line plain-text "/" landing page with "see /docs for API" would
  remove the dead end.
- **Server log says `INFO: 127.0.0.1:64870 - "GET /healthz"` etc.
  in uvicorn-default format.** Fine, but the iam-jit banner is
  multi-line and the uvicorn logs are single-line: visually
  inconsistent. Minor.

## Recommendations

Ranked by impact-per-effort.

1. **Make `POST /api/v1/requests` succeed on local-mode boot.** This
   is the demo. The 90-second pitch ends with "Claude requests a
   grant"; if that path 500s with `user_store is not configured`,
   the product feels broken. Either wire user_store automatically
   in local mode, or return a clear 4xx pointing to the MCP path.
2. **Reconcile the audit-log story.** Pick: ship a minimal SQLite
   writer now (just append-only JSON rows of every score + request),
   or remove the audit-log promises from the recipe + banner. The
   gap between "247-grant weekly summary mockup in the docs" and
   "audit.db doesn't exist" is the most trust-eroding mismatch in
   the whole experience.
3. **Recipe CI**: add a CI job that boots local mode, walks every
   command in the canonical recipe, and fails the build if any
   step doesn't work. Stops doc-drift cold.
4. **Pick one MCP transport** in the banner + docs. Drop the
   confusing parenthetical.
5. **Friendlier admin identity** — `local-admin@iam-jit.local` or
   even just `local-admin` (no email shape at all).
6. **`GET /` should return a one-screen welcome** with links to
   `/docs`, `/healthz`, and a "next step: install MCP into Claude
   Code" command.

## Would I trust this enough to actually use?

Honest answer: **not yet, but very close.**

What would tip me over:

- The `POST /api/v1/requests` path works end-to-end with the
  placeholder account on first boot — even if it just returns a
  mock STS response with `"ACCESS_KEY":"MOCK..."` for testing,
  the flow has to be exercisable without real AWS keys.
- The audit log actually exists. Even a minimal append-only JSONL
  at `<data-dir>/audit.jsonl` would be enough — I want to see what
  Claude did. The recipe sells the audit log as the #1 trust
  artifact ("a weekly audit log showing exactly what Claude
  touched"); I need to see it.
- A `iam-jit doctor` or `iam-jit --check` command that
  pre-flight-validates: AWS creds resolvable? Account ID known?
  MCP transport reachable? `requests/` writable? Audit store
  writable? One command, ten checks, green/red per line. Cheap
  to build, hugely trust-building.
- One real end-to-end recorded demo (the comic-strip format
  already in the project's plan would be ideal) showing a Claude
  session that requests a grant, hits the read-only/write
  elevation moment, and shows the audit row that resulted.

What's *already* there that earns trust:

- The startup banner naming where data lives.
- File-mode 600 on the auto-created YAMLs.
- The graceful boto3-missing fallback.
- The "what it does NOT protect against" section in the recipe —
  this is the single biggest trust signal in the entire doc set.
- The score API working out of the box, including honesty about
  `llm_skip_reason: tier_does_not_use_llm`.
- The /docs OpenAPI surface being browsable.

Net: the foundation feels real. The 90-second promise is real for
boot + score. It is **not** real for the full request lifecycle,
which is the actual flagship. Close the request-lifecycle and
audit-log gaps and this is a ship-worthy v0.1 for solo devs.
