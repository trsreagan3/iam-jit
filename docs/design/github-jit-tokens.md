# iam-jit for GitHub — JIT scoped GitHub tokens

**Status:** planned (2026-06-05). **Trigger:** a malicious skill with a broad
standing GitHub token infected *every PR of every repo it had access to* — the
canonical agent blast-radius / supply-chain failure.

**Thesis:** an AI agent should receive a GitHub credential scoped to *this
task* (these repos, these permissions), valid ~1 hour, then gone — and every
call it makes with that credential is audited and boundable. "Infect every
repo" becomes structurally impossible because the agent never had access to the
others.

---

## Goal & threat model

**Goal:** automated provisioning of **scoped, short-TTL** GitHub tokens for
agents/machines, so that when one is compromised the **blast radius is small** —
in repos, in permissions, and in time. Replace the standing broad PAT (the thing
that let the malicious skill hit *every* repo) with a per-task token that
expires.

**What this contains (the win):**
- *Lateral spread* — an infected agent with a token for repo X **cannot** touch
  repo Y (GitHub rejects it server-side). "Infect every repo" is impossible.
- *Permission spread* — a `pull_requests`-only token can't rewrite `contents` or
  CI `workflows`.
- *Persistence* — the token dies at TTL (~1h); a stolen token is useless after.
- *Theft window* — exfiltrated creds are scope- + time-bounded.

**What it does NOT contain (be honest — these need the other layers):**
- *Damage inside the granted scope during the TTL.* If the task legitimately
  needs `contents:write` on repo X, an infected agent can still push bad code to
  repo X within the window. → mitigated by (a) the **scorer** keeping grants
  minimal + denying over-broad scopes, (b) **human approval** for high-risk
  scopes, (c) the **optional bouncer** (audit / anomaly / dynamic-deny within
  scope), (d) short TTL shrinking the window.
- *Infected-at-request-time.* If the agent is already compromised when it
  *requests* scope, it could ask for a broad one. → the **deterministic scorer +
  auto-approve thresholds + human approval** are load-bearing here: a malicious
  broad request (e.g. `contents:write` × all repos) scores high → not
  auto-approved → flagged for a human. This is why the scorer is core, not
  optional.

**Non-goals:** this is not branch protection, not secret-scanning, not code
review. It is least-privilege + TTL for the *credential* an agent holds.

## The control is the scoped token — works with ZERO bouncers

The blast-radius containment comes from the **token's scope, enforced by GitHub
server-side**. A skill handed a 1h token for repo X *cannot* touch repo Y —
GitHub rejects it — regardless of whether any bouncer is running. So this is a
**standalone iam-jit issuer**; it does NOT depend on gbounce or any bouncer
(same independence principle as iam-jit ↔ ibounce). The malicious-skill incident
is contained by the token alone.

- **Core (standalone): the JIT issuer.** Mint short-lived, task-scoped GitHub
  tokens. Primitive = **GitHub App installation access tokens** (natively ≤1h,
  down-scopable to a subset of repos + permissions, revocable; the same
  mechanism Actions/Dependabot use — **scalable**: cheap on-demand minting,
  per-installation rate limits 5k–15k/hr, installs per-org for multi-tenant).
  No role-creation dance like AWS.

- **Optional layer: the bouncer (gbounce).** Because the GitHub API is HTTPS,
  routing an agent's `gh`/HTTPS-git/REST/GraphQL through gbounce *additionally*
  gives OCSF audit, dynamic-deny, anomaly detection (cross-repo write burst),
  flight-recorder, and the "bouncer holds the token" property. **Strictly
  additive defense-in-depth + observability — never required for the security
  guarantee.** This is the only place transport matters (and SSH-git, which
  doesn't use tokens, is simply out of scope).

---

## Mapping (iam-jit AWS → GitHub) — reuse the existing architecture

| AWS today | GitHub equivalent |
|---|---|
| account in `accounts.yaml` | GitHub org + App **installation** (`installation_id`) |
| provisioner role (assume w/ external-id) — the one-time bootstrap | the **iam-jit GitHub App** an org admin installs once |
| `provisioning_mode: classic_iam` | NEW `provisioning_mode: github_app` |
| IAM policy = grant scope | `{repositories: [...], permissions: {contents, pull_requests, …}}` |
| create role + assume → STS creds | `POST /app/installations/{id}/access_tokens` (repo+perm subset) → 1h token |
| `GET /requests/{id}/assume` → role_arn + external_id | → the scoped installation token (or a handle; see "bouncer holds the token") |
| `review.analyze_policy` → risk 1–10 | NEW `analyze_github_scope` → risk 1–10 |
| revoke role | `DELETE /installation/token` |

The grant **lifecycle** (`lifecycle.py`: submit → approve/auto-approve →
provisioning → active → revoke/expire) is already provisioning-backend-agnostic.
GitHub is a new **provisioner backend** behind the same lifecycle + the same
serve API (`POST /requests`, `/approve`, `/assume`, `/revoke`) + the same
auto-approve evaluator.

---

## Product boundary (keep these separate)

**This feature ships entirely in iam-jit** (the issuer/provisioner) — repo
`iam-jit`, no bouncer dependency, usable on its own. iam-jit is a separate
product from the bouncers; the GitHub work must not couple to them. The
*optional* gbounce GitHub audit/gate is a **separate change in a separate
product** (`gbounce`), additive, and is listed below only so the boundary is
explicit — it is not part of shipping this feature.

## iam-jit seams (named, so this is executable)

- **`accounts_store.py`** — add `"github_app"` to `provisioning_mode`; add
  GitHub-installation fields (`github_app_id`, `installation_id`, `org`).
- **`onboarding.py`** — accept `github_app`; add an `iam-jit github connect`
  flow that records the App + installation (the GitHub analog of seeding
  `accounts.yaml`).
- **`provision.py`** — add `GitHubAppProvisioner` behind the existing provisioner
  interface (where `classic_iam` / `identity_center` live): authenticate as the
  App (JWT from the App private key) → mint a down-scoped installation token →
  return it; `revoke()` → `DELETE /installation/token`.
- **`review.py`** — add `analyze_github_scope()`, the deterministic GitHub
  permission scorer (see below). Auto-approve reuses `auto_approve_evaluator.py`.
- **serve API** — new request `kind: GitHubTokenRequest` (or a `github`
  provisioning block on the existing RoleRequest). Everything else in the
  lifecycle/API is reused.
- **MCP** — new `github_scope_self_for_task` (mirror of
  `iam_jit_scope_self_for_task`): agent declares `{repos, permissions}` → scored
  → token issued. Plus `submit_github_request`.
(gbounce GitHub support is NOT an iam-jit seam — it's a separate optional change
in the `gbounce` product; see the "Separate, optional" note under Phasing.)

## UI (the iam-jit web UI — `serve`, Jinja templates in `src/iam_jit/templates/`)

The iam-jit web console (admin/approver/requester) must render the GitHub use
case as a first-class peer of AWS — this is iam-jit's OWN UI, distinct from the
gbounce dashboards. The request lifecycle is shared, so the views become
provisioning-backend-aware rather than AWS-only:

- **`accounts.html` / `account_new.html` / `account_detail.html`** — support a
  GitHub "account" (org + App installation): a **`github connect`** page (install
  the iam-jit App / capture `installation_id`), and show installed repos +
  granted App permissions.
- **`all_requests.html` / `queue.html`** — list GitHub token requests alongside
  AWS, with a readable scope summary (e.g. `2 repos · pull_requests:write · 1h`)
  and the risk band.
- **request-detail / approve view** — render the GitHub scope **human-readably**:
  the repos, the permissions (contents/PRs/workflows/…, read vs write), the TTL,
  and the **`analyze_github_scope` risk + the "why"** (e.g. "all-repos
  contents:write = HIGH"). An approver eyeballs this — it must read clearly, not
  as raw JSON. Approve / reject / request-changes reuse the existing flow.
- **`tokens.html` (active grants)** — show issued GitHub tokens: scope, **TTL
  countdown**, and a **revoke** button (→ `DELETE /installation/token`).
- **guided reduction (optional, mirrors the AWS reduction checklist)** — a
  "which repos / permissions do you NOT need?" multi-select that narrows the
  grant before submit; defaults pre-checked to the least-privilege set.
- **token handback in the UI:** if "bouncer holds the token," the UI never shows
  a raw token; if raw-to-agent, a one-time reveal. (Tracks the handback decision.)

**UI tests/UAT (same discipline):** route/template tests render a GitHub request
+ active grant (assert the scope, risk band, TTL, revoke control are present and
correct — not just that HTML returns 200); browser UAT clicks
connect → request → approve → see active grant → revoke, end-to-end against the
real test org+App.

---

## The deterministic GitHub scorer (`analyze_github_scope`)

Risk model over a GitHub permission set, calibrated like the IAM scorer
(a graded corpus of GitHub-scope examples):

- **Breadth:** all repos = high; > N repos = elevated; single repo = low.
- **Permission severity:** `contents:write`, `workflows:write`,
  `administration` = high (these alter code/CI — the supply-chain vector);
  `pull_requests:write` = medium; `*:read` = low.
- The incident scores accordingly: `contents:write` × *all repos* → max risk →
  would **not** auto-approve and would be flagged. A single-repo
  `pull_requests:write` for a code-review task → low → auto-approve.

---

## A differentiator worth designing for: "the bouncer holds the token"

Optional but compelling: the agent never *sees* the token. iam-jit mints it and
hands gbounce a handle; gbounce **injects** the credential on egress to
`api.github.com` and strips it from anything the agent can read. A fully
compromised agent then cannot *exfiltrate* a token it never possessed — only use
it, in-scope, through the audited proxy. This is unique to the issuer+bouncer
combo and is the strongest version of the pitch. Flag as a design choice
(simplest first cut hands the agent the raw token).

---

## Testing & UAT discipline (every phase, along the way)

Per standing discipline: **unit tests (mocked GitHub API) + an independent UAT
that dogfoods against a REAL test GitHub org + App** for each phase — unit-green
≠ works. The headline UAT, repeated/extended each phase, *is the blast-radius
property*:

> A token issued for **repo X / `pull_requests:write`** must: ✅ succeed writing
> a PR on repo X; ❌ be **rejected** pushing `contents` to repo X (ungranted
> permission); ❌ be **rejected** on **repo Y** (ungranted repo); ❌ be
> **rejected after TTL expiry**; ❌ be **rejected after explicit revoke**.

If any of those ❌ cases ever *succeeds*, the feature has failed its reason for
existing — so they are hard UAT gates, not nice-to-haves.

## Phasing (all iam-jit, standalone — no bouncer)

- **Phase 1 — issuer core.** GitHub App + `GitHubAppProvisioner`
  (mint/scope/revoke installation tokens) + `accounts_store` `github_app` mode +
  `iam-jit github connect`. *Delivers the security guarantee on its own.*
  - **Unit:** mocked GitHub App API — JWT mint, down-scope request body
    (repos+perms subset), TTL parse, revoke call, error paths.
  - **UAT (real org+App):** the full blast-radius matrix above (X ✅; X-wrong-perm
    ❌; Y ❌; post-TTL ❌; post-revoke ❌).
  - **UI:** `github connect` page + GitHub account in `account_*.html` (+ route
    test asserting the installation/repos render).
- **Phase 2 — request + scorer + lifecycle.** `GitHubTokenRequest` +
  `analyze_github_scope` + serve lifecycle (submit/approve/assume/revoke +
  auto-approve).
  - **Unit:** scorer table (all-repos×`contents:write` = high/not-auto-approve;
    1-repo×`pull_requests:write` = low/auto-approve; `workflows:write` = high) +
    lifecycle state machine.
  - **UAT (real):** submit→auto-approve(low)→assume→use→revoke; submit(high)→
    NOT auto-approved→human approve→assume; calibrate the scorer on a graded
    GitHub-scope corpus.
  - **UI:** GitHub requests in `queue.html`/`all_requests.html` + the
    human-readable scope+risk request-detail/approve view + active grants
    (scope/TTL/revoke) in `tokens.html`. Template tests assert scope/risk/TTL/
    revoke render correctly; browser UAT clicks request→approve→grant→revoke.
- **Phase 3 — agent self-scoping.** MCP `github_scope_self_for_task`.
  - **Unit:** tool schema + scope derivation from `{repos, permissions}`.
  - **UAT (real):** drive the MCP tool end-to-end → agent gets a working scoped
    token, then the blast-radius matrix holds for the token it received.
- **Phase 4 — docs + demo.** The malicious-skill incident as the demo (broad-PAT
  vs JIT side-by-side); add to the real-world-agent-incidents catalog.
  - **UAT:** the demo script runs clean start-to-finish.

**Separate, optional, NOT part of shipping this** (lives in the `gbounce`
product, no iam-jit dependency): gbounce GitHub-aware audit enrichment + bouncer
profile/presets + flight-recorder/compliance wiring. Additive observability +
defense-in-depth for operators who also run the bouncer.

---

## Open decisions (founder)

1. **GitHub App (recommended/required)** — only Apps can programmatically mint
   *down-scoped* short-lived tokens. User-provided fine-grained PATs can't be
   down-scoped per task → weaker. → App.
2. **Token handback:** raw token to the agent (simple) vs. "bouncer holds the
   token" (stronger, agent never sees it). Pick per phase.
3. **SSH-git gap:** only HTTPS git + `gh`/REST/GraphQL are interceptable by
   gbounce; SSH is not. Either document, or require HTTPS remotes for gated repos.
4. **Positioning honesty:** GitHub already ships fine-grained PATs. The
   differentiation is **automated JIT-per-task issuance + the runtime bouncer +
   cross-protocol audit, for agents** — not "fine-grained tokens." The pitch must
   say that or a reviewer dismisses it.
