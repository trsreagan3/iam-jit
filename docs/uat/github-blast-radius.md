# GitHub JIT-token blast-radius UAT (the hard gate)

The hermetic unit/route tests prove iam-jit *requests* the right scope and
never mints on a high-risk request. This UAT proves the part that actually
contains the blast radius: **GitHub enforces the scope server-side.** A token
scoped to repo A / `contents:read` must be unable to write A, unable to touch
repo B, and dead the instant it is revoked — regardless of what the holder
(an infected machine or agent) tries.

This is the incident that motivated the feature: a malicious skill held a
broad, standing GitHub token and infected every PR of every repo it could
reach. A scoped, ≤1h, revocable token shrinks that to "one repo, one
permission, one hour."

## One-time setup (a throwaway test org)

1. Create a test GitHub org (or use an existing sandbox). Create two empty
   repos in it, e.g. `iam-jit-uat-a` (in-scope) and `iam-jit-uat-b`
   (out-of-scope). Put at least one file in each so `GET contents/` returns
   200 for a working token.
2. Create a **GitHub App** in the org (Settings → Developer settings → GitHub
   Apps → New). Permissions: **Repository contents: Read & write** (the App's
   *maximum* — iam-jit mints tokens that are a SUBSET of this). No webhook
   needed. Generate and download a **private key** (`.pem`).
3. **Install** the App on the org and grant it access to **both** test repos.
   Note the **installation id** (in the install URL:
   `.../installations/<INSTALLATION_ID>`) and the **App id** (App settings).

## Run

```bash
export IAM_JIT_GH_UAT=1
export IAM_JIT_GH_UAT_APP_ID=123456
export IAM_JIT_GH_UAT_INSTALLATION_ID=98765432
export IAM_JIT_GH_UAT_PRIVATE_KEY_PATH=/secure/path/app.private-key.pem
export IAM_JIT_GH_UAT_OWNER=my-test-org
export IAM_JIT_GH_UAT_REPO_IN_SCOPE=iam-jit-uat-a
export IAM_JIT_GH_UAT_REPO_OUT_OF_SCOPE=iam-jit-uat-b

pytest tests/test_github_blast_radius_uat.py -v
```

Without `IAM_JIT_GH_UAT=1` (and all vars set) the suite **skips** — CI stays
hermetic.

## The matrix (every row is GitHub enforcing, not iam-jit)

| # | Token scope | Action attempted | Expect |
|---|-------------|------------------|--------|
| 1 | repo A, `contents:read` | `GET /repos/owner/A/contents/` | **200** ✅ |
| 2 | repo A, `contents:read` | `PUT .../A/contents/probe.txt` (write) | **403/404** ❌ |
| 3 | repo A, `contents:read` | `GET /repos/owner/B/contents/` | **404** ❌ |
| 4 | repo A, `contents:read` | read A **after** `DELETE /installation/token` | **401** ❌ |

Row 2 proves the *permission* boundary (a read token can't write). Row 3
proves the *repository* boundary (the token is invisible to repos outside its
scope — GitHub returns 404, not 403, so the token can't even confirm B
exists). Row 4 proves early revocation works (independent of the ≤1h TTL).

## Post-TTL (manual / optional)

The ≤1h expiry is enforced by GitHub's `expires_at` on the token; it is not
worth a 60-minute test in CI. To spot-check: mint a token, wait past
`expires_at`, and confirm a read returns **401**. The `expire_stale()` sweep
in `github_requests.py` drops the local record's token at that point so the
UI never shows an expired grant as live.

## End-to-end through serve (optional)

To exercise the full product path (not just the provisioner):

1. `iam-jit github connect --org my-test-org --app-id 123456
   --installation-id 98765432 --private-key-path app.private-key.pem`
2. Start `iam-jit serve --local`, open `/github`.
3. Submit repo A / `pull_requests:write` → auto-issues (low risk); copy the
   one-time token and run row 1/2/3 against it.
4. Submit 30 repos / `contents:write` → queued (high risk), **no token
   minted**. Approve as an admin → token issued. Revoke from the dashboard →
   confirm row 4.
