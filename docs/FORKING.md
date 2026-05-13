# Forking + customizing iam-jit

iam-jit is built to be forked. The deterministic-scoring +
typed-context model handles the median case; the meaningful
value an org gets is from grafting in THEIR specific context —
their k8s clusters, their GitHub orgs, their GCP projects, their
CI runners, their on-call calendar.

This doc covers:

  - the architecture's extension points (where to plug stuff in)
  - the file/module layout so you know where to look
  - concrete examples (k8s, GitHub, GCP)
  - upstreaming vs forking decisions (when to PR back, when to
    keep your customizations local)
  - the testing model so your fork stays maintainable

## High-level architecture

```
                ┌─────────────────────────────────────┐
                │   AWS Lambda (Python 3.12, Mangum)  │
                │  ┌──────────────────────────────┐   │
   POST request │  │  src/iam_jit/                │   │
   ─────────►   │  │   ├─ routes/  (FastAPI)      │   │
   /api/v1/...  │  │   │   ├─ requests.py         │   │
                │  │   │   ├─ auth.py             │   │
                │  │   │   ├─ admin.py            │   │
                │  │   │   └─ ...                 │   │
                │  │   ├─ review.py     ◄────────┐│   │   <- risk scorer
                │  │   ├─ auto_approve.py        ││   │   <- gate logic
                │  │   ├─ settings_store.py      ││   │   <- admin tuning
                │  │   ├─ provision.py           ││   │   <- IAM grant
                │  │   ├─ memory.py              ││   │   <- org context
                │  │   ├─ intake.py              ││   │   <- LLM intake
                │  │   └─ llm.py                 ││   │   <- backend stub
                │  └──────────────────────────────┘│   │
                │                                  │   │
                │   ┌─ DynamoDB                    │   │
                │   │   ├─ iam-jit-requests        │   │
                │   │   ├─ iam-jit-users           │   │
                │   │   ├─ iam-jit-api-tokens      │   │
                │   │   ├─ iam-jit-cidrs           │   │
                │   │   └─ iam-jit-settings        │   │
                │   ├─ S3 state bucket             │   │
                │   └─ ALB / Function URL          │   │
                └─────────────────────────────────────┘
                              │
                              ▼
                ┌────────────────────────────┐
                │   Destination AWS accounts │
                │   (via cross-account       │
                │    iam-jit-provisioner     │
                │    role with SourceArn +   │
                │    sts:ExternalId)         │
                └────────────────────────────┘
```

## Extension points (the cleanest places to hook in)

### 1. Risk scoring — `src/iam_jit/review.py`

The single function `analyze_policy(policy, request, *, backend,
extra_sensitive_services, extra_high_impact_actions)` is the hot
spot. It returns a `ReviewAnalysis` dataclass with score +
factors + suggestions + (optional) LLM narrative.

**Fork patterns for risk scoring:**

  - **Add a new score axis** — read additional signals from
    `request` (e.g. `request['metadata']['k8s_cluster']`) and
    raise the score when the cluster is "prod". One-function
    change in `_deterministic`.

  - **Plug in an external policy engine** — replace the
    deterministic block with a call to OPA, Cedar, or your
    in-house policy-as-code system. Keep the
    `ReviewAnalysis` return shape so the rest of the app
    doesn't notice.

  - **Add a non-LLM advisor** — add a function that consults
    your CMDB (e.g. ServiceNow), an internal "criticality"
    database, etc., and surfaces additional risk factors in
    the analysis. Idempotent + cached.

### 2. Auto-approve gates — `src/iam_jit/auto_approve.py`

The `evaluate(...)` function runs four gates in order. To add
a new gate (e.g. "block if the requester's GitHub team isn't
on the project's CODEOWNERS"):

  - Add a new check between existing gates
  - Read from `request` + your custom store/API
  - Return `AutoApproveDecision(auto_approve=False, reason="...", details=...)`
  - Add tests in `tests/test_auto_approve.py`

The gate ordering matters — force-review-style gates run first
(deny-side wins), allow-side gates run after (subject to
upstream floor checks).

### 3. Provisioning — `src/iam_jit/provision.py`

The `provision(request, *, accounts_store, sts_client,
iam_client_factory)` function does the actual cross-account
role creation. To support different provisioning modes (e.g.
GCP service-account creation, k8s RoleBinding):

  - Read `request['spec']['provisioning']['mode']` — already
    supports `classic_iam` and `identity_center`
  - Dispatch to a new module e.g. `provision_gcp.py` for
    `mode: gcp_service_account`
  - The dispatcher returns a `ProvisioningResult` (role_arn,
    assumer_principal_arn, expires_at, etc.); for non-AWS
    targets, set role_arn to a stable identifier (the GCP SA
    email, the k8s SA name) and let the assume flow use
    that.

### 4. LLM intake — `src/iam_jit/intake.py`

Conversational policy-from-description. Already supports
multiple backends (none, ollama, anthropic, bedrock). To plug
in something more domain-specific:

  - Implement `LLMBackend` Protocol in `llm.py`
  - Add a new SAM parameter `LLMBackend=your-backend`
  - Wire it into the factory in `app.py`

A typical fork: add a backend that's a thin shim around your
internal LLM gateway, with your org's prompt-injection guards
and content filters baked in.

### 5. Memory / org context — `src/iam_jit/memory.py`

Stores admin-curated org context that the LLM intake uses to
disambiguate ("when the requester mentions 'analytics', they
probably mean the redshift cluster, not the S3 buckets").

**Fork patterns for memory:**

  - Replace the DDB-backed store with one that reads from
    your wiki / Notion / internal docs database
  - Add a periodic job that re-syncs from your source of
    truth (e.g. weekly Confluence scrape)
  - Add per-team memory partitions so different teams see
    different context

### 6. Routes / UI — `src/iam_jit/routes/`, `templates/`

Standard FastAPI app. Add new endpoints, templates, or
middleware in the obvious places. The audit log + auth
middleware are already in place; new routes pick them up
automatically by adding a `Depends(require_admin)` or
similar.

## Concrete fork examples

### Example A: K8s cluster context

You want iam-jit to know which k8s namespaces a request maps
to, so granting an AWS-side role can be cross-checked against
the k8s ServiceAccount the request claims to be for.

```python
# new file: src/iam_jit/k8s_context.py
from kubernetes import client, config

def cluster_namespaces_for_user(email: str) -> list[str]:
    """Return the k8s namespaces this user has RBAC access to."""
    config.load_incluster_config()  # or load_kube_config_from_dict
    v1 = client.RbacAuthorizationV1Api()
    # walk RoleBindings + ClusterRoleBindings, return matching namespaces
    ...

# wire into review.py:
def _deterministic(policy, request, *, extra_..., k8s_context):
    if k8s_context.cluster_namespaces_for_user(request['metadata']['requester']['email']):
        ...
```

Stash k8s creds in Secrets Manager; mount them as Lambda env;
read at cold-start. Cache for the lifetime of the container.

### Example B: GitHub CODEOWNERS check

Block auto-approve for requests touching a service unless the
requester is in CODEOWNERS for that service.

```python
# new file: src/iam_jit/github_context.py
import os
import httpx

GH_TOKEN = os.environ["GITHUB_TOKEN_SECRET_ARN"]  # fetched from Secrets Manager

def is_owner(email: str, service: str) -> bool:
    """Check CODEOWNERS for `service`-named directory in the configured repo."""
    repo = os.environ["IAM_JIT_GITHUB_OWNERS_REPO"]
    headers = {"Authorization": f"Bearer {_fetch_token()}"}
    r = httpx.get(
        f"https://api.github.com/repos/{repo}/contents/services/{service}/CODEOWNERS",
        headers=headers,
    )
    if r.status_code != 200:
        return False
    return f"@{email.split('@')[0]}" in r.text

# wire as a new auto_approve gate (before quota):
if not github_context.is_owner(user_id, target_service):
    return AutoApproveDecision(auto_approve=False, reason="not_codeowner", ...)
```

Adds ~50ms of latency per auto-approve check; cache aggressively.

### Example C: GCP cross-cloud requests

iam-jit becomes the access-grant interface for both AWS and
GCP. The request schema gets a new `provisioning.mode:
gcp_service_account` value.

```python
# new file: src/iam_jit/provision_gcp.py
from google.cloud import iam_credentials_v1

def provision_gcp(request, *, gcp_credentials_store):
    """Create a temporary GCP service account binding."""
    sa_email = request['spec']['gcp']['service_account']
    role = request['spec']['gcp']['role']
    duration = request['spec']['duration']['duration_hours']

    # Use the iam_jit-managed GCP service account to grant the binding
    # with a time-bounded condition (similar to the AWS sts:RoleSessionName /
    # expiry pattern).
    iam = iam_credentials_v1.IAMCredentialsClient()
    iam.generate_access_token(...)  # or use IAM Policy bindings

    return ProvisioningResult(
        role_arn=f"gcp:sa:{sa_email}",  # use the GCP SA email as the "role id"
        ...
    )
```

Then in `routes/requests.py`, dispatch on
`spec.provisioning.mode`.

### Example D: Make iam-jit your standard provisioning interface

The hub Lambda handles everything; the destination "accounts"
become any provider (AWS account, GCP project, k8s cluster,
Snowflake warehouse, etc.). Each provider gets a new entry in
`accounts_store` with a `provider_type` field, and a new
`provision_<provider>.py` module that knows how to grant +
revoke for that provider.

## What to upstream vs keep local

**Upstream (PR to iam-jit):**

  - Bug fixes in existing code
  - New BUILT-IN sensitive services / high-impact actions if
    they apply to the median AWS environment (e.g.,
    "everyone should treat `kms:Decrypt` on `*` as high-risk")
  - New typed config fields that other orgs would benefit from
    (e.g., "environment-aware risk dimension" — every org
    has dev/staging/prod)
  - Improvements to the LLM intake prompt
  - Doc clarifications

**Keep local (don't PR):**

  - Org-specific config values (your prod account IDs, your
    GitHub org name, your k8s context names) — these are
    config, not code; they live in DDB or env vars
  - Custom LLM backends that wrap YOUR internal gateway
  - Provider integrations for things only YOUR org uses (e.g.,
    a custom CMDB lookup)
  - UI customizations (logos, colors, your org's design system)

The split: code that another org could benefit from → upstream;
code that only makes sense for YOUR org → fork.

## Maintaining a fork

If you're going to maintain a fork long-term:

1. **Keep the test suite green.** The 990+ test suite is the
   regression net. Your fork should add tests for your
   customizations + keep the upstream tests passing.

2. **Pin your extension points.** If you've modified
   `review.py`, add a test that asserts your custom logic
   fires (so a future upstream merge doesn't silently break
   your customization).

3. **Use the typed extension points where possible.** Adding
   to `additional_sensitive_services` is a config change,
   not a code change. It survives upstream merges trivially.
   Modifying `_deterministic` directly will conflict on
   upstream merges and require manual reconciliation.

4. **Track your divergence.** `git log --oneline
   upstream/main..HEAD` should show a tight, reviewed list
   of changes. If it gets bigger than ~20 commits, consider
   upstreaming or refactoring.

5. **Re-fetch upstream regularly.** Use `git remote add
   upstream …` + monthly rebase. Upstream's security fixes
   should land in your fork within a week.

## Project conventions worth knowing

  - **Tests live next to the feature they test.** Adding a
    new module `foo.py` → add `tests/test_foo.py`.
  - **Integration tests are gated.** They live in
    `tests/integration/` and require external services
    (Ollama, LocalStack, etc.) to be reachable. Mark them
    `@pytest.mark.integration`.
  - **No emojis in code/docs by default.** The project uses
    ASCII text; emojis only when explicitly visual (UI
    banners).
  - **One config source of truth.** Avoid putting the same
    config in two places. If it's in DDB (settings_store),
    don't also put it in env vars except as deploy-time
    floors.
  - **Audit everything.** Every state change goes through
    `audit_mod.emit()`. Don't add an admin endpoint that
    mutates state without emitting an audit event.

## Performance + cost notes for forks

  - Lambda cold-start: ~3s with the current deps. Adding
    boto3 clients for GCP / k8s / GitHub will inflate this.
    Consider lazy imports in your provider modules
    (`import boto3 inside function`).
  - DynamoDB: pay-per-request mode. Each request submission
    does ~5 DDB calls. Heavy auto-approve traffic
    (>10/sec sustained) starts to add up — consider a
    per-Lambda-instance cache for settings + cidrs.
  - LLM costs: the deterministic path is free. Bedrock/
    Anthropic backends are per-token. For high-traffic
    deploys, prefer a self-hosted Ollama in your VPC.

## When to NOT fork

If your customizations fit entirely into:

  - `additional_sensitive_services` (admin tuning)
  - `additional_high_impact_actions` (admin tuning)
  - `preset_toggles` (deploy-time + admin enable/disable)
  - A custom destination-account CloudFormation template
  - Different SAM parameter values

…you don't need a fork. The upstream version handles all of
these via config. Open a PR if you find yourself wanting a
new config field — chances are other orgs want it too.

## Getting help

  - Open a GitHub issue with the `customization` label
  - Read `docs/security-notes.md` and `docs/PRODUCTION-READINESS.md`
    before adding new mutations to make sure your fork doesn't
    weaken the threat model
  - Check `tests/` for patterns — the existing tests are the
    style guide for new tests
