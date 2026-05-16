"""iam-jit-bouncer — local AWS-API call gating proxy.

Per [[iam-jit-bouncer]] memo: defense-in-depth over role scoping.
The bouncer sits between the local AWS SDK (boto3, aws-cli, agent
calls) and AWS API endpoints. It inspects every request, matches
against learned rules, and gates the call (allow / deny / prompt).

The boundary the JIT role draws is correct; the bouncer catches
the case where the call TARGET is wrong (prompt-injection, agent
mistake, typo on a destructive call). Doesn't exist productized
elsewhere.

Per [[four-products-one-brand]]: the bouncer is one of iam-jit's
four shipped products — separately addressable market, separate
brand asset (`iam-jit-bouncer` CLI), shares the scorer/audit
infrastructure.

Per [[no-hosted-saas]] and [[local-only-safety-mode]]: the bouncer
runs entirely on the user's laptop, against their local AWS creds,
with no iam-jit-the-company involvement. SQLite-backed local state
at `~/.iam-jit/bouncer/`.

Per [[creates-never-mutates]]: the bouncer never modifies IAM. It
inspects + forwards + denies — that's the entire surface.

Per [[safety-mode-lean-permissive]]: the default mode is `learn`
(observe, never block). Users review the captured calls before
flipping to `enforce`. Block-happy = uninstalled.

This package ships the foundation:
- `rules`: ProxyRule + RuleSet + matcher
- `decisions`: mode logic (learn / enforce / prompt) + Decision enum
- `store`: SQLite-backed rule + audit-log store
- `request_parser`: SigV4 wire-format parser → service/action/region/resource

Stage 2 (next slice) adds:
- HTTP proxy server (uvicorn-based; AWS_ENDPOINT_URL injection)
- Interactive PROMPT decision UX
- Service-specific request parsers (S3 path/virtual-host, DynamoDB streams, etc.)
"""

from __future__ import annotations
