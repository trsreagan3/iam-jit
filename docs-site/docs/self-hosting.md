# Self-hosting

Two deploy shapes; pick what matches your need.

## Just the CLI (offline)

No infrastructure. `pip install iam-jit`. Done.

The deterministic scorer is fully functional offline — no API
calls, no network dependency. The numeric score and all factors /
suggestions are available.

This is the right path for **air-gapped environments, pre-commit
hooks, and CI pipelines** — most users never need anything else.

## Self-hosted iam-jit provisioner (your AWS account)

For organizations that want the full **iam-jit** provisioner — a
time-bound least-privilege IAM role provisioner with approval
workflow, audit trail, and automatic revocation — in their own
AWS account, behind their own VPN / firewall / SCP.

The full feature set ships in the Apache-2.0 release — no license
enforcement at v1.0. Bring your own LLM backend (Bedrock /
Anthropic / local) per
[LLM-BACKENDS.md](https://github.com/trsreagan3/iam-jit/blob/main/docs/LLM-BACKENDS.md).

Deploy the destination-account CloudFormation template into each
AWS account iam-jit will provision into:

```bash
git clone https://github.com/trsreagan3/iam-jit.git
cd iam-jit
python3.12 -m venv .venv
.venv/bin/pip install -e '.[dev]'
make test   # ~6,800 tests should pass

# Deploy the destination-account role into each target AWS account:
aws cloudformation deploy \
  --template-file infrastructure/cloudformation/destination-account-roles.yaml \
  --stack-name iam-jit-destination \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides ExternalId=$(openssl rand -hex 16)
```

Then run iam-jit locally with `iam-jit serve --local` (single
admin, SQLite audit, MCP + REST on localhost) — see
[docs/GETTING-STARTED.md](https://github.com/trsreagan3/iam-jit/blob/main/docs/GETTING-STARTED.md).

> **No hosted iam-jit-the-company SaaS.** Per `[[no-hosted-saas]]`,
> there is no shared multi-tenant infrastructure tier. The
> previously-hosted `api.iam-risk-score.com` scoring endpoint was
> dropped on 2026-05-24 to restore this stance to 100%. The OSS
> scorer + self-host destination-account CFN are the supported
> deployment shapes.

See [production hardening](production-hardening.md) for log
retention tuning, multi-region, multi-account, edge protection.

## Compose with the rest of the Bounce suite

The same `pip install iam-jit` ships the **ibounce** local proxy
(gates every AWS API call against rules). Pair it with the iam-jit
provisioner for defense-in-depth — the role narrows what's possible
in principle; ibounce narrows what's actually attempted at the API
boundary. Both run on your laptop or in your own AWS account.

`kbounce` (Go, K8s) and `dbounce` / `gbounce` ship from separate
repos. See the main README for the full topology.
