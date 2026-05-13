# Self-hosting

Three deploy shapes; pick what matches your need.

## Just the CLI (offline)

No infrastructure. `pip install iam-risk-score`. Done.

The deterministic scorer is fully functional offline — no API calls,
no network dependency. The LLM narrative isn't available, but the
numeric score and all factors / suggestions are.

This is the right path for **air-gapped environments, pre-commit
hooks, and CI pipelines that don't need the LLM narrative**.

## Self-hosted API (your AWS account)

For organizations that want the scoring API behind their own VPN /
firewall / SCP, or that want the LLM narrative without depending on
the public hosted service.

See [docs/GETTING-STARTED.md](https://github.com/trsreagan3/iam-jit/blob/main/docs/GETTING-STARTED.md)
in the source repo for a 5-minute MVP deploy walkthrough.

Short version:

```bash
git clone https://github.com/trsreagan3/iam-jit.git
cd iam-jit
python3.12 -m venv .venv
.venv/bin/pip install -e '.[dev]'
make test   # 2,691 tests should pass

# Then deploy:
AWS_PROFILE=your-profile MVP_EMAIL=you@example.com make deploy-mvp
```

The MVP deploy creates Lambda + DynamoDB + S3 state bucket. No
Bedrock, no CloudFront, no custom domain — those are layered on
top via subsequent stack updates. See
[production hardening](production-hardening.md).

## Hosted API (us)

If you don't want to operate the stack yourself,
`https://api.iam-risk-score.com` is the hosted service:

- Free tier: 100 req/month per IP
- Indie / Pro / Team / Enterprise — see [pricing](pricing.md)

Same scoring engine as self-hosted. Same calibration. The hosted
service adds the LLM narrative on paid tiers and the usual
SaaS quality-of-life (uptime monitoring, logs, billing).

## What about the iam-jit provisioner?

`iam-risk-score` (this docs site) is just the scoring layer.
The full **iam-jit** is a separate, larger product — a time-bound
least-privilege IAM role provisioner with approval workflow,
audit trail, and automatic revocation. It uses the same scoring
engine internally.

If you want the full provisioner, deploy the entire SAM stack
(not just the score endpoint). The MVP `make deploy-mvp` target
deploys both — the score endpoint is exposed at `/api/v1/score`,
the provisioner endpoints at `/api/v1/requests`. They share the
Lambda; runtime cost is identical.

See the main repo README for the iam-jit feature set.
