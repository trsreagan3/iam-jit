# iam-jit

> **Don't give your AI agent standing admin.**
> iam-jit is a service you **self-host in your own AWS account**. It issues
> narrow, time-bound, audited IAM roles **per task** — so an AI agent (or a
> human) can do real infra work without holding standing credentials. Reads
> auto-approve generously; writes get scored and gated; every grant expires.
>
> **Free + open source. No SaaS, no phone-home, no per-seat fee** — you run it,
> you own the data and the audit trail.
>
> Works with any MCP-compatible agent: Claude Code, Cursor, Codex MCP, Devin,
> custom runtimes. The MCP server speaks the open Model Context Protocol — no
> agent-specific build required.

[![CI](https://img.shields.io/badge/CI-19%2B%20rounds%20BB%2BWB%20audited-brightgreen)](docs/security/) [![Calibration](https://img.shields.io/badge/AWS--managed%20corpus-1489%2F1489-brightgreen)](docs/CONVERGENCE-REPORT-2026-05.md) [![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

The write-gating decision is made by a deterministic scoring engine with an open, calibrated corpus:

| Corpus | Pass rate |
|---|---:|
| AWS-managed policies (every published one) | **1,489 / 1,489 (100%)** |
| Documented attack patterns (Bishop Fox / Rhino / HackingTheCloud / MITRE) | **203 / 217 (93.5%)** |
| Adversarial audit rounds (BB+WB) | **19+ shipped** |

Open corpus, open methodology, open commit history.

---

## Quick start — self-host iam-jit

iam-jit deploys as a Lambda + DynamoDB stack **into your own AWS account**.
Nobody else runs it; there is no hosted tier. ~$6–10/mo idle.

**1. Clone + deploy** (needs the [AWS SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/install-sam-cli.html), Docker, and AWS credentials for the target account):

```bash
git clone https://github.com/trsreagan3/iam-jit.git
cd iam-jit
export AWS_PROFILE=your-profile          # creds for the account you're deploying into
make deploy-self-host MVP_EMAIL=you@example.com
```

This builds the iam-jit Lambda (the FastAPI app + web UI + JSON API + MCP
endpoint, Mangum-wrapped) and provisions the DynamoDB tables. The deploy
prints a **Function URL** — that's your iam-jit instance.

> Want to see exactly what gets created first? `make deploy-dry-run` lints both
> CloudFormation templates locally in ~30s — no AWS write, no credentials needed.

**2. Claim the first admin + lock down access:**

```bash
make claim-bootstrap
```

This signs you in as the bootstrap admin and narrows the network allowlist from
`0.0.0.0/0` to your current IP. Open the Function URL in your browser — you're in.

**3. Point your agent at it.** Install the CLI, then wire the MCP server so your
agent can request scoped roles for itself:

```bash
pipx install git+https://github.com/trsreagan3/iam-jit.git   # or: curl -fsSL https://raw.githubusercontent.com/trsreagan3/iam-jit/main/install.sh | sh
iam-jit mcp install-claude-code      # also: install-cursor / install-codex / install-devin
```

For any other MCP client, `iam-jit mcp show-config` prints the raw snippet; see
[docs/MCP-RECIPES.md](docs/MCP-RECIPES.md).

Full walkthrough (App config, edge protection, Bedrock, custom domain):
**[docs/GETTING-STARTED.md](docs/GETTING-STARTED.md)** and
**[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)**.

---

## How it works (60 seconds)

Most agents using AWS today have one of three setups, all bad:

1. **Agent has your admin keys.** Terrifying — one bad prompt and your prod database is gone.
2. **Agent has a too-narrow role.** Frustrating — the agent constantly hits permission errors and stalls.
3. **No AWS access.** Loses ~50% of the agent's productive value.

iam-jit's answer: **read-only access by default; writes require your explicit OK.**
~80% of agent operations are reads; the 20% writes are where ~all the risk lives.
Asymmetric friction matches asymmetric risk.

- iam-jit issues short-lived (1h default) AWS roles per task
- Reads auto-approve generously; writes get scored (deterministic 1–10) + gated
- Every grant is time-bounded, region-scoped, account-scoped, and audited
- The role's trust policy is locked to the requesting principal — **AWS itself enforces the scope**
- An agent operating through iam-jit *cannot accidentally* delete prod, pivot to another region, or exceed your authority

For the full architecture + audit + compliance picture see [docs/FEATURES.md](docs/FEATURES.md).

---

## Run it on a laptop first (development / solo)

To try iam-jit without deploying — or to run it as a single-admin safety layer on
your own machine — use **local mode**. It uses your local AWS credentials, persists
state to `~/.iam-jit/`, and serves the same web UI at `http://127.0.0.1:8765/`:

```bash
iam-jit init-solo --account-id <YOUR_AWS_ACCT_ID>   # auto-detected if `aws` is configured
iam-jit serve --local
```

Scoring, preview, gating, and the audit trail all work with no AWS access; *issuing*
a real role additionally needs valid AWS credentials + a provisioner role. Local mode
is best for evaluation and solo use — **the self-host deploy above is the path for a
team.** Details: [docs/GETTING-STARTED.md](docs/GETTING-STARTED.md).

> **Side note — the scorer on its own.** The same deterministic engine ships as a
> standalone offline CLI, `iam-risk-score my-policy.json` (also a Python lib + GitHub
> Action), if you only want to score a policy with no AWS and no server. It's a
> convenience, not the main product.

> **Side note — runtime bouncers (beta).** The Bounce suite (`ibounce`, `gbounce`,
> `kbounce`, `dbounce`) is a separate, **experimental** line of local proxies that
> gate an agent's *outbound* calls (AWS API, HTTP, Kubernetes, SQL) at runtime —
> defense-in-depth alongside iam-jit's IAM scoping. They are **beta and not yet
> recommended for production**; they're intentionally not part of the flow above.
> If you want to experiment, see [docs/WIRING-AN-AGENT.md](docs/WIRING-AN-AGENT.md).

---

## Read this next

- **[docs/GETTING-STARTED.md](docs/GETTING-STARTED.md)** — clone-to-working-endpoint deploy walkthrough + local mode
- **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)** — self-host deployment reference (parameters, edge protection, Bedrock, custom domain)
- **[docs/FEATURES.md](docs/FEATURES.md)** — full feature catalog (every shipping flag, what's NOT in iam-jit and why)
- **[docs/MCP-RECIPES.md](docs/MCP-RECIPES.md)** — wire iam-jit's MCP server into any agent runtime
- **[docs/SECURITY-POSTURE.md](docs/SECURITY-POSTURE.md)** — trust model + threat model
- **[docs/KNOWN-CAVEATS.md](docs/KNOWN-CAVEATS.md)** — read before deploy
- **[docs/GITHUB-ACTION-RECIPE.md](docs/GITHUB-ACTION-RECIPE.md)** — score policies in CI (`trsreagan3/iam-jit-action@v1`)
- **[docs/README.md](docs/README.md)** — TOC for the ~100 markdown files in `docs/`; tells you which to read by role

---

## Verify your install

```bash
iam-jit doctor install-check        # confirms PATH, console scripts, MCP install support
```

> **Note:** the `pipx`/`pip` commands switch to `pipx install iam-jit` once we publish to PyPI (#235). Homebrew tap users: `brew install --HEAD trsreagan3/tap/iam-jit` until tagged releases land. See [docs/GETTING-STARTED.md](docs/GETTING-STARTED.md) for every install path.

---

## Contributing

Issues + discussions: [GitHub Issues](https://github.com/trsreagan3/iam-jit/issues). The calibration corpus + adversarial-loop methodology is fully open; contributions of attack patterns + legitimate-policy examples are especially valuable. See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for testing standards and [docs/ADVERSARIAL-LOOP-PROCESS.md](docs/ADVERSARIAL-LOOP-PROCESS.md) for the calibration methodology.

## License

Apache-2.0 — see [LICENSE](./LICENSE).

Copyright 2026 trsreagan3.
