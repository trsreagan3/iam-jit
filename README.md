# iam-jit · iam-risk-score

> **Don't give Claude full admin.**
> iam-jit issues narrow, time-bound, audited AWS credentials per task — and `ibounce` (the Bounce-family AWS gate; formerly `iam-jit-bouncer`) gates every AWS API call against a local rule set — so your AI agent can do real infra work without standing admin authority.
>
> Works with any MCP-compatible agent: Claude Code, Cursor, Codex MCP, Devin, custom runtimes. The MCP server speaks the open Model Context Protocol — no agent-specific build required.

[![CI](https://img.shields.io/badge/CI-19%2B%20rounds%20BB%2BWB%20audited-brightgreen)](docs/security/) [![Calibration](https://img.shields.io/badge/AWS--managed%20corpus-1489%2F1489-brightgreen)](docs/CONVERGENCE-REPORT-2026-05.md) [![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

| Corpus | Pass rate |
|---|---:|
| AWS-managed policies (every published one) | **1,489 / 1,489 (100%)** |
| Documented attack patterns (Bishop Fox / Rhino / HackingTheCloud / MITRE) | **203 / 217 (93.5%)** |
| Adversarial audit rounds (BB+WB) | **19+ shipped** |

Open corpus, open methodology, open commit history.

---

## Install + add to your agent

Two steps, both copy-paste. **(1)** install the tool, **(2)** wire it into
your agent. The wiring commands are **identical across every bouncer** — pick
your bouncer, the shape never changes.

### 1. Install

Lead with the no-toolchain paths. "From source" is last (it needs git + a
build step).

**One-line installer (any OS — no toolchain needed):**

```bash
curl -fsSL https://raw.githubusercontent.com/trsreagan3/iam-jit/main/install.sh | sh
```

Installs `iam-jit` + `ibounce`. Add Go bouncers in the same run with
`IAM_JIT_BOUNCERS=ibounce,kbounce,dbounce,gbounce` (see [G8](#go-bouncers-kbounce--dbounce--gbounce) below).

**Homebrew tap (macOS + Linux — for the Go bouncers):**

```bash
brew tap trsreagan3/tap
brew install --HEAD trsreagan3/tap/iam-jit     # iam-jit + ibounce + iam-risk-score
```

> Use `--HEAD` until tagged releases land — the versioned formulas still carry
> placeholder checksums (a tagged `brew install …/iam-jit` will fail a sha256
> check). For the most reliable install today, prefer **pipx** (below).

See [docs/INSTALL-HOMEBREW.md](docs/INSTALL-HOMEBREW.md) for the Go bouncers + version pinning.

**macOS — Homebrew Python (most common dev setup):**

```bash
brew install pipx
pipx install git+https://github.com/trsreagan3/iam-jit.git
```

> **Why pipx?** macOS's Homebrew Python enforces [PEP 668](https://peps.python.org/pep-0668/), which blocks `pip install --user` with an "externally-managed-environment" error. `pipx` manages an isolated venv per tool and is the path PEP 668 itself recommends. The `iam-jit` binary lands in `~/.local/bin/` (automatically on `PATH` after `brew install pipx`).

**Linux / Windows / generic Python — `pip install --user`:**

```bash
pip install --upgrade pip      # PEP 660 editable needs pip >= 22.3 (#548)
pip install --user git+https://github.com/trsreagan3/iam-jit.git
# ensure ~/.local/bin is in PATH (add to ~/.bashrc if not already there):
# export PATH="$HOME/.local/bin:$PATH"
```

> **Note:** the `pipx`/`pip` commands will switch to `pipx install iam-jit` / `pip install --user iam-jit` once we publish to PyPI (#235).

**From source (last resort — needs git + build):** see [docs/GETTING-STARTED.md](docs/GETTING-STARTED.md).

After any install, verify your environment:

```bash
iam-jit doctor install-check        # confirms PATH, console scripts, MCP install support
```

### 2. Add to your agent / Claude session

Two ways to wire a bouncer into an agent. **MCP mode is recommended** — one
command writes the config; the **identical** subcommand exists for every agent
and every bouncer.

**MCP mode (recommended):**

```bash
ibounce mcp install-claude-code     # Claude Code
ibounce mcp install-cursor          # Cursor
ibounce mcp install-codex           # Codex (prints snippet + config path)
ibounce mcp install-devin           # Devin (prints cloud-agent wiring recipe)
```

`kbounce` exposes the same `mcp install-*` subcommands for the Kubernetes gate.
For any other MCP client, see [docs/MCP-RECIPES.md](docs/MCP-RECIPES.md).

**Transparent proxy mode (one env var):** point the agent's AWS SDK at the
running ibounce proxy — no MCP host required.

```bash
export AWS_ENDPOINT_URL=http://127.0.0.1:8767     # ibounce
```

After starting the bouncer you can let the CLI emit the right exports for
whatever is running: `eval "$(iam-jit shellinit)"`.

**Each bouncer wires through a different protocol** (AWS SDK, HTTPS proxy,
kubeconfig, SQL conn-string). The exact value for each is in
**[docs/WIRING-AN-AGENT.md](docs/WIRING-AN-AGENT.md)** (per-protocol table +
[canonical port table](docs/WIRING-AN-AGENT.md#canonical-port-table)).

**In Docker (Claude-in-container):** see
[docs/DOCKER-CLAUDE-INTEGRATION.md](docs/DOCKER-CLAUDE-INTEGRATION.md) — in-container
+ sidecar patterns for ibounce and the Go bouncers.

### Go bouncers (kbounce / dbounce / gbounce)

Optional — only needed if you use K8s, database, or generic-HTTP interception.

**macOS / Linux — Homebrew tap (no Go toolchain needed):**

```bash
brew tap trsreagan3/tap
brew install trsreagan3/tap/kbounce trsreagan3/tap/dbounce trsreagan3/tap/gbounce
```

**With a Go toolchain (Go ≥ 1.26; auto-fetched via GOTOOLCHAIN on Go 1.21+; older runtimes need toolchain access or a fresh Go install — see [go.dev/dl](https://go.dev/dl/)):**

```bash
go install github.com/trsreagan3/kbouncer/cmd/kbounce@latest
go install github.com/trsreagan3/dbounce/cmd/dbounce@latest
go install github.com/trsreagan3/gbounce/cmd/gbounce@latest
```

Binaries land in `$GOPATH/bin` (defaults to `$HOME/go/bin`). Add that directory to
your `PATH` if it is not already present.

> **Note:** `kbounce` lives in the `kbouncer` repo; `dbounce` and `gbounce` live in
> same-named repos. These are the canonical install commands — confirmed against the
> public module proxy.

---

Four products ship under the iam-jit brand. Pick the one that fits.

| # | Product | One-line install | What it is |
|---|---|---|---|
| 1 | **iam-risk-score** | `iam-risk-score my-policy.json` | Offline 1–10 risk score for any AWS IAM policy. CLI + Python lib + GitHub Action. **No AWS needed.** |
| 2 | **ibounce** | `ibounce init && ibounce run --audit-log-path ~/.iam-jit/ibounce/audit.jsonl` | Local proxy gating every AWS API call against a rule set. Defense-in-depth over IAM scoping. |
| 3 | **iam-jit local** | `iam-jit init-solo --account-id <YOUR_AWS_ACCT_ID> && iam-jit serve --local` | Local-only safety layer between your agent and AWS, with a web UI at `http://127.0.0.1:8765/`. Zero SaaS dependency. |
| 4 | **iam-jit self-host** | `git clone && sam build && sam deploy --guided` | Full JIT-IAM provisioner running in your own AWS account. |

All four share the same deterministic scoring engine. Open source under Apache 2.0.

**First-run notes for #3 (iam-jit local):**
- It needs your **12-digit AWS account id** (`--account-id`; auto-detected if `aws` is already configured). The account id is in the AWS console (top-right) or `aws sts get-caller-identity`.
- After `serve --local`, **open `http://127.0.0.1:8765/` in your browser** and sign in (in local mode the magic-link is shown on-screen — no email needed).
- **Scoring, preview, gating, and the audit trail work with no AWS access.** *Issuing* a real IAM role additionally needs valid AWS credentials + a provisioner role in that account; without them a request scores + auto-decides but lands in `provisioning_failed` (expected for a local demo). Just want scores? Use #1 (`iam-risk-score`) — zero setup.
- Port already in use? `iam-jit serve --local --port 8766`.

**No multi-tenant hosted SaaS.** iam-jit-the-company runs zero shared infrastructure. The scorer is an offline CLI + library (no hosted API). The other three products run on your laptop or in your own AWS account. See [docs/FEATURES.md](docs/FEATURES.md) for the rationale.

---

## Read this next

- **[docs/FEATURES.md](docs/FEATURES.md)** — full feature catalog (every product, every shipping flag, the v1.0 platform-features cluster, what's NOT in iam-jit and why)
- **[docs/GETTING-STARTED.md](docs/GETTING-STARTED.md)** — install (pipx / one-liner / Homebrew) + self-host MVP deploy walkthrough (git clone to working endpoint in ~5 minutes)
- **[docs/WIRING-AN-AGENT.md](docs/WIRING-AN-AGENT.md)** — wire any agent through any bouncer (per-protocol table + canonical port table for ibounce / gbounce / kbounce / dbounce)
- **[docs/DOCKER-CLAUDE-INTEGRATION.md](docs/DOCKER-CLAUDE-INTEGRATION.md)** — add any bouncer to a Claude-in-container setup (in-container, sidecar, + the Go bouncers)
- **[docs/GITHUB-ACTION-RECIPE.md](docs/GITHUB-ACTION-RECIPE.md)** — first-class GitHub Actions recipe (`trsreagan3/iam-jit-action@v1`)
- **[docs/CI-RECIPES.md](docs/CI-RECIPES.md)** — reference recipes for GitLab CI, CircleCI, Jenkins, and Buildkite
- **[docs/README.md](docs/README.md)** — TOC for the ~100 markdown files in `docs/`; tells you which to read by role (operator / developer / reviewer)
- **[docs/SECURITY-POSTURE.md](docs/SECURITY-POSTURE.md)** — trust model + threat model
- **[docs/KNOWN-CAVEATS.md](docs/KNOWN-CAVEATS.md)** — read before install

---

## Why this exists (60 seconds)

Most agents using AWS today have one of three setups, all bad:

1. **Agent has your admin keys.** Terrifying — one bad prompt and your prod database is gone.
2. **Agent has a too-narrow role.** Frustrating — agent constantly hits permission errors and stalls.
3. **No AWS access.** Loses ~50% of the agent's productive value.

iam-jit's answer: **read-only access by default; writes require your explicit OK.** ~80% of agent operations are reads; the 20% writes are where ~all the risk lives. Asymmetric friction matches asymmetric risk.

- iam-jit issues short-lived (1h default) AWS roles per task
- Reads auto-approve generously; writes get scored + gated
- Every grant is time-bounded, region-scoped, account-scoped, audited
- An agent operating through iam-jit *cannot accidentally* delete prod, pivot to another region, or exceed the user's authority

For the full architecture + audit + compliance picture see [docs/FEATURES.md](docs/FEATURES.md).

---

## Contributing

Issues + discussions: [GitHub Issues](https://github.com/trsreagan3/iam-jit/issues). The calibration corpus + adversarial-loop methodology is fully open; contributions of attack patterns + legitimate-policy examples are especially valuable. See [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) for testing standards and [docs/ADVERSARIAL-LOOP-PROCESS.md](docs/ADVERSARIAL-LOOP-PROCESS.md) for the calibration methodology.

## License

Apache-2.0 — see [LICENSE](./LICENSE).

Copyright 2026 trsreagan3.
