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

## Install

### macOS — Homebrew Python (most common dev setup)

```bash
brew install pipx
pipx install git+https://github.com/trsreagan3/iam-jit.git
```

> **Why pipx?** macOS's Homebrew Python enforces [PEP 668](https://peps.python.org/pep-0668/), which blocks `pip install --user` with an "externally-managed-environment" error. `pipx` manages an isolated venv per tool and is the path PEP 668 itself recommends. The `iam-jit` binary lands in `~/.local/bin/` (automatically on `PATH` after `brew install pipx`).

> **Note:** Will switch to `pipx install iam-jit` once we publish to PyPI (#235).

### Linux — Ubuntu / Debian

```bash
pip install --upgrade pip      # PEP 660 editable needs pip >= 22.3 (#548)
pip install --user git+https://github.com/trsreagan3/iam-jit.git
# ensure ~/.local/bin is in PATH (add to ~/.bashrc if not already there):
# export PATH="$HOME/.local/bin:$PATH"
```

> **Note:** Will switch to `pip install --user iam-jit` once we publish to PyPI (#235).

### Windows / generic Python

```bash
pip install --user git+https://github.com/trsreagan3/iam-jit.git
```

> **Note:** Will switch to `pip install --user iam-jit` once we publish to PyPI (#235).

### Go bouncers (kbounce / dbounce / gbounce)

Optional — only needed if you use K8s, database, or generic-HTTP interception.
Requires Go ≥ 1.26 (auto-fetched via GOTOOLCHAIN on Go 1.21+; older runtimes need toolchain access or a fresh Go install — see [go.dev/dl](https://go.dev/dl/)).

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
| 1 | **iam-risk-score** | `iam-risk-score my-policy.json` | Offline 1–10 risk score for any AWS IAM policy. CLI + Python lib + GitHub Action. |
| 2 | **ibounce** | `ibounce init && ibounce run` | Local proxy gating every AWS API call against a rule set. Defense-in-depth over IAM scoping. |
| 3 | **iam-jit local** | `iam-jit init-solo && iam-jit serve --local` | Local-only safety layer between your agent and AWS. Zero SaaS dependency. |
| 4 | **iam-jit self-host** | `git clone && sam build && sam deploy --guided` | Full JIT-IAM provisioner running in your own AWS account. |

All four share the same deterministic scoring engine. Open source under Apache 2.0.

**No multi-tenant hosted SaaS.** iam-jit-the-company runs zero shared infrastructure. The scorer is an offline CLI + library (no hosted API). The other three products run on your laptop or in your own AWS account. See [docs/FEATURES.md](docs/FEATURES.md) for the rationale.

---

## Read this next

- **[docs/FEATURES.md](docs/FEATURES.md)** — full feature catalog (every product, every shipping flag, the v1.0 platform-features cluster, what's NOT in iam-jit and why)
- **[docs/GETTING-STARTED.md](docs/GETTING-STARTED.md)** — self-host MVP deploy walkthrough (git clone to working endpoint in ~5 minutes)
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
