# Security posture

Technical reference for the `iam-jit` family + the Bounce-suite
binaries (`ibounce`, `kbounce`, `dbounce`, `gbounce` — all
shipped). Written for a SecOps procurement reviewer asking *"what
does this binary actually do?"* — quotable from a security
questionnaire. Pairs with [`SECURITY.md`](../SECURITY.md) (threat
model + disclosure policy) and [`SECURITY-SLA.md`](SECURITY-SLA.md)
(patch SLAs).

For wiring the MCP surface into non-Claude-Code clients, see
[`MCP-RECIPES.md`](MCP-RECIPES.md).

---

## 1. Summary

`iam-jit` is a self-hosted IAM credential issuer that creates short-
lived, narrowly-scoped IAM principals in the customer's own AWS
account. The Bounce suite (`ibounce` for AWS, `kbounce` for
Kubernetes, `dbounce` for SQL databases, `gbounce` for outbound
HTTP — all shipped at v1.0) is a family of local transparent proxies
that gate the traffic an operator's machine sends to those upstreams
against a local rule set.

What these tools do NOT do:

- They do **not** operate a multi-tenant hosted SaaS. There is no
  shared infrastructure holding trust roles or credentials across
  customers. (The previously-hosted `api.iam-risk-score.com`
  stateless scorer was dropped on 2026-05-24 to restore
  `[[no-hosted-saas]]` to 100% — the scorer ships as an offline
  CLI + Python library only.)
- They do **not** phone home. There is no usage telemetry, no
  error reporting, and no licensing call-back. The Enterprise
  license is a signed local file (Ed25519); no server check happens
  at runtime.
- The Bounce proxies never re-sign credentials and never hold them.
  `ibounce` forwards SigV4-signed AWS requests verbatim; `kbounce`
  forwards bearer tokens / client certs verbatim; the planned
  `dbounce` will pass the SASL auth exchange through unmodified.
- They do **not** persist any credential. The audit log records who
  asked for what and the verdict — not the secret material.

Cross-suite framing (per the honest-positioning memo): the Bounce
proxies are a **deterrent + audit surface, not an AWS- / kube- /
DB-enforced security boundary.** The AWS-enforced boundary is the
IAM policy on the credential the operator gives the agent;
`ibounce` adds an additional client-side gate that catches mistakes
and prompt-injection traffic between the agent and the upstream. An
attacker who can bypass the proxy (e.g., by using a different
endpoint URL or going direct) bypasses the gate — that is a known
property of the architecture, and is why scope + IAM still matter.

---

## 2. Network behavior — every outbound call enumerated

Every network destination any binary in the suite ever contacts,
the trigger, and the payload shape. The table is exhaustive — if a
destination isn't on this list, the binary does not contact it.

| Binary | Destination | Trigger | What's sent |
|---|---|---|---|
| `ibounce` (HTTP proxy) | AWS endpoint named in the request's SigV4 `Host` header | Proxied SDK request from the operator's process | Original request bytes, verbatim — including the SigV4 signature. The proxy never decodes or re-signs |
| `ibounce` (`version-check`, opt-in) | `https://api.github.com/repos/trsreagan3/iam-jit/releases/latest` | Operator runs `ibounce version-check` interactively, OR a future scheduled-check codepath the operator opts into | GET request with a standard User-Agent (`ibounce/<version>`); no install ID, no machine fingerprint. The `IBOUNCE_NO_VERSION_CHECK=1` env var suppresses the call entirely |
| `kbounce` (proxy) | Configured `kube-apiserver` URL (from the operator's `kubeconfig`) | Proxied `kubectl` / client-go request | Original request bytes, verbatim. Bearer tokens / mTLS client certs forwarded unchanged |
| `kbounce` (`version-check`, opt-in) | `https://api.github.com/repos/trsreagan3/kbouncer/releases/latest` | Same as `ibounce`; suppressed by `KBOUNCE_NO_VERSION_CHECK=1` | Same as `ibounce` |
| `dbounce` (future) (proxy) | Configured DB upstream URL | Proxied SQL query | Wire-protocol bytes verbatim; SCRAM / cleartext-password phase passes through unmodified — the proxy never sees the password in plaintext form usable for replay |
| `iam-jit` (scorer/JIT issuer, self-host Lambda) | Customer-configured IdP endpoint (Google Workspace / Okta / generic OIDC) | Operator-initiated login flow | Standard OIDC authorization-code exchange; no extra payload added by iam-jit |
| `iam-jit` (scorer, Pro+ LLM tier) | Customer-configured Bedrock OR Anthropic API endpoint | Policy scoring when LLM-augmented mode is enabled for the customer's account | The policy text being scored (which the customer themselves provided to iam-jit) |
| `iam-jit` (Slack approval bot, Pro+) | Customer-configured Slack webhook | Approval-request notification | Approval payload — request ID, requester, scored policy summary |
| (none) | iam-jit-the-company infrastructure | NEVER. There is no phone-home. | n/a |

Confirm any row above by running the binary in a network-isolated
environment and tracing traffic; only the configured-upstream
endpoint should appear.

---

## 3. Telemetry — none

- iam-jit-the-company collects **zero** telemetry from any binary
  in the suite. No usage tracking. No error reporting. No
  performance metrics.
- The future opt-in error/crash-reporting pipeline (per the
  opt-in-feedback-pipeline memo) has **not** shipped at v1.0; when
  it does, it will be off by default and gated by an explicit
  env-var opt-in with a payload-sanitizer that strips AWS
  credentials and policy contents.
- The `version-check` subcommand on `ibounce` / `kbounce` is
  **not** telemetry. It performs a single GET to the GitHub
  Releases API and reports the latest tag. No install ID, no
  machine fingerprint, no usage data is sent. The standard
  `User-Agent` header (`ibounce/<version>` /
  `kbounce/<version>`) is the only identifying string.
  Suppress with `IBOUNCE_NO_VERSION_CHECK=1` or
  `KBOUNCE_NO_VERSION_CHECK=1`.
- The Ed25519-signed license file (per the
  self-host-zero-billing-dependency memo) is verified locally; no
  network call is made to validate it.

---

## 4. Credentials handling

| Component | Credential type | Handling |
|---|---|---|
| `ibounce` | AWS SigV4-signed HTTP requests | Received from the SDK client; forwarded **verbatim** to the AWS endpoint named in the signed Host header. The proxy never re-signs. The proxy never holds the operator's secret access key — the signature is computed by the SDK before the request reaches the proxy |
| `kbounce` | Kubernetes bearer tokens, mTLS client certs | Forwarded verbatim. `kbounce` does not mint, refresh, or cache tokens — it is a pure pass-through with rule evaluation |
| `dbounce` | PG / MySQL SCRAM, cleartext-password, certificate auth | The SASL auth exchange between client and server is forwarded transparently. The proxy participates only at the wire-protocol framing level; the password material is never decoded into a form `dbounce` could reuse |
| `iam-jit` (JIT issuer) | Short-lived IAM principals (AWS STS) | iam-jit **creates** new short-lived scoped IAM users / role-session credentials in the customer's account via the customer's deployed Lambda. Per the creates-never-mutates invariant, iam-jit never modifies existing IAM resources the customer owns. The issued credentials are returned to the requester directly; iam-jit's own state stores only the issuance record (who, when, what scope, expiry) — not the secret material |
| `iam-jit` (scorer) | None — pure policy text in / risk score out | The scorer takes a JSON IAM policy as input and returns a 1–10 risk score. No AWS API calls; no credentials involved |

The proxies' credentials behavior is verifiable by source review:
search the proxy codepaths for any reference to AWS secret-access-
key material or k8s token decoding — there is none.

---

## 5. Data leaves the machine — only via the proxied upstream

Every byte of network traffic the proxy emits is the operator's
own request to their own configured upstream:

- For `ibounce`: the AWS endpoint named in the operator's request
- For `kbounce`: the kube-apiserver from the operator's kubeconfig
- For `dbounce`: the database URL the operator configured

The proxy adds nothing to those requests. The proxy does not
secondarily copy, log, or forward any payload to any other
destination.

This has been confirmed across 19+ rounds of black-box + white-box
adversarial audits (see `docs/security/AUDIT-2026-05-WB-*.md` for
the full series). Per the audit-cadence-discipline memo, every
security-relevant change is followed by a focused BB+WB audit
before the feature is declared shipped.

The local SQLite audit log (`~/.iam-jit/bouncer/state.db` for
`ibounce`, equivalent for `kbounce`) is exactly that — **local**.
The audit log never leaves the operator's machine; there is no
shipper, no sync, no remote sink.

---

## 6. Code execution provenance

- All Bounce binaries (`ibounce`, `kbounce`, `dbounce`, `gbounce`)
  are Apache 2.0 and shipped at v1.0. Build-from-source is available;
  full commit history is public on GitHub.
- `kbounce` and `dbounce` ship as single static Go binaries.
  Reproducible builds: same source + same toolchain version
  produces byte-identical output.
- `ibounce` ships as a Python wheel via PyPI (`pip install
  iam-jit`); dependency hashes are pinned in `pyproject.toml`. The
  binary is the `ibounce` console script entrypoint.
- No native-code plugins. No dynamically-loaded user code beyond
  the OS standard libraries, the Go / Python standard library, and
  the explicitly-imported third-party dependencies listed in
  `go.mod` / `pyproject.toml`.
- The MCP server is in-process within the same binary — no
  separate daemon, no separate user; it runs under the operator's
  uid and respects the operator's filesystem ACLs.

To audit the dependency surface: `pip show` against the wheel for
`ibounce`, or `go list -m all` against the repo for `kbounce` /
`dbounce`. Both surfaces are deliberately small.

---

## 7. Threat model summary

The full threat model is in [`../SECURITY.md`](../SECURITY.md). The
per-product summary, for procurement-questionnaire reference:

| Threat | iam-jit | ibounce / kbounce / dbounce |
|---|---|---|
| Compromised binary on operator machine | Bounded by what the deployed Lambda's role can do in the customer's account; per creates-never-mutates, cannot elevate existing IAM | Same blast radius as anything the operator could already do — the proxy uses the operator's own credentials and forwards verbatim. Compromising the proxy gives an attacker the operator's existing authority, not more |
| Compromised operator machine (full root) | Out of scope. An attacker with operator privileges can already invoke AWS APIs directly. iam-jit's audit log on that machine is also compromised | Same — the proxy + audit log on that machine are compromised |
| Compromised / prompt-injected agent | Scoring engine + auto-approve threshold + human-approver routing for non-trivial requests + creates-never-mutates floor | Cooperative-mode = advisory log; transparent-mode = enforce DENY (returns 403 to the agent's SDK). The deterrent-not-boundary framing applies — an agent that can bypass the proxy (different endpoint URL) bypasses the gate |
| Compromised upstream (AWS / kube-apiserver / DB) | Catastrophic upstream compromise is out of scope (per `SECURITY.md`) | Same |

Cross-suite invariants:

- **No shared infrastructure across customers.** No multi-tenant
  SaaS tier exists; there is no cross-tenant blast radius.
- **No credentials cross machine boundaries.** The proxy never
  ships credentials anywhere. iam-jit issues credentials in the
  customer's account, returned to the customer's requester
  directly.

---

## 8. Audit + disclosure SLAs

| Severity | Disclosure → patch shipped | Customer upgrade window |
|---|---|---|
| CRITICAL | 7 days | 14 days |
| HIGH | 30 days | 60 days |
| MEDIUM | 90 days | 180 days |
| LOW | Next minor release | Next minor release |

Full SLA + process: [`SECURITY-SLA.md`](SECURITY-SLA.md).

Disclosure email: **`security@iam-jit.dev`** (DNS setup pending —
pre-launch reports may be sent to `trsreagan3+security@gmail.com`).
For CRITICAL / HIGH issues we follow coordinated disclosure;
customers on the announce list are notified ~24–48 hours **before**
public disclosure so they can patch ahead of the public
announcement.

PGP key: published at `security@iam-jit.dev` before v1.0 launch.

---

## 9. Update mechanism

- Updates are **customer-driven**. No auto-update; the customer
  decides when to upgrade.
- Update paths:
  - `pip install --upgrade iam-jit` for `ibounce` (requires pip >= 22.3 for PEP 660 editable installs of source checkouts; published wheels work on older pip — `python3 -m pip install --upgrade pip` first if you hit a `build_editable`-shaped error; #548)
  - `brew upgrade kbounce` / GitHub Releases binary for `kbounce`
  - GitHub Releases binary for `dbounce` (when shipped)
- The opt-in `ibounce version-check` / `kbounce version-check`
  subcommand performs a single GET to GitHub Releases and reports
  the latest tag; it does not download, install, or modify any
  file. Suppress with the `*_NO_VERSION_CHECK=1` env var.
- Per the update-release-strategy memo, environment-variable names
  and HTTP API endpoints carry a 2-minor-version backward-
  compatibility window. Breaking changes land on major-version
  boundaries with a deprecation warning in the preceding minor
  release.
- The scoring engine version is independent of the software
  version — customers can upgrade the binary without the scorer
  changing its verdicts.

---

## 10. Compliance posture

One-line per framework; detail in
[`compliance/COMPLIANCE-MAPPING.md`](compliance/COMPLIANCE-MAPPING.md).

- **SOC 2 (Type 1, pre-attestation):** audit logs, RBAC,
  change-management, monitoring all documented; vendor-attestation
  not yet engaged.
- **PCI DSS:** see the compliance mapping for the §8.6
  agent-as-system-account treatment (agents are system accounts
  authorized by a human; the human's MFA satisfies §8.6).
- **HIPAA:** §164.312(b) (audit-trail) requirement satisfied by
  the SQLite audit chain on each Bounce proxy and the iam-jit
  Lambda's structured audit log.
- **ISO 27001:** not yet pursued; on the post-launch roadmap.
- **NIST 800-53 SI-2:** patch SLA per
  [`SECURITY-SLA.md`](SECURITY-SLA.md).

---

## 11. Pre-procurement checklist

A SecOps reviewer can confirm everything in this doc with the
following local checks. None of them require a vendor call.

- [ ] **No phone-home.** Search the source for outbound HTTP
      destinations: `git grep -nE
      "(urllib|requests|httpx|http\.Client|net/http)"` then
      audit the destination of every match. The expected set is
      enumerated in §2; anything else is a finding.
- [ ] **No telemetry.** `git grep -niE
      "(sentry|datadog|segment|mixpanel|posthog|amplitude)"` —
      should return nothing.
- [ ] **Apache 2.0 license + open commit history.** Confirm at
      [LICENSE](../LICENSE) and the repo's git log.
- [ ] **Audit history.** Review `docs/security/AUDIT-*.md` —
      19+ BB+WB rounds shipped; every closed finding has a pinned
      regression test under `tests/test_appsec_audit_round*_*.py`.
- [ ] **Calibration corpus.** Review
      `docs/CONVERGENCE-REPORT-2026-05.md` and the
      `tests/corpus/` tree — every AWS-managed policy (1,489 /
      1,489) passes; documented-attack-pattern corpus at 203/217.
- [ ] **Network-isolated install.** On a clean machine (or
      VPC-isolated EC2), install the binary, invoke the proxy
      against a configured upstream, and confirm that the only
      outbound traffic is to the configured upstream + (if
      opted-in) `api.github.com` for `version-check`.
- [ ] **Threat model + disclosure.** Review
      [`../SECURITY.md`](../SECURITY.md) and
      [`SECURITY-SLA.md`](SECURITY-SLA.md). Both name the
      maintainer contact and the exact patch SLAs.

---

Last reviewed: 2026-05-17. Maintainer:
[`security@iam-jit.dev`](mailto:security@iam-jit.dev).
