# kbounce (K8s API call gating)

> **kbounce lives in its own repository:** https://github.com/trsreagan3/kbouncer
> *(repo path retains the historical `kbouncer` slug; the CLI + brand
> is `kbounce` per the v1.0 Bounce-suite naming.)*

kbounce is product 5 of 5 in the LLC's suite. It gates Kubernetes
API calls for AI agents (and humans) the way `ibounce` (the AWS
sibling; renamed from `iam-jit-bouncer` in v1.0) gates AWS API
calls — but written in Go, cloud-agnostic, and shipped from its
own repo.

## Why it's separate from this repo

- **Cloud-agnostic.** kbouncer works on EKS, GKE, AKS, bare-metal,
  on-prem — anywhere Kubernetes runs. It is NOT coupled to AWS,
  doesn't depend on iam-jit, and shouldn't live inside an
  AWS-IAM-named repo.
- **Go, not Python.** K8s ecosystem expects Go (kubectl,
  controller-runtime, OPA, Kyverno, Hoop, Falco, Cilium — all Go).
  kbouncer's Go module path is `github.com/trsreagan3/kbouncer` so
  the repo URL IS the import path (canonical Go convention).
- **Separate audience.** K8s operators / SREs / platform teams find
  kbouncer through K8s-ecosystem channels; they don't need to know
  about iam-jit's AWS focus.
- **Separate release pipeline.** Go binaries on GitHub Releases vs
  Python wheels on PyPI want different CI matrices.

See the planning memo `project_kbouncer_separate_repo.md` for the
detailed rationale + the `project_repo_topology_decision.md` for the
broader "3 repos for 5 products" decision.

## How they compose

- **ibounce** (this repo; formerly `iam-jit-bouncer`): AWS API call gating. Python.
- **kbounce** (separate repo; module path `github.com/trsreagan3/kbouncer`): K8s API call gating. Go.
- **Phase 2 recipe** ("iam-jit for K8s on AWS"): documented
  integration combining IRSA-bound IAM roles from iam-jit + K8s
  call gating from kbounce. Post-launch v1.1. NOT a sixth
  product — a documented integration pattern.
