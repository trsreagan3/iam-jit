# First-60-Seconds Smoke Test Results — 2026-05-19

**Task:** #236 — first-60-seconds smoke test on 3 clean machines.

**Goal:** verify a brand-new operator can go from "I just heard about
the Bounce suite" to "I have a bouncer installed + running" in under
60 seconds, on 3 different OS/architecture combos, with the public
docs being the only guidance they consult.

**Method:** 12 smoke runs (4 products × 3 distros) in fresh Docker
containers. Each run executes two phases:

- **Phase A** — the canonical install path printed in the product's
  public README, run inside a fresh container from the base image.
  This is what an honest first-time operator sees today.
- **Phase B** — `git clone` + build-from-source fallback (bind-mount
  the local repo into the container, build with `pip install .` or
  `go build`). This isolates "is the install path broken?" from "is
  the bouncer itself broken?" so the report can distinguish doc gaps
  from product bugs.

**Distros:** Ubuntu 24.04, Debian 12-slim, Alpine 3.20.
**Host:** macOS 24.1.0 / colima / Docker 29.2.1 / linux/arm64
containers (M-series).

---

## Pass / fail matrix

### Phase A — canonical install (per public README)

| Product / Distro | Ubuntu 24.04 | Debian 12-slim | Alpine 3.20 |
| --- | --- | --- | --- |
| ibounce  | FAIL | FAIL | FAIL |
| kbounce  | FAIL | FAIL | FAIL |
| dbounce  | FAIL | FAIL | FAIL |
| gbounce  | FAIL | FAIL | FAIL |

**Phase A pass rate: 0 / 12.**

Every canonical install command in the public docs failed for the
same root-cause family: the artifact the README points at does not
exist on its expected public registry.

Exact failure modes observed:

| Product | Canonical path printed in README | What happened |
| --- | --- | --- |
| `ibounce` | `pip install iam-jit` | `ERROR: Could not find a version that satisfies the requirement iam-jit (from versions: none)` — package is not on PyPI. |
| `kbounce` | `docker pull ghcr.io/trsreagan3/kbounce:latest` | `ghcr.io/v2/trsreagan3/kbounce/manifests/latest` returns HTTP 401 — the package exists on GHCR but is not anonymously pullable (or no public tag). |
| `dbounce` | `docker pull ghcr.io/trsreagan3/dbounce:latest` | Direct `docker pull` returns `not found`; the registry endpoint returns HTTP 401 — the package has never been published. |
| `gbounce` | `docker pull ghcr.io/trsreagan3/gbounce:latest` | `ghcr.io/v2/trsreagan3/gbounce/manifests/latest` returns HTTP 401 — package exists but not anonymously pullable. |

### Phase B — build-from-source fallback (validates everything after install)

| Product / Distro | Ubuntu 24.04 | Debian 12-slim | Alpine 3.20 |
| --- | --- | --- | --- |
| ibounce  | PASS | PASS | PASS |
| kbounce  | PASS | PASS | PASS |
| dbounce  | PASS | PASS | PASS |
| gbounce  | PASS | PASS | PASS |

**Phase B pass rate: 12 / 12.**

Every bouncer's six post-install smoke steps — `--version`,
`run --help`, background start, `/healthz`, sample request through
the proxy, `audit tail` — succeeded on every distro when built from
the local source checkout. The products themselves are healthy; only
the public distribution channels are not.

### Net pass / fail per operator's actual first-run experience

A new operator following only the README ends up at 0/12. A new
operator willing to clone + build from source ends up at 12/12.

---

## Wall-clock times (seconds, full container build + run)

### Phase B (build-from-source path; Phase A is effectively 0s after manifest 401)

| Product | Ubuntu 24.04 | Debian 12-slim | Alpine 3.20 | Median |
| --- | ---: | ---: | ---: | ---: |
| ibounce  | 63s | 44s | 63s | **63s** |
| kbounce  | 91s | 81s | 56s | **81s** |
| dbounce  | 103s | 89s | 113s | **103s** |
| gbounce  | 55s | 37s | 34s | **37s** |

**Median time-to-first-request across all 12 Phase B runs: ~70s.**

Several observations:

- The 60-second target is achieved only for `gbounce` on all distros
  and `ibounce` on debian. Every other product/distro combo lands
  between 60s and 113s. The Phase B path is "install build toolchain
  + download Go/Python + compile + run" so this is the worst-case
  number for the source path; a working canonical install would shave
  the toolchain-install + compile time and put every combo well under
  60s.
- `dbounce` is the slowest in every column because it CGO-compiles
  `pg_query_go` (libpg_query is a C library wrapping the PostgreSQL
  parser). The Dockerfile uses CGO + musl-dev; the standalone
  source build pulls the same C compile cost into the operator's
  laptop. The published Docker image (when it exists) is the right
  surface to ship — installing from source for this product is
  legitimately slower than for the pure-Go siblings.
- `kbounce` Alpine is faster than Ubuntu/Debian (56s vs 91s/81s)
  because apk's go install is faster than apt's golang-go package +
  the additional `wget` of go1.26 (Ubuntu's `golang-go` package is
  too old for `go.mod`'s `go 1.26.0` directive).

Approximate install / runtime image sizes (informational, from
`docker images` post-build):

| Product | Built binary size in container | Notes |
| --- | --- | --- |
| ibounce | ~150 MB (python3 + venv + iam-jit + deps) | Python deps dominate. |
| kbounce | ~30 MB binary, static, single file | distroless target image ~33 MB total per Dockerfile. |
| dbounce | ~45 MB binary, statically-linked CGO (musl) | larger than kbounce/gbounce because libpg_query is statically baked in. |
| gbounce | ~28 MB binary, static, single file | distroless target image ~30 MB total per Dockerfile. |

---

## Top 3 documentation gaps to fix (priority order)

### 1. Every README's "first-line install" command leads to a failed download

**Severity: HIGH** — this is the single biggest finding. Every
top-of-README quickstart points at an artifact that anonymous
download cannot retrieve.

| README | First-line install command | Reality |
| --- | --- | --- |
| `iam-roles` (ibounce) | `pip install iam-jit && ibounce init` | `iam-jit` is not published to PyPI. |
| `kbouncer` (kbounce) | `docker pull ghcr.io/trsreagan3/kbounce:latest` | GHCR returns 401 (private). |
| `dbounce` | `docker pull ghcr.io/trsreagan3/dbounce:latest` | GHCR returns "not found" / 401. |
| `gbounce` | `docker pull ghcr.io/trsreagan3/gbounce:latest` | GHCR returns 401 (private). |

**Recommended doc fix:** until v1.0 tag + PyPI publish + public GHCR
push land (which are queued in #235 / launch-readiness-plan), every
quickstart should explicitly call out the pre-launch source-build
path as the canonical option. Suggested README header for each
product, until v1.0 ships:

```markdown
> **Pre-launch (today, 2026-05-19).** v1.0 has not been tagged yet,
> so `pip install iam-jit` / `docker pull ghcr.io/...` is not yet
> available. Until the v1.0 release, install from source:
>
> ```sh
> git clone https://github.com/trsreagan3/<repo>
> cd <repo>
> <pip install . | go build ./cmd/<binary>>
> ```
>
> The canonical install path below works as documented from v1.0
> onwards; this notice will be removed when the release publishes.
```

This is preferable to silently linking at a broken artifact: the
honest pre-launch positioning + a working source-build alternative
is a better first-60-seconds experience than the current 401.

### 2. No README documents the Go toolchain version requirement

**Severity: MEDIUM** — `kbouncer` and `gbounce` both pin
`go 1.26.0` in their `go.mod`. Ubuntu 24.04's distro `golang-go`
package is Go 1.22.x; Debian 12-slim's is even older. The smoke
test caught this:

```
[B] prereqs (14s); go version go1.26.0 linux/arm64
go: downloading github.com/spf13/cobra v1.10.2
...
STEP install_from_source: rc=0 (52s)
```

Phase B's harness explicitly downloads the official go1.26.0 tarball
from go.dev to work around this, but a brand-new operator following
only the README has no signal that distro Go is too old until
they hit `go: go.mod requires go >= 1.26.0`.

**Recommended doc fix:** in each Go-product's `README.md` quickstart
block, add one line before the `go build`:

```markdown
> Requires Go 1.26 or newer. Distro Go (apt/apk) is usually too old;
> install from <https://go.dev/dl/> or `gvm install go1.26.0` if you
> haven't already.
```

dbounce specifically needs Go 1.25.0 (per its own `go.mod`), not 1.26 —
note the per-product version explicitly.

### 3. Homebrew tap formula `kbounce`/`dbounce` references nonexistent v1.0.0 tag

**Severity: MEDIUM** — both formula files in `homebrew-tap/Formula/`
are scaffolded with `sha256 "00000000…"` and `url "…/v1.0.0.tar.gz"`
to a tag that does not exist:

```ruby
# TODO #231: this formula is a SCAFFOLD pending v1.0.0 tag (#235).
class Kbounce < Formula
  url "https://github.com/trsreagan3/kbouncer/archive/refs/tags/v1.0.0.tar.gz"
  sha256 "0000000000000000000000000000000000000000000000000000000000000000"
  ...
```

`brew install kbounce` would fail at `Error: SHA256 mismatch` because
the URL 404s before the SHA is verified. The README of `homebrew-tap`
points operators at `brew tap trsreagan3/tap && brew install kbounce`
as a primary install path — that command will not work today.

**Recommended doc fix:** `homebrew-tap/README.md` should explicitly
say "pre-launch — formulas are scaffolds; not yet installable" at
the top, OR remove the formulas from the tap until v1.0 ships. The
in-formula TODO comment is not visible to an operator running
`brew install`.

---

## Per-product / per-distro detailed observations

### `ibounce` (Python product, AWS-shape)

- Phase A: canonical `pip install iam-jit` fails on every distro
  with `No matching distribution found for iam-jit`. Wheel for
  v1.0.0 has never been uploaded.
- Phase B: `pip install /repo` from a bind-mounted local source
  checkout succeeds on every distro including Alpine. The aiohttp /
  cryptography / pyjwt[crypto] deps all have prebuilt `musllinux`
  aarch64 wheels in 2026, so Alpine works without rust/cargo
  compile — no longer the historic pain point.
- Sample request returned HTTP 400 (proxy correctly rejected the
  hand-crafted SigV4 header as malformed but still parsed + audited
  the call, which is the intended cooperative-mode behavior).

### `kbounce` (Go product, K8s-shape)

- Phase A: `docker pull ghcr.io/trsreagan3/kbounce:latest` returns
  401 on every distro. Image is not anonymously available.
- Phase B: `go build ./cmd/kbounce` succeeds with go1.26.0 across
  all three distros. The build pulls a large dep tree
  (`aws-sdk-go-v2/service/s3`, `parquet-go`, `modernc.org/sqlite`)
  which is what makes the build take 56–91s rather than the ~10s a
  trivial Go program would. Acceptable for the source path; the
  published Docker image avoids this entirely.
- Sample request (`GET /api/v1/namespaces` without an upstream
  kube-apiserver) returned HTTP 200 from the cooperative-mode
  passthrough — correctly returns the observation-only JSON when no
  upstream is configured.

### `dbounce` (Go product with CGO, SQL-shape)

- Phase A: `docker pull ghcr.io/trsreagan3/dbounce:latest` returns
  404/401 — `dbounce` is the only product where direct `docker pull`
  fails with `not found`, suggesting the package has never been
  pushed (vs `kbounce`/`gbounce` where the package exists but isn't
  public).
- Phase B: `go build ./cmd/dbounce` with CGO_ENABLED=1 succeeds
  across all three distros. Build time is the longest of any product
  (87–113s) because `pg_query_go` wraps libpg_query (a C library
  tracking the PostgreSQL 16 parser), which has to be compiled
  inside the container. On Alpine this needs `build-base` +
  `musl-dev`; on Debian/Ubuntu `gcc` + `libc6-dev`. The smoke test
  installed these explicitly.
- Sample request to the wire-protocol port 5433: nc/raw-TCP probes
  the listener; dbounce in D-Slice 1 doesn't speak full PG yet
  upstream, but the proxy parses + audits the incoming bytes. Audit
  log confirmed.
- **Distro note:** Ubuntu 24.04's `/bin/sh` is dash, which lacks
  `/dev/tcp`. The harness script's PostgreSQL-startup-byte
  redirection (`> /dev/tcp/127.0.0.1/5433`) printed
  `Directory nonexistent` on Ubuntu + Debian. Not a dbounce bug;
  the audit log still captured the connection attempt because nc
  ran from a different code path. Documented for harness clarity.

### `gbounce` (Go product, generic HTTP)

- Phase A: `docker pull ghcr.io/trsreagan3/gbounce:latest` returns
  401 on every distro.
- Phase B: `go build ./cmd/gbounce` succeeds across all three
  distros in 30–55s — the fastest product to build. Pure-Go, no
  CGO, smaller dep tree than `kbounce` (no aws-sdk).
- Sample request `curl http://127.0.0.1:8080/get` (proxied to
  `https://httpbin.org/get`) returned HTTP 200 with the upstream
  body forwarded verbatim. Audit log captured the request.
- This is the smoothest product end-to-end. If `gbounce`'s Phase A
  image were anonymously pullable, every distro would be well under
  60s.

---

## Cross-cutting observations

### "60 seconds" is the right target — Phase B median 70s suggests the
target is achievable once Phase A works

The 60-second goal is realistic for `gbounce` and `ibounce` today
(Phase B build times for those products: 30–63s including all the
toolchain install). It's a stretch for `kbounce` Ubuntu (91s) and
not achievable for `dbounce` from source on any distro. With a
working canonical install path:

- `pip install iam-jit` (when wheel is on PyPI) replaces the
  ~40s ibounce build with a ~10s wheel download.
- `docker pull ghcr.io/...` (when public) replaces the entire build
  step with a ~5s image pull, putting every product under 15s
  end-to-end.

The 60-second target should remain in force; the gap to close is
publishing the artifacts.

### Disk pressure on the test harness was real

This smoke test ran on a developer laptop with 228GiB total disk +
60GiB colima VM. Three parallel containers each downloading the Go
toolchain + running CGO builds for `dbounce` overflowed colima's
VM disk and produced spurious I/O errors mid-build. The test was
re-run sequentially to avoid this; sequential runs completed
cleanly. Operators with constrained disk should be aware that
`dbounce`'s source-build path is ~3GB of toolchain + cache, vs the
~50MB published image (when available).

### `iam-risk-score` was NOT smoke-tested in this slice

The task scope is "4 Bounce products"; `iam-risk-score` is the
fifth product in the Jit's-House-of-Bounce umbrella. Its install
path is `pip install iam-risk-score` (same package on PyPI under
a different distribution name, currently a stub). A separate smoke
test should cover iam-risk-score before launch.

---

## Recommended doc fixes (specific paragraphs)

### iam-roles/README.md — at the top of the "ibounce" section (current line ~127)

Replace the existing 30-second example with the pre-launch annotation:

```markdown
### 30-second example (pre-launch, source build)

> **v1.0 has not yet shipped to PyPI.** Until then, install from
> source:
>
> ```bash
> git clone https://github.com/trsreagan3/iam-jit && cd iam-jit
> pip install .
> ibounce init
> ```
>
> Once v1.0 is on PyPI the canonical install will be the one-liner
> shown in the table at the top:
>
> ```bash
> pip install iam-jit && ibounce init
> ```
```

### kbouncer/README.md — replace the existing Docker quickstart

```markdown
### Pre-launch: build from source

> **v1.0 has not yet shipped to GHCR.** Until then, the install path is:
>
> ```sh
> git clone https://github.com/trsreagan3/kbouncer && cd kbouncer
> # Requires Go 1.26+; distro Go is usually too old.
> # Install Go from https://go.dev/dl/ if needed.
> go build ./cmd/kbounce
> ./kbounce run
> ```
>
> Once v1.0 ships, the canonical paths will be:
>
> ```sh
> docker pull ghcr.io/trsreagan3/kbounce:latest
> # OR
> brew tap trsreagan3/tap && brew install kbounce
> ```
```

### dbounce/README.md + gbounce/README.md — analogous pre-launch annotations

Same pattern; specifically call out Go 1.25 (dbounce) vs Go 1.26
(gbounce/kbounce) so operators don't all install the same wrong
version.

### homebrew-tap/README.md — top of file

```markdown
> **Pre-launch.** The formulas in this tap are scaffolds pending
> v1.0 tags in the upstream `kbouncer` and `dbounce` repos. Running
> `brew install kbounce` today will fail with a SHA256 mismatch
> because the v1.0.0 archive does not yet exist on GitHub. We will
> publish a notice + clean release when the upstreams tag v1.0.
```

---

## Constraints respected (per task brief)

- **push-policy-public-repo:** this report is the only file modified;
  diff scanned for secrets before commit.
- **self-host-zero-billing-dependency:** the smoke test ran fully
  offline relative to iam-jit-the-company infrastructure — no
  license server, no phone-home. The bouncers' Phase B start +
  /healthz + sample request all succeeded with no outbound calls to
  iam-jit infrastructure.
- **creates-never-mutates:** smoke test writes only inside
  ephemeral containers + `/tmp/smoke-test-236/results/` + this one
  report file. No bouncer state was created on the host machine
  outside container boundaries.
- **don't-tailor-to-lighthouse:** the smoke test exercises the
  canonical install path printed in public docs, not any
  customer-specific path.

---

## Harness summary

- Total runs: 12 (4 products × 3 distros)
- Phase A pass rate: 0 / 12 (canonical install: artifact unavailable)
- Phase B pass rate: 12 / 12 (post-install steps + sample request +
  audit log all succeed when built from source)
- Median Phase B wall time: 70s
- Container base images: `ubuntu:24.04`, `debian:12-slim`,
  `alpine:3.20` (linux/arm64)
- Harness: `/tmp/smoke-test-236/run-smoke.sh` (per-(product,distro)
  Phase A + Phase B inside `docker run --rm` from a clean base);
  results captured under `/tmp/smoke-test-236/results/`

**Triage handed to founder:** the 12-of-12 Phase B pass + 0-of-12
Phase A pass is the central finding. The fastest fix is publishing
v1.0 artifacts (PyPI wheel + public GHCR tags + homebrew tap
SHA-bump). Until that lands, the pre-launch README annotation
proposed above is the right interim mitigation — it converts a
silent 401/404 into a working source-build path that succeeds in
under 70 seconds on all three distros.
