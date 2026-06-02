# Installing Bounce Suite via RPM

> **Status:** Build pipeline ships with v1.0.0. Artifacts are attached to GitHub
> Releases. A hosted public RPM repository (e.g. via Cloudsmith or COPR) is
> planned post-v1.0 — see #746.
>
> Per [[vendor-integration-claim-qualifier]]: artifacts are built + smoke-tested
> in CI (fedora:40 container) but NOT published to a public `dnf/yum` repo yet.

## Prerequisites

- Fedora 38+ / RHEL 9+ / Rocky Linux 9+ / AlmaLinux 9+ (x86_64 or aarch64)
- `curl`, `rpm` or `dnf`

## Install kbounce (Kubernetes proxy)

```bash
# Detect architecture (x86_64 or aarch64)
ARCH=$(uname -m)
VERSION=1.0.0

curl -fsSL \
  "https://github.com/trsreagan3/kbouncer/releases/download/v${VERSION}/kbounce_${VERSION}_linux_${ARCH}.rpm" \
  -o kbounce.rpm

sudo rpm -i kbounce.rpm
# or: sudo dnf install ./kbounce.rpm

# Verify
kbounce --version
```

## Install dbounce (SQL proxy)

```bash
ARCH=$(uname -m)
VERSION=1.0.0

curl -fsSL \
  "https://github.com/trsreagan3/dbounce/releases/download/v${VERSION}/dbounce_${VERSION}_linux_${ARCH}.rpm" \
  -o dbounce.rpm

sudo rpm -i dbounce.rpm

dbounce --version
```

## Install gbounce (HTTP/HTTPS proxy)

```bash
ARCH=$(uname -m)
VERSION=1.0.0

curl -fsSL \
  "https://github.com/trsreagan3/gbounce/releases/download/v${VERSION}/gbounce_${VERSION}_linux_${ARCH}.rpm" \
  -o gbounce.rpm

sudo rpm -i gbounce.rpm

gbounce --version
```

## Install ibounce + iam-jit (AWS API proxy, Python)

ibounce is distributed as a Python package — no .rpm yet (planned post-v1.0).

```bash
pip install iam-jit

ibounce --version
iam-jit --version
iam-risk-score --version
```

## Uninstall

```bash
sudo rpm -e kbounce
sudo rpm -e dbounce
sudo rpm -e gbounce
```

## Verifying the download

Each GitHub Release includes a `checksums.txt` file with SHA-256 hashes:

```bash
curl -fsSL "https://github.com/trsreagan3/kbouncer/releases/download/v${VERSION}/checksums.txt" \
  | grep "linux_${ARCH}.rpm" \
  | sha256sum -c -
```

## What gets installed

| File | Location |
|------|----------|
| `kbounce` binary | `/usr/local/bin/kbounce` |
| `kbouncer` shim (deprecated, v1.0 only) | `/usr/local/bin/kbouncer` |
| `dbounce` binary | `/usr/local/bin/dbounce` |
| `gbounce` binary | `/usr/local/bin/gbounce` |

No daemon is installed. Running a bouncer does not require `sudo` once installed.

## Supported architectures

| Bouncer | x86_64 | aarch64 |
|---------|--------|---------|
| kbounce | ✅ | ✅ |
| dbounce | ✅ | ✅ |
| gbounce | ✅ | ✅ |

## Build pipeline

`.rpm` packages are produced by [goreleaser](https://goreleaser.com) + [nfpm](https://nfpm.goreleaser.com)
in the `release` GitHub Actions workflow of each bouncer repo. Smoke-tested in
`fedora:40` Docker containers before the release is finalized.

See:
- [kbouncer release workflow](https://github.com/trsreagan3/kbouncer/blob/main/.github/workflows/release.yml)
- [dbounce release workflow](https://github.com/trsreagan3/dbounce/blob/main/.github/workflows/release.yml)
- [gbounce release workflow](https://github.com/trsreagan3/gbounce/blob/main/.github/workflows/release.yml)
