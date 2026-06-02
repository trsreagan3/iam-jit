# Installing Bounce Suite via APT (.deb)

> **Status:** Build pipeline ships with v1.0.0. Artifacts are attached to GitHub
> Releases. A hosted public APT repository (e.g. via Cloudsmith or GitHub Pages)
> is planned post-v1.0 — see #746.
>
> Per [[vendor-integration-claim-qualifier]]: artifacts are built + smoke-tested
> in CI (ubuntu:22.04 container) but NOT published to a public `apt-get` repo yet.

## Prerequisites

- Debian/Ubuntu 20.04 or later (amd64 or arm64)
- `curl`, `dpkg`

## Install kbounce (Kubernetes proxy)

```bash
# Download the latest .deb for your architecture
ARCH=$(dpkg --print-architecture)   # amd64 or arm64
VERSION=1.0.0

curl -fsSL \
  "https://github.com/trsreagan3/kbouncer/releases/download/v${VERSION}/kbounce_${VERSION}_linux_${ARCH}.deb" \
  -o kbounce.deb

sudo dpkg -i kbounce.deb

# Verify
kbounce --version
```

## Install dbounce (SQL proxy)

```bash
ARCH=$(dpkg --print-architecture)
VERSION=1.0.0

curl -fsSL \
  "https://github.com/trsreagan3/dbounce/releases/download/v${VERSION}/dbounce_${VERSION}_linux_${ARCH}.deb" \
  -o dbounce.deb

sudo dpkg -i dbounce.deb

dbounce --version
```

## Install gbounce (HTTP/HTTPS proxy)

```bash
ARCH=$(dpkg --print-architecture)
VERSION=1.0.0

curl -fsSL \
  "https://github.com/trsreagan3/gbounce/releases/download/v${VERSION}/gbounce_${VERSION}_linux_${ARCH}.deb" \
  -o gbounce.deb

sudo dpkg -i gbounce.deb

gbounce --version
```

## Install ibounce + iam-jit (AWS API proxy, Python)

ibounce is distributed as a Python package — no .deb yet (planned post-v1.0).

```bash
# Until iam-jit lands on PyPI (#235), install from source:
pip install git+https://github.com/trsreagan3/iam-jit.git

ibounce --version
iam-jit --version
iam-risk-score --version
```

## Uninstall

```bash
sudo dpkg -r kbounce
sudo dpkg -r dbounce
sudo dpkg -r gbounce
```

## Verifying the download

Each GitHub Release includes a `checksums.txt` file with SHA-256 hashes:

```bash
curl -fsSL "https://github.com/trsreagan3/kbouncer/releases/download/v${VERSION}/checksums.txt" \
  | grep "linux_${ARCH}.deb" \
  | sha256sum -c -
```

## What gets installed

| File | Location |
|------|----------|
| `kbounce` binary | `/usr/local/bin/kbounce` |
| `kbouncer` shim (deprecated, v1.0 only) | `/usr/local/bin/kbouncer` |
| `dbounce` binary | `/usr/local/bin/dbounce` |
| `gbounce` binary | `/usr/local/bin/gbounce` |

No daemon is installed. Each bouncer is a CLI process; running it does not require
`sudo` once installed.

## Supported architectures

| Bouncer | amd64 | arm64 |
|---------|-------|-------|
| kbounce | ✅ | ✅ |
| dbounce | ✅ | ✅ |
| gbounce | ✅ | ✅ |

## Build pipeline

`.deb` packages are produced by [goreleaser](https://goreleaser.com) + [nfpm](https://nfpm.goreleaser.com)
in the `release` GitHub Actions workflow of each bouncer repo. Smoke-tested in
`ubuntu:22.04` Docker containers before the release is finalized.

See:
- [kbouncer release workflow](https://github.com/trsreagan3/kbouncer/blob/main/.github/workflows/release.yml)
- [dbounce release workflow](https://github.com/trsreagan3/dbounce/blob/main/.github/workflows/release.yml)
- [gbounce release workflow](https://github.com/trsreagan3/gbounce/blob/main/.github/workflows/release.yml)
