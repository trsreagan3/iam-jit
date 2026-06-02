# Installing Bounce Suite via Scoop (Windows)

> **Status:** Scoop bucket created at `trsreagan3/scoop-bucket`. Manifests are
> scaffolds with placeholder hashes pending v1.0.0 tags (#235). goreleaser
> will auto-update manifests and open PRs when tags are cut.
>
> Per [[vendor-integration-claim-qualifier]]: bucket structure is correct and
> manifests pass `scoop checkup`; not yet submitted to the main Scoop bucket
> registry. Windows cross-compile is produced by goreleaser alongside linux/darwin.
>
> **ibounce on Windows:** Python pip install only (v1.0). Native `.exe` via
> PyInstaller/Nuitka is planned for v1.1 (#746).

## Prerequisites

- Windows 10/11
- [Scoop](https://scoop.sh) installed (`irm get.scoop.sh | iex` in PowerShell)

## One-time setup: add the bucket

```powershell
scoop bucket add trsreagan3 https://github.com/trsreagan3/scoop-bucket
```

## Install Go bouncers

```powershell
# Kubernetes proxy
scoop install trsreagan3/kbounce
kbounce --version

# SQL proxy (PostgreSQL + MySQL)
scoop install trsreagan3/dbounce
dbounce --version

# HTTP/HTTPS forward proxy
scoop install trsreagan3/gbounce
gbounce --version
```

## Install ibounce + iam-jit (Python)

Native `.exe` for ibounce is v1.1 work. For now, use pip:

```powershell
pip install iam-jit
ibounce --version
iam-jit --version
iam-risk-score --version
```

## Upgrade

```powershell
scoop update trsreagan3/kbounce trsreagan3/dbounce trsreagan3/gbounce
```

## Uninstall

```powershell
scoop uninstall kbounce dbounce gbounce
scoop bucket rm trsreagan3   # optional
```

## How manifest updates work

When a new version is tagged in a bouncer repo, goreleaser opens a PR against
`trsreagan3/scoop-bucket` that updates the `version`, `url`, and `hash` fields
in the relevant manifest. Requires `TAP_GITHUB_TOKEN` secret set in each bouncer
repo (same token used for the Homebrew tap).

## Supported architectures

Windows amd64 only in v1.0. arm64 Windows cross-compile is a v1.1 item.

## Manifest source

- [`bucket/kbounce.json`](https://github.com/trsreagan3/scoop-bucket/blob/main/bucket/kbounce.json)
- [`bucket/dbounce.json`](https://github.com/trsreagan3/scoop-bucket/blob/main/bucket/dbounce.json)
- [`bucket/gbounce.json`](https://github.com/trsreagan3/scoop-bucket/blob/main/bucket/gbounce.json)
- [`bucket/ibounce.json`](https://github.com/trsreagan3/scoop-bucket/blob/main/bucket/ibounce.json) (pip note)
