# Installing Bounce Suite via Homebrew (macOS + Linux)

> **Status:** Tap is live at `trsreagan3/homebrew-tap`. Formulas are scaffolds
> with placeholder sha256 values pending the v1.0.0 tag (#235). `--HEAD` installs
> (from GitHub source) work today.
>
> Per [[vendor-integration-claim-qualifier]]: formulas are audited + structure
> is correct; `--HEAD` builds are verified; versioned installs require the tag.

## One-time setup: add the tap

```bash
brew tap trsreagan3/tap
```

## Install Go bouncers

Once v1.0.0 tags are cut (or using `--HEAD` for now):

```bash
# Kubernetes proxy
brew install trsreagan3/tap/kbounce
kbounce --version

# SQL proxy (PostgreSQL + MySQL)
brew install trsreagan3/tap/dbounce
dbounce --version

# HTTP/HTTPS forward proxy
brew install trsreagan3/tap/gbounce
gbounce --version
```

## Install iam-jit + ibounce (Python, all three entry points)

```bash
brew install trsreagan3/tap/iam-jit
# or equivalently:
brew install trsreagan3/tap/ibounce

iam-jit --version
iam-risk-score --version
ibounce --version
```

Both `iam-jit` and `ibounce` formulas install the same Python package into a
Homebrew-managed virtualenv and produce all three console_scripts.

## Install from HEAD (current main branch)

If the v1.0.0 tag has not been cut yet, or you want the latest main:

```bash
brew install --HEAD trsreagan3/tap/kbounce
brew install --HEAD trsreagan3/tap/dbounce
brew install --HEAD trsreagan3/tap/gbounce
brew install --HEAD trsreagan3/tap/iam-jit
```

## Upgrade

```bash
brew upgrade trsreagan3/tap/kbounce trsreagan3/tap/dbounce \
             trsreagan3/tap/gbounce trsreagan3/tap/iam-jit
```

## Uninstall

```bash
brew uninstall kbounce dbounce gbounce iam-jit
brew untap trsreagan3/tap   # optional
```

## How formula updates work

When a new version is tagged in a bouncer repo, goreleaser opens a PR against
`trsreagan3/homebrew-tap` that bumps the formula's `url` and `sha256`. The PR
is auto-merged by the tap's CI once `brew audit` passes.

Requires `TAP_GITHUB_TOKEN` secret set in each bouncer repo (see
[INSTALL-APT.md](INSTALL-APT.md) or the release workflow READMEs).

## Formula source

- [`Formula/kbounce.rb`](https://github.com/trsreagan3/homebrew-tap/blob/main/Formula/kbounce.rb)
- [`Formula/dbounce.rb`](https://github.com/trsreagan3/homebrew-tap/blob/main/Formula/dbounce.rb)
- [`Formula/gbounce.rb`](https://github.com/trsreagan3/homebrew-tap/blob/main/Formula/gbounce.rb)
- [`Formula/ibounce.rb`](https://github.com/trsreagan3/homebrew-tap/blob/main/Formula/ibounce.rb)
- [`Formula/iam-jit.rb`](https://github.com/trsreagan3/homebrew-tap/blob/main/Formula/iam-jit.rb)
