# GitHub Action Marketplace submission checklist

*What's done, what's blocking submission, and the choice you need to
make about repo layout before submitting.*

## What's already in place

- ✅ `github-action/action.yml` — composite action with three presets
  (strict / standard / permissive), SARIF output, PR-comment posting,
  glob-pattern policy-file matching, worst-score gating across files.
  Branding: shield icon, red color.
- ✅ `github-action/README.md` — usage examples, input/output reference.
- ✅ Repo-root `LICENSE` (Apache-2.0).
- ✅ Action tested locally via the `iam-risk-score` CLI it depends on.
- ✅ Underlying CLI now ships in a clean wheel (TestPyPI dry-run #68
  passed), so the `pip install` step in the action will work once the
  package is on PyPI.

## What's blocking submission

GitHub Marketplace requires `action.yml` at the **repository root**.
Right now it's at `github-action/action.yml`. You have three reasonable
ways to resolve this; pick one before submitting.

### Option A — move action.yml to root (simplest)

Pros: standard layout, no extra repo, no extra discovery.
Cons: a `~/repo/action.yml` at root is unusual for a polyglot repo
that also ships a Python CLI + Astro landing site + SAM templates.
Some users will be confused about whether the repo IS an action vs
HAS an action.

```bash
git mv github-action/action.yml action.yml
git mv github-action/README.md docs/github-action-README.md
# Update root README.md to add a "GitHub Action usage" section
# pointing at docs/github-action-README.md.
```

### Option B — separate `trsreagan3/iam-risk-score-action` repo (cleanest for users)

Pros: clear single-purpose repo, easy to grok at first glance, the
versioning of the action becomes independent of the iam-jit codebase
(useful — actions need to evolve slowly because users pin to tags).
Cons: one more repo to maintain, must keep the action.yml in sync
with the underlying CLI manually.

Layout of the new repo:
```
iam-risk-score-action/
├── action.yml           (copy of github-action/action.yml)
├── README.md            (the marketplace listing — must include
│                        usage block, inputs table, branding)
├── LICENSE              (Apache-2.0; copy from this repo)
└── examples/
    ├── basic.yml        (minimal usage)
    └── with-sarif.yml   (paired with codeql/upload-sarif@v3)
```

Steps:
```bash
mkdir ../iam-risk-score-action
cp -r github-action/* ../iam-risk-score-action/
cp LICENSE ../iam-risk-score-action/
cd ../iam-risk-score-action
git init && gh repo create trsreagan3/iam-risk-score-action --public --source=.
git add . && git commit -m "Initial action layout"
git tag v1.0.0
git push origin main --tags
gh release create v1.0.0 --generate-notes
# Then submit via the Marketplace UI on github.com/trsreagan3/iam-risk-score-action
```

### Option C — symlink / git-subtree (clever but fragile)

Don't.

## After whichever option you pick

1. **Cut a release tag** (semver). Marketplace requires a tag to be
   selectable in the UI. Recommended first tag: `v1.0.0`.

2. **Verify the published listing** by adding the action to a throwaway
   repo's workflow:
   ```yaml
   - uses: trsreagan3/iam-risk-score-action@v1
     with:
       policy-file: 'examples/policies/dangerous/01-iam-passrole-star.json'
       preset: 'strict'
   ```
   Confirm: action runs, returns score 9-10, gate fails (preset=strict
   has threshold=3).

3. **Submit to Marketplace** via the Releases page → "Publish this
   release to the GitHub Marketplace" checkbox. Categories to pick:
   - **Primary:** Code review
   - **Secondary:** Security
   The marketplace listing inherits `name`, `description`, and
   `branding` from action.yml.

4. **First-week monitoring.** GitHub will email you on action errors;
   triage anything from real users within 24h while marketplace
   discoverability is highest. The first 100 users are critical for
   reviews, which gate marketplace-search ranking.

## Recommended choice

**Option B** (separate repo) is the right move. Reasons:

- The action's API (inputs, outputs, behaviour) needs to evolve slowly
  because users pin to tags. The iam-jit repo evolves rapidly; sharing
  a repo means breaking the action by accident is just one over-eager
  refactor away.
- A separate repo + listing makes the [[two-product-split]] memo's
  "iam-risk-score is the free scorer" framing concrete: the action IS
  the most discoverable surface of the free scorer, not a bolt-on of
  the SaaS product.
- The maintenance burden is small (action.yml + README + maybe a
  workflow that runs the action on each tag), and the cost is paid
  only when releasing.

But Option A is fine if you want to ship today and decide later — you
can always migrate to Option B later by moving the file + updating the
listing's repo association.

## Pre-launch positioning

Per the `[[ci-standard-play]]` memo, the goal is to make
"we run iam-risk-score in CI" the standard phrase (per the
Snyk/Semgrep 2018-2022 model). The marketplace listing IS the
distribution surface for this goal. Treat it as launch-day content.
