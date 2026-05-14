# CI/CD Integration Landscape Research for iam-jit

Research date: 2026-05-14
Author: Research pass (Claude)
Goal: Decide which CI hosts iam-jit (a.k.a. iam-risk-score) should integrate
with after the GitHub Action, in what order, and what universal patterns to
support so we can claim "we run iam-jit in CI" across heterogeneous shops the
way Snyk and Semgrep can.

---

## 1. Executive Summary

GitHub Actions already covers the dominant slice of the market and most OSS
mindshare, so the next wins are GitLab CI (template/component include),
Jenkins (a thin plugin that wraps the existing Docker image), and CircleCI
(an Orb), because together those three pull in roughly the long tail of
established enterprise CI plus the cloud-native GitLab-shop segment. Before
investing in any per-host plugin we should ship two universal substrates:
a SARIF + JUnit-emitting CLI and a Docker image with the CLI baked in, so
that every other CI host (Buildkite, Bitbucket Pipelines, Azure DevOps,
TeamCity, Drone) can adopt iam-jit with three to ten lines of YAML even
before we publish a first-class plugin. The single highest-leverage move
is SARIF output — it lights up GitHub code-scanning, GitLab security
dashboards, and Azure DevOps Advanced Security with zero per-host code.

---

## 2. Ranked CI Hosts: Effort vs. Payoff

Ranking criteria: (a) installed base of teams who would credibly run a
policy-scoring step, (b) marginal effort over what we ship for free with
the universal CLI + Docker image, (c) marketplace discoverability, and
(d) community signal we can borrow from Snyk/Semgrep/Trivy precedent.

| Rank | Host | Effort (person-days) | Payoff | Ship in |
|------|------|----------------------|--------|---------|
| 1 | GitHub Actions | (already shipped) | Very high | v1.0 (done) |
| 2 | GitLab CI | 2-3 | High | v1.0 |
| 3 | Jenkins (OSS + CloudBees) | 5-8 | High but slow | v1.1 |
| 4 | CircleCI Orb | 2-3 | Medium | v1.1 |
| 5 | Azure DevOps Pipelines | 3-5 | Medium (enterprise) | v1.1 |
| 6 | Bitbucket Pipelines (Pipe) | 1-2 | Low-medium | v1.1 |
| 7 | Buildkite plugin | 1-2 | Low (small base, vocal) | v1.2 |
| 8 | TeamCity plugin | 5-7 | Low (Java, JetBrains shops only) | v1.2 / defer |
| 9 | Drone CI / Harness plugin | 1 | Low (already covered by Docker image) | defer |

Below: one paragraph per host plus the structured fields requested.

---

### 2.1 GitHub Actions (already shipped)

GitHub Actions is the default for OSS and is increasingly the default in
small/mid commercial shops. Stack Overflow's 2024 Developer Survey shows
GitHub Actions as the most-used async dev tool category alongside
GitHub-the-platform, and the GitHub Marketplace is where security tools
get discovered. We already ship a GitHub Action; the remaining work is
just to wire SARIF output into the upload-sarif step so iam-jit findings
show up in GitHub's code-scanning UI, and to publish a PR-comment action
variant that posts the risk delta. This is the canonical reference
implementation everyone else will compare against.

- **Market share**: ~54% of professional respondents in SO 2024 use GitHub
  as their primary VCS; GH Actions is the default CI on those repos. SO
  2024 lists it among most-used async tools alongside Jira/Confluence.
- **Canonical pattern**: a published Action in the Marketplace + a
  `uses: aws-iam-jit/iam-jit-action@v1` step.
- **Install friction**: 3-5 YAML lines.
- **Marketplace**: GitHub Marketplace, free, no approval gate beyond
  metadata.
- **Community signal**: Snyk, Semgrep, Trivy, Checkov, Bandit all live
  here; this is the gold standard.
- **Effort**: shipped. Remaining polish ~0.5 day (SARIF + PR-comment).

---

### 2.2 GitLab CI / GitLab Self-Hosted

GitLab is the second largest "where the code lives" CI-host, and the
GitLab security dashboard already understands SARIF and GitLab's own
JSON vulnerability schema. The canonical pattern is publishing a
**CI/CD component** (the new pattern as of GitLab 16/17) or a
classic **template** that users `include:` in their `.gitlab-ci.yml`.
Because GitLab pipelines already accept a Docker image directly, the
universal Docker image gets us 80% there; the component just packages
the right `image:`, `script:`, `artifacts.reports.sast` block, and a
couple of sensible variables.

- **Market share**: GitLab usage in SO 2024 hovers around 15-20% of
  respondents using GitLab/GitLab CI; second behind GH for VCS+CI
  combined. Strong in EU, government, and security-sensitive industries.
- **Canonical pattern**: a GitLab CI/CD Component or a `Security/iam-jit.gitlab-ci.yml`
  template in the catalog; user does `include: - component: ...iam-jit/scan@v1`.
- **Install friction**: 3-5 YAML lines.
- **Marketplace**: GitLab CI/CD Catalog (component registry, free,
  effectively self-service for OSS projects on gitlab.com).
- **Community signal**: Snyk, Semgrep, and GitLab's own SAST analyzers
  all use this pattern; documented and well-trodden. SARIF upload into
  the Security Dashboard is a force multiplier.
- **Effort**: 2-3 person-days including catalog listing, sample
  pipeline, and SARIF artifact wiring.

---

### 2.3 Jenkins (OSS + CloudBees)

Jenkins still has the largest **enterprise** installed base — Datanyze
puts it at ~44% of CI market share by some measures and Enlyft at ~21%,
and CloudBees disclosed 79% YoY growth in Jenkins Pipeline jobs through
2023. The catch: Jenkins integrations are Java plugins (Maven/Gradle
build, hpi packaging) hosted on the Jenkins Plugin Index, which is a
months-long publishing flow and a different language stack than the
rest of iam-jit. The fast path is to ship a **shared library / Pipeline
step** plus a documented "wrap our Docker image in a `sh` step" recipe;
publish a real plugin in v1.1 only after the universal pattern proves
demand.

- **Market share**: 21-44% depending on source; dominant in finance,
  insurance, manufacturing, telco; large self-hosted footprints.
- **Canonical pattern**: a Jenkins plugin (Java, HPI) that adds a
  build step + freestyle UI + Pipeline DSL function (`iamJitScan {}`).
  Lighter alternative: a shared pipeline library on GitHub that
  exposes the same DSL but doesn't require plugin install.
- **Install friction**: with a plugin, 1-3 lines of Pipeline DSL. With
  raw Docker, ~10 lines.
- **Marketplace**: Jenkins Plugin Index (plugins.jenkins.io). Submission
  via Jenkins JIRA + hosting infra repo; weeks-to-months to first
  approval; security scan required.
- **Community signal**: Snyk, Checkmarx, Veracode, SonarQube, Probely
  all ship Jenkins plugins; the format is well-trodden but the
  publishing motion is heavy.
- **Effort**: 5-8 person-days for a polished plugin (Java setup + tests
  + plugin index submission); ~1 day for the shared-library shortcut.

---

### 2.4 CircleCI Orb

CircleCI's Orb registry is one of the cleanest publishing flows in the
industry: an orb is just YAML, you publish via CLI, and Snyk's orb is
a near-perfect template. CircleCI's overall share is smaller than
GitHub/GitLab/Jenkins but its users are disproportionately startups
and cloud-native shops — exactly the iam-jit ICP. Effort is low because
the universal Docker image does most of the work; the orb just exposes
opinionated jobs (`scan`, `scan-and-comment`) and parameters.

- **Market share**: ~5-10% of CI users in industry surveys; over-indexes
  on startups, dev-tool companies, and Y Combinator alumni.
- **Canonical pattern**: a CircleCI Orb published to the Orb Registry
  under the `aws-iam-jit` namespace.
- **Install friction**: 4-6 YAML lines.
- **Marketplace**: CircleCI Orb Registry. Self-service publishing for
  any namespace owner; "certified" status is reserved for CircleCI's
  own orbs but "partner" orbs are fully usable and discoverable.
- **Community signal**: Snyk orb is the canonical reference; Anchore,
  Trivy, and GitGuardian all maintain orbs. CircleCI Discuss forum
  is active.
- **Effort**: 2-3 person-days including registry listing and a sample
  `.circleci/config.yml`.

---

### 2.5 Azure DevOps Pipelines

Azure DevOps Pipelines has a large enterprise footprint (Microsoft
disclosed Azure DevOps approaching ~1B Azure AD users for the org-level
service; pipelines themselves are a smaller subset but Bitbucket-class
in size) and a polished marketplace ("Visual Studio Marketplace"). Tasks
are TypeScript/Node packages with a manifest, published to a publisher
namespace. Snyk's `Snyk Security Scan` task on the VS Marketplace is
the model. Marketplace approval is real but predictable (days, not
months), and the install UX is a one-click "Get it free" from the org's
extension manager. This is the host you need to credibly call iam-jit
"enterprise-ready."

- **Market share**: ~10-15% of CI users globally; concentrated in
  Microsoft-stack enterprises, public sector, and .NET shops.
- **Canonical pattern**: an Azure Pipelines Task extension published
  to the Visual Studio Marketplace.
- **Install friction**: 4-8 YAML lines or a few UI clicks in the
  classic pipeline editor.
- **Marketplace**: Visual Studio Marketplace; publisher account
  required (free, identity verification), review typically days.
- **Community signal**: Snyk, SonarCloud, Checkmarx, WhiteSource all
  ship VS Marketplace tasks. Microsoft tags security/SAST extensions
  on the marketplace.
- **Effort**: 3-5 person-days (Node task scaffolding, marketplace
  manifest, publisher cert).

---

### 2.6 Bitbucket Pipelines (Pipe)

Bitbucket Pipelines has a smaller but meaningful share (Atlassian's
own positioning + Datanyze-style numbers put it in ~15-18% of CI
shops, concentrated in Atlassian-stack orgs). The canonical pattern
is a **Pipe**, which is literally a Docker image referenced by name
in `bitbucket-pipelines.yml` plus a `pipe.yml` manifest. Snyk, Anchore,
and Spectral all ship Pipes. Because a Pipe is fundamentally just
"our Docker image + a thin wrapper script," shipping one is nearly
free once the universal Docker image exists.

- **Market share**: ~10-15% of CI users; strong in Atlassian-stack
  orgs (Jira/Confluence/Bitbucket Server).
- **Canonical pattern**: Bitbucket Pipe (Docker image + `pipe.yml`),
  invoked via `- pipe: aws-iam-jit/scan:1.0.0`.
- **Install friction**: 3-5 YAML lines.
- **Marketplace**: Bitbucket Pipes integrations page; community
  contributions are documented and accepted; official "Atlassian
  Verified" tier exists but is not required for adoption.
- **Community signal**: Snyk Pipe, Anchore Pipe, Spectral Pipe are
  all well-used references. Atlassian Community forum is active.
- **Effort**: 1-2 person-days (mostly the `pipe.yml` manifest plus
  README); reuses the iam-jit Docker image directly.

---

### 2.7 Buildkite Plugin

Buildkite is small in absolute terms (~1,000 customers, ~60k users by
their own 2024 disclosures) but the customer list is exceptional:
Airbnb, Block, Canva, Cruise, Elastic, Lyft, Pinterest, Shopify, Slack,
Tinder, Twilio, Uber, Wayfair. A Buildkite plugin is a Git repository
containing hook scripts (`pre-command`, `command`, `post-command`),
referenced by URL in `pipeline.yml`. Wiz, BoostSecurity, and others
ship plugins of this exact shape. Low effort, low immediate volume,
high logo value.

- **Market share**: ~1-2% of CI users but extremely high logo density
  among 2-5k-engineer tech companies.
- **Canonical pattern**: a Buildkite plugin Git repo with `plugin.yml`
  + `hooks/command`, referenced as
  `plugins: - aws-iam-jit/iam-jit-buildkite-plugin#v1.0.0`.
- **Install friction**: 3-5 YAML lines.
- **Marketplace**: Buildkite Plugins directory (community-maintained
  index); discovery is via the directory + GitHub topic.
- **Community signal**: Wiz, BoostSecurity, ECR, Docker login plugins
  are the standard references. Buildkite has an active community
  Slack.
- **Effort**: 1-2 person-days; mostly hook script + README; reuses
  Docker image.

---

### 2.8 TeamCity Plugin

TeamCity has a small but loyal user base, mostly JVM shops and existing
JetBrains tooling customers. Plugins are Java (Kotlin OK), packaged
as Maven/Gradle artifacts, published to the JetBrains Marketplace.
Snyk, Checkmarx, Veracode, Amazon Inspector, and ZeroThreat all ship
TeamCity plugins, so the precedent exists, but the cost-per-user
is the highest in this list and we should only invest after JetBrains
shops actually ask for it.

- **Market share**: ~2-4% of CI users; concentrated in JVM shops and
  long-running TeamCity-on-prem deployments.
- **Canonical pattern**: JetBrains Marketplace plugin (Java/Kotlin,
  Gradle build, TeamCity SDK), exposes a build runner step.
- **Install friction**: a few UI clicks + 1-2 fields once installed.
- **Marketplace**: JetBrains Marketplace; review process is real
  (days-to-weeks) and quality bar is higher than CircleCI/Bitbucket.
- **Community signal**: Snyk's TeamCity plugin is the closest
  reference; JetBrains blog post on building it exists.
- **Effort**: 5-7 person-days including JVM tooling, plugin SDK,
  marketplace listing.

---

### 2.9 Drone CI / Harness

Drone is a Docker-native CI that was acquired by Harness in 2020.
Every "plugin" is just a Docker image with a fixed entrypoint and
settings via environment variables — there is essentially no
plugin work to do beyond publishing the universal iam-jit Docker
image and a sample `.drone.yml`. Drone Plugins index is community-
contributed; getting listed is a PR to the index repo. Realistic
audience is small; this is "free coverage" once the Docker image
exists.

- **Market share**: <1% of CI users but vocal OSS community
  (DockerHub pulls >100M, ~50k active users by Harness's
  2023 disclosure).
- **Canonical pattern**: a Drone plugin Docker image + an entry
  on plugins.drone.io.
- **Install friction**: 4-6 YAML lines.
- **Marketplace**: plugins.drone.io (community-maintained PR-based
  index).
- **Community signal**: Harness STO ingests scanner output; Drone
  community Slack/Discord is small but responsive.
- **Effort**: <1 person-day on top of the universal Docker image.

---

## 3. Universal Integration Patterns (Ship These First)

The single highest-leverage decision is to make iam-jit useful on
*every* CI host before we ship any host-specific plugin. Three
substrates do most of the work:

### 3.1 Standalone CLI with SARIF + JUnit output

- **SARIF (Static Analysis Results Interchange Format)** is the
  de facto interop format for security findings. GitHub's
  `github/codeql-action/upload-sarif` natively renders it in
  code-scanning UI. GitLab consumes it in the security dashboard.
  Azure DevOps Advanced Security ingests it. Most modern security
  tools (Semgrep, Trivy, Checkov, Bandit, CodeQL) emit SARIF.
- **JUnit XML** is the universal test-result schema. Jenkins,
  GitLab, CircleCI, Buildkite, TeamCity, Azure DevOps, and Bitbucket
  all parse it and render pass/fail counts in the build UI without
  any plugin. Emitting JUnit for "fail-the-build-on-score-N"
  thresholds gives us pretty per-finding rows on every host.
- **Plain text + exit codes**: required floor; every CI can fail
  a build on non-zero exit.

Action: iam-jit CLI should support `--format sarif`, `--format junit`,
`--format json`, `--format text` and have a `--fail-above-score N`
flag. This alone makes us trivially adoptable on every host listed.

### 3.2 Docker image with CLI baked in

- Every CI host listed (including Jenkins, TeamCity, Bitbucket,
  Buildkite, GitLab runners, CircleCI, Azure agents, Drone) can run
  a Docker container as a build step.
- A `ghcr.io/aws-iam-jit/iam-jit:latest` (and a pinned `:v1.0.0`)
  image with the CLI as entrypoint means *any* CI host has a
  working integration in ~5 lines of YAML before we publish a
  single plugin.
- The Docker image is also the substrate that CircleCI Orbs,
  Bitbucket Pipes, Buildkite plugins, Drone plugins, and (with
  a wrapper) Jenkins steps all sit on top of.

Action: build, tag, and publish to GHCR and Docker Hub; document
the "run in any CI" recipe in README.

### 3.3 pre-commit hook + pre-commit.ci

- pre-commit is the dominant local-hook framework in Python
  shops (which is most of iam-jit's audience). Publishing a
  `pre-commit-hooks.yaml` with iam-jit means devs run it before
  ever pushing.
- pre-commit.ci is a free hosted service that runs pre-commit
  hooks as a GitHub/GitLab check on every PR — effectively a
  zero-config CI integration for any project that already uses
  pre-commit.

Action: add a `.pre-commit-hooks.yaml` entry to the iam-jit repo
and document opt-in usage.

---

## 4. Recommended Shipping Order

### v1.0 (immediate, "we run iam-jit in CI" claim defensible)
1. **SARIF + JUnit output** in the CLI. [universal, P0]
2. **Docker image** published to GHCR + Docker Hub with CLI as
   entrypoint and pinned semver tags. [universal, P0]
3. **GitHub Action** polish: ensure `--format sarif` + `upload-sarif`
   integration so findings land in GitHub code-scanning. [already
   shipped, ~0.5 day of polish]
4. **GitLab CI/CD Component** (or template) + sample
   `.gitlab-ci.yml` with SARIF artifact upload. [2-3 days]
5. **Docs page**: "Run iam-jit in any CI" — generic Docker recipe +
   per-host snippets for the eight CI hosts in this doc. [0.5 day]

### v1.1 (next 4-6 weeks, broadens enterprise reach)
6. **CircleCI Orb** with `scan` and `scan-and-comment` jobs. [2-3 days]
7. **Bitbucket Pipe** wrapping the Docker image. [1-2 days]
8. **Azure DevOps Task** on the Visual Studio Marketplace. [3-5 days]
9. **Jenkins shared library** (Pipeline DSL only, no plugin yet) +
   docs. [1 day]

### v1.2 (when there's pull / first paid customer asks)
10. **Jenkins plugin** proper, published to plugins.jenkins.io.
    [5-8 days]
11. **Buildkite plugin** (1-2 days, do this opportunistically when
    a Buildkite shop asks).
12. **pre-commit hook** registration. [0.5 day, can move earlier
    cheaply]

### Defer until requested
- **TeamCity plugin** — only if a JetBrains-shop customer asks.
- **Drone plugin** — Docker image already covers it; only formalize
  if Harness STO ingestion becomes a deal driver.

---

## 5. Universal-Integration Angle Summary

The fastest way to make "we run iam-jit in CI" a true claim is *not*
to ship plugins faster. It's to ship the three universal substrates
(SARIF, JUnit, Docker image) so that on day one, every CI host listed
above has a working 5-10-line recipe. Each subsequent plugin then
becomes a polish layer on top of the substrate it already supports,
reducing risk on any single host bet and letting us prioritize plugin
order by customer pull instead of upfront speculation.

---

## 6. Sources

- Stack Overflow 2024 Developer Survey: https://survey.stackoverflow.co/2024/
- Stack Overflow 2024 results blog: https://stackoverflow.blog/2024/08/06/2024-developer-survey/
- JetBrains State of Developer Ecosystem 2024: https://www.jetbrains.com/lp/devecosystem-2024/
- Jenkins growth (CloudBees / CDF, 79% YoY pipeline growth): https://cd.foundation/announcement/2023/08/29/jenkins-project-growth/
- Jenkins market share (Datanyze): https://www.datanyze.com/market-share/ci--319
- Jenkins market share (Enlyft): https://enlyft.com/tech/products/jenkins
- Jenkins 2023 recap: https://www.jenkins.io/blog/2024/01/25/jenkins-2023-recap/
- Snyk CircleCI Orb: https://github.com/snyk/snyk-orb
- CircleCI Orb publishing docs: https://circleci.com/docs/orbs/author/create-test-and-publish-a-registry-orb/
- CircleCI Orbs registry: https://circleci.com/developer/orbs
- Snyk for GitLab: https://docs.gitlab.com/solutions/components/integrated_snyk/
- Semgrep for GitLab announcement: https://semgrep.dev/blog/2021/introducing-semgrep-for-gitlab/
- GitLab Unit test reports (JUnit): https://docs.gitlab.com/ci/testing/unit_test_reports/
- Bitbucket Pipes integrations: https://bitbucket.org/product/features/pipelines/integrations
- Snyk Bitbucket Pipe docs: https://docs.snyk.io/developer-tools/snyk-ci-cd-integrations/bitbucket-pipelines-integration-using-a-snyk-pipe
- Anchore Bitbucket Pipe: https://anchore.com/blog/announcing-anchore-scan-pipe-for-atlassian-bitbucket-pipelines/
- Snyk Azure DevOps Task (VS Marketplace): https://marketplace.visualstudio.com/items?itemName=Snyk.snyk-security-scan
- Snyk Azure DevOps task source: https://github.com/snyk/snyk-azure-pipelines-task
- Snyk Azure DevOps docs: https://docs.snyk.io/developer-tools/snyk-ci-cd-integrations/azure-pipelines-integration
- TeamCity Snyk plugin: https://docs.snyk.io/scm-ide-and-ci-cd-workflow-and-integrations/snyk-ci-cd-integrations/teamcity-jetbrains-integration-using-the-snyk-security-plugin
- JetBrains Marketplace TeamCity plugins: https://plugins.jetbrains.com/teamcity
- Building the Snyk Plugin for TeamCity (JetBrains blog): https://blog.jetbrains.com/teamcity/2019/05/building-the-snyk-plugin-for-teamcity/
- Buildkite agent hooks docs: https://buildkite.com/docs/agent/hooks
- Wiz Buildkite plugin (reference): https://github.com/buildkite-plugins/wiz-buildkite-plugin
- Buildkite enterprise positioning + customer list (Q1 2024): https://buildkite.com/resources/releases/2024-q1/
- Buildkite Scale-Out Delivery Platform launch (Oct 2024): https://www.businesswire.com/news/home/20241009617062/en/Buildkite-Launches-First-Scale-Out-Delivery-Platform-to-Bring-the-Engineering-Velocity-of-Top-Software-Companies-to-All-Enterprises
- Harness Drone CI Plugin Index: https://www.harness.io/blog/drone-ci-plugin-index
- Drone Plugins: https://plugins.drone.io/
- Harness acquires Drone: https://www.harness.io/blog/harness-acquires-ci-pioneer-drone-io-and-commits-to-open-source
- SARIF for code scanning (GitHub Docs): https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/sarif-support-for-code-scanning
- Uploading SARIF to GitHub: https://docs.github.com/en/code-security/code-scanning/integrating-with-code-scanning/uploading-a-sarif-file-to-github
- pre-commit framework: https://pre-commit.com/
- pre-commit.ci hosted service: https://pre-commit.ci/
- Jenkins JUnit plugin: https://github.com/jenkinsci/junit-plugin
- Azure DevOps enterprise adoption (Fortune 500): https://spacelift.io/blog/devops-statistics
