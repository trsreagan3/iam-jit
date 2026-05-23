# Changelog

All notable changes to iam-jit follow [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)
and adhere to semantic versioning per [docs/UPGRADING.md](docs/UPGRADING.md).

Calibration corpus + scorer rules ship pinned to the wheel
version in v1.0. A future release may split scorer version
from software version (see `docs/ROADMAP-V1.1.md`); changes to
the scorer corpus today are noted as `### Scorer` blocks
within the same release.

## Unreleased — Bounce-suite rename (2026-05-17)

### Documentation

- **#344 — Live dogfood loop: MEASURED audit-pinned profile hit-rate** (2026-05-23) —
  Ran the end-to-end chain (discovery → legit traffic → audit JSONL →
  `iam-jit profile generate-from-audit` → save → attempt install →
  adversarial → wire verdict) for I1 + D1 + G1 against shipped binaries
  with LocalStack, real Postgres, and a Python mock HTTP server.
  Surfaced two integration gaps that contradict the previously projected
  84.6% audit-pinned hit-rate per `[[scorer-is-ground-truth]]`:
  (1) the YAML schema emitted by `iam-jit profile generate-from-audit`
  (`denies: [{target, actions, reason}]`) does NOT match the parser in
  `src/iam_jit/bouncer/profiles.py:_profile_from_dict` which only
  understands `deny_actions` / `deny_keywords` / `allow_rules` — the
  generated YAML parses to an EMPTY Profile (verified by direct
  invocation; dbounce has the same shape mismatch);
  (2) `ibounce profile install --from` is HTTPS-only with no
  `file://` / local-path mode despite the quick-start in
  `docs/PROFILE-GENERATION.md` line 53 showing `bounce profile install
  --from ./profiles/`. Also surfaced that the local Ollama qwen2.5:7b
  backend emits inverse-of-correct rules for both I1 and D1 (denying
  the observed actions); deterministic-fallback is safety-floor-only.
  MEASURED hit-rate on end-to-end chain: 0/3 MEANINGFUL (3/3 PARTIAL).
  Full details + REASONED grades for adjacent scenarios in
  `tests/dogfood/role-effectiveness-grades-post-pivot.md` ("MEASURED
  via end-to-end live dogfood loop — 2026-05-23"). Recommendation:
  honest single-claim marketing number is the post-#324f 69.2%
  (dynamic-deny path IS wired end-to-end in prior measurement); do
  not claim 84.6% until the #326 profile-install path is wired
  end-to-end.

### Changed

- **#296 / §A22 — Cross-product concurrent-terminal ceiling lifted (audit-write hardening)** (2026-05-22) —
  Closes the cross-product launch-blocker that §B13 had documented as
  "1-3 concurrent terminals in v1.0; 10+ produces session-attribution
  issues." Diagnosis under a 20-session × 600-call SQLite load probe:
    - **ibounce (Python):** ALREADY passing — `BouncerStore.record_decision`
      under a global `threading.Lock` + PRAGMA `journal_mode=WAL` (set at
      Open) handles 20 concurrent writers at p99 = 10ms with 0 errors;
      end-to-end HTTP-level test (50 sessions × 10 RPS × 60s = 30,000
      reqs through the live aiohttp proxy) passes at p99 = 85.5ms with
      50/50 distinct session-id attribution intact. No ibounce code
      change shipped under §A22.
    - **kbouncer (Go):** CRITICAL — lost 11,791/12,000 audit rows to
      `SQLITE_BUSY`. Fixed by adding WAL + busy_timeout + synchronous=
      NORMAL PRAGMAs via DSN. Details in `kbouncer/CHANGELOG.md`.
    - **gbounce (Go):** CRITICAL — lost 11,804/12,000 audit rows.
      Same DSN PRAGMA fix. Details in `gbounce/CHANGELOG.md`.
    - **dbounce (Go):** functional but slow — p99 = 86ms, max = 1.4s
      tail. Fixed by ADDING WAL to the existing PRAGMA triple. The
      LOW-D8-12 `synchronous=FULL` durability posture is preserved
      (FULL is WAL-compatible). Details in `dbounce/CHANGELOG.md`.
  Verified ceiling after-fix: **30+ concurrent agent sessions on one
  machine, 0 errors, p99 < 50ms, 100% session-id attribution per
  bouncer.** `docs/KNOWN-CAVEATS.md` §A22 records the full diagnosis
  + verification matrix; §B13 marked RESOLVED.

### Added

- **#343 / §A24 — Pre-launch claims-vs-functionality audit fix sweep** (2026-05-23) —
  Closes 5 quick wins surfaced by the 2026-05-23 claims-vs-functionality
  audit:
    1. **H1 — Org-distribution doc overclaim**: docs claimed
       `bounce init --org-url` + `bounce profile sync` + ETag-based
       sync as shipped surface. Code only ships
       `ibounce profile install --from URL --sha256 <hex>`. Added a
       prominent v1.0-vs-v1.1 status note at the top of
       `docs/ORG-PROFILE-DISTRIBUTION.md`; reshaped §3 (Distribution
       mechanics), §4 (Engineer onboarding), §6 (Update flow), §7
       (CI/CD), §8 (Audit chain) so the v1.0-shipped flow is the
       PRIMARY path and v1.1 enhancements are marked PLANNED.
       README L436 + L489 updated to cite the actually-shipped CLI
       command.
    2. **H2 — Tag `RECOMMENDER-API-SPEC.md` status**: strengthened
       the status banner at the top of the spec so it's impossible
       to miss it's a design draft, NOT a v1.0 launch artifact, with
       pointers to the actually-shipped recommender code paths
       (`src/iam_jit/bouncer/recommender.py` per #173 and
       `src/iam_jit/dynamic_denies/recommender.py` per #324f).
       README MCP-tools list (§Status) footnotes
       `reduce_policy` / `get_reduction_checklist` /
       `apply_reduction_checklist` as design-draft.
    3. **M1 — Honest caveat for `secret:NAME` shorthand**: added a
       new bullet to `docs/DYNAMIC-DENY-RULES.md` "Honest caveats"
       documenting that `secret:NAME` shorthand fires at the bouncer
       layer only and is NOT embedded into iam-jit-issued role
       Deny statements (which require ARN-shaped targets per #324f).
       Operators wanting defense-in-depth at both layers should use
       the explicit `arn:aws:secretsmanager:*:*:secret:NAME-*` form.
    4. **M3 — gbounce LogWriter rotation footnote**: README L395
       audit-log paragraph now notes gbounce LogWriter-level rotation
       is deferred to v1.1 per KNOWN-CAVEATS §A10; gbounce ships
       the rotation primitives + CLI surface but the WRITER-side
       hook is pending.
    5. **Unit tests for `ProxyConfig.default_mode` property** (15
       tests in `tests/bouncer/test_default_mode.py`): exercises
       the discovery-vs-profile truth-table — `None` / `""` /
       `"full-user"` / `"none"` resolve to "discovery"; any other
       profile name resolves to "profile". Closes the load-bearing
       gap that the 38.5% / 69.2% / 84.6% role-effectiveness hit-
       rate numbers depend on (default-mode=discovery is the
       baseline they're measured against; a silent regression
       flipping the property would invalidate the published claims).

- **#342 / §A23 — Formal Apache-2.0 LICENSE + NOTICE files + README license attribution** (2026-05-23) —
  Closes the cross-suite license-file gap surfaced by the 2026-05-23
  verification (no LICENSE files in kbouncer; unfilled `[yyyy] [name of
  copyright owner]` boilerplate in iam-roles + gbounce; `Copyright 2026
  dbounce contributors` placeholder in dbounce; no NOTICE files
  anywhere; bare `## License` headers in the iam-roles + gbounce
  READMEs; missing `## License` sections in kbouncer + dbounce
  READMEs). Apache-2.0 with `trsreagan3` as the copyright holder per
  founder direction; same shape across all 4 repos so the suite
  presents one coherent license posture. iam-roles' `pyproject.toml`
  also gets `[tool.setuptools].license-files = ["LICENSE", "NOTICE"]`
  so the wheel ships both files (conservative; doesn't bump
  `setuptools>=68` to `>=77.0.3` purely for PEP 639's modernized
  `license-files` field). Unblocks: Anthropic Cyber Verification
  Program application (#338) + iam-jit-vs-OneCLI competitive-matrix
  accuracy + satellite-repo (#231 / #232 / #233) license alignment.
  Per-source-file SPDX-License-Identifier headers DEFERRED to v1.1 per
  `[[deliberate-feature-completion]]` (good hygiene, but adds churn to
  every source file — out of scope for this slice).

- **#324f — iam-jit recommender Deny-injection from dynamic-deny rules + role-effectiveness re-grade** (2026-05-22) —
  Closes the final slice of the #324 dynamic-deny family. The
  defense-in-depth half of the model: when iam-jit issues a new IAM
  role (`src/iam_jit/provision.py::provision()`), the inline policy
  it puts on that role now embeds an explicit `Deny` statement per
  active dynamic-deny rule that (a) routes to `ibounce` via
  `applied_to`, (b) has `applies_to_recommender: true`, (c) has at
  least one AWS-ARN-shaped target, and (d) has not expired. The
  embed runs AFTER the existing `_augment_policy_with_time_condition()`
  pass so every embedded Deny carries the DateLessThan time
  condition that bounds every Allow.
  - **New module `src/iam_jit/dynamic_denies/recommender.py`** —
    pure functions `build_deny_statements(ruleset)`,
    `embedded_rule_ids(ruleset)`, and
    `inject_into_policy(policy, ruleset)`. Each statement carries
    `Sid: "dynamicdeny<id>"` (IAM Sid grammar strips the underscore
    from `dd_<ULID>`), `Effect: "Deny"`, `Action: "*"`, `Resource:
    <rule.targets>` — operator reading the role policy in the AWS
    console can pattern-match all dynamic-deny statements with
    `grep dynamicdeny`. AWS evaluates explicit-Deny with absolute
    precedence over any Allow, so the embedded Deny fires even when
    the bouncer is bypassed.
  - **Provisioning helper `_build_issued_policy()`** —
    composes the time-condition augmentation with the dynamic-deny
    injection so the same call site can be used by both the preview
    + the live `provision()` path. Returns
    `(inline_policy, embedded_rule_ids)` so the caller can surface
    the rule ids on `ProvisioningResult.embedded_dynamic_denies` +
    on the audit emit.
  - **Env-var gate `IAM_JIT_DYNAMIC_DENIES_RECOMMENDER`** —
    default enabled (matches the existing
    `ProxyConfig.dynamic_denies_enabled` default from #324a).
    Setting to `0` / `false` / `no` / `off` short-circuits the
    injection for operators who want bouncer-only enforcement.
    Re-resolved on every issuance so a SIGHUP-style env refresh
    works without a process restart.
  - **Audit emission `request.provisioned_with_dynamic_denies`**
    — fires on every issuance that embedded at least one rule,
    carrying `details.unmapped.iam_jit.ext.embedded_dynamic_denies[]`
    + `details.unmapped.iam_jit.ext.embedded_dynamic_denies_count`.
    Best-effort: a broken audit sink never fails the issuance per
    `[[creates-never-mutates]]`. SIEM filter
    `kind:"request.provisioned_with_dynamic_denies"` answers
    "which role issuances embedded a dynamic-deny over the last
    N days?".
  - **Schema update** — `schemas/request.schema.json` gains an
    additive optional `status.provisioned.embedded_dynamic_denies`
    field (array of `dd_<ULID>` strings). Additive only — no
    schema_version bump per the cross-product convention.
  - **Tests** — `tests/recommender/test_dynamic_deny_injection.py`
    14 cases: embed for active ARN rule, skip non-ibounce rules,
    skip expired rules, multi-rule embed, no-YAML baseline, audit
    event carries `embedded_dynamic_denies`, hot-reload on YAML
    change, disabled-flag short-circuit, + pure-function unit tests
    for `build_deny_statements` (opt-out flag, non-mutation,
    non-ARN-target filtering, GovCloud + China partitions, IAM
    Sid legality, YAML round-trip).
  - **Role-effectiveness re-grade** — appended a
    "POST-#324f dynamic-denies" section to
    `tests/dogfood/role-effectiveness-grades-post-pivot.md`.
    **New hit-rate is 69.2% (9/13)** — 30.7 points above the
    post-pivot default of 38.5%, 0.8 points below the 70%
    launch-bar target. Dynamic-denies close 4 of 5 IAM-axis
    THEATER gaps (I1, I2, I4, K2 → MEANINGFUL); D1 stays THEATER
    because dbounce's dynamic-deny matcher operates at the
    connection level not the statement level (logged as v1.1
    candidate `KNOWN-CAVEATS.md §B18` per
    `[[scorer-is-ground-truth]]`).

  **Honest caveats:** existing roles minted BEFORE a deny lands
  keep the bouncer-only enforcement path until they expire at
  their TTL — we don't retroactively mutate existing roles per
  `[[creates-never-mutates]]`. The `secret:NAME` shorthand target
  shape (per the cross-protocol resolver) does NOT embed into the
  role policy at v1.0 — IAM's evaluator wants a full ARN in
  `Resource`; the bouncer-side path still enforces. v1.1
  enhancement could resolve the shorthand to
  `arn:aws:secretsmanager:*:*:secret:NAME*` at embed time.
  Statement-level dynamic-denies on dbounce remain a v1.1 candidate
  (logged at `KNOWN-CAVEATS.md §B18`).

- **#324e — iam-jit unified `deny` CLI + `bounce_deny_*` MCP tools + cross-bouncer fan-out** (2026-05-22) —
  Replaces the design-stage skeleton at `src/iam_jit/cli_deny.py`
  with the live implementation. With #324a/b/c/d already shipping the
  per-bouncer enforcement, this slice ships what operators actually
  type day-to-day:
  - **CLI:** `iam-jit deny add | list | remove | show` now reads +
    atomically writes `~/.iam-jit/dynamic-denies.yaml` (write-temp +
    rename + 0600) and POSTs each affected bouncer's
    `/admin/dynamic-denies/reload` endpoint. The flag shape mirrors
    the skeleton; success exits 0, operator-fixable errors exit 1.
  - **Cross-protocol target resolver
    (`src/iam_jit/dynamic_denies/resolver.py`):** ARN ->
    ibounce; `namespace:` / `cluster:` / k8s GVR shapes -> kbouncer;
    `rds:` / RDS-endpoint / DB-shaped hostnames -> dbounce + gbounce;
    URL / IP / CIDR / bare hostname -> gbounce. Unclassifiable
    targets are rejected at add-time with a structured error pointing
    to `--bouncer NAME` overrides per the design doc.
  - **Atomic writer (`src/iam_jit/dynamic_denies/store.py`):** ULID
    generator (`dd_<26-char-Crockford>`), Go-style duration parser
    (`30m`/`3h`/`7d`/`permanent`), `expires_at` computed at write
    time (no clock-drift extension on remote hosts), `ruamel.yaml`
    round-tripper preserves operator comments for hand-edited files.
  - **Fan-out (`src/iam_jit/dynamic_denies/fanout.py`):** POSTs each
    bouncer's reload endpoint with a 5s timeout. Unreachable bouncers
    are surfaced honestly (`[WARN] ibounce ... unreachable: ...`
    plus a `curl -XPOST ...` retry hint) but the CLI still exits 0 —
    the YAML file IS the source of truth, per
    `[[ibounce-honest-positioning]]`. `--bouncer-url NAME=URL`
    (repeatable) overrides the default 127.0.0.1 mgmt ports.
  - **MCP tools (`src/iam_jit/mcp_server.py`):** `bounce_deny_add`,
    `bounce_deny_list`, `bounce_deny_remove` share the operations
    backend with the CLI per `[[cross-product-agent-parity]]`.
    Each response carries both a structured payload + a human-
    readable `summary` so Claude can quote routing/expiry back to
    the operator.
  - **Audit:** best-effort `dynamic_deny.added` /
    `dynamic_deny.removed` admin-action OCSF events fire when the
    CLI/MCP runs inside a proxy emit context; honest no-op out of
    process.
  - **Tests:** `tests/cli/test_deny_real.py` (40 cases — resolver
    matrix, CLI happy + JSON + multi-target + remove + reason-match
    + unreachable-bouncer paths + MCP shape);
    `tests/integration/dynamic_deny_cross_product_test.py` (10 cases
    — boots 4 in-process HTTP fakes per the bouncer mgmt-port reload
    contract, walks the 9 brief scenarios + an honest-failure path).
  - **`[[creates-never-mutates]]`:** the original skeleton tests at
    `tests/cli/test_deny_skeleton.py` are preserved + skip-marked so
    the skeleton -> real-impl transition remains visible in history.

  **Honest caveats:** the per-bouncer reload endpoint is best-effort;
  if a bouncer is down, the rule lands in YAML but isn't live until
  the bouncer's watcher picks it up on next start. Org-distributed
  denies (`source: "org-distributed"`) cannot be loosened by a
  personal `iam-jit deny remove` — the request is refused with a
  structured pointer to the rule's `org_distributed_url`. Recommender
  Deny-injection (defense-in-depth in iam-jit-issued roles) lands in
  #324f.

- **#324a — ibounce dynamic-deny core (loader + watcher + matcher + mgmt endpoint)** (2026-05-22) —
  First implementation slice of the cross-product dynamic-deny rules
  surface (`docs/DYNAMIC-DENY-RULES.md`). ibounce now reads
  `~/.iam-jit/dynamic-denies.yaml` (override via
  `$IAM_JIT_DYNAMIC_DENIES_PATH` or `--dynamic-denies-path`), validates
  it against `docs/schemas/dynamic-denies-v1.json`, filters down to
  rules whose `applied_to` list contains `ibounce`, and matches each
  inbound request's resource ARN against the active rule set BEFORE
  the existing profile + global + task evaluation. A matching rule
  produces a DENY observation annotated with `deny_source="dynamic"`
  + `dynamic_deny_rule_id="dd_<ULID>"` + `dynamic_deny_pattern=<glob>`;
  the verdict reason surfaces both the rule id + the operator-supplied
  reason verbatim. Per the cross-product design's Conflict-resolution
  rules: static profile-DENY still wins (it short-circuits earlier);
  dynamic-deny beats every other ALLOW layer.
  - **New package `src/iam_jit/dynamic_denies/`** (`loader.py`,
    `matcher.py`, `watcher.py`, `types.py`) — JSON-schema-validated
    YAML loader; fsevents/inotify-driven hot reload via `watchdog`;
    AWS-IAM-style glob matcher (same grammar as
    `bouncer/rules.py`); cross-partition ARN support
    (`arn:aws:*`, `arn:aws-cn:*`, `arn:aws-us-gov:*`); `secret:NAME`
    shorthand for the common "lock out a specific secret" case.
  - **`ProxyConfig.dynamic_denies_enabled` + `.dynamic_denies_path`**
    fields plumb through `bouncer_cli.run_cmd`'s
    `--dynamic-denies-path` + `--disable-dynamic-denies` flags. Default
    enabled (no-op when the file is absent).
  - **`/admin/dynamic-denies/reload` mgmt-port endpoint** triggers an
    explicit reload, bypasses the 100ms debounce window, returns
    `{reloaded, rules_count, rules_applied_to_ibounce, rule_ids,
    source_path, loaded_at}`. Mirrors gbounce's #324d endpoint shape
    per `[[cross-product-agent-parity]]`.
  - **`/healthz` `dynamic_denies` block** surfaces
    `enabled / rules_count / rules_in_file / source_path /
    total_reloads / total_parse_errors / initial_load_error` so
    external monitoring detects stale snapshots without grep'ing the
    audit log.
  - **OCSF admin-action events** `dynamic_deny.reloaded` +
    `dynamic_deny.parse_error` ride the existing `#278` admin-action
    queue + `audit_export.admin_action.enqueue_admin_action`. The
    verdict-side `dynamic_deny_rule_id` annotation lands at
    `unmapped.iam_jit.ext.dynamic_deny_rule_id`.
  - **Tests**: `tests/dynamic_denies/test_loader.py` (41 cases —
    schema validation, partition coverage, glob matching, secret
    shorthand, filter behavior, expiry), `tests/dynamic_denies/
    test_watcher.py` (12 cases — initial load, file create / modify,
    debounce, parse-error retention, mgmt-endpoint reload),
    `tests/bouncer/test_dynamic_deny_integration.py` (9 cases —
    end-to-end evaluate_request + serve() + mgmt endpoint).
  - **Out of scope for this slice** (tracked separately): unified
    `iam-jit deny add | list | remove | show` CLI replacing the
    skeleton (#324e); MCP fan-out (#324e); recommender `Deny`-injection
    + role-effectiveness re-grade (#324f); kbouncer (#324b) /
    dbounce (#324c) parallel slices (live in their own repos).

  **Honest caveats:** the dynamic-deny match runs in the proxy hot
  path; a stale snapshot mid-watcher-reload is acceptable because the
  in-memory `RuleSet` is immutable + atomic-swapped, so concurrent
  reads never tear. On parse error the watcher retains the previous
  snapshot AND emits a `dynamic_deny.parse_error` admin-action event
  (fail-CLOSED per `[[ibounce-honest-positioning]]`). The dynamic-deny
  path is bypassable by an agent that calls AWS directly without
  routing through ibounce; defense-in-depth via role-issuance
  embedding ships in #324f.

### Changed

- **BREAKING — §A21 / [[discovery-first-default]] — ibounce default flips to DISCOVERY MODE** (2026-05-22) —
  Per the role-effectiveness eval at `tests/dogfood/role-effectiveness-grades.md`
  the v1.0 safe-default profile landed at 23.1% hit-rate vs the 50% launch bar:
  NEGATIVE-VALUE over-blocking (K1/K3/D2) + THEATER under-scoping on reads
  (I1/I4/K2/D1) dominated. gbounce alone hit 66.7% because its primitives
  (deny_hosts + MITM URL+method) are operator-set OPT-IN denies, not blanket
  safe-defaults. The pivot flips ibounce to match gbounce's shape: default
  behavior is observe + audit + pass-through (the `full-user` profile), with
  named profiles (safe-default, plus any operator-curated profile) as
  OPT-IN via `--profile <name>` or `IAM_JIT_BOUNCER_PROFILE`.
  - **`ProxyConfig.default_mode` (new property):** surfaces `"discovery"` |
    `"profile"` for cross-product symmetry + agent introspection. `discovery`
    fires when `active_profile` is None or resolves to `full-user`/`none`;
    `profile` fires when the operator explicitly picked a named profile.
    Per [[cross-product-agent-parity]]: same semantic shape across kbouncer +
    dbounce + gbounce.
  - **Startup banner (refreshed):** explicitly names the operating shape
    ("default mode: discovery — observing all requests, denying none.") +
    surfaces `default_mode=discovery|profile` on the headline `ibounce
    proxy starting on ...` line. Per [[security-team-positioning-safety-
    not-surveillance]]: framed as audit transparency, NOT "we're not
    enforcing anything." Named-profile opt-in instructions stay one line
    away.
  - **Named profiles preserved:** `safe-default` (readonly-admin-minus
    floor) + any custom profile in `~/.iam-jit/bouncer/profiles.yaml`
    continue to work exactly as before; operators who want pre-pivot
    behavior pin `ibounce run --profile safe-default` or `export
    IAM_JIT_BOUNCER_PROFILE=safe-default` in their shell rc.
  - **No code path lost:** the recommender (#173), plan-capture (#132),
    OCSF audit pipeline, agent attribution (#318/#320), and the entire
    enforcement stack still fire; the change is which DEFAULT rule layer
    is active out of the box.

  **BREAKING-CHANGE:** operators upgrading from pre-pivot v1.0 builds
  where ibounce auto-applied the safe-default profile would see writes
  unconditionally blocked. After this change, fresh installs and
  upgrades land in discovery mode by default; existing operators must
  explicitly pin `--profile safe-default` to keep the pre-pivot behavior.
  See `docs/PROFILE-UPGRADE.md` + KNOWN-CAVEATS §A21 for the upgrade
  path; the re-graded corpus lives at `tests/dogfood/
  role-effectiveness-grades-post-pivot.md`.

### Fixed

- **§A20 R3-01 — `ibounce run` crashed on `--audit-log-max-size-mb` / `--audit-log-max-age-days` / `--audit-db-retention-days`** (2026-05-22) —
  `src/iam_jit/bouncer_cli.py` declared the three rotation click options
  (per the §A10 LOG-RETENTION cross-product spec) + passed them as
  kwargs into `ProxyConfig(...)`, but `src/iam_jit/bouncer/proxy.py`'s
  dataclass didn't declare the fields. Result: every `ibounce run`
  invocation that passed any rotation flag crashed immediately with
  `TypeError: ProxyConfig.__init__() got an unexpected keyword
  argument 'audit_log_max_size_mb'`. The flags were advertised in
  `--help` + `docs/LOG-RETENTION.md`; both said "works"; neither did.
  Surfaced by UAT round 3 (`tests/dogfood/findings-2026-05-22-round-3.md`).
  Fix: `ProxyConfig` gains three `int | None = None` fields with
  documented "None = shipped default; 0 = explicitly disabled"
  semantics (per the Go bouncer convention documented in
  [[cross-product-agent-parity]]). `serve()` threads
  `audit_log_max_size_mb` + `audit_log_max_age_days` into
  `AuditLogWriter(max_size_mb=..., max_age_days=...)` at startup;
  the startup log line now surfaces all three effective values.
  New regression suite `tests/bouncer/test_ibounce_run_smoke.py`
  (7 cases) covers dataclass acceptance, None/0 semantics, CliRunner
  end-to-end `run --audit-log-max-size-mb ...` no longer raising
  TypeError, AuditLogWriter receiving the threaded values, and a
  source-level guard that the writer init mentions both rotation
  kwargs (defensive against a refactor that adds fields but forgets
  to wire them). KNOWN-CAVEATS §A20.

### Added

- **#321 / §A19 — `ibounce profile doctor` + cross-product upgrade-blindness fix** (2026-05-22) —
  Closes the D3 launch-blocker surfaced by the role-effectiveness eval
  2026-05-22 (a dbounce operator who installed pre-#302 was silently
  running without `deny_dcl_targets_public`; ibounce + kbouncer share
  the same "never-overwrite-once-exists" architecture and were
  vulnerable to the same pattern).
  - **ibounce** — new `src/iam_jit/bouncer/profile_doctor.py` module
    with `check()` / `apply()` / `acknowledge()` / `is_acknowledged()`
    / `startup_banner_line()` / `format_report()` /
    `report_to_json_str()`. `apply()` additively merges missing
    default fields + backs up the prior file before write per
    [[creates-never-mutates]] — operator-customized field values are
    NEVER overwritten. `bouncer_cli.py` gains `ibounce profile
    doctor` subcommand with `--apply` / `--acknowledge` / `--diff`
    / `--check` / `--json` flags (same shape across all 4 Bounce
    products per [[cross-product-agent-parity]]). `ibounce run`
    emits a §A19 startup-banner caveat when a safety-floor field is
    missing AND the operator hasn't acknowledged the current
    shipped-defaults version. Per
    [[security-team-positioning-safety-not-surveillance]]: framed as
    "your profile is behind" not "you are non-compliant."
  - **Cross-product integration test** —
    `tests/integration/profile_upgrade_doctor_test.py` boots each of
    the 4 bouncer binaries, seeds a pre-floor profile shape, asserts
    `profile doctor` reports the missing safety-floor field with the
    correct category, asserts `--apply` merges + writes a timestamped
    backup, asserts post-apply state is current. The D3 role-
    effectiveness scenario now grades MEANINGFUL not PARTIAL after
    `--apply`.
  - **Docs** — new `docs/PROFILE-UPGRADE.md` operator-facing runbook.
    `docs/KNOWN-CAVEATS.md` adds §A19 entry between §A18 and the
    next section.
  - **Per-product slices** — see `dbounce/CHANGELOG.md`,
    `kbouncer/CHANGELOG.md`, `gbounce/CHANGELOG.md` for the per-
    product portions. All 4 ship together per
    [[deliberate-feature-completion]].

- **#320 / §A18 — `/audit/events` wire-shape parity fix** (2026-05-22) —
  closes a UAT-discovered CRIT: the HTTP `/audit/events` endpoint
  that powers `iam-jit audit query` was emitting an empty agent
  block on dbounce events + mis-labelling `detected_from` on
  kbouncer events. The cross-bouncer "query by agent.session_id"
  claim from §A16 was wire-protocol false for SOC analysts.
  - **iam-jit CLI** — `cli_audit_query.py` gains
    `_expand_short_form_filter` + `_expand_short_form_filters`
    helpers that translate `agent.session_id=X` /
    `agent.name=X` / `agent.detected_from=X` to their canonical
    `unmapped.iam_jit.agent.*` long forms client-side before
    forwarding. Closes the UAT-surfaced "spec example returns
    HTTP 400" gap — operators copy-pasting from the docs now
    just work.
  - **ibounce audit_export** —
    `extract_agent_headers_with_rejections` (additive sibling to
    the existing 2-tuple `extract_agent_headers`) returns the
    structured rejection breadcrumb list. New cross-product
    bounded enum constants
    (`AGENT_HEADER_REJECTION_INVALID_NAME_CHARSET` etc.) +
    `build_agent_header_rejection_breadcrumb` helper. Lands at
    `unmapped.iam_jit.ext.agent_header_rejection` via
    `audit_event_from_decision(agent_header_rejections=...)`.
  - **Cross-product test** —
    `tests/integration/audit_events_wire_parity_test.py` brings
    up all four bouncers, fires one request per bouncer with a
    shared session id, hits each `/audit/events` endpoint
    directly, asserts the agent block lands with the correct
    `detected_from` per transport, AND runs
    `iam-jit audit query --filter agent.session_id=X` (short
    form) + asserts 4 events back.
  - **Docs:** `docs/KNOWN-CAVEATS.md` §A18 entry between §A16 +
    §A17 mirroring the §A16/§A17 diagnostic + fix shape.
    `docs/AGENT-ATTRIBUTION.md` gains the
    `agent_header_rejection` breadcrumb wire-shape section with
    the bounded enum table + SIEM-query example.
  - Closes `[[cross-product-agent-parity]]` for the audit-events
    wire-protocol surface.

- **#317 / §A15 — cloud-neutral S3-compatible NDJSON object-storage sink** (2026-05-22) —
  closes the headline cloud-neutrality gap surfaced by founder
  direction 2026-05-22: bouncers other than ibounce are
  cloud-neutral; the AWS-only Security Lake adapter (#258) alone
  doesn't serve operators on GCS / Azure Blob / MinIO / R2 / B2 /
  DigitalOcean Spaces. ibounce ships the new sink alongside the
  existing JSONL + webhook + Security Lake transports per
  [[creates-never-mutates]] (additive composition).
  - `ibounce run --audit-object-storage-endpoint URL
    --audit-object-storage-bucket NAME
    --audit-object-storage-prefix PREFIX
    --audit-object-storage-region REGION
    --audit-object-storage-credentials-file PATH
    --audit-object-storage-rotation-minutes N
    --audit-object-storage-max-size-mb N
    --audit-object-storage-instance-id ID` — generic S3-compat sink.
    Same flag shape ships on kbouncer + dbounce + gbounce per
    [[cross-product-agent-parity]].
  - New module: `src/iam_jit/bouncer/audit_export/object_storage.py`
    — `ObjectStorageWriter` (background-rotated; refuse-to-start
    HeadBucket probe; fail-soft Write; synchronous flush on stop) +
    `ObjectStorageCredentials` + `LoadObjectStorageCredentials`
    (env-var precedence; YAML / INI credentials file overrides).
  - Output layout: NDJSON (one OCSF event per line),
    gzip-compressed, Hive-partitioned at
    `{prefix}/year=YYYY/month=MM/day=DD/hour=HH/{product}-{instance_id}-{timestamp}.jsonl.gz`.
    Athena / BigQuery / Spark / Trino auto-discover the partitions;
    SIEM collectors `LIST + GET` against the prefix.
  - Per-instance file naming derives `instance_id` from
    `hostname-pid` (override with `--audit-object-storage-instance-id`)
    so multiple bouncer instances writing the same bucket get
    collision-free paths.
  - `bouncer/proxy.py` wires the writer through the existing
    `_emit_audit_event_raw` fan-out alongside the JSONL + webhook +
    Security Lake channels. Default OFF; only constructed when
    `--audit-object-storage-bucket` is set. `Start()` issues a
    HeadBucket probe so credential / endpoint / bucket-name
    misconfigurations surface immediately rather than at first
    flush.
  - Per [[self-host-zero-billing-dependency]]: destination is
    operator-owned (operator creates the bucket; bouncer never
    creates buckets). Per [[don't-tailor-to-lighthouse]]: generic
    S3-compat; works with AWS S3 (native), GCS (S3 interop / HMAC),
    Azure Blob (S3-compat layer), MinIO, Cloudflare R2, Backblaze
    B2, DigitalOcean Spaces.
  - Cross-product wire-format invariants (partition path, file
    naming, gzip-NDJSON shape) fixed in
    `tests/integration/object_storage_sink_test.py`.
- **What does NOT ship in v1.0** (deferred to v1.1 per
  [[don't-tailor-to-lighthouse]]): native GCS auth (Workload
  Identity / Service Account) + native Azure Blob auth (Managed
  Identity). S3 interop covers ~95% of operators today.
- **Regression tests:** `tests/bouncer/test_audit_export_object_storage.py`
  — 27 tests cover defaults, credentials resolution (env + YAML +
  INI), partition path format, construction refusal, write/flush
  happy path, status surface, size-cap synchronous flush,
  drop-on-buffer-full, write-before-start no-op,
  stop-flushes-pending, put_object failure -> writes_ok=false, and
  the rotation timer triggering a background flush.
- **Docs:**
  - `docs/PRODUCTION-LOG-STORAGE.md` — new "Cloud-neutral S3-compat"
    row in the §1 decision table; new §2.4b section detailing the
    sink with a multi-cloud endpoint reference; §2.5 GCP +
    §2.6 Azure updated to recommend the new sink as the preferred
    path for cold-storage / archive.
  - `docs/KNOWN-CAVEATS.md` §A15 → `STATUS: FIXED 2026-05-22`.
- **Task:** #317 — completed 2026-05-22.
- **#318 / §A16 — cross-bouncer X-Agent-Session-Id header parity** (2026-05-22) —
  closes the headline cross-bouncer correlation gap surfaced by the
  #312 NanoClaw integration test. ibounce now reads inbound
  `X-Agent-Name` + `X-Agent-Session-Id` headers at HIGHEST detection
  precedence (above MCP / User-Agent / process-tree). Cross-product
  invariants mirrored from gbounce's #308 reference:
  - `src/iam_jit/bouncer/audit_export/agent_context.py` gains
    `extract_agent_headers()` + `is_valid_agent_name()` +
    `is_valid_agent_session_id()` + `total_agent_headers_rejected()` +
    `reset_agent_headers_rejected_for_tests()`. Header validators
    match gbounce's regexes byte-for-byte (`[A-Za-z0-9._-]{1,64}` for
    name, `[A-Za-z0-9_-]{1,128}` for session_id) so a SIEM query on
    `unmapped.iam_jit.agent.session_id=X` is portable across products.
  - `resolve_agent_block()` accepts `header_agent_name` +
    `header_agent_session_id` kwargs; populates `detected_from=
    "http_header"` when both validate, `"http_header_name_only"` when
    only the name validates, and overlays the explicit session_id
    onto downstream detection sources (MCP / UA / process-tree) so
    cross-bouncer correlation works even when the name fell through.
  - `audit_event_from_decision()` threads the new kwargs through to
    the OCSF event.
  - `bouncer/proxy.py:evaluate_request` extracts the headers once +
    threads them through all three `audit_event_from_decision` call
    sites (unclassifiable-deny, profile-deny, normal decision).
  - Invalid headers are dropped (audited as anonymous) with one
    stderr log line + the `audit_export.total_agent_headers_rejected`
    counter on `/healthz` bumped. Header values are truncated + have
    control characters stripped before logging so a malicious header
    can't reposition the operator's terminal cursor.
  - 47 new regression tests in
    `tests/bouncer/test_agent_headers_318.py` covering validator
    regex parity, extract / rejection counter, resolver precedence
    (header > MCP > UA > PID), partial-detection shape, and the
    canonical cross-product test names
    (`test_AgentHeaders_HappyPath` etc).
  - `docs/AGENT-ATTRIBUTION.md` extended with the dbounce SQL
    `application_name=iam-jit-agent:NAME:SESSIONID` convention.
  - `docs/KNOWN-CAVEATS.md` §A16 marked `STATUS: FIXED 2026-05-22`.
  - `docs/INTEGRATION-OPENCLAW-NANOCLAW.md` §B16 (gbounce-only gap
    note) updated — parity now ships pre-launch.
  - Sibling Bounce products (kbouncer / dbounce) ship the same
    surface; see their respective `CHANGELOG.md` entries.
  - Cross-product integration test at
    `tests/integration/cross_bouncer_session_id_parity_test.py`
    asserts a single `iam-jit audit query --filter agent.session_id=
    <UUID>` returns one event per bouncer.

- **#311 / §A10 — robust local audit-log retention** (2026-05-22) —
  cross-product launch-blocker resolved. Ships
  `docs/LOG-RETENTION.md` (cross-product runbook with defaults table,
  CLI flags, `/healthz` shape, "audit log degraded" operator runbook,
  parity matrix). On the `ibounce`/`AuditLogWriter` side:
  - New `src/iam_jit/bouncer/audit_export/rotation.py` with `rotate`,
    `recover_partial_tail`, `purge_older_than`, `archive_logs`,
    `verify_integrity`, `disk_status`, `rotate_db_daily`,
    `should_rotate_by_{size,age}`
  - `AuditLogWriter` extended with `max_size_mb` (default 100) +
    `max_age_days` (default 7) + rotation/recovery callbacks; status
    payload now includes `rotations`, `rotation_failures`,
    `last_rotation_at_unix`, `last_rotation_path`,
    `partial_bytes_recovered`
  - Startup partial-tail recovery: corrupt trailing JSONL line
    truncated automatically; emits `audit.log.recovered_partial`
    admin-action
  - Five new admin-action kinds: `audit.log.rotated`,
    `audit.log.rotation_failed`, `audit.log.recovered_partial`,
    `audit.log.purged`, `audit.log.archived` (all five
    registered in `KNOWN_ADMIN_ACTION_KINDS` so the dispatcher
    routes them correctly)
  - New `ibounce logs purge --older-than DURATION --yes` /
    `ibounce logs archive --out FILE [--exclude-active]` /
    `ibounce logs verify [--json]` CLI subcommands
  - New `ibounce doctor logs` health check: integrity + freshness
    + retention + disk; exits non-zero on any failure
  - 30 new tests in `tests/bouncer/test_audit_export_rotation.py`
    covering rotation, recovery, purge, archive, integrity, disk
    classification, and AuditLogWriter integration
  - `docs/KNOWN-CAVEATS.md` §A10 marked `STATUS: FIXED 2026-05-22`
  - Sibling Bounce products (kbounce / dbounce / gbounce) ship the
    same surface; see their respective `CHANGELOG.md` entries.

- **#308 — gbounce agent-identity attribution + cross-bouncer doc**
  (2026-05-22) — closes the last `[[agent-identity-in-audit]]`
  (#266) parity gap. gbounce events now carry the same
  `unmapped.iam_jit.agent.{name,session_id,detected_from}` block as
  ibounce + kbounce + dbounce, so `iam-jit audit query --filter
  unmapped.iam_jit.agent.session_id=...` resolves gbounce events the
  same way it resolves the other three products. iam-roles-side
  artifacts:
  - **`docs/AGENT-ATTRIBUTION.md`** — new cross-suite doc: the two
    HTTP headers (`X-Agent-Session-Id` + `X-Agent-Name`),
    validation rules, per-runtime setup (Claude Code / Cursor /
    Codex / Devin / OpenClaw / custom), the
    `[[security-team-positioning-safety-not-surveillance]]`
    framing, anonymous-fallback semantics, failure modes.
  - **`docs/KNOWN-CAVEATS.md` §A9** — new entry documents the
    pre-#308 gap + the post-fix invariant + the regression-test
    pointers.
  - **`ibounce mcp show-config` / `install-*`** — the canonical
    snippet now stamps `IBOUNCE_AGENT_NAME` +
    `IBOUNCE_AGENT_SESSION_ID` env vars on the generated MCP server
    entry. `install-claude-code` defaults to `claude-code`;
    `install-cursor` to `cursor`; `install-codex` to `openai-codex`.
    The footer now points operators at `docs/AGENT-ATTRIBUTION.md`
    for per-runtime patterns. Regression test:
    `test_show_config_mentions_agent_attribution_doc` +
    updated `test_show_config_emits_valid_json_with_ibounce_entry` in
    `tests/bouncer/test_mcp_install.py`.
  - **Cross-bouncer query test** —
    `test_query_filter_by_agent_session_id_resolves_gbounce_events`
    in `tests/test_cli_audit_query.py` verifies the `iam-jit audit
    query --filter unmapped.iam_jit.agent.session_id=...` flow
    against a gbounce-shaped mock bouncer end-to-end.

- **#304 — KNOWN-CAVEATS discoverability surfaces** (2026-05-22) —
  per founder direction, caveats are now surfaced at five sites
  instead of being buried in `docs/KNOWN-CAVEATS.md`:
  - `src/iam_jit/bouncer/caveats.py` — new module centralizes the
    ibounce-relevant §B entries (B1, B2, B3, B4, B10, B11, B12
    product-related; B13, B14, B15 cross-product) + their canonical-
    doc anchors. `caveats.banner_lines(Trigger)` returns the runtime-
    triggered banner output; `caveats.doctor_entries()` returns the
    full applicable list; `caveats.link_suffix(id)` produces the
    inline `(see KNOWN-CAVEATS §X: <URL>)` suffix for error responses.
    Mirrors the Go `internal/caveats` packages in gbounce / kbounce /
    dbounce per `[[cross-product-agent-parity]]`.
  - **README "Known limitations" section** — top 3 ibounce-relevant
    §B entries (B1 / B3 / B4) linked to the canonical doc; sits under
    the existing ibounce-product section.
  - **Startup banner** — `ibounce run` emits the §B1 line on every
    startup (the SigV4-only shape is structural) + the §B3 line when
    `--profile safe-default` is active. Quiet otherwise.
  - **`iam-jit doctor caveats`** — new subcommand under the existing
    `bouncer_cli` doctor group (same group that hosts `doctor logs`
    + `doctor compatibility`). Matches the `*bounce doctor caveats`
    shape sibling products ship.
  - **MCP tool descriptions** — `bouncer_active_mode` description
    now embeds a §B4 reference + link (agents reading `tools/list`
    see the verb-level / content-aware caveat at registration time,
    before the first tool call).
  - **Error message links** — the cooperative-mode "unclassifiable
    request" 400 body appends `(see KNOWN-CAVEATS §B1: <URL>)` to
    the hint string + emits a `caveat_url` field; the transparent-
    mode 403 DENY body appends `(see KNOWN-CAVEATS §B4: <URL>)` to
    the decision_reason + emits a `caveat_url` field. Per
    `[[security-team-positioning-safety-not-surveillance]]` the link
    is helpful framing, not accusatory.

- **random-policy fuzz methodology** (founder direction
  2026-05-22, `scripts/random_policy_fuzz.py` +
  `scripts/random_policy_fuzz_oracle_prompt.md` +
  `scripts/random_policy_fuzz_compare.py` +
  `docs/RANDOM-FUZZ-METHODOLOGY-2026-05-22.md`) — generator
  samples 2-5 AWS-managed policies uniformly at random (50%
  pairs / 30% triples / 15% quads / 5% pentuples), concatenates
  their `Statement` blocks (with statement-level dedupe), and
  scores each composite LOCALLY via `iam_jit.review.analyze_policy`
  — no LLM calls in any iam-jit script. Initial 100-composite
  batch at `seed=42` lands in
  `tests/calibration_corpus/random_composites/` and is content-
  hashed for cross-run dedupe. The oracle phase (Opus judgment)
  is a separate manual step using the documented prompt; the
  comparison script classifies each composite per the rubric
  (CALIBRATED / DRIFT / UNDER_FLAG / OVER_FLAG / LIKELY_BUG) +
  emits `docs/RANDOM-FUZZ-RESULTS-{date}.md`. Per
  `[[scorer-is-ground-truth]]` the scorer is NOT auto-tuned to
  match Opus; promotion of LIKELY_BUG cases to
  `bug_regressions/` is a deliberate manual step. Calibration
  loader (`tests/test_calibration_corpus.py`) explicitly skips
  the `random_composites/` subdir because composites carry a
  `scores`-style schema (not the `expected`-assertion schema).
  Regression coverage in
  `tests/scripts/test_random_policy_fuzz.py` (3 tests:
  determinism + content-hash dedupe + det_score populated on
  every composite).

### Fixed

- **#319 / §A17 — UAT findings cluster: cross-product CLI parity + doc-truth-up gaps** (2026-05-22) —
  Closes the 1 CRIT + 5 HIGH + 4 MED launch-blockers surfaced by the
  dogfood UAT loop on 2026-05-22. The ibounce + iam-roles slice:
  - **F-316-1 (CRIT)** — `docs/PRODUCTION-LOG-STORAGE.md` §2.7 rewritten to use the actual graceful-shutdown drain (SIGTERM → audit-channel `.stop()` chain in `bouncer/proxy.py`'s shutdown finalizer drains in-flight webhook + JSONL + SQLite writes before returning) instead of the nonexistent `ibounce audit-export flush --wait DUR` subcommand. Belt-and-braces: §2.7 also recommends pairing `--audit-webhook-url` with `--audit-log-path` so a webhook outage during shutdown still leaves a local file for post-job upload. The "Why not `flush --wait`?" sub-section names the engineering reason (the signal handler IS the drain; a duplicate flush RPC would introduce a new failure mode).
  - **F-311-4 (HIGH)** — added `--audit-log-max-size-mb` + `--audit-log-max-age-days` + `--audit-db-retention-days` click options on `ibounce run` with matching `IBOUNCE_AUDIT_LOG_MAX_SIZE_MB` / `_MAX_AGE_DAYS` / `_DB_RETENTION_DAYS` env-var overrides. Wired into `AuditLogWriter.__init__(max_size_mb=..., max_age_days=...)` so the live writer rotates per the cross-product LOG-RETENTION.md spec. New fields on `ProxyConfig` (`audit_log_max_size_mb`, `audit_log_max_age_days`, `audit_db_retention_days`) preserve `None`-means-default semantics; `0` explicitly disables a trigger.
  - **F-316-2 (HIGH)** — `docs/PRODUCTION-LOG-STORAGE.md` TL;DR table swaps the gbounce GCP row to ibounce + adds an explicit "(gbounce v1.0: use JSONL + Fluent Bit / Vector — see §3 gap)" annotation. The per-product parity matrix already correctly scoped webhook export to G-Slice 6 / v1.1; the TL;DR row was the remaining inconsistency.
  - **`docs/LOG-RETENTION.md` updated** — CLI flags section now documents the env-var override shape across all four products + the per-product writer-level wiring matrix (ibounce / kbounce / dbounce: live writer; gbounce: flag accepted + on-demand purge path, writer-level rotation deferred per the existing parity matrix).
  - **§A17 in `docs/KNOWN-CAVEATS.md` flipped to `STATUS: FIXED 2026-05-22`** with per-finding closure notes documenting which findings were real-and-fixed vs already-fixed-and-the-doc-was-stale.
  Regression coverage: `test_run_help_documents_rotation_flags` in `tests/bouncer/test_proxy_wb32_closures.py` asserts all three flags + all three env-var names surface in `ibounce run --help`. Full ibounce regression suite (1421 tests) continues to pass.

- **ibounce hardcoded HTTPS upstream scheme** (UAT 2026-05-22
  Variant A + C, KNOWN-CAVEATS A3, task #300,
  `src/iam_jit/bouncer/proxy.py` + `src/iam_jit/bouncer_cli.py`) —
  the bouncer always forwarded over HTTPS to the inbound SigV4-
  signed Host header, so pointing it at LocalStack
  (`http://127.0.0.1:4566`) failed and UAT had to bypass ibounce
  for every write. CRITICAL launch-blocker. Adds `ibounce run
  --upstream URL` flag with new `parse_upstream_url(url)` helper
  that extracts scheme + host:port + validates scheme ∈ {http,
  https} (rejects `ftp://`, `file://`, schemeless URLs at startup
  with a clear error). New `ProxyConfig.forward_host_override`
  field threads the parsed host through both `_forward_to_aws`
  call sites; existing CRIT-32-01 outbound-host allowlist still
  gates the override target. Default behaviour unchanged when
  `--upstream` is unset (forward to signed Host over HTTPS — the
  real-AWS shape). Regression coverage in
  `tests/bouncer/test_proxy_upstream_scheme.py` (14 tests: parser
  unit + CLI-startup-rejection + end-to-end mock-LocalStack +
  no-override regression-guard). End-to-end verified against
  LocalStack 3.8 on 2026-05-22:
  `list_buckets / create_bucket / put_object / get_object` all
  200 through `ibounce --upstream http://127.0.0.1:4566 --mode
  transparent`, audit log shows `allow` verdicts on each call.

- **Solo-mode self-approve deadlock** (Variant B UAT finding #2,
  `src/iam_jit/routes/requests.py`) — `IAM_JIT_DEPLOYMENT_MODE=solo`
  enabled the self-approve-reductions gate but the auto-approve
  override in `_apply_mfa_and_self_approve_enforcement` only fired
  on `auto_decision.reason == "above_threshold"`. Solo deployments
  default to `auto_approve_risk_below=None` so the route returned
  `feature_disabled` instead — the override never had a chance and
  the admin's own reduction landed in `pending`, where the
  four-eyes check in `lifecycle.py` refused approver==owner. Net
  effect: every solo founder ran into a deadlock on their first
  request. Fix extends override-eligible reasons to include
  `feature_disabled`. Strict-mode, toggle, blocklist, and quota
  denials remain non-overrideable (platform floors). Per the
  [[self-approve-reductions]] memo the skip is APPROVAL, not
  AUDIT — the `request.auto_approved` audit event still emits
  with actor `self_approve_reduction:<user.id>`, and the
  `original_reason` field on the override now carries through the
  pre-override reason (`feature_disabled` or `above_threshold`)
  for the audit trail. Adds 4 route-level regression tests in
  `tests/test_routes_requests.py` and 4 helper-level tests in
  `tests/test_mfa_self_approve_enforcement.py` covering the
  override-eligible vs floor-protected reasons.

### Docs

- **LLM-backend reframe in `docs/DEPLOYMENT.md`** — Step 5 now
  presents the four supported LLM backends (Bedrock / Anthropic
  API / OpenAI API / Ollama) as equal first-class choices with a
  per-backend cost-per-1k-scores table, instead of recommending
  Bedrock as the default. Notes that Bedrock requires a one-time
  per-account model-access approval (with variable lead time) and
  that the other three backends have no AWS-side approval gate.
  Bedrock-specific sections (AWS Budget alarm, model-access
  prerequisite, pilot parameter set) now carry "Bedrock-only"
  banners pointing operators at the equivalent path for the other
  backends. Companion polish in `docs/ENTERPRISE-SELF-BOOTSTRAP.md`
  to add OpenAI to the LLM-backend list. No code changes.

### Added

- **Pluggable LLM-backend abstraction** (`src/iam_jit/llm/`) — the
  Pro-tier LLM call is now a 4-way choice (Bedrock / Anthropic API /
  OpenAI API / Ollama) selected by `IAM_JIT_LLM_BACKEND` env or
  per-account `llm_preferred_backend`. Backs the doc claims that
  shipped in `d31d8e4`. Old single-file `src/iam_jit/llm.py` is now
  a package; every back-compat import path (`NoOpBackend`,
  `OllamaBackend`, `AnthropicBackend`, `BedrockBackend`,
  `RecordingBackend`, `CassetteMiss`, `wrap_with_cassette`, `_parse`,
  `_cassette_key`, `get_backend`, `get_backend_for_tier`,
  `LLMBackend`, `SYSTEM_PROMPT`) is preserved verbatim. New public
  surface: `score_policy()`, `default_score_backend()`,
  `get_score_backend()`, `available_backends()`, `ScoreContext`,
  `ScoreResponse`. Per-account `LLMDecision` now carries
  `preferred_backend` so the score route can route prod accounts to
  a specific provider. `pyproject.toml` adds per-backend extras
  (`[bedrock]`, `[anthropic]`, `[openai]`, `[ollama]`,
  `[all-llm-backends]`); the legacy `[llm]` extra keeps mapping to
  Anthropic for back-compat. New ops doc at `docs/LLM-BACKENDS.md`.
  Closes the doc/code gap from `d31d8e4` (Bedrock 30-60 day approval
  lead time, see `[aws-account-verification]`).

- **AWS-usage builder cron** (`scripts/aws_usage_builder.py`) — tiny
  operator-side daily job that warms an AWS account with three cheap
  no-op calls per day (`s3:PutObject` of a 1-byte file,
  `cloudwatch:PutMetricData` against namespace `iam-jit/usage-builder`,
  and `ec2:DescribeRegions`) to build usage + billing history per
  Amazon's 2026-05-19 Bedrock denial-email guidance ("Continue to
  actively use other AWS services on your account to build Usage and
  billing history"). Refuses to run without `IAM_JIT_USAGE_BUCKET` or
  configured credentials; partial failures don't abort the run; exits
  non-zero only when ALL three calls fail (cron-friendly). Logs to
  `~/.iam-jit/aws-usage-builder.log`. Cost: well under $1/month at
  one tick per day. Per `[[creates-never-mutates]]` read-only on the
  operator's machine outside the log file + the 1-byte S3 object. Per
  `[[self-host-zero-billing-dependency]]` talks only to the operator's
  own AWS account; no phone-home. Crontab template
  (`scripts/aws_usage_builder.crontab.example`) + setup README
  (`scripts/README.md`) included. 6 moto-mocked tests in
  `tests/scripts/test_aws_usage_builder.py`.

- **Per-org notification routing engine** (#280; ENTERPRISE tier) — new
  `--alert-routes ROUTES.yaml` flag on `ibounce run` activates the
  multi-destination routing engine. Each event is matched against the
  YAML's `routes:` list (per-route `match` block with `equals` /
  `gte` / `lte` / `gt` / `lt` / `in` / `match` (regex) / `glob`
  operators; AND-within / OR-across); matching routes dispatch the
  event to their declared `destinations:` (`webhook` per #257 preset,
  `pagerduty` via the Events API v2, `slack` via incoming-webhook).
  `on_match: stop` (default) short-circuits subsequent routes;
  `on_match: continue` enables fan-out (e.g. "all-events archive"
  alongside team-scoped routes). Secrets live in env vars via
  `${ENV_VAR}` interpolation; literal tokens in the YAML are refused
  at parse time. Startup banner reports each resolved secret as
  `ENV_NAME (first-8-char-prefix***)`; tokens NEVER appear in logs,
  status surfaces, or routing-error messages. New `ibounce config
  preview-routes --routes ROUTES.yaml --event sample.json` subcommand
  dry-runs a sample event against the file and prints matched routes
  + masked destinations without sending any HTTP. When `--alert-routes`
  is set, the legacy `--audit-webhook-url` flag is ignored (with a
  warning at parse time + at startup); the JSONL log + Security Lake
  adapters stay independent. Enterprise-tier feature; license gate
  fires at CLI parse AND serve() start (defense in depth). Per
  `[[creates-never-mutates]]` the engine never mutates the event it
  routes. Per `[[no-hosted-saas]]` + `[[self-host-zero-billing-
  dependency]]` every destination is operator-configured (no phone-
  home). Documented in `docs/PER-ORG-NOTIFICATION-ROUTING.md`.
- **AWS Security Lake audit-export adapter** (#258) — new
  `--security-lake-bucket BUCKET --security-lake-region REGION
  [--security-lake-role-arn ARN] [--security-lake-rotation-seconds N]`
  flags on `ibounce run` write OCSF v1.1.0 class 6003 events as
  parquet files into a Security-Lake-compatible S3 bucket layout
  (`region=<r>/eventday=<YYYYMMDD>/eventhour=<HH>/api_activity-
  <unix-ms>.parquet`). Per-class in-memory batching with rotation on
  the configured interval (default 300s) OR a 10 MiB size cap,
  whichever fires first; `stop()` flushes pending batches
  synchronously. Credentials via STS AssumeRole when
  `--security-lake-role-arn` is set, otherwise the default boto3
  credential chain; refuses to start with a clear error if no
  credentials are reachable. New `pip install iam-jit[security-lake]`
  extra brings pyarrow in only when needed. Per
  `[[cross-product-agent-parity]]` kbouncer + dbounce ship the
  matching adapter (Go) with byte-identical column set + partition
  layout. Per `[[no-hosted-saas]]` + `[[self-host-zero-billing-
  dependency]]` the bucket lives in the operator's AWS account; no
  iam-jit-the-company traffic. Per `[[creates-never-mutates]]` every
  S3 operation is `PutObject` only. Documented in
  `docs/SECURITY-LAKE-INTEGRATION.md`.
- **Per-session recording + cross-product replay CLI** (#285) — new
  `--record-sessions-dir PATH` flag on `ibounce run` tees every
  audit event into a per-session NDJSON file at
  `{dir}/{agent.session_id}.ndjson`. Each file carries a `_meta`
  header (recording_schema_version, session_id, agent_name,
  bouncer_product, recording_started_at) followed by one OCSF event
  per line; `.partial` suffix while in-flight, atomically renamed on
  clean shutdown or heartbeat-timeout finalisation. File mode 0o600.
  New `ibounce session` subcommand group (`list / show / export /
  purge`) inspects recordings; new cross-product `iam-jit session
  replay <FILE>` CLI walks any product's recording with optional
  `--realtime` timing preservation, `--filter EXPR` (same grammar
  as #268), `--max-events N`, and `--what-if-profile NAME` that
  re-evaluates each event against an alternate profile and reports
  the diff. Documented in `docs/SESSION-REPLAY.md`. Per
  `[[cross-product-agent-parity]]` kbouncer / dbounce / gbounce
  ship the matching recorder + subcommands with the same on-disk
  shape. Per `[[creates-never-mutates]]` the recorder is additive
  (tees existing events); per `[[self-host-zero-billing-dependency]]`
  entirely local filesystem.
- **`ibounce run --preset security-observe`** (#254) — single-flag
  shortcut for the canonical security-team observation deployment
  shape. Equivalent to `--mode transparent --default-policy allow
  --audit-log-path ~/.iam-jit/audit/ibounce.jsonl --alert-rules
  defaults --heartbeat-interval 30`. Designed for the
  "gather data first; author profile second" starting position per
  `[[bouncer-mode-selection-for-agents]]` + the cross-product
  `docs/SECURITY-TEAM-AUDIT-EXPORT.md` memo. HARD override on
  `--mode` (the entire point of the preset is transparent);
  passing `--preset security-observe --mode cooperative` errors
  fast with a clear "drop the preset OR drop the explicit flag"
  message. SOFT overrides on the audit-log-path / alert-rules /
  heartbeat-interval / default-policy (operators have different
  SIEM destinations + tunings). Startup banner names the preset +
  every derived setting (with hard/soft annotation). Same preset
  name + same override semantics ships across `kbounce` /
  `dbounce` / `gbounce` per `[[cross-product-agent-parity]]`.
  Framework docs at `docs/DEPLOYMENT-PRESETS.md`; the post-v1.0
  roadmap (`dev-loop`, `production-strict`, `compliance-audit`)
  is documented but explicitly NOT shipped in this slice per
  `[[deliberate-feature-completion]]`.
- **Cross-product JSON Schema registry** (#276) — published JSON
  Schemas for the four cross-product audit / artifact wire shapes
  every Bounce product emits identically: OCSF v1.1.0 class 6003
  audit event (`schemas/ocsf-iam-jit-audit-event.schema.json`),
  admin-action event (`schemas/admin-action-event.schema.json`),
  diagnostics bundle manifest (`schemas/diagnostics-manifest.schema.json`),
  backup metadata table (`schemas/backup-metadata.schema.json`).
  Each schema validates against a representative sample in
  `schemas/testdata/` (CI guard); a triage tool consuming a bundle
  from any Bounce product can validate identically. New cross-product
  schema index at `schemas/INDEX.md` lists every per-product config
  schema + the cross-product common subset (`schema_version` +
  `product` + `exported_at` + `source_hostname_hash`). Per
  `[[cross-product-agent-parity]]`.
- **`GET /schemas/config` HTTP endpoint** (#276) — ibounce's mgmt
  port serves the embedded `ibounce-config.schema.json` byte-for-byte
  at `Content-Type: application/schema+json`. An agent that wants to
  validate a proposed `ibounce config import` payload against the
  LIVE bouncer's accepted shape fetches this rather than relying on
  a stale GitHub URL. Read-only; no auth (matches `/healthz`). Per
  `[[cross-product-agent-parity]]`: kbounce + dbounce + gbounce ship
  the same endpoint shape with their own product schema.
- **`ibounce audit-webhook presets list`** (#259) — operator-facing
  CLI subcommand that prints the four webhook preset shapes the
  binary speaks (`generic`, `datadog`, `splunk-hec`, `sentinel`) +
  each preset's required + optional flags + auth header + body
  shape. `--json` flag emits the structured descriptor list for
  agent consumption. Mirrors the new `list_audit_webhook_presets`
  MCP tool. Per `[[audit-webhook-presets]]` + `[[cross-product-agent-parity]]`.
- **`list_audit_webhook_presets` MCP tool** (#259) — agent-facing
  surface that returns the same descriptor list `ibounce audit-webhook
  presets list --json` emits. Read-only; safe for agents to poll;
  identical JSON shape across `ibounce` / `kbounce` / `dbounce` so
  cross-product orchestration code can call the matching tool on each
  bouncer and collate the results uniformly.
- **`docs/WEBHOOK-PRESETS.md`** (#259) — cross-product reference for
  the webhook preset framework: what each preset shape is, when to
  use which, per-vendor token-acquisition steps (Splunk HEC token,
  Datadog API key, Sentinel shared key), per-preset wire shape
  (header set + body shape + HMAC signing for Sentinel), cross-links
  to the #283 marketplace assets (Splunk app + Datadog content pack).
  Sentinel grep test in `tests/test_webhook_presets_doc.py` keeps the
  doc in sync with the preset registry.
- **`iam-jit audit stream` cross-bouncer live TUI** (#272) — k9s-
  style terminal UI that subscribes to every reachable Bounce-suite
  bouncer's `/audit/events` endpoint and renders one merged, sorted,
  colourised table that updates live. Title-bar carries total + per-
  bouncer counts (with `(skip)` next to unreachable bouncers, matching
  `iam-jit audit query`). Keyboard shortcuts: `/` filter (forwarded
  server-side), `p` pause/resume, `t` toggle per-bouncer column,
  `c` clear, `q` quit. Row colours follow SIEM convention (red=deny,
  green=allow, blue=admin, grey=heartbeat). Built on `rich.live`
  rather than `textual` so iam-roles takes no new direct dependency
  (rich ships transitively via click). Per `[[creates-never-mutates]]`
  the TUI is read-only — no keystroke mutates bouncer state. New
  module `iam_jit/cli_audit_stream.py`; new doc
  `docs/AUDIT-STREAM-TUI.md`.
- **ibounce live web UI at `GET /`** (#272 A) — minimal vanilla-JS
  page on ibounce's mgmt port (8767) alongside `/healthz` and
  `/audit/events`. Single self-contained HTML+CSS+JS file (no build
  step, no CDN, no Google Fonts, no analytics), under 500 lines.
  Long-polls `/audit/events?since=<cursor>` every two seconds and
  renders a colour-coded table with top-bar event counters, filter
  input (same syntax as `/audit/events?filter=`), pause + clear
  controls, mobile-responsive layout. Same auth model as the
  endpoint: loopback no auth; external bind takes the bearer token
  through the URL `#token=...` fragment so the HTML body never
  embeds the secret. Per `[[creates-never-mutates]]` the UI is
  read-only; strict CSP headers; cross-product-identical HTML
  shape with kbounce / dbounce / gbounce. New module
  `iam_jit/bouncer/audit_export/events_ui.py`; new doc section in
  `docs/QUERYING-AUDIT-LOGS.md`.
- **`iam-jit audit query` cross-bouncer CLI** (#271) — single
  command that queries the `/audit/events` HTTP endpoint on every
  reachable Bounce-suite bouncer in parallel and merges results
  into one OCSF-compliant stream. Defaults probe ibounce (8767) +
  kbounce (8766) + dbounce (8768) + gbounce (8769); unreachable
  bouncers skip with a stderr note. Four output formats: `jsonl`
  (default; merged + sorted NDJSON), `ocsf-bundle` (single OCSF
  v1.1.0 class 2004 Detection Finding wrapping all events from all
  bouncers — cross-product correlation in one SIEM-ingestible
  artifact), `csv` (tabular with the per-bouncer column), `summary`
  (per-bouncer + total counts). Filters forwarded server-side per
  [[cross-product-agent-parity]]. Bearer-token auth supported via
  `--audit-events-token` for externally-bound bouncers.
  ThreadPoolExecutor fan-out so one slow bouncer doesn't pin the
  query. New module `iam_jit/cli_audit_query.py`; new doc
  `docs/IAM-JIT-AUDIT-QUERY.md`. Pairs with the per-product HTTP
  endpoint (ibounce serves it on port 8767 alongside `/healthz`).
- **ibounce HTTP `GET /audit/events` endpoint** (#271 A) — headless
  sibling of `ibounce audit tail --filter ... --export jsonl`.
  Same filter language, same supported field catalog, same OCSF
  v1.1.0 wire shape. Query parameters: `since` / `until` (ISO
  8601), `filter` (repeatable; `field=value` / `field~regex` /
  `field>=N` / `field<=N`), `limit` (default 100, max 1000),
  `format` (`jsonl` default | `ocsf-bundle`). Loopback bind needs
  no auth; external bind requires `--audit-events-token TOKEN`
  (refuses to start in external-bind mode without it). New module
  `iam_jit/bouncer/audit_export/events_endpoint.py`. Powers the
  cross-bouncer query CLI above.
- **`ibounce investigate` subcommand** (#273) — one-shot helper
  that lands a Claude-ready evidence pack on disk. Composes the
  existing `audit tail --export ocsf-bundle` (#268) and
  `diagnostics bundle` (#277) into a single command: writes
  `ibounce-investigation.ndjson` (OCSF Detection Finding wrapping
  filtered events) and `ibounce-investigation-context.zip`
  (redacted diagnostics bundle with `--no-audit`) into `--out-dir`,
  then prints a "now what" block with three starter prompts.
  Flags: `--out-dir`, `--time-range` (e.g. `24h`/`7d`/`4w`),
  `--filter` (forwarded to the audit-tail filter grammar),
  `--print-prompts` (lists the 10 starter prompts without writing
  files). Cross-product alignment per [[cross-product-agent-
  parity]] — `kbounce` / `dbounce` / `gbounce` ship the same
  subcommand shape. Per [[self-host-zero-billing-dependency]] the
  command never calls Anthropic; the operator opens THEIR Claude
  session and drops both files in. Per [[creates-never-mutates]]
  it's strictly read-only.
- **`docs/INVESTIGATE-WITH-CLAUDE.md`** — workflow walkthrough,
  the 10 starter prompts, privacy story, and cross-product
  parity notes. Cross-linked from `DIAGNOSTICS.md` +
  `QUERYING-AUDIT-LOGS.md`.

### Fixed

- **#272 regression — audit-stream UI shadowed root-path AWS
  operations on the proxy port.** The `GET /` route registered for the
  live audit UI was unconditionally matching every request to `/`,
  which silently swallowed S3 ListBuckets (the most common root-path
  AWS API call) plus unclassifiable proxy traffic and presigned-URL
  redirects. The UI now defers to the proxy handler whenever the
  request does not advertise `Accept: text/html`, so browser visits
  still land on the UI while SDK + curl + agent traffic flows through
  the normal verdict path. Resolves 5 pre-existing test failures
  surfaced across multiple ship-reports
  (`test_proxy_plan_capture.py::test_plan_capture_never_forwards_to_backend`
  + four `test_proxy_slice2.py` cases). Files touched:
  `src/iam_jit/bouncer/audit_export/events_ui.py`,
  `src/iam_jit/bouncer/proxy.py`.
- **`test_parse_duration_rejects_garbage` stale expectation** — the
  test predated #285's addition of the `d` (days) suffix for
  session-recording retention; it asserted `30d` should raise
  `BadParameter`. Updated to assert the suffix set the parser
  actually accepts today (`s/m/h/d`) and switched the
  unsupported-suffix probe to `30y`. Files touched:
  `tests/bouncer/test_pause_for.py`.

### Docs

- `docs/LOCAL-TEST-INFRA.md` now documents the AWS-SDK
  HTTPS-default-with-HTTP-endpoint quirk that bites first-time
  LocalStack users (boto3 ignores the scheme on `AWS_ENDPOINT_URL`
  for some code paths and tries HTTPS regardless, producing
  `SSL: WRONG_VERSION_NUMBER`). Documented the three workarounds
  (`AWS_ENDPOINT_URL_<SERVICE>`, `AWS_USE_SSL=0`, CLI
  `--no-verify-ssl`).

### Changed (canonical names; deprecation aliases ship in v1.0)

- **`iam-jit-bouncer` → `ibounce`** — canonical CLI name for the
  AWS-API gating proxy. Console-script `iam-jit-bouncer` keeps
  working (prints a one-line stderr deprecation warning + forwards
  to the same Click app); removed in v1.1. Wheel name unchanged
  (`iam-jit` still ships both the scorer and `ibounce`).
- **MCP tools: `bouncer_*` → `ibounce_*`** — every `bouncer_*` tool
  gets an `ibounce_*` alias in v1.0. Both dispatch to the same
  handler. The legacy `bouncer_*` descriptions carry a
  `(DEPRECATED — use ibounce_* in v1.1)` prefix on every
  `tools/list` response. Removed in v1.1.
- **Built-in profiles reduced to two** — `full-user` (passthrough,
  default-active) + `readonly` (cross-product write/destructive-verb
  block). Replaces the pre-rename `none` + `prod-readonly` names.
  Old names still resolve in v1.0 + emit a one-line stderr
  deprecation banner; removed in v1.1.
- **`ibounce run` banner** — when invoked without `--profile`, the
  proxy now prints a one-line banner pointing the operator at
  `--profile readonly` OR `export IAM_JIT_BOUNCER_PROFILE=readonly`
  in their shell rc as the recommended write-block opt-in. Per
  `feedback_bounce_default_profile_pattern`.

### Moved

- **Opinionated profiles moved out of built-ins** — `dev-only`,
  `staging-work`, and `incident-response` profiles relocate from
  `src/iam_jit/bouncer/profiles.py:DEFAULT_PROFILES` to standalone
  YAML files under `tools/community-profiles/`. Future home:
  `trsreagan3/bounce-profiles` (the cross-product community-profile
  bundle). Install via `ibounce profile install --from URL` once
  hosted.
- **Doc file renames (`git mv` preserves history)**
  `docs/IAM-JIT-BOUNCER.md` → `docs/IBOUNCE.md`;
  `docs/launch-posts/DONT-GIVE-CLAUDE-YOUR-AWS-KEYS.md` →
  `docs/launch-posts/DONT-GIVE-CLAUDE-FULL-ADMIN.md`.

### Unchanged (v1.0 backward-compat surface)

- `IAM_JIT_BOUNCER_*` env vars stay as the canonical names (no
  `IBOUNCE_*` aliases — env-var alignment ships in v1.1 with the
  rest of the deprecation removal).
- HTTP response headers `x-iam-jit-bouncer-*` keep their old prefix
  for v1.0 (agents + tooling that grep on them keep working);
  renamed in v1.1.
- Wire-protocol observability (audit-log row shape, SQLite schema,
  `/healthz` JSON shape) unchanged.

### Quality (audit-cadence)

Per `feedback_audit_cadence_discipline`, a brief BB+WB self-check
for the rename change-set:

- **Does the deprecation shim actually run the new code path?** Yes
  — `main_deprecated_alias()` in `src/iam_jit/bouncer_cli.py`
  prints to stderr then calls the canonical `main()` Click app
  with `sys.argv` intact. The `iam-jit-bouncer` console-script
  binding in `pyproject.toml` points at the wrapper; both
  entrypoints exercise the same Click groups and subcommands.
- **Does any test assume the old name in a way that hides a
  regression?** Tests updated to the new `full-user` / `readonly` /
  `ibounce_*` names; backward-compat aliases get explicit pinned
  tests (`test_resolve_active_profile_legacy_none_alias_still_works`,
  `test_resolve_active_profile_legacy_prod_readonly_alias_still_works`,
  `test_tools_list_exposes_ibounce_aliases_for_every_bouncer_tool`,
  `test_bouncer_tool_descriptions_carry_deprecation_note`,
  `test_ibounce_alias_dispatches_to_same_handler`,
  `test_legacy_prod_readonly_alias_points_at_readonly`) so a
  regression breaks loudly.
- **Does the alias mechanism mask a permission elevation bug?** No
  — every MCP `ibounce_*` call normalizes to its `bouncer_*` lookup
  string at the dispatch boundary (one transform, no per-tool
  branching), so the alias cannot accept arguments the canonical
  name wouldn't accept. The profile-name aliases resolve to the
  same `Profile` object instance (`profiles["none"] is
  profiles["full-user"]`); there is no parallel resolution path
  where an alias could pick up different rules. Pre-existing bug
  in `bouncer_cli.py` — `os` not imported at module level despite
  `os.environ` use in `profile_list_cmd` — fixed in passing
  (caught by smoke-running `ibounce profile list` to verify the
  rename touched paths still execute).

## Unreleased (2026-05-15)

### Added — multi-feature push

- **Multi-provider OIDC SSO** (`src/iam_jit/oidc.py` +
  `src/iam_jit/routes/oidc.py`) — generic OIDC client with
  Google Workspace + Okta provider configs; generic provider
  for Azure AD / Auth0 / others. Full authorization-code flow,
  JWKS-cached signature verification, mandatory claim checks
  (iss, aud, exp, iat, nonce), provider-specific gates (Google
  `hd`, Okta `groups`), AMR-based MFA detection per RFC 8176.
  54 OIDC tests; round-9 BB+WB audit shipped + closures
  landed.
- **Per-account LLM policy** (`src/iam_jit/llm_account_policy.py`)
  — per-`Account` `llm_policy` field (use_llm /
  deterministic_only / unset) gates LLM-backend selection
  BEFORE the per-customer monthly budget cap. Decision flow:
  account policy → deployment default → budget cap. Surfaced
  in score response as `llm_used` + `llm_skip_reason` +
  `llm_skip_detail`. 12 unit + 7 route tests.
- **Slack approval bot** (`src/iam_jit/slack_bot.py` +
  `src/iam_jit/routes/slack.py`) — interactive approve / reject
  / request-changes flow with signed-request authentication
  (HMAC + 300s replay window), Block Kit rendering, modal-based
  context capture. Approver resolution by explicit
  `slack_user_id` mapping OR Slack `users.info` → email →
  iam-jit User. Workspace + channel pinning. App manifest +
  setup runbook. 105 Slack-surface tests.
- **Read-only-default for agent-safety mode** — MCP server's
  `generate_iam_policy` tool description instructs Claude to
  default to `access_type: "read-only"`. The behavioral contract
  for the agent-safety adoption channel. 7 pinned tests.
- **Safety-mode two-mode resolver** (`src/iam_jit/safety_mode.py`)
  — `read_write_swap` (default, lean-permissive) vs `strict`
  (compliance-strict) modes. Per-deployment / per-account /
  per-session override resolution. 14 tests.

### Security

- **Round-7 audit closures** (`docs/security/AUDIT-2026-05-WB-ROUND7-FOCUSED.md`):
  Deleted `bridge_role.py` (made 6 of 8 findings moot — the
  module violated [[creates-never-mutates]]; pattern superseded
  by Secrets Manager rotation recipe). WB7F-07 MED + WB7F-08
  LOW closed via shared `trusted_proxy.client_ip` + anchored
  `is_conditional_check_failed` substring match.
- **Round-8 Slack-bot audit closures**
  (`docs/security/AUDIT-2026-05-WB-ROUND8-SLACK-BOT.md`):
  WB8-01 HIGH (Block Kit / mrkdwn injection via
  `spec.description` + `risk_factors` — closed via
  `_escape_mrkdwn` helper applied to requester-influenced
  fields). WB8-02 MED (ambiguous `slack_user_id` mapping —
  closed via multi-match raise). WB8-03 MED (workspace pin
  via `IAM_JIT_SLACK_TEAM_ID`). WB8-04 MED (channel pin via
  approval channel ID).
- **Round-9 OIDC audit closures**
  (`docs/security/AUDIT-2026-05-WB-ROUND9-OIDC.md`):
  WB9-01 HIGH (MFA cookie now bound to `user.id`). WB9-02
  MED (token-exchange error no longer leaks access_token to
  logs). WB9-04 MED (endpoints cache has 1hr TTL). WB9-05
  LOW (iss-missing → clean error). WB9-06 LOW (AMR set
  tightened per RFC 8176 + NIST 800-63B). WB9-07 LOW
  (`_cookie_secure` delegates to canonical helper).

### Documentation

- **README rewrite** (499 → 234 lines): three-mode framing
  leading with "Don't give Claude your AWS keys." Removed
  terraform references (we use SAM); removed outdated
  "upsell SaaS" framing.
- **`docs/recipes/AGENT-IAMJIT-HOOP-EXAMPLES.md`** — six
  agent + iam-jit + Hoop scenarios using Secrets Manager
  rotation pattern.
- **`docs/recipes/SLACK-APP-SETUP.md`** — operator runbook
  for the Slack approval bot.
- **`docs/recipes/GOOGLE-OIDC-SSO.md`** — multi-provider OIDC
  setup with Google + Okta sections.
- **`docs/RECOMMENDER-API-SPEC.md`** — recommender intent +
  needs_context flow spec.
- **DEPLOYMENT.md** Step 5.5 (self-host Bedrock billing) +
  Step 5.6 (pilot deployment profile with cost-capped
  Enterprise tier).

## Unreleased (pre-launch — 2026-05-14)

### Added

- **SARIF 2.1.0 output mode** in the score CLI (`iam-risk-score
  ... --format sarif`). High-leverage CI integration substrate
  — one output mode, broad reach (GitHub Code Scanning, GitLab
  Code Quality, generic security-CI consumers). [Commit
  2966adf]
- **GitHub Action `preset:` input** with `strict | standard |
  permissive` shorthand bundling threshold + access-type.
  Explicit `threshold:` / `access-type:` inputs still override.
  Mirrors the Snyk / Semgrep "three-tier preset" pattern.
- **GitHub Action `sarif-output:` input** writes a combined
  SARIF 2.1.0 report at the given path for `actions/upload-
  sarif@v3` integration.
- **`session_revocation` module** (`src/iam_jit/session_
  revocation.py`) — Protocol + InMemory + DynamoDB
  implementations. Wired into the middleware on every
  authenticated request. SAM template provisions the table
  with TTL on `expires_at`.
- **`trusted_proxy` module** (`src/iam_jit/trusted_proxy.py`)
  — single source of truth for `IAM_JIT_TRUSTED_PROXY_CIDRS`
  parsing across score, network_acl, public_url, and the
  magic-link route's IP limiter. Normalizes IPv4-mapped IPv6.
- **`DynamoDBMagicLinkNonceStore`** for multi-instance magic-
  link replay protection. SAM table with TTL on `expires_at`.
- **`DynamoDBBanStore`** for multi-instance ban enforcement.
- **`LAUNCH-DAY-RUNBOOK.md`** — first-72h operational triage
  (dashboards, down-site decision tree, attack-decision tree,
  bug-bounty intake protocol).

### Closed (security)

10 HIGH findings, 12 MED findings, 8 LOW findings closed across
3 adversarial-audit rounds (BB+WB each). Highlights:

- **Round 1 HIGH** — STRIPE-NO-IDEMPOTENCY, SCORE-XFF-
  RATELIMIT-BYPASS, WEB-NO-CSRF-TOKEN.
- **Round 2 HIGH** — STRIPE-IDEMPOTENCY-TOCTOU (atomic
  claim()), SCORE-XFF-LEFTMOST-TRUSTED (right-to-left walk),
  NETWORK-ACL-XFF-DEFAULT-TRUSTED (default-off), MAGIC-LINK-
  XFH-POISONING (peer + allowlist gates), MAGIC-LINK-LOG-
  CHANNEL (fingerprint-only opt-in), MAGIC-LINK-REPLAY-MULTI-
  INSTANCE + BAN-MULTI-INSTANCE-DESYNC (DDB-backed stores).
- **Round 3 HIGH** — STRIPE-CLAIM-BEFORE-PROCESS (release on
  handler crash), BB3-01 logout-doesn't-revoke (session-
  revocation list), BB3-02 /openapi.json 500 (Response
  ForwardRef fix).
- **Round 3 MED** — WEB-MAGIC-CALLBACK-BROKEN-AUTO-SEED (now
  takes Request param), TOKENS-PER-USER-CAP-TOCTOU (per-user
  Lock), BODY-SIZE-GUARD-CHUNKED-BYPASS (411 on chunked + no-
  Content-Length), MAGIC-LINK-DEV-INSECURE-OUTRANKS-SES (SES
  wins), DEV-INSECURE-SECRET-MULTI-EFFECT-FOOTGUN (refused in
  Lambda without explicit opt-in), BAN-CHECK-FAIL-OPEN (503
  default), BAN-STORE-CORRUPT-FILE-UNBAN (raise not silent
  un-ban).
- **Round 3 LOW** — BB-13 / BB3-03 /healthz posture leak,
  PUBLIC-URL-XFH-LEFTMOST, XFP-SCHEME-INJECTION, MAGIC-LINK-
  IP-LIMITER-PEER-ONLY-DOS, TRUSTED-PROXY-CIDRS-PARSER-
  DISCREPANCY, XFF-IPV4-MAPPED-IPV6, BB3-04 stripe-verbose
  error, BB3-05 empty event_id bypass, BB3-10 event_type
  echo.

Full audit docs in `docs/security/AUDIT-2026-05-*.md`.

### Documentation

- **`docs/PRODUCTION-READINESS.md`** updated with new env vars
  (`IAM_JIT_TRUSTED_PROXY_CIDRS`, `IAM_JIT_ALLOWED_PUBLIC_
  HOSTS`, `IAM_JIT_SES_SENDER` / `IAM_JIT_ALLOW_LOG_CHANNEL`,
  `IAM_JIT_MAGIC_LINK_NONCES_TABLE`, `IAM_JIT_BANS_TABLE`,
  `IAM_JIT_SESSION_REVOCATION_TABLE`,
  `IAM_JIT_ALLOW_INSECURE_NONCES`).
- **`docs/ROADMAP.md`** added "continuous role auto-discovery
  + risk-threshold alerts" as a self-hosted v2 feature.
- **`docs/ADVERSARIAL-LOOP-PROCESS.md`** captures the
  cross-cutting lesson from rounds 1-3: "fix where named,
  miss the siblings." Now part of the closure methodology.

### Quality

- **1,369 tests pass** (16 ignored by tag — e2e Playwright +
  calibration-corpus residuals from the scorer adversarial
  loop). Round-1, -2, -3 audit-pinned tests on the entire BB
  + WB surface.
- **`pip-audit`** clean on locked deps.
- **Dist builds cleanly** and passes `twine check`.
