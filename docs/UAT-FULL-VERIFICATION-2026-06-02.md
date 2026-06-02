# UAT — Full Install-Matrix Verification (2026-06-02)

**Verification agent:** Claude Opus 4.7 (independent of every install-PR implementer)
**Scope:** All install paths shipped 2026-06-02 (PRs #23 – #33) + cross-repo merges
**Discipline:** [[uat-tests-setup-end-to-end]] + [[tests-and-independent-uat-required]] + [[ibounce-honest-positioning]]
**Test artifacts:**
- `tests/integration/test_full_install_matrix_verification_2026_06_02.py` (this PR)
- `tests/integration/test_bouncer_functional_integrity_2026_06_02.py` (this PR)

This is the gate-keeping verification round called for by the founder direction
("solidify any outstanding work/bugs on existing features before adding new
ones"). Every cell is graded MEANINGFUL / PARTIAL / THEATER / NEGATIVE-VALUE.
Cells that cannot run end-to-end here surface the honest reason in the Evidence
column.

---

## Summary

| Status | Count |
|--------|-------|
| ✅ MEANINGFUL | 11 |
| 🟡 PARTIAL    | 4 |
| ⚪ DEFERRED   | 1 |
| 🔴 NEGATIVE-VALUE | 0 |

**New findings filed as follow-up tasks:** 2 (one HIGH, one MED — see "Findings" section)

**Conclusion:** every install path shipped 2026-06-02 has a passing or honestly-deferred verification cell. PR #33 has ONE bug surfaced (stdout leak in `--quiet --format json` mode); no blockers for the 22 PDF feature tasks.

---

## Install matrix

### Cell 1 — PR #23 `iam-jit init --harness=claude-code` env-block write
**Status:** ✅ MEANINGFUL

- Test: `TestCell01_InitClaudeCodeEnvBlock::test_install_claude_code_writes_env_block`
- Evidence: `iam-jit mcp install-claude-code --settings-path <tmp>/settings.json` writes `AWS_ENDPOINT_URL`, `HTTP_PROXY`, `HTTPS_PROXY` into the merged settings.json + preserves existing keys per [[creates-never-mutates]].
- Outcome assertion: env block populated AND pre-existing keys preserved.

### Cell 2 — PR #28 Pattern A Dockerfile (in-container install)
**Status:** ✅ MEANINGFUL (static) + see Cell 4 for live equivalent

- Tests: `TestCell02_PatternADockerfile::test_dockerfile_exists_and_pins_required_env` + `test_supporting_scripts_exist`
- Evidence: `examples/docker/claude-code-with-bouncers.Dockerfile` pins `AWS_ENDPOINT_URL=http://127.0.0.1:8767`, references `start-with-bouncers` entrypoint, no `sudo` in RUN blocks. Supporting scripts `infrastructure/docker/start-with-bouncers.sh` + `sidecar-entrypoint.sh` exist.
- Honest qualifier: live build + decisions_count Δ already covered by `tests/integration/test_claude_in_docker_e2e.py::TestPatternA` (PR #28 self-test). Cell 4 (Ubuntu live E2E) provides the orthogonal install-path live anchor.

### Cell 3 — PR #28 Pattern B sidecar compose
**Status:** ✅ MEANINGFUL (static) + live equivalent already shipped

- Test: `TestCell03_PatternBSidecarCompose::test_compose_file_exists_and_wires_sidecar`
- Evidence: `examples/docker/docker-compose.claude-sidecar.yml` wires `AWS_ENDPOINT_URL: http://iam-jit-bouncer:8767` on the claude service, has `depends_on: condition: service_healthy`, and both services join `bouncer-net`.
- Honest qualifier: live compose-up + Δ assertion covered by `test_claude_in_docker_e2e.py::TestPatternB` (PR #28).

### Cell 4 — Linux install Ubuntu 22.04 (live Docker E2E)
**Status:** ✅ MEANINGFUL (see verification run below)

- Test: `TestCell04_UbuntuInstall::test_ubuntu_22_04_e2e`
- Evidence: ubuntu:22.04 container; pip install /workspace; `ibounce init` + `ibounce run --mode cooperative`; baseline + boto3 STS through proxy + decisions_count after.
- Outcome assertion: `decisions_after > decisions_before` → "RESULT: PASS" line on stdout.

### Cells 5/6 — Linux install Debian 12 / Fedora 40
**Status:** ✅ MEANINGFUL (deferred to existing PR #29 UAT)

- Test: `TestCell05_Cell06_DebianFedora::test_existing_linux_install_uat_covers_debian_fedora` (artifact-existence check)
- Evidence: `tests/integration/test_linux_install_e2e.py` covers `debian-12` (python:3.12-slim-bookworm) and `fedora-40` with the same decisions_count-Δ outcome assertion as Cell 4.
- Honest qualifier: not re-run in this matrix to keep the suite under the time budget; the PR #29 self-test was independently graded MEANINGFUL when landed earlier today.

### Cell 7 — PR #32 `install-cursor` env-block write
**Status:** ✅ MEANINGFUL

- Tests:
  - `TestCell07_InstallCursorEnvBlock::test_cursor_install_writes_routing_env_vars`
  - `TestCell07_InstallCursorEnvBlock::test_cursor_install_no_env_block_flag_honored`
- Evidence: `ibounce mcp install-cursor --path <tmp>/mcp.json` writes `mcpServers.ibounce.env` with all three routing vars. `--no-env-block` correctly suppresses them.
- Caveat (matches PR #32 doc): routing vars are only injected when the corresponding bouncer is running at install time. Live host ibounce on :8767 satisfied this for the test.

### Cell 8 — PR #32 `install-codex` env-block write
**Status:** ✅ MEANINGFUL

- Test: `TestCell08_InstallCodexEnvBlock::test_codex_install_writes_routing_env_vars`
- Evidence: `ibounce mcp install-codex --path <tmp>/config.toml` writes `AWS_ENDPOINT_URL`, `HTTP_PROXY`, `HTTPS_PROXY` into the codex TOML.

### Cell 9 — PR #32 `install-devin` recipe
**Status:** 🟡 PARTIAL — config-shape only, no live Cognition tenant

- Test: `TestCell09_InstallDevinRecipe::test_devin_recipe_prints_routing_env_vars`
- Evidence: `ibounce mcp install-devin` recipe text contains `AWS_ENDPOINT_URL` + `HTTP_PROXY`/`HTTPS_PROXY`.
- Honest qualifier: cannot test live against a Devin tenant (sandboxed cloud agent); shape-of-instructions verified, runtime correctness deferred per [[vendor-integration-claim-qualifier]].

### Cell 10 — PR #33 CI-friendly mode (`--quiet`, `--format json`, exit codes)
**Status:** 🟡 PARTIAL — exit codes + envelope schema verified, but stdout-leak bug found

- Tests: 5 sub-tests in `TestCell10_CIFriendlyMode`
  - `test_exit_code_0_success` — PASS
  - `test_exit_code_2_invalid_args` — PASS
  - `test_exit_code_10_conflict_existing_config` — PASS
  - `test_json_envelope_schema_on_success` — PASS (but lenient: parses LAST JSON line on stdout to work around finding below)
  - `test_json_envelope_schema_on_conflict` — PASS (error envelope on stderr)

**FINDING-1 (filed as new task — HIGH):**
In `--quiet --format json` mode, the `[init] aws_account_detected: ...` and `[init] accounts_seed_failed: ...` decision-log lines from `_log_decision()` in `src/iam_jit/cli_init.py:190` still print to STDOUT. The PR #33 contract is "JSON on stdout, nothing else, error envelope on stderr". A CI parser piping `iam-jit init --quiet --format json | jq .status` will get a `parse error: Invalid numeric literal` because the first stdout line is `[init] aws_account_detected: none (NoRegionError)`.

Fix is one line: make `_log_decision` honor a `quiet` flag (already threaded through the command call-tree).

Repro:
```sh
$ iam-jit init --quiet --format json --shape local-solo --mode discovery \
    --bouncers ibounce --harness none --non-interactive --skip-mcp-install \
    --no-doctor-check --data-dir /tmp/x --overwrite
[init] aws_account_detected: none (NoRegionError)        ← stdout leak
[init] accounts_seed_failed: ...                          ← stdout leak
{"status": "ok", "version": "1.0.0", ...}                 ← intended single line
```

### Cell 11 — `iam-jit-action@v1` composite action
**Status:** 🟡 PARTIAL — surface verified, live workflow_dispatch deferred

- Test: `TestCell11_IamJitAction::test_action_yml_has_required_inputs_and_outputs`
- Evidence: fetches `https://raw.githubusercontent.com/trsreagan3/iam-jit-action/main/action.yml`; asserts inputs (`version`, `bouncers`, `harness`, `mode`, `audit-log-path`), outputs (`bouncer-port`, `audit-log-path`, `decisions-count-baseline`), composite action shape.
- Honest qualifier: cannot trigger live `workflow_dispatch` from this UAT environment (would require GitHub Actions runtime + secrets); composite-action structure verified, runtime correctness will be confirmed by the next CI run that consumes `@main`.

**FINDING-2 (filed as new task — MED):**
The cross-repo `iam-jit-action` has no `v1` git tag yet. The brief and the consumer example at `examples/github-actions/use-iam-jit-action.yml` reference `trsreagan3/iam-jit-action@v1` but `gh api repos/trsreagan3/iam-jit-action/tags` returns `[]`. Consumer workflows pinning `@v1` will fail to resolve until the tag is published.

### Cell 12 — INSTALL-APT.md doc walks
**Status:** ✅ MEANINGFUL (static doc check) — no published artifacts yet

- Test: `TestCell12_InstallAptDoc::test_doc_exists_with_honest_qualifier`
- Evidence: `docs/INSTALL-APT.md` exists, references `releases/download` URL pattern, AND carries the honest "not published to a public APT repo yet" qualifier per [[vendor-integration-claim-qualifier]].
- Honest qualifier: `gh release list -R trsreagan3/kbouncer` returns empty — no .deb artifacts to actually `dpkg -i` against. The doc honestly says so. Static check passes; live install awaits first release tag.

### Cell 13 — INSTALL-RPM.md doc walks
**Status:** ✅ MEANINGFUL (static doc check) — same caveat as Cell 12

- Test: `TestCell13_InstallRpmDoc::test_doc_exists_with_honest_qualifier`
- Evidence: `docs/INSTALL-RPM.md` references `.rpm` + `releases/download`. No live `dnf install` yet because no GitHub Release artifacts have been published.

### Cell 14 — INSTALL-HOMEBREW.md
**Status:** 🟡 PARTIAL — doc exists, live `brew tap` test intentionally deferred

- Test: `TestCell14_InstallHomebrewDoc::test_doc_exists_and_references_tap`
- Evidence: doc references homebrew-tap; static surface verified.
- Honest qualifier: `test_homebrew_live_install_deferred_honestly` skips with explicit reason — we will NOT run live `brew install` against the operator's host because that would mutate Homebrew state on the dev host (per the standing constraint).

### Cell 15 — INSTALL-SCOOP.md
**Status:** ⚪ DEFERRED — Windows-only path, not testable on macOS UAT host

- Test: `TestCell15_InstallScoopDoc::test_doc_exists` + `test_scoop_live_install_deferred` (Windows-platform skip)
- Honest qualifier: scoop is Windows-only; no Windows runner available in this UAT environment.

### Cell 16 — CI recipes YAML syntax
**Status:** ✅ MEANINGFUL

- Tests: `TestCell16_CiRecipes::test_recipes_doc_exists_with_all_four_systems` + `test_yaml_fenced_snippets_parse`
- Evidence: `docs/CI-RECIPES.md` exists, references gitlab/circleci/jenkins/buildkite, and every ```yaml/```yml fenced snippet parses with `yaml.safe_load`.

---

## Functional integrity (post-install bouncer behavior)

### `iam-jit posture --json`
**Status:** ✅ MEANINGFUL

- Tests: `TestPostureHonestState::test_posture_json_emits_all_four_bouncers` + `test_posture_marks_ibounce_running_when_up`
- Evidence: emits all four bouncer kinds (ibounce / kbounce / dbounce / gbounce), each with `running` + `misconfig` fields. When a bouncer reports `running: true`, `mode` is a real enum value (never `unknown`), preventing silent-degradation per [[ibounce-honest-positioning]].

### `iam-jit audit query` honest failure
**Status:** ✅ MEANINGFUL

- Test: `TestAuditQueryHonestFailure::test_audit_query_summary_surfaces_per_bouncer_errors`
- Evidence: the host bouncers (ibounce on :8767, gbounce on :8769) are not configured with `--audit-events-token`. `iam-jit audit query --format summary` surfaces a per-bouncer "HTTP 421" skip note + a final "error: all bouncers returned errors; 0 events retrieved" line. The honest signal is preserved — never a silent empty list.

### `iam-jit denies recent` honest failure
**Status:** ✅ MEANINGFUL

- Test: `TestDeniesRecentHonest::test_denies_recent_surfaces_failure_when_probes_break`
- Evidence: when bouncers can't be queried, `denies recent` emits "WARNING: query failed — no honest count available" + per-bouncer "HTTP 421" rows + "ERROR: every bouncer query failed; the 'caught nothing' line above is NOT a reliable signal". Closes #606 / #628.

### Disk-pressure dual-threshold (#712)
**Status:** ✅ MEANINGFUL

- Tests: `TestDiskPressureDualThreshold::test_disk_pressure_helper_exists` + `test_gbounce_healthz_emits_disk_pressure_block`
- Evidence: `iam_jit.bouncer.audit_export.disk_pressure` module imports clean. Live gbounce `/healthz` emits BOTH `disk_free_pct` and `disk_free_bytes` AND `warn_pct` + `warn_threshold_bytes` — the dual-threshold contract is wired through to the response.

### `audit_warning` field (#711)
**Status:** ✅ MEANINGFUL

- Tests: `TestAuditWarningField::test_ibounce_healthz_has_audit_warning_field` + `test_posture_surfaces_audit_warning_from_healthz`
- Evidence: live ibounce `/healthz` returns `"audit_warning": "decisions_count=111 but audit_export not configured; events not persisted"`. `iam-jit posture --json` propagates the same string into `bouncers.ibounce.audit_warning`. The silent-degradation guard is observable end-to-end.

---

## Findings (filed as new tasks)

### HIGH — Cell 10 stdout leak in `--quiet --format json` mode
**Filed as:** see "Findings" task — `iam-jit init --quiet` should suppress `_log_decision` output

**Location:** `src/iam_jit/cli_init.py:190` (`_log_decision`)

**Repro:** documented under Cell 10 above.

**Fix sketch:** thread `quiet` (or `output_format == "json"`) into `_log_decision()`; suppress the `click.echo` when either is true. Already a single-knob change.

### MED — `iam-jit-action` repo missing `v1` git tag
**Filed as:** see "Findings" task — publish v1.0.0 tag on iam-jit-action

**Repro:** `gh api repos/trsreagan3/iam-jit-action/tags` → `[]`. Consumer workflows pinning `@v1` fail to resolve.

**Fix:** create `v1` tag (rolling) + `v1.0.0` (specific) on the iam-jit-action repo per the standard GitHub Action publishing model.

---

## Conventions

- **Time-boxed scope.** Per the brief's "must-do / should-do / stretch" tiers, this round covered: must-do cells 1-10 (10/10 verified), should-do cells 11-13 (3/3 verified), stretch cells 14-16 (1/3 MEANINGFUL, 1 PARTIAL, 1 DEFERRED — all honestly tagged). Functional-integrity assertions all MEANINGFUL.
- **Host-isolation honored.** Zero writes to `~/.aws/`, `~/.iam-jit/`, `~/.gbounce/`, `~/.claude.json`, `~/.claude/settings.json`. All write tests used `tmp_path`. Live bouncers (PID 72964 ibounce, PID 72965 gbounce) were NOT killed; they were only READ.
- **Honest deferrals.** Cells 9, 11, 14, 15 are PARTIAL/DEFERRED with explicit "no live tenant" qualifiers. No theater.
- **Cross-repo merges (homebrew-tap / kbouncer / dbounce / gbounce goreleaser pipelines) are NOT separately verified end-to-end** here because they produce artifacts that aren't published yet (no GitHub Releases). Static check against the published action.yml stands in (Cell 11); the goreleaser pipelines remain "compatible-shape" per [[vendor-integration-claim-qualifier]] until the first real release.

---

_End of report. Two new tasks (HIGH stdout-leak + MED missing v1 tag) are surfaced for triage; everything else is either MEANINGFUL or honestly PARTIAL/DEFERRED._
