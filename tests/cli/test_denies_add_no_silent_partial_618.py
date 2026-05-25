"""#618 HIGH — `iam-jit deny add` MUST NOT silently report success
when the bouncer is reading a different file from the one the CLI
wrote to.

Surfaced in UAT-Cross G5 2026-05-25: operator runs `deny add`, gets
"OK added" + exit 0, but the bouncer was started with
``--dynamic-denies-path /elsewhere`` (or under a different
``IAM_JIT_DYNAMIC_DENIES_PATH``) so the rule landed in the CLI's
default ``~/.iam-jit/dynamic-denies.yaml`` while the bouncer's
matcher kept reading ``/elsewhere``. The reload-fanout endpoint
returned ``reloaded: true`` (it DID reload, just from a different
file), which the CLI cheerfully translated to "OK" exit 0.

Per ``[[agents-default-to-iam-jit]]`` agent-facing silent failures
are the highest-priority leak class.

This is the 13th silent-degradation recurrence in the v1.0 cycle
(per [[uat-debt-audit-2026-05-23]] + UAT-Cross findings).

Per docs/CONTRIBUTING.md: every "status: ok" claim MUST be paired
with an observable-state assertion. The bouncer's reload response
includes ``source_path`` — that IS the observable state to compare
against the CLI's ``written_to``.

Fix shape: Shape B (honest multi-store fan-out reporting). The CLI
captures each bouncer's ``source_path`` from the reload response,
compares it to its own ``written_to`` path, and surfaces ``HARD``
mismatches as exit 2 with a loud per-bouncer line + a trailing
operator-actionable summary. ``SOFT`` mismatches (older bouncer
build that doesn't report source_path) preserve exit 0 with a WARN
line so the change is backward-compatible.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from iam_jit.cli import main
from iam_jit.dynamic_denies.fanout import ReloadResult
from iam_jit.dynamic_denies.operations import (
    _PATH_DIVERGENCE_HARD,
    _PATH_DIVERGENCE_NONE,
    _PATH_DIVERGENCE_SOFT,
    _classify_path_divergence,
    _serialise_reload,
    add_rule,
    list_rules,
)


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------


def _make_reload(
    *,
    bouncer: str = "ibounce",
    source_path: str | None,
    reloaded: bool = True,
) -> ReloadResult:
    """Build a ReloadResult shaped like one a real bouncer would return.

    ``source_path=None`` simulates a pre-#618 bouncer build that
    doesn't include the field; the divergence check classifies that
    as SOFT (warn only)."""
    return ReloadResult(
        bouncer=bouncer,
        url=f"http://127.0.0.1:8767",
        reloaded=reloaded,
        status_code=200 if reloaded else 503,
        rules_count=1,
        rules_applied_to_self=1,
        error=None if reloaded else "boom",
        source_path=source_path,
    )


def _patch_fanout(
    monkeypatch: pytest.MonkeyPatch,
    factory,
) -> list[str]:
    """Patch ``operations.fanout_reload`` to return whatever
    ``factory(affected, **kw)`` returns.

    The captured ``calls`` list records the bouncer names dispatched
    so a test can sabotage-check that the fan-out really was driven."""
    calls: list[str] = []

    def _fake_fanout(affected, *, overrides=None, timeout=5.0):
        out: list[ReloadResult] = []
        for b in affected:
            calls.append(b)
            out.append(factory(b))
        return out

    monkeypatch.setattr(
        "iam_jit.dynamic_denies.operations.fanout_reload",
        _fake_fanout,
    )
    return calls


# ======================================================================
# Pure-function divergence classifier — unit-level guard
# ======================================================================


def test_classify_no_mismatch_when_paths_equal(tmp_path: Path) -> None:
    """Paths that resolve to the same file -> no mismatch."""
    p = tmp_path / "denies.yaml"
    p.write_text("schema_version: '1.0'\n")
    mismatch, reason, severity = _classify_path_divergence(
        written_to=str(p),
        bouncer_source_path=str(p),
        reloaded=True,
    )
    assert mismatch is False
    assert reason is None
    assert severity == _PATH_DIVERGENCE_NONE


def test_classify_hard_mismatch_when_paths_differ(tmp_path: Path) -> None:
    """Different real paths -> HARD mismatch."""
    a = tmp_path / "a.yaml"
    b = tmp_path / "b.yaml"
    a.touch()
    b.touch()
    mismatch, reason, severity = _classify_path_divergence(
        written_to=str(a),
        bouncer_source_path=str(b),
        reloaded=True,
    )
    assert mismatch is True
    assert severity == _PATH_DIVERGENCE_HARD
    assert reason and "WILL NOT apply" in reason
    assert str(a) in reason
    assert str(b) in reason


def test_classify_soft_when_bouncer_reports_no_source_path(tmp_path: Path) -> None:
    """No source_path returned -> SOFT (older bouncer build / unknown)."""
    p = tmp_path / "denies.yaml"
    p.touch()
    mismatch, reason, severity = _classify_path_divergence(
        written_to=str(p),
        bouncer_source_path=None,
        reloaded=True,
    )
    assert mismatch is True
    assert severity == _PATH_DIVERGENCE_SOFT
    assert reason and "source_path" in reason


def test_classify_none_when_reload_failed(tmp_path: Path) -> None:
    """A failed reload's error is surfaced separately; path divergence
    only applies to successful reloads."""
    p = tmp_path / "denies.yaml"
    p.touch()
    mismatch, reason, severity = _classify_path_divergence(
        written_to=str(p),
        bouncer_source_path=None,
        reloaded=False,
    )
    assert mismatch is False
    assert reason is None
    assert severity == _PATH_DIVERGENCE_NONE


def test_classify_normalises_symlink_paths(tmp_path: Path) -> None:
    """Symlink and target compare equal after realpath()."""
    real = tmp_path / "real.yaml"
    real.write_text("data")
    link = tmp_path / "link.yaml"
    try:
        os.symlink(real, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks not supported on this filesystem")
    mismatch, _reason, severity = _classify_path_divergence(
        written_to=str(real),
        bouncer_source_path=str(link),
        reloaded=True,
    )
    assert mismatch is False, "symlink and target must compare equal"
    assert severity == _PATH_DIVERGENCE_NONE


# ======================================================================
# Test 1 — write-then-read same path: rule appears (sanity)
# ======================================================================


def test_t1_write_then_read_same_path_rule_appears(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Baseline: write `deny add` and read `deny list` against the
    SAME path env. The new rule must appear in the list output.

    Confirms the happy path still works after the #618 changes — if
    it didn't, every existing operator workflow would break."""
    p = tmp_path / "dynamic-denies.yaml"
    monkeypatch.setenv("IAM_JIT_DYNAMIC_DENIES_PATH", str(p))
    monkeypatch.setenv("HOME", str(tmp_path))

    # Stub the fan-out so we don't hit real bouncers; report a matching
    # source_path so this is a clean "no mismatch" case.
    _patch_fanout(
        monkeypatch,
        lambda b: _make_reload(bouncer=b, source_path=str(p)),
    )

    runner = CliRunner()
    add_result = runner.invoke(main, [
        "deny", "add",
        "--target", "arn:aws:s3:::prod-*",
        "--reason", "incident triage",
        "--duration", "3h",
    ])
    assert add_result.exit_code == 0, add_result.output

    # State verification: the YAML file exists with the rule + the
    # operator's `deny list` command surfaces it.
    list_result = list_rules(path=str(p))
    assert list_result["count"] == 1
    rule_ids = [r["id"] for r in list_result["rules"]]
    assert any(rid.startswith("dd_") for rid in rule_ids)

    # And the CLI list output renders it:
    cli_list = runner.invoke(main, ["deny", "list"])
    assert cli_list.exit_code == 0
    assert "arn:aws:s3:::prod-*" in cli_list.output


# ======================================================================
# Test 2 — write-then-read divergent env: HARD mismatch surfaces
# ======================================================================


def test_t2_write_then_read_divergent_env_hard_mismatch_exits_nonzero(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The #618 bug shape directly:

      * CLI writes to path A (driven by IAM_JIT_DYNAMIC_DENIES_PATH).
      * Bouncer reports it reloaded from a DIFFERENT path B.

    Pre-#618: CLI reported exit 0 + "OK added"; rule never applied
    at the bouncer's matcher.

    Post-#618: CLI exits 2 + emits a loud ERROR line + the per-
    bouncer [FAIL] line names both paths.
    """
    path_a = tmp_path / "cli-path.yaml"
    path_b = tmp_path / "bouncer-path.yaml"
    monkeypatch.setenv("IAM_JIT_DYNAMIC_DENIES_PATH", str(path_a))
    monkeypatch.setenv("HOME", str(tmp_path))

    # Bouncer claims it reloaded from path B (the divergence).
    _patch_fanout(
        monkeypatch,
        lambda b: _make_reload(bouncer=b, source_path=str(path_b)),
    )

    runner = CliRunner()
    result = runner.invoke(main, [
        "deny", "add",
        "--target", "arn:aws:s3:::prod-*",
        "--reason", "incident triage",
        "--duration", "3h",
    ])

    # 1. Reported state (the claim): CLI now exits 2.
    assert result.exit_code == 2, (
        f"expected exit 2 on hard path mismatch, got {result.exit_code}; "
        f"output: {result.output}"
    )

    # 2. Observable state on disk: rule DID land in path_a (the write
    #    succeeded; only the fan-out applies elsewhere).
    assert path_a.exists(), "rule YAML must exist at the CLI's write path"
    list_result = list_rules(path=str(path_a))
    assert list_result["count"] == 1

    # 3. Observable state in operator-facing output:
    #    - the per-bouncer [FAIL] line names the bouncer's path
    #    - the trailing ERROR summary names both paths + the
    #      remediation hint
    assert "[FAIL]" in result.output
    assert str(path_b) in result.output, (
        "expected the bouncer's source_path to appear in the [FAIL] "
        "line so the operator can see WHICH path the bouncer is on"
    )
    assert "ERROR" in result.output
    assert str(path_a) in result.output, (
        "expected the CLI's write path to appear in the ERROR summary"
    )
    assert "WILL NOT apply" in result.output


def test_t2_json_shape_surfaces_path_mismatch_aggregates(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The JSON wire shape MUST carry ``any_hard_path_mismatch`` +
    ``path_mismatches`` + per-fanout entries with ``source_path`` so
    a wrapping agent can branch on them programmatically.

    Per [[cross-product-agent-parity]] the JSON shape is the
    machine-stable surface; agents read this, not the text banner."""
    path_a = tmp_path / "cli.yaml"
    monkeypatch.setenv("IAM_JIT_DYNAMIC_DENIES_PATH", str(path_a))
    monkeypatch.setenv("HOME", str(tmp_path))

    _patch_fanout(
        monkeypatch,
        lambda b: _make_reload(bouncer=b, source_path="/var/somewhere-else/x.yaml"),
    )

    runner = CliRunner()
    result = runner.invoke(main, [
        "deny", "add",
        "--target", "arn:aws:s3:::prod-*",
        "--reason", "incident triage",
        "--duration", "3h",
        "--json",
    ])
    assert result.exit_code == 2, result.output

    # Parse the JSON body. Some output (the OK lines etc.) is mixed
    # in; the runner here uses click's CliRunner which collects all
    # stdout. We need to be robust: find the first JSON object in
    # the output.
    raw = result.output.strip()
    payload = json.loads(raw)

    # Aggregates present + correct.
    assert payload["any_hard_path_mismatch"] is True
    assert payload["any_path_mismatch"] is True
    assert payload["path_mismatches"], "must list the mismatched bouncers"
    assert len(payload["path_mismatches"]) == 1
    pm = payload["path_mismatches"][0]
    assert pm["bouncer"] == "ibounce"
    assert pm["source_path"] == "/var/somewhere-else/x.yaml"
    assert pm["path_mismatch_severity"] == "hard"
    assert pm["path_mismatch"] is True

    # And the per-fanout entry carries source_path so an agent
    # iterating fanout can extract it without re-deriving from the
    # path_mismatches subset.
    fanout = payload["fanout"]
    assert len(fanout) == 1
    assert fanout[0]["source_path"] == "/var/somewhere-else/x.yaml"


# ======================================================================
# Test 3 — multi-bouncer fan-out: HARD mismatch on SOME bouncers
# ======================================================================


def test_t3_multibouncer_fanout_partial_hard_mismatch_exits_nonzero(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When multiple bouncers are addressed (e.g. a target that fans
    to ibounce + gbounce) and ONE reports a divergent source_path,
    the CLI must still exit non-zero. The other bouncer's clean
    reload must NOT mask the failed one.

    Drives the resolver via a target shape ("rds:payments-db-prod")
    that fans to dbounce + gbounce per the design doc. The fan-out
    stub returns ibounce-path for dbounce (matching) but a divergent
    path for gbounce."""
    cli_path = tmp_path / "cli.yaml"
    monkeypatch.setenv("IAM_JIT_DYNAMIC_DENIES_PATH", str(cli_path))
    monkeypatch.setenv("HOME", str(tmp_path))

    def factory(bouncer):
        if bouncer == "dbounce":
            return _make_reload(bouncer=bouncer, source_path=str(cli_path))
        # gbounce reports divergent path.
        return _make_reload(
            bouncer=bouncer,
            source_path="/etc/some-other-place/denies.yaml",
        )

    calls = _patch_fanout(monkeypatch, factory)

    runner = CliRunner()
    result = runner.invoke(main, [
        "deny", "add",
        "--target", "rds:payments-db-prod",
        "--reason", "incident triage",
        "--duration", "3h",
        "--json",
    ])
    assert result.exit_code == 2, result.output

    # Sanity: the fan-out really was driven against multiple bouncers.
    assert "dbounce" in calls
    assert "gbounce" in calls

    payload = json.loads(result.output.strip())
    assert payload["any_hard_path_mismatch"] is True

    # The dbounce entry shows no mismatch; the gbounce entry does.
    by_b = {f["bouncer"]: f for f in payload["fanout"]}
    assert by_b["dbounce"]["path_mismatch"] is False
    assert by_b["gbounce"]["path_mismatch"] is True
    assert by_b["gbounce"]["path_mismatch_severity"] == "hard"

    # The aggregate path_mismatches list contains only the failing one.
    pm_bouncers = {p["bouncer"] for p in payload["path_mismatches"]}
    assert pm_bouncers == {"gbounce"}


# ======================================================================
# Test 4 — SOFT mismatch (no source_path reported) preserves exit 0
# ======================================================================


def test_t4_soft_mismatch_unknown_source_path_warns_but_exits_zero(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A pre-#618 bouncer build doesn't include ``source_path`` in
    its reload response. We can't verify divergence, so we WARN but
    exit 0 -- this preserves backward-compat with the dozens of
    existing CLI tests + integration scripts that stub the fan-out.

    The WARN appears in the per-bouncer text output AND in the JSON
    fields so an aware operator can spot it; we just don't hard-fail
    on absent information."""
    cli_path = tmp_path / "cli.yaml"
    monkeypatch.setenv("IAM_JIT_DYNAMIC_DENIES_PATH", str(cli_path))
    monkeypatch.setenv("HOME", str(tmp_path))

    _patch_fanout(
        monkeypatch,
        lambda b: _make_reload(bouncer=b, source_path=None),
    )

    runner = CliRunner()
    text_result = runner.invoke(main, [
        "deny", "add",
        "--target", "arn:aws:s3:::prod-*",
        "--reason", "incident triage",
        "--duration", "3h",
    ])
    # Exit 0 -- soft is not hard.
    assert text_result.exit_code == 0, text_result.output
    # WARN line surfaces in the text output.
    assert "[WARN]" in text_result.output
    assert "did not report source_path" in text_result.output

    # Same query in JSON: any_path_mismatch True (we DID flag), but
    # any_hard_path_mismatch False (no hard severity).
    json_result = runner.invoke(main, [
        "deny", "add",
        "--target", "arn:aws:s3:::prod-other-*",
        "--reason", "incident triage 2",
        "--duration", "3h",
        "--json",
    ])
    assert json_result.exit_code == 0, json_result.output
    payload = json.loads(json_result.output.strip())
    assert payload["any_path_mismatch"] is True
    assert payload["any_hard_path_mismatch"] is False
    assert len(payload["path_mismatches"]) == 1
    assert payload["path_mismatches"][0]["path_mismatch_severity"] == "soft"


# ======================================================================
# Test 5 — sabotage check: prove the path-mismatch wiring is load-bearing
# ======================================================================


def test_t5_sabotage_check_proves_source_path_check_is_load_bearing(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sabotage the source_path extraction in `_serialise_reload`
    and confirm the divergence-detection test FAILS. This proves the
    new code is actually doing work — if a regression silently
    bypassed the check, this test would still pass (false negative),
    so we explicitly verify the wiring carries load.

    The sabotage: monkeypatch the operations module's
    ``_classify_path_divergence`` to always return "no mismatch".
    Then construct the same Test 2 setup (hard mismatch) and confirm
    the CLI now (incorrectly) exits 0 — proving the real classifier
    is what's driving the exit code.
    """
    path_a = tmp_path / "cli.yaml"
    monkeypatch.setenv("IAM_JIT_DYNAMIC_DENIES_PATH", str(path_a))
    monkeypatch.setenv("HOME", str(tmp_path))

    _patch_fanout(
        monkeypatch,
        lambda b: _make_reload(bouncer=b, source_path="/somewhere/else.yaml"),
    )

    # Sabotage: replace the classifier with one that always says "no
    # mismatch".
    monkeypatch.setattr(
        "iam_jit.dynamic_denies.operations._classify_path_divergence",
        lambda **_kw: (False, None, _PATH_DIVERGENCE_NONE),
    )

    runner = CliRunner()
    result = runner.invoke(main, [
        "deny", "add",
        "--target", "arn:aws:s3:::prod-*",
        "--reason", "incident triage",
        "--duration", "3h",
    ])

    # Under sabotage, the CLI reverts to the pre-#618 behaviour:
    # exit 0 even though the bouncer is reading a different file.
    # This is the silent-degradation shape we're guarding against.
    assert result.exit_code == 0, (
        "sabotage check failed: even with the classifier neutralised "
        "the CLI still exited non-zero — that means SOMETHING ELSE is "
        "driving the exit code, not the path-divergence check. The "
        "test scaffolding above is therefore unreliable as a guard."
    )
    # No FAIL line emitted, because the sabotaged classifier never
    # flagged a mismatch.
    assert "[FAIL]" not in result.output


def test_t5_sabotage_check_unpatched_path_check_does_flag(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The companion to the sabotage test: re-run WITHOUT the
    sabotage and confirm the same input now correctly exits 2.
    The pair (this + the sabotage above) proves the new wiring is
    load-bearing -- toggling the classifier toggles the exit code,
    so the divergence test is what's catching the bug."""
    path_a = tmp_path / "cli.yaml"
    monkeypatch.setenv("IAM_JIT_DYNAMIC_DENIES_PATH", str(path_a))
    monkeypatch.setenv("HOME", str(tmp_path))

    _patch_fanout(
        monkeypatch,
        lambda b: _make_reload(bouncer=b, source_path="/somewhere/else.yaml"),
    )

    runner = CliRunner()
    result = runner.invoke(main, [
        "deny", "add",
        "--target", "arn:aws:s3:::prod-*",
        "--reason", "incident triage",
        "--duration", "3h",
    ])
    assert result.exit_code == 2, (
        f"unsabotaged run must exit 2 on hard mismatch; got "
        f"{result.exit_code}; output: {result.output}"
    )
    assert "[FAIL]" in result.output


# ======================================================================
# Bonus: parity check on `deny remove` — same shape, same exit code
# ======================================================================


def test_deny_remove_also_exits_nonzero_on_hard_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per [[cross-product-agent-parity]] `deny remove` must behave
    the same as `deny add` on path divergence. A removal that
    "succeeds" against the CLI's path while the bouncer keeps
    reading a different file leaves the rule LIVE at the matcher --
    exactly the silent-failure shape #618 targets.
    """
    cli_path = tmp_path / "cli.yaml"
    monkeypatch.setenv("IAM_JIT_DYNAMIC_DENIES_PATH", str(cli_path))
    monkeypatch.setenv("HOME", str(tmp_path))

    # First add a rule (matching path -> exit 0).
    _patch_fanout(
        monkeypatch,
        lambda b: _make_reload(bouncer=b, source_path=str(cli_path)),
    )
    runner = CliRunner()
    add_result = runner.invoke(main, [
        "deny", "add",
        "--target", "arn:aws:s3:::prod-*",
        "--reason", "incident triage",
        "--duration", "3h",
    ])
    assert add_result.exit_code == 0, add_result.output

    listed = list_rules(path=str(cli_path))
    rid = listed["rules"][0]["id"]

    # Now flip the fan-out stub to report a divergent path. The
    # remove SHOULD report exit 2 even though the on-disk YAML
    # was correctly updated.
    _patch_fanout(
        monkeypatch,
        lambda b: _make_reload(
            bouncer=b,
            source_path="/elsewhere/denies.yaml",
        ),
    )

    rm_result = runner.invoke(main, ["deny", "remove", rid])
    assert rm_result.exit_code == 2, (
        f"expected `deny remove` to exit 2 on hard mismatch; got "
        f"{rm_result.exit_code}; output: {rm_result.output}"
    )
    assert "[FAIL]" in rm_result.output
    # State verification: the YAML was correctly updated even though
    # the fan-out divergence is reported -- the on-disk file is the
    # source of truth.
    post = list_rules(path=str(cli_path))
    assert post["count"] == 0, "rule should be removed from CLI's file"


# ======================================================================
# Cross-check: operations.add_rule directly returns the new fields
# ======================================================================


def test_add_rule_returns_path_mismatch_aggregates_directly(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The MCP layer + future callers consume ``add_rule`` directly
    (not via the CLI). Confirm the aggregates ``any_path_mismatch``
    + ``any_hard_path_mismatch`` + ``path_mismatches`` land on the
    return dict so those callers can branch without re-walking the
    fanout list."""
    cli_path = tmp_path / "cli.yaml"
    _patch_fanout(
        monkeypatch,
        lambda b: _make_reload(bouncer=b, source_path="/elsewhere/x.yaml"),
    )
    result = add_rule(
        targets=["arn:aws:s3:::prod-*"],
        reason="incident",
        duration="3h",
        path=str(cli_path),
    )
    assert result["any_path_mismatch"] is True
    assert result["any_hard_path_mismatch"] is True
    assert len(result["path_mismatches"]) == 1
    assert result["path_mismatches"][0]["bouncer"] == "ibounce"
    assert result["path_mismatches"][0]["source_path"] == "/elsewhere/x.yaml"


def test_serialise_reload_omits_path_fields_when_no_written_to() -> None:
    """When no ``written_to`` is supplied (no comparison possible),
    ``_serialise_reload`` should NOT inject path_mismatch fields.
    This preserves the legacy wire shape for callers that don't pass
    a path to compare against."""
    r = _make_reload(bouncer="ibounce", source_path="/x/y.yaml")
    out = _serialise_reload(r)
    assert "path_mismatch" not in out
    assert "path_mismatch_severity" not in out
    # but source_path is always surfaced.
    assert out["source_path"] == "/x/y.yaml"
