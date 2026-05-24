"""GH #10 state-verification tests for ``_format_denies_table``.

These tests target the production UX bug found by the #566 triage
agent on 2026-05-24: when the structured-deny classifier runs
deterministic-only (no LLM backend — the default-mode per
[[bouncer-zero-llm-when-agent-in-loop]]), non-destructive rows were
classified ``pending_classification`` and then silently dropped by
the rendering loop. The header advertised "Your bouncer caught N
thing(s)" but the operator saw fewer than N rows.

Per the state-verification convention in ``docs/CONTRIBUTING.md``
every test here asserts an OBSERVABLE invariant of the rendered
table (line counts, label visibility, row-presence) — not a return
status. The bug was a *render-side* drop, so the assertions live on
the rendered output.

Discipline tags:
  * [[ibounce-honest-positioning]] — silently dropping rows = lying
    about reality. Every input row MUST render in some bucket.
  * [[ambient-value-prop-and-friction-framing]] — "your bouncer
    caught N" MUST equal the number of rows the operator actually
    sees in the table.
  * [[bouncer-zero-llm-when-agent-in-loop]] — deterministic-only is
    DEFAULT mode (no LLM credentials in tests + most installs).
    Coverage here exercises that path explicitly.
"""

from __future__ import annotations

import pytest

from iam_jit import cli_profile_allow as _cli_mod
from iam_jit.cli_profile_allow import _format_denies_table
from iam_jit.profile_allow.denies import DenyRow


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _row(
    *,
    action: str,
    resource: str = "arn:aws:s3:::example/x",
    deny_source: str = "static_profile",
    deny_reason: str = "profile 'safe-default' has no matching allow",
    bouncer: str = "ibounce",
    when: str = "2026-05-23T10:00:00Z",
    suggested: str | None = None,
) -> DenyRow:
    """Build a DenyRow with a unique action+resource so render counts
    are easy to verify."""
    return DenyRow(
        when=when,
        bouncer=bouncer,
        agent_session_id="sess-gh10",
        action=action,
        resource=resource,
        deny_reason=deny_reason,
        deny_source=deny_source,
        rule_id_if_dynamic=None,
        suggested_allow_command=(
            suggested
            if suggested is not None
            else (
                f"iam-jit profile allow --target '{resource}' "
                f"--action '{action}' --reason \"<why this is safe>\""
            )
        ),
    )


def _count_data_rows(rendered: str) -> int:
    """Count rendered data rows by scanning for lines that contain the
    timestamp prefix we emit (``2026-05-23T10:00:00``). The header,
    column-header, rule, and meta lines do not start with the timestamp
    so this is a stable count even as bucket headings change."""
    return sum(
        1 for line in rendered.splitlines() if "2026-05-23T10:00:00" in line
    )


# ---------------------------------------------------------------------------
# Invariant 1: all rows render regardless of classifier mode
# ---------------------------------------------------------------------------


def test_denies_table_renders_all_rows_regardless_of_classifier_mode() -> None:
    """All input rows MUST render in the table when running with the
    default-mode (deterministic-only) classifier — no silent drops.

    Mix of one adversarial (destructive verb forces
    ``appears_adversarial`` via the structural-heuristic backstop) and
    four non-destructive rows (which the deterministic path classifies
    ``pending_classification``). Before the GH #10 fix, only the
    adversarial row rendered."""
    rows = [
        _row(action="s3:DeleteObject", resource="arn:aws:s3:::prod-data/x"),
        _row(action="s3:GetObject", resource="arn:aws:s3:::cache-a/x"),
        _row(action="s3:ListBucket", resource="arn:aws:s3:::cache-b"),
        _row(action="s3:HeadObject", resource="arn:aws:s3:::cache-c/y"),
        _row(action="ec2:DescribeInstances", resource="*"),
    ]
    out = _format_denies_table(rows, notes=[])
    rendered_count = _count_data_rows(out)
    assert rendered_count == 5, (
        f"expected all 5 rows rendered; got {rendered_count}.\n"
        f"output:\n{out}"
    )


# ---------------------------------------------------------------------------
# Invariant 2: classifier label appears as a column / bucket heading
# ---------------------------------------------------------------------------


def test_denies_table_renders_classifier_label_per_row() -> None:
    """Each classifier output MUST surface as a bucket heading so the
    operator can see WHY each row was categorized.

    Adversarial → ``likely-adversarial``; pending_classification (the
    default deterministic-mode output for non-destructive verbs) →
    ``ambiguous``."""
    rows = [
        _row(action="s3:DeleteObject", resource="arn:aws:s3:::prod-data/x"),
        _row(action="s3:GetObject", resource="arn:aws:s3:::cache/x"),
    ]
    out = _format_denies_table(rows, notes=[])
    assert "likely-adversarial" in out, f"missing adversarial heading:\n{out}"
    # pending_classification renders under an ambiguous-flavored
    # heading so non-destructive rows surface honestly. Substring
    # match — exact phrasing may evolve but the word MUST appear.
    assert "ambiguous" in out, f"missing ambiguous/pending heading:\n{out}"


# ---------------------------------------------------------------------------
# Invariant 3: header count equals input row count
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "actions",
    [
        ["s3:GetObject"],
        ["s3:GetObject", "s3:HeadObject"],
        ["s3:DeleteObject", "s3:GetObject", "s3:HeadObject"],
        ["iam:DeleteUser", "iam:DeleteRole", "ec2:DescribeInstances"],
        ["s3:GetObject"] * 7,
    ],
)
def test_denies_table_count_matches_input_length(actions: list[str]) -> None:
    """The lead-line "caught N" MUST equal len(rows) AND the rendered
    data-row count MUST equal len(rows). The bug was that the header
    showed N but the body showed fewer; this asserts both numbers
    agree with the input length."""
    rows = [
        _row(action=a, resource=f"arn:aws:s3:::bucket/{i}")
        for i, a in enumerate(actions)
    ]
    out = _format_denies_table(rows, notes=[])
    n = len(rows)
    # Header claim.
    assert f"caught {n} thing(s)" in out, (
        f"header count != len(rows); expected 'caught {n} thing(s)'\n"
        f"output:\n{out}"
    )
    # Body reality (the prior bug lived here).
    rendered_count = _count_data_rows(out)
    assert rendered_count == n, (
        f"body row count {rendered_count} != input length {n}\n"
        f"output:\n{out}"
    )


# ---------------------------------------------------------------------------
# Invariant 4 + 5: render is honest in BOTH classifier modes
# ---------------------------------------------------------------------------


def test_denies_table_renders_when_no_llm_backend(monkeypatch) -> None:
    """Explicit no-LLM environment (default install path). All rows
    MUST render — the classifier returns ``pending_classification``
    for non-destructive verbs in this mode and the bug surfaced
    precisely here. Pinning the env locally so the test is
    independent of the surrounding shell."""
    monkeypatch.delenv("IAM_JIT_ENABLE_SIDE_LLM", raising=False)
    monkeypatch.delenv("IAM_JIT_INJECTION_CLASSIFIER_HOOK", raising=False)
    rows = [
        _row(action="s3:GetObject", resource="arn:aws:s3:::cache/x"),
        _row(action="s3:HeadObject", resource="arn:aws:s3:::cache/y"),
        _row(action="ec2:DescribeInstances", resource="*"),
    ]
    out = _format_denies_table(rows, notes=[])
    assert _count_data_rows(out) == 3, (
        f"expected 3 rendered rows in no-LLM mode; got "
        f"{_count_data_rows(out)}\noutput:\n{out}"
    )
    assert "caught 3 thing(s)" in out


def test_denies_table_renders_when_classifier_hook_pins_label(
    monkeypatch,
) -> None:
    """Regression check: when a classifier hook pins a definite label
    (simulating the LLM-augmented path returning ``appears_legitimate``
    or ``ambiguous``), the table STILL renders every row and the
    label-specific bucket headings still appear.

    Uses the env-var-pinned hook surface so we don't depend on a real
    LLM backend (no network, no creds)."""

    def _pinned_hook(**_kwargs: object) -> tuple[str, str]:
        return ("appears_legitimate", "test_pin")

    monkeypatch.setenv(
        "IAM_JIT_INJECTION_CLASSIFIER_HOOK",
        "tests.cli.test_denies_table_render_invariants_gh10:_pinned_hook",
    )
    # Make the hook discoverable at module scope.
    import sys as _sys
    _sys.modules[__name__]._pinned_hook = _pinned_hook  # type: ignore[attr-defined]

    rows = [
        _row(action="s3:GetObject", resource="arn:aws:s3:::cache/x"),
        _row(action="s3:HeadObject", resource="arn:aws:s3:::cache/y"),
    ]
    out = _format_denies_table(rows, notes=[])
    assert _count_data_rows(out) == 2, (
        f"expected 2 rendered rows with pinned hook; got "
        f"{_count_data_rows(out)}\noutput:\n{out}"
    )
    assert "likely-legit" in out, (
        f"pinned 'appears_legitimate' label not surfaced as heading\n"
        f"output:\n{out}"
    )


# ---------------------------------------------------------------------------
# Invariant 6: unknown classifier labels still render (defensive)
# ---------------------------------------------------------------------------


def test_denies_table_renders_unknown_classifier_label(monkeypatch) -> None:
    """Defensive: if a future classifier hook returns a label
    ``_CATEGORY_ORDER`` doesn't know about, the rows MUST still render
    (under an "uncategorized" bucket). The render loop iterates
    discovered buckets — not a hardcoded subset — precisely to prevent
    this class of silent-drop bug from recurring."""

    # Monkeypatch the local _classify_row helper to return a label
    # outside _CATEGORY_ORDER. This is the surgical equivalent of a
    # future classifier returning a new label.
    monkeypatch.setattr(
        _cli_mod, "_classify_row", lambda _r: "totally_new_label_v2"
    )
    rows = [
        _row(action="s3:GetObject", resource="arn:aws:s3:::cache/x"),
        _row(action="s3:HeadObject", resource="arn:aws:s3:::cache/y"),
    ]
    out = _format_denies_table(rows, notes=[])
    assert _count_data_rows(out) == 2, (
        f"unknown classifier label dropped rows; got "
        f"{_count_data_rows(out)}\noutput:\n{out}"
    )
    assert "caught 2 thing(s)" in out


# ---------------------------------------------------------------------------
# Invariant 7: sabotage-check — proves Invariant 1 is load-bearing
# ---------------------------------------------------------------------------


def test_sabotage_check_invariant_1_detects_silent_drop(monkeypatch) -> None:
    """Sabotage-check per CONTRIBUTING.md: monkeypatch the renderer to
    silently drop ambiguous + pending rows and verify that Invariant 1
    (all rows render) would FAIL. This proves the invariant catches
    the original GH #10 regression shape — if a future refactor
    reintroduces the bug, Invariant 1 will catch it.

    Test passes if the sabotaged renderer fails to render all rows;
    fails if the sabotaged renderer somehow still emits everything
    (which would mean Invariant 1 is not load-bearing)."""

    def _sabotaged(rows, notes):  # type: ignore[no-untyped-def]
        # Mimic the original GH #10 bug: drop pending_classification
        # rows on render.
        filtered = [
            r
            for r in rows
            if _cli_mod._classify_row(r) != "pending_classification"
        ]
        # Reuse the real renderer on the filtered set so the format
        # stays realistic — the bug shape is drop-on-render, not
        # rewrite-of-renderer.
        original = monkeypatch  # silence linter; not used
        from iam_jit.cli_profile_allow import _format_denies_table as _real
        return _real.__wrapped__(filtered, notes) if hasattr(_real, "__wrapped__") else _real(filtered, notes)

    # Build input where 2 of 3 rows are pending_classification in
    # default-mode (non-destructive verbs).
    rows = [
        _row(action="s3:DeleteObject", resource="arn:aws:s3:::prod/x"),
        _row(action="s3:GetObject", resource="arn:aws:s3:::cache/x"),
        _row(action="s3:HeadObject", resource="arn:aws:s3:::cache/y"),
    ]
    # Run the sabotaged renderer directly (don't monkeypatch the
    # module symbol — that would also affect the real renderer in
    # the assertion below).
    sabotaged_out = _sabotaged(rows, [])
    sabotaged_count = _count_data_rows(sabotaged_out)
    # Sabotage MUST drop rows; if it doesn't, the test isn't load-bearing.
    assert sabotaged_count < 3, (
        "sabotage failed to drop rows — Invariant 1 would not catch "
        f"the GH #10 regression. sabotaged_count={sabotaged_count}\n"
        f"output:\n{sabotaged_out}"
    )

    # And the real renderer (post-fix) MUST render all 3.
    real_out = _format_denies_table(rows, notes=[])
    assert _count_data_rows(real_out) == 3, (
        f"real renderer dropped rows post-fix — regression\n"
        f"output:\n{real_out}"
    )
