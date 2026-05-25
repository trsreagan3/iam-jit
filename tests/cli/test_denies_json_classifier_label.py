"""#575 state-verification tests for ``iam-jit denies recent --json``.

UAT-B 2026-05-25 found that ``iam-jit denies recent --json`` returned
row objects with all the standard fields but NO ``classifier_label``
(or ``category``) field per row. The human/text output groups rows
by classifier label (``(?) ambiguous``, ``(!) likely-adversarial``,
etc.) via ``_format_denies_table`` but the JSON output lost that
signal entirely.

Per ``[[bouncer-zero-llm-when-agent-in-loop]]``: downstream agents
consume ``--json`` to reason about denies. Without ``classifier_label``
they had to reverse-engineer from ``deny_reason`` strings — brittle
and opaque.

This is the JSON-parity counterpart to GH #10 (which fixed the silent
row-drop bug in the TEXT output). Per
``[[cross-product-agent-parity]]`` the JSON and text outputs should
expose the same signals — different presentation, not different
information content.

Per the state-verification convention in ``docs/CONTRIBUTING.md``
every test here asserts an OBSERVABLE invariant of the rendered JSON
(field presence, value enumeration, text/json parity) — not internal
function returns. The bug was a wire-shape omission, so the
assertions live on the wire shape.

Discipline tags:
  * ``[[ibounce-honest-positioning]]`` — quietly omitting a signal
    the text path emits is the JSON-side equivalent of silently
    dropping a row.
  * ``[[bouncer-zero-llm-when-agent-in-loop]]`` — deterministic-only
    is DEFAULT mode; the ``pending_classification`` label is the
    classifier's honest "no LLM here yet" signal and MUST reach
    agent consumers.
  * ``[[cross-product-agent-parity]]`` — JSON + text outputs should
    expose the same signals; this asserts that parity on every row.
"""

from __future__ import annotations

import json

import pytest

from iam_jit import cli_profile_allow as _cli_mod
from iam_jit.cli_profile_allow import (
    _CATEGORY_ORDER,
    _JSON_UNKNOWN_CLASSIFIER_LABEL,
    _format_denies_table,
    _row_to_json_dict,
)
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
    when: str = "2026-05-25T10:00:00Z",
    suggested: str | None = None,
) -> DenyRow:
    """Build a DenyRow with a unique action+resource so JSON shape
    assertions stay deterministic."""
    return DenyRow(
        when=when,
        bouncer=bouncer,
        agent_session_id="sess-575",
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


# ---------------------------------------------------------------------------
# Invariant 1: every JSON row carries a classifier_label field
# ---------------------------------------------------------------------------


def test_json_each_row_has_classifier_label(monkeypatch) -> None:
    """Every row in the ``--json`` output MUST have a
    ``classifier_label`` field populated. Cover all four canonical
    classifier categories at once.

    Pin the env so the deterministic-only path is active (no LLM
    backend) — that's the DEFAULT mode per
    ``[[bouncer-zero-llm-when-agent-in-loop]]``.
    """
    monkeypatch.delenv("IAM_JIT_ENABLE_SIDE_LLM", raising=False)
    monkeypatch.delenv("IAM_JIT_INJECTION_CLASSIFIER_HOOK", raising=False)

    rows = [
        # Destructive verb -> appears_adversarial via heuristic backstop.
        _row(action="s3:DeleteObject", resource="arn:aws:s3:::prod/x"),
        # Non-destructive verbs in default-mode -> pending_classification.
        _row(action="s3:GetObject", resource="arn:aws:s3:::cache/x"),
        _row(action="s3:HeadObject", resource="arn:aws:s3:::cache/y"),
        _row(action="ec2:DescribeInstances", resource="*"),
    ]
    serialized = [_row_to_json_dict(r) for r in rows]

    # State assertion: every row has the field, every value is non-empty.
    for i, row in enumerate(serialized):
        assert "classifier_label" in row, (
            f"row {i} missing classifier_label field; got keys={list(row)}"
        )
        assert row["classifier_label"], (
            f"row {i} has empty classifier_label; row={row}"
        )

    # All values must be drawn from the enumerable set the text output
    # also recognises (or the explicit uncategorized fallback).
    valid_labels = set(_CATEGORY_ORDER) | {_JSON_UNKNOWN_CLASSIFIER_LABEL}
    seen = {row["classifier_label"] for row in serialized}
    assert seen <= valid_labels, (
        f"unexpected classifier_label value(s): {seen - valid_labels}"
    )


# ---------------------------------------------------------------------------
# Invariant 2: per-row classifier_label matches the text-output category
# ---------------------------------------------------------------------------


def test_json_classifier_label_matches_text_output_category(
    monkeypatch,
) -> None:
    """For the SAME input rows the JSON ``classifier_label`` MUST
    match the bucket the text output renders the row under. This is
    the cross-output parity assertion per
    ``[[cross-product-agent-parity]]``."""
    monkeypatch.delenv("IAM_JIT_ENABLE_SIDE_LLM", raising=False)
    monkeypatch.delenv("IAM_JIT_INJECTION_CLASSIFIER_HOOK", raising=False)

    rows = [
        _row(action="s3:DeleteObject", resource="arn:aws:s3:::prod/x"),
        _row(action="s3:GetObject", resource="arn:aws:s3:::cache/x"),
        _row(action="iam:DeleteUser", resource="arn:aws:iam::123:user/svc"),
    ]
    # Text path: count rows that should land in each bucket by running
    # the production classifier (same one the JSON helper uses).
    expected_text_counts: dict[str, int] = {}
    for r in rows:
        cls = _cli_mod._classify_row(r)
        if cls not in _CATEGORY_ORDER:
            cls = _JSON_UNKNOWN_CLASSIFIER_LABEL
        expected_text_counts[cls] = expected_text_counts.get(cls, 0) + 1

    # JSON path: count rows by classifier_label.
    json_rows = [_row_to_json_dict(r) for r in rows]
    json_counts: dict[str, int] = {}
    for jr in json_rows:
        json_counts[jr["classifier_label"]] = (
            json_counts.get(jr["classifier_label"], 0) + 1
        )

    assert json_counts == expected_text_counts, (
        f"json classifier_label distribution {json_counts} does not "
        f"match expected text bucket distribution {expected_text_counts}"
    )

    # Also verify the text renderer's bucket headings appear for each
    # non-empty category — observable state on the text side.
    text_out = _format_denies_table(rows, notes=[])
    for cls, count in expected_text_counts.items():
        if count <= 0:
            continue
        if cls == "appears_adversarial":
            assert "likely-adversarial" in text_out
        elif cls == "appears_legitimate":
            assert "likely-legit" in text_out
        else:
            # ambiguous / pending_classification / uncategorized all
            # surface as some flavor of "ambiguous" or "uncategorized"
            # in the text output.
            assert (
                "ambiguous" in text_out or "uncategorized" in text_out
            ), f"expected ambiguous/uncategorized heading for {cls!r}"


# ---------------------------------------------------------------------------
# Invariant 3: deterministic-only default mode emits pending_classification
# ---------------------------------------------------------------------------


def test_json_pending_classification_label_when_no_llm_backend(
    monkeypatch,
) -> None:
    """In the explicit no-LLM-backend mode (the DEFAULT install path
    per ``[[bouncer-zero-llm-when-agent-in-loop]]``), non-destructive
    verbs MUST surface as ``classifier_label == "pending_classification"``
    in the JSON wire shape — the JSON-side parallel of GH #10's text
    fix.
    """
    monkeypatch.delenv("IAM_JIT_ENABLE_SIDE_LLM", raising=False)
    monkeypatch.delenv("IAM_JIT_INJECTION_CLASSIFIER_HOOK", raising=False)

    row = _row(
        action="s3:GetObject",
        resource="arn:aws:s3:::cache/x",
    )
    serialized = _row_to_json_dict(row)

    assert serialized["classifier_label"] == "pending_classification", (
        f"expected pending_classification in default no-LLM mode; "
        f"got {serialized['classifier_label']!r}"
    )


# ---------------------------------------------------------------------------
# Invariant 4: pinned-hook adversarial label flows through to JSON
# ---------------------------------------------------------------------------


def _adversarial_pinned_hook(**_kwargs: object) -> tuple[str, str]:
    """Module-scoped hook so the IAM_JIT_INJECTION_CLASSIFIER_HOOK
    env-var loader can import + invoke it (the loader does
    ``module:attr`` resolution)."""
    return ("appears_adversarial", "test_pin_575")


def test_json_appears_adversarial_label_when_classifier_assigns(
    monkeypatch,
) -> None:
    """When the classifier hook pins ``appears_adversarial`` for a
    row, the JSON wire shape MUST surface ``classifier_label ==
    "appears_adversarial"`` so downstream agents can prioritize
    high-signal denies without re-running the classifier themselves.
    """
    monkeypatch.setenv(
        "IAM_JIT_INJECTION_CLASSIFIER_HOOK",
        "tests.cli.test_denies_json_classifier_label:_adversarial_pinned_hook",
    )

    row = _row(
        action="s3:GetObject",
        resource="arn:aws:s3:::cache/x",
    )
    serialized = _row_to_json_dict(row)

    assert serialized["classifier_label"] == "appears_adversarial", (
        f"pinned 'appears_adversarial' label not surfaced; "
        f"got {serialized['classifier_label']!r}"
    )


# ---------------------------------------------------------------------------
# Invariant 5: unknown classifier label collapses to "uncategorized"
# ---------------------------------------------------------------------------


def test_json_unknown_label_falls_under_uncategorized(monkeypatch) -> None:
    """Defensive: if a future classifier returns a label outside
    ``_CATEGORY_ORDER``, the JSON wire shape MUST collapse to
    ``classifier_label == "uncategorized"``. Mirrors the GH #10
    union-of-categories pattern on the text side: the wire shape
    stays stable + enumerable for downstream agents regardless of
    classifier evolution.
    """
    monkeypatch.setattr(
        _cli_mod, "_classify_row", lambda _r: "totally_new_label_v2"
    )

    row = _row(
        action="s3:GetObject",
        resource="arn:aws:s3:::cache/x",
    )
    serialized = _row_to_json_dict(row)

    assert serialized["classifier_label"] == "uncategorized", (
        f"unknown classifier label should collapse to 'uncategorized'; "
        f"got {serialized['classifier_label']!r}"
    )


# ---------------------------------------------------------------------------
# Invariant 6: JSON row count equals the count header (parity with GH #10)
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
def test_json_row_count_equals_header_count(
    monkeypatch, actions: list[str]
) -> None:
    """The CLI ``--json`` payload MUST satisfy ``count == len(rows)``
    AND every row MUST have a classifier_label — JSON-side analogue
    of the GH #10 text-output invariant (header N == body N).
    """
    monkeypatch.delenv("IAM_JIT_ENABLE_SIDE_LLM", raising=False)
    monkeypatch.delenv("IAM_JIT_INJECTION_CLASSIFIER_HOOK", raising=False)

    from click.testing import CliRunner
    from iam_jit.cli_audit_query import _BouncerQueryResult
    from iam_jit.cli import main

    def _events_for_actions(action_list: list[str]) -> list[dict]:
        events: list[dict] = []
        for i, a in enumerate(action_list):
            events.append({
                "time": 1_700_000_000_000 + i,
                "_bouncer": "ibounce",
                "metadata": {"product": {"name": "ibounce"}},
                "status_detail": (
                    f"profile 'safe-default': action {a} not in allow_baseline"
                ),
                "api": {"operation": a},
                "resources": [{
                    "uid": f"arn:aws:s3:::bucket/{i}",
                    "name": f"arn:aws:s3:::bucket/{i}",
                }],
                "unmapped": {
                    "iam_jit": {
                        "verdict": "deny",
                        "ext": {"reason": "profile 'safe-default'"},
                        "agent": {"session_id": "sess-575-count"},
                    },
                },
            })
        return events

    captured_events = _events_for_actions(actions)

    def _fake_one(endpoint, **kw):
        if endpoint.name == "ibounce":
            return _BouncerQueryResult(
                bouncer="ibounce",
                events=captured_events,
                error="",
            )
        return _BouncerQueryResult(
            bouncer=endpoint.name, events=[], error="",
        )

    monkeypatch.setattr(
        "iam_jit.cli_audit_query._query_one_bouncer", _fake_one,
    )

    runner = CliRunner()
    result = runner.invoke(main, [
        "denies", "recent", "--since", "1h", "--json",
    ])
    assert result.exit_code == 0, result.output
    payload = json.loads(result.stdout)
    n = len(actions)

    assert payload["count"] == n, (
        f"count header {payload['count']} != input length {n}"
    )
    assert len(payload["rows"]) == n, (
        f"rows array length {len(payload['rows'])} != input length {n}"
    )
    for i, row in enumerate(payload["rows"]):
        assert "classifier_label" in row, (
            f"row {i} missing classifier_label in CLI --json output; "
            f"keys={list(row)}"
        )
        assert row["classifier_label"], (
            f"row {i} has empty classifier_label; row={row}"
        )


# ---------------------------------------------------------------------------
# Invariant 7: sabotage-check — proves Invariant 1 is load-bearing
# ---------------------------------------------------------------------------


def test_sabotage_check_invariant_1_detects_missing_label(monkeypatch) -> None:
    """Sabotage-check per CONTRIBUTING.md: monkeypatch the JSON
    serializer to OMIT the classifier_label field and verify that
    Invariant 1 (every row has classifier_label) would FAIL. This
    proves the invariant catches the original #575 omission shape —
    if a future refactor regresses the fix, Invariant 1 will catch
    it.
    """
    monkeypatch.delenv("IAM_JIT_ENABLE_SIDE_LLM", raising=False)
    monkeypatch.delenv("IAM_JIT_INJECTION_CLASSIFIER_HOOK", raising=False)

    def _sabotaged_serializer(row):  # type: ignore[no-untyped-def]
        # Mimic the pre-#575 wire shape: dataclass dict only, no
        # classifier_label.
        return row.as_dict()

    rows = [
        _row(action="s3:DeleteObject", resource="arn:aws:s3:::prod/x"),
        _row(action="s3:GetObject", resource="arn:aws:s3:::cache/x"),
    ]
    sabotaged_serialized = [_sabotaged_serializer(r) for r in rows]

    # Run the Invariant-1 shape on the sabotaged output: every row must
    # have classifier_label. The sabotaged path MUST fail this check —
    # if it doesn't, Invariant 1 isn't load-bearing.
    missing = [
        i for i, row in enumerate(sabotaged_serialized)
        if "classifier_label" not in row
    ]
    assert missing == [0, 1], (
        "sabotage failed to omit classifier_label — Invariant 1 would "
        f"not catch the #575 regression. missing={missing} "
        f"serialized={sabotaged_serialized}"
    )

    # And the real serializer (post-#575) MUST include the field on
    # every row — observable state on the production path.
    real_serialized = [_row_to_json_dict(r) for r in rows]
    real_missing = [
        i for i, row in enumerate(real_serialized)
        if "classifier_label" not in row
    ]
    assert real_missing == [], (
        f"real serializer omitted classifier_label post-fix — "
        f"regression. serialized={real_serialized}"
    )
