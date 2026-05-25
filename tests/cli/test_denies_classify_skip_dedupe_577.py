"""#577 MED state-verification — denies recent deduplicates the
``structured_deny.classify: ran deterministic-only`` skip banner.

UAT-B 2026-05-25 finding G6: ``iam-jit denies recent`` emitted ONE
``logger.warning`` banner per ``pending_classification`` row (UAT-B
observed 21 identical banners for a 21-row deterministic-only
invocation). Cosmetic but UX-degrading: terminal fills with
repetitive noise on routine queries.

Fix: caller-side aggregation. The CLI denies command wraps its
render in :func:`iam_jit.cli_profile_allow._suppress_classify_skip`
(forwards ``suppress_skip_report=True`` through
:func:`_classify_row` -> :func:`classify_injection_likelihood`),
pre-counts pending rows, and emits ONE aggregated banner with the
count.

Per the state-verification convention in ``docs/CONTRIBUTING.md``
every test here asserts an OBSERVABLE invariant of stderr / log
state (caplog record count + message content), not internal function
returns.

Discipline tags:
  * ``[[ibounce-honest-positioning]]`` — consolidate, never suppress.
    The aggregated banner says WHAT (deterministic classification) +
    WHY (no LLM backend) + HOW to enable LLM (mode_hint).
  * ``[[cross-product-agent-parity]]`` — the JSON and text paths
    both classify rows; both must dedupe.
  * The sabotage-check (test 5) proves the dedup is load-bearing —
    it would catch a future regression that re-introduced per-row
    banners.
"""

from __future__ import annotations

import json
import logging
from typing import Any

import pytest
from click.testing import CliRunner

from iam_jit import cli_profile_allow as _cli_mod
from iam_jit.cli import main
from iam_jit.cli_audit_query import _BouncerQueryResult
from iam_jit.llm.report_skip import reset_skip_counter


_LOGGER_NAME = "iam_jit.llm.skip"


def _pending_classification_event(action: str, i: int) -> dict[str, Any]:
    """Build an audit event that the fetch_recent_denies parser turns
    into a DenyRow which classifies as ``pending_classification`` (the
    deterministic-only default: non-destructive verb, no LLM backend).
    """
    return {
        "time": 1_700_000_000_000 + i,
        "_bouncer": "ibounce",
        "metadata": {"product": {"name": "ibounce"}},
        "status_detail": (
            f"profile 'safe-default': action {action} not in allow_baseline"
        ),
        "api": {"operation": action},
        "resources": [{
            "uid": f"arn:aws:s3:::bucket/{i}",
            "name": f"arn:aws:s3:::bucket/{i}",
        }],
        "unmapped": {
            "iam_jit": {
                "verdict": "deny",
                "ext": {"reason": "profile 'safe-default'"},
                "agent": {"session_id": "sess-577"},
            },
        },
    }


def _wire_fake_bouncer(
    monkeypatch: pytest.MonkeyPatch, events: list[dict[str, Any]]
) -> None:
    """Stub the bouncer query so fetch_recent_denies returns ``events``
    as if scraped from a live ibounce ``/audit/events`` endpoint."""
    def _fake_one(endpoint, **_kw):  # type: ignore[no-untyped-def]
        if endpoint.name == "ibounce":
            return _BouncerQueryResult(
                bouncer="ibounce", events=events, error="",
            )
        return _BouncerQueryResult(
            bouncer=endpoint.name, events=[], error="",
        )

    monkeypatch.setattr(
        "iam_jit.cli_audit_query._query_one_bouncer", _fake_one,
    )


def _classify_skip_records(caplog: pytest.LogCaptureFixture) -> list[Any]:
    """Return all caplog records emitted by the structured_deny.classify
    skip-report path (the banner the dedup targets)."""
    return [
        r for r in caplog.records
        if r.name == _LOGGER_NAME
        and getattr(r, "llm_skip_feature", None) == "structured_deny.classify"
    ]


@pytest.fixture(autouse=True)
def _reset_skip_counter() -> None:
    """Reset the process-local skip counter between tests so per-test
    snapshots stay deterministic. Mirrors the convention in
    tests/llm/test_report_skip.py."""
    reset_skip_counter()
    yield
    reset_skip_counter()


# ---------------------------------------------------------------------------
# Invariant 1: many pending rows -> exactly one aggregated banner
# ---------------------------------------------------------------------------


def test_denies_recent_emits_single_no_llm_banner_for_many_pending(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
) -> None:
    """The #577 core fix: feed 10 pending_classification rows; stderr
    has EXACTLY ONE structured_deny.classify banner mentioning the
    count — not 10. Pre-fix shape was N banners per N rows (UAT-B
    observed 21).
    """
    monkeypatch.delenv("IAM_JIT_ENABLE_SIDE_LLM", raising=False)
    monkeypatch.delenv("IAM_JIT_INJECTION_CLASSIFIER_HOOK", raising=False)
    caplog.set_level(logging.WARNING, logger=_LOGGER_NAME)

    events = [
        _pending_classification_event(f"s3:GetObject", i)
        for i in range(10)
    ]
    _wire_fake_bouncer(monkeypatch, events)

    runner = CliRunner()
    result = runner.invoke(main, ["denies", "recent", "--since", "1h"])
    assert result.exit_code == 0, result.output

    records = _classify_skip_records(caplog)
    assert len(records) == 1, (
        f"expected exactly 1 aggregated structured_deny.classify banner; "
        f"got {len(records)}: "
        f"{[r.getMessage() for r in records]}"
    )


# ---------------------------------------------------------------------------
# Invariant 2: zero pending rows -> zero banners
# ---------------------------------------------------------------------------


def test_denies_recent_no_banner_when_zero_pending(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
) -> None:
    """When the window contains no rows that land in
    ``pending_classification`` (e.g. all rows hit the destructive-verb
    structural-heuristic backstop -> appears_adversarial), the
    aggregated banner MUST NOT fire — there's no skip to report.
    """
    monkeypatch.delenv("IAM_JIT_ENABLE_SIDE_LLM", raising=False)
    monkeypatch.delenv("IAM_JIT_INJECTION_CLASSIFIER_HOOK", raising=False)
    caplog.set_level(logging.WARNING, logger=_LOGGER_NAME)

    # Destructive verbs go down the structural-heuristic path which
    # returns appears_adversarial WITHOUT calling report_skip.
    events = [
        _pending_classification_event("s3:DeleteObject", i)
        for i in range(5)
    ]
    _wire_fake_bouncer(monkeypatch, events)

    runner = CliRunner()
    result = runner.invoke(main, ["denies", "recent", "--since", "1h"])
    assert result.exit_code == 0, result.output

    records = _classify_skip_records(caplog)
    assert records == [], (
        f"expected no banners for all-destructive-verb batch; "
        f"got {len(records)}: {[r.getMessage() for r in records]}"
    )


# ---------------------------------------------------------------------------
# Invariant 3: empty result set -> zero banners
# ---------------------------------------------------------------------------


def test_denies_recent_no_banner_when_zero_rows(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
) -> None:
    """No rows fetched at all -> no aggregated banner. Defensive
    check on the helper's pending_count <= 0 guard."""
    monkeypatch.delenv("IAM_JIT_ENABLE_SIDE_LLM", raising=False)
    monkeypatch.delenv("IAM_JIT_INJECTION_CLASSIFIER_HOOK", raising=False)
    caplog.set_level(logging.WARNING, logger=_LOGGER_NAME)

    _wire_fake_bouncer(monkeypatch, [])

    runner = CliRunner()
    result = runner.invoke(main, ["denies", "recent", "--since", "1h"])
    assert result.exit_code == 0, result.output

    records = _classify_skip_records(caplog)
    assert records == [], (
        f"empty fetch should emit zero banners; got {len(records)}"
    )


# ---------------------------------------------------------------------------
# Invariant 4: aggregated banner message contains the pending-row count
# ---------------------------------------------------------------------------


def test_denies_recent_banner_message_includes_count(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
) -> None:
    """The aggregated banner MUST surface the pending-row count so the
    operator sees "21 of N row(s) classified deterministically", not a
    generic "ran deterministic-only" with no batch context.
    """
    monkeypatch.delenv("IAM_JIT_ENABLE_SIDE_LLM", raising=False)
    monkeypatch.delenv("IAM_JIT_INJECTION_CLASSIFIER_HOOK", raising=False)
    caplog.set_level(logging.WARNING, logger=_LOGGER_NAME)

    n = 7
    events = [
        _pending_classification_event("s3:GetObject", i) for i in range(n)
    ]
    _wire_fake_bouncer(monkeypatch, events)

    runner = CliRunner()
    result = runner.invoke(main, ["denies", "recent", "--since", "1h"])
    assert result.exit_code == 0, result.output

    records = _classify_skip_records(caplog)
    assert len(records) == 1, (
        f"expected single banner; got {len(records)}"
    )
    msg = records[0].getMessage()
    assert str(n) in msg, (
        f"expected pending-row count {n} in banner message; got: {msg!r}"
    )
    # The structured extra field also carries the count for downstream
    # log shippers.
    assert getattr(records[0], "llm_skip_pending_rows", None) == n, (
        f"extra field llm_skip_pending_rows should equal {n}; got "
        f"{getattr(records[0], 'llm_skip_pending_rows', None)!r}"
    )


# ---------------------------------------------------------------------------
# Invariant 5: --json shape is unchanged (stderr-only fix)
# ---------------------------------------------------------------------------


def test_denies_recent_json_output_shape_unchanged(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per the brief out-of-scope: the JSON shape must be unchanged.
    Banners are stderr-only; --json on stdout still carries every
    row + classifier_label per #575.
    """
    monkeypatch.delenv("IAM_JIT_ENABLE_SIDE_LLM", raising=False)
    monkeypatch.delenv("IAM_JIT_INJECTION_CLASSIFIER_HOOK", raising=False)

    events = [
        _pending_classification_event("s3:GetObject", i) for i in range(4)
    ]
    _wire_fake_bouncer(monkeypatch, events)

    runner = CliRunner()
    result = runner.invoke(
        main, ["denies", "recent", "--since", "1h", "--json"],
    )
    assert result.exit_code == 0, result.output

    payload = json.loads(result.stdout)
    assert payload["count"] == 4
    assert len(payload["rows"]) == 4
    for row in payload["rows"]:
        assert row.get("classifier_label") == "pending_classification"


# ---------------------------------------------------------------------------
# Invariant 6: sabotage-check — Invariant 1 IS load-bearing
# ---------------------------------------------------------------------------


def test_sabotage_check_invariant_1_catches_pre_fix_shape(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture,
) -> None:
    """Sabotage-check per CONTRIBUTING.md: monkeypatch
    :func:`_classify_row` to call the underlying classifier WITHOUT
    forwarding the suppress flag — restoring the pre-#577 per-row
    banner shape. Invariant 1 (exactly 1 banner) MUST then fail,
    proving the dedup is load-bearing.
    """
    monkeypatch.delenv("IAM_JIT_ENABLE_SIDE_LLM", raising=False)
    monkeypatch.delenv("IAM_JIT_INJECTION_CLASSIFIER_HOOK", raising=False)
    caplog.set_level(logging.WARNING, logger=_LOGGER_NAME)

    # Restore the pre-fix shape: classify each row WITHOUT honoring the
    # context-var suppression. Matches the original codepath that
    # produced 21 banners in UAT-B G6.
    def _pre_fix_classify_row(row) -> str:  # type: ignore[no-untyped-def]
        from iam_jit.structured_deny import classify_injection_likelihood
        cls, _hook = classify_injection_likelihood(
            action=row.action or "",
            resource=row.resource or "",
            deny_source=row.deny_source or "",
            deny_reason=row.deny_reason or "",
            agent_session_id=row.agent_session_id or "",
            # suppress_skip_report intentionally OMITTED -> defaults to
            # False -> per-row banners are emitted.
        )
        return cls

    monkeypatch.setattr(_cli_mod, "_classify_row", _pre_fix_classify_row)

    n = 8
    events = [
        _pending_classification_event("s3:GetObject", i) for i in range(n)
    ]
    _wire_fake_bouncer(monkeypatch, events)

    runner = CliRunner()
    result = runner.invoke(main, ["denies", "recent", "--since", "1h"])
    assert result.exit_code == 0, result.output

    records = _classify_skip_records(caplog)
    # Pre-fix shape: aggregated banner from the helper (1) PLUS one
    # banner per row from each render-time classify call (renderer
    # iterates rows twice — pre-count + bucket-render — but the
    # important sabotage signal is "many banners, not one").
    assert len(records) > 1, (
        f"sabotage should re-introduce per-row banners; saw "
        f"{len(records)} — Invariant 1 would not catch the #577 "
        f"regression"
    )
