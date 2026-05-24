"""Ambient-config-test fixtures.

Per GH #9 (test env isolation, sibling to GH #5): tests in this
directory exercise ``iam-jit doctor apply-config`` and the
``apply_declaration`` / ``plan_declaration`` planners. When invoked
without an explicit ``posture=`` kwarg those planners call
``iam_jit.ambient_config.setup._capture_posture_safe`` which imports
``iam_jit.posture.capture_posture`` and snapshots the LIVE host posture.

On a dogfood machine a real ibounce is typically listening on
``127.0.0.1:8767`` (the developer's own session bouncer). Posture
detection correctly classifies it as ``running``, which causes
``apply_declaration`` to add ibounce to ``bouncers_already_running``
(per [[creates-never-mutates]]) instead of ``bouncers_planned``.
``test_doctor_apply_config_reads_iam_jit_yaml_in_cwd`` (and any sibling
test that asserts a clean-slate plan) then fails non-deterministically
depending on whether the developer has dev-ibounce up.

This autouse fixture monkeypatches ``iam_jit.posture.capture_posture``
to return a clean-slate snapshot (no bouncers running) for every test
in ``tests/ambient_config/``. Tests that need a specific posture
override should pass it explicitly via the planner's ``posture=`` kwarg
(the pattern used throughout ``test_setup.py``,
``test_setup_from_config_transactional.py``, etc.) — that bypasses the
autouse-mocked capture entirely.

Per docs/CONTRIBUTING.md state-verification convention: the included
``test_conftest_clean_slate_posture_active`` confirms the fixture is
wired correctly so a future regression that disables it surfaces here
rather than in the downstream test that depends on it.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any

import pytest


def _clean_slate_snapshot() -> dict[str, Any]:
    """Return a posture snapshot in which no bouncers are running.

    Mirrors the shape ``iam_jit.posture.capture_posture`` returns (see
    ``src/iam_jit/posture/report.py``): an outer dict with a
    ``bouncers`` mapping whose entries each have ``running: False``.
    """
    return {
        "iam_jit": {},
        "bouncers": {
            "ibounce": {"running": False, "port": 8767, "default_port": 8767,
                        "mode": "unknown", "active_profile": "unknown"},
            "kbounce": {"running": False, "port": 8766, "default_port": 8766,
                        "mode": "unknown", "active_profile": "unknown"},
            "dbounce": {"running": False, "port": 5433, "default_port": 5433,
                        "mode": "unknown", "active_profile": "unknown"},
            "gbounce": {"running": False, "port": 8080, "default_port": 8080,
                        "mode": "unknown", "active_profile": "unknown"},
        },
        "effective": {},
        "tips": [],
    }


@pytest.fixture(autouse=True)
def _isolate_ambient_config_posture(
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[None]:
    """Force ``iam_jit.posture.capture_posture`` to return clean-slate.

    Per GH #9: prevents a dogfood ibounce on :8767 from shadowing the
    clean-slate posture assumption of ``apply_declaration`` callers
    that don't pass an explicit ``posture=`` kwarg.
    """
    from iam_jit import posture as posture_pkg

    def _fake_capture_posture(*, sanitize: bool = True) -> dict[str, Any]:
        return _clean_slate_snapshot()

    monkeypatch.setattr(posture_pkg, "capture_posture", _fake_capture_posture)
    yield


def test_conftest_clean_slate_posture_active() -> None:
    """State-verification per docs/CONTRIBUTING.md: confirms the autouse
    ``_isolate_ambient_config_posture`` fixture is active so a future
    refactor that disables it fails here, not downstream."""
    from iam_jit.posture import capture_posture

    snap = capture_posture()
    for name in ("ibounce", "kbounce", "dbounce", "gbounce"):
        assert snap["bouncers"][name]["running"] is False, (
            f"clean-slate posture fixture is NOT active; "
            f"{name} reports running={snap['bouncers'][name]['running']!r}. "
            f"Check tests/ambient_config/conftest.py per GH #9."
        )
