"""§M4 — tests for the dogfood-metrics writers in ``cli_canary``.

Per docs/MRR-5-MONITORING-RUNBOOK.md §M4: three fields in status.json
(``denies_24h``, ``intervention_count_24h``, ``improvement_cycles``)
were READ by ``status_cmd`` + ``report_cmd`` but NEVER WRITTEN. The
phantom-fields shape is calibration-drift catalog entry #22 — the
exact #475 ``state-claimed-without-observable-state`` shape on the
canary surface.

Per docs/CONTRIBUTING.md state-verification convention: every test
below asserts the OBSERVABLE value (the persisted status.json field +
the rendered output) matches the mocked source, not just that the
helper "ran".
"""

from __future__ import annotations

import datetime as _dt
import io
import json
import pathlib
import urllib.error

import pytest
from click.testing import CliRunner

import iam_jit.cli_canary as cc
from iam_jit.cli import main


@pytest.fixture
def isolated_canary(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> pathlib.Path:
    """Point ALL canary-module paths at a tmp dir + isolate the
    autopilot-status dir so tests never touch the operator's real
    ~/.iam-jit/."""
    canary_dir = tmp_path / "canary"
    canary_dir.mkdir()
    monkeypatch.setattr(cc, "CANARY_DIR", canary_dir)
    monkeypatch.setattr(cc, "ISSUES_PATH", canary_dir / "issues.jsonl")
    monkeypatch.setattr(cc, "NOTES_PATH", canary_dir / "notes.md")
    monkeypatch.setattr(cc, "STATUS_PATH", canary_dir / "status.json")
    monkeypatch.setattr(cc, "URLS_PATH", canary_dir / "urls.md")
    # Isolate autopilot status into a separate tmp dir.
    autopilot_dir = tmp_path / "autopilot_home"
    autopilot_dir.mkdir()
    monkeypatch.setenv("IAM_JIT_AUTOPILOT_DIR", str(autopilot_dir))
    return canary_dir


def _now_iso_for_issues(offset_seconds: int = 0) -> str:
    """Return a UTC ISO 8601 timestamp suitable for issues.jsonl ``ts``.

    ``offset_seconds`` is added to *now*; pass a negative number for
    "this many seconds ago" (issues older than 24h test).
    """
    t = _dt.datetime.now(tz=_dt.timezone.utc) + _dt.timedelta(
        seconds=offset_seconds
    )
    return t.strftime("%Y-%m-%dT%H:%M:%SZ")


class _FakeAuditResponse:
    """File-like stand-in for urlopen's context-manager return value."""

    def __init__(self, body: str, status: int = 200) -> None:
        self._buf = io.BytesIO(body.encode("utf-8"))
        self._status = status

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self._buf.close()
        return False

    def read(self) -> bytes:
        return self._buf.read()

    def getcode(self) -> int:
        return self._status


def _ocsf_deny_line(decision_id: int, verdict: str = "deny") -> str:
    """Build one minimal OCSF v1.1.0 class 6003 event JSONL line with
    the given verdict at ``unmapped.iam_jit.verdict``.
    """
    ev = {
        "metadata": {"version": "1.1.0"},
        "time": int(_dt.datetime.now(tz=_dt.timezone.utc).timestamp() * 1000),
        "class_uid": 6003,
        "unmapped": {"iam_jit": {"verdict": verdict,
                                  "decision_id": decision_id}},
    }
    return json.dumps(ev, separators=(",", ":"))


def _ocsf_allow_line(decision_id: int) -> str:
    ev = {
        "metadata": {"version": "1.1.0"},
        "time": int(_dt.datetime.now(tz=_dt.timezone.utc).timestamp() * 1000),
        "class_uid": 6003,
        "unmapped": {"iam_jit": {"verdict": "allow",
                                  "decision_id": decision_id}},
    }
    return json.dumps(ev, separators=(",", ":"))


def _install_urlopen_mock(
    monkeypatch: pytest.MonkeyPatch,
    *,
    per_port_bodies: dict[int, str],
    per_port_errors: dict[int, Exception] | None = None,
) -> list[str]:
    """Patch ``urllib.request.urlopen`` used by ``cli_canary`` so each
    bouncer port returns the configured body (or raises the configured
    error).

    Returns a list that captures every URL the helper requested — the
    test can assert which bouncers were polled.
    """
    requested_urls: list[str] = []
    errors = per_port_errors or {}

    def fake_urlopen(req, timeout=None):  # noqa: ARG001
        url = req.full_url if hasattr(req, "full_url") else str(req)
        requested_urls.append(url)
        # Parse port from URL (host is always 127.0.0.1).
        # URL shape: http://127.0.0.1:<port>/audit/events?...
        port = None
        try:
            after_colon = url.split("127.0.0.1:")[1]
            port_str = after_colon.split("/")[0]
            port = int(port_str)
        except (IndexError, ValueError):
            port = None
        if port is not None and port in errors:
            raise errors[port]
        body = per_port_bodies.get(port, "")
        return _FakeAuditResponse(body)

    monkeypatch.setattr(cc.urllib.request, "urlopen", fake_urlopen)
    return requested_urls


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_denies_24h_aggregates_across_bouncers(
    isolated_canary: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """State-verification: status.json ``denies_24h`` equals the sum of
    mocked per-bouncer deny counts (3 from ibounce + 2 from gbounce_mgmt)."""
    cc.write_status({
        "canary_day": 1,
        "ports": {
            "ibounce": 7401,
            "gbounce": 7402,
            "gbounce_mgmt": 7412,
        },
    })

    ibounce_body = "\n".join(
        _ocsf_deny_line(i) for i in range(3)
    ) + "\n" + _ocsf_allow_line(99)  # 1 allow ignored
    gbounce_body = "\n".join(
        _ocsf_deny_line(i, verdict="DENY") for i in range(2)
    )
    # gbounce mgmt is the audit endpoint; the proxy port (7402) must
    # NOT be queried (would double-count).
    bodies = {7401: ibounce_body, 7412: gbounce_body}
    requested = _install_urlopen_mock(monkeypatch, per_port_bodies=bodies)

    updated = cc._refresh_dogfood_metrics()

    # 1. Reported value (return + persisted) is 5 (3 + 2).
    assert updated["denies_24h"] == 5, updated

    # 2. Observable: status.json on disk matches.
    persisted = json.loads((isolated_canary / "status.json").read_text())
    assert persisted["denies_24h"] == 5

    # 3. Observable: gbounce mgmt was queried; gbounce proxy port was NOT.
    urls_str = " ".join(requested)
    assert "127.0.0.1:7412" in urls_str
    assert "127.0.0.1:7401" in urls_str
    assert "127.0.0.1:7402" not in urls_str

    # 4. degraded_sources is absent because all sources answered.
    assert "dogfood_metrics_degraded_sources" not in persisted


def test_denies_24h_skips_unreachable_bouncer(
    isolated_canary: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """State-verification: when one bouncer is unreachable, the
    aggregate is the reachable bouncer's count AND
    degraded_sources contains the unreachable bouncer name."""
    cc.write_status({
        "ports": {
            "ibounce": 7401,
            "gbounce": 7402,
            "gbounce_mgmt": 7412,
        },
    })

    ibounce_body = "\n".join(_ocsf_deny_line(i) for i in range(4))
    bodies = {7401: ibounce_body}
    errors = {7412: urllib.error.URLError("Connection refused")}
    _install_urlopen_mock(
        monkeypatch, per_port_bodies=bodies, per_port_errors=errors,
    )

    updated = cc._refresh_dogfood_metrics()

    # 1. denies_24h reflects ONLY the reachable bouncer (4).
    assert updated["denies_24h"] == 4

    # 2. Observable: persisted status carries the degraded source.
    persisted = json.loads((isolated_canary / "status.json").read_text())
    assert persisted["denies_24h"] == 4
    degraded = persisted.get("dogfood_metrics_degraded_sources") or []
    # gbounce was the unreachable one — joined as "<name>:<reason>".
    assert any(s.startswith("gbounce:") for s in degraded), degraded


def test_intervention_count_24h_filters_correctly(
    isolated_canary: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """State-verification: intervention_count_24h matches the count of
    issues whose category=operator_friction OR severity in (HIGH, CRIT).
    """
    cc.write_status({"ports": {}})  # no bouncers → no /audit fan-out

    # No URL mock needed (no ports), but install a 0-body default
    # in case future code paths fan out anyway.
    _install_urlopen_mock(monkeypatch, per_port_bodies={})

    # 3 interventions: 1 operator_friction (LOW), 1 HIGH, 1 CRIT.
    # 2 non-interventions: 1 LOW/other, 1 MED/other.
    cc.append_issue(
        bouncer="ibounce", severity="LOW", category="operator_friction",
        observable="friction case", expected="smooth",
    )
    cc.append_issue(
        bouncer="ibounce", severity="HIGH", category="deny_surprise",
        observable="high case", expected="x",
    )
    cc.append_issue(
        bouncer="gbounce", severity="CRIT", category="bouncer_error",
        observable="crit case", expected="x",
    )
    cc.append_issue(
        bouncer="ibounce", severity="LOW", category="other",
        observable="ignored LOW", expected="x",
    )
    cc.append_issue(
        bouncer="ibounce", severity="MED", category="other",
        observable="ignored MED", expected="x",
    )

    updated = cc._refresh_dogfood_metrics()

    # 1. Counted intervention shape.
    assert updated["intervention_count_24h"] == 3, updated

    # 2. Observable persisted file matches.
    persisted = json.loads((isolated_canary / "status.json").read_text())
    assert persisted["intervention_count_24h"] == 3


def test_intervention_count_24h_respects_24h_window(
    isolated_canary: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """State-verification: issues older than 24h are NOT counted."""
    cc.write_status({"ports": {}})
    _install_urlopen_mock(monkeypatch, per_port_bodies={})

    # 1 inside window (HIGH), 1 outside window (HIGH).
    cc.append_issue(
        bouncer="ibounce", severity="HIGH", category="deny_surprise",
        observable="recent high", expected="x",
        ts=_now_iso_for_issues(offset_seconds=-3600),  # 1h ago
    )
    cc.append_issue(
        bouncer="ibounce", severity="HIGH", category="deny_surprise",
        observable="old high", expected="x",
        ts=_now_iso_for_issues(offset_seconds=-(48 * 3600)),  # 48h ago
    )

    updated = cc._refresh_dogfood_metrics()

    # Only the recent one counts.
    assert updated["intervention_count_24h"] == 1, updated
    persisted = json.loads((isolated_canary / "status.json").read_text())
    assert persisted["intervention_count_24h"] == 1


def test_improvement_cycles_from_autopilot(
    isolated_canary: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """State-verification: improvement_cycles reads
    ``autopilot.status.json``'s ``.improve.improve_count_since_startup``
    when the file exists."""
    cc.write_status({"ports": {}})
    _install_urlopen_mock(monkeypatch, per_port_bodies={})

    autopilot_dir = pathlib.Path(
        __import__("os").environ["IAM_JIT_AUTOPILOT_DIR"]
    )
    (autopilot_dir / "autopilot.status.json").write_text(
        json.dumps(
            {
                "schema_version": "1.1",
                "improve": {
                    "enabled": True,
                    "improve_count_since_startup": 7,
                },
            }
        ),
        encoding="utf-8",
    )

    updated = cc._refresh_dogfood_metrics()
    assert updated["improvement_cycles"] == 7, updated

    persisted = json.loads((isolated_canary / "status.json").read_text())
    assert persisted["improvement_cycles"] == 7


def test_improvement_cycles_zero_when_autopilot_absent(
    isolated_canary: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """State-verification: missing autopilot file → improvement_cycles=0
    (honest 0 per [[ibounce-honest-positioning]] — file absence IS the
    observable signal). NOT a phantom write, NOT a synthesised count.
    """
    cc.write_status({"ports": {}})
    _install_urlopen_mock(monkeypatch, per_port_bodies={})

    # Do NOT create autopilot.status.json.
    updated = cc._refresh_dogfood_metrics()
    assert updated["improvement_cycles"] == 0

    persisted = json.loads((isolated_canary / "status.json").read_text())
    assert persisted["improvement_cycles"] == 0


def test_status_json_writers_invoked_on_canary_status(
    isolated_canary: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """End-to-end: invoking ``iam-jit canary status`` populates the
    three fields in status.json with values matching the mocked
    sources."""
    cc.write_status({
        "canary_day": 1,
        "started_at": "2026-05-23T22:00:00Z",
        "llm_mode": "agent-delegated",
        "bouncers": {"ibounce": "discovery"},
        "ports": {"ibounce": 7401},
        "commits": {"iam-roles": "abc1234567890"},
    })

    bodies = {
        7401: "\n".join(_ocsf_deny_line(i) for i in range(2)),
    }
    _install_urlopen_mock(monkeypatch, per_port_bodies=bodies)

    # Add 1 intervention (HIGH issue).
    cc.append_issue(
        bouncer="ibounce", severity="HIGH", category="deny_surprise",
        observable="intervention case", expected="x",
    )

    # Seed autopilot.status.json so improvement_cycles is non-zero.
    autopilot_dir = pathlib.Path(
        __import__("os").environ["IAM_JIT_AUTOPILOT_DIR"]
    )
    (autopilot_dir / "autopilot.status.json").write_text(
        json.dumps({"improve": {"improve_count_since_startup": 4}}),
        encoding="utf-8",
    )

    runner = CliRunner()
    result = runner.invoke(main, ["canary", "status", "--json"])
    assert result.exit_code == 0, result.output

    parsed = json.loads(result.output)
    # Each field matches the mocked source — no claim w/o observable
    # state per docs/CONTRIBUTING.md.
    assert parsed["denies_24h"] == 2, parsed
    assert parsed["intervention_count_24h"] == 1, parsed
    assert parsed["improvement_cycles"] == 4, parsed

    # And the on-disk file matches what the JSON output reported.
    persisted = json.loads((isolated_canary / "status.json").read_text())
    assert persisted["denies_24h"] == 2
    assert persisted["intervention_count_24h"] == 1
    assert persisted["improvement_cycles"] == 4


def test_no_phantom_fields(
    isolated_canary: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Regression guard for the §M4 phantom-fields shape: after
    ``iam-jit canary status`` runs, all three dogfood-metric fields
    must be present in status.json AND must be ints (never null,
    never absent). This is the exact #475 + #463 shape guard.
    """
    cc.write_status({
        "canary_day": 1,
        "ports": {"ibounce": 7401},
    })

    bodies = {7401: ""}  # zero deny events
    _install_urlopen_mock(monkeypatch, per_port_bodies=bodies)

    runner = CliRunner()
    result = runner.invoke(main, ["canary", "status", "--json"])
    assert result.exit_code == 0, result.output

    parsed = json.loads(result.output)
    for field in (
        "denies_24h",
        "intervention_count_24h",
        "improvement_cycles",
    ):
        assert field in parsed, (
            f"{field!r} missing from status.json after canary status "
            f"— that is the §M4 phantom-fields shape"
        )
        assert isinstance(parsed[field], int), (
            f"{field!r} must be int, got {type(parsed[field]).__name__}; "
            f"value={parsed[field]!r}"
        )

    # Also assert the freshness stamp is present so operators can tell
    # the refresh actually ran (not just reading stale persisted values).
    assert "dogfood_metrics_computed_at" in parsed
