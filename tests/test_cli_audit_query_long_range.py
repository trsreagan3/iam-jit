"""#436 / §A70 — tests for the Phase G long-range additions to
`iam-jit audit query`.

Covers:
  * `--since 2y` shorthand → ISO 8601 lower bound
  * cold-tier stderr warning for windows >= threshold
  * `--scope-filter` JSON classifier (clusters/accounts/regions/...)
  * `--output FILE` streaming (jsonl writes incrementally; non-jsonl
    formats write the rendered body to the file)
  * `--extract-permissions` composes with --scope-filter + --output
  * MCP `bounce_query_audit_long_range` returns streaming + cold-
    tier-warning flag
"""

from __future__ import annotations

import datetime as _dt
import json
import re
import threading
import time as _time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

import pytest
from click.testing import CliRunner

from iam_jit.cli import main as iam_jit_main
from iam_jit.cli_audit_query import (
    LONG_RANGE_WARN_DAYS,
    _event_matches_classifier,
    _parse_scope_filter,
    _parse_since_long_range,
    _since_window_days,
)


# ---------------------------------------------------------------------------
# Pure-function helpers
# ---------------------------------------------------------------------------


def test_parse_since_long_range_handles_year_shorthand():
    iso = _parse_since_long_range("2y")
    assert iso is not None
    # Should be roughly two years before now.
    parsed = _dt.datetime.fromisoformat(iso.replace("Z", "+00:00"))
    delta_days = (_dt.datetime.now(_dt.timezone.utc) - parsed).days
    # 2 * 365 ± 1 day for timing slop.
    assert 728 <= delta_days <= 732


def test_parse_since_long_range_handles_month_shorthand():
    iso = _parse_since_long_range("6M")
    assert iso is not None
    parsed = _dt.datetime.fromisoformat(iso.replace("Z", "+00:00"))
    delta_days = (_dt.datetime.now(_dt.timezone.utc) - parsed).days
    # 6 * 30 = 180 ± 1 day.
    assert 179 <= delta_days <= 181


def test_parse_since_long_range_iso_passthrough():
    assert _parse_since_long_range("2024-01-01T00:00:00Z") == (
        "2024-01-01T00:00:00Z"
    )


def test_since_window_days_handles_year_shorthand():
    assert _since_window_days("2y") == pytest.approx(730.0, abs=0.1)


def test_since_window_days_handles_iso():
    one_year_ago = (
        _dt.datetime.now(_dt.timezone.utc) - _dt.timedelta(days=365)
    ).replace(microsecond=0).isoformat().replace("+00:00", "Z")
    days = _since_window_days(one_year_ago)
    assert days is not None
    assert 364.5 <= days <= 365.5


def test_parse_scope_filter_accepts_classifier_dict():
    result = _parse_scope_filter(
        '{"clusters":["prod-*","staging-east"],"accounts":["999"]}'
    )
    assert result == {
        "clusters": ["prod-*", "staging-east"],
        "accounts": ["999"],
    }


def test_parse_scope_filter_rejects_non_list_values():
    import click

    with pytest.raises(click.BadParameter):
        _parse_scope_filter('{"clusters":"prod-*"}')


def test_event_matches_classifier_glob_on_cluster():
    ev = {
        "unmapped": {"iam_jit": {"cluster": "prod-east"}},
    }
    assert _event_matches_classifier(ev, {"clusters": ["prod-*"]}) is True
    assert _event_matches_classifier(ev, {"clusters": ["staging-*"]}) is False


def test_event_matches_classifier_anded_dimensions():
    ev = {
        "unmapped": {"iam_jit": {"cluster": "prod-east"}},
        "cloud": {"account": {"uid": "999"}, "region": "us-east-1"},
    }
    assert _event_matches_classifier(
        ev,
        {
            "clusters": ["prod-*"],
            "accounts": ["999"],
            "regions": ["us-east-1"],
        },
    ) is True
    # Mismatch on accounts breaks the AND.
    assert _event_matches_classifier(
        ev,
        {"clusters": ["prod-*"], "accounts": ["111"]},
    ) is False


def test_event_matches_classifier_supports_host_dimension():
    ev = {"dst_endpoint": {"hostname": "api.prod.example.com"}}
    assert _event_matches_classifier(
        ev, {"hosts": ["*.prod.example.com"]},
    ) is True
    assert _event_matches_classifier(
        ev, {"hosts": ["*.staging.example.com"]},
    ) is False


def test_event_matches_classifier_empty_means_match_all():
    assert _event_matches_classifier({"anything": "ok"}, {}) is True


# ---------------------------------------------------------------------------
# Mock bouncer (single-server shape — long-range queries are single-
# bouncer per [[bouncer-informs-agent-informs-iam-jit]]).
# ---------------------------------------------------------------------------


def _ocsf_event(
    *,
    operation: str,
    bouncer_name: str = "kbounce",
    cluster: str | None = None,
    account: str | None = None,
    region: str | None = None,
    host: str | None = None,
    seconds_ago: int = 60,
) -> dict[str, Any]:
    now_ms = int(_time.time() * 1000)
    ev: dict[str, Any] = {
        "metadata": {
            "version": "1.1.0",
            "product": {"name": bouncer_name, "vendor_name": "iam-jit"},
        },
        "time": now_ms - seconds_ago * 1000,
        "class_uid": 6003,
        "class_name": "API Activity",
        "category_uid": 6,
        "category_name": "Application Activity",
        "activity_id": 2,
        "activity_name": "Read",
        "severity_id": 1,
        "severity": "Informational",
        "status_id": 1,
        "status": "Success",
        "api": {"operation": operation, "service": {"name": bouncer_name}},
        "unmapped": {"iam_jit": {"verdict": "ALLOW", "mode": "discovery"}},
    }
    if cluster:
        ev["unmapped"]["iam_jit"]["cluster"] = cluster
    if account or region:
        ev.setdefault("cloud", {})
        if account:
            ev["cloud"]["account"] = {"uid": account}
        if region:
            ev["cloud"]["region"] = region
    if host:
        ev["dst_endpoint"] = {"hostname": host}
    return ev


class _SingleMockBouncer:
    def __init__(self, name: str, events: list[dict[str, Any]]):
        self.name = name
        self.events = events
        self.inbound_queries: list[dict[str, list[str]]] = []
        self._server: HTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.port: int = 0

    def start(self) -> None:
        outer = self

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, *_a, **_kw):
                pass

            def do_GET(self):  # noqa: N802
                parsed = urlparse(self.path)
                if parsed.path != "/audit/events":
                    self.send_response(404)
                    self.end_headers()
                    return
                outer.inbound_queries.append(parse_qs(parsed.query))
                self.send_response(200)
                self.send_header("Content-Type", "application/x-ndjson")
                self.end_headers()
                body = "".join(json.dumps(e) + "\n" for e in outer.events)
                self.wfile.write(body.encode("utf-8"))

        self._server = HTTPServer(("127.0.0.1", 0), _Handler)
        self.port = self._server.server_address[1]
        self._thread = threading.Thread(
            target=self._server.serve_forever, daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}"


@pytest.fixture
def kbouncer_mock():
    events = [
        _ocsf_event(
            operation="kube:get pods", cluster="prod-east",
            account="999988887777", seconds_ago=30,
        ),
        _ocsf_event(
            operation="kube:list services", cluster="prod-west",
            account="999988887777", seconds_ago=60,
        ),
        _ocsf_event(
            operation="kube:list configmaps", cluster="staging-east",
            account="111122223333", seconds_ago=90,
        ),
        _ocsf_event(
            operation="kube:list secrets", cluster="staging-west",
            account="111122223333", seconds_ago=120,
        ),
    ]
    b = _SingleMockBouncer("kbounce", events)
    b.start()
    yield b
    b.stop()


# ---------------------------------------------------------------------------
# CLI behaviors
# ---------------------------------------------------------------------------


def _run_query(*args: str):
    runner = CliRunner()
    return runner.invoke(
        iam_jit_main,
        ["audit", "query", *args],
        catch_exceptions=False,
    )


def test_audit_query_scope_filter_supports_classifier_dict(kbouncer_mock):
    """`--scope-filter` filters the returned event stream by the
    deployment-target classifier dimensions."""
    classifier = json.dumps({"clusters": ["prod-*"]})
    result = _run_query(
        "--bouncer", f"kbounce={kbouncer_mock.url}",
        "--scope-filter", classifier,
    )
    assert result.exit_code == 0, result.output
    lines = [ln for ln in result.output.splitlines() if ln.strip()]
    parsed = [json.loads(ln) for ln in lines]
    clusters = {
        ev.get("unmapped", {}).get("iam_jit", {}).get("cluster")
        for ev in parsed
    }
    # Only prod-east + prod-west survived; staging-* filtered out.
    assert clusters == {"prod-east", "prod-west"}


def _combined(result) -> str:
    return (result.output or "") + (getattr(result, "stderr", "") or "")


def test_audit_query_cold_tier_warns_operator(kbouncer_mock):
    """A `--since 2y` window crosses the cold-tier threshold and the
    operator sees a stderr warning."""
    runner = CliRunner()
    result = runner.invoke(
        iam_jit_main,
        [
            "audit", "query",
            "--bouncer", f"kbounce={kbouncer_mock.url}",
            "--since", "2y",
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    # The warning lands on stderr; the event stream lands on stdout.
    # Click 8.3+: stderr separation; we union both for resilience.
    combined = _combined(result).lower()
    assert "cold-tier" in combined or "warning" in combined


def test_audit_query_cold_tier_warning_disabled_by_zero(kbouncer_mock):
    runner = CliRunner()
    result = runner.invoke(
        iam_jit_main,
        [
            "audit", "query",
            "--bouncer", f"kbounce={kbouncer_mock.url}",
            "--since", "2y",
            "--cold-tier-warn-days", "0",
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    # No cold-tier warning when explicitly disabled.
    assert "cold-tier" not in _combined(result).lower()


def test_audit_query_since_2y_streams_response_not_loaded_into_memory(
    kbouncer_mock, tmp_path,
):
    """The `--output FILE` path writes incrementally; combined with
    a year+ window this is the streaming-response shape the long-
    range spec requires."""
    out_path = tmp_path / "two_year_window.ndjson"
    runner = CliRunner()
    result = runner.invoke(
        iam_jit_main,
        [
            "audit", "query",
            "--bouncer", f"kbounce={kbouncer_mock.url}",
            "--since", "2y",
            "--output", str(out_path),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    # Stdout itself should NOT carry the JSONL events when --output
    # is set (the warning may land on the combined stream — we only
    # check that the JSONL events went to the file).
    stdout_only = result.stdout or ""
    # No `{"metadata"...}` JSONL lines on stdout.
    for line in stdout_only.splitlines():
        if line.strip().startswith("{"):
            raise AssertionError(
                f"unexpected JSONL event on stdout: {line}",
            )
    # File exists + each line parses as JSON (NDJSON).
    body = out_path.read_text()
    lines = [ln for ln in body.splitlines() if ln.strip()]
    assert len(lines) == 4
    for ln in lines:
        json.loads(ln)
    # The cold-tier stderr warning still fires for the 2y window.
    assert "warning" in _combined(result).lower()


def test_audit_query_composes_with_extract_permissions_flag(
    kbouncer_mock, tmp_path,
):
    """`--extract-permissions` reshapes the merged stream; --output
    + --scope-filter both compose with it."""
    out_path = tmp_path / "perms.json"
    classifier = json.dumps({"clusters": ["prod-*"]})
    runner = CliRunner()
    result = runner.invoke(
        iam_jit_main,
        [
            "audit", "query",
            "--bouncer", f"kbounce={kbouncer_mock.url}",
            "--since", "1y",
            "--scope-filter", classifier,
            "--extract-permissions",
            "--output", str(out_path),
        ],
        catch_exceptions=False,
    )
    assert result.exit_code == 0, result.output
    doc = json.loads(out_path.read_text())
    assert doc["bouncer"] == "kbounce"
    # Only prod-* events survived the scope filter (2 events).
    assert doc["events_analyzed"] == 2


# ---------------------------------------------------------------------------
# MCP backend
# ---------------------------------------------------------------------------


def test_mcp_bounce_query_audit_long_range_returns_streaming(kbouncer_mock):
    """The MCP backend returns a streaming-shaped envelope (events
    list + cold_tier_warning flag + scope-filter stats)."""
    from iam_jit.mcp_server import _bounce_query_audit_long_range_for_mcp

    payload = _bounce_query_audit_long_range_for_mcp({
        "bouncer": f"kbounce={kbouncer_mock.url}",
        "since": "2y",
        "scope_filter": {"clusters": ["prod-*"]},
        "limit": 100,
    })
    assert payload["status"] == "ok"
    assert payload["bouncer"] == "kbounce"
    assert payload["cold_tier_warning"] is True
    assert payload["events_before_scope_filter"] == 4
    assert payload["events_returned"] == 2
    assert payload["scope_filter_applied"] == {"clusters": ["prod-*"]}
    clusters = {
        ev.get("unmapped", {}).get("iam_jit", {}).get("cluster")
        for ev in payload["events"]
    }
    assert clusters == {"prod-east", "prod-west"}


def test_mcp_bounce_query_audit_long_range_no_warning_for_recent_window(
    kbouncer_mock,
):
    from iam_jit.mcp_server import _bounce_query_audit_long_range_for_mcp

    payload = _bounce_query_audit_long_range_for_mcp({
        "bouncer": f"kbounce={kbouncer_mock.url}",
        "since": "1h",
        "limit": 100,
    })
    assert payload["status"] == "ok"
    assert payload["cold_tier_warning"] is False
    assert payload["events_returned"] == 4
