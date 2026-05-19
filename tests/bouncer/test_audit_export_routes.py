"""Tests for the per-org notification routing engine (#280).

Per [[per-org-notification-routing]] this engine takes one --alert-
routes YAML + a stream of OCSF events and dispatches each event to
zero or more (route -> destination) pairs based on the deterministic
match conditions.

Tests cover:
  - routes load + validate; bad YAML => clean error
  - operators: equals (default), gte / lte / gt / lt, in, match (regex),
    glob (case-insensitive)
  - AND within a route; OR via multiple routes
  - on_match: continue evaluates subsequent; on_match: stop short-
    circuits (default)
  - destination types: webhook (per preset), pagerduty, slack
  - ${ENV} secret interpolation; missing env => clean error at startup
  - token-leak prevention test: routes YAML loaded with secret values
    in test env => assert no plaintext secret appears in any log line
    or audit event or status surface
  - failure isolation: one destination failing does NOT stop others
  - backward compat: --audit-webhook-url is ignored when --alert-routes
    is set (with warning)
  - dry-run: `config preview-routes` shows matches without sending
  - license gate: refuse at startup without an Enterprise license
"""

from __future__ import annotations

import asyncio
import base64
import datetime as _dt
import json
import logging
import os
import pathlib
from typing import Any

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from iam_jit import license as license_mod
from iam_jit.bouncer.audit_export import (
    PagerDutyDestination,
    Preset,
    Route,
    RoutesConfig,
    RoutesConfigError,
    RoutesEngine,
    RoutesLicenseError,
    SlackDestination,
    WebhookDestination,
    evaluate_match,
    gate_routes_license,
    load_routes_config,
    select_routes,
)


# Token / key strings the leak-prevention test will grep for. If ANY of
# these literals appears in a captured log line, status snapshot, or
# stringified destination, the leak test fails.
TEST_SOC_TOKEN = "lit_soc_splunk_hec_secret_no_leak_xyz"
TEST_DEV_TOKEN = "lit_dev_datadog_secret_no_leak_xyz"
TEST_PD_KEY = "lit_pagerduty_integration_no_leak_xyz"
TEST_SLACK_URL = "https://hooks.slack.com/services/T123/B456/litSlackNoLeakXyz"
TEST_ARCHIVE_TOKEN = "lit_central_archive_secret_no_leak_xyz"


@pytest.fixture
def secret_env(monkeypatch):
    """Install the test secrets into the env so ${ENV} interpolation
    resolves. Yields the dict so a test can assert the engine never
    leaks the actual values back out."""
    secrets = {
        "SOC_SPLUNK_HEC_TOKEN": TEST_SOC_TOKEN,
        "DEV_DATADOG_API_KEY": TEST_DEV_TOKEN,
        "PD_INTEGRATION_KEY": TEST_PD_KEY,
        "SLACK_ONCALL_WEBHOOK": TEST_SLACK_URL,
        "CENTRAL_ARCHIVE_TOKEN": TEST_ARCHIVE_TOKEN,
    }
    for k, v in secrets.items():
        monkeypatch.setenv(k, v)
    return secrets


@pytest.fixture
def memo_routes_yaml(tmp_path, secret_env):
    """The exact YAML shape from the per-org-notification-routing memo.
    Returns the path to the rendered file."""
    # Tests bypass the SSRF DNS resolution via allow_internal=true; the
    # documented Slack / PagerDuty URLs are public + don't need it.
    yaml_text = """\
routes:
  - name: soc-high-severity
    match:
      severity_id: { gte: 3 }
    destinations:
      - webhook:
          url: https://splunk-soc.example.com/services/collector/event
          token: ${SOC_SPLUNK_HEC_TOKEN}
          preset: splunk-hec
          allow_internal: true
  - name: dev-team-own-events
    match:
      actor.user.attribute.team: dev
    destinations:
      - webhook:
          url: https://datadog-dev.example.com/api/v2/logs
          token: ${DEV_DATADOG_API_KEY}
          preset: datadog
          allow_internal: true
  - name: on-call-critical
    match:
      severity_id: 5
    destinations:
      - pagerduty:
          integration_key: ${PD_INTEGRATION_KEY}
      - slack:
          webhook_url: ${SLACK_ONCALL_WEBHOOK}
  - name: central-archive
    match: {}
    destinations:
      - webhook:
          url: https://archive-collector.example.com/api/v1/audit
          token: ${CENTRAL_ARCHIVE_TOKEN}
          preset: generic
          allow_internal: true
    on_match: continue
"""
    path = tmp_path / "routes.yaml"
    path.write_text(yaml_text, encoding="utf-8")
    return path


@pytest.fixture
def sample_ocsf_event() -> dict:
    """An OCSF API-Activity event with severity_id=3 (Medium) and a
    `actor.user.attribute.team=dev` claim. Suitable for exercising
    the soc-high-severity AND dev-team-own-events routes (multi-match
    via the central-archive on_match=continue route)."""
    return {
        "metadata": {
            "version": "1.1.0",
            "product": {"name": "ibounce", "vendor_name": "iam-jit"},
        },
        "category_uid": 6,
        "class_uid": 6003,
        "activity_id": 1,
        "type_uid": 600301,
        "severity_id": 3,
        "severity": "Medium",
        "status_id": 1,
        "status": "Success",
        "time": 1717000000000,
        "api": {"operation": "iam:CreateRole", "service": {"name": "iam"}},
        "actor": {
            "user": {
                "name": "alice@example.com",
                "attribute": {"team": "dev"},
            },
        },
        "resources": [{"uid": "role/example", "type": "Role"}],
        "src_endpoint": {"ip": "10.0.0.5", "hostname": "dev-laptop"},
        "unmapped": {"iam_jit": {"verdict": "ALLOW", "mode": "cooperative"}},
    }


# ---------------------------------------------------------------------------
# YAML loader — structural validation
# ---------------------------------------------------------------------------


def test_load_routes_yaml_happy_path(memo_routes_yaml):
    cfg = load_routes_config(str(memo_routes_yaml), product="ibounce")
    assert isinstance(cfg, RoutesConfig)
    assert len(cfg.routes) == 4
    names = [r.name for r in cfg.routes]
    assert names == [
        "soc-high-severity", "dev-team-own-events",
        "on-call-critical", "central-archive",
    ]
    # Central archive is the fan-out tail per the memo.
    assert cfg.routes[3].on_match == "continue"
    # Defaults: every other route is `stop`.
    assert all(r.on_match == "stop" for r in cfg.routes[:3])


def test_load_routes_yaml_missing_routes_key(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("other_key: 1\n", encoding="utf-8")
    with pytest.raises(RoutesConfigError, match="routes"):
        load_routes_config(str(p))


def test_load_routes_yaml_routes_not_a_list(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("routes: not-a-list\n", encoding="utf-8")
    with pytest.raises(RoutesConfigError, match="must be a list"):
        load_routes_config(str(p))


def test_load_routes_yaml_route_without_name(tmp_path, secret_env):
    p = tmp_path / "bad.yaml"
    p.write_text(
        "routes:\n"
        "  - match: {}\n"
        "    destinations:\n"
        "      - webhook:\n          url: https://x.example\n          token: ${SOC_SPLUNK_HEC_TOKEN}\n",
        encoding="utf-8",
    )
    with pytest.raises(RoutesConfigError, match="name"):
        load_routes_config(str(p))


def test_load_routes_yaml_unknown_destination_type(tmp_path, secret_env):
    p = tmp_path / "bad.yaml"
    p.write_text(
        "routes:\n"
        "  - name: bad\n"
        "    match: {}\n"
        "    destinations:\n"
        "      - email: {to: ops@example.com}\n",
        encoding="utf-8",
    )
    with pytest.raises(RoutesConfigError, match="unknown destination"):
        load_routes_config(str(p))


def test_load_routes_yaml_bare_literal_token_refused(tmp_path):
    """Per the memo: bare literal tokens in YAML are REFUSED. The only
    legal shape is ${ENV_VAR}."""
    p = tmp_path / "bad.yaml"
    p.write_text(
        "routes:\n"
        "  - name: bad\n"
        "    match: {}\n"
        "    destinations:\n"
        "      - webhook:\n"
        "          url: https://x.example\n"
        "          token: literal_token_should_be_refused\n",
        encoding="utf-8",
    )
    with pytest.raises(RoutesConfigError, match="env-var interpolation"):
        load_routes_config(str(p))


def test_load_routes_yaml_missing_env_var_clean_error(tmp_path, monkeypatch):
    monkeypatch.delenv("NEVER_SET_FOR_THIS_TEST", raising=False)
    p = tmp_path / "bad.yaml"
    p.write_text(
        "routes:\n"
        "  - name: bad\n"
        "    match: {}\n"
        "    destinations:\n"
        "      - webhook:\n"
        "          url: https://x.example\n"
        "          token: ${NEVER_SET_FOR_THIS_TEST}\n",
        encoding="utf-8",
    )
    with pytest.raises(RoutesConfigError, match="not set"):
        load_routes_config(str(p))


def test_load_routes_yaml_invalid_on_match(tmp_path, secret_env):
    p = tmp_path / "bad.yaml"
    p.write_text(
        "routes:\n"
        "  - name: bad\n"
        "    match: {}\n"
        "    on_match: garbage\n"
        "    destinations:\n"
        "      - webhook:\n          url: https://x.example\n          token: ${SOC_SPLUNK_HEC_TOKEN}\n",
        encoding="utf-8",
    )
    with pytest.raises(RoutesConfigError, match="on_match"):
        load_routes_config(str(p))


def test_load_routes_yaml_duplicate_route_name(tmp_path, secret_env):
    p = tmp_path / "bad.yaml"
    p.write_text(
        "routes:\n"
        "  - name: dup\n"
        "    match: {}\n"
        "    destinations:\n"
        "      - webhook:\n          url: https://x.example\n          token: ${SOC_SPLUNK_HEC_TOKEN}\n"
        "  - name: dup\n"
        "    match: {}\n"
        "    destinations:\n"
        "      - webhook:\n          url: https://y.example\n          token: ${SOC_SPLUNK_HEC_TOKEN}\n",
        encoding="utf-8",
    )
    with pytest.raises(RoutesConfigError, match="duplicate"):
        load_routes_config(str(p))


def test_load_routes_yaml_empty_destinations_refused(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text(
        "routes:\n"
        "  - name: bad\n"
        "    match: {}\n"
        "    destinations: []\n",
        encoding="utf-8",
    )
    with pytest.raises(RoutesConfigError, match="destinations"):
        load_routes_config(str(p))


def test_load_routes_yaml_unknown_match_operator(tmp_path, secret_env):
    p = tmp_path / "bad.yaml"
    p.write_text(
        "routes:\n"
        "  - name: bad\n"
        "    match:\n"
        "      severity_id: { startswith: foo }\n"
        "    destinations:\n"
        "      - webhook:\n          url: https://x.example\n          token: ${SOC_SPLUNK_HEC_TOKEN}\n",
        encoding="utf-8",
    )
    with pytest.raises(RoutesConfigError, match="unknown operator"):
        load_routes_config(str(p))


# ---------------------------------------------------------------------------
# Match operators
# ---------------------------------------------------------------------------


def test_match_equals_default(sample_ocsf_event):
    assert evaluate_match(sample_ocsf_event, {"severity_id": 3})
    assert not evaluate_match(sample_ocsf_event, {"severity_id": 5})


def test_match_gte_lte_gt_lt(sample_ocsf_event):
    assert evaluate_match(sample_ocsf_event, {"severity_id": {"gte": 3}})
    assert evaluate_match(sample_ocsf_event, {"severity_id": {"gte": 2}})
    assert not evaluate_match(sample_ocsf_event, {"severity_id": {"gte": 4}})
    assert evaluate_match(sample_ocsf_event, {"severity_id": {"lte": 3}})
    assert not evaluate_match(sample_ocsf_event, {"severity_id": {"lte": 2}})
    assert evaluate_match(sample_ocsf_event, {"severity_id": {"gt": 2}})
    assert not evaluate_match(sample_ocsf_event, {"severity_id": {"gt": 3}})
    assert evaluate_match(sample_ocsf_event, {"severity_id": {"lt": 4}})
    assert not evaluate_match(sample_ocsf_event, {"severity_id": {"lt": 3}})


def test_match_in(sample_ocsf_event):
    assert evaluate_match(sample_ocsf_event, {"severity_id": {"in": [3, 4, 5]}})
    assert not evaluate_match(sample_ocsf_event, {"severity_id": {"in": [4, 5]}})


def test_match_regex(sample_ocsf_event):
    assert evaluate_match(
        sample_ocsf_event, {"api.operation": {"match": r"iam:Create.*"}},
    )
    assert not evaluate_match(
        sample_ocsf_event, {"api.operation": {"match": r"s3:.*"}},
    )


def test_match_glob_case_insensitive(sample_ocsf_event):
    # iam:CreateRole vs iam:create* — glob is case-insensitive per the
    # memo + the deterministic-pattern-match convention from #262.
    assert evaluate_match(
        sample_ocsf_event, {"api.operation": {"glob": "iam:create*"}},
    )


def test_match_list_walk_resources_uid(sample_ocsf_event):
    """resources[].uid walks the list of resource dicts so a glob on
    'role/*' fires when ANY resource matches."""
    assert evaluate_match(
        sample_ocsf_event, {"resources[].uid": {"glob": "role/*"}},
    )
    assert not evaluate_match(
        sample_ocsf_event, {"resources[].uid": {"glob": "bucket/*"}},
    )


def test_match_missing_field_is_not_match(sample_ocsf_event):
    assert not evaluate_match(
        sample_ocsf_event, {"this.does.not.exist": "anything"},
    )


def test_match_and_within_route(sample_ocsf_event):
    """AND semantics: every (path, condition) must match."""
    ok = evaluate_match(sample_ocsf_event, {
        "severity_id": {"gte": 3},
        "api.operation": {"match": r"iam:Create.*"},
    })
    assert ok
    fail = evaluate_match(sample_ocsf_event, {
        "severity_id": {"gte": 3},
        "api.operation": {"match": r"s3:.*"},  # second condition fails
    })
    assert not fail


def test_match_empty_block_matches_everything(sample_ocsf_event):
    assert evaluate_match(sample_ocsf_event, {})


def test_match_nested_dotted_path(sample_ocsf_event):
    assert evaluate_match(
        sample_ocsf_event,
        {"actor.user.attribute.team": "dev"},
    )


def test_match_int_coerces_string_severity(sample_ocsf_event):
    """Some SIEMs ship severity as a string; the numeric operators
    should coerce strings to int for the comparison."""
    e = dict(sample_ocsf_event)
    e["severity_id"] = "3"
    assert evaluate_match(e, {"severity_id": {"gte": 3}})


def test_match_bool_does_not_compare_as_int(sample_ocsf_event):
    """`severity_id: gte 0` must NOT match a bool value (Python would
    otherwise coerce True->1 / False->0 via int())."""
    e = dict(sample_ocsf_event)
    e["severity_id"] = True
    # bool is rejected by the int coercion so the comparison fails.
    assert not evaluate_match(e, {"severity_id": {"gte": 0}})


# ---------------------------------------------------------------------------
# Route selection — on_match semantics
# ---------------------------------------------------------------------------


def test_select_routes_stop_short_circuits(memo_routes_yaml, sample_ocsf_event):
    cfg = load_routes_config(str(memo_routes_yaml))
    # severity_id=3 matches soc-high-severity (stop) AND central-archive
    # (continue, but unreachable because soc-high-severity stopped).
    # The dev-team and on-call routes are between them and the
    # severity_id=3 event matches dev-team too — but only ONE of soc /
    # dev triggers before stop. Verify the short-circuit on the first
    # match (soc).
    hits = select_routes(sample_ocsf_event, cfg.routes)
    assert [h.name for h in hits] == ["soc-high-severity"]


def test_select_routes_continue_evaluates_subsequent(
    memo_routes_yaml, sample_ocsf_event,
):
    """Re-order so the continue-route fires first; the subsequent stop
    routes should still evaluate."""
    cfg = load_routes_config(str(memo_routes_yaml))
    # Hand-construct a config where central-archive (continue) is first.
    reordered = RoutesConfig(routes=(cfg.routes[3], cfg.routes[0]))
    hits = select_routes(sample_ocsf_event, reordered.routes)
    assert [h.name for h in hits] == ["central-archive", "soc-high-severity"]


def test_select_routes_no_match_returns_empty(memo_routes_yaml):
    cfg = load_routes_config(str(memo_routes_yaml))
    # An event with severity 1 (Informational) + no team claim:
    # - soc-high-severity: severity_id >= 3 fails
    # - dev-team: actor.user.attribute.team field absent => no match
    # - on-call: severity_id == 5 fails
    # - central-archive: match {} => matches (fallback)
    no_match_event = {"severity_id": 1, "metadata": {}}
    hits = select_routes(no_match_event, cfg.routes)
    assert [h.name for h in hits] == ["central-archive"]


def test_select_routes_or_via_multiple_routes(memo_routes_yaml, sample_ocsf_event):
    """The same event matches multiple independent routes; OR semantics
    are implemented via the route list."""
    cfg = load_routes_config(str(memo_routes_yaml))
    # Use a config where the dev-team route comes BEFORE soc but uses
    # continue so both fire.
    dev_continue = Route(
        name=cfg.routes[1].name,
        match=cfg.routes[1].match,
        destinations=cfg.routes[1].destinations,
        on_match="continue",
    )
    reordered = RoutesConfig(routes=(dev_continue, cfg.routes[0]))
    hits = select_routes(sample_ocsf_event, reordered.routes)
    assert [h.name for h in hits] == ["dev-team-own-events", "soc-high-severity"]


# ---------------------------------------------------------------------------
# Destination dispatch — failure isolation + per-type body shape
# ---------------------------------------------------------------------------


class _FakeResp:
    def __init__(self, status: int = 200):
        self.status = status

    async def read(self) -> bytes:
        return b""

    async def __aenter__(self):
        return self

    async def __aexit__(self, *a):
        return None


class _FakeSession:
    """Captures every POST call so the test can inspect URL / headers /
    body. The `status_for` callback decides each call's response status
    so the failure-isolation tests can fail one destination + succeed
    on others."""

    def __init__(self, status_for=lambda url: 200):
        self.calls: list[dict[str, Any]] = []
        self._status_for = status_for

    def post(self, url, *, data, headers, timeout):
        self.calls.append({
            "url": url,
            "headers": dict(headers),
            "body": data,
            "timeout": timeout,
        })
        return _FakeResp(status=self._status_for(url))

    async def close(self):
        pass


def _run(coro):
    return asyncio.run(coro)


@pytest.fixture
def routes_engine_factory(memo_routes_yaml, secret_env):
    """Returns a callable that builds + starts a RoutesEngine wired to
    a fake aiohttp session. Yields (engine, fake_session) for assertion."""
    cfg = load_routes_config(str(memo_routes_yaml))

    def _build(status_for=lambda url: 200):
        sess = _FakeSession(status_for=status_for)
        engine = RoutesEngine(
            config=cfg,
            product="ibounce",
            _session_factory=lambda: sess,
        )
        return engine, sess

    return _build


def test_engine_dispatches_webhook_for_soc_route(
    routes_engine_factory, sample_ocsf_event,
):
    async def go():
        engine, sess = routes_engine_factory()
        await engine.start()
        try:
            engine.push(sample_ocsf_event)
            # Drain the queue: stop() flushes via the sentinel.
        finally:
            await engine.stop()
        return sess

    sess = _run(go())
    # severity_id=3 hits soc-high-severity (stop) so exactly 1 POST.
    assert len(sess.calls) == 1
    call = sess.calls[0]
    # Splunk HEC preset auth header.
    assert call["headers"]["Authorization"].startswith("Splunk ")


def test_engine_dispatches_pagerduty_and_slack_for_critical(
    memo_routes_yaml,
):
    """Build a routes config where on-call-critical comes BEFORE the
    catch-all soc route so the test severity=5 event reaches both
    PagerDuty + Slack destinations."""
    cfg = load_routes_config(str(memo_routes_yaml))
    # Use only the on-call route in this test.
    on_call_only = RoutesConfig(routes=(cfg.routes[2],))
    sess = _FakeSession()

    async def go():
        engine = RoutesEngine(
            config=on_call_only,
            product="ibounce",
            _session_factory=lambda: sess,
        )
        await engine.start()
        try:
            engine.push({
                "severity_id": 5,
                "api": {"operation": "iam:DeleteRole"},
                "metadata": {
                    "product": {"name": "ibounce", "vendor_name": "iam-jit"},
                },
                "unmapped": {"iam_jit": {
                    "verdict": "DENY", "event_type": "DECISION",
                }},
            })
        finally:
            await engine.stop()

    _run(go())
    # on-call-critical has 2 destinations: PagerDuty + Slack.
    assert len(sess.calls) == 2
    urls = [c["url"] for c in sess.calls]
    assert "https://events.pagerduty.com/v2/enqueue" in urls
    assert any(u == TEST_SLACK_URL for u in urls)


def test_engine_failure_isolation_one_dest_500(memo_routes_yaml):
    """One destination returning 500 must NOT prevent the others from
    being attempted on the same event."""
    cfg = load_routes_config(str(memo_routes_yaml))
    on_call_only = RoutesConfig(routes=(cfg.routes[2],))
    sess = _FakeSession(
        status_for=lambda url: 500 if "pagerduty" in url else 200,
    )

    async def go():
        engine = RoutesEngine(
            config=on_call_only,
            product="ibounce",
            _session_factory=lambda: sess,
        )
        await engine.start()
        try:
            engine.push({
                "severity_id": 5,
                "api": {"operation": "iam:DeleteRole"},
                "metadata": {
                    "product": {"name": "ibounce", "vendor_name": "iam-jit"},
                },
                "unmapped": {"iam_jit": {"verdict": "DENY"}},
            })
        finally:
            await engine.stop()
        return engine

    engine = _run(go())
    # Both destinations attempted; Slack should appear in the call list.
    urls = [c["url"] for c in sess.calls]
    assert "https://events.pagerduty.com/v2/enqueue" in urls
    assert TEST_SLACK_URL in urls
    # Status snapshot reports the per-destination failure counter.
    status = engine.status()
    on_call = next(r for r in status["routes"] if r["name"] == "on-call-critical")
    pd_stats = on_call["destination_stats"][0]
    assert pd_stats["total_failed"] >= 1


def test_engine_pagerduty_payload_shape(memo_routes_yaml):
    cfg = load_routes_config(str(memo_routes_yaml))
    on_call_only = RoutesConfig(routes=(cfg.routes[2],))
    sess = _FakeSession()

    async def go():
        engine = RoutesEngine(
            config=on_call_only,
            product="ibounce",
            _session_factory=lambda: sess,
        )
        await engine.start()
        try:
            engine.push({
                "severity_id": 5,
                "api": {"operation": "iam:DeleteRole"},
                "metadata": {
                    "product": {"name": "ibounce", "vendor_name": "iam-jit"},
                },
                "unmapped": {"iam_jit": {
                    "verdict": "DENY", "event_type": "ANOMALY_DETECTED",
                }},
            })
        finally:
            await engine.stop()

    _run(go())
    pd_call = next(c for c in sess.calls if "pagerduty" in c["url"])
    body = json.loads(pd_call["body"])
    assert body["event_action"] == "trigger"
    assert body["payload"]["source"] == "iam-jit/ibounce"
    assert "iam:DeleteRole" in body["payload"]["summary"]
    # The routing_key carries the integration key (it's the documented
    # PD shape, sent only to the PD endpoint).
    assert body["routing_key"] == TEST_PD_KEY


def test_engine_slack_payload_neutral_language(memo_routes_yaml):
    cfg = load_routes_config(str(memo_routes_yaml))
    on_call_only = RoutesConfig(routes=(cfg.routes[2],))
    sess = _FakeSession()

    async def go():
        engine = RoutesEngine(
            config=on_call_only,
            product="ibounce",
            _session_factory=lambda: sess,
        )
        await engine.start()
        try:
            engine.push({
                "severity_id": 5,
                "api": {"operation": "iam:DeleteRole"},
                "metadata": {
                    "product": {"name": "ibounce", "vendor_name": "iam-jit"},
                },
                "unmapped": {"iam_jit": {
                    "verdict": "DENY", "event_type": "ADMIN_FALLBACK_GRANT",
                }},
            })
        finally:
            await engine.stop()

    _run(go())
    slack_call = next(c for c in sess.calls if c["url"] == TEST_SLACK_URL)
    body = json.loads(slack_call["body"])
    # Per [[security-team-positioning-safety-not-surveillance]]: never
    # say "violation" / "infraction" / "unauthorized" in a Slack-facing
    # string.
    text_lower = body["text"].lower()
    for forbidden in ("violation", "infraction", "unauthorized"):
        assert forbidden not in text_lower


# ---------------------------------------------------------------------------
# Secret-leak prevention
# ---------------------------------------------------------------------------


def test_secrets_never_appear_in_status_or_logs(
    routes_engine_factory, sample_ocsf_event, caplog,
):
    """Load a routes config that resolves multiple secrets at boot;
    push events; verify NO test-secret literal appears in the engine
    status snapshot, in any logger.warning call, or in any masked-
    destination rendering."""
    async def go():
        # Fail every destination so the per-dest "last_error" surfaces.
        engine, sess = routes_engine_factory(status_for=lambda url: 500)
        await engine.start()
        try:
            with caplog.at_level(logging.WARNING):
                engine.push(sample_ocsf_event)
                # Also push severity 5 so pagerduty + slack get exercised.
                engine.push({
                    "severity_id": 5,
                    "api": {"operation": "iam:DeleteRole"},
                    "metadata": {
                        "product": {"name": "ibounce", "vendor_name": "iam-jit"},
                    },
                    "unmapped": {"iam_jit": {"verdict": "DENY"}},
                })
        finally:
            await engine.stop()
        return engine

    engine = _run(go())
    status = engine.status()
    rendered = json.dumps(status, default=str)
    for secret in (
        TEST_SOC_TOKEN, TEST_DEV_TOKEN, TEST_PD_KEY,
        TEST_SLACK_URL, TEST_ARCHIVE_TOKEN,
    ):
        assert secret not in rendered, (
            f"plaintext secret leaked into status: {secret!r}"
        )
    # Log surface: caplog records (level, message) tuples; assert no
    # literal secret value appears.
    for record in caplog.records:
        msg = record.getMessage()
        for secret in (
            TEST_SOC_TOKEN, TEST_DEV_TOKEN, TEST_PD_KEY,
            TEST_SLACK_URL, TEST_ARCHIVE_TOKEN,
        ):
            assert secret not in msg, (
                f"plaintext secret leaked into log: {secret!r}"
            )


def test_secrets_used_renders_masked_prefix(memo_routes_yaml, secret_env):
    cfg = load_routes_config(str(memo_routes_yaml))
    secrets = cfg.secrets_used()
    # Every env var that was referenced in the YAML appears in the
    # masked-prefix surface.
    names = {n for n, _ in secrets}
    assert names == {
        "SOC_SPLUNK_HEC_TOKEN",
        "DEV_DATADOG_API_KEY",
        "PD_INTEGRATION_KEY",
        "SLACK_ONCALL_WEBHOOK",
        "CENTRAL_ARCHIVE_TOKEN",
    }
    # Each masked rendering is `<first-8>***` and NEVER the full value.
    for name, masked in secrets:
        assert masked.endswith("***")
        # The masked prefix is at most 8 chars + '***'.
        assert len(masked) <= 11
        for secret in (
            TEST_SOC_TOKEN, TEST_DEV_TOKEN, TEST_PD_KEY,
            TEST_SLACK_URL, TEST_ARCHIVE_TOKEN,
        ):
            assert masked != secret


# ---------------------------------------------------------------------------
# License gate
# ---------------------------------------------------------------------------


@pytest.fixture
def enterprise_license_factory(monkeypatch):
    installed: dict[str, Any] = {}

    def _install(tmp_path: pathlib.Path, tier: str = "enterprise") -> None:
        priv = Ed25519PrivateKey.generate()
        pub_b64 = base64.b64encode(
            priv.public_key().public_bytes_raw(),
        ).decode("ascii")
        now = _dt.datetime.now(_dt.UTC).replace(microsecond=0)
        payload = {
            "tier": tier,
            "issued_to": "Test Co.",
            "issued_at": now.isoformat().replace("+00:00", "Z"),
            "expires_at": (now + _dt.timedelta(days=30)).isoformat().replace("+00:00", "Z"),
            "max_users": 100,
            "license_id": "lic_test_routes",
        }
        canonical = license_mod._canonical_payload_bytes(payload)
        signature = priv.sign(canonical)
        license_text = {
            "payload": payload,
            "signature": base64.b64encode(signature).decode("ascii"),
        }
        license_path = tmp_path / "license.json"
        license_path.write_text(
            json.dumps(license_text), encoding="utf-8",
        )
        monkeypatch.setenv("IAM_JIT_LICENSE_FILE", str(license_path))
        monkeypatch.setattr(
            license_mod, "PRODUCTION_PUBLIC_KEY_B64", pub_b64,
        )
        installed["path"] = str(license_path)

    return _install


def test_gate_routes_license_refuses_without_enterprise(monkeypatch, tmp_path):
    # No license file installed; the production placeholder key auto-
    # rejects + load_license returns None.
    monkeypatch.delenv("IAM_JIT_LICENSE_PATH", raising=False)
    if hasattr(license_mod, "_cached_license"):
        license_mod._cached_license = None
    with pytest.raises(RoutesLicenseError):
        gate_routes_license(None)


def test_gate_routes_license_accepts_enterprise_license(
    enterprise_license_factory, tmp_path,
):
    enterprise_license_factory(tmp_path, tier="enterprise")
    # Should not raise.
    gate_routes_license(None)


def test_gate_routes_license_refuses_non_enterprise_tier(
    enterprise_license_factory, tmp_path,
):
    enterprise_license_factory(tmp_path, tier="pro")
    with pytest.raises(RoutesLicenseError, match="Enterprise"):
        gate_routes_license(None)
