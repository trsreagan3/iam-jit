"""Tests for the suspicious-activity rule engine (#262 Slice 2).

Per [[security-team-audit-export]] Slice 2 ships:
  - 4 built-in deterministic rules
  - Sliding-window state (per-rule, time-bounded + count-capped)
  - YAML configuration loader
  - Enterprise license gate (CLI parse + serve() start)
  - OCSF v1.1.0 class-6003 anomaly_detected event wire format
  - MCP `bouncer_audit_export_status` extension (alerts_enabled,
    alerts_fired_count, last_alert_pattern)
  - Neutral-language posture per
    [[security-team-positioning-safety-not-surveillance]]

The neutral-language scan (`test_no_forbidden_words_in_alert_strings`)
is the load-bearing assertion — it greps every string an alert event
exposes to an operator for the forbidden words `violation` /
`infraction` / `unauthorized`.
"""

from __future__ import annotations

import asyncio
import base64
import datetime as _dt
import json
import pathlib
from typing import Any

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from iam_jit import license as license_mod
from iam_jit.bouncer.audit_export import (
    BUILTIN_RULES,
    FORBIDDEN_ALERT_WORDS,
    AlertRule,
    AlertsConfig,
    AlertsLicenseError,
    AuditLogWriter,
    RuleEngine,
    WebhookPusher,
    audit_event_from_decision,
    gate_alerts_license,
    load_alerts_config,
    make_admin_fallback_grant_event,
    make_pause_end_event,
    make_profile_install_event,
)
from iam_jit.bouncer.audit_export.alerts import (
    DEFAULT_ADMIN_FALLBACK_THRESHOLD,
    DEFAULT_ADMIN_FALLBACK_WINDOW_SECONDS,
    DEFAULT_HIGH_RISK_ACTIONS,
    DEFAULT_PAUSE_LONG_THRESHOLD_SECONDS,
    EVENT_TYPE_ANOMALY_DETECTED,
    _glob_match,
)


# ---------------------------------------------------------------------------
# Test fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def enterprise_license_factory(monkeypatch):
    """Installs a freshly-signed Enterprise license file for tests
    that need the license gate to pass.

    Mirrors the fixture in test_audit_export_webhook.py — alerts share
    the same license plumbing per [[enterprise-self-host-only]] so
    keeping the fixture-shape parity makes refactoring either gate
    easier later.
    """
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
            "expires_at": (
                now + _dt.timedelta(days=30)
            ).isoformat().replace("+00:00", "Z"),
            "max_users": 100,
            "license_id": "lic_test_alerts",
        }
        canonical = license_mod._canonical_payload_bytes(payload)
        sig = priv.sign(canonical)
        license_doc = {
            "payload": payload,
            "signature": base64.b64encode(sig).decode("ascii"),
        }
        lic_path = tmp_path / "license.json"
        lic_path.write_text(json.dumps(license_doc))
        monkeypatch.setenv("IAM_JIT_LICENSE_FILE", str(lic_path))
        monkeypatch.setattr(
            license_mod, "PRODUCTION_PUBLIC_KEY_B64", pub_b64,
        )
        installed["path"] = lic_path

    return _install


@pytest.fixture
def fake_clock():
    """Inject a controllable wall-clock into RuleEngine for
    sliding-window tests that need deterministic timing."""
    class _Clock:
        def __init__(self):
            self.now = 1_700_000_000.0

        def advance(self, seconds: float) -> None:
            self.now += seconds

        def __call__(self) -> float:
            return self.now

    return _Clock()


# ---------------------------------------------------------------------------
# License gate
# ---------------------------------------------------------------------------


def test_gate_alerts_license_refuses_without_license(monkeypatch) -> None:
    """No license file = refuse with AlertsLicenseError."""
    monkeypatch.delenv("IAM_JIT_LICENSE_FILE", raising=False)
    with pytest.raises(AlertsLicenseError, match="Enterprise license"):
        gate_alerts_license(None)


def test_gate_alerts_license_refuses_invalid_license(
    monkeypatch, tmp_path,
) -> None:
    """Bad signature = refuse + surface the underlying error."""
    bad = tmp_path / "bad.json"
    bad.write_text('{"payload": {"tier": "enterprise"}, "signature": "x"}')
    monkeypatch.setenv("IAM_JIT_LICENSE_FILE", str(bad))
    with pytest.raises(AlertsLicenseError):
        gate_alerts_license(None)


def test_gate_alerts_license_passes_with_enterprise(
    enterprise_license_factory, tmp_path,
) -> None:
    """A valid Enterprise license = gate returns None silently."""
    enterprise_license_factory(tmp_path)
    gate_alerts_license(None)  # no raise


def test_gate_alerts_license_refuses_pro_tier(
    enterprise_license_factory, tmp_path,
) -> None:
    """Pro license = refuse (alerts are Enterprise-only)."""
    # Use the factory's tier hook; the factory signs ANY tier the
    # caller asks for, then the gate refuses anything != "enterprise".
    enterprise_license_factory(tmp_path, tier="pro")
    with pytest.raises(AlertsLicenseError, match="Enterprise"):
        gate_alerts_license(None)


# ---------------------------------------------------------------------------
# YAML loader
# ---------------------------------------------------------------------------


def test_load_alerts_config_defaults_on_empty_file(tmp_path) -> None:
    """An empty YAML file = AlertsConfig with all defaults."""
    p = tmp_path / "alerts.yaml"
    p.write_text("")
    config = load_alerts_config(str(p))
    assert config.enabled_rules is None  # all built-ins enabled
    assert config.admin_fallback_threshold == DEFAULT_ADMIN_FALLBACK_THRESHOLD
    assert (
        config.admin_fallback_window_seconds
        == DEFAULT_ADMIN_FALLBACK_WINDOW_SECONDS
    )
    assert (
        config.pause_long_threshold_seconds
        == DEFAULT_PAUSE_LONG_THRESHOLD_SECONDS
    )
    assert config.profile_install_allowlist == ()
    assert config.high_risk_actions == DEFAULT_HIGH_RISK_ACTIONS


def test_load_alerts_config_full_yaml(tmp_path) -> None:
    """A YAML with every key set overrides the defaults."""
    p = tmp_path / "alerts.yaml"
    p.write_text(
        "enabled_rules:\n"
        "  - admin_fallback_burst\n"
        "  - pause_long\n"
        "admin_fallback_threshold: 5\n"
        "admin_fallback_window_seconds: 600\n"
        "pause_long_threshold_seconds: 3600\n"
        "profile_install_allowlist:\n"
        "  - https://profiles.example.com/dev.yaml\n"
        "  - https://profiles.example.com/prod.yaml\n"
        "high_risk_actions:\n"
        "  - iam:CreateUser\n"
        "  - kms:Decrypt\n"
    )
    config = load_alerts_config(str(p))
    assert config.enabled_rules == frozenset(
        {"admin_fallback_burst", "pause_long"}
    )
    assert config.admin_fallback_threshold == 5
    assert config.admin_fallback_window_seconds == 600
    assert config.pause_long_threshold_seconds == 3600
    assert config.profile_install_allowlist == (
        "https://profiles.example.com/dev.yaml",
        "https://profiles.example.com/prod.yaml",
    )
    assert config.high_risk_actions == ("iam:CreateUser", "kms:Decrypt")


def test_load_alerts_config_empty_enabled_list_disables_all(tmp_path) -> None:
    """Explicit `enabled_rules: []` = empty frozenset (disable all)."""
    p = tmp_path / "alerts.yaml"
    p.write_text("enabled_rules: []\n")
    config = load_alerts_config(str(p))
    assert config.enabled_rules == frozenset()


def test_load_alerts_config_rejects_non_mapping_top_level(tmp_path) -> None:
    """YAML that's a list at the top level = ValueError."""
    p = tmp_path / "alerts.yaml"
    p.write_text("- one\n- two\n")
    with pytest.raises(ValueError, match="mapping"):
        load_alerts_config(str(p))


def test_load_alerts_config_warns_on_unknown_key(tmp_path, caplog) -> None:
    """Unknown top-level key = warning, not crash. Fail-soft so a
    typo doesn't refuse to start the proxy."""
    p = tmp_path / "alerts.yaml"
    p.write_text("admin_fallback_thresshold: 9\n")  # typo
    import logging
    with caplog.at_level(logging.WARNING):
        config = load_alerts_config(str(p))
    assert config.admin_fallback_threshold == DEFAULT_ADMIN_FALLBACK_THRESHOLD
    assert any("unknown key" in r.message for r in caplog.records)


# ---------------------------------------------------------------------------
# Glob matcher
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("pattern,value,expected", [
    ("iam:CreateUser", "iam:CreateUser", True),
    ("iam:CreateUser", "iam:DeleteUser", False),
    ("iam:Create*", "iam:CreateUser", True),
    ("iam:Create*", "iam:CreateRole", True),
    ("iam:Create*", "iam:DeleteUser", False),
    ("iam:*", "iam:CreateUser", True),
    ("*:Decrypt", "kms:Decrypt", True),
    ("*:Decrypt", "kms:Encrypt", False),
    ("iam:*User", "iam:CreateUser", True),
    ("iam:*User", "iam:CreateGroup", False),
    # Case-insensitivity.
    ("IAM:CREATE*", "iam:CreateUser", True),
    ("iam:create*", "IAM:CreateUser", True),
])
def test_glob_match(pattern, value, expected) -> None:
    assert _glob_match(pattern, value) is expected


# ---------------------------------------------------------------------------
# admin_fallback_burst rule
# ---------------------------------------------------------------------------


def test_admin_fallback_burst_fires_above_threshold(fake_clock) -> None:
    """4 admin-fallback events inside the 5-min window = rule fires."""
    fired: list[dict] = []
    engine = RuleEngine(
        config=AlertsConfig.default(),
        emit=fired.append,
        _now=fake_clock,
    )
    # Threshold is 3 — fire on the 4th.
    for i in range(3):
        emitted = engine.observe(
            make_admin_fallback_grant_event(principal="alice", grant_id=i)
        )
        assert emitted == []
    emitted = engine.observe(
        make_admin_fallback_grant_event(principal="alice", grant_id=3)
    )
    assert len(emitted) == 1
    alert = emitted[0]
    assert alert["unmapped"]["iam_jit"]["pattern"] == "admin-fallback-burst"
    assert alert["unmapped"]["iam_jit"]["matched_event_count"] == 4
    assert alert["unmapped"]["iam_jit"]["window_seconds"] == 300
    assert alert["severity_id"] == 3
    assert alert["severity"] == "Medium"
    assert "admin-fallback-burst" in alert["status_detail"]
    # Surfaced via emit() AND via the return value.
    assert fired == emitted


def test_admin_fallback_burst_does_not_fire_at_or_below_threshold(
    fake_clock,
) -> None:
    """Exactly threshold events = no fire (rule is `>`, not `>=`)."""
    engine = RuleEngine(
        config=AlertsConfig.default(), emit=lambda _: None, _now=fake_clock,
    )
    for i in range(DEFAULT_ADMIN_FALLBACK_THRESHOLD):
        emitted = engine.observe(
            make_admin_fallback_grant_event(principal="alice", grant_id=i)
        )
        assert emitted == []


def test_admin_fallback_burst_ignores_non_matching_events(fake_clock) -> None:
    """Decision events / pause events / profile installs do NOT
    count toward the admin-fallback window — only ADMIN_FALLBACK_GRANT
    events do."""
    engine = RuleEngine(
        config=AlertsConfig.default(), emit=lambda _: None, _now=fake_clock,
    )
    # Mix in 10 non-matching events.
    for _ in range(10):
        engine.observe(
            audit_event_from_decision(
                decision_id=1, mode="cooperative", profile=None,
                verdict="allow", reason="", service="s3", action="GetObject",
                arn=None, region=None, host="s3.us-east-1.amazonaws.com",
            )
        )
    # Then 3 admin-fallback (should NOT fire).
    for i in range(3):
        emitted = engine.observe(
            make_admin_fallback_grant_event(principal="bob", grant_id=i)
        )
        assert emitted == []


# ---------------------------------------------------------------------------
# Sliding-window expiry
# ---------------------------------------------------------------------------


def test_admin_fallback_burst_window_expiry(fake_clock) -> None:
    """Events older than admin_fallback_window_seconds drop out of
    the window. After expiry the counter resets."""
    engine = RuleEngine(
        config=AlertsConfig.default(), emit=lambda _: None, _now=fake_clock,
    )
    # 3 events at t=0.
    for i in range(3):
        engine.observe(
            make_admin_fallback_grant_event(principal="alice", grant_id=i)
        )
    # Advance past the window.
    fake_clock.advance(DEFAULT_ADMIN_FALLBACK_WINDOW_SECONDS + 10)
    # One more event — should NOT fire (window is now [t=305..now],
    # the old 3 are gone). Total in window after this observe = 1.
    emitted = engine.observe(
        make_admin_fallback_grant_event(principal="alice", grant_id=99)
    )
    assert emitted == []
    # Add 3 more close together — now the rolling window has 4 fresh
    # events; rule should fire.
    fake_clock.advance(1)
    engine.observe(
        make_admin_fallback_grant_event(principal="alice", grant_id=100)
    )
    fake_clock.advance(1)
    engine.observe(
        make_admin_fallback_grant_event(principal="alice", grant_id=101)
    )
    fake_clock.advance(1)
    emitted = engine.observe(
        make_admin_fallback_grant_event(principal="alice", grant_id=102)
    )
    assert len(emitted) == 1
    assert emitted[0]["unmapped"]["iam_jit"]["matched_event_count"] == 4


# ---------------------------------------------------------------------------
# pause_long rule
# ---------------------------------------------------------------------------


def test_pause_long_fires_above_threshold(fake_clock) -> None:
    """Pause window of 40min > default 30min threshold = fires."""
    fired: list[dict] = []
    engine = RuleEngine(
        config=AlertsConfig.default(), emit=fired.append, _now=fake_clock,
    )
    emitted = engine.observe(
        make_pause_end_event(pause_id=42, duration_seconds=40 * 60)
    )
    assert len(emitted) == 1
    assert emitted[0]["unmapped"]["iam_jit"]["pattern"] == "long-pause"
    assert emitted[0]["unmapped"]["iam_jit"]["window_seconds"] == 40 * 60
    assert emitted[0]["severity_id"] == 3
    assert "40min" in emitted[0]["status_detail"]


def test_pause_long_does_not_fire_below_threshold(fake_clock) -> None:
    """Pause of 20min < threshold = no fire."""
    engine = RuleEngine(
        config=AlertsConfig.default(), emit=lambda _: None, _now=fake_clock,
    )
    emitted = engine.observe(
        make_pause_end_event(pause_id=42, duration_seconds=20 * 60)
    )
    assert emitted == []


def test_pause_long_does_not_fire_on_non_pause_event(fake_clock) -> None:
    """A decision event (even with high duration in some other field)
    does not fire pause_long — only PAUSE_END events do."""
    engine = RuleEngine(
        config=AlertsConfig.default(), emit=lambda _: None, _now=fake_clock,
    )
    emitted = engine.observe(
        audit_event_from_decision(
            decision_id=1, mode="cooperative", profile=None,
            verdict="allow", reason="", service="s3", action="GetObject",
            arn=None, region=None, host="s3.us-east-1.amazonaws.com",
        )
    )
    assert emitted == []


# ---------------------------------------------------------------------------
# non_org_profile_install rule
# ---------------------------------------------------------------------------


def test_non_org_profile_install_fires_when_url_not_in_allowlist(
    fake_clock,
) -> None:
    """Profile install from a URL not on the allowlist = fires."""
    config = AlertsConfig(
        profile_install_allowlist=(
            "https://profiles.example.com/approved.yaml",
        ),
    )
    fired: list[dict] = []
    engine = RuleEngine(config=config, emit=fired.append, _now=fake_clock)
    emitted = engine.observe(
        make_profile_install_event(
            profile_name="suspicious",
            source_url="https://random-blog.example.org/profile.yaml",
            installed_by="alice",
        )
    )
    assert len(emitted) == 1
    assert (
        emitted[0]["unmapped"]["iam_jit"]["pattern"]
        == "non-org-profile-install"
    )
    assert (
        "https://random-blog.example.org/profile.yaml"
        in emitted[0]["status_detail"]
    )


def test_non_org_profile_install_does_not_fire_when_url_allowlisted(
    fake_clock,
) -> None:
    """Install from an allowlisted URL = no fire."""
    url = "https://profiles.example.com/approved.yaml"
    config = AlertsConfig(profile_install_allowlist=(url,))
    engine = RuleEngine(config=config, emit=lambda _: None, _now=fake_clock)
    emitted = engine.observe(
        make_profile_install_event(
            profile_name="approved",
            source_url=url,
            installed_by="alice",
        )
    )
    assert emitted == []


def test_non_org_profile_install_fires_when_allowlist_empty(fake_clock) -> None:
    """Empty allowlist = every install fires (default posture)."""
    engine = RuleEngine(
        config=AlertsConfig.default(), emit=lambda _: None, _now=fake_clock,
    )
    emitted = engine.observe(
        make_profile_install_event(
            profile_name="anything",
            source_url="https://anywhere.example.com/p.yaml",
            installed_by="alice",
        )
    )
    assert len(emitted) == 1


# ---------------------------------------------------------------------------
# unusual_high_risk_action rule
# ---------------------------------------------------------------------------


def test_high_risk_action_fires_on_transparent_deny() -> None:
    """A transparent-mode enforced DENY on a watchlist action fires."""
    fired: list[dict] = []
    engine = RuleEngine(
        config=AlertsConfig.default(), emit=fired.append,
    )
    # iam:CreateUser hits the iam:Create* glob.
    event = audit_event_from_decision(
        decision_id=99,
        mode="transparent",
        profile=None,
        verdict="deny",
        reason="default-deny",
        service="iam",
        action="CreateUser",
        arn=None,
        region="us-east-1",
        host="iam.amazonaws.com",
        enforced=True,
    )
    emitted = engine.observe(event)
    assert len(emitted) == 1
    alert = emitted[0]
    assert (
        alert["unmapped"]["iam_jit"]["pattern"] == "high-risk-action-denied"
    )
    assert alert["severity_id"] == 4
    assert alert["severity"] == "High"
    assert "iam:CreateUser" in alert["status_detail"]


def test_high_risk_action_does_not_fire_on_allow() -> None:
    """ALLOW verdicts never fire this rule, even on watchlist actions."""
    engine = RuleEngine(
        config=AlertsConfig.default(), emit=lambda _: None,
    )
    event = audit_event_from_decision(
        decision_id=1, mode="transparent", profile=None,
        verdict="allow", reason="", service="iam", action="CreateUser",
        arn=None, region="us-east-1", host="iam.amazonaws.com",
        enforced=False,
    )
    assert engine.observe(event) == []


def test_high_risk_action_does_not_fire_on_cooperative_deny() -> None:
    """Cooperative-mode advisory deny does not fire (call succeeded
    upstream regardless)."""
    engine = RuleEngine(
        config=AlertsConfig.default(), emit=lambda _: None,
    )
    event = audit_event_from_decision(
        decision_id=1, mode="cooperative", profile=None,
        verdict="deny", reason="", service="iam", action="CreateUser",
        arn=None, region="us-east-1", host="iam.amazonaws.com",
        enforced=False,
    )
    assert engine.observe(event) == []


def test_high_risk_action_does_not_fire_on_pause_demoted_deny() -> None:
    """A transparent-mode deny with active_pause_id set (= demoted
    to advisory) does not fire."""
    engine = RuleEngine(
        config=AlertsConfig.default(), emit=lambda _: None,
    )
    event = audit_event_from_decision(
        decision_id=1, mode="transparent", profile=None,
        verdict="deny", reason="", service="kms", action="Decrypt",
        arn=None, region="us-east-1", host="kms.amazonaws.com",
        enforced=False,  # demoted by pause
        active_pause_id=7,
    )
    assert engine.observe(event) == []


def test_high_risk_action_does_not_fire_on_non_watchlist_action() -> None:
    """s3:GetObject (not on watchlist) = no fire even if denied."""
    engine = RuleEngine(
        config=AlertsConfig.default(), emit=lambda _: None,
    )
    event = audit_event_from_decision(
        decision_id=1, mode="transparent", profile=None,
        verdict="deny", reason="default-deny",
        service="s3", action="GetObject",
        arn=None, region="us-east-1", host="s3.us-east-1.amazonaws.com",
        enforced=True,
    )
    assert engine.observe(event) == []


# ---------------------------------------------------------------------------
# Enabled-rules filter
# ---------------------------------------------------------------------------


def test_disabled_rule_does_not_fire(fake_clock) -> None:
    """Rules not in enabled_rules don't fire even if their pattern
    matches the event."""
    config = AlertsConfig(
        enabled_rules=frozenset({"pause_long"}),  # only pause_long
    )
    engine = RuleEngine(
        config=config, emit=lambda _: None, _now=fake_clock,
    )
    # admin_fallback would fire on the 4th — but it's disabled.
    for i in range(10):
        emitted = engine.observe(
            make_admin_fallback_grant_event(principal="alice", grant_id=i)
        )
        assert emitted == []


def test_empty_enabled_rules_disables_everything(fake_clock) -> None:
    """`enabled_rules: []` in YAML = no rules fire = alerts_enabled=False."""
    config = AlertsConfig(enabled_rules=frozenset())
    engine = RuleEngine(
        config=config, emit=lambda _: None, _now=fake_clock,
    )
    assert engine.status()["alerts_enabled"] is False
    assert engine.active_rules == ()


# ---------------------------------------------------------------------------
# Engine.status() — MCP surface
# ---------------------------------------------------------------------------


def test_engine_status_default_shape() -> None:
    """status() returns the spec's 3 Slice 2 fields + active_rules.

    #264 added `heartbeat_gap` to BUILTIN_RULES; the default config
    enables it alongside the original four rules.
    """
    engine = RuleEngine(config=AlertsConfig.default(), emit=lambda _: None)
    snap = engine.status()
    assert snap["alerts_enabled"] is True
    assert snap["alerts_fired_count"] == 0
    assert snap["last_alert_pattern"] is None
    assert set(snap["active_rules"]) == {
        "admin_fallback_burst",
        "pause_long",
        "non_org_profile_install",
        "unusual_high_risk_action",
        "heartbeat_gap",
    }


def test_engine_status_tracks_fired_count_and_last_pattern() -> None:
    """alerts_fired_count + last_alert_pattern update on each fire."""
    engine = RuleEngine(config=AlertsConfig.default(), emit=lambda _: None)
    # Fire pause_long.
    engine.observe(make_pause_end_event(pause_id=1, duration_seconds=60 * 60))
    snap = engine.status()
    assert snap["alerts_fired_count"] == 1
    assert snap["last_alert_pattern"] == "long-pause"
    # Then fire high-risk-action.
    engine.observe(
        audit_event_from_decision(
            decision_id=2, mode="transparent", profile=None,
            verdict="deny", reason="", service="kms", action="Decrypt",
            arn=None, region="us-east-1", host="kms.amazonaws.com",
            enforced=True,
        )
    )
    snap = engine.status()
    assert snap["alerts_fired_count"] == 2
    assert snap["last_alert_pattern"] == "high-risk-action-denied"


# ---------------------------------------------------------------------------
# Re-entry guard
# ---------------------------------------------------------------------------


def test_engine_does_not_observe_its_own_anomaly_events(fake_clock) -> None:
    """An ANOMALY_DETECTED event passed to observe() is dropped on
    the floor — no rule fires on the engine's own output."""
    config = AlertsConfig.default()
    engine = RuleEngine(config=config, emit=lambda _: None, _now=fake_clock)
    # Build a synthetic anomaly event and feed it back in. Should
    # not fire ANY rule (even if the inner fields look like a real
    # admin-fallback or pause-end event).
    fake_alert = {
        "metadata": {"version": "1.1.0", "product": {"name": "ibounce"}},
        "class_uid": 6003,
        "activity_id": 99,
        "activity_name": "anomaly_detected",
        "severity_id": 3,
        "severity": "Medium",
        "status_id": 99,
        "status": "Other",
        "status_detail": "irrelevant",
        "unmapped": {
            "iam_jit": {
                "event_type": EVENT_TYPE_ANOMALY_DETECTED,
                "pattern": "admin-fallback-burst",
            },
        },
    }
    assert engine.observe(fake_alert) == []
    assert engine.status()["alerts_fired_count"] == 0


# ---------------------------------------------------------------------------
# Buggy rule containment
# ---------------------------------------------------------------------------


def test_buggy_rule_does_not_kill_other_rules(fake_clock) -> None:
    """A rule pattern that raises an exception is logged + skipped;
    the remaining rules still evaluate normally."""
    fired: list[dict] = []

    def _exploder(event, window, config):
        raise RuntimeError("boom")

    rules = (
        AlertRule(
            name="exploder", pattern=_exploder, severity=3,
            description="always raises",
        ),
        # The real pause_long rule from the built-in registry.
        *[r for r in BUILTIN_RULES if r.name == "pause_long"],
    )
    engine = RuleEngine(
        config=AlertsConfig.default(), emit=fired.append, _now=fake_clock,
        rules=rules,
    )
    emitted = engine.observe(
        make_pause_end_event(pause_id=1, duration_seconds=60 * 60)
    )
    # exploder swallowed; pause_long still fired.
    assert len(emitted) == 1
    assert emitted[0]["unmapped"]["iam_jit"]["pattern"] == "long-pause"


# ---------------------------------------------------------------------------
# OCSF event shape
# ---------------------------------------------------------------------------


def test_alert_event_ocsf_shape() -> None:
    """Every alert event conforms to OCSF v1.1.0 class 6003 with
    activity_id=99 + the Slice 2 unmapped fields."""
    fired: list[dict] = []
    engine = RuleEngine(config=AlertsConfig.default(), emit=fired.append)
    engine.observe(make_pause_end_event(pause_id=1, duration_seconds=60 * 60))
    assert len(fired) == 1
    alert = fired[0]
    # OCSF cross-product invariants.
    assert alert["class_uid"] == 6003
    assert alert["category_uid"] == 6
    assert alert["activity_id"] == 99
    assert alert["activity_name"] == "anomaly_detected"
    assert alert["type_uid"] == 600399
    assert alert["status_id"] == 99
    assert alert["status"] == "Other"
    assert alert["metadata"]["version"] == "1.1.0"
    assert alert["metadata"]["product"]["name"] == "ibounce"
    assert alert["metadata"]["product"]["vendor_name"] == "iam-jit"
    # Slice 2 fields.
    iam_jit = alert["unmapped"]["iam_jit"]
    assert iam_jit["event_type"] == EVENT_TYPE_ANOMALY_DETECTED
    assert iam_jit["pattern"] == "long-pause"
    assert "matched_event_count" in iam_jit
    assert "window_seconds" in iam_jit
    assert "suggestion" in iam_jit


# ---------------------------------------------------------------------------
# Neutral-language scan — the load-bearing Slice 2 invariant
# ---------------------------------------------------------------------------


def test_no_forbidden_words_in_alert_strings() -> None:
    """Per [[security-team-positioning-safety-not-surveillance]]:
    NO user-facing alert string ever contains
    `violation`/`infraction`/`unauthorized`. Scans every string
    surface across all four built-in rules.
    """
    fired: list[dict] = []
    engine = RuleEngine(config=AlertsConfig.default(), emit=fired.append)
    # Fire EVERY rule once.
    for i in range(DEFAULT_ADMIN_FALLBACK_THRESHOLD + 1):
        engine.observe(
            make_admin_fallback_grant_event(principal="alice", grant_id=i)
        )
    engine.observe(
        make_pause_end_event(pause_id=1, duration_seconds=60 * 60)
    )
    engine.observe(
        make_profile_install_event(
            profile_name="x",
            source_url="https://unknown.example.com/p.yaml",
            installed_by="alice",
        )
    )
    engine.observe(
        audit_event_from_decision(
            decision_id=99, mode="transparent", profile=None,
            verdict="deny", reason="", service="iam", action="CreateUser",
            arn=None, region="us-east-1", host="iam.amazonaws.com",
            enforced=True,
        )
    )
    assert len(fired) >= 4
    serialized = json.dumps(fired).lower()
    for word in FORBIDDEN_ALERT_WORDS:
        assert word not in serialized, (
            f"forbidden word {word!r} appeared in alert payload: "
            f"{serialized[:200]}..."
        )

    # Also scan the built-in rule descriptions for the same words —
    # the description shows up in operator-facing CLI help.
    for rule in BUILTIN_RULES:
        desc = rule.description.lower()
        for word in FORBIDDEN_ALERT_WORDS:
            assert word not in desc, (
                f"rule {rule.name!r} description contains forbidden "
                f"word {word!r}"
            )


# ---------------------------------------------------------------------------
# Token-leak: alert event payload doesn't contain webhook token
# ---------------------------------------------------------------------------


def test_alert_event_does_not_contain_webhook_token() -> None:
    """The rule engine never sees the webhook token (it's held by the
    pusher, not the engine), but assert defensively that no alert
    payload contains a token-shaped string we'd accidentally smuggle
    in via the engine's config or rule patterns."""
    fired: list[dict] = []
    engine = RuleEngine(config=AlertsConfig.default(), emit=fired.append)
    engine.observe(
        make_pause_end_event(pause_id=1, duration_seconds=60 * 60)
    )
    serialized = json.dumps(fired)
    # The canonical token-leak test secret from the webhook tests.
    assert "lit_secret_bearer_value_donotleak_xyz" not in serialized
    # Generic Bearer-style leak shapes.
    assert "Bearer " not in serialized
    assert "Authorization:" not in serialized


# ---------------------------------------------------------------------------
# End-to-end via the proxy decision path
# ---------------------------------------------------------------------------


@pytest.fixture
def restore_registry():
    """Tests below mutate the proxy's audit-export registry. Restore
    after each test."""
    from iam_jit.bouncer.proxy import (
        register_audit_log_writer,
        register_audit_rule_engine,
        register_audit_webhook_pusher,
    )
    yield
    register_audit_log_writer(None)
    register_audit_webhook_pusher(None)
    register_audit_rule_engine(None)


def _sigv4_auth_header(*, service: str, region: str) -> str:
    return (
        "AWS4-HMAC-SHA256 "
        f"Credential=AKIAEXAMPLE/20260518/{region}/{service}/aws4_request, "
        "SignedHeaders=host;x-amz-date, "
        "Signature=fakefakefake"
    )


@pytest.mark.asyncio
async def test_end_to_end_decision_triggers_alert_in_log_and_webhook(
    tmp_path, restore_registry,
) -> None:
    """A transparent-mode DENY on iam:CreateUser flows through the
    proxy → audit-export channels → rule engine → an ANOMALY_DETECTED
    event lands in BOTH the JSONL log and the webhook."""
    from iam_jit.bouncer.audit_export import RuleEngine
    from iam_jit.bouncer.decisions import DefaultPolicy
    from iam_jit.bouncer.proxy import (
        ProxyMode, _emit_audit_event_raw, evaluate_request,
        register_audit_log_writer, register_audit_rule_engine,
        register_audit_webhook_pusher,
    )
    from iam_jit.bouncer.store import BouncerStore

    # Re-use the webhook test's fake session pattern.
    from tests.bouncer.test_audit_export_webhook import (
        TEST_WEBHOOK_TOKEN_VALUE, _FakeSession,
    )

    log_path = tmp_path / "audit.jsonl"
    writer = AuditLogWriter(path=log_path)
    await writer.start()
    register_audit_log_writer(writer)

    session = _FakeSession(statuses=[200])
    pusher = WebhookPusher(
        url="https://collector.example.com/audit",
        token=TEST_WEBHOOK_TOKEN_VALUE,
        allow_internal=True,
        _session_factory=lambda: session,
    )
    await pusher.start()
    register_audit_webhook_pusher(pusher)

    engine = RuleEngine(
        config=AlertsConfig.default(),
        emit=_emit_audit_event_raw,
    )
    register_audit_rule_engine(engine)

    store = BouncerStore(db_path=str(tmp_path / "b.db"))
    try:
        # iam:CreateUser will hit the iam:Create* glob.
        obs = evaluate_request(
            method="POST",
            host="iam.amazonaws.com",
            path="/",
            headers={
                "host": "iam.amazonaws.com",
                "authorization": _sigv4_auth_header(
                    service="iam", region="us-east-1",
                ),
                "x-amz-date": "20260518T000000Z",
                "x-amz-target": "IAM.CreateUser",
            },
            body=b"Action=CreateUser&Version=2010-05-08&UserName=foo",
            query=None,
            store=store,
            mode=ProxyMode.TRANSPARENT,
            default_policy=DefaultPolicy.DENY,
        )
        assert obs.decision_verdict == "deny"

        # Drain — expect 2 events on each channel: the decision + the
        # alert that fired on it.
        for _ in range(200):
            wrote = writer.status()["total_events"] >= 2
            posted = len(session.posts) >= 2
            if wrote and posted:
                break
            await asyncio.sleep(0.02)
    finally:
        await pusher.stop()
        await writer.stop()
        store.close()

    lines = log_path.read_text().splitlines()
    events = [json.loads(line) for line in lines]
    # Find the anomaly event.
    anomalies = [
        e for e in events
        if e["unmapped"]["iam_jit"].get("event_type")
        == EVENT_TYPE_ANOMALY_DETECTED
    ]
    assert len(anomalies) == 1, (
        f"expected exactly 1 anomaly event in the JSONL log; got events: "
        f"{[e['unmapped']['iam_jit'] for e in events]}"
    )
    alert = anomalies[0]
    assert alert["unmapped"]["iam_jit"]["pattern"] == "high-risk-action-denied"
    assert alert["severity_id"] == 4

    # Webhook channel got the same alert.
    webhook_alerts = []
    for post in session.posts:
        # NDJSON body — split on newlines.
        for raw in post["data"].decode("utf-8").splitlines():
            obj = json.loads(raw)
            if (
                obj.get("unmapped", {}).get("iam_jit", {}).get("event_type")
                == EVENT_TYPE_ANOMALY_DETECTED
            ):
                webhook_alerts.append(obj)
    assert len(webhook_alerts) == 1


@pytest.mark.asyncio
async def test_audit_export_status_includes_alert_engine_fields(
    tmp_path, restore_registry,
) -> None:
    """The MCP status snapshot includes Slice 2's three required
    fields (alerts_enabled, alerts_fired_count, last_alert_pattern)
    at the top level."""
    from iam_jit.bouncer.audit_export import RuleEngine
    from iam_jit.bouncer.proxy import (
        _emit_audit_event_raw, audit_export_status,
        register_audit_rule_engine,
    )

    engine = RuleEngine(
        config=AlertsConfig.default(),
        emit=_emit_audit_event_raw,
    )
    register_audit_rule_engine(engine)
    # Fire one alert.
    engine.observe(make_pause_end_event(pause_id=1, duration_seconds=60 * 60))
    snap = audit_export_status()
    assert snap["alerts_enabled"] is True
    assert snap["alerts_fired_count"] == 1
    assert snap["last_alert_pattern"] == "long-pause"
    # Nested alerts block carries the same info + active_rules.
    assert snap["alerts"]["active_rules"]


def test_audit_export_status_when_no_engine_installed(restore_registry) -> None:
    """No engine = alerts_enabled False, count 0, pattern None.
    Stable shape so MCP consumers branch on the bool, not KeyError."""
    from iam_jit.bouncer.proxy import (
        audit_export_status, register_audit_rule_engine,
    )
    register_audit_rule_engine(None)
    snap = audit_export_status()
    assert snap["alerts_enabled"] is False
    assert snap["alerts_fired_count"] == 0
    assert snap["last_alert_pattern"] is None


# ---------------------------------------------------------------------------
# CLI license gate — --alert-rules without Enterprise fails fast
# ---------------------------------------------------------------------------


def test_cli_alert_rules_without_license_fails_fast(
    tmp_path, monkeypatch,
) -> None:
    """`ibounce run --alert-rules defaults` without an Enterprise
    license = exit 2 + a clear error message before serve() starts."""
    from click.testing import CliRunner

    from iam_jit.bouncer_cli import main

    monkeypatch.delenv("IAM_JIT_LICENSE_FILE", raising=False)
    runner = CliRunner()
    result = runner.invoke(
        main,
        ["run", "--alert-rules", "defaults", "--port", "0"],
        catch_exceptions=False,
    )
    assert result.exit_code == 2
    assert "Enterprise license" in result.output


def test_cli_alert_rules_with_enterprise_license_proceeds(
    tmp_path, monkeypatch, enterprise_license_factory,
) -> None:
    """With a valid Enterprise license, the --alert-rules gate passes.
    We don't actually start serve() (that would block) — patch it to
    a no-op so we only exercise the CLI parse + gate path."""
    from click.testing import CliRunner

    from iam_jit import bouncer_cli

    enterprise_license_factory(tmp_path)

    async def _fake_serve(*args, **kwargs):
        return None

    # Replace serve in the proxy module so the CLI's `from .bouncer.proxy
    # import serve` call sees the no-op.
    from iam_jit.bouncer import proxy as proxy_mod
    monkeypatch.setattr(proxy_mod, "serve", _fake_serve)

    runner = CliRunner()
    result = runner.invoke(
        bouncer_cli.main,
        ["run", "--alert-rules", "defaults", "--port", "0"],
        catch_exceptions=False,
    )
    # The CLI should reach serve() (which is now a no-op) — exit 0.
    # The license gate firing would have produced exit code 2.
    assert "Enterprise license" not in result.output
    assert "audit-export alerts refused" not in result.output


# ---------------------------------------------------------------------------
# Bounded sliding window — DoS defense
# ---------------------------------------------------------------------------


def test_sliding_window_bounded_by_count_cap(fake_clock) -> None:
    """Pushing >_MAX_WINDOW_EVENTS events into a single window does
    not grow the deque unboundedly — the count cap kicks in."""
    from iam_jit.bouncer.audit_export.alerts import _MAX_WINDOW_EVENTS

    engine = RuleEngine(
        config=AlertsConfig.default(), emit=lambda _: None, _now=fake_clock,
    )
    # All events in the same second so time-pruning does NOT fire.
    for i in range(_MAX_WINDOW_EVENTS + 100):
        engine.observe(
            make_admin_fallback_grant_event(principal="alice", grant_id=i)
        )
    # Inspect the engine's internal state directly to confirm bound.
    for rule_name, window in engine._windows.items():
        assert len(window) <= _MAX_WINDOW_EVENTS, (
            f"window for {rule_name} grew to {len(window)}, "
            f"exceeding cap {_MAX_WINDOW_EVENTS}"
        )
