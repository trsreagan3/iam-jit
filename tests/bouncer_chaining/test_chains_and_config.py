"""#724 / BUILD-3 — chain-rule + config loader unit tests."""

from __future__ import annotations

import pytest

from iam_jit.bouncer_chaining.chains import (
    ChainRulesError,
    load_chain_rules,
    parse_rule,
)
from iam_jit.bouncer_chaining.config import ConfigError, load_config
from iam_jit.bouncer_chaining.signal_store import SIGNAL_KIND_PII_OBSERVED


# ---------------------------------------------------------------------------
# chain rules
# ---------------------------------------------------------------------------


def test_canonical_rule_parses():
    rule = parse_rule({
        "trigger": "dbounce.pii_detected",
        "scope": "agent_session",
        "action": "ibounce.tighten_egress",
        "ttl": "1h",
    })
    assert rule.trigger_source == "dbounce"
    assert rule.trigger_kind == SIGNAL_KIND_PII_OBSERVED
    assert rule.action_bouncer == "ibounce"
    assert rule.action_verb == "tighten_egress"
    assert rule.ttl_seconds == 3600
    assert rule.applies_to_egress is True


def test_pii_observed_wire_name_also_accepted():
    rule = parse_rule({
        "trigger": "dbounce.pii_observed",
        "action": "ibounce.tighten_egress",
    })
    assert rule.trigger_kind == SIGNAL_KIND_PII_OBSERVED
    # ttl defaults to 1h.
    assert rule.ttl_seconds == 3600


def test_gbounce_action_alias_is_egress():
    """A rule naming gbounce (the Go HTTP bouncer) is honoured by the
    ibounce consumer too — same protocol family."""
    rule = parse_rule({
        "trigger": "dbounce.pii_detected",
        "action": "gbounce.tighten_egress",
    })
    assert rule.applies_to_egress is True


def test_unknown_trigger_event_rejected():
    with pytest.raises(ChainRulesError):
        parse_rule({"trigger": "dbounce.something_weird", "action": "ibounce.tighten_egress"})


def test_unknown_action_verb_rejected():
    with pytest.raises(ChainRulesError):
        parse_rule({"trigger": "dbounce.pii_detected", "action": "ibounce.loosen_egress"})


def test_unknown_key_rejected():
    with pytest.raises(ChainRulesError):
        parse_rule({
            "trigger": "dbounce.pii_detected",
            "action": "ibounce.tighten_egress",
            "bogus": 1,
        })


def test_no_loosen_verb_exists():
    """Tightening-only invariant at the format level: there is NO
    loosen action verb in the grammar."""
    for verb in ("loosen", "loosen_egress", "allow", "widen", "open_egress"):
        with pytest.raises(ChainRulesError):
            parse_rule({
                "trigger": "dbounce.pii_detected",
                "action": f"ibounce.{verb}",
            })


def test_load_missing_dir_is_empty(tmp_path):
    """A missing chains dir means 'no chains configured' — not an
    error (chaining is opt-in + additive)."""
    assert load_chain_rules(tmp_path / "does-not-exist") == []


def test_load_from_yaml_files(tmp_path):
    (tmp_path / "pii.yaml").write_text(
        "- trigger: dbounce.pii_detected\n"
        "  scope: agent_session\n"
        "  action: ibounce.tighten_egress\n"
        "  ttl: 30m\n"
    )
    rules = load_chain_rules(tmp_path)
    assert len(rules) == 1
    assert rules[0].ttl_seconds == 1800


def test_load_malformed_yaml_raises(tmp_path):
    (tmp_path / "bad.yaml").write_text("- trigger: only_trigger_no_action\n")
    with pytest.raises(ChainRulesError):
        load_chain_rules(tmp_path)


# ---------------------------------------------------------------------------
# config (default-off)
# ---------------------------------------------------------------------------


def test_config_none_is_disabled():
    cfg = load_config(None)
    assert cfg.enabled is False


def test_config_default_off_when_block_absent_enabled():
    cfg = load_config({"enabled": False})
    assert cfg.enabled is False


def test_config_enabled_block_mode_default():
    cfg = load_config({"enabled": True})
    assert cfg.enabled is True
    assert cfg.mode == "block"


def test_config_alert_mode():
    cfg = load_config({"enabled": True, "mode": "alert"})
    assert cfg.mode == "alert"


def test_config_bad_mode_rejected():
    with pytest.raises(ConfigError):
        load_config({"enabled": True, "mode": "loosen"})


def test_config_unknown_key_rejected():
    with pytest.raises(ConfigError):
        load_config({"enabled": True, "bogus": 1})
