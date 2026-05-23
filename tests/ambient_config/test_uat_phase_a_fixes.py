"""Tests for UAT #414 Phase A fix bundle — #432 + #433 + #434 + #435.

Each fix is exercised twice:
  * BROKEN-behavior repro on pre-fix-equivalent inputs (locks in
    that the fix actually changed observable behavior — not just
    moved code).
  * Fixed behavior asserts the desired output shape / error
    surfacing.

Test naming follows the brief's required scenarios exactly so the
parent UAT cycle can pattern-match them to the original report.
"""

from __future__ import annotations

import json
import pathlib
import socket
import threading
import time
from contextlib import closing
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from click.testing import CliRunner

from iam_jit.ambient_config import (
    ConfigLoadError,
    apply_declaration,
    load_declaration,
    plan_declaration,
    validate_declaration,
)
from iam_jit.ambient_config.setup import (
    DECLARATION_MODE_TO_RUNTIME,
    RUNTIME_MODE_TO_DECLARED,
    _modes_match,
    _probe_bouncer_healthz,
    declared_runtime_alias,
    runtime_declared_alias,
)
from iam_jit.cli import main


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------


def _posture_with(running: dict | None = None) -> dict:
    blocks = {
        "ibounce": {"running": False, "port": 8767},
        "kbounce": {"running": False, "port": 8766},
        "dbounce": {"running": False, "port": 5433},
        "gbounce": {"running": False, "port": 8080},
    }
    if running:
        for k, v in running.items():
            blocks[k] = {**blocks[k], **v}
    return {
        "schema_version": "1.0",
        "overall_mode": "neither",
        "bouncers": blocks,
        "effective_protection": {},
        "iam_jit": {},
    }


def _free_port() -> int:
    """Return a free loopback port the test can bind to."""
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _NonBouncerServer:
    """Tiny HTTP server that responds to /healthz with a non-bouncer
    body — simulates a generic web app squatting on 8767."""

    def __init__(self, port: int, body: dict | None = None) -> None:
        self.port = port
        self.body = body if body is not None else {"hello": "world"}
        self.server: HTTPServer | None = None
        self.thread: threading.Thread | None = None

    def _make_handler(self):
        body_bytes = json.dumps(self.body).encode()

        class _H(BaseHTTPRequestHandler):
            def do_GET(inner):  # noqa: N802
                inner.send_response(200)
                inner.send_header("Content-Type", "application/json")
                inner.send_header("Content-Length", str(len(body_bytes)))
                inner.end_headers()
                inner.wfile.write(body_bytes)

            def log_message(inner, *a, **k):  # noqa: N802 — silence logs
                pass

        return _H

    def start(self) -> None:
        self.server = HTTPServer(("127.0.0.1", self.port), self._make_handler())
        self.thread = threading.Thread(
            target=self.server.serve_forever, daemon=True,
        )
        self.thread.start()
        # Give it a beat to bind.
        time.sleep(0.05)

    def stop(self) -> None:
        if self.server is not None:
            self.server.shutdown()
            self.server.server_close()


class _BouncerServer(_NonBouncerServer):
    """Simulates an iam-jit bouncer by responding with the bouncer_kind
    marker."""

    def __init__(self, port: int, kind: str = "ibounce") -> None:
        super().__init__(port, body={"bouncer_kind": kind, "status": "ok"})


# ---------------------------------------------------------------------------
# #432 (CRIT) — managed-mode schema fields + cross-field validation
# ---------------------------------------------------------------------------


def test_schema_rejects_managed_with_improve_true() -> None:
    """managed + improve.enabled=true → cross-field error with
    operator-language. Repro of the canonical managed-mode
    misconfiguration: forgetting to flip improve off."""
    declaration = {
        "iam-jit": {
            "enabled": True,
            "posture": "managed",
            "bouncers": {
                "ibounce": {
                    "enabled": True,
                    "mode": "strict",
                    "profile": "ci-staging",
                    "profile_source": "./profiles/ci-staging.yaml",
                },
            },
            "improve": {"enabled": True},
        }
    }
    with pytest.raises(ConfigLoadError) as exc:
        validate_declaration(declaration)
    assert exc.value.code == "posture_cross_field_error"
    msgs = " ".join(
        e["message"] for e in exc.value.details["errors"]
    )
    assert "managed posture forbids auto-improve" in msgs
    assert "commit profile changes via PR" in msgs


def test_schema_rejects_managed_with_profile_auto() -> None:
    """managed + profile=auto → cross-field error."""
    declaration = {
        "iam-jit": {
            "enabled": True,
            "posture": "managed",
            "bouncers": {
                "ibounce": {
                    "enabled": True,
                    "mode": "strict",
                    "profile": "auto",
                    "profile_source": "./profiles/x.yaml",
                },
            },
            "improve": {"enabled": False},
        }
    }
    with pytest.raises(ConfigLoadError) as exc:
        validate_declaration(declaration)
    assert exc.value.code == "posture_cross_field_error"
    msgs = " ".join(
        e["message"] for e in exc.value.details["errors"]
    )
    assert "managed posture requires named + pinned profile" in msgs
    assert "auto" in msgs


def test_schema_requires_profile_source_for_each_enabled_bouncer_in_managed() -> None:
    """managed + missing profile_source → cross-field error per enabled
    bouncer."""
    declaration = {
        "iam-jit": {
            "enabled": True,
            "posture": "managed",
            "bouncers": {
                "ibounce": {
                    "enabled": True,
                    "mode": "strict",
                    "profile": "ci-staging",
                    # No profile_source!
                },
                "kbouncer": {
                    "enabled": True,
                    "mode": "strict",
                    "profile": "kbouncer-prod",
                    "profile_source": "./profiles/kbouncer-prod.yaml",
                },
            },
            "improve": {"enabled": False},
        }
    }
    with pytest.raises(ConfigLoadError) as exc:
        validate_declaration(declaration)
    paths = [e["path"] for e in exc.value.details["errors"]]
    assert "iam-jit/bouncers/ibounce/profile_source" in paths
    # kbouncer has profile_source so should NOT be in the error list.
    assert "iam-jit/bouncers/kbouncer/profile_source" not in paths


def test_schema_warns_on_ambient_with_fail_on_deny() -> None:
    """ambient + fail_on_deny=true → soft warning (NOT error).
    Declaration still validates; warning is attached as a sentinel."""
    declaration = {
        "iam-jit": {
            "enabled": True,
            "posture": "ambient",
            "bouncers": {"ibounce": {"enabled": True}},
            "fail_on_deny": True,
        }
    }
    # Must NOT raise.
    validated = validate_declaration(declaration)
    warnings = validated.get("__posture_warnings__")
    assert warnings, "expected at least one posture cross-field warning"
    joined = " ".join(warnings)
    assert "ambient posture typically tolerates blocks" in joined
    assert "posture: managed" in joined  # nudges to managed for CI


def test_managed_mode_full_declaration_validates_cleanly() -> None:
    """A correctly-shaped managed declaration must validate without
    errors AND without warnings."""
    declaration = {
        "iam-jit": {
            "enabled": True,
            "posture": "managed",
            "bouncers": {
                "ibounce": {
                    "enabled": True,
                    "mode": "strict",
                    "profile": "ci-staging",
                    "profile_source": "./profiles/ci-staging.yaml",
                    "profile_sha256": "a" * 64,
                },
            },
            "improve": {"enabled": False},
            "fail_on_deny": True,
            "require_signed_profiles": True,
        }
    }
    validated = validate_declaration(declaration)
    # No warnings either.
    assert "__posture_warnings__" not in validated or not validated[
        "__posture_warnings__"
    ]


def test_managed_mode_emits_all_four_errors_for_complete_misconfig() -> None:
    """When the operator misconfigures managed mode in multiple ways,
    each rule fires INDEPENDENTLY so the operator gets one fix per
    error instead of having to re-run after each fix."""
    declaration = {
        "iam-jit": {
            "enabled": True,
            "posture": "managed",
            "bouncers": {
                "ibounce": {"enabled": True, "profile": "auto"},
                "kbouncer": {"enabled": True, "profile": "auto"},
            },
            "improve": {"enabled": True},
        }
    }
    with pytest.raises(ConfigLoadError) as exc:
        validate_declaration(declaration)
    errors = exc.value.details["errors"]
    # 1 improve + 2x (profile_auto + profile_source missing) = 5 errors
    assert len(errors) >= 5, errors


def test_schema_managed_mode_invalid_profile_sha256_rejected() -> None:
    """profile_sha256 must be 64 hex chars; anything else is a schema
    error (caught at the JSON-Schema layer, before cross-field)."""
    declaration = {
        "iam-jit": {
            "enabled": True,
            "posture": "managed",
            "bouncers": {
                "ibounce": {
                    "enabled": True,
                    "mode": "strict",
                    "profile": "ci",
                    "profile_source": "./p.yaml",
                    "profile_sha256": "tooshort",
                },
            },
            "improve": {"enabled": False},
        }
    }
    with pytest.raises(ConfigLoadError) as exc:
        validate_declaration(declaration)
    # JSON-Schema layer catches this first, before cross-field.
    assert exc.value.code == "schema_validation_error"


def test_schema_managed_mode_bouncer_explicit_false_skips_cross_field() -> None:
    """A bouncer with enabled:false is OK without profile_source in
    managed mode — the operator opted out."""
    declaration = {
        "iam-jit": {
            "enabled": True,
            "posture": "managed",
            "bouncers": {
                "ibounce": {
                    "enabled": True,
                    "mode": "strict",
                    "profile": "ci",
                    "profile_source": "./profiles/ci.yaml",
                },
                "kbouncer": {"enabled": False},
                "dbounce": {"enabled": False},
                "gbounce": {"enabled": False},
            },
            "improve": {"enabled": False},
        }
    }
    # Should NOT raise — only ibounce is enabled and it's pinned.
    validated = validate_declaration(declaration)
    assert validated["iam-jit"]["posture"] == "managed"


def test_apply_config_inspect_surfaces_cross_field_errors_via_cli(
    tmp_path: pathlib.Path,
) -> None:
    """`iam-jit doctor apply-config --inspect` must surface cross-field
    errors before any setup happens."""
    (tmp_path / ".iam-jit.yaml").write_text(
        """iam-jit:
  enabled: true
  posture: managed
  bouncers:
    ibounce:
      enabled: true
      mode: strict
      profile: ci-staging
      profile_source: ./profiles/ci-staging.yaml
  improve:
    enabled: true
"""
    )
    runner = CliRunner()
    result = runner.invoke(
        main,
        [
            "doctor",
            "apply-config",
            "--cwd",
            str(tmp_path),
            "--inspect",
            "--json",
        ],
    )
    # Cross-field error → exit code 2 (loader raises ConfigLoadError).
    assert result.exit_code == 2, result.output
    payload = json.loads(result.output)
    assert payload["code"] == "posture_cross_field_error"
    msgs = " ".join(e["message"] for e in payload["details"]["errors"])
    assert "managed posture forbids auto-improve" in msgs


# ---------------------------------------------------------------------------
# #433 (MED) — port-conflict false-positive
# ---------------------------------------------------------------------------


def test_probe_bouncer_healthz_returns_free_when_port_closed() -> None:
    port = _free_port()
    kind, detail = _probe_bouncer_healthz(port, expected_kind="ibounce")
    assert kind == "free"


def test_probe_bouncer_healthz_returns_non_bouncer_when_marker_missing() -> None:
    """A non-bouncer listener (returns JSON without bouncer_kind) should
    be flagged as non_bouncer."""
    port = _free_port()
    srv = _NonBouncerServer(port)
    srv.start()
    try:
        kind, detail = _probe_bouncer_healthz(port, expected_kind="ibounce")
        assert kind == "non_bouncer"
        assert "not an iam-jit bouncer" in detail
    finally:
        srv.stop()


def test_probe_bouncer_healthz_returns_bouncer_when_marker_present() -> None:
    """A real bouncer (returns bouncer_kind=ibounce) is identified."""
    port = _free_port()
    srv = _BouncerServer(port, kind="ibounce")
    srv.start()
    try:
        kind, detail = _probe_bouncer_healthz(port, expected_kind="ibounce")
        assert kind == "bouncer"
        assert detail == "ibounce"
    finally:
        srv.stop()


def test_setup_port_conflict_probes_healthz_before_claiming_ibounce_running(
) -> None:
    """When posture reports ibounce port bound BUT the listener isn't a
    bouncer, apply_declaration must NOT report 'ibounce already
    running'. Instead it surfaces a 'port occupied by non-iam-jit
    process' warning + skip."""
    port = _free_port()
    srv = _NonBouncerServer(port)
    srv.start()
    try:
        declaration = {
            "iam-jit": {
                "enabled": True,
                "bouncers": {
                    "ibounce": {
                        "enabled": True,
                        "mode": "discovery",
                        "port": port,
                    },
                },
            }
        }
        # Posture says running=True (the TCP probe sees the port bound)
        posture = _posture_with({
            "ibounce": {"running": True, "port": port},
        })
        result = plan_declaration(declaration, posture=posture, env={})
        # NOT "already running": should be in skipped instead.
        assert "ibounce" not in result.bouncers_already_running
        skipped_names = [s["name"] for s in result.bouncers_skipped]
        assert "ibounce" in skipped_names
        skip_reason = next(
            s for s in result.bouncers_skipped if s["name"] == "ibounce"
        )["reason"]
        assert "non-iam-jit process" in skip_reason
        # Warning should NOT use the misleading "ibounce already
        # running with mode=..." template.
        joined_warnings = " ".join(result.warnings)
        assert "already running with" not in joined_warnings.lower(), (
            f"warnings: {joined_warnings}"
        )
        assert "not identify as an iam-jit bouncer" in joined_warnings.lower()
    finally:
        srv.stop()


def test_setup_port_conflict_non_bouncer_listener_clear_error() -> None:
    """The skipped reason must be clear + actionable: 'port X
    occupied by a non-iam-jit process'."""
    port = _free_port()
    srv = _NonBouncerServer(port)
    srv.start()
    try:
        declaration = {
            "iam-jit": {
                "enabled": True,
                "bouncers": {
                    "ibounce": {"enabled": True, "port": port},
                },
            }
        }
        posture = _posture_with({
            "ibounce": {"running": True, "port": port},
        })
        result = plan_declaration(declaration, posture=posture, env={})
        skipped = next(
            s for s in result.bouncers_skipped if s["name"] == "ibounce"
        )
        # The reason cites the port + names the process as non-iam-jit.
        assert str(port) in skipped["reason"]
        assert "non-iam-jit" in skipped["reason"]
        # And suggests how to fix.
        assert "different port" in skipped["reason"] or "stop the existing" in skipped["reason"]
    finally:
        srv.stop()


def test_setup_port_conflict_real_bouncer_passes_probe() -> None:
    """When the listener IS a real ibounce, the probe accepts it and
    the legacy 'already running' path runs."""
    port = _free_port()
    srv = _BouncerServer(port, kind="ibounce")
    srv.start()
    try:
        declaration = {
            "iam-jit": {
                "enabled": True,
                "bouncers": {
                    "ibounce": {"enabled": True, "port": port},
                },
            }
        }
        posture = _posture_with({
            "ibounce": {"running": True, "port": port},
        })
        result = plan_declaration(declaration, posture=posture, env={})
        # Real bouncer: claim "already running" (legacy contract).
        assert "ibounce" in result.bouncers_already_running
        skipped_names = [s["name"] for s in result.bouncers_skipped]
        assert "ibounce" not in skipped_names
    finally:
        srv.stop()


# ---------------------------------------------------------------------------
# #434 (MED) — mode-naming asymmetry
# ---------------------------------------------------------------------------


def test_declaration_mode_to_runtime_alias_map() -> None:
    """The alias map is the single source of truth for declaration ↔
    runtime translation."""
    assert DECLARATION_MODE_TO_RUNTIME["discovery"] == "cooperative"
    assert DECLARATION_MODE_TO_RUNTIME["strict"] == "transparent"
    # Operator who writes "cooperative" literally in the declaration
    # gets cooperative runtime (no double-translation).
    assert DECLARATION_MODE_TO_RUNTIME["cooperative"] == "cooperative"


def test_runtime_mode_to_declared_alias_map() -> None:
    assert RUNTIME_MODE_TO_DECLARED["cooperative"] == "discovery"
    assert RUNTIME_MODE_TO_DECLARED["transparent"] == "strict"
    assert RUNTIME_MODE_TO_DECLARED["plan-capture"] == "plan-capture"


def test_modes_match_handles_alias() -> None:
    """declared=discovery + runtime=cooperative → match (no mismatch
    warning)."""
    assert _modes_match("discovery", "cooperative") is True
    assert _modes_match("strict", "transparent") is True
    assert _modes_match("discovery", "transparent") is False  # real mismatch
    assert _modes_match("strict", "cooperative") is False


def test_posture_reports_mode_discovery_consistently() -> None:
    """When the declaration says mode: discovery and the bouncer is
    already running with the runtime alias (cooperative), apply-config
    must NOT report a mode mismatch."""
    declaration = {
        "iam-jit": {
            "enabled": True,
            "bouncers": {
                "ibounce": {"enabled": True, "mode": "discovery"},
            },
        }
    }
    # Use a free port + a real bouncer simulator so the probe passes,
    # then assert no "asks for mode='discovery'" mismatch warning fires
    # against runtime cooperative.
    port = _free_port()
    srv = _BouncerServer(port, kind="ibounce")
    srv.start()
    try:
        posture = _posture_with({
            "ibounce": {
                "running": True,
                "port": port,
                "mode": "cooperative",  # runtime vocabulary
                "active_profile": "auto",
            }
        })
        # Override the port in the declaration to match.
        declaration["iam-jit"]["bouncers"]["ibounce"]["port"] = port
        result = plan_declaration(declaration, posture=posture, env={})
        joined = " ".join(result.warnings)
        # No "asks for mode='discovery' ... already running with mode=
        # 'cooperative'" — the alias should resolve as a match.
        assert "asks for mode='discovery'" not in joined, (
            f"warnings:\n{joined}"
        )
    finally:
        srv.stop()


def test_already_running_warning_uses_declared_vocabulary() -> None:
    """When a real mismatch DOES exist (declared=strict but running=
    cooperative), the warning surfaces the running mode in BOTH
    vocabularies so the operator can compare apples-to-apples."""
    port = _free_port()
    srv = _BouncerServer(port, kind="ibounce")
    srv.start()
    try:
        declaration = {
            "iam-jit": {
                "enabled": True,
                "bouncers": {
                    "ibounce": {
                        "enabled": True,
                        "mode": "strict",  # declaration vocabulary
                        "port": port,
                    },
                },
            }
        }
        posture = _posture_with({
            "ibounce": {
                "running": True,
                "port": port,
                "mode": "cooperative",  # runtime vocabulary
                "active_profile": "auto",
            }
        })
        result = plan_declaration(declaration, posture=posture, env={})
        joined = " ".join(result.warnings)
        # Surfaces the declared form of the running mode ("discovery")
        # AND the runtime form ("cooperative").
        assert "mode='discovery'" in joined  # declared form of cooperative
        assert "runtime: 'cooperative'" in joined  # explicit runtime form
        # AND surfaces the declaration's desired mode.
        assert "mode='strict'" in joined
    finally:
        srv.stop()


def test_setup_result_records_mode_resolutions() -> None:
    """SetupResult.bouncer_mode_resolutions surfaces declared→runtime +
    mode_source: declaration."""
    declaration = {
        "iam-jit": {
            "enabled": True,
            "bouncers": {
                "ibounce": {"enabled": True, "mode": "discovery"},
                "kbouncer": {"enabled": True, "mode": "strict"},
            },
        }
    }
    result = plan_declaration(declaration, posture=_posture_with(), env={})
    bouncers_seen = {r["bouncer"]: r for r in result.bouncer_mode_resolutions}
    assert bouncers_seen["ibounce"]["mode_declared"] == "discovery"
    assert bouncers_seen["ibounce"]["mode_runtime"] == "cooperative"
    assert bouncers_seen["ibounce"]["mode_source"] == "declaration"
    assert bouncers_seen["kbouncer"]["mode_declared"] == "strict"
    assert bouncers_seen["kbouncer"]["mode_runtime"] == "transparent"
    assert bouncers_seen["kbouncer"]["mode_source"] == "declaration"


def test_bouncer_planned_record_includes_both_mode_forms() -> None:
    """Planned start records both forms so JSON output is unambiguous."""
    declaration = {
        "iam-jit": {
            "enabled": True,
            "bouncers": {
                "ibounce": {"enabled": True, "mode": "discovery"},
            },
        }
    }
    result = plan_declaration(declaration, posture=_posture_with(), env={})
    planned = [r for r in result.bouncers_planned if r["name"] == "ibounce"]
    assert planned, "expected an ibounce planned record"
    rec = planned[0]
    assert rec["mode_declared"] == "discovery"
    assert rec["mode_runtime"] == "cooperative"


# ---------------------------------------------------------------------------
# #435 (LOW) — mode_source provenance attribution
# ---------------------------------------------------------------------------


def test_resolve_active_mode_uses_iam_jit_mode_source_env_for_declaration(
    monkeypatch,
) -> None:
    """When IAM_JIT_BOUNCER_MODE + IAM_JIT_MODE_SOURCE=declaration are
    both set in the env (as ambient-config's apply_declaration does
    when it starts the bouncer), resolve_active_mode reports
    source=declaration — NOT source=env."""
    from iam_jit.bouncer.proxy import resolve_active_mode

    monkeypatch.setenv("IAM_JIT_BOUNCER_MODE", "cooperative")
    monkeypatch.setenv("IAM_JIT_MODE_SOURCE", "declaration")
    result = resolve_active_mode()
    assert result["mode"] == "cooperative"
    assert result["source"] == "declaration"


def test_resolve_active_mode_defaults_to_env_when_no_source_attr(
    monkeypatch,
) -> None:
    """Backward compat: when only IAM_JIT_BOUNCER_MODE is set (no
    IAM_JIT_MODE_SOURCE), source remains 'env' so existing tests +
    callers don't see a behavioral change."""
    from iam_jit.bouncer.proxy import resolve_active_mode

    monkeypatch.setenv("IAM_JIT_BOUNCER_MODE", "transparent")
    monkeypatch.delenv("IAM_JIT_MODE_SOURCE", raising=False)
    result = resolve_active_mode()
    assert result["mode"] == "transparent"
    assert result["source"] == "env"


def test_resolve_active_mode_rejects_unknown_source(monkeypatch) -> None:
    """An unrecognized IAM_JIT_MODE_SOURCE value falls back to 'env'
    rather than crashing or surfacing the garbage value."""
    from iam_jit.bouncer.proxy import resolve_active_mode

    monkeypatch.setenv("IAM_JIT_BOUNCER_MODE", "cooperative")
    monkeypatch.setenv("IAM_JIT_MODE_SOURCE", "made-up-source")
    result = resolve_active_mode()
    assert result["source"] == "env"


def test_resolve_active_mode_no_mode_env_returns_default(monkeypatch) -> None:
    """When no env mode is set, source=default regardless of
    IAM_JIT_MODE_SOURCE (which only matters when the mode env IS set)."""
    from iam_jit.bouncer.proxy import resolve_active_mode

    monkeypatch.delenv("IAM_JIT_BOUNCER_MODE", raising=False)
    monkeypatch.setenv("IAM_JIT_MODE_SOURCE", "declaration")
    result = resolve_active_mode()
    assert result["mode"] == "cooperative"
    assert result["source"] == "default"


def test_posture_reports_mode_source_from_declaration_not_default(
    monkeypatch,
) -> None:
    """End-to-end: when ambient-config-equivalent env is set, the
    posture snapshot's per-bouncer mode_source reads 'declaration'."""
    from iam_jit.posture.bouncers import detect_ibounce

    monkeypatch.setenv("IAM_JIT_BOUNCER_MODE", "cooperative")
    monkeypatch.setenv("IAM_JIT_MODE_SOURCE", "declaration")
    block = detect_ibounce()
    # mode + mode_source surfaced from resolve_active_mode.
    assert block.get("mode") == "cooperative"
    assert block.get("mode_source") == "declaration"


# ---------------------------------------------------------------------------
# Helpers self-check (the alias surface API)
# ---------------------------------------------------------------------------


def test_alias_helpers_roundtrip_canonical_modes() -> None:
    """discovery → cooperative → discovery and strict → transparent →
    strict round-trip cleanly."""
    assert runtime_declared_alias(declared_runtime_alias("discovery")) == "discovery"
    assert runtime_declared_alias(declared_runtime_alias("strict")) == "strict"


def test_alias_helpers_passthrough_unknowns() -> None:
    """Unknown values pass through unchanged (so we don't lie about
    modes we don't recognize — e.g. a future custom mode)."""
    assert declared_runtime_alias("custom-mode") == "custom-mode"
    assert runtime_declared_alias("custom-runtime") == "custom-runtime"
