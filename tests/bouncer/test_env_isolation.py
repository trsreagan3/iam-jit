"""State-verification tests for the autouse env-isolation fixture.

Per docs/CONTRIBUTING.md state-verification convention: it's not
enough for a fixture to *claim* it isolates the test environment;
some test must actually observe that the isolation is in effect.
Otherwise a future refactor could silently remove the delenv /
setenv lines and the tests it was protecting (#564, #565) would
start passing or failing on the developer's dogfood env state
without any test calling it out at PR time.

These tests assert the observable post-fixture environment shape
that GH #565 + GH #564 depend on:

  * IBOUNCE_AGENT_NAME is absent (no dogfood agent identity leak)
  * IBOUNCE_AGENT_SESSION_ID is absent (no live session id leak)
  * IBOUNCE_PROBE_PORT is set to a non-default port (so the
    "ibounce already running" probe doesn't false-positive against a
    real running bouncer on 127.0.0.1:8767)
  * IAM_JIT_BOUNCER_PROFILES_FILE points at a per-test tmpdir
    location that doesn't exist (the GH #5 isolation invariant)

Per [[ibounce-honest-positioning]]: these tests document the
fixture contract so a future contributor who edits conftest.py
sees the failing assertions and knows what they broke.
"""

from __future__ import annotations

import os
import pathlib
import socket


# ---------------------------------------------------------------------------
# GH #565 — IBOUNCE_AGENT_* delenv
# ---------------------------------------------------------------------------


def test_conftest_delenvs_ibounce_agent_name() -> None:
    """The autouse fixture MUST strip IBOUNCE_AGENT_NAME from os.environ
    so a dogfood agent-identity setting doesn't leak into the snippet
    surfaces (#564 regression vector)."""
    assert "IBOUNCE_AGENT_NAME" not in os.environ, (
        "IBOUNCE_AGENT_NAME leaked into the test env; the conftest "
        "autouse fixture must delenv it (GH #565). Without this strip "
        "the dogfood agent name shows up in `ibounce mcp show-config` "
        "output during tests and breaks deterministic assertions."
    )


def test_conftest_delenvs_ibounce_agent_session_id() -> None:
    """The autouse fixture MUST strip IBOUNCE_AGENT_SESSION_ID so a
    live UUIDv7 session id doesn't leak into per-test artefacts."""
    assert "IBOUNCE_AGENT_SESSION_ID" not in os.environ, (
        "IBOUNCE_AGENT_SESSION_ID leaked into the test env; the "
        "conftest autouse fixture must delenv it (GH #565). Without "
        "this strip a real session id (from a live agent run) appears "
        "in MCP-config snippet tests and would couple test output to "
        "wall-clock state."
    )


# ---------------------------------------------------------------------------
# GH #565 — IBOUNCE_PROBE_PORT ephemeral set
# ---------------------------------------------------------------------------


_IBOUNCE_DEFAULT_PROBE_PORT = "8767"


def test_conftest_sets_unused_probe_port() -> None:
    """The autouse fixture MUST set IBOUNCE_PROBE_PORT to a non-default
    ephemeral port so `is_ibounce_running()` probes an empty port
    instead of the dogfood machine's real ibounce on 8767. State
    verification: the env var is present AND the value is a parseable
    int AND it's not the default 8767."""
    raw = os.environ.get("IBOUNCE_PROBE_PORT")
    assert raw is not None, (
        "IBOUNCE_PROBE_PORT not set; the conftest autouse fixture "
        "must set it (GH #565). Without this set, tests that exercise "
        "the import-refuse-if-running probe will false-positive "
        "against a dogfood ibounce listening on 127.0.0.1:8767."
    )
    assert raw.strip(), (
        "IBOUNCE_PROBE_PORT set to empty string; the conftest must "
        "supply a numeric ephemeral port."
    )
    port = int(raw)  # raises ValueError if non-int — caught by pytest
    assert port != int(_IBOUNCE_DEFAULT_PROBE_PORT), (
        f"IBOUNCE_PROBE_PORT == {port} (the default); the conftest "
        "must pick an ephemeral non-default port so the probe doesn't "
        "hit a real ibounce."
    )
    assert 1024 < port < 65536, (
        f"IBOUNCE_PROBE_PORT={port} is outside the ephemeral range; "
        "the conftest's _find_unused_port() should return an OS-picked "
        "high port."
    )


def test_conftest_probe_port_is_actually_unbound() -> None:
    """The chosen port must reject a TCP connect (no listener) so
    `is_ibounce_running()` returns False during tests that don't
    explicitly bind a socket."""
    port = int(os.environ["IBOUNCE_PROBE_PORT"])
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(0.25)
    try:
        # A connect to an unbound port returns ECONNREFUSED → OSError.
        # If it succeeds, something is listening on the port — that's
        # a fixture bug.
        connected = False
        try:
            s.connect(("127.0.0.1", port))
            connected = True
        except OSError:
            pass
        assert not connected, (
            f"port {port} chosen by the conftest fixture has a live "
            "listener; the OS may have raced or _find_unused_port() "
            "logic is wrong."
        )
    finally:
        s.close()


# ---------------------------------------------------------------------------
# GH #5 — IAM_JIT_BOUNCER_PROFILES_FILE isolation (still in effect)
# ---------------------------------------------------------------------------


def test_conftest_sets_bouncer_profiles_file_to_tmpdir() -> None:
    """The pre-existing GH #5 isolation MUST still be in effect after
    the GH #565 extension — the conftest extends, not replaces."""
    raw = os.environ.get("IAM_JIT_BOUNCER_PROFILES_FILE")
    assert raw, (
        "IAM_JIT_BOUNCER_PROFILES_FILE not set; the GH #5 autouse "
        "behavior was lost during the GH #565 extension."
    )
    path = pathlib.Path(raw)
    # The fixture points at a tmpdir-named file that doesn't yet exist
    # (so load_profiles() falls through to DEFAULT_PROFILES).
    assert "isolated_profiles.yaml" in path.name
    assert not path.exists(), (
        f"IAM_JIT_BOUNCER_PROFILES_FILE={path} exists on disk — the "
        "fixture should point at a non-existent path so load_profiles "
        "falls through to DEFAULT_PROFILES."
    )
