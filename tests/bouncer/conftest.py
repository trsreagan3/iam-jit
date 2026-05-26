"""Bouncer-test fixtures.

Per GH #5 (test env isolation): tests in this directory MUST NOT read
the developer's actual ``~/.iam-jit/bouncer/profiles.yaml``. On a
dogfooded machine that file may contain a custom profile set that
lacks ``safe-default`` (or any other DEFAULT_PROFILES name a test
expects), which would cause non-deterministic ``KeyError`` failures
unrelated to the code under test.

The autouse fixture below points ``IAM_JIT_BOUNCER_PROFILES_FILE`` at
a per-test ``tmp_path`` location that doesn't exist on disk. The
``load_profiles()`` function then falls through to
``_build_default_profile_map()`` (and, post GH #6, the merge with
DEFAULT_PROFILES also covers any test that writes its own user file).

Any test that wants to provide its own profiles file simply overrides
the env var via ``monkeypatch.setenv`` to point at the file it wrote —
the standard pattern used throughout ``test_profiles_slice7.py``.

Per GH #565 (env-isolation cluster, 2026-05-24): the same autouse
fixture also strips ``IBOUNCE_AGENT_NAME`` + ``IBOUNCE_AGENT_SESSION_ID``
from the test process environment, and points ``IBOUNCE_PROBE_PORT``
at an ephemeral unused port. On a founder dogfood machine those env
vars carry a live agent identity (and a real ibounce listens on
``127.0.0.1:8767``), and either leak would silently change the
observable behavior of tests like
``test_show_config_emits_valid_json_with_ibounce_entry`` (which
inspects emitted env for the MCP snippet — pre-fix the test asserted
``env == {}`` and per #564 now asserts the production-emitted keys
are present) and ``test_cli_export_then_import_round_trip`` (which
refuses import when the probe sees a live listener).

Per GH #665 (audit-log isolation, 2026-05-26): the same autouse
fixture also points ``IAM_JIT_BOUNCER_AUDIT_LOG`` at a per-test
non-existent path so ``default_audit_log_path()`` in the
``/audit/events`` handler never falls back to the developer's real
``~/.iam-jit/audit.jsonl``. On a dogfooded machine that file carries
live audit events; without isolation every test that passes
``audit_log_path=None`` to the handler silently reads those events
instead of the seeded fixture data (the root cause of
``test_audit_events_endpoint_store_ocsf_bundle_format`` returning 77
events vs the expected 3).

Any test that wants to provide its own profiles file simply overrides
the env var via ``monkeypatch.setenv(...)`` in the test body — the
autouse delenv composes cleanly with a subsequent setenv.
"""

from __future__ import annotations

import socket
from collections.abc import Iterator

import pytest


def _find_unused_port() -> int:
    """Bind a socket to port 0 to let the OS pick an unused port,
    then release it. The returned port is suitable for use as a
    probe-target that's guaranteed empty for the duration of the test
    (test code runs fast enough that race-reuse is not a real concern
    for this single-process-per-test pytest configuration)."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(autouse=True)
def _isolate_bouncer_env(
    tmp_path: object,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[None]:
    """Isolate every bouncer-test from the developer's environment.

    Per GH #5: forces IAM_JIT_BOUNCER_PROFILES_FILE → per-test tmpdir
    so tests never leak into ``~/.iam-jit/bouncer/profiles.yaml``.

    Per GH #565: strips IBOUNCE_AGENT_NAME + IBOUNCE_AGENT_SESSION_ID
    so a dogfood machine's agent-identity env doesn't change what
    ``ibounce mcp show-config`` reports during tests; and sets
    IBOUNCE_PROBE_PORT to an ephemeral unused port so the
    "ibounce already running" probe doesn't false-positive against a
    real running bouncer on 127.0.0.1:8767.
    """
    isolated = tmp_path / "isolated_profiles.yaml"  # type: ignore[operator]
    monkeypatch.setenv("IAM_JIT_BOUNCER_PROFILES_FILE", str(isolated))
    monkeypatch.delenv("IBOUNCE_AGENT_NAME", raising=False)
    monkeypatch.delenv("IBOUNCE_AGENT_SESSION_ID", raising=False)
    monkeypatch.setenv("IBOUNCE_PROBE_PORT", str(_find_unused_port()))
    # GH #665: prevent default_audit_log_path() from falling back to the
    # developer's real ~/.iam-jit/audit.jsonl. Point at a per-test path
    # that never exists so tests seeding their own stores get exactly the
    # events they wrote, not 77+ live dogfood events.
    isolated_audit_log = tmp_path / "isolated_audit.jsonl"  # type: ignore[operator]
    monkeypatch.setenv("IAM_JIT_BOUNCER_AUDIT_LOG", str(isolated_audit_log))
    yield
