"""Shared fixtures for the threat-feed tests.

Per [[push-policy-public-repo]] every test that needs a publisher
keypair generates one EPHEMERALLY in tmp_path. No private key ever
gets persisted into the repo by these tests.
"""

from __future__ import annotations

import pathlib

import pytest

from iam_jit.threat_feed import ed25519_keygen


@pytest.fixture(autouse=True)
def _isolate_threat_feed_dirs(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> pathlib.Path:
    """Point the cache directory + ledger + pending queue + home at
    tmp_path so test runs are independent."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("IAM_JIT_THREAT_FEED_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.setenv(
        "IAM_JIT_THREAT_FEED_LEDGER_PATH",
        str(tmp_path / "applied.jsonl"),
    )
    monkeypatch.setenv(
        "IAM_JIT_PROFILE_ALLOW_PENDING_PATH",
        str(tmp_path / "profile-allow-pending.jsonl"),
    )
    monkeypatch.setenv(
        "IAM_JIT_DYNAMIC_DENIES_PATH",
        str(tmp_path / "dynamic-denies.yaml"),
    )
    return tmp_path


@pytest.fixture
def ephemeral_keypair() -> tuple[str, str]:
    """Generate a single ephemeral Ed25519 keypair for the test session.

    Private key is held only in memory; never persisted to disk by
    this fixture. The publisher tests that persist it write it under
    ``tmp_path`` (so it's auto-cleaned + outside the repo).
    """
    return ed25519_keygen()
