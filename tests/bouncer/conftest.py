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
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest


@pytest.fixture(autouse=True)
def _isolate_bouncer_profiles_file(
    tmp_path: object,
    monkeypatch: pytest.MonkeyPatch,
) -> Iterator[None]:
    """Force IAM_JIT_BOUNCER_PROFILES_FILE to a per-test tmpdir path.

    Per GH #5: prevents tests from leaking into the developer's actual
    ``~/.iam-jit/bouncer/profiles.yaml`` (and vice versa).
    """
    isolated = tmp_path / "isolated_profiles.yaml"  # type: ignore[operator]
    monkeypatch.setenv("IAM_JIT_BOUNCER_PROFILES_FILE", str(isolated))
    yield
