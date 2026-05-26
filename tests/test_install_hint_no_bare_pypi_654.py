"""Guard test for #654 — install hints must NOT reference bare PyPI package name.

iam-jit is not yet on PyPI (HTTP 404 for https://pypi.org/pypi/iam-jit/json).
Every operator-facing install hint must use the git+https:// source install
until the PyPI publish task (#235) is complete.

This test asserts that no hint string returned by _python_install_hint() ends
with a bare 'iam-jit' token (i.e., 'pipx install iam-jit' or
'pip install iam-jit' without a URL/extra following).

Skip condition: set IAM_JIT_PYPI_PUBLISHED=1 in environment to skip this test
once the package is live on PyPI and the hints are updated to the bare name.

Per [[tests-and-independent-uat-required]]: every shipped feature includes a
guard test. Per [[ibounce-honest-positioning]]: hints must actually work.
"""

from __future__ import annotations

import os
import re
import sys

import pytest

from iam_jit import cli_doctor_install_check as dic


# ---------------------------------------------------------------------------
# Skip gate
# ---------------------------------------------------------------------------

_PYPI_PUBLISHED = os.environ.get("IAM_JIT_PYPI_PUBLISHED", "").strip() == "1"

pytestmark = pytest.mark.skipif(
    _PYPI_PUBLISHED,
    reason=(
        "IAM_JIT_PYPI_PUBLISHED=1 set — iam-jit is on PyPI; "
        "bare package-name hints are now correct. "
        "Remove or unset the env var to re-enable this guard (#654)."
    ),
)

# ---------------------------------------------------------------------------
# Patterns that indicate a bare PyPI package name in the install command
# ---------------------------------------------------------------------------

# Matches 'pipx install iam-jit' or 'pip install iam-jit' or
# 'pip install --user iam-jit' where 'iam-jit' is the LAST non-whitespace
# token on the hint line (i.e., no git+https:// or extras following).
_BARE_PYPI_RE = re.compile(
    r"\bpip(?:x)? install\b(?:\s+--\S+)*\s+iam-jit\s*(?:#|$)",
)

# ---------------------------------------------------------------------------
# Helper: collect all OS-branch hints
# ---------------------------------------------------------------------------

_PLATFORM_EXE_PAIRS = [
    # (platform, executable)  — covers every branch in _python_install_hint
    ("darwin", "/opt/homebrew/Cellar/python@3.12/3.12.9/bin/python3.12"),
    ("darwin", "/usr/local/Cellar/python@3.11/3.11.9/bin/python3.11"),
    ("darwin", "/usr/bin/python3"),
    ("darwin", "/Users/someuser/.local/share/pipx/venvs/iam-jit/bin/python3"),
    ("linux", "/usr/bin/python3"),   # apt-managed branch (dpkg mock)
    ("win32", "/some/unknown/python3"),  # generic fallback
    # #655 + #656 new paths
    ("darwin", "/Users/someuser/.pyenv/versions/3.12.0/bin/python"),  # pyenv macOS
    ("linux", "/root/.pyenv/versions/3.11.5/bin/python3"),            # pyenv Linux
    ("linux", "/nix/store/abc123-python3-3.12.0/bin/python3"),        # nix-store
]


def _get_hint(platform: str, exe: str, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setattr("iam_jit.cli_doctor_install_check.sys.platform", platform)
    monkeypatch.setattr("iam_jit.cli_doctor_install_check.sys.executable", exe)
    # For the Linux apt branch, make dpkg return success so that branch fires.
    if platform.startswith("linux"):
        import subprocess
        import types

        fake_result = types.SimpleNamespace(returncode=0, stdout="", stderr="")

        def _fake_run(*args, **kwargs):  # noqa: ANN001, ANN002, ANN003
            return fake_result

        monkeypatch.setattr("iam_jit.cli_doctor_install_check.subprocess.run", _fake_run)
    return dic._python_install_hint()


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("platform,exe", _PLATFORM_EXE_PAIRS)
def test_no_bare_pypi_name_in_hint(
    platform: str,
    exe: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Hint for (platform, exe) must NOT reference 'iam-jit' as a bare PyPI
    package name. It must use the git+https:// source URL (#654).

    Failure here means someone re-introduced 'pipx install iam-jit' or
    'pip install iam-jit' without the git+https:// URL, which breaks for
    any operator on a fresh machine before PyPI publish (#235).

    To permanently suppress this test once iam-jit is on PyPI, set
    IAM_JIT_PYPI_PUBLISHED=1 in the CI environment.
    """
    hint = _get_hint(platform, exe, monkeypatch)
    assert hint, f"hint must be a non-empty string (platform={platform!r}, exe={exe!r})"

    match = _BARE_PYPI_RE.search(hint)
    assert match is None, (
        f"Install hint references iam-jit as a bare PyPI name (#654). "
        f"Use 'git+https://github.com/trsreagan3/iam-jit.git' instead.\n"
        f"  platform={platform!r}  exe={exe!r}\n"
        f"  hint={hint!r}\n"
        f"  matched={match.group(0)!r}"
    )


def test_hint_contains_git_url(monkeypatch: pytest.MonkeyPatch) -> None:
    """At least the Homebrew macOS hint (most common dev path) must
    include the canonical git+https:// URL so operators can paste it
    directly (#654).
    """
    monkeypatch.setattr(
        "iam_jit.cli_doctor_install_check.sys.platform", "darwin",
    )
    monkeypatch.setattr(
        "iam_jit.cli_doctor_install_check.sys.executable",
        "/opt/homebrew/Cellar/python@3.12/3.12.9/bin/python3.12",
    )
    hint = dic._python_install_hint()
    assert "git+https://github.com/trsreagan3/iam-jit.git" in hint, (
        f"macOS Homebrew hint must reference the canonical git+https:// URL.\n"
        f"Got: {hint!r}"
    )
