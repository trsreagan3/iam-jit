"""Guard test for #654 / #669 — install hints must NOT reference bare PyPI package name.

iam-jit is not yet on PyPI (HTTP 404 for https://pypi.org/pypi/iam-jit/json).
Every operator-facing install hint must use the git+https:// source install
until the PyPI publish task (#235) is complete.

This test asserts that:
  1. No hint string returned by _python_install_hint() ends with a bare
     'iam-jit' token (i.e., 'pipx install iam-jit' or 'pip install iam-jit'
     without a URL/extra following).  [#654]
  2. No ```bash or ```shell fenced code block in README.md or docs/*.md
     contains a bare 'pip(x) install iam-jit' pattern.  [#669]

"Note: Will switch to pip install iam-jit once ..." blockquotes are prose
references to the future PyPI form and are intentionally excluded from the
scan (they are not runnable commands).

Skip condition: set IAM_JIT_PYPI_PUBLISHED=1 in environment to skip this test
once the package is live on PyPI and the hints are updated to the bare name.

Per [[tests-and-independent-uat-required]]: every shipped feature includes a
guard test. Per [[ibounce-honest-positioning]]: hints must actually work.
"""

from __future__ import annotations

import os
import pathlib
import re
import sys

import pytest

from iam_jit import cli_doctor_install_check as dic

# ---------------------------------------------------------------------------
# README path (resolved relative to this file so it works regardless of cwd)
# ---------------------------------------------------------------------------

_REPO_ROOT = pathlib.Path(__file__).parent.parent
_README = _REPO_ROOT / "README.md"


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


# ---------------------------------------------------------------------------
# #669 — fenced ```bash / ```shell blocks in README + docs/*.md must not
#         contain bare PyPI patterns
# ---------------------------------------------------------------------------

# Files to scan: README.md + every .md under docs/.
# Historical records are excluded by name to avoid false positives on
# intentional "these commands fail" smoke-test results.
_HISTORICAL_EXCLUDE_STEMS = {
    "SMOKE-TEST-RESULTS-2026-05-19",
    "LAUNCH-READINESS-2026-05-16",
    "PUBLISHING",          # forward-looking action.yml TODO (post-PyPI)
}

# "Note: Will switch to pip install iam-jit ..." blockquotes are prose
# references to the future PyPI form; they are not runnable commands.
# We only scan content *inside* fenced ```bash or ```shell blocks.
_FENCE_OPEN_RE = re.compile(r"^```(?:bash|shell)\s*$")
_FENCE_CLOSE_RE = re.compile(r"^```\s*$")


def _scan_md_file_bash_blocks(
    md_path: pathlib.Path,
) -> list[tuple[str, int, str]]:
    """Return list of (rel_path, start_line, matched_text) for every bare
    PyPI install pattern found inside ```bash or ```shell fenced blocks.

    Line numbers are 1-based (the opening fence line).
    """
    violations: list[tuple[str, int, str]] = []
    try:
        lines = md_path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return violations

    rel = str(md_path.relative_to(_REPO_ROOT))
    in_block = False
    block_start = 0

    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if not in_block and _FENCE_OPEN_RE.match(stripped):
            in_block = True
            block_start = i
        elif in_block and _FENCE_CLOSE_RE.match(stripped):
            in_block = False
        elif in_block:
            for match in _BARE_PYPI_RE.finditer(line):
                violations.append((rel, block_start, match.group(0)))

    return violations


def _collect_md_targets() -> list[pathlib.Path]:
    """Collect README.md + all .md files under docs/ that are not in the
    historical-exclude list.
    """
    targets: list[pathlib.Path] = []
    if _README.exists():
        targets.append(_README)
    docs_dir = _REPO_ROOT / "docs"
    if docs_dir.is_dir():
        for md in sorted(docs_dir.rglob("*.md")):
            if md.stem not in _HISTORICAL_EXCLUDE_STEMS:
                targets.append(md)
    return targets


def test_docs_bash_blocks_no_bare_pypi() -> None:
    """Every ```bash/```shell fenced block in README.md and docs/*.md must
    not contain a bare 'pip(x) install iam-jit' pattern (#669 closes here).

    Bare PyPI names are incorrect until iam-jit is published to PyPI
    (#235). All install commands must use the git+https:// source URL.

    'Note: Will switch to pip install iam-jit ...' blockquotes are prose
    (not inside fenced blocks) and are intentionally excluded.

    Historical smoke-test results and planning docs are excluded by name
    (SMOKE-TEST-RESULTS-2026-05-19, LAUNCH-READINESS-2026-05-16, PUBLISHING).

    Skip condition: set IAM_JIT_PYPI_PUBLISHED=1 once iam-jit is live on
    PyPI and install commands are updated to the bare package name.
    """
    targets = _collect_md_targets()
    assert targets, "Expected at least README.md to exist in repo root"

    all_violations: list[str] = []
    for md_path in targets:
        for rel, start_line, matched in _scan_md_file_bash_blocks(md_path):
            all_violations.append(
                f"{rel} (code block starting line {start_line}): "
                f"bare PyPI pattern {matched!r}"
            )

    assert not all_violations, (
        "Fenced bash/shell blocks contain bare PyPI install patterns (#669). "
        "Use 'git+https://github.com/trsreagan3/iam-jit.git' until #235 lands.\n"
        + "\n".join(all_violations)
    )
