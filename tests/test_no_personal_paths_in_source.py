"""#600 — guard against personal-filesystem-path leaks in non-test source.

Independent code review 2026-05-25 flagged a `/Users/reagan/repos/...`
path in `src/iam_jit/dynamic_denies/watcher.py:6`. Per
[[push-policy-public-repo]] those paths must never land in the public
repo (information disclosure: home directory shape, project layout,
operator identity).

This test pair acts as a structural guardrail:

  1. `test_no_personal_paths_in_python_source` — scan tracked Python
     source under src/iam_jit/ and assert zero `/Users/<name>/` or
     `/home/<name>/` matches. This is the inverse of the #600 fix —
     if a future commit re-introduces a personal path, this test
     fails loudly at PR time before the pre-commit hook even gets a
     chance to run.

  2. `test_pre_commit_hook_catches_violation` /
     `test_pre_commit_hook_passes_clean_file` — exercise the script
     itself with a fixture violation + a fixture clean file. Proves
     the structural prevention (the pre-commit hook) actually works,
     not just that someone wrote a script with the right name.

Per docs/CONTRIBUTING.md state-verification convention: each test
asserts the OBSERVABLE outcome (file contents, script exit code,
stderr text), not just internal behaviour.
"""

from __future__ import annotations

import pathlib
import re
import subprocess


_REPO_ROOT = pathlib.Path(__file__).parent.parent
_SRC_ROOT = _REPO_ROOT / "src" / "iam_jit"
_SCRIPT = _REPO_ROOT / "scripts" / "check_no_personal_paths.sh"

# Same pattern the script uses. Matches /Users/<lowercase-name> or
# /home/<lowercase-name>. Does NOT match `~/` (tilde-relative is fine)
# or repo-relative paths.
_PERSONAL_PATH_RE = re.compile(r"/Users/[a-z]+|/home/[a-z]+")

# Files legitimately excluded from the personal-path ban (test data,
# security-audit reports that document attacker-visible paths, etc).
# The script applies the same exclusions; this list keeps the test +
# script in sync.
_EXCLUDE_PATTERNS = (
    "/tests/", "test_", "/fixtures/", "fixtures/",
)


def _iter_tracked_python_sources() -> list[pathlib.Path]:
    """Yield TRACKED Python files under src/iam_jit/ that are NOT
    test/fixture files. We use `git ls-files` (not rglob) so that
    untracked work-in-progress from concurrent agents doesn't fail
    this test. The pre-commit hook is the structural prevention that
    catches a newly-added file BEFORE it lands; this test catches
    regressions in what's already on the branch.
    """
    import subprocess
    out = subprocess.run(
        ["git", "-C", str(_REPO_ROOT), "ls-files", "src/iam_jit/**/*.py"],
        capture_output=True, text=True, check=True,
    )
    paths: list[pathlib.Path] = []
    for rel in out.stdout.splitlines():
        if not rel.strip():
            continue
        if any(pat in rel for pat in _EXCLUDE_PATTERNS):
            continue
        p = _REPO_ROOT / rel
        if p.exists():
            paths.append(p)
    return paths


# ----- The source-state check --------------------------------------------


def test_no_personal_paths_in_python_source() -> None:
    """Scan all non-test Python under src/iam_jit/ for personal-path
    leaks. This is the #600 regression test — when watcher.py:6 leaked
    `/Users/reagan/repos/gbounce/...`, this test would have failed at
    PR time.
    """
    leaks: list[str] = []
    for p in _iter_tracked_python_sources():
        text = p.read_text(encoding="utf-8", errors="replace")
        for ln, line in enumerate(text.splitlines(), start=1):
            for m in _PERSONAL_PATH_RE.finditer(line):
                leaks.append(f"{p.relative_to(_REPO_ROOT)}:{ln}: {m.group(0)}")

    assert not leaks, (
        "personal filesystem paths leaked into non-test Python source "
        "(violates [[push-policy-public-repo]]):\n  "
        + "\n  ".join(leaks)
        + "\n\nFix by replacing with repo-relative refs or canonical "
        "placeholders (~/.kube/config, ./foo, <repo>: path/file)."
    )


# ----- The pre-commit hook script checks ---------------------------------


def test_pre_commit_script_exists_and_is_executable() -> None:
    """The structural prevention script must be present + executable
    for the pre-commit hook to invoke it."""
    assert _SCRIPT.exists(), (
        f"pre-commit script missing at {_SCRIPT}; "
        "[[push-policy-public-repo]] structural prevention not in place"
    )
    import os
    assert os.access(_SCRIPT, os.X_OK), (
        f"pre-commit script not executable: {_SCRIPT}"
    )


def test_pre_commit_hook_catches_violation(tmp_path: pathlib.Path) -> None:
    """State verification: feed the script a file containing a
    personal path; it must exit non-zero AND name the offending path
    in stderr (so the operator who triggered the pre-commit hook can
    see what to fix)."""
    violator = tmp_path / "violator.py"
    violator.write_text(
        '# This module talks to the gbounce binary at\n'
        '# /Users/reagan/repos/gbounce/cmd/main.go\n'
    )
    result = subprocess.run(
        [str(_SCRIPT), str(violator)],
        capture_output=True, text=True,
    )
    assert result.returncode != 0, (
        f"pre-commit script let a personal-path violation through "
        f"(exit code 0). stdout={result.stdout!r} stderr={result.stderr!r}"
    )
    # State verification: the error message names the offending path
    # so the operator can fix it without spelunking.
    assert "/Users/reagan" in result.stderr, (
        f"script exited non-zero but didn't surface the bad path; "
        f"stderr={result.stderr!r}"
    )


def test_pre_commit_hook_passes_clean_file(tmp_path: pathlib.Path) -> None:
    """Inverse check: a file with NO personal paths must exit 0."""
    clean = tmp_path / "clean.py"
    clean.write_text(
        '"""Module that uses repo-relative refs."""\n'
        '# See ~/.iam-jit/dynamic-denies.yaml for the watched file.\n'
        '# Architecture mirrors gbounce: internal/dynamicdeny/watcher.go\n'
        'X = 1\n'
    )
    result = subprocess.run(
        [str(_SCRIPT), str(clean)],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, (
        f"pre-commit script rejected a clean file. "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )


def test_pre_commit_hook_excludes_test_files(tmp_path: pathlib.Path) -> None:
    """Test fixtures legitimately reference personal paths (this very
    test does so to exercise the script). The hook must exclude them."""
    # Create a "test" file inside tmp_path that has a personal path —
    # the script's exclusion is name-based, so anything matching
    # `test_*` should be skipped.
    test_file = tmp_path / "test_something.py"
    test_file.write_text(
        '# Intentional personal path for test data:\n'
        '# /Users/reagan/repos/foo/bar.go\n'
    )
    result = subprocess.run(
        [str(_SCRIPT), str(test_file)],
        capture_output=True, text=True,
    )
    assert result.returncode == 0, (
        f"pre-commit script flagged a test file (should be excluded). "
        f"stdout={result.stdout!r} stderr={result.stderr!r}"
    )


def test_pre_commit_hook_zero_files_is_noop() -> None:
    """pre-commit invokes the hook with zero positional args when the
    commit contains no matching file types. Hook must exit 0 cleanly."""
    result = subprocess.run([str(_SCRIPT)], capture_output=True, text=True)
    assert result.returncode == 0, (
        f"zero-arg invocation failed; stderr={result.stderr!r}"
    )
