"""
Invariant tests for the CONTENT-KEYED baseline.

These prove the two halves of the security-critical contract:

  1. Line-number shifts of an EXISTING baselined finding are recognized as the
     SAME finding (the false-positive bug this change fixes).
  2. A genuinely-NEW silent-degradation in new/changed code is STILL flagged
     (the property the linter exists for — must never be weakened).

Plus duplicate handling and lossless migration of the real baseline.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

_TOOLS_DIR = Path(__file__).parent.parent.parent
if str(_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(_TOOLS_DIR))

from silent_degradation_linter.lint import (  # noqa: E402
    baseline_counts,
    load_baseline,
    new_findings,
    save_baseline,
    scan_paths,
)

_REPO_ROOT = _TOOLS_DIR.parent
_REAL_BASELINE = _TOOLS_DIR / "silent_degradation_linter" / "baseline.json"


def _scan(root: Path):
    return scan_paths(["src"], repo_root=root, rules=("SD-1", "SD-2", "SD-4"))


def _make_tree(tmp_path: Path, body: str) -> Path:
    """Create a minimal repo tree with one source file containing *body*."""
    src = tmp_path / "src"
    src.mkdir(parents=True, exist_ok=True)
    (src / "mod.py").write_text(body)
    return tmp_path


# ---------------------------------------------------------------------------
# INVARIANT 1 — line shift of an existing finding is NOT new (the bug fix)
# ---------------------------------------------------------------------------

def test_line_shift_of_existing_finding_is_recognized(tmp_path):
    """Insert blank lines ABOVE a baselined finding → ratchet PASSES.

    This is the exact false-positive that every rebase used to trigger.
    """
    body = (
        "def f():\n"
        "    try:\n"
        "        risky()\n"
        "    except Exception:\n"
        "        pass\n"
    )
    root = _make_tree(tmp_path, body)
    findings_before = _scan(root)
    assert findings_before, "fixture must produce at least one finding"
    baseline_file = tmp_path / "baseline.json"
    save_baseline(baseline_file, findings_before)
    before_line = findings_before[0].line

    # Shift the finding DOWN by prepending blank + comment lines.
    shifted = ("\n# unrelated edit above\n\n\n") + body
    _make_tree(root, shifted)
    findings_after = _scan(root)
    after_line = findings_after[0].line

    assert after_line != before_line, "line should have actually shifted"

    baseline = load_baseline(baseline_file)
    fresh = new_findings(findings_after, baseline)
    assert fresh == [], (
        "Line-shifted existing finding was wrongly flagged as NEW: "
        + str([(x.rule, x.line) for x in fresh])
    )


# ---------------------------------------------------------------------------
# INVARIANT 2 — a genuinely-new finding in new code IS flagged (must hold)
# ---------------------------------------------------------------------------

def test_new_finding_in_new_code_is_flagged(tmp_path):
    """Add a brand-new `except Exception: pass` → ratchet FAILS (flagged)."""
    body = (
        "def f():\n"
        "    try:\n"
        "        risky()\n"
        "    except Exception:\n"
        "        pass\n"
    )
    root = _make_tree(tmp_path, body)
    baseline_file = tmp_path / "baseline.json"
    save_baseline(baseline_file, _scan(root))

    # Add a SECOND, genuinely-new swallow in different surrounding code.
    body2 = body + (
        "\n"
        "def g():\n"
        "    try:\n"
        "        other_call()\n"
        "    except ValueError:\n"
        "        pass\n"
    )
    _make_tree(root, body2)
    findings_after = _scan(root)
    baseline = load_baseline(baseline_file)
    fresh = new_findings(findings_after, baseline)

    assert len(fresh) == 1, (
        f"Expected exactly the new swallow to be flagged, got: "
        + str([(x.rule, x.line, x.message) for x in fresh])
    )
    assert "ValueError" in fresh[0].message or fresh[0].line > 5


def test_new_finding_with_same_text_but_new_context_is_flagged(tmp_path):
    """A NEW swallow whose matched line text equals an existing one, but in
    genuinely different surrounding code, is still flagged (context differs)."""
    body = (
        "def f():\n"
        "    try:\n"
        "        alpha()\n"
        "    except Exception:\n"
        "        pass\n"
    )
    root = _make_tree(tmp_path, body)
    baseline_file = tmp_path / "baseline.json"
    save_baseline(baseline_file, _scan(root))

    body2 = body + (
        "\n"
        "def g():\n"
        "    try:\n"
        "        beta()\n"          # different surrounding code
        "    except Exception:\n"   # same matched-line text as the baselined one
        "        pass\n"
    )
    _make_tree(root, body2)
    fresh = new_findings(_scan(root), load_baseline(baseline_file))
    assert len(fresh) == 1, (
        "A new except-pass with same text but new context must be flagged: "
        + str([(x.line, x.snippet) for x in fresh])
    )


# ---------------------------------------------------------------------------
# INVARIANT 3 — duplicate handling (add/remove identical findings)
# ---------------------------------------------------------------------------

def test_adding_a_second_identical_finding_is_flagged(tmp_path):
    """Two identical findings share a signature → multiset count detects the
    NEW second copy even though the signature already exists in the baseline."""
    one = (
        "def f():\n"
        "    try:\n"
        "        risky()\n"
        "    except Exception:\n"
        "        pass\n"
    )
    root = _make_tree(tmp_path, one)
    baseline_file = tmp_path / "baseline.json"
    save_baseline(baseline_file, _scan(root))

    # Two byte-identical functions → two identical findings (same signature).
    two = one + "\n" + one.replace("def f", "def f2")
    # Make context identical by keeping bodies identical; only the def name
    # differs which is NOT part of SD-1's signature material.
    two = one + "\n" + (
        "def f():\n"
        "    try:\n"
        "        risky()\n"
        "    except Exception:\n"
        "        pass\n"
    )
    _make_tree(root, two)
    after = _scan(root)
    # Sanity: the two SD-1 findings must collide on signature.
    sigs = {x.signature() for x in after if x.rule == "SD-1"}
    assert len(sigs) == 1, "expected the two identical swallows to share a signature"

    fresh = new_findings(after, load_baseline(baseline_file))
    assert len(fresh) == 1, (
        "Adding a second identical swallow must be flagged as one new finding, "
        f"got {len(fresh)}"
    )


def test_removing_one_of_two_identical_is_not_new(tmp_path):
    """Going from 2 identical findings to 1 is debt REDUCTION, not new debt —
    the ratchet must pass (it only fails on additions)."""
    block = (
        "def f():\n"
        "    try:\n"
        "        risky()\n"
        "    except Exception:\n"
        "        pass\n"
    )
    two = block + "\n" + block
    root = _make_tree(tmp_path, two)
    baseline_file = tmp_path / "baseline.json"
    save_baseline(baseline_file, _scan(root))

    # Remove one copy.
    _make_tree(root, block)
    fresh = new_findings(_scan(root), load_baseline(baseline_file))
    assert fresh == [], "removing one of two identical findings must not be 'new'"


# ---------------------------------------------------------------------------
# INVARIANT 3b — SLOT-FREEING is defeated by the enclosing-scope key
# ---------------------------------------------------------------------------

def test_slot_freeing_across_functions_is_flagged(tmp_path):
    """The HIGH masking hole from the PR #64 review.

    Without the enclosing-scope component, two byte-identical boilerplate
    swallows in DIFFERENT functions share a signature.  An attacker could then
    DELETE one occurrence of a high-count baselined signature and ADD a
    genuinely-new swallow with byte-identical normalized context in another
    function: the multiset count stays unchanged, so the ratchet would report
    0 new — masking a real new silent-degradation.

    With the enclosing-scope (qualified def/class name) folded into the
    signature, the deleted occurrence and the new occurrence live in DIFFERENT
    scopes → different signatures → the new one is flagged (surplus), and the
    deleted one is debt-reduction (count drops to 0).  Net: exactly one NEW
    finding is reported and the ratchet FAILS as it must.
    """
    # Three functions, each containing the byte-identical boilerplate swallow.
    # The bodies are byte-for-byte identical so context + message collide; only
    # the enclosing function name differs.
    swallow = (
        "    try:\n"
        "        do_work()\n"
        "    except Exception:\n"
        "        pass\n"
    )
    body = (
        "def alpha():\n" + swallow +
        "\n"
        "def beta():\n" + swallow +
        "\n"
        "def gamma():\n" + swallow
    )
    root = _make_tree(tmp_path, body)
    baseline_file = tmp_path / "baseline.json"
    before = _scan(root)
    save_baseline(baseline_file, before)

    # Sanity: under the OLD (scope-less) scheme these would all collide on one
    # signature (count 3).  Under the new scheme they are three distinct sigs.
    sigs_before = {f.signature() for f in before if f.rule == "SD-1"}
    assert len(sigs_before) == 3, (
        "enclosing-scope key must make the three identical swallows distinct; "
        f"got {len(sigs_before)} signature(s)"
    )

    # SLOT-FREEING attempt: delete the swallow in `gamma` (one occurrence of a
    # baselined pattern) and ADD a byte-identical swallow in a brand-NEW
    # function `delta`.  The multiset COUNT of the boilerplate is unchanged (3),
    # which is exactly what a scope-less key would be fooled by.
    attacked = (
        "def alpha():\n" + swallow +
        "\n"
        "def beta():\n" + swallow +
        "\n"
        "def gamma():\n"
        "    return 1\n"  # gamma's swallow removed
        "\n"
        "def delta():\n" + swallow  # genuinely-new swallow elsewhere
    )
    _make_tree(root, attacked)
    after = _scan(root)
    fresh = new_findings(after, load_baseline(baseline_file))

    assert len(fresh) == 1, (
        "Slot-freeing must NOT mask the new swallow — expected exactly the "
        "delta() swallow to be flagged, got: "
        + str([(x.scope, x.line, x.snippet) for x in fresh])
    )
    assert fresh[0].scope == "delta", (
        f"the flagged finding must be the new delta() swallow, not {fresh[0].scope}"
    )


def test_line_shift_within_same_function_still_recognized(tmp_path):
    """The original line-shift fix must STILL hold under the scope key: moving
    an existing finding's lines WITHIN the same function is not new."""
    body = (
        "def f():\n"
        "    x = 1\n"
        "    try:\n"
        "        risky()\n"
        "    except Exception:\n"
        "        pass\n"
    )
    root = _make_tree(tmp_path, body)
    baseline_file = tmp_path / "baseline.json"
    before = _scan(root)
    save_baseline(baseline_file, before)
    before_line = before[0].line

    # Shift the swallow DOWN within the SAME function by adding statements above
    # it (still inside f) — scope is unchanged, so signature is unchanged.
    shifted = (
        "def f():\n"
        "    x = 1\n"
        "    y = 2\n"
        "    z = 3\n"
        "    try:\n"
        "        risky()\n"
        "    except Exception:\n"
        "        pass\n"
    )
    _make_tree(root, shifted)
    after = _scan(root)
    assert after[0].line != before_line, "line should have actually shifted"
    assert after[0].scope == "f"
    fresh = new_findings(after, load_baseline(baseline_file))
    assert fresh == [], (
        "Line-shifted finding within the same function must not be flagged: "
        + str([(x.scope, x.line) for x in fresh])
    )


# ---------------------------------------------------------------------------
# INVARIANT 4 — the SHIPPED baseline migrates cleanly with no loss
# ---------------------------------------------------------------------------

def test_shipped_baseline_recognizes_every_current_finding():
    """Every finding in the current tree must be covered by the shipped
    content-keyed baseline — i.e. the ratchet is clean and nothing was lost
    in migration."""
    findings = scan_paths(
        ["src/iam_jit", "tests"], repo_root=_REPO_ROOT, rules=("SD-1", "SD-2", "SD-4")
    )
    baseline = load_baseline(_REAL_BASELINE)
    fresh = new_findings(findings, baseline)
    assert fresh == [], (
        f"{len(fresh)} current finding(s) not covered by shipped baseline: "
        + str([(x.rule, x.path, x.line) for x in fresh[:10]])
    )


def test_shipped_baseline_count_matches_tree():
    """The pinned multiset total equals the number of findings in the tree."""
    findings = scan_paths(
        ["src/iam_jit", "tests"], repo_root=_REPO_ROOT, rules=("SD-1", "SD-2", "SD-4")
    )
    baseline = load_baseline(_REAL_BASELINE)
    assert sum(baseline.values()) == len(findings), (
        f"baseline pins {sum(baseline.values())} but tree has {len(findings)}"
    )
    # And the per-signature multiset must match exactly.
    assert baseline_counts(findings) == baseline
