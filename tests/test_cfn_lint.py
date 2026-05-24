"""Run `cfn-lint` against the destination-account template.

Pre-2026-05-24 this file also covered the hosted SAM template
(`infrastructure/sam/template.yaml`) — that template was deleted
when the hosted iam-risk-score Lambda was dropped per
[[no-hosted-saas]] restoration. The destination-account template
stays because operators deploy it into their own AWS accounts when
running the self-host suite.

This catches CFN-specific problems that the YAML-only structural
tests in `test_cloudformation_templates.py` can't see:

  - properties of the wrong type (e.g. `MaxValue: "180"` vs `180`)
  - required properties missing
  - deprecated resource shapes
  - intrinsic-function misuse (Sub vs Ref vs Join confusion)

No AWS account or credentials needed — cfn-lint is purely local.

If you intentionally need to suppress a specific lint rule, add it
to `.cfnlintrc` at the repo root rather than skipping the test.
"""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys

import pytest


_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
_DESTINATION_TEMPLATE = (
    _REPO_ROOT / "infrastructure" / "cloudformation"
    / "destination-account-roles.yaml"
)


def _cfn_lint_bin() -> str | None:
    """Locate cfn-lint. Prefer the venv copy (deterministic) but fall
    back to PATH so contributors who installed it system-wide still
    get coverage."""
    venv_bin = pathlib.Path(sys.executable).parent / "cfn-lint"
    if venv_bin.exists():
        return str(venv_bin)
    return shutil.which("cfn-lint")


_CFN_LINT = _cfn_lint_bin()


pytestmark = pytest.mark.skipif(
    _CFN_LINT is None,
    reason="cfn-lint not installed; install with `pip install cfn-lint`",
)


def _run_cfn_lint(template: pathlib.Path) -> subprocess.CompletedProcess:
    """Invoke cfn-lint with `cwd=_REPO_ROOT` so .cfnlintrc is found.
    cfn-lint searches CWD upward; if the test happens to run from a
    deeper or unrelated dir, the config wouldn't apply and suppressed
    rules would re-fire here."""
    return subprocess.run(
        [_CFN_LINT, str(template)],
        capture_output=True,
        text=True,
        timeout=120,
        cwd=_REPO_ROOT,
    )


def test_destination_account_template_lints_clean() -> None:
    result = _run_cfn_lint(_DESTINATION_TEMPLATE)
    assert result.returncode == 0, (
        f"cfn-lint reported issues on the destination-account template:\n"
        f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
    )
