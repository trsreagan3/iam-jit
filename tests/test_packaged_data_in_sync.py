"""#699 dogfood regression guard: packaged data files must stay
in sync with their canonical repo-root copies.

History — this class of bug:
- 5fd3565 (#324f, weeks ago): canonical schemas/request.schema.json
  gained `status.provisioned.embedded_dynamic_denies` field; the
  shipped src/iam_jit/schemas/request.schema.json was never updated.
  Result: every auto-approved provisioning request crashed 500 in
  pip-installed iam-jit (the shipped schema rejected the field).
  Latent for weeks — neither unit tests nor integration tests
  detected the drift because they used the canonical schema.
- dee1d80 (#698 MED-5, this session): same shape — operator-tags
  field added to canonical, missed in shipped. Surfaced by the #699
  re-dogfood.

The drift is invisible to in-repo tests because development reads the
canonical (via _resources.find walking parents[2] = repo root); only
pip-install / wheel deploys hit the shipped copy. So the test gate
must compare the TWO files byte-for-byte, regardless of which one
any individual feature ends up loading.

The proper structural fix would be a single source of truth (delete
the shipped copy + always serve via importlib.resources from the
canonical), but that's a wider refactor. This test is the immediate
gate: any commit that breaks sync fails CI.

Generalization: every file mirrored by scripts/sync-lambda-data.sh
gets one test here. New mirrors → add a check.
"""
from __future__ import annotations

import hashlib
import pathlib

import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
CANONICAL_DIR = REPO_ROOT / "schemas"
SHIPPED_DIR = REPO_ROOT / "src" / "iam_jit" / "schemas"
CFN_CANONICAL_DIR = REPO_ROOT / "infrastructure" / "cloudformation"
CFN_SHIPPED_DIR = REPO_ROOT / "src" / "iam_jit" / "infrastructure" / "cloudformation"


def _digest(p: pathlib.Path) -> str:
    return hashlib.sha256(p.read_bytes()).hexdigest()


def _mirror_pairs():
    """Yield (canonical, shipped, kind) for every file that
    scripts/sync-lambda-data.sh mirrors."""
    for f in sorted(CANONICAL_DIR.glob("*.json")):
        yield f, SHIPPED_DIR / f.name, "schema"
    for f in sorted(CFN_CANONICAL_DIR.glob("*.yaml")):
        yield f, CFN_SHIPPED_DIR / f.name, "cfn-template"


@pytest.mark.parametrize(
    "canonical,shipped,kind",
    list(_mirror_pairs()),
    ids=lambda p: p.name if isinstance(p, pathlib.Path) else str(p),
)
def test_packaged_data_matches_canonical(canonical, shipped, kind):
    """Each repo-root data file must have a byte-identical copy in
    src/iam_jit/ so the wheel ships the current shape.

    To fix a failure: `bash scripts/sync-lambda-data.sh`.
    """
    assert canonical.exists(), f"canonical missing: {canonical}"
    assert shipped.exists(), (
        f"shipped copy missing: {shipped} (run scripts/sync-lambda-data.sh)"
    )
    cd = _digest(canonical)
    sd = _digest(shipped)
    assert cd == sd, (
        f"{kind} drift between canonical {canonical.relative_to(REPO_ROOT)} "
        f"and shipped {shipped.relative_to(REPO_ROOT)}. "
        f"Run `bash scripts/sync-lambda-data.sh` and commit the result. "
        f"This drift is INVISIBLE to in-repo tests but breaks pip-installed "
        f"deployments — see test docstring for #699 history."
    )


def test_at_least_one_mirror_pair_exists():
    """Sanity: if scripts/sync-lambda-data.sh stops mirroring anything,
    this test fails LOUDLY so we know to delete this guard or fix the
    discovery. Prevents the parametrize from silently iterating zero
    pairs and the test 'passing' vacuously."""
    pairs = list(_mirror_pairs())
    assert len(pairs) > 0, (
        "no mirror pairs discovered — the sync layout changed; "
        "update _mirror_pairs() in this test file"
    )
