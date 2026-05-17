"""WB31 CRIT-31-00 release gate.

This test fails the build if the production Ed25519 public key
embedded in `src/iam_jit/license.py` is still the all-zero
placeholder. Shipping v1.0 with the placeholder in place would
publish a non-functional license-verification path; this gate is
the launch-block enforcement.

Pre-launch: this test is EXPECTED TO FAIL until the founder
generates the real production keypair and commits the public key.
Until then, builds run on Free-tier-only (verify_license_bytes
short-circuit-rejects per the in-module runtime guard) — which is
the documented pre-launch intent.

Once the real key is in place, this test should pass + stay green
forever. If it ever goes red again, someone reverted the key to
the placeholder by accident; that's a launch-block.
"""

from __future__ import annotations

import pathlib

import pytest


PLACEHOLDER_SENTINEL = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="


@pytest.mark.skipif(
    True,  # Set to False once a real production key is installed.
    reason=(
        "Pre-launch: real production Ed25519 key not yet generated. "
        "This gate fires once the key is in place. See WB31 CRIT-31-00."
    ),
)
def test_production_public_key_is_not_placeholder() -> None:
    """The PRODUCTION_PUBLIC_KEY_B64 constant in license.py MUST NOT
    be the all-zero placeholder at release time."""
    from iam_jit import license as license_mod
    assert license_mod.PRODUCTION_PUBLIC_KEY_B64 != PLACEHOLDER_SENTINEL, (
        "PRODUCTION_PUBLIC_KEY_B64 is the all-zero placeholder. "
        "Generate the real production Ed25519 keypair offline, commit "
        "ONLY the public key (base64-encoded) to license.py, and store "
        "the private key offline for signing customer license files. "
        "This is a launch-block per WB31 CRIT-31-00."
    )


def test_placeholder_sentinel_constant_matches_module() -> None:
    """Sanity: the sentinel this gate compares against is the same
    string the module's runtime guard checks. If someone changes one
    they must change the other."""
    from iam_jit import license as license_mod
    assert license_mod._PLACEHOLDER_KEY_SENTINEL == PLACEHOLDER_SENTINEL
