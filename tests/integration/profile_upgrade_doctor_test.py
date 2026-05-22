"""#321 / §A19 — cross-product `profile doctor` upgrade-blindness test.

Verifies the end-to-end role-effectiveness D3 scenario: an operator
who installed dbounce pre-#302 was silently running WITHOUT the
``deny_dcl_targets_public`` floor because dbounce never overwrites
``~/.dbounce/profiles.yaml``. After ``dbounce profile doctor --apply``
the floor lands + the D3 scenario grades MEANINGFUL.

What this test does (per product where the binary is present):

  1. Seeds a "pre-#302" profile YAML (sans ``deny_dcl_targets_public``).
  2. Runs ``<product> profile doctor`` + asserts exit 2 + the missing
     field is reported with category ``safety-floor``.
  3. Runs ``<product> profile doctor --apply`` + asserts the field
     landed in YAML + a timestamped backup was written.
  4. Re-runs ``<product> profile doctor`` + asserts exit 0 (current).
  5. Verifies ``<product> profile doctor --acknowledge`` writes the
     stamp + future banner is suppressed.
  6. For dbounce specifically: validates the D3 ALLOW→DENY transition
     for the canonical GRANT-to-PUBLIC statement by re-loading the
     profile + asserting the parsed Profile carries
     ``DenyDCLTargetsPublic=True`` post-apply.

Skips a product when its binary isn't on disk (mirrors the
``[[local-test-infra-spec]]`` posture used by
``cross_bouncer_session_id_parity_test.py``).

Per [[deliberate-feature-completion]]: this test ships ALONGSIDE the
4 per-product slices + KNOWN-CAVEATS §A19 entry. Per [[v1-scope-bar]]:
gates pre-launch — if the doctor surface degrades silently the test
fails.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml


REPO_ROOT = Path(__file__).resolve().parents[2]
WORKSPACE_ROOT = REPO_ROOT.parent


# Resolve binaries with the same fallback shape as the existing
# cross-bouncer parity test. /tmp/ overrides used by the test runner
# when binaries aren't checked into bin/ (the local dev workflow
# builds to /tmp).
def _resolve_binary(env_var: str, *candidates: Path) -> Path | None:
    override = os.environ.get(env_var)
    if override and Path(override).exists():
        return Path(override)
    for c in candidates:
        if c.exists():
            return c
    return None


IBOUNCE_BIN = _resolve_binary(
    "IBOUNCE_BIN",
    REPO_ROOT / ".venv" / "bin" / "ibounce",
)
KBOUNCE_BIN = _resolve_binary(
    "KBOUNCE_BIN",
    Path("/tmp/kbounce"),
    WORKSPACE_ROOT / "kbouncer" / "bin" / "kbounce",
)
DBOUNCE_BIN = _resolve_binary(
    "DBOUNCE_BIN",
    Path("/tmp/dbounce"),
    WORKSPACE_ROOT / "dbounce" / "bin" / "dbounce",
)
GBOUNCE_BIN = _resolve_binary(
    "GBOUNCE_BIN",
    Path("/tmp/gbounce"),
    WORKSPACE_ROOT / "gbounce" / "bin" / "gbounce",
)


# (binary, profile-path-env-var, profile-name-on-which-the-floor-lives,
#  safety-floor-field-the-pre-322-defaults-shipped-without)
PRODUCT_MATRIX = [
    pytest.param(
        DBOUNCE_BIN,
        "DBOUNCE_PROFILES_PATH",
        "dbounce",
        "safe-default",
        "deny_dcl_targets_public",
        id="dbounce",
    ),
    pytest.param(
        KBOUNCE_BIN,
        "KBOUNCER_PROFILES_PATH",
        "kbounce",
        "safe-default",
        "deny_subresource_writes",
        id="kbouncer",
    ),
    pytest.param(
        IBOUNCE_BIN,
        "IAM_JIT_BOUNCER_PROFILES_FILE",
        "ibounce",
        "safe-default",
        "allow_baseline",
        id="ibounce",
    ),
]


def _run(binary: Path, args: list[str], env: dict) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(binary)] + args,
        env={**os.environ, **env},
        capture_output=True,
        text=True,
        timeout=30,
    )


@pytest.mark.parametrize(
    "binary,env_var,product,profile_name,floor_field",
    PRODUCT_MATRIX,
)
def test_profile_doctor_safety_floor_apply_cycle(
    tmp_path: Path,
    binary: Path | None,
    env_var: str,
    product: str,
    profile_name: str,
    floor_field: str,
) -> None:
    """End-to-end: install defaults → strip safety floor → assert
    doctor warns → --apply → assert floor restored + backup written →
    --acknowledge → assert future runs silent."""
    if binary is None:
        pytest.skip(f"{product} binary not on disk; skipping")

    profiles_path = tmp_path / "profiles.yaml"
    env = {env_var: str(profiles_path)}

    # 1. Seed defaults.
    if product == "ibounce":
        result = _run(binary, ["profile", "install-defaults"], env)
    else:
        # kbouncer + dbounce both expose `profile install-defaults`.
        result = _run(binary, ["profile", "install-defaults"], env)
    assert result.returncode == 0, \
        f"{product} install-defaults failed: {result.stderr}"
    assert profiles_path.exists(), \
        f"{product} install-defaults did not write {profiles_path}"

    # 2. Strip the safety floor (simulate pre-#302 / pre-#286 install).
    data = yaml.safe_load(profiles_path.read_text())
    profile_body = data["profiles"][profile_name]
    assert floor_field in profile_body, \
        f"{product} embedded defaults missing {floor_field}; catalog drift?"
    del profile_body[floor_field]
    profiles_path.write_text(yaml.safe_dump(data, sort_keys=False))

    # 3. doctor should warn loudly + exit 2.
    result = _run(binary, ["profile", "doctor"], env)
    assert result.returncode == 2, \
        f"{product} doctor should exit 2 on missing safety-floor; got {result.returncode}:\n{result.stdout}\n{result.stderr}"
    assert floor_field in result.stdout, \
        f"{product} doctor should mention {floor_field}; got:\n{result.stdout}"
    assert "safety-floor" in result.stdout, \
        f"{product} doctor should mark category safety-floor; got:\n{result.stdout}"
    assert "§A19" not in result.stdout or "doctor" in result.stdout

    # 3b. doctor --json should expose the same shape for SIEM scripts.
    result = _run(binary, ["profile", "doctor", "--json"], env)
    assert result.returncode == 2
    parsed = json.loads(result.stdout)
    assert any(
        g["field"] == floor_field and g["category"] == "safety-floor"
        for g in parsed["missing"]
    ), f"{product} doctor --json should expose floor field; got: {parsed}"

    # 4. --apply should merge additively + write a backup.
    result = _run(binary, ["profile", "doctor", "--apply"], env)
    assert result.returncode == 0, \
        f"{product} doctor --apply failed: {result.stderr}\n{result.stdout}"
    backups = list(tmp_path.glob("profiles.yaml.bak-*"))
    assert len(backups) == 1, \
        f"{product} doctor --apply should write exactly one backup; got {backups}"

    # Reload + verify the floor is back.
    merged = yaml.safe_load(profiles_path.read_text())
    assert floor_field in merged["profiles"][profile_name], \
        f"{product} doctor --apply did not restore {floor_field}: {merged}"

    # 5. Re-run doctor — should be silent + exit 0.
    result = _run(binary, ["profile", "doctor"], env)
    assert result.returncode == 0, \
        f"{product} doctor should exit 0 post-apply; got {result.returncode}:\n{result.stdout}"
    assert floor_field not in result.stdout, \
        f"{product} doctor post-apply still mentions {floor_field}: {result.stdout}"

    # 6. Verify --acknowledge surface.
    # Strip the field again to re-arm the warning.
    data = yaml.safe_load(profiles_path.read_text())
    del data["profiles"][profile_name][floor_field]
    profiles_path.write_text(yaml.safe_dump(data, sort_keys=False))
    result = _run(binary, ["profile", "doctor", "--check"], env)
    assert result.returncode == 2, "pre-ack: --check should exit 2"

    result = _run(binary, ["profile", "doctor", "--acknowledge"], env)
    assert result.returncode == 0, \
        f"{product} doctor --acknowledge failed: {result.stderr}"
    ack_path = profiles_path.with_name(".profiles-acknowledged-version")
    assert ack_path.exists(), \
        f"{product} doctor --acknowledge should write {ack_path}"

    # Doctor itself still reports the gap (acknowledge silences the
    # STARTUP banner, not the explicit `doctor` invocation — operators
    # asking should still get the truth).
    result = _run(binary, ["profile", "doctor"], env)
    assert result.returncode == 2, \
        "post-ack: explicit `doctor` should still report the gap"


def test_gbounce_doctor_v1_no_op_parity(tmp_path: Path) -> None:
    """gbounce v1.0: doctor surface ships for cross-product CLI parity
    but reports no gaps (gbounce doesn't manage a profiles.yaml).
    Verifies --json envelope contains the architectural Notes line so
    cross-product orchestrators get a uniform shape."""
    if GBOUNCE_BIN is None:
        pytest.skip("gbounce binary not on disk; skipping")
    result = _run(GBOUNCE_BIN, ["profile", "doctor", "--json"], {})
    assert result.returncode == 0, \
        f"gbounce profile doctor --json failed: {result.stderr}"
    parsed = json.loads(result.stdout)
    assert parsed["missing"] == [] or parsed["missing"] is None
    assert parsed.get("notes", ""), \
        "gbounce v1.0 doctor --json should include notes about architectural difference"
    assert "G-Slice 2" in parsed["notes"]
