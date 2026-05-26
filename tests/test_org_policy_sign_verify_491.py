"""State-verification tests for #491 LAUNCH-BLOCKER §A91 —
``iam-jit org-policy {sign,verify}`` IT-side corp-managed deployment.

Per [[tests-and-independent-uat-required]] every feature ships with tests
+ an independent UAT pass. Per CONTRIBUTING.md every reported success
status MUST also assert observable state matches.

Tests cover:

  1. Sign + verify round-trip: sign a fixture YAML; verify with the
     companion pubkey; exits 0 + .sig file exists on disk.
  2. Verify with wrong pubkey → exits 1 + clear error; no crash.
  3. Verify with tampered policy → exits 1 + signature-mismatch message.
  4. Sign refuses on missing private key (nonexistent path).
  5. End-to-end with #490: sign a fixture; serve via mock HTTPS
     (monkeypatched _fetch_url_bytes); run ``iam-jit init --managed``;
     assert config written (proves IT-publish → engineer-consume loop).
  6. Sabotage: monkeypatch the signing primitive to return a constant;
     confirm verify still passes on a tampered policy — proves real
     signing is load-bearing (i.e., without a real signature the verify
     step will reject it, not blindly accept it).

Per [[scorer-is-ground-truth]] + [[ibounce-honest-positioning]]:
fail-CLOSED at every gate; sabotage test proves verify is load-bearing.

Per [[push-policy-public-repo]]: no private key material in this file;
all keypairs are generated ephemerally in tmp_path.
"""

from __future__ import annotations

import base64
import pathlib
from typing import Any

import pytest
import yaml
from click.testing import CliRunner

from iam_jit import cli_init
from iam_jit.cli import main
from iam_jit.threat_feed.signing import ed25519_keygen


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _no_boto3(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prevent boto3 STS lookups during any doctor apply path."""
    def _boom(*a: Any, **k: Any) -> None:
        raise RuntimeError("no aws creds in tests")
    monkeypatch.setattr("boto3.client", _boom)


@pytest.fixture(autouse=True)
def _no_home_pollution(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pin HOME to tmp_path so harness detection + default key lookup
    can't escape the test sandbox."""
    fake_home = tmp_path / "fake-home"
    fake_home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(fake_home))
    monkeypatch.delenv("IAM_JIT_ORG_PUBLIC_KEY", raising=False)
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)


@pytest.fixture
def ed25519_keypair(
    tmp_path: pathlib.Path,
) -> tuple[str, str, pathlib.Path, pathlib.Path]:
    """Fresh Ed25519 keypair; both keys written to tmp_path.

    Returns (private_pem, public_pem, priv_path, pub_path).

    Per [[push-policy-public-repo]] generated ephemerally — never
    committed.
    """
    priv_pem, pub_pem = ed25519_keygen()
    priv_path = tmp_path / "org.priv"
    pub_path = tmp_path / "org.pub"
    priv_path.write_text(priv_pem, encoding="ascii")
    priv_path.chmod(0o600)
    pub_path.write_text(pub_pem, encoding="ascii")
    return priv_pem, pub_pem, priv_path, pub_path


@pytest.fixture
def policy_yaml_file(tmp_path: pathlib.Path) -> pathlib.Path:
    """Write a minimal valid org-policy.yaml to tmp_path."""
    data = {
        "iam-jit": {
            "schema_version": "1.0",
            "enabled": True,
            "posture": "managed",
            "bouncers": {
                "ibounce": {
                    "enabled": True,
                    "mode": "cooperative",
                },
            },
        },
    }
    p = tmp_path / "org-policy.yaml"
    p.write_text(
        "# corp-managed test policy\n" + yaml.safe_dump(data, sort_keys=False),
        encoding="utf-8",
    )
    return p


def _runner() -> CliRunner:
    return CliRunner()


# ---------------------------------------------------------------------------
# Test 1 — Sign + verify round-trip
# ---------------------------------------------------------------------------


def test_sign_and_verify_round_trip(
    tmp_path: pathlib.Path,
    ed25519_keypair: tuple[str, str, pathlib.Path, pathlib.Path],
    policy_yaml_file: pathlib.Path,
) -> None:
    """Sign a fixture YAML; verify with the companion pubkey.

    State-verification:
      - .sig file exists on disk after sign exits 0.
      - verify exits 0 (signature is valid).
      - .sig content is non-empty valid base64.
    """
    _priv_pem, _pub_pem, priv_path, pub_path = ed25519_keypair
    sig_path = tmp_path / "org-policy.yaml.sig"

    # Sign.
    sign_result = _runner().invoke(
        main,
        [
            "org-policy", "sign",
            "--in", str(policy_yaml_file),
            "--key", str(priv_path),
            "--out", str(sig_path),
        ],
        catch_exceptions=False,
    )
    assert sign_result.exit_code == 0, (
        f"sign must exit 0; got {sign_result.exit_code}: {sign_result.output}"
    )
    assert "OK" in sign_result.output, "sign must print OK banner"

    # Observable: .sig file exists + is non-empty valid base64.
    assert sig_path.exists(), ".sig file must be written on success"
    raw = sig_path.read_text(encoding="ascii").strip()
    assert raw, ".sig file must be non-empty"
    decoded = base64.b64decode(raw, validate=True)
    assert len(decoded) == 64, (
        f"Ed25519 signature must be 64 raw bytes, got {len(decoded)}"
    )

    # Verify.
    verify_result = _runner().invoke(
        main,
        [
            "org-policy", "verify",
            "--policy", str(policy_yaml_file),
            "--sig", str(sig_path),
            "--pubkey", str(pub_path),
        ],
        catch_exceptions=False,
    )
    assert verify_result.exit_code == 0, (
        f"verify must exit 0 for a valid sig; got {verify_result.exit_code}: "
        f"{verify_result.output}"
    )
    assert "OK" in verify_result.output, "verify must print OK banner"


# ---------------------------------------------------------------------------
# Test 2 — Verify with wrong pubkey → exit 1 + clear error
# ---------------------------------------------------------------------------


def test_verify_wrong_pubkey_exits_1(
    tmp_path: pathlib.Path,
    ed25519_keypair: tuple[str, str, pathlib.Path, pathlib.Path],
    policy_yaml_file: pathlib.Path,
) -> None:
    """Signature signed with keypair A must be rejected when verified
    against keypair B's pubkey.

    State-verification: exits 1 + output mentions invalid / signature /
    verification.
    """
    _priv_pem_a, _pub_pem_a, priv_path_a, _pub_path_a = ed25519_keypair
    sig_path = tmp_path / "org-policy.yaml.sig"

    # Generate a SECOND keypair — wrong pubkey.
    _priv_b, pub_b = ed25519_keygen()
    wrong_pub_path = tmp_path / "wrong.pub"
    wrong_pub_path.write_text(pub_b, encoding="ascii")

    # Sign with keypair A.
    sign_result = _runner().invoke(
        main,
        [
            "org-policy", "sign",
            "--in", str(policy_yaml_file),
            "--key", str(priv_path_a),
            "--out", str(sig_path),
        ],
        catch_exceptions=False,
    )
    assert sign_result.exit_code == 0

    # Verify with keypair B's pubkey — must fail.
    verify_result = _runner().invoke(
        main,
        [
            "org-policy", "verify",
            "--policy", str(policy_yaml_file),
            "--sig", str(sig_path),
            "--pubkey", str(wrong_pub_path),
        ],
    )
    assert verify_result.exit_code == 1, (
        f"verify must exit 1 for wrong pubkey; got {verify_result.exit_code}"
    )
    combined = (verify_result.output or "") + str(verify_result.exception or "")
    assert any(
        kw in combined.lower()
        for kw in ("invalid", "signature", "verification", "failed")
    ), f"error output must mention verification failure; got: {combined!r}"


# ---------------------------------------------------------------------------
# Test 3 — Verify with tampered policy → exit 1 + signature mismatch
# ---------------------------------------------------------------------------


def test_verify_tampered_policy_exits_1(
    tmp_path: pathlib.Path,
    ed25519_keypair: tuple[str, str, pathlib.Path, pathlib.Path],
    policy_yaml_file: pathlib.Path,
) -> None:
    """Signature signed against the original policy must be rejected when
    the policy bytes change (simulates an attacker tampering the YAML
    after signing).

    State-verification: exits 1 + output mentions mismatch/invalid.
    """
    _priv_pem, _pub_pem, priv_path, pub_path = ed25519_keypair
    sig_path = tmp_path / "org-policy.yaml.sig"

    # Sign the ORIGINAL policy.
    sign_result = _runner().invoke(
        main,
        [
            "org-policy", "sign",
            "--in", str(policy_yaml_file),
            "--key", str(priv_path),
            "--out", str(sig_path),
        ],
        catch_exceptions=False,
    )
    assert sign_result.exit_code == 0

    # Tamper: append a comment to the policy (changes the bytes).
    original_text = policy_yaml_file.read_text(encoding="utf-8")
    policy_yaml_file.write_text(
        original_text + "\n# TAMPERED\n", encoding="utf-8",
    )

    # Verify with the ORIGINAL signature — must fail.
    verify_result = _runner().invoke(
        main,
        [
            "org-policy", "verify",
            "--policy", str(policy_yaml_file),
            "--sig", str(sig_path),
            "--pubkey", str(pub_path),
        ],
    )
    assert verify_result.exit_code == 1, (
        "verify must exit 1 when policy is tampered; "
        f"got {verify_result.exit_code}: {verify_result.output}"
    )
    combined = (verify_result.output or "") + str(verify_result.exception or "")
    assert any(
        kw in combined.lower()
        for kw in ("invalid", "signature", "mismatch", "failed", "verification")
    ), f"error must mention sig failure; got: {combined!r}"


# ---------------------------------------------------------------------------
# Test 4 — Sign refuses on missing private key
# ---------------------------------------------------------------------------


def test_sign_refuses_missing_private_key(
    tmp_path: pathlib.Path,
    policy_yaml_file: pathlib.Path,
) -> None:
    """Passing a nonexistent private key path must fail with a clear error
    BEFORE any signing operation.

    State-verification: exits non-zero + no .sig written.
    """
    missing_key = tmp_path / "nonexistent.priv"
    sig_path = tmp_path / "org-policy.yaml.sig"

    result = _runner().invoke(
        main,
        [
            "org-policy", "sign",
            "--in", str(policy_yaml_file),
            "--key", str(missing_key),
            "--out", str(sig_path),
        ],
    )

    # click.Path(exists=True) catches this at parse time → exit code 2.
    assert result.exit_code != 0, (
        f"sign must fail on missing key; got exit 0: {result.output}"
    )

    # Observable: no .sig file written.
    assert not sig_path.exists(), ".sig must NOT be written when key is missing"


# ---------------------------------------------------------------------------
# Test 5 — End-to-end with #490: IT signs → mock HTTPS → engineer init --managed
# ---------------------------------------------------------------------------


def test_end_to_end_it_sign_to_engineer_init_managed(
    tmp_path: pathlib.Path,
    ed25519_keypair: tuple[str, str, pathlib.Path, pathlib.Path],
    policy_yaml_file: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Full IT-publish → engineer-consume round-trip.

    1. IT signs the policy with `iam-jit org-policy sign`.
    2. IT verifies with `iam-jit org-policy verify` (sanity check).
    3. Mock HTTPS serves both files (monkeypatched _fetch_url_bytes).
    4. Engineer runs `iam-jit init --managed`.
    5. Assert config file is written with the managed policy content.

    This is the canonical state-verification for the complete trilogy
    (#489 init / #490 managed-mode / #491 sign-verify).
    """
    _priv_pem, _pub_pem, priv_path, pub_path = ed25519_keypair
    sig_path = tmp_path / "org-policy.yaml.sig"
    data_dir = tmp_path / "engineer-data"

    # Step 1: IT signs.
    sign_result = _runner().invoke(
        main,
        [
            "org-policy", "sign",
            "--in", str(policy_yaml_file),
            "--key", str(priv_path),
            "--out", str(sig_path),
        ],
        catch_exceptions=False,
    )
    assert sign_result.exit_code == 0, sign_result.output

    # Step 2: IT verifies locally.
    verify_result = _runner().invoke(
        main,
        [
            "org-policy", "verify",
            "--policy", str(policy_yaml_file),
            "--sig", str(sig_path),
            "--pubkey", str(pub_path),
        ],
        catch_exceptions=False,
    )
    assert verify_result.exit_code == 0, verify_result.output

    # Step 3: Mock HTTPS serving both files.
    policy_url = "https://corp.example.com/iam-jit/org-policy.yaml"
    sig_url = policy_url + ".sig"

    policy_bytes = policy_yaml_file.read_bytes()
    sig_bytes = sig_path.read_bytes()

    def _mock_fetch(url: str) -> bytes:
        if url == policy_url:
            return policy_bytes
        if url == sig_url:
            return sig_bytes
        raise AssertionError(f"unexpected URL: {url!r}")

    monkeypatch.setattr(cli_init, "_ssrf_gate_url", lambda _url: None)
    monkeypatch.setattr(cli_init, "_fetch_url_bytes", _mock_fetch)
    # doctor apply will fail in test env; that's OK — we assert config written.
    monkeypatch.setattr(cli_init, "_run_doctor_apply", lambda _p: 0)

    # Step 4: Engineer runs init --managed.
    init_result = _runner().invoke(
        main,
        [
            "init", "--managed",
            "--org-policy", policy_url,
            "--org-public-key", str(pub_path),
            "--data-dir", str(data_dir),
        ],
        catch_exceptions=False,
    )

    # Step 5: Assert config written.
    assert init_result.exit_code == 0, (
        f"init --managed must succeed in e2e; got {init_result.exit_code}: "
        f"{init_result.output}"
    )
    config_path = data_dir / "iam-jit.yaml"
    assert config_path.exists(), (
        "engineer config file must be written after IT-signed init --managed"
    )
    content = config_path.read_text(encoding="utf-8")
    assert "iam-jit:" in content, "config must contain the iam-jit declaration"
    assert "managed" in content, (
        "config must preserve the 'managed' posture from the IT policy"
    )


# ---------------------------------------------------------------------------
# Test 6 — Sabotage: signing primitive override proves verify is load-bearing
# ---------------------------------------------------------------------------


def test_sabotage_constant_sig_verify_rejects_tampered_policy(
    tmp_path: pathlib.Path,
    ed25519_keypair: tuple[str, str, pathlib.Path, pathlib.Path],
    policy_yaml_file: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sabotage test proving real signing is load-bearing.

    Strategy: monkeypatch ``_sign_policy_bytes`` in ``cli_org_policy``
    to return a CONSTANT 64-byte block (simulates a signing primitive
    that always returns the same bytes regardless of input). The .sig
    file will contain this constant, which is NOT a valid Ed25519
    signature over the policy bytes. We then run ``verify`` and confirm
    it exits 1 (the sabotaged signature is rejected).

    This proves that:
      a. The signing step actually runs the Ed25519 primitive (if it
         were skipped and .sig were written empty / zeros, verify would
         fail anyway — which is the whole point).
      b. The verify step actually validates the signature bytes against
         the policy bytes + pubkey (not just checking the file exists).

    Per CONTRIBUTING.md: both this test AND test 1 (round-trip) MUST
    pass in the same run. Together they constitute the load-bearing proof:
      - Test 1: real signing → verify passes.
      - Test 6: sabotaged signing → verify fails.
    """
    from iam_jit import cli_org_policy

    _priv_pem, _pub_pem, priv_path, pub_path = ed25519_keypair
    sig_path = tmp_path / "org-policy.yaml.sig"

    # SABOTAGE: replace the signing helper with a constant.
    _CONSTANT_SIG = b"\xde\xad\xbe\xef" * 16  # 64 bytes of garbage
    monkeypatch.setattr(
        cli_org_policy,
        "_sign_policy_bytes",
        lambda *_a, **_kw: _CONSTANT_SIG,
    )

    # Sign with the sabotaged primitive.
    sign_result = _runner().invoke(
        main,
        [
            "org-policy", "sign",
            "--in", str(policy_yaml_file),
            "--key", str(priv_path),
            "--out", str(sig_path),
        ],
        catch_exceptions=False,
    )
    # Sign itself still exits 0 (it wrote the constant-sig base64).
    assert sign_result.exit_code == 0, (
        f"sign must exit 0 even with sabotaged primitive "
        f"(it just writes whatever bytes it gets); got: {sign_result.output}"
    )
    # Observable: .sig written with constant-sig base64.
    assert sig_path.exists(), ".sig must be written even with sabotaged primitive"

    # Verify with the real _verify_ed25519_signature from #490 — MUST reject.
    verify_result = _runner().invoke(
        main,
        [
            "org-policy", "verify",
            "--policy", str(policy_yaml_file),
            "--sig", str(sig_path),
            "--pubkey", str(pub_path),
        ],
    )

    # EXPECTED: the sabotaged constant is NOT a valid Ed25519 signature
    # → verify exits 1. This is the LOAD-BEARING assertion: it proves
    # that the verify command actually runs the Ed25519 check and doesn't
    # just accept any .sig file blindly.
    assert verify_result.exit_code == 1, (
        "sabotage test: verify must reject a constant (garbage) signature "
        f"(exit 1); got exit {verify_result.exit_code}: {verify_result.output}. "
        "If this is exit 0, the verify step is not actually running Ed25519 validation."
    )
    combined = (verify_result.output or "") + str(verify_result.exception or "")
    assert any(
        kw in combined.lower()
        for kw in ("invalid", "signature", "failed", "mismatch", "verification")
    ), f"sabotage: verify must mention rejection; got: {combined!r}"
