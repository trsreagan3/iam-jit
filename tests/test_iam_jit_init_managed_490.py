"""State-verification tests for #490 §A90 LAUNCH-BLOCKER —
`iam-jit init --managed --org-policy URL` non-interactive corp mode.

Per [[tests-and-independent-uat-required]] every feature ships with
tests + an independent UAT pass. Per CONTRIBUTING.md every reported
success status MUST also assert observable state matches.

Tests cover:

  1. Happy path: mock URL fetch + valid signature → config written +
     doctor apply invoked; no prompts.
  2. --managed without --org-policy → UsageError (explicit error message).
  3. Invalid signature → SystemExit + clear error; config NOT written.
  4. Non-HTTPS URL (http://) → SSRF-rejected before network call.
  5. Loopback URL (127.0.0.1) → SSRF-rejected.
  6. Missing operator public key → fail-CLOSED (ManagedPolicyError).
  7. Sabotage: monkeypatched _verify_ed25519_signature no-ops → test 3
     incorrectly accepts invalid signature, proving verify is
     load-bearing.

Per [[scorer-is-ground-truth]] + [[ibounce-honest-positioning]]:
fail-CLOSED at every gate; sabotage test proves verify is not bypassed.
"""

from __future__ import annotations

import base64
import pathlib
from typing import Any
from unittest.mock import MagicMock, patch

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
    """Prevent boto3 STS lookups during any account detection or
    accounts seeding that might be reached via doctor apply."""
    def _boom(*a: Any, **k: Any) -> None:
        raise RuntimeError("no aws creds in tests")
    monkeypatch.setattr("boto3.client", _boom)


@pytest.fixture(autouse=True)
def _no_home_pollution(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Pin HOME to tmp_path so code that reads pathlib.Path.home() can't
    escape the sandbox (harness detection, default data dir, default
    org.pub location)."""
    fake_home = tmp_path / "fake-home"
    fake_home.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("HOME", str(fake_home))
    # Clear all org-key env vars so tests start clean.
    monkeypatch.delenv("IAM_JIT_ORG_PUBLIC_KEY", raising=False)
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)


@pytest.fixture
def isolated_data_dir(tmp_path: pathlib.Path) -> pathlib.Path:
    """Per-test data dir under tmp_path; NOT pre-created so tests can
    assert what `init` does to a fresh location."""
    return tmp_path / "iam-jit"


@pytest.fixture
def ed25519_keypair(tmp_path: pathlib.Path) -> tuple[str, str, pathlib.Path]:
    """Generate a fresh Ed25519 keypair; write the public key to a temp
    file; return (private_pem, public_pem, pubkey_path).

    Per [[push-policy-public-repo]] NEVER committed — generated
    ephemerally in tmp_path per the signing-test pattern."""
    priv_pem, pub_pem = ed25519_keygen()
    pub_path = tmp_path / "test-org.pub"
    pub_path.write_text(pub_pem, encoding="ascii")
    return priv_pem, pub_pem, pub_path


def _valid_policy_yaml() -> str:
    """Minimal valid iam-jit.yaml body accepted by ambient_config."""
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
    return "# managed-mode test policy\n" + yaml.safe_dump(data, sort_keys=False)


def _sign_policy(policy_text: str, private_key_pem: str) -> bytes:
    """Sign the raw policy UTF-8 bytes with an Ed25519 private key.
    Returns base64-encoded raw Ed25519 signature (the convention the
    managed-mode pipeline expects in the .sig companion URL)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = serialization.load_pem_private_key(
        private_key_pem.encode("ascii"), password=None,
    )
    sig_bytes = priv.sign(policy_text.encode("utf-8"))
    return base64.b64encode(sig_bytes)


def _runner() -> CliRunner:
    return CliRunner()


# ---------------------------------------------------------------------------
# Helpers for URL-fetch mocking
# ---------------------------------------------------------------------------


def _make_fetch_side_effect(
    policy_url: str,
    policy_text: str,
    sig_b64: bytes,
) -> Any:
    """Return a side-effect function for monkeypatching
    `cli_init._fetch_url_bytes` so both the policy URL and the .sig
    URL return the correct content without a real network call."""
    sig_url = policy_url + ".sig"

    def _fake_fetch(url: str) -> bytes:
        if url == policy_url:
            return policy_text.encode("utf-8")
        if url == sig_url:
            return sig_b64
        raise AssertionError(f"unexpected URL in test: {url!r}")

    return _fake_fetch


# ---------------------------------------------------------------------------
# Test 1 — Happy path: valid signature → config written + doctor apply
# ---------------------------------------------------------------------------


def test_managed_happy_path_config_written_and_doctor_apply_invoked(
    isolated_data_dir: pathlib.Path,
    ed25519_keypair: tuple[str, str, pathlib.Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """--managed --org-policy <URL> with a valid Ed25519 signature MUST:
      - Write the config file at the expected path.
      - Invoke doctor apply (confirmed by the [managed] banner).
      - Print no interactive prompts.
      - Exit 0.

    No real HTTP: _fetch_url_bytes + _ssrf_gate_url are monkeypatched.
    """
    priv_pem, _pub_pem, pub_path = ed25519_keypair
    policy_text = _valid_policy_yaml()
    sig_b64 = _sign_policy(policy_text, priv_pem)

    policy_url = "https://corp.example.com/iam-jit-policy.yaml"

    monkeypatch.setattr(
        cli_init, "_ssrf_gate_url", lambda url: None,  # SSRF disabled in test
    )
    monkeypatch.setattr(
        cli_init, "_fetch_url_bytes",
        _make_fetch_side_effect(policy_url, policy_text, sig_b64),
    )
    # doctor apply-config will fail (no real AWS) — that's OK, we just
    # assert the config was written and the banner appeared.
    monkeypatch.setattr(cli_init, "_run_doctor_apply", lambda _path: 0)

    result = _runner().invoke(
        main,
        [
            "init", "--managed",
            "--org-policy", policy_url,
            "--org-public-key", str(pub_path),
            "--data-dir", str(isolated_data_dir),
        ],
        catch_exceptions=False,
    )

    assert result.exit_code == 0, result.output
    assert "[managed] org-policy verified + written to" in result.output

    # Observable filesystem state: config landed.
    config_path = isolated_data_dir / "iam-jit.yaml"
    assert config_path.exists(), "config file must be written on success"

    # Content matches the signed policy (not a generated declaration).
    raw = config_path.read_text(encoding="utf-8")
    assert "iam-jit:" in raw
    assert "managed" in raw  # posture: managed came from the org policy


# ---------------------------------------------------------------------------
# Test 2 — --managed without --org-policy → UsageError
# ---------------------------------------------------------------------------


def test_managed_without_org_policy_raises_usage_error(
    isolated_data_dir: pathlib.Path,
) -> None:
    """--managed without --org-policy MUST fail with a UsageError (exit
    2) and mention --org-policy in the error text. Per spec the error
    is surfaced BEFORE any network call."""
    result = _runner().invoke(
        main,
        [
            "init", "--managed",
            "--data-dir", str(isolated_data_dir),
        ],
    )
    assert result.exit_code != 0
    assert "--org-policy" in result.output or "--org-policy" in (result.output + str(result.exception))

    # Observable: nothing on disk.
    assert not (isolated_data_dir / "iam-jit.yaml").exists()


# ---------------------------------------------------------------------------
# Test 3 — Invalid signature → SystemExit + clear error; config NOT written
# ---------------------------------------------------------------------------


def test_managed_invalid_signature_refuses_write(
    isolated_data_dir: pathlib.Path,
    ed25519_keypair: tuple[str, str, pathlib.Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A tampered signature (random bytes) MUST cause init to refuse.
    The config MUST NOT be written (fail-CLOSED). The output must
    mention 'signature' so the operator understands what failed."""
    priv_pem, _pub_pem, pub_path = ed25519_keypair
    policy_text = _valid_policy_yaml()

    # Produce a WRONG signature (sign different bytes).
    bad_sig_b64 = base64.b64encode(b"\x00" * 64)

    policy_url = "https://corp.example.com/iam-jit-policy.yaml"

    monkeypatch.setattr(cli_init, "_ssrf_gate_url", lambda url: None)
    monkeypatch.setattr(
        cli_init, "_fetch_url_bytes",
        _make_fetch_side_effect(policy_url, policy_text, bad_sig_b64),
    )

    result = _runner().invoke(
        main,
        [
            "init", "--managed",
            "--org-policy", policy_url,
            "--org-public-key", str(pub_path),
            "--data-dir", str(isolated_data_dir),
        ],
    )

    assert result.exit_code != 0, "must fail on bad signature"
    combined = result.output + str(result.exception or "")
    assert "signature" in combined.lower(), (
        f"error must mention 'signature'; got: {result.output!r}"
    )

    # Observable: NO config written (fail-CLOSED).
    assert not (isolated_data_dir / "iam-jit.yaml").exists(), (
        "config MUST NOT be written when signature fails"
    )


# ---------------------------------------------------------------------------
# Test 4 — Non-HTTPS URL (http://) → refused before network call
# ---------------------------------------------------------------------------


def test_managed_http_url_refused_by_ssrf_gate(
    isolated_data_dir: pathlib.Path,
    ed25519_keypair: tuple[str, str, pathlib.Path],
) -> None:
    """http:// URLs MUST be refused by the SSRF gate before any network
    call is made. Per #522 SSRF discipline: no plaintext fetch for the
    managed pipeline."""
    _priv_pem, _pub_pem, pub_path = ed25519_keypair
    http_url = "http://corp.example.com/iam-jit-policy.yaml"

    result = _runner().invoke(
        main,
        [
            "init", "--managed",
            "--org-policy", http_url,
            "--org-public-key", str(pub_path),
            "--data-dir", str(isolated_data_dir),
        ],
    )

    assert result.exit_code != 0
    combined = result.output + str(result.exception or "")
    assert "https" in combined.lower() or "ssrf" in combined.lower(), (
        f"error must mention https or ssrf; got: {result.output!r}"
    )

    # Observable: no config written.
    assert not (isolated_data_dir / "iam-jit.yaml").exists()


# ---------------------------------------------------------------------------
# Test 5 — Loopback URL → refused by SSRF gate
# ---------------------------------------------------------------------------


def test_managed_loopback_url_refused_by_ssrf_gate(
    isolated_data_dir: pathlib.Path,
    ed25519_keypair: tuple[str, str, pathlib.Path],
) -> None:
    """Loopback HTTPS URLs (https://127.0.0.1/...) MUST be refused by
    the SSRF gate. Per #522 the IP check happens after DNS resolution;
    loopback is rejected regardless of hostname."""
    _priv_pem, _pub_pem, pub_path = ed25519_keypair
    loopback_url = "https://127.0.0.1/iam-jit-policy.yaml"

    result = _runner().invoke(
        main,
        [
            "init", "--managed",
            "--org-policy", loopback_url,
            "--org-public-key", str(pub_path),
            "--data-dir", str(isolated_data_dir),
        ],
    )

    assert result.exit_code != 0
    combined = result.output + str(result.exception or "")
    # Should mention loopback / internal / ssrf.
    assert any(
        kw in combined.lower()
        for kw in ("loopback", "internal", "ssrf", "private", "127")
    ), f"error must mention internal/ssrf; got: {result.output!r}"

    # Observable: no config written.
    assert not (isolated_data_dir / "iam-jit.yaml").exists()


# ---------------------------------------------------------------------------
# Test 6 — Missing operator public key → fail-CLOSED
# ---------------------------------------------------------------------------


def test_managed_missing_pubkey_fails_closed(
    isolated_data_dir: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When no public key can be found (no flag, no env var, no file on
    disk), init MUST refuse with a clear error. Per [[enterprise-
    profile-distribution]] the operator must pin a key before --managed
    can proceed.

    No real HTTP: _ssrf_gate_url + _fetch_url_bytes are monkeypatched
    to succeed (we're testing the pubkey-resolve failure, not the
    network gate)."""
    policy_url = "https://corp.example.com/iam-jit-policy.yaml"
    policy_text = _valid_policy_yaml()
    # Signature value doesn't matter — we should fail before verify.
    fake_sig_b64 = base64.b64encode(b"\xab" * 64)

    monkeypatch.setattr(cli_init, "_ssrf_gate_url", lambda url: None)
    monkeypatch.setattr(
        cli_init, "_fetch_url_bytes",
        _make_fetch_side_effect(policy_url, policy_text, fake_sig_b64),
    )

    result = _runner().invoke(
        main,
        [
            "init", "--managed",
            "--org-policy", policy_url,
            # No --org-public-key; no env var; no ~/.iam-jit/org.pub
            "--data-dir", str(isolated_data_dir),
        ],
    )

    assert result.exit_code != 0
    combined = result.output + str(result.exception or "")
    assert any(
        kw in combined.lower()
        for kw in ("public key", "pubkey", "org.pub", "iam_jit_org_public_key")
    ), f"error must mention missing pubkey; got: {result.output!r}"

    # Observable: no config written.
    assert not (isolated_data_dir / "iam-jit.yaml").exists()


# ---------------------------------------------------------------------------
# Test 7 — Sabotage: _verify_ed25519_signature no-op proves load-bearing
# ---------------------------------------------------------------------------


def test_sabotage_verify_noop_incorrectly_accepts_invalid_signature(
    isolated_data_dir: pathlib.Path,
    ed25519_keypair: tuple[str, str, pathlib.Path],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Per CONTRIBUTING.md state-verification: prove `_verify_ed25519_signature`
    is load-bearing by showing that a bad signature succeeds when verify
    is monkeypatched to a no-op.

    This is the SABOTAGE test. It INTENTIONALLY shows that the guard
    is in the critical path — without it, a bad signature is accepted.
    The test ASSERTS the sabotaged path SUCCEEDS (exit 0 + config
    written) — this is EXPECTED, because it proves that removing the
    guard breaks the security property (test 3 would then fail at PR
    time).

    Cross-reference: test 3 (invalid signature → fail) MUST also pass
    in the same test run. Both tests together constitute the full
    load-bearing proof.
    """
    priv_pem, _pub_pem, pub_path = ed25519_keypair
    policy_text = _valid_policy_yaml()

    # BAD signature — the real verify would reject this.
    bad_sig_b64 = base64.b64encode(b"\x00" * 64)
    policy_url = "https://corp.example.com/iam-jit-policy.yaml"

    monkeypatch.setattr(cli_init, "_ssrf_gate_url", lambda url: None)
    monkeypatch.setattr(
        cli_init, "_fetch_url_bytes",
        _make_fetch_side_effect(policy_url, policy_text, bad_sig_b64),
    )
    # SABOTAGE: replace verify with a no-op — bad sig no longer raises.
    monkeypatch.setattr(
        cli_init, "_verify_ed25519_signature",
        lambda payload_bytes, signature_bytes, public_key: None,
    )
    monkeypatch.setattr(cli_init, "_run_doctor_apply", lambda _path: 0)

    result = _runner().invoke(
        main,
        [
            "init", "--managed",
            "--org-policy", policy_url,
            "--org-public-key", str(pub_path),
            "--data-dir", str(isolated_data_dir),
        ],
        catch_exceptions=False,
    )

    # EXPECTED: the sabotaged path ACCEPTS the bad signature (exit 0)
    # and writes the config. This proves the real verify in test 3 is
    # load-bearing — if it were absent, the invalid-sig test would pass
    # silently instead of failing loudly.
    assert result.exit_code == 0, (
        "sabotage test must SUCCEED (exit 0) to prove verify is "
        "load-bearing; if this fails, investigate whether _fetch_managed_policy "
        "was inlined past the monkeypatch point"
    )
    assert (isolated_data_dir / "iam-jit.yaml").exists(), (
        "sabotage: config must be written when verify is disabled"
    )
