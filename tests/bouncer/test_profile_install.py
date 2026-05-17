"""Tests for `iam-jit-bouncer profile install --from URL` (#4).

Mocks HTTPS fetch via urllib.request.urlopen so tests are hermetic
(no real network). Covers:
- happy path: HTTPS URL → profiles installed with source = URL
- http:// URL is refused
- sha256 mismatch refuses install
- malformed YAML refused
- profile validation errors fail BEFORE writing anything (no partial install)
- conflict + no --force is refused; --force overwrites
- source field is forced to the URL even if payload says source: local
- read-only invariant: an installed profile shows source = URL
"""

from __future__ import annotations

import hashlib
import io
from contextlib import contextmanager
from unittest import mock

import pytest
import yaml
from click.testing import CliRunner

from iam_jit.bouncer.profiles import load_profiles
from iam_jit.bouncer_cli import main


@contextmanager
def _mock_https(payload: bytes, *, status: int = 200):
    """Patch urllib.request.urlopen to return `payload` for any URL."""
    class _Resp:
        def __init__(self, b: bytes) -> None:
            self._b = b
        def read(self) -> bytes:
            return self._b
        def __enter__(self):
            return self
        def __exit__(self, *a):
            return False

    with mock.patch(
        "iam_jit.bouncer_cli.urllib.request.urlopen",
        return_value=_Resp(payload),
        create=False,
    ):
        yield


def _invoke(args, env):
    runner = CliRunner()
    return runner.invoke(main, args, env=env, catch_exceptions=False)


@pytest.fixture()
def profiles_path(tmp_path, monkeypatch):
    """Isolate profiles.yaml per test."""
    p = tmp_path / "profiles.yaml"
    monkeypatch.setenv("IAM_JIT_BOUNCER_PROFILES_FILE", str(p))
    return p


def test_happy_path_installs_profiles(profiles_path) -> None:
    payload = yaml.safe_dump({
        "profiles": {
            "acme-staging": {
                "description": "Acme's staging guardrail",
                "deny_keywords": ["prod"],
            },
            "acme-readonly": {
                "description": "no writes",
                "deny_verbs": ["*:Delete*", "*:Put*"],
            },
        },
    }).encode("utf-8")
    url = "https://internal.acme.com/iam-jit-profiles/bundle.yaml"
    # urllib.request is imported lazily inside profile_install_cmd, so
    # we need to patch where it's USED (in the module), which means
    # patching the bouncer_cli module's imported reference.
    with mock.patch("urllib.request.urlopen") as m:
        m.return_value.__enter__.return_value.read.return_value = payload
        result = _invoke(
            ["profile", "install", "--from", url],
            env={"IAM_JIT_BOUNCER_PROFILES_FILE": str(profiles_path)},
        )
    assert result.exit_code == 0, result.output
    assert "installed 2 profile(s)" in result.output
    assert "acme-staging" in result.output

    profs = load_profiles()
    assert "acme-staging" in profs
    assert profs["acme-staging"].source == url
    assert profs["acme-staging"].deny_keywords == ("prod",)
    assert "acme-readonly" in profs
    assert profs["acme-readonly"].source == url


def test_http_url_refused(profiles_path) -> None:
    result = _invoke(
        ["profile", "install", "--from", "http://example.com/p.yaml"],
        env={"IAM_JIT_BOUNCER_PROFILES_FILE": str(profiles_path)},
    )
    assert result.exit_code == 2
    assert "https://" in result.output or "https://" in (result.stderr or "")
    # No profiles file created
    assert not profiles_path.exists()


def test_sha256_mismatch_refuses(profiles_path) -> None:
    payload = yaml.safe_dump({"profiles": {"x": {"description": "ok"}}}).encode()
    wrong = "0" * 64
    with mock.patch("urllib.request.urlopen") as m:
        m.return_value.__enter__.return_value.read.return_value = payload
        result = _invoke(
            ["profile", "install", "--from", "https://example.com/p.yaml",
             "--sha256", wrong],
            env={"IAM_JIT_BOUNCER_PROFILES_FILE": str(profiles_path)},
        )
    assert result.exit_code == 2
    assert "sha256 mismatch" in result.output


def test_sha256_match_succeeds(profiles_path) -> None:
    payload = yaml.safe_dump({"profiles": {"x": {"description": "ok"}}}).encode()
    correct = hashlib.sha256(payload).hexdigest()
    with mock.patch("urllib.request.urlopen") as m:
        m.return_value.__enter__.return_value.read.return_value = payload
        result = _invoke(
            ["profile", "install", "--from", "https://example.com/p.yaml",
             "--sha256", correct],
            env={"IAM_JIT_BOUNCER_PROFILES_FILE": str(profiles_path)},
        )
    assert result.exit_code == 0
    assert "sha256 verified" in result.output


def test_malformed_yaml_refused(profiles_path) -> None:
    payload = b"\xff\xfe not yaml \n  - [\n"
    with mock.patch("urllib.request.urlopen") as m:
        m.return_value.__enter__.return_value.read.return_value = payload
        result = _invoke(
            ["profile", "install", "--from", "https://example.com/p.yaml"],
            env={"IAM_JIT_BOUNCER_PROFILES_FILE": str(profiles_path)},
        )
    assert result.exit_code == 1
    # Either YAML error or unicode error message is acceptable
    assert ("not valid YAML" in result.output
            or "yaml" in result.output.lower()
            or "decode" in result.output.lower())


def test_payload_without_profiles_object_refused(profiles_path) -> None:
    payload = yaml.safe_dump({"not_profiles": []}).encode()
    with mock.patch("urllib.request.urlopen") as m:
        m.return_value.__enter__.return_value.read.return_value = payload
        result = _invoke(
            ["profile", "install", "--from", "https://example.com/p.yaml"],
            env={"IAM_JIT_BOUNCER_PROFILES_FILE": str(profiles_path)},
        )
    assert result.exit_code == 1
    assert "profiles" in result.output


def test_validation_failure_aborts_before_writing(profiles_path) -> None:
    """All-or-nothing install: if one profile fails validation, no
    profiles are written. Prevents a partial state where some org
    profiles are installed but the install LOOKED like it failed."""
    payload = yaml.safe_dump({
        "profiles": {
            "good": {"description": "ok"},
            "bad": {"keyword_match": "regex"},  # invalid: must be word_boundary/substring
        },
    }).encode()
    with mock.patch("urllib.request.urlopen") as m:
        m.return_value.__enter__.return_value.read.return_value = payload
        result = _invoke(
            ["profile", "install", "--from", "https://example.com/p.yaml"],
            env={"IAM_JIT_BOUNCER_PROFILES_FILE": str(profiles_path)},
        )
    assert result.exit_code == 1
    # No partial-write: profiles file should not exist (or have neither)
    if profiles_path.exists():
        loaded = load_profiles()
        assert "good" not in loaded


def test_conflict_without_force_refused(profiles_path) -> None:
    # Pre-existing local profile
    profiles_path.write_text(yaml.safe_dump({
        "profiles": {"acme-staging": {"description": "user's local copy"}},
    }))
    payload = yaml.safe_dump({
        "profiles": {"acme-staging": {"description": "org version"}},
    }).encode()
    with mock.patch("urllib.request.urlopen") as m:
        m.return_value.__enter__.return_value.read.return_value = payload
        result = _invoke(
            ["profile", "install", "--from", "https://example.com/p.yaml"],
            env={"IAM_JIT_BOUNCER_PROFILES_FILE": str(profiles_path)},
        )
    assert result.exit_code == 2
    assert "--force" in result.output
    # Local version preserved
    profs = load_profiles()
    assert profs["acme-staging"].description == "user's local copy"


def test_conflict_with_force_overwrites(profiles_path) -> None:
    profiles_path.write_text(yaml.safe_dump({
        "profiles": {"acme-staging": {"description": "user's local copy"}},
    }))
    payload = yaml.safe_dump({
        "profiles": {"acme-staging": {"description": "org version"}},
    }).encode()
    url = "https://internal.acme.com/staging.yaml"
    with mock.patch("urllib.request.urlopen") as m:
        m.return_value.__enter__.return_value.read.return_value = payload
        result = _invoke(
            ["profile", "install", "--from", url, "--force"],
            env={"IAM_JIT_BOUNCER_PROFILES_FILE": str(profiles_path)},
        )
    assert result.exit_code == 0
    profs = load_profiles()
    assert profs["acme-staging"].description == "org version"
    assert profs["acme-staging"].source == url


def test_source_field_in_payload_is_overridden(profiles_path) -> None:
    """Engineer cannot spoof `source: local` in a malicious payload
    to escape the read-only check. The install ALWAYS forces source
    to the fetch URL."""
    payload = yaml.safe_dump({
        "profiles": {
            "sneaky": {
                "description": "claims to be local",
                "source": "local",  # malicious — would mark profile editable
            },
        },
    }).encode()
    url = "https://attacker.example.com/bad.yaml"
    with mock.patch("urllib.request.urlopen") as m:
        m.return_value.__enter__.return_value.read.return_value = payload
        result = _invoke(
            ["profile", "install", "--from", url],
            env={"IAM_JIT_BOUNCER_PROFILES_FILE": str(profiles_path)},
        )
    assert result.exit_code == 0
    profs = load_profiles()
    # source MUST be the URL, not "local"
    assert profs["sneaky"].source == url


def test_installed_profile_is_read_only_via_upsert(profiles_path) -> None:
    """Profiles installed via URL are read-only at the
    upsert_profile boundary — `recommend --save-as-profile NAME`
    where NAME matches an installed org profile is refused."""
    from iam_jit.bouncer.profiles import Profile, upsert_profile
    url = "https://example.com/p.yaml"
    payload = yaml.safe_dump({
        "profiles": {"acme-locked": {"description": "org"}},
    }).encode()
    with mock.patch("urllib.request.urlopen") as m:
        m.return_value.__enter__.return_value.read.return_value = payload
        result = _invoke(
            ["profile", "install", "--from", url],
            env={"IAM_JIT_BOUNCER_PROFILES_FILE": str(profiles_path)},
        )
    assert result.exit_code == 0

    with pytest.raises(ValueError, match="read-only"):
        upsert_profile(Profile(name="acme-locked", description="local"))


def test_install_url_records_source_field(profiles_path) -> None:
    payload = yaml.safe_dump({"profiles": {"x": {"description": "ok"}}}).encode()
    url = "https://internal.acme.com/iam-jit-profiles/x.yaml"
    with mock.patch("urllib.request.urlopen") as m:
        m.return_value.__enter__.return_value.read.return_value = payload
        result = _invoke(
            ["profile", "install", "--from", url],
            env={"IAM_JIT_BOUNCER_PROFILES_FILE": str(profiles_path)},
        )
    assert result.exit_code == 0
    profs = load_profiles()
    assert profs["x"].source == url
