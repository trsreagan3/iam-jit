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


def test_http_url_non_loopback_warns_but_proceeds(profiles_path) -> None:
    """Per §A26 (#350) `--from http://...` is no longer hard-refused;
    a one-line WARN fires for non-loopback hosts (loopback gets silent
    pass for local-dev parity with the audit-export convention). The
    install itself proceeds — operators who want a hard refusal can
    add a wrapper script or rely on the warning + their SIEM."""
    payload = yaml.safe_dump({
        "profiles": {"plaintext-fetched": {"description": "via http"}},
    }).encode()
    url = "http://example.com/p.yaml"
    with mock.patch("urllib.request.urlopen") as m:
        m.return_value.__enter__.return_value.read.return_value = payload
        result = _invoke(
            ["profile", "install", "--from", url],
            env={"IAM_JIT_BOUNCER_PROFILES_FILE": str(profiles_path)},
        )
    assert result.exit_code == 0, result.output
    # WARN must surface on stderr/output (CliRunner merges them in
    # `output` by default).
    assert "WARN" in result.output
    assert "plaintext" in result.output.lower()
    profs = load_profiles()
    assert "plaintext-fetched" in profs
    assert profs["plaintext-fetched"].source == url


def test_http_url_loopback_no_warning(profiles_path) -> None:
    """Loopback HTTP gets a silent pass — local-dev convention."""
    payload = yaml.safe_dump({
        "profiles": {"loopback-fetched": {"description": "via localhost"}},
    }).encode()
    url = "http://127.0.0.1:8080/p.yaml"
    with mock.patch("urllib.request.urlopen") as m:
        m.return_value.__enter__.return_value.read.return_value = payload
        result = _invoke(
            ["profile", "install", "--from", url],
            env={"IAM_JIT_BOUNCER_PROFILES_FILE": str(profiles_path)},
        )
    assert result.exit_code == 0, result.output
    assert "WARN" not in result.output


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


# ---------------------------------------------------------------------------
# §A26 (#349 + #350) — local-path install + schema bridge
# ---------------------------------------------------------------------------


def test_install_from_local_file_path(profiles_path, tmp_path) -> None:
    """Per §A26 (#350): `--from /path/to/file.yaml` reads + installs
    the YAML directly (no HTTP round-trip). Closes the gap where the
    documented quick-start `ibounce profile install --from ./profiles/`
    used to refuse with `https://-only` even though docs/PROFILE-
    GENERATION.md showed the example."""
    src = tmp_path / "local-bundle.yaml"
    src.write_text(yaml.safe_dump({
        "profiles": {
            "local-test": {
                "description": "from disk",
                "deny_keywords": ["prod"],
            },
        },
    }))
    result = _invoke(
        ["profile", "install", "--from", str(src)],
        env={"IAM_JIT_BOUNCER_PROFILES_FILE": str(profiles_path)},
    )
    assert result.exit_code == 0, result.output
    profs = load_profiles()
    assert "local-test" in profs
    # Source is the absolute resolved path so SIEM viewers can replay
    # the install. NOT "local" (which would mark the profile editable
    # via upsert_profile — installed-from-path profiles stay read-only).
    assert profs["local-test"].source == str(src.resolve())
    assert profs["local-test"].deny_keywords == ("prod",)


def test_install_from_file_url(profiles_path, tmp_path) -> None:
    """`file:///abs/path/...` parses to the same local-file path as
    a bare `/abs/path/...` argument."""
    src = tmp_path / "file-url-bundle.yaml"
    src.write_text(yaml.safe_dump({
        "profiles": {"via-file-url": {"description": "ok"}},
    }))
    result = _invoke(
        ["profile", "install", "--from", f"file://{src}"],
        env={"IAM_JIT_BOUNCER_PROFILES_FILE": str(profiles_path)},
    )
    assert result.exit_code == 0, result.output
    profs = load_profiles()
    assert "via-file-url" in profs


def test_install_from_missing_path_fails_with_clear_error(profiles_path, tmp_path) -> None:
    missing = tmp_path / "absent.yaml"
    result = _invoke(
        ["profile", "install", "--from", str(missing)],
        env={"IAM_JIT_BOUNCER_PROFILES_FILE": str(profiles_path)},
    )
    assert result.exit_code == 2
    assert "does not exist" in result.output


def test_install_from_unknown_scheme_refused(profiles_path) -> None:
    """A bogus scheme (`gopher://...`) is refused with exit code 2 +
    a message that enumerates the supported set. Prevents silent
    fallthrough to file-read on a typo."""
    result = _invoke(
        ["profile", "install", "--from", "gopher://example.com/p.yaml"],
        env={"IAM_JIT_BOUNCER_PROFILES_FILE": str(profiles_path)},
    )
    assert result.exit_code == 2
    assert "gopher" in result.output.lower() or "not supported" in result.output


def test_install_from_bundle_directory(profiles_path, tmp_path) -> None:
    """Per §A26 (#350): when `--from` points at a directory, the
    install looks for `ibounce.yaml` inside (the generator's per-
    bouncer slot in a bundle layout). This closes the documented
    quick-start example `--from ./profiles/`."""
    bundle = tmp_path / "audit-pinned"
    bundle.mkdir()
    (bundle / "ibounce.yaml").write_text(yaml.safe_dump({
        "schema_version": 1,
        "profile_name": "from-bundle-dir",
        "bouncer": "ibounce",
        "deny_actions": ["s3:DeleteBucket"],
    }))
    result = _invoke(
        ["profile", "install", "--from", str(bundle)],
        env={"IAM_JIT_BOUNCER_PROFILES_FILE": str(profiles_path)},
    )
    assert result.exit_code == 0, result.output
    profs = load_profiles()
    assert "from-bundle-dir" in profs
    assert "s3:DeleteBucket" in profs["from-bundle-dir"].deny_actions


def test_install_from_generator_shape_single_file(profiles_path, tmp_path) -> None:
    """Per §A26 (#349): the parser accepts the
    `iam-jit profile generate-from-audit` per-bouncer file shape
    (top-level `profile_name:` + `bouncer:` + `denies: [{target,
    actions, reason}]`) and translates it to enforceable
    deny_actions. The generated profile parses into a NON-EMPTY
    Profile (pre-fix it parsed into an empty Profile and enforced
    nothing — the load-bearing dogfood finding)."""
    src = tmp_path / "ibounce.yaml"
    src.write_text(yaml.safe_dump({
        "schema_version": 1,
        "profile_name": "audit-pinned-staging",
        "bouncer": "ibounce",
        "provenance": {"source": "generate-from-audit", "events_analyzed": 5},
        "allows": [
            {
                "target": "arn:aws:s3:::staging-bucket/*",
                "actions": ["s3:GetObject", "s3:ListBucket"],
                "reason": "observed reads on staging bucket",
            },
        ],
        "denies": [
            {
                "target": "arn:aws:iam::*:role/break-glass-*",
                "actions": ["sts:AssumeRole"],
                "reason": "break-glass roles require human approval",
            },
            {
                "target": "*",
                "actions": ["iam:CreateAccessKey", "iam:CreateUser"],
                "reason": "agents must not mint credentials",
            },
        ],
    }))
    result = _invoke(
        ["profile", "install", "--from", str(src)],
        env={"IAM_JIT_BOUNCER_PROFILES_FILE": str(profiles_path)},
    )
    assert result.exit_code == 0, result.output
    profs = load_profiles()
    assert "audit-pinned-staging" in profs
    p = profs["audit-pinned-staging"]
    # The cross-bouncer `denies: [{target, actions, reason}]` shape
    # translates to canonical `deny_actions` — these are the load-
    # bearing assertions: pre-fix this list was EMPTY.
    assert "sts:AssumeRole" in p.deny_actions
    assert "iam:CreateAccessKey" in p.deny_actions
    assert "iam:CreateUser" in p.deny_actions
    # Allow rules also bridge — scoped to the observed bucket.
    allow_patterns = [r.pattern for r in p.allow_rules]
    assert "s3:GetObject" in allow_patterns
    assert "s3:ListBucket" in allow_patterns


def test_parser_old_shape_unchanged(tmp_path, monkeypatch) -> None:
    """Per [[creates-never-mutates]]: operator-authored profiles
    using the canonical `deny_actions:` / `allow_rules:` shape must
    continue to parse identically post-fix. This locks in the
    backwards-compat contract."""
    from iam_jit.bouncer.profiles import _profile_from_dict

    body = {
        "description": "operator-authored",
        "deny_actions": ["secretsmanager:GetSecretValue"],
        "deny_keywords": ["prod"],
        "allow_baseline": "aws_managed_readonly_access",
        "deny_actions_with_condition": [
            {
                "action": "s3:GetObject",
                "condition": {"tag/sensitive": "true"},
            },
        ],
    }
    p = _profile_from_dict("hand-written", body)
    assert p.deny_actions == ("secretsmanager:GetSecretValue",)
    assert p.deny_keywords == ("prod",)
    assert p.allow_baseline == "aws_managed_readonly_access"
    assert len(p.deny_actions_with_condition) == 1


def test_parser_translates_generator_denies(tmp_path) -> None:
    """Unit test for the schema bridge — generator-shape `denies:`
    list translates into canonical `deny_actions`."""
    from iam_jit.bouncer.profiles import _profile_from_dict

    body = {
        "schema_version": 1,
        "profile_name": "x",
        "bouncer": "ibounce",
        "denies": [
            {
                "target": "arn:aws:iam::*:role/break-glass-*",
                "actions": ["sts:AssumeRole"],
                "reason": "break-glass",
            },
            {
                # Non-AWS rule shape (kbounce / dbounce verbs) is
                # skipped at the ibounce parser — no service:action
                # form to translate.
                "target": "cluster",
                "verbs": ["delete"],
                "resources": ["namespaces"],
                "reason": "k8s shape",
            },
        ],
    }
    p = _profile_from_dict("x", body)
    assert "sts:AssumeRole" in p.deny_actions


def test_parser_both_shapes_compose(tmp_path) -> None:
    """A profile that mixes old (`deny_actions:`) + new (`denies:`)
    shapes merges them additively. Order-preserving, de-duped."""
    from iam_jit.bouncer.profiles import _profile_from_dict

    body = {
        "deny_actions": ["iam:CreateAccessKey"],
        "denies": [
            {"target": "*", "actions": ["iam:CreateUser", "iam:CreateAccessKey"]},
        ],
    }
    p = _profile_from_dict("merged", body)
    # Existing entry preserved + new entry added; the duplicated
    # iam:CreateAccessKey doesn't appear twice.
    assert p.deny_actions == ("iam:CreateAccessKey", "iam:CreateUser")


def test_enforcement_via_generator_shape_blocks_adversarial(tmp_path) -> None:
    """End-to-end-shaped unit test: a profile installed in
    generator-shape MUST actually DENY the malicious action at
    `evaluate_profile` time. This is the load-bearing assertion
    that the schema bridge connects all the way through to
    enforcement (not just parsing)."""
    from iam_jit.bouncer.profiles import (
        _profile_from_dict,
        evaluate_profile,
    )

    body = {
        "schema_version": 1,
        "profile_name": "adversarial-test",
        "bouncer": "ibounce",
        "denies": [
            {
                "target": "*",
                "actions": ["iam:CreateAccessKey"],
                "reason": "agents must not mint credentials",
            },
        ],
    }
    p = _profile_from_dict("adversarial-test", body)
    verdict = evaluate_profile(
        p,
        arn="arn:aws:iam::123456789012:user/agent",
        service="iam",
        action="CreateAccessKey",
    )
    assert verdict.denied is True, (
        f"profile {p.name!r} failed to deny iam:CreateAccessKey via "
        f"the generator-shape bridge — schema integration regression"
    )
    assert "iam:CreateAccessKey" in verdict.reason
