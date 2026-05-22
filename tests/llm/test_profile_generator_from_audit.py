"""#326 — golden tests for audit-driven profile generation.

Test strategy:

* DON'T require a real LLM. We monkeypatch the legacy `get_backend()`
  to return a stub backend whose `chat()` returns a canned JSON
  string. This exercises the strict-parser path.
* For the deterministic-fallback path we use a stub that returns
  garbage; the parser must still produce a valid profile bundle.
* Honest-positioning surfaces (flagged_for_review on broad globs,
  skipped list, provenance metadata) are asserted directly on the
  parsed result.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from iam_jit.llm import profile_generator as pg


class _StubBackend:
    """Test-only LLMBackend stub with a deterministic chat() reply."""

    name = "stub"

    def __init__(self, reply: str) -> None:
        self._reply = reply

    def chat(self, *, system_prompt: str, messages: list[dict[str, str]]) -> str:
        return self._reply


@pytest.fixture
def patch_backend(monkeypatch: pytest.MonkeyPatch):
    """Patch `_resolve_backend` to return a stub backend with the
    caller-supplied reply text."""

    def _make(reply: str, name: str = "stub"):
        def _resolve(preferred: str | None):
            return _StubBackend(reply), name
        monkeypatch.setattr(pg, "_resolve_backend", _resolve)
    return _make


def _sample_events() -> list[dict[str, Any]]:
    """A realistic 1-hour audit window: one agent doing legitimate
    S3 read work + occasional EC2 describe calls."""
    return [
        {
            "_bouncer": "ibounce",
            "time": 1716412800000,
            "activity_name": "allow",
            "unmapped": {"iam_jit": {
                "verdict": "allow",
                "agent": {"session_id": "abc-123"},
            }},
            "api": {
                "service": {"name": "s3"},
                "operation": "GetObject",
                "resources": [{"name": "arn:aws:s3:::reports-bucket/2026/q2/sales.csv"}],
            },
        },
        {
            "_bouncer": "ibounce",
            "time": 1716412900000,
            "activity_name": "allow",
            "unmapped": {"iam_jit": {
                "verdict": "allow",
                "agent": {"session_id": "abc-123"},
            }},
            "api": {
                "service": {"name": "s3"},
                "operation": "ListBucket",
                "resources": [{"name": "arn:aws:s3:::reports-bucket"}],
            },
        },
        {
            "_bouncer": "ibounce",
            "time": 1716413000000,
            "activity_name": "allow",
            "unmapped": {"iam_jit": {"verdict": "allow"}},
            "api": {
                "service": {"name": "ec2"},
                "operation": "DescribeInstances",
                "resources": [{"name": "*"}],
            },
        },
        {
            "_bouncer": "kbounce",
            "time": 1716413100000,
            "activity_name": "allow",
            "unmapped": {"iam_jit": {"verdict": "allow"}},
            "api": {
                "service": {"name": "k8s"},
                "operation": "list/pods",
                "resources": [{"name": "ns/api-staging"}],
            },
        },
    ]


def test_strict_parse_happy_path(patch_backend):
    reply = json.dumps({
        "profiles": [
            {
                "bouncer": "ibounce",
                "allows": [
                    {
                        "target": "arn:aws:s3:::reports-bucket/2026/q2/*",
                        "actions": ["s3:GetObject"],
                        "reason": "observed read of reports-bucket/2026/q2 contents",
                    },
                    {
                        "target": "arn:aws:s3:::reports-bucket",
                        "actions": ["s3:ListBucket"],
                        "reason": "observed bucket list",
                    },
                ],
                "denies": [],
                "flagged_for_review": [],
                "skipped": ["one-off ec2:DescribeInstances: ambiguous pattern"],
            },
            {
                "bouncer": "kbounce",
                "allows": [
                    {
                        "verbs": ["list"],
                        "resources": ["pods"],
                        "scope": "ns/api-staging",
                        "reason": "observed pod list in api-staging",
                    },
                ],
                "denies": [],
                "flagged_for_review": [],
                "skipped": [],
            },
        ],
        "explanation": "Generated from 4 events.",
    })
    patch_backend(reply, name="anthropic")

    result = pg.generate_from_audit(
        events=_sample_events(),
        time_range="1h",
        agent_session_id="abc-123",
        add_safety_denies=True,
        profile_name="test-bundle",
        audit_window_start="2026-05-22T17:00:00Z",
        audit_window_end="2026-05-22T18:00:00Z",
    )

    assert result.parser_strict_match is True
    assert result.backend_name == "anthropic"
    assert {p.bouncer for p in result.bundle} == {"ibounce", "kbounce"}

    ibounce = next(p for p in result.bundle if p.bouncer == "ibounce")
    # Allow rules survived parsing.
    assert "s3:GetObject" in ibounce.profile_yaml
    # Safety floor denies got layered in even though the LLM omitted them.
    assert "iam:CreateAccessKey" in ibounce.profile_yaml
    assert "break-glass" in ibounce.profile_yaml
    assert "kms:ScheduleKeyDeletion" in ibounce.profile_yaml
    # Provenance + audit window in the rendered yaml.
    assert "llm-generated-from-audit" in ibounce.profile_yaml
    assert "2026-05-22T17:00:00Z" in ibounce.profile_yaml
    assert "abc-123" in ibounce.profile_yaml
    # Skipped list surfaces in YAML.
    assert "one-off ec2:DescribeInstances" in ibounce.profile_yaml
    # Honest label.
    assert "STARTING POINT" in ibounce.profile_yaml

    # Bundle index ties them together.
    assert "test-bundle-ibounce" in result.index_yaml or "ibounce.yaml" in result.index_yaml
    assert "kbounce.yaml" in result.index_yaml


def test_broad_glob_auto_flagged_clientside(patch_backend):
    """Even if the LLM doesn't flag a broad glob, the client must."""
    reply = json.dumps({
        "profiles": [
            {
                "bouncer": "ibounce",
                "allows": [
                    {
                        "target": "arn:aws:s3:::*-staging-*",
                        "actions": ["s3:GetObject"],
                        "reason": "observed reads across all staging buckets",
                    },
                ],
                "denies": [],
                "flagged_for_review": [],
                "skipped": [],
            },
        ],
        "explanation": "ok",
    })
    patch_backend(reply)
    result = pg.generate_from_audit(
        events=_sample_events(),
        time_range="1h",
        add_safety_denies=False,
        profile_name="broad-test",
    )
    ibounce = next(p for p in result.bundle if p.bouncer == "ibounce")
    assert any("broad pattern" in f.lower() for f in ibounce.flagged_for_review), (
        f"expected client-side broad-pattern flag in {ibounce.flagged_for_review}"
    )


def test_deterministic_fallback_on_garbage(patch_backend):
    """Junk LLM output -> deterministic fallback per bouncer; profile
    is still usable + carries the explanation."""
    patch_backend("not json at all <html>", name="stub")
    result = pg.generate_from_audit(
        events=_sample_events(),
        time_range="1h",
        add_safety_denies=True,
        profile_name="fallback-test",
    )
    assert result.parser_strict_match is False
    assert "deterministic fallback" in result.explanation.lower()
    assert len(result.bundle) >= 1
    # Safety floor still present.
    ibounce = next(p for p in result.bundle if p.bouncer == "ibounce")
    assert "iam:CreateAccessKey" in ibounce.profile_yaml


def test_deterministic_fallback_on_empty_response(patch_backend):
    patch_backend("", name="stub")
    result = pg.generate_from_audit(
        events=_sample_events(),
        time_range="1h",
        add_safety_denies=True,
        profile_name="empty-test",
    )
    assert result.parser_strict_match is False
    # Allows from observed events present (deterministic fallback
    # synthesizes exact-match allows).
    ibounce = next(p for p in result.bundle if p.bouncer == "ibounce")
    assert "reports-bucket" in ibounce.profile_yaml
    # Honest "LLM unavailable" note in flagged_for_review.
    assert any(
        "LLM unavailable" in f for f in ibounce.flagged_for_review
    )


def test_empty_events_returns_empty_bundle(patch_backend):
    patch_backend("", name="stub")
    result = pg.generate_from_audit(
        events=[],
        time_range="1h",
        add_safety_denies=True,
        profile_name="empty",
    )
    assert result.bundle == ()
    assert "No events provided" in result.explanation


def test_bouncer_filter_restricts_output(patch_backend):
    """Passing bouncers=["ibounce"] excludes kbounce events from output."""
    reply = json.dumps({
        "profiles": [
            {
                "bouncer": "ibounce",
                "allows": [],
                "denies": [],
                "flagged_for_review": [],
                "skipped": [],
            },
        ],
        "explanation": "ibounce only",
    })
    patch_backend(reply)
    result = pg.generate_from_audit(
        events=_sample_events(),
        time_range="1h",
        bouncers=["ibounce"],
        add_safety_denies=False,
        profile_name="filtered",
    )
    bouncers = {p.bouncer for p in result.bundle}
    assert bouncers == {"ibounce"}


def test_safety_denies_disabled(patch_backend):
    reply = json.dumps({
        "profiles": [
            {
                "bouncer": "ibounce",
                "allows": [],
                "denies": [],
                "flagged_for_review": [],
                "skipped": [],
            },
        ],
        "explanation": "no safety floor",
    })
    patch_backend(reply)
    result = pg.generate_from_audit(
        events=_sample_events(),
        time_range="1h",
        bouncers=["ibounce"],
        add_safety_denies=False,
        profile_name="no-safety",
    )
    ibounce = next(p for p in result.bundle if p.bouncer == "ibounce")
    # Safety floor strings NOT present when disabled.
    assert "iam:CreateAccessKey" not in ibounce.profile_yaml
    assert "break-glass" not in ibounce.profile_yaml


def test_yaml_rendering_is_valid_yaml(patch_backend):
    """Round-trip every rendered profile through PyYAML to confirm
    the generator emits valid YAML (the operator + bouncer install
    layer will both yaml.safe_load it)."""
    import yaml
    reply = json.dumps({
        "profiles": [
            {
                "bouncer": "ibounce",
                "allows": [
                    {
                        "target": "arn:aws:s3:::reports-bucket",
                        "actions": ["s3:ListBucket", "s3:GetObject"],
                        "reason": "observed reads",
                    },
                ],
                "denies": [],
                "flagged_for_review": ["sample flag"],
                "skipped": ["sample skip"],
            },
        ],
        "explanation": "ok",
    })
    patch_backend(reply)
    result = pg.generate_from_audit(
        events=_sample_events(),
        time_range="1h",
        bouncers=["ibounce"],
        add_safety_denies=True,
        profile_name="yaml-round-trip",
    )
    ibounce = next(p for p in result.bundle if p.bouncer == "ibounce")
    parsed = yaml.safe_load(ibounce.profile_yaml)
    assert isinstance(parsed, dict)
    assert parsed["schema_version"] == 1
    assert parsed["bouncer"] == "ibounce"
    assert parsed["provenance"]["source"] == "llm-generated-from-audit"
    assert "STARTING POINT" not in parsed  # it's in a comment, not a field
    assert isinstance(parsed["allows"], list)
    assert isinstance(parsed["denies"], list)
    assert parsed["flagged_for_review"] == ["sample flag"]
    assert parsed["skipped"] == ["sample skip"]

    # Index yaml also valid
    idx = yaml.safe_load(result.index_yaml)
    assert idx["schema_version"] == 1
    assert idx["provenance"]["source"] == "llm-generated-from-audit"


def test_save_bundle_refuses_overwrite(tmp_path, patch_backend):
    """Per [[creates-never-mutates]] saving must never overwrite."""
    patch_backend("", name="stub")
    result = pg.generate_from_audit(
        events=_sample_events(),
        time_range="1h",
        bouncers=["ibounce"],
        add_safety_denies=True,
        profile_name="dont-overwrite",
    )
    out = tmp_path / "bundle"
    manifest = pg.save_bundle(result, out)
    assert (out / "index.yaml").exists()
    assert (out / "ibounce.yaml").exists()
    assert manifest["bundle_sha256"]
    # Second save into the same dir must fail.
    with pytest.raises(FileExistsError):
        pg.save_bundle(result, out)


def test_save_bundle_manifest_structure(tmp_path, patch_backend):
    patch_backend("", name="stub")
    result = pg.generate_from_audit(
        events=_sample_events(),
        time_range="1h",
        add_safety_denies=True,
        profile_name="manifest-test",
        audit_window_start="2026-05-22T17:00:00Z",
        audit_window_end="2026-05-22T18:00:00Z",
    )
    out = tmp_path / "m"
    manifest = pg.save_bundle(result, out)
    assert manifest["out_dir"] == str(out)
    assert manifest["audit_window_start"] == "2026-05-22T17:00:00Z"
    assert manifest["audit_window_end"] == "2026-05-22T18:00:00Z"
    # Files include index + one per bouncer.
    file_names = {pathlib_basename(f["path"]) for f in manifest["files"]}
    assert "index.yaml" in file_names


def pathlib_basename(p: str) -> str:
    import pathlib as _p
    return _p.Path(p).name
