"""#326 — round-trip test: save a generated bundle then re-read its
files. The bouncer's install layer (`bounce profile install --from
PATH`) consumes the same files this generator writes; this test
verifies the on-disk shape is what install expects.
"""

from __future__ import annotations

import json

import pytest
import yaml

from iam_jit.llm import profile_generator as pg


class _StubBackend:
    name = "stub"

    def __init__(self, reply: str) -> None:
        self._reply = reply

    def chat(self, *, system_prompt: str, messages: list[dict[str, str]]) -> str:
        return self._reply


@pytest.fixture
def patch_backend(monkeypatch: pytest.MonkeyPatch):
    def _make(reply: str, name: str = "stub"):
        def _resolve(preferred: str | None):
            return _StubBackend(reply), name
        monkeypatch.setattr(pg, "_resolve_backend", _resolve)
    return _make


def _make_events():
    return [
        {
            "_bouncer": "ibounce",
            "time": 1716412800000,
            "activity_name": "allow",
            "unmapped": {"iam_jit": {"verdict": "allow"}},
            "api": {
                "service": {"name": "s3"},
                "operation": "GetObject",
                "resources": [{"name": "arn:aws:s3:::data-bucket"}],
            },
        },
    ]


def test_save_then_read_roundtrip(tmp_path, patch_backend):
    reply = json.dumps({
        "profiles": [
            {
                "bouncer": "ibounce",
                "allows": [
                    {
                        "target": "arn:aws:s3:::data-bucket",
                        "actions": ["s3:GetObject"],
                        "reason": "observed read",
                    },
                ],
                "denies": [],
                "flagged_for_review": [],
                "skipped": [],
            },
        ],
        "explanation": "roundtrip",
    })
    patch_backend(reply)
    result = pg.generate_from_audit(
        events=_make_events(),
        time_range="1h",
        add_safety_denies=True,
        profile_name="roundtrip-test",
    )
    out = tmp_path / "roundtrip"
    manifest = pg.save_bundle(result, out)

    # Index parses.
    idx_path = out / "index.yaml"
    assert idx_path.exists()
    idx = yaml.safe_load(idx_path.read_text())
    assert idx["schema_version"] == 1
    assert idx["bundle_name"] == "roundtrip-test"
    # Each referenced file actually exists + parses.
    for entry in idx["profiles"]:
        f = out / entry["file"]
        assert f.exists()
        parsed = yaml.safe_load(f.read_text())
        assert parsed["bouncer"] == entry["bouncer"]

    # Manifest sha256s match on-disk content.
    import hashlib as _h
    for entry in manifest["files"]:
        from pathlib import Path
        body = Path(entry["path"]).read_text()
        assert _h.sha256(body.encode("utf-8")).hexdigest() == entry["sha256"]


def test_save_for_mcp_writes_under_env_override(tmp_path, monkeypatch):
    """`bounce_profile_save` MCP tool writes under
    `IAM_JIT_GENERATED_PROFILES_DIR` when set."""
    from iam_jit.cli_profile_generate import save_for_mcp

    monkeypatch.setenv("IAM_JIT_GENERATED_PROFILES_DIR", str(tmp_path))
    result = save_for_mcp({
        "yaml": "schema_version: 1\nprofile_name: x\n",
        "name": "save-test",
    })
    assert "error" not in result
    assert result["name"] == "save-test"
    assert (tmp_path / "save-test" / "profile.yaml").exists()


def test_save_for_mcp_refuses_overwrite(tmp_path, monkeypatch):
    from iam_jit.cli_profile_generate import save_for_mcp

    monkeypatch.setenv("IAM_JIT_GENERATED_PROFILES_DIR", str(tmp_path))
    r1 = save_for_mcp({
        "yaml": "schema_version: 1\nprofile_name: a\n",
        "name": "twice",
    })
    assert "error" not in r1
    r2 = save_for_mcp({
        "yaml": "schema_version: 1\nprofile_name: b\n",
        "name": "twice",
    })
    assert "error" in r2
    assert "creates-never-mutates" in r2["error"]


def test_save_for_mcp_rejects_empty_yaml(tmp_path, monkeypatch):
    from iam_jit.cli_profile_generate import save_for_mcp

    monkeypatch.setenv("IAM_JIT_GENERATED_PROFILES_DIR", str(tmp_path))
    assert "error" in save_for_mcp({"yaml": "", "name": "empty"})
    assert "error" in save_for_mcp({"yaml": "x", "name": ""})
