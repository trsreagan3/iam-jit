"""#326 — CLI integration test for profile generate-from-audit.

This test exercises the cross-bouncer fan-out + profile-generation
path end-to-end through the `iam-jit profile generate-from-audit`
CLI surface. We mock the per-bouncer HTTP layer (the same hook the
audit-query CLI uses) so the test doesn't require live bouncer
binaries; the spec calls for verifying that the resulting profile
installs + that the resulting role narrows correctly, which we do
by:

  1. Mocking 4 bouncer responses with realistic OCSF events for one
     agent session.
  2. Invoking `iam-jit profile generate-from-audit --output <tmp>`.
  3. Reading the resulting bundle dir + asserting:
       - index.yaml + per-bouncer YAMLs were written
       - each YAML parses as YAML + has the expected provenance
       - the safety floor was layered on (when --add-safety-denies)
       - the flagged_for_review surface fired for broad globs
       - the bundle could be passed to `bounce profile install --from`
         (we verify the file layout matches the install layer's
         documented expectations; the install layer itself is
         tested separately in tests/bouncer/test_profile_install_*.py)

Per [[deliberate-feature-completion]] this ships in the same commit
as the implementation.
"""

from __future__ import annotations

import io
import json

import pytest
import yaml
from click.testing import CliRunner

# Realistic 1-hour audit window: agent doing legitimate report-generation
# work touching prod-reports bucket + api-staging namespace + audit_log
# table + an internal monitoring HTTPS endpoint.
_TIMESTAMP_BASE = 1716412800000  # 2026-05-22T17:00:00Z


def _make_event(bouncer: str, t_offset: int, service: str, op: str,
                resource: str, session: str = "session-abc123") -> dict:
    return {
        "_bouncer": bouncer,
        "time": _TIMESTAMP_BASE + t_offset,
        "activity_name": "allow",
        "api": {
            "service": {"name": service},
            "operation": op,
            "resources": [{"name": resource}],
        },
        "unmapped": {"iam_jit": {
            "verdict": "allow",
            "agent": {"session_id": session, "name": "claude-code"},
        }},
    }


def _ibounce_events() -> list[dict]:
    return [
        _make_event("ibounce", i, "s3", "GetObject",
                    f"arn:aws:s3:::prod-reports/2026/q2/file-{i}.csv")
        for i in range(10)
    ] + [
        _make_event("ibounce", 100, "s3", "ListBucket",
                    "arn:aws:s3:::prod-reports"),
    ]


def _kbounce_events() -> list[dict]:
    return [
        _make_event("kbounce", 100 + i, "k8s", "list/pods", "ns/api-staging")
        for i in range(5)
    ]


def _dbounce_events() -> list[dict]:
    return [
        _make_event("dbounce", 200, "postgres", "SELECT", "public.audit_log"),
        _make_event("dbounce", 201, "postgres", "SELECT", "public.audit_log"),
    ]


def _gbounce_events() -> list[dict]:
    return [
        _make_event("gbounce", 300, "https", "GET",
                    "https://internal-monitoring.example.com/health"),
    ]


def _all_events() -> list[dict]:
    return (
        _ibounce_events()
        + _kbounce_events()
        + _dbounce_events()
        + _gbounce_events()
    )


def _stub_urlopen_factory():
    """Build a urlopen replacement that returns per-bouncer NDJSON
    based on the URL host:port (matches DEFAULT_BOUNCERS in the
    audit-query module)."""
    by_port = {
        8767: _ibounce_events(),
        8766: _kbounce_events(),
        8768: _dbounce_events(),
        8769: _gbounce_events(),
    }

    class _FakeResp:
        def __init__(self, body: bytes) -> None:
            self._body = body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def read(self):
            return self._body

    def _stub(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else str(req)
        port = None
        for p in by_port:
            if f":{p}" in url:
                port = p
                break
        events = by_port.get(port, [])
        body = "\n".join(json.dumps(e) for e in events).encode("utf-8")
        return _FakeResp(body)

    return _stub


class _StubLLMBackend:
    """LLM backend stub that emits a realistic narrowed profile."""
    name = "stub"

    def chat(self, *, system_prompt, messages):
        return json.dumps({
            "profiles": [
                {
                    "bouncer": "ibounce",
                    "allows": [
                        {
                            "target": "arn:aws:s3:::prod-reports/2026/q2/*",
                            "actions": ["s3:GetObject"],
                            "reason": (
                                "observed 10 reads on 2026/q2 prefix"
                            ),
                        },
                        {
                            "target": "arn:aws:s3:::prod-reports",
                            "actions": ["s3:ListBucket"],
                            "reason": "observed bucket listing",
                        },
                    ],
                    "denies": [],
                    "flagged_for_review": [],
                    "skipped": [],
                },
                {
                    "bouncer": "kbounce",
                    "allows": [
                        {
                            "verbs": ["list"],
                            "resources": ["pods"],
                            "scope": "ns/api-staging",
                            "reason": "observed pod listings",
                        },
                    ],
                    "denies": [],
                    "flagged_for_review": [],
                    "skipped": [],
                },
                {
                    "bouncer": "dbounce",
                    "allows": [
                        {
                            "target": "public.audit_log",
                            "actions": ["SELECT"],
                            "reason": "observed 2 reads",
                        },
                    ],
                    "denies": [],
                    "flagged_for_review": [],
                    "skipped": [],
                },
                {
                    "bouncer": "gbounce",
                    "allows": [
                        {
                            "target": "internal-monitoring.example.com",
                            "actions": ["GET"],
                            "reason": "observed health-check",
                        },
                    ],
                    "denies": [],
                    "flagged_for_review": [],
                    "skipped": [],
                },
            ],
            "explanation": (
                "Generated profile from 18 events across 4 bouncers. "
                "ibounce uses /2026/q2/* narrowing because all 10 reads "
                "were in that prefix — flagged for operator confirmation."
            ),
        })


def test_cli_generate_from_audit_writes_bundle(tmp_path, monkeypatch):
    """End-to-end: CLI fan-out -> LLM -> bundle dir with one YAML
    per observed bouncer + index.yaml."""
    from iam_jit import cli as cli_module
    from iam_jit import cli_audit_query
    from iam_jit.llm import profile_generator as pg

    # Replace the urlopen used by cli_audit_query so the fan-out
    # returns our canned events without needing real bouncer binaries.
    monkeypatch.setattr(cli_audit_query, "_urlopen", _stub_urlopen_factory())

    # Replace the LLM backend with our deterministic stub.
    monkeypatch.setattr(
        pg, "_resolve_backend",
        lambda preferred: (_StubLLMBackend(), "anthropic"),
    )
    # §A93 / #509 Phase 3 — opt in to bouncer-side LLM for this test
    # (we explicitly want to exercise the LLM round-trip path).
    monkeypatch.setenv("IAM_JIT_ENABLE_SIDE_LLM", "1")

    runner = CliRunner()
    out_dir = tmp_path / "bundle"
    result = runner.invoke(cli_module.main, [
        "profile", "generate-from-audit",
        "--time-range", "1h",
        "--agent-session", "session-abc123",
        "--add-safety-denies",
        "--name", "integration-test-bundle",
        "--output", str(out_dir),
        "--limit", "500",
    ])
    assert result.exit_code == 0, (
        f"CLI exited {result.exit_code}: stdout={result.stdout} "
        f"stderr={result.stderr}"
    )

    # The CLI writes a manifest JSON on success.
    manifest = json.loads(result.stdout)
    assert "bundle_sha256" in manifest
    assert "files" in manifest

    # Bundle dir layout matches the documented spec.
    assert (out_dir / "index.yaml").exists()
    assert (out_dir / "ibounce.yaml").exists()
    assert (out_dir / "kbounce.yaml").exists()
    assert (out_dir / "dbounce.yaml").exists()
    assert (out_dir / "gbounce.yaml").exists()

    # Index parses + references each bouncer file.
    idx = yaml.safe_load((out_dir / "index.yaml").read_text())
    assert idx["bundle_name"] == "integration-test-bundle"
    assert idx["provenance"]["source"] == "llm-generated-from-audit"
    referenced_files = {entry["file"] for entry in idx["profiles"]}
    for fname in ("ibounce.yaml", "kbounce.yaml",
                  "dbounce.yaml", "gbounce.yaml"):
        assert fname in referenced_files, f"index missing {fname}"

    # Per-bouncer YAMLs parse + carry the right narrowing.
    ibounce = yaml.safe_load((out_dir / "ibounce.yaml").read_text())
    assert ibounce["bouncer"] == "ibounce"
    assert ibounce["provenance"]["source_session_id"] == "session-abc123"
    assert ibounce["provenance"]["events_analyzed"] >= 10
    # Allow + safety-floor deny both present.
    allow_targets = [r["target"] for r in ibounce["allows"]]
    assert any("prod-reports" in t for t in allow_targets)
    deny_reasons = [r["reason"] for r in ibounce["denies"]]
    assert any("credentials" in r.lower() for r in deny_reasons)

    # Broad-glob flagged for review (client-side detection of `*`).
    flagged = ibounce.get("flagged_for_review") or []
    assert any("broad pattern" in f.lower() for f in flagged), (
        f"expected broad-pattern flag in {flagged}"
    )

    # kbounce + dbounce + gbounce also rendered.
    kbounce = yaml.safe_load((out_dir / "kbounce.yaml").read_text())
    assert kbounce["bouncer"] == "kbounce"
    dbounce = yaml.safe_load((out_dir / "dbounce.yaml").read_text())
    assert dbounce["bouncer"] == "dbounce"
    gbounce = yaml.safe_load((out_dir / "gbounce.yaml").read_text())
    assert gbounce["bouncer"] == "gbounce"

    # Manifest sha256 chain is internally consistent.
    import hashlib
    for entry in manifest["files"]:
        from pathlib import Path
        body = Path(entry["path"]).read_text()
        assert hashlib.sha256(body.encode("utf-8")).hexdigest() == entry["sha256"]


def test_cli_generate_from_audit_refuses_overwrite(tmp_path, monkeypatch):
    """Per [[creates-never-mutates]] a second run into the same dir
    surfaces a refusal."""
    from iam_jit import cli as cli_module
    from iam_jit import cli_audit_query
    from iam_jit.llm import profile_generator as pg

    monkeypatch.setattr(cli_audit_query, "_urlopen", _stub_urlopen_factory())
    monkeypatch.setattr(
        pg, "_resolve_backend",
        lambda preferred: (_StubLLMBackend(), "stub"),
    )
    # §A93 / #509 Phase 3 — opt in to bouncer-side LLM for this test
    # (we explicitly want to exercise the LLM round-trip path).
    monkeypatch.setenv("IAM_JIT_ENABLE_SIDE_LLM", "1")

    runner = CliRunner()
    out_dir = tmp_path / "noclobber"

    r1 = runner.invoke(cli_module.main, [
        "profile", "generate-from-audit",
        "--time-range", "1h",
        "--name", "first",
        "--output", str(out_dir),
    ])
    assert r1.exit_code == 0, r1.stdout + r1.stderr

    r2 = runner.invoke(cli_module.main, [
        "profile", "generate-from-audit",
        "--time-range", "1h",
        "--name", "second",
        "--output", str(out_dir),
    ])
    assert r2.exit_code != 0
    combined = (r2.stdout or "") + (r2.stderr or "")
    assert "creates-never-mutates" in combined or "refusing" in combined.lower()


def test_cli_generate_yaml_bundle_format(tmp_path, monkeypatch):
    """--format yaml-bundle emits one YAML stream with `---` separators."""
    from iam_jit import cli as cli_module
    from iam_jit import cli_audit_query
    from iam_jit.llm import profile_generator as pg

    monkeypatch.setattr(cli_audit_query, "_urlopen", _stub_urlopen_factory())
    monkeypatch.setattr(
        pg, "_resolve_backend",
        lambda preferred: (_StubLLMBackend(), "stub"),
    )
    # §A93 / #509 Phase 3 — opt in to bouncer-side LLM for this test
    # (we explicitly want to exercise the LLM round-trip path).
    monkeypatch.setenv("IAM_JIT_ENABLE_SIDE_LLM", "1")
    runner = CliRunner()
    r = runner.invoke(cli_module.main, [
        "profile", "generate-from-audit",
        "--time-range", "1h",
        "--name", "yaml-fmt",
        "--format", "yaml-bundle",
    ])
    assert r.exit_code == 0, r.output
    # stdout should carry the YAML stream; stderr the flag: notes.
    assert "# index.yaml" in r.stdout
    assert "# ibounce.yaml" in r.stdout
    assert "---" in r.stdout
    # Multiple documents present in stdout.
    assert r.stdout.count("schema_version: 1") >= 2


def test_mcp_tool_dispatch_smoke(monkeypatch):
    """The MCP server dispatches the three new tools to the right
    handlers. We don't exercise the full JSON-RPC path; just the
    handler resolution + structured-content shape."""
    from iam_jit import cli_profile_generate
    from iam_jit.llm import profile_generator as pg

    monkeypatch.setattr(
        pg, "_resolve_backend",
        lambda preferred: (_StubLLMBackend(), "stub"),
    )
    # §A93 / #509 Phase 3 — opt in to bouncer-side LLM for this test
    # (we explicitly want to exercise the LLM round-trip path).
    monkeypatch.setenv("IAM_JIT_ENABLE_SIDE_LLM", "1")
    out = cli_profile_generate.generate_from_audit_for_mcp({
        "events": _all_events(),
        "time_range": "1h",
        "agent_session_id": "session-abc123",
        "add_safety_denies": True,
        "name": "mcp-smoke",
    })
    assert "bundle" in out
    assert out["backend_name"] == "stub"
    assert out["parser_strict_match"] is True
    # All 4 bouncers represented.
    bouncers = {p["bouncer"] for p in out["bundle"]}
    assert bouncers == {"ibounce", "kbounce", "dbounce", "gbounce"}

    # Context tool also works.
    ctx_out = cli_profile_generate.generate_from_context_for_mcp({
        "context": "Test org context",
        "name": "ctx-smoke",
    })
    assert "bundle" in ctx_out
    # Save tool refuses to overwrite.
    import os
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        monkeypatch.setenv("IAM_JIT_GENERATED_PROFILES_DIR", td)
        s1 = cli_profile_generate.save_for_mcp({
            "yaml": "schema_version: 1\nprofile_name: t\n",
            "name": "save-dup",
        })
        assert "error" not in s1
        s2 = cli_profile_generate.save_for_mcp({
            "yaml": "schema_version: 1\nprofile_name: t\n",
            "name": "save-dup",
        })
        assert "error" in s2
