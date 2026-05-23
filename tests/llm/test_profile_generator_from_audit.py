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
    caller-supplied reply text.

    Also enables the §A93 / #509 Phase 3 opt-in
    (``IAM_JIT_ENABLE_SIDE_LLM=1``) — these tests explicitly want to
    exercise the LLM-path behavior, so they signal opt-in matching the
    new local-dev / agent-in-loop default."""

    def _make(reply: str, name: str = "stub"):
        def _resolve(preferred: str | None):
            return _StubBackend(reply), name
        monkeypatch.setattr(pg, "_resolve_backend", _resolve)
        monkeypatch.setenv("IAM_JIT_ENABLE_SIDE_LLM", "1")
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


# ---------------------------------------------------------------------------
# §A38 #370 — scope-preservation + scope-emission tests
# Per [[multi-account-region-cluster-use-case]] + [[profile-generation-quality-bar]]
# the FLOOR is: a profile generated from observing scope A must DENY
# scope B. Without scope preservation in the compactor + scope emission
# in the renderer, generated profiles permit cross-scope traffic by
# default. These tests are the launch-blocker proof.
# ---------------------------------------------------------------------------


def _ibounce_event_with_scope(
    account_id: str, region: str, action: str = "s3:GetObject",
    bucket: str = "reports", verdict: str = "allow",
) -> dict[str, Any]:
    arn = f"arn:aws:s3:{region}:{account_id}:{bucket}"
    svc, op = action.split(":", 1) if ":" in action else (action, "")
    return {
        "_bouncer": "ibounce",
        "time": 1716412800000,
        "activity_name": verdict,
        "unmapped": {"iam_jit": {
            "verdict": verdict,
            "ext": {"aws_region": region, "aws_account_id": account_id},
        }},
        "api": {
            "service": {"name": svc},
            "operation": op,
            "resources": [{"name": bucket, "uid": arn}],
        },
    }


def _kbounce_event_with_scope(
    namespace: str, cluster: str | None = None, verb: str = "list",
    resource: str = "pods",
) -> dict[str, Any]:
    ext: dict[str, Any] = {"namespace": namespace}
    if cluster:
        ext["cluster"] = cluster
    return {
        "_bouncer": "kbounce",
        "time": 1716413100000,
        "activity_name": "allow",
        "unmapped": {"iam_jit": {
            "verdict": "allow",
            "ext": ext,
        }},
        "api": {
            "service": {"name": "k8s"},
            "operation": f"{verb}/{resource}",
            "resources": [{"name": f"{namespace}/{resource}",
                          "uid": f"namespaces/{namespace}/{resource}"}],
        },
    }


def _dbounce_event_with_scope(
    host: str, database: str | None = None, statement: str = "SELECT",
    port: int = 5432,
) -> dict[str, Any]:
    ext: dict[str, Any] = {}
    if database:
        ext["database"] = database
    return {
        "_bouncer": "dbounce",
        "time": 1716413200000,
        "activity_name": statement.lower(),
        "unmapped": {"iam_jit": {"verdict": "allow", "ext": ext}},
        "api": {
            "service": {"name": "postgres"},
            "operation": statement,
            "resources": [{"name": "public.users"}],
        },
        "dst_endpoint": {"hostname": host, "port": port},
    }


def _gbounce_event_with_scope(
    host: str, method: str = "GET", path: str = "/v1/items",
) -> dict[str, Any]:
    return {
        "_bouncer": "gbounce",
        "time": 1716413300000,
        "activity_name": method.lower(),
        "unmapped": {"iam_jit": {"verdict": "allow", "ext": {}}},
        "api": {
            "service": {"name": host},
            "operation": f"{method} {path}",
            "resources": [{"name": path, "uid": f"https://{host}{path}"}],
        },
        "dst_endpoint": {"hostname": host, "port": 443},
    }


def test_compactor_preserves_account_id_for_ibounce_events():
    """The compactor must surface account_id as a first-class key per
    event so the LLM prompt + scope overlay can emit only_account_ids."""
    events = [
        _ibounce_event_with_scope("111122223333", "us-east-1"),
        _ibounce_event_with_scope("999988887777", "us-west-2",
                                  bucket="other"),
    ]
    compacted = pg._compact_audit_events_for_prompt(events)
    ibounce = compacted["ibounce"]
    accounts = {ev.get("account_id") for ev in ibounce}
    assert "111122223333" in accounts
    assert "999988887777" in accounts


def test_compactor_preserves_region_for_ibounce_events():
    events = [
        _ibounce_event_with_scope("111122223333", "us-east-1"),
        _ibounce_event_with_scope("111122223333", "eu-west-1",
                                  bucket="other"),
    ]
    compacted = pg._compact_audit_events_for_prompt(events)
    regions = {ev.get("region") for ev in compacted["ibounce"]}
    assert "us-east-1" in regions
    assert "eu-west-1" in regions


def test_compactor_preserves_namespace_for_kbounce_events():
    events = [
        _kbounce_event_with_scope(namespace="api-staging"),
        _kbounce_event_with_scope(namespace="api-prod", verb="get"),
    ]
    compacted = pg._compact_audit_events_for_prompt(events)
    nss = {ev.get("namespace") for ev in compacted["kbounce"]}
    assert "api-staging" in nss
    assert "api-prod" in nss


def test_compactor_preserves_host_database_for_dbounce_events():
    events = [
        _dbounce_event_with_scope(host="db.staging.internal",
                                  database="analytics"),
        _dbounce_event_with_scope(host="db.prod.internal",
                                  database="orders", statement="INSERT"),
    ]
    compacted = pg._compact_audit_events_for_prompt(events)
    hosts = {ev.get("host") for ev in compacted["dbounce"]}
    dbs = {ev.get("database") for ev in compacted["dbounce"]}
    assert "db.staging.internal" in hosts
    assert "db.prod.internal" in hosts
    assert "analytics" in dbs
    assert "orders" in dbs


def test_compactor_preserves_host_for_gbounce_events():
    events = [
        _gbounce_event_with_scope(host="api.staging.internal"),
        _gbounce_event_with_scope(host="api.prod.internal",
                                  method="POST", path="/v1/orders"),
    ]
    compacted = pg._compact_audit_events_for_prompt(events)
    hosts = {ev.get("host") for ev in compacted["gbounce"]}
    methods = {ev.get("method") for ev in compacted["gbounce"]}
    assert "api.staging.internal" in hosts
    assert "api.prod.internal" in hosts
    assert "GET" in methods
    assert "POST" in methods


def test_generator_emits_only_account_ids_for_ibounce(patch_backend):
    """Observed account 111122223333 → generated profile carries
    only_account_ids=[111122223333]. The client-side scope overlay
    fills this even if the LLM forgets."""
    reply = json.dumps({
        "profiles": [{
            "bouncer": "ibounce",
            "allows": [],
            "denies": [],
            "flagged_for_review": [],
            "skipped": [],
        }],
        "explanation": "ok",
    })
    patch_backend(reply, name="stub")
    events = [
        _ibounce_event_with_scope("111122223333", "us-east-1"),
        _ibounce_event_with_scope("111122223333", "us-east-1",
                                  action="s3:ListBucket"),
    ]
    result = pg.generate_from_audit(
        events=events, time_range="1h",
        add_safety_denies=False, profile_name="scope-acct",
    )
    ibounce = next(p for p in result.bundle if p.bouncer == "ibounce")
    import yaml as _yaml
    parsed = _yaml.safe_load(ibounce.profile_yaml)
    assert parsed.get("only_account_ids") == ["111122223333"]


def test_generator_emits_only_regions_for_ibounce(patch_backend):
    """Observed region us-east-1 → generated profile carries
    only_regions=[us-east-1]."""
    patch_backend(json.dumps({
        "profiles": [{"bouncer": "ibounce", "allows": [], "denies": [],
                       "flagged_for_review": [], "skipped": []}],
        "explanation": "ok",
    }))
    events = [
        _ibounce_event_with_scope("111122223333", "us-east-1"),
    ]
    result = pg.generate_from_audit(
        events=events, time_range="1h",
        add_safety_denies=False, profile_name="scope-region",
    )
    ibounce = next(p for p in result.bundle if p.bouncer == "ibounce")
    import yaml as _yaml
    parsed = _yaml.safe_load(ibounce.profile_yaml)
    assert parsed.get("only_regions") == ["us-east-1"]


def test_generator_emits_only_namespaces_for_kbouncer(patch_backend):
    """Observed namespace api-staging → only_namespaces=[api-staging]."""
    patch_backend(json.dumps({
        "profiles": [{"bouncer": "kbounce", "allows": [], "denies": [],
                       "flagged_for_review": [], "skipped": []}],
        "explanation": "ok",
    }))
    events = [
        _kbounce_event_with_scope(namespace="api-staging"),
        _kbounce_event_with_scope(namespace="api-staging", verb="get"),
    ]
    result = pg.generate_from_audit(
        events=events, time_range="1h",
        add_safety_denies=False, profile_name="scope-ns",
    )
    kb = next(p for p in result.bundle if p.bouncer == "kbounce")
    import yaml as _yaml
    parsed = _yaml.safe_load(kb.profile_yaml)
    assert parsed.get("only_namespaces") == ["api-staging"]


def test_generator_emits_only_hosts_for_dbounce(patch_backend):
    """Observed host db.staging.internal → only_hosts=[db.staging.internal]."""
    patch_backend(json.dumps({
        "profiles": [{"bouncer": "dbounce", "allows": [], "denies": [],
                       "flagged_for_review": [], "skipped": []}],
        "explanation": "ok",
    }))
    events = [
        _dbounce_event_with_scope(host="db.staging.internal",
                                  database="analytics"),
    ]
    result = pg.generate_from_audit(
        events=events, time_range="1h",
        add_safety_denies=False, profile_name="scope-host",
    )
    db = next(p for p in result.bundle if p.bouncer == "dbounce")
    import yaml as _yaml
    parsed = _yaml.safe_load(db.profile_yaml)
    assert parsed.get("only_hosts") == ["db.staging.internal"]
    assert parsed.get("only_databases") == ["analytics"]


def test_generator_emits_only_hosts_for_gbounce(patch_backend):
    """Observed host api.staging.internal → only_hosts=[...]."""
    patch_backend(json.dumps({
        "profiles": [{"bouncer": "gbounce", "allows": [], "denies": [],
                       "flagged_for_review": [], "skipped": []}],
        "explanation": "ok",
    }))
    events = [
        _gbounce_event_with_scope(host="api.staging.internal"),
        _gbounce_event_with_scope(host="api.staging.internal",
                                  method="POST", path="/v1/orders"),
    ]
    result = pg.generate_from_audit(
        events=events, time_range="1h",
        add_safety_denies=False, profile_name="scope-gbounce",
    )
    gb = next(p for p in result.bundle if p.bouncer == "gbounce")
    import yaml as _yaml
    parsed = _yaml.safe_load(gb.profile_yaml)
    assert parsed.get("only_hosts") == ["api.staging.internal"]


def test_deterministic_fallback_emits_scope_for_ibounce(patch_backend):
    """The deterministic-fallback path (LLM unavailable) must ALSO
    emit scope restrictions — observed-account 111 staging must DENY
    222 prod even when the LLM is offline."""
    patch_backend("", name="stub")  # forces deterministic fallback
    events = [
        _ibounce_event_with_scope("111122223333", "us-east-1"),
    ]
    result = pg.generate_from_audit(
        events=events, time_range="1h",
        add_safety_denies=False, profile_name="fallback-scope",
    )
    assert result.parser_strict_match is False
    ibounce = next(p for p in result.bundle if p.bouncer == "ibounce")
    import yaml as _yaml
    parsed = _yaml.safe_load(ibounce.profile_yaml)
    assert parsed.get("only_account_ids") == ["111122223333"]
    assert parsed.get("only_regions") == ["us-east-1"]


def test_floor_failure_observed_scope_a_denies_scope_b(patch_backend, tmp_path):
    """THE END-TO-END FLOOR TEST per
    [[profile-generation-quality-bar]]:

    1. Observe events scoped to account=111 region=us-east-1
    2. Generate profile from them
    3. Save + load through the canonical bouncer profile loader
    4. Attempt cross-account / cross-region request
    5. MUST be DENIED with profile_only_account_ids or
       profile_only_regions

    This is the launch-blocker proof for §A38 + §A39.
    """
    patch_backend("", name="stub")  # deterministic fallback
    events = [
        _ibounce_event_with_scope("111122223333", "us-east-1",
                                  action="s3:GetObject"),
        _ibounce_event_with_scope("111122223333", "us-east-1",
                                  action="s3:ListBucket"),
    ]
    result = pg.generate_from_audit(
        events=events, time_range="1h",
        add_safety_denies=False, profile_name="floor-test",
    )
    out_dir = tmp_path / "bundle"
    pg.save_bundle(result, out_dir)
    # Now load the rendered ibounce profile through the canonical
    # bouncer loader + evaluate cross-account + cross-region.
    from iam_jit.bouncer.profiles import (
        _profile_from_dict, evaluate_profile,
    )
    import yaml as _yaml
    ibounce_yaml_text = (out_dir / "ibounce.yaml").read_text()
    body = _yaml.safe_load(ibounce_yaml_text)
    # The renderer writes profile_name at top-level + scope alongside.
    # _profile_from_dict expects a single profile body.
    body.pop("profile_name", None)
    profile = _profile_from_dict("floor-test", body)
    assert profile.only_account_ids == ("111122223333",)
    assert profile.only_regions == ("us-east-1",)
    # Cross-account request → DENIED
    v = evaluate_profile(profile, account_id="999988887777",
                          region="us-east-1")
    assert v.denied
    assert "profile_only_account_ids" in v.reason
    # Same account, cross-region → DENIED
    v = evaluate_profile(profile, account_id="111122223333",
                          region="eu-west-1")
    assert v.denied
    assert "profile_only_regions" in v.reason
    # Observed account + region → no objection (downstream rules decide)
    v = evaluate_profile(profile, account_id="111122223333",
                          region="us-east-1")
    assert not v.denied


def test_scope_overlay_unions_llm_with_observed(patch_backend):
    """The client-side overlay UNIONs the LLM's scope with observed
    values — an LLM that already emitted only_account_ids gets the
    observed values merged in (not overwritten)."""
    reply = json.dumps({
        "profiles": [{
            "bouncer": "ibounce",
            "only_account_ids": ["111122223333"],  # LLM emitted this
            "allows": [], "denies": [],
            "flagged_for_review": [], "skipped": [],
        }],
        "explanation": "ok",
    })
    patch_backend(reply, name="stub")
    events = [
        # Observed events also include account=999... — the overlay
        # must add it to the LLM's existing scope, not drop it.
        _ibounce_event_with_scope("111122223333", "us-east-1"),
        _ibounce_event_with_scope("999988887777", "us-east-1",
                                  bucket="other"),
    ]
    result = pg.generate_from_audit(
        events=events, time_range="1h",
        add_safety_denies=False, profile_name="union",
    )
    ibounce = next(p for p in result.bundle if p.bouncer == "ibounce")
    import yaml as _yaml
    parsed = _yaml.safe_load(ibounce.profile_yaml)
    # Both observed values present (the LLM's seed value + the overlay's)
    assert set(parsed.get("only_account_ids") or []) == {
        "111122223333", "999988887777",
    }


def test_no_scope_emitted_when_dimension_absent(patch_backend):
    """If a dimension can't be extracted from any observed event, the
    field is NOT emitted (honest: don't fabricate scope). Per
    [[ibounce-honest-positioning]]."""
    patch_backend("", name="stub")  # deterministic fallback
    # ARN without account-id portion + no aws_region in ext.
    events = [{
        "_bouncer": "ibounce",
        "time": 1716412800000,
        "activity_name": "allow",
        "unmapped": {"iam_jit": {"verdict": "allow", "ext": {}}},
        "api": {
            "service": {"name": "s3"},
            "operation": "GetObject",
            "resources": [{"name": "bucket", "uid": "s3://bucket"}],
        },
    }]
    result = pg.generate_from_audit(
        events=events, time_range="1h",
        add_safety_denies=False, profile_name="no-scope",
    )
    ibounce = next(p for p in result.bundle if p.bouncer == "ibounce")
    import yaml as _yaml
    parsed = _yaml.safe_load(ibounce.profile_yaml)
    # No scope fields emitted — operator sees absence rather than guesses.
    assert "only_account_ids" not in parsed
    assert "only_regions" not in parsed
