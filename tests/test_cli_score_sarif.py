"""Tests for the SARIF output mode of `iam-risk-score`.

SARIF (Static Analysis Results Interchange Format) is OASIS-
standard JSON consumed natively by GitHub Code Scanning, GitLab
Code Quality, and most security-CI tooling. The CLI's `--format
sarif` is the high-leverage CI integration substrate: one output,
broad reach.

These tests pin:
  - the SARIF skeleton conforms to 2.1.0 (top-level shape);
  - failing policies emit `level=error` results;
  - passing policies still emit at least one result so CI artifacts
    aren't empty;
  - the policy fingerprint propagates to partialFingerprints (CI
    deduplication relies on it).
"""

from __future__ import annotations

import json

from iam_jit import cli_score


_ADMIN_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Action": "*", "Resource": "*"}
    ],
}

_TIGHT_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": "arn:aws:s3:::my-bucket/data/*",
        }
    ],
}


def _score_offline(policy: dict) -> dict:
    return cli_score._score_offline({"policy": policy})


def _sarif(policy: dict, threshold: int = 5, policy_path: str = "policy.json") -> dict:
    result = _score_offline(policy)
    raw = cli_score._format_sarif(result, threshold, policy_path=policy_path)
    return json.loads(raw)


def test_sarif_top_level_shape() -> None:
    sarif = _sarif(_ADMIN_POLICY)
    assert sarif["version"] == "2.1.0"
    assert sarif["$schema"].startswith("https://")
    assert isinstance(sarif["runs"], list) and len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "iam-risk-score"
    assert run["tool"]["driver"]["version"] == cli_score.__version__
    assert run["tool"]["driver"]["informationUri"].startswith("https://")
    assert isinstance(run["results"], list)


def test_sarif_admin_policy_emits_error_level() -> None:
    sarif = _sarif(_ADMIN_POLICY)
    run = sarif["runs"][0]
    # At least one result, all at error level (admin = FAIL @ threshold 5)
    assert len(run["results"]) >= 1
    for r in run["results"]:
        assert r["level"] == "error"
        assert r["ruleId"].startswith("iam-risk-score/")
        # Each result has a location → artifactLocation → uri
        loc = r["locations"][0]["physicalLocation"]["artifactLocation"]
        assert loc["uri"]


def test_sarif_tight_policy_still_emits_a_result() -> None:
    """A passing policy should still produce a SARIF artifact with at
    least one result so CI consumers can prove the scanner ran. An
    empty results array makes CIs treat the job as "no findings"
    which is indistinguishable from "scanner didn't run."""
    sarif = _sarif(_TIGHT_POLICY)
    run = sarif["runs"][0]
    assert len(run["results"]) >= 1
    # Levels are tier-driven, not severity-of-absence
    for r in run["results"]:
        assert r["level"] in {"note", "warning", "error"}


def test_sarif_stdin_path_becomes_synthetic_uri() -> None:
    sarif = _sarif(_ADMIN_POLICY, policy_path="-")
    locs = sarif["runs"][0]["results"][0]["locations"]
    uri = locs[0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "stdin://policy.json"


def test_sarif_threshold_drives_pass_fail_flag() -> None:
    sarif_pass = _sarif(_TIGHT_POLICY, threshold=5)
    sarif_fail = _sarif(_ADMIN_POLICY, threshold=5)
    assert sarif_pass["runs"][0]["properties"]["iam_jit.pass"] is True
    assert sarif_fail["runs"][0]["properties"]["iam_jit.pass"] is False


def test_sarif_fingerprint_propagates() -> None:
    sarif = _sarif(_ADMIN_POLICY)
    pf = sarif["runs"][0]["results"][0].get("partialFingerprints") or {}
    fp = pf.get("policy.fingerprint/v1", "")
    assert fp.startswith("sha256:")


def test_sarif_properties_carry_score_metadata() -> None:
    sarif = _sarif(_ADMIN_POLICY, threshold=7)
    props = sarif["runs"][0]["properties"]
    assert isinstance(props["iam_jit.score"], int)
    assert props["iam_jit.tier"] in {"low", "medium", "high"}
    assert props["iam_jit.threshold"] == 7
    assert props["iam_jit.analyzer"]
