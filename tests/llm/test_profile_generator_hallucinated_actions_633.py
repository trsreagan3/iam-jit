"""#633 — LLM-output parser filters hallucinated IAM action names.

Extends the #580 fix (which filtered hallucinated actions only in the
sibling_action_prefixes lean-permissive expansion path) to the primary
LLM-output parser path in _parse_llm_response.

State-verification per CONTRIBUTING.md:
  * Assert the hallucinated action is NOT in the rendered allows.
  * Assert the flagged_for_review list explains what was dropped.
  * Sabotage check: if the filter is removed, hallucinated action passes
    through — proves the filter is the load-bearing gate.
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
    """Patch `_resolve_backend` to return a stub, with opt-in env."""

    def _make(reply: str, name: str = "stub"):
        def _resolve(preferred: str | None):
            return _StubBackend(reply), name
        monkeypatch.setattr(pg, "_resolve_backend", _resolve)
        monkeypatch.setenv("IAM_JIT_ENABLE_SIDE_LLM", "1")

    return _make


def _sample_events() -> list[dict[str, Any]]:
    return [
        {
            "_bouncer": "ibounce",
            "activity": {
                "service_name": "s3",
                "action_name": "GetObject",
                "resource": {"uid": "arn:aws:s3:::my-bucket/data.json"},
            },
            "time": "2026-05-26T10:00:00Z",
            "status_id": 1,
        }
    ]


def _llm_reply_with_hallucination() -> str:
    """LLM response that includes a real action AND a hallucinated one."""
    payload = {
        "profiles": [
            {
                "bouncer": "ibounce",
                "allows": [
                    {
                        # Real action — must survive.
                        "actions": [
                            "s3:GetObject",
                            # Hallucinated: not in the AWS catalog.
                            "s3:FetchBucketTotally",
                        ],
                        "reason": "observed S3 read traffic",
                    }
                ],
                "denies": [],
                "flagged_for_review": [],
                "skipped": [],
            }
        ],
        "explanation": "test reply",
    }
    return json.dumps(payload)


def _llm_reply_hallucination_only() -> str:
    """LLM response where the ONLY action in a rule is hallucinated."""
    payload = {
        "profiles": [
            {
                "bouncer": "ibounce",
                "allows": [
                    {
                        "actions": ["s3:FetchBucketTotally"],
                        "reason": "ghost action",
                    }
                ],
                "denies": [],
                "flagged_for_review": [],
                "skipped": [],
            }
        ],
        "explanation": "test reply",
    }
    return json.dumps(payload)


# ---------------------------------------------------------------------------
# #633 core: hallucinated action removed + warning surfaces
# ---------------------------------------------------------------------------


def test_hallucinated_action_removed_from_allows(
    patch_backend, monkeypatch: pytest.MonkeyPatch
) -> None:
    """s3:FetchBucketTotally is NOT in the AWS action catalog; the parser
    MUST drop it from the allows section and keep s3:GetObject.

    State-verification: parse the allows section of the rendered YAML and
    confirm the hallucinated action is absent. The action may legitimately
    appear in the flagged_for_review section (that's where the drop warning
    goes), so we inspect the allows block specifically."""
    import re

    patch_backend(_llm_reply_with_hallucination())
    result = pg.generate_from_audit(
        events=_sample_events(),
        time_range="1h",
        add_safety_denies=False,
    )
    for profile in result.bundle:
        yaml_text = profile.profile_yaml
        # Extract the allows section: everything between 'allows:' and the
        # next top-level key ('denies:' or 'flagged_for_review:').
        allows_match = re.search(
            r"\nallows:(.*?)(?=\ndenies:|\nflagged_for_review:|\Z)",
            yaml_text,
            re.DOTALL,
        )
        allows_section = allows_match.group(1) if allows_match else ""
        assert "s3:FetchBucketTotally" not in allows_section, (
            f"#633 regression: hallucinated action in the allows section of "
            f"{profile.bouncer} profile YAML"
        )
        # Real action must survive in the allows section.
        assert "s3:GetObject" in allows_section, (
            f"s3:GetObject is a real action and must appear in the allows "
            f"section of {profile.bouncer} YAML"
        )


def test_hallucinated_action_surfaces_in_flagged_for_review(
    patch_backend,
) -> None:
    """The flagged_for_review list MUST contain an entry mentioning
    the dropped hallucinated action name.

    State-verification: check flagged_for_review tuples."""
    patch_backend(_llm_reply_with_hallucination())
    result = pg.generate_from_audit(
        events=_sample_events(),
        time_range="1h",
        add_safety_denies=False,
    )
    all_flags: list[str] = []
    for profile in result.bundle:
        all_flags.extend(profile.flagged_for_review)
    assert any("FetchBucketTotally" in f for f in all_flags), (
        "#633: dropped hallucinated action must surface in flagged_for_review"
    )


def test_rule_with_only_hallucinated_actions_dropped_entirely(
    patch_backend,
) -> None:
    """If a rule's actions list contains ONLY hallucinated actions, the
    entire rule MUST be dropped. Check: the allows section of the profile
    YAML must not include the hallucinated action."""
    import re

    patch_backend(_llm_reply_hallucination_only())
    result = pg.generate_from_audit(
        events=_sample_events(),
        time_range="1h",
        add_safety_denies=False,
    )
    for profile in result.bundle:
        yaml_text = profile.profile_yaml
        allows_match = re.search(
            r"\nallows:(.*?)(?=\ndenies:|\nflagged_for_review:|\Z)",
            yaml_text,
            re.DOTALL,
        )
        allows_section = allows_match.group(1) if allows_match else ""
        assert "s3:FetchBucketTotally" not in allows_section, (
            "#633: all-hallucinated rule must be dropped entirely from "
            f"the allows section of {profile.bouncer} profile YAML"
        )


# ---------------------------------------------------------------------------
# Sabotage check — proves the filter is the load-bearing gate
# ---------------------------------------------------------------------------


def test_sabotage_without_filter_hallucinated_action_passes_through(
    patch_backend, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If _is_real_aws_action is monkeypatched to always return True,
    hallucinated actions pass through — proves the actual filter is the gate.

    We patch the alias imported into profile_generator (not the source
    module) to be certain we're disabling the filter used in the parser."""
    # Patch the alias directly inside profile_generator's namespace.
    monkeypatch.setattr(pg, "_is_real_aws_action", lambda _: True)

    import re

    patch_backend(_llm_reply_with_hallucination())
    result = pg.generate_from_audit(
        events=_sample_events(),
        time_range="1h",
        add_safety_denies=False,
    )
    # With the filter disabled the hallucinated action SHOULD pass through
    # into the ALLOWS section of the rendered YAML.
    any_has_hallucinated_in_allows = False
    for profile in result.bundle:
        allows_match = re.search(
            r"\nallows:(.*?)(?=\ndenies:|\nflagged_for_review:|\Z)",
            profile.profile_yaml,
            re.DOTALL,
        )
        allows_section = allows_match.group(1) if allows_match else ""
        if "s3:FetchBucketTotally" in allows_section:
            any_has_hallucinated_in_allows = True
            break
    assert any_has_hallucinated_in_allows, (
        "Sabotage check: with is_real_aws_action forced True, hallucinated "
        "action must appear in the allows section — if this fails the "
        "filter has moved elsewhere"
    )
