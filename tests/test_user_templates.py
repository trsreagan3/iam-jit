"""Tests for the per-user template store + MCP tools.

Per [[evolving-preset-library]] pre-launch slice (task #150):
personal-tier templates. Org-tier templates ship post-launch.
"""

from __future__ import annotations

import os
import time
from unittest.mock import patch

import pytest

from iam_jit.mcp_server import (
    _find_similar_templates_for_mcp,
    _handle_request,
    _list_my_templates_for_mcp,
    _save_template_for_mcp,
)
from iam_jit.user_templates_store import (
    InMemoryUserTemplateStore,
    UserTemplate,
    UserTemplateNameTaken,
    UserTemplateNotFound,
    action_overlap_similarity,
    compute_shape_hash,
    find_similar,
    reset_default_store_for_tests,
)


@pytest.fixture(autouse=True)
def _reset_store():
    """Reset the module-level singleton between tests."""
    reset_default_store_for_tests()
    yield
    reset_default_store_for_tests()


def _policy(actions, resource="*"):
    return {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": actions, "Resource": resource}
        ],
    }


# ---------------------------------------------------------------------------
# UserTemplateStore (in-memory)
# ---------------------------------------------------------------------------


def test_store_put_and_get_round_trip() -> None:
    s = InMemoryUserTemplateStore()
    t = UserTemplate(
        template_id="tmpl_1", user_id="alice", name="read-prod-s3",
        policy=_policy("s3:GetObject"), created_at=int(time.time()),
    )
    s.put(t)
    out = s.get("tmpl_1")
    assert out.name == "read-prod-s3"
    assert out.user_id == "alice"


def test_store_get_by_name() -> None:
    s = InMemoryUserTemplateStore()
    s.put(UserTemplate(
        template_id="tmpl_1", user_id="alice", name="read-prod",
        policy=_policy("s3:GetObject"), created_at=0,
    ))
    found = s.get_by_name("alice", "read-prod")
    assert found.template_id == "tmpl_1"
    with pytest.raises(UserTemplateNotFound):
        s.get_by_name("alice", "nonexistent")
    with pytest.raises(UserTemplateNotFound):
        s.get_by_name("bob", "read-prod")  # other user can't see alice's


def test_store_rejects_duplicate_name_per_user() -> None:
    s = InMemoryUserTemplateStore()
    s.put(UserTemplate(
        template_id="tmpl_1", user_id="alice", name="read-prod",
        policy=_policy("s3:GetObject"), created_at=0,
    ))
    with pytest.raises(UserTemplateNameTaken):
        s.put(UserTemplate(
            template_id="tmpl_2", user_id="alice", name="read-prod",
            policy=_policy("s3:ListBucket"), created_at=0,
        ))


def test_store_allows_same_name_different_users() -> None:
    """Per-user namespace — alice and bob can both have 'read-prod'."""
    s = InMemoryUserTemplateStore()
    s.put(UserTemplate(
        template_id="tmpl_1", user_id="alice", name="read-prod",
        policy=_policy("s3:GetObject"), created_at=0,
    ))
    s.put(UserTemplate(
        template_id="tmpl_2", user_id="bob", name="read-prod",
        policy=_policy("dynamodb:GetItem"), created_at=0,
    ))
    assert s.get_by_name("alice", "read-prod").template_id == "tmpl_1"
    assert s.get_by_name("bob", "read-prod").template_id == "tmpl_2"


def test_store_list_for_user_returns_newest_first() -> None:
    s = InMemoryUserTemplateStore()
    s.put(UserTemplate(
        template_id="tmpl_1", user_id="alice", name="old",
        policy=_policy("s3:GetObject"), created_at=100,
    ))
    s.put(UserTemplate(
        template_id="tmpl_2", user_id="alice", name="new",
        policy=_policy("s3:ListBucket"), created_at=200,
    ))
    out = s.list_for_user("alice")
    assert [t.name for t in out] == ["new", "old"]


def test_store_increment_reuse() -> None:
    s = InMemoryUserTemplateStore()
    s.put(UserTemplate(
        template_id="tmpl_1", user_id="alice", name="x",
        policy=_policy("s3:GetObject"), created_at=0, reuse_count=0,
    ))
    s.increment_reuse("tmpl_1")
    s.increment_reuse("tmpl_1")
    assert s.get("tmpl_1").reuse_count == 2


def test_store_isolation_per_user() -> None:
    """Critical: alice cannot see bob's templates."""
    s = InMemoryUserTemplateStore()
    s.put(UserTemplate(
        template_id="tmpl_1", user_id="alice", name="alice-secret",
        policy=_policy("s3:GetObject"), created_at=0,
    ))
    s.put(UserTemplate(
        template_id="tmpl_2", user_id="bob", name="bob-secret",
        policy=_policy("dynamodb:GetItem"), created_at=0,
    ))
    assert {t.name for t in s.list_for_user("alice")} == {"alice-secret"}
    assert {t.name for t in s.list_for_user("bob")} == {"bob-secret"}


# ---------------------------------------------------------------------------
# Similarity / shape-hash helpers
# ---------------------------------------------------------------------------


def test_shape_hash_identical_policies_collide() -> None:
    h1 = compute_shape_hash(_policy("s3:GetObject"))
    h2 = compute_shape_hash(_policy("s3:GetObject"))
    assert h1 == h2


def test_shape_hash_order_insensitive_on_actions() -> None:
    """Same actions in different order = same hash."""
    h1 = compute_shape_hash(_policy(["s3:GetObject", "s3:ListBucket"]))
    h2 = compute_shape_hash(_policy(["s3:ListBucket", "s3:GetObject"]))
    assert h1 == h2


def test_shape_hash_different_actions_differ() -> None:
    h1 = compute_shape_hash(_policy("s3:GetObject"))
    h2 = compute_shape_hash(_policy("s3:PutObject"))
    assert h1 != h2


def test_shape_hash_ignores_sid() -> None:
    p1 = {
        "Version": "2012-10-17",
        "Statement": [{"Sid": "A", "Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}],
    }
    p2 = {
        "Version": "2012-10-17",
        "Statement": [{"Sid": "B", "Effect": "Allow", "Action": "s3:Get*", "Resource": "*"}],
    }
    assert compute_shape_hash(p1) == compute_shape_hash(p2)


def test_action_overlap_identical_is_1() -> None:
    assert action_overlap_similarity(
        _policy(["s3:GetObject", "s3:ListBucket"]),
        _policy(["s3:GetObject", "s3:ListBucket"]),
    ) == 1.0


def test_action_overlap_disjoint_is_0() -> None:
    assert action_overlap_similarity(
        _policy("s3:GetObject"),
        _policy("dynamodb:GetItem"),
    ) == 0.0


def test_action_overlap_partial() -> None:
    """{s3:GetObject, s3:ListBucket, s3:PutObject} vs {s3:GetObject,
    s3:ListBucket} — intersection=2, union=3, similarity = 2/3."""
    sim = action_overlap_similarity(
        _policy(["s3:GetObject", "s3:ListBucket", "s3:PutObject"]),
        _policy(["s3:GetObject", "s3:ListBucket"]),
    )
    assert abs(sim - 2/3) < 0.001


def test_action_overlap_ignores_deny() -> None:
    """Only Allow-statement actions count toward similarity."""
    p1 = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
            {"Effect": "Deny", "Action": "secretsmanager:GetSecretValue", "Resource": "*"},
        ],
    }
    p2 = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
    }
    assert action_overlap_similarity(p1, p2) == 1.0


def test_find_similar_returns_above_threshold_only() -> None:
    s = InMemoryUserTemplateStore()
    s.put(UserTemplate(
        template_id="t1", user_id="alice", name="s3-only",
        policy=_policy("s3:GetObject"), created_at=0,
    ))
    s.put(UserTemplate(
        template_id="t2", user_id="alice", name="dynamodb-only",
        policy=_policy("dynamodb:GetItem"), created_at=0,
    ))
    matches = find_similar(s, "alice", _policy("s3:GetObject"), min_similarity=0.5)
    assert len(matches) == 1
    assert matches[0][0].template_id == "t1"


def test_find_similar_respects_top_k() -> None:
    s = InMemoryUserTemplateStore()
    for i in range(10):
        s.put(UserTemplate(
            template_id=f"t{i}", user_id="alice", name=f"variant-{i}",
            policy=_policy("s3:GetObject"), created_at=0,
        ))
    matches = find_similar(s, "alice", _policy("s3:GetObject"), top_k=3)
    assert len(matches) == 3


def test_find_similar_excludes_other_users() -> None:
    s = InMemoryUserTemplateStore()
    s.put(UserTemplate(
        template_id="t1", user_id="alice", name="alice-template",
        policy=_policy("s3:GetObject"), created_at=0,
    ))
    s.put(UserTemplate(
        template_id="t2", user_id="bob", name="bob-template",
        policy=_policy("s3:GetObject"), created_at=0,
    ))
    matches = find_similar(s, "alice", _policy("s3:GetObject"))
    assert len(matches) == 1
    assert matches[0][0].user_id == "alice"


# ---------------------------------------------------------------------------
# MCP tools — save_template / list_my_templates / find_similar_templates
# ---------------------------------------------------------------------------


def test_mcp_save_template_round_trip() -> None:
    with patch.dict(os.environ, {"IAM_JIT_USER_ID": "alice"}, clear=False):
        result = _save_template_for_mcp({
            "name": "read-prod-s3",
            "policy": _policy("s3:GetObject"),
            "description": "Read from prod-data bucket during incidents",
        })
    assert result["template_id"].startswith("tmpl_")
    assert result["name"] == "read-prod-s3"
    assert result["shape_hash"]  # non-empty


def test_mcp_save_template_rejects_duplicate_name() -> None:
    with patch.dict(os.environ, {"IAM_JIT_USER_ID": "alice"}, clear=False):
        _save_template_for_mcp({
            "name": "dupe", "policy": _policy("s3:GetObject"),
        })
        result = _save_template_for_mcp({
            "name": "dupe", "policy": _policy("s3:ListBucket"),
        })
    assert result["template_id"] is None
    assert "dupe" in result["error"]


def test_mcp_save_template_rejects_missing_name() -> None:
    result = _save_template_for_mcp({"policy": _policy("s3:GetObject")})
    assert result["template_id"] is None
    assert "name" in result["error"]


def test_mcp_save_template_rejects_non_dict_policy() -> None:
    result = _save_template_for_mcp({"name": "x", "policy": "not-a-dict"})
    assert result["template_id"] is None
    assert "policy" in result["error"]


def test_mcp_list_my_templates_returns_user_only() -> None:
    with patch.dict(os.environ, {"IAM_JIT_USER_ID": "alice"}, clear=False):
        _save_template_for_mcp({"name": "a1", "policy": _policy("s3:GetObject")})
        _save_template_for_mcp({"name": "a2", "policy": _policy("s3:PutObject")})
    with patch.dict(os.environ, {"IAM_JIT_USER_ID": "bob"}, clear=False):
        _save_template_for_mcp({"name": "b1", "policy": _policy("dynamodb:GetItem")})
        result = _list_my_templates_for_mcp({})
    # bob only sees bob's
    assert result["total"] == 1
    assert result["templates"][0]["name"] == "b1"


def test_mcp_find_similar_templates_returns_matches() -> None:
    with patch.dict(os.environ, {"IAM_JIT_USER_ID": "alice"}, clear=False):
        _save_template_for_mcp({
            "name": "s3-read", "policy": _policy(["s3:GetObject", "s3:ListBucket"]),
        })
        _save_template_for_mcp({
            "name": "ddb-read", "policy": _policy("dynamodb:GetItem"),
        })
        # Query with a policy similar to s3-read
        result = _find_similar_templates_for_mcp({
            "policy": _policy(["s3:GetObject", "s3:ListBucket"]),
        })
    assert result["total"] == 1
    assert result["matches"][0]["name"] == "s3-read"
    assert result["matches"][0]["similarity"] == 1.0


def test_mcp_find_similar_rejects_non_dict_policy() -> None:
    result = _find_similar_templates_for_mcp({"policy": "not-a-dict"})
    assert result["matches"] == []
    assert "policy" in result["error"]


def test_mcp_find_similar_rejects_bad_top_k() -> None:
    result = _find_similar_templates_for_mcp({
        "policy": _policy("s3:GetObject"), "top_k": 999,
    })
    assert "top_k" in result["error"]


def test_mcp_find_similar_rejects_bool_top_k() -> None:
    """bool subclasses int in Python — reject explicitly (audit-cadence-discipline pattern)."""
    result = _find_similar_templates_for_mcp({
        "policy": _policy("s3:GetObject"), "top_k": True,
    })
    assert "top_k" in result["error"]


def test_mcp_find_similar_rejects_out_of_range_similarity() -> None:
    result = _find_similar_templates_for_mcp({
        "policy": _policy("s3:GetObject"), "min_similarity": 2.0,
    })
    assert "min_similarity" in result["error"]


# ---------------------------------------------------------------------------
# Full dispatch round-trip via tools/call
# ---------------------------------------------------------------------------


def _call(name: str, args: dict) -> dict:
    return _handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": name, "arguments": args},
    })


def test_dispatch_save_template() -> None:
    with patch.dict(os.environ, {"IAM_JIT_USER_ID": "alice"}, clear=False):
        resp = _call("save_template", {
            "name": "test-template", "policy": _policy("s3:GetObject"),
        })
    sc = resp["result"]["structuredContent"]
    assert sc["template_id"].startswith("tmpl_")


def test_dispatch_list_my_templates() -> None:
    with patch.dict(os.environ, {"IAM_JIT_USER_ID": "alice"}, clear=False):
        _call("save_template", {"name": "t1", "policy": _policy("s3:GetObject")})
        resp = _call("list_my_templates", {})
    sc = resp["result"]["structuredContent"]
    assert sc["total"] >= 1


def test_dispatch_find_similar_templates() -> None:
    with patch.dict(os.environ, {"IAM_JIT_USER_ID": "alice"}, clear=False):
        _call("save_template", {"name": "t1", "policy": _policy("s3:GetObject")})
        resp = _call("find_similar_templates", {"policy": _policy("s3:GetObject")})
    sc = resp["result"]["structuredContent"]
    assert sc["total"] >= 1


def test_three_new_tools_appear_in_tools_list() -> None:
    resp = _handle_request({
        "jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {},
    })
    names = {t["name"] for t in resp["result"]["tools"]}
    assert "save_template" in names
    assert "list_my_templates" in names
    assert "find_similar_templates" in names
