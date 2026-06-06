from __future__ import annotations

from iam_jit.mcp_server import TOOLS, _github_scope_self_for_task_for_mcp


def test_tool_is_registered() -> None:
    names = {t["name"] for t in TOOLS}
    assert "github_scope_self_for_task" in names
    tool = next(t for t in TOOLS if t["name"] == "github_scope_self_for_task")
    assert tool["inputSchema"]["required"] == ["org", "description", "repositories", "permissions"]


def test_handler_validation_errors() -> None:
    assert "error" in _github_scope_self_for_task_for_mcp({})
    assert "error" in _github_scope_self_for_task_for_mcp(
        {"org": "acme", "description": "x", "repositories": [], "permissions": {"contents": "read"}}
    )
    assert "error" in _github_scope_self_for_task_for_mcp(
        {"org": "acme", "description": "x", "repositories": ["r"], "permissions": {}}
    )
    # "all" repos is exactly the footgun — a non-empty list is required, named.
    assert "error" in _github_scope_self_for_task_for_mcp(
        {"org": "acme", "description": "x", "repositories": ["r", 5], "permissions": {"contents": "read"}}
    )
    # unknown permission category is rejected (normalize_permissions)
    assert "error" in _github_scope_self_for_task_for_mcp(
        {"org": "acme", "description": "x", "repositories": ["r"], "permissions": {"frob": "read"}}
    )


def test_handler_submits_into_shared_queue_no_mint(monkeypatch, tmp_path) -> None:
    # The MCP tool submits a GitHubTokenRequest into the SAME request store as
    # AWS roles (pending) — it never mints standalone. Hermetic: a tmp file
    # request store, no GitHub network.
    monkeypatch.setenv("IAM_JIT_REQUESTS_DIR", str(tmp_path / "reqs"))
    monkeypatch.delenv("IAM_JIT_REQUESTS_TABLE", raising=False)
    monkeypatch.delenv("IAM_JIT_STATE_BUCKET", raising=False)
    out = _github_scope_self_for_task_for_mcp(
        {
            "org": "acme",
            "description": "open a PR on web",
            "repositories": ["web", "api"],
            "permissions": {"contents": "read", "pull_requests": "write"},
            "duration_minutes": 30,
        }
    )
    assert out["decision"] == "needs_approval"
    assert "token" not in out
    rid = out["request_id"]
    assert rid.startswith("ghr-")
    assert out["permissions"] == {"contents": "read", "pull_requests": "write"}

    # it actually landed in the shared request store as a pending GitHub request
    from iam_jit.app import _build_request_store_from_env
    stored = _build_request_store_from_env().get(rid)
    assert stored["kind"] == "GitHubTokenRequest"
    assert stored["status"]["state"] == "pending"
    assert stored["spec"]["github"]["repositories"] == ["web", "api"]
