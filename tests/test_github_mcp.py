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
    bad = _github_scope_self_for_task_for_mcp(
        {"org": "acme", "description": "x", "repositories": ["r", 5], "permissions": {"contents": "read"}}
    )
    assert "error" in bad


def test_handler_high_risk_needs_approval_mints_nothing(monkeypatch, tmp_path) -> None:
    # high-risk scope returns needs_approval BEFORE touching any installation/
    # network — fully hermetic (no registry, no GitHub call).
    monkeypatch.setenv("IAM_JIT_GITHUB_INSTALLATIONS", str(tmp_path / "none.yaml"))
    out = _github_scope_self_for_task_for_mcp(
        {
            "org": "acme",
            "description": "rewrite contents across everything (suspicious)",
            "repositories": [f"r{i}" for i in range(30)],
            "permissions": {"contents": "write"},
        }
    )
    assert out["decision"] == "needs_approval"
    assert out["band"] == "high"
    assert "token" not in out
    assert out["risk_score"] >= 7
