"""Tests for the approved-request memory layer.

Covers:
  - sanitization (concrete ARNs become shapes; account stays; resource
    names dropped)
  - storage (file round-trip, dedupe by request_id, max-entries cap)
  - similarity (services Jaccard + account / access-type bonuses)
  - prompt rendering
  - off-by-default behavior (no env, IAM_JIT_MEMORY_DISABLED, no LLM)
"""

from __future__ import annotations

import pathlib

import pytest

from iam_jit import memory


def _request(
    rid: str = "rq",
    *,
    services: list[str] | None = None,
    access_type: str = "read-only",
    account: str = "060392206767",
    resources: list[str] | None = None,
) -> dict:
    services = services or ["s3"]
    resources = resources or ["arn:aws:s3:::my-bucket", "arn:aws:s3:::my-bucket/*"]
    return {
        "metadata": {"id": rid, "name": f"name-{rid}"},
        "spec": {
            "description": "read s3 config",
            "access_type": access_type,
            "accounts": [{"account_id": account}],
            "duration": {"duration_hours": 4},
            "policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [f"{s}:GetObject" for s in services],
                        "Resource": resources,
                    }
                ],
            },
        },
    }


# ---- sanitize ----


def test_sanitize_drops_specific_resource_names() -> None:
    e = memory.sanitize(_request())
    # The bucket name "my-bucket" must NOT appear in the resource shapes.
    assert all("my-bucket" not in r for r in e.resource_shapes)
    # The shape preserves the service prefix and the wildcard suffix.
    assert any(r.startswith("arn:aws:s3:::") and "<resource>" in r for r in e.resource_shapes)
    assert any(r.endswith("/*") for r in e.resource_shapes)


def test_sanitize_keeps_account_id() -> None:
    e = memory.sanitize(_request(account="111122223333"))
    assert e.account_id == "111122223333"


def test_sanitize_extracts_services_in_order_seen() -> None:
    e = memory.sanitize(_request(services=["dynamodb", "s3"]))
    assert set(e.services) == {"dynamodb", "s3"}


def test_sanitize_lambda_arn_drops_function_name() -> None:
    req = _request(
        services=["lambda"],
        resources=["arn:aws:lambda:us-east-1:060392206767:function:my-private-fn"],
    )
    req["spec"]["policy"]["Statement"][0]["Action"] = ["lambda:GetFunction"]
    e = memory.sanitize(req)
    # function name must be replaced
    assert all("my-private-fn" not in r for r in e.resource_shapes)
    assert any("function:<resource>" in r for r in e.resource_shapes)


def test_sanitize_truncates_long_descriptions() -> None:
    req = _request()
    req["spec"]["description"] = "x" * 500
    e = memory.sanitize(req)
    assert len(e.description) <= 200


# ---- store ----


def test_store_round_trip_through_file(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "memory.yaml"
    store = memory.MemoryStore(str(path))
    e1 = memory.sanitize(_request("rq-1"))
    e2 = memory.sanitize(_request("rq-2", services=["lambda"]))
    store.append(e1)
    store.append(e2)
    out = store.all()
    assert {e.request_id for e in out} == {"rq-1", "rq-2"}


def test_store_dedupes_by_request_id(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "memory.yaml"
    store = memory.MemoryStore(str(path))
    store.append(memory.sanitize(_request("rq-1", services=["s3"])))
    store.append(memory.sanitize(_request("rq-1", services=["dynamodb"])))
    out = store.all()
    assert len(out) == 1
    assert "dynamodb" in out[0].services


def test_store_caps_entries(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "memory.yaml"
    store = memory.MemoryStore(str(path), max_entries=3)
    for i in range(5):
        store.append(memory.sanitize(_request(f"rq-{i}")))
    out = store.all()
    assert len(out) == 3
    # Oldest two evicted.
    assert {e.request_id for e in out} == {"rq-2", "rq-3", "rq-4"}


def test_store_file_mode_is_owner_only(tmp_path: pathlib.Path) -> None:
    path = tmp_path / "memory.yaml"
    store = memory.MemoryStore(str(path))
    store.append(memory.sanitize(_request("rq")))
    import stat

    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600


# ---- similarity ----


def test_similarity_prefers_matching_services() -> None:
    entries = [
        memory.sanitize(_request("rq-s3", services=["s3"])),
        memory.sanitize(_request("rq-lambda", services=["lambda"])),
        memory.sanitize(_request("rq-mixed", services=["s3", "logs"])),
    ]
    out = memory.find_similar(
        entries,
        services=["s3"],
        access_type="read-only",
        account_id="060392206767",
        limit=3,
    )
    # rq-s3 should win (perfect Jaccard); rq-mixed second (partial).
    assert out[0].request_id == "rq-s3"


def test_similarity_account_match_bonus() -> None:
    same = memory.sanitize(_request("same", account="111111111111"))
    other = memory.sanitize(_request("other", account="999999999999"))
    out = memory.find_similar(
        [same, other],
        services=["s3"],
        access_type="read-only",
        account_id="111111111111",
    )
    assert out[0].request_id == "same"


def test_similarity_returns_empty_when_no_overlap() -> None:
    entries = [memory.sanitize(_request("a", services=["s3"]))]
    out = memory.find_similar(
        entries, services=["dynamodb"], access_type="", account_id=""
    )
    assert out == []


# ---- prompt rendering ----


def test_render_for_prompt_returns_empty_for_empty_list() -> None:
    assert memory.render_for_prompt([]) == ""


def test_render_for_prompt_includes_services_and_account() -> None:
    e = memory.sanitize(_request("rq", services=["s3", "logs"]))
    out = memory.render_for_prompt([e])
    assert "PAST APPROVED SHAPES" in out
    assert "s3" in out
    assert "logs" in out
    assert "060392206767" in out
    # Specific resource name must NOT leak.
    assert "my-bucket" not in out


# ---- off-switches ----


def test_disabled_when_no_env_var(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("IAM_JIT_MEMORY_FILE", raising=False)
    monkeypatch.delenv("IAM_JIT_MEMORY_DISABLED", raising=False)
    assert not memory.is_enabled()
    assert memory.get_store() is None


def test_disabled_when_explicit_kill_switch_set(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    monkeypatch.setenv("IAM_JIT_MEMORY_FILE", str(tmp_path / "m.yaml"))
    monkeypatch.setenv("IAM_JIT_MEMORY_DISABLED", "1")
    assert not memory.is_enabled()
    assert memory.get_store() is None


def test_disabled_when_no_llm(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    """Memory only feeds the LLM intake prompt — if LLM is off, the
    feature is off too. Recording would be dead weight."""
    monkeypatch.setenv("IAM_JIT_MEMORY_FILE", str(tmp_path / "m.yaml"))
    monkeypatch.delenv("IAM_JIT_MEMORY_DISABLED", raising=False)
    monkeypatch.setenv("IAM_JIT_LLM", "none")
    assert not memory.is_enabled()


def test_enabled_when_file_set_and_llm_on(
    monkeypatch: pytest.MonkeyPatch, tmp_path: pathlib.Path
) -> None:
    monkeypatch.setenv("IAM_JIT_MEMORY_FILE", str(tmp_path / "m.yaml"))
    monkeypatch.delenv("IAM_JIT_MEMORY_DISABLED", raising=False)
    # Force LLM enabled.
    from iam_jit import review

    monkeypatch.setattr(review, "is_review_enabled", lambda: True)
    assert memory.is_enabled()
    store = memory.get_store()
    assert store is not None
