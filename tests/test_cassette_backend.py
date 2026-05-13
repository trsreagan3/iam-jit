"""Unit tests for the cassette/replay LLM wrapper.

These exercise the recording and replay paths without any actual LLM.
The behavioral tests in test_intake_llm.py use the same wrapper against
a real model.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from iam_jit.llm import (
    CassetteMiss,
    RecordingBackend,
    _cassette_key,
    wrap_with_cassette,
)


class _ScriptedBackend:
    """Returns canned responses in order; tracks calls."""

    name = "scripted"

    def __init__(self, responses: list[str]) -> None:
        self.responses = list(responses)
        self.calls: list[dict] = []

    def refine(self, **kw):  # type: ignore[no-untyped-def]
        return [], []

    def chat(self, *, system_prompt, messages):  # type: ignore[no-untyped-def]
        self.calls.append({"system": system_prompt, "messages": messages})
        return self.responses.pop(0) if self.responses else ""


def test_record_writes_cassette(tmp_path: pathlib.Path) -> None:
    inner = _ScriptedBackend(["response-A"])
    cassette = tmp_path / "cassette.jsonl"
    rec = RecordingBackend(inner, cassette_path=cassette, mode="record")

    out = rec.chat(system_prompt="sys", messages=[{"role": "user", "content": "hi"}])
    assert out == "response-A"
    assert cassette.exists()
    entries = [json.loads(line) for line in cassette.read_text().splitlines() if line.strip()]
    assert len(entries) == 1
    assert entries[0]["response"] == "response-A"
    assert "sys" in entries[0]["system_prompt_sample"]


def test_record_dedupes_repeat_prompts(tmp_path: pathlib.Path) -> None:
    """Recording the same (prompt, messages) twice keeps a single entry."""
    inner = _ScriptedBackend(["response-A", "response-B"])
    cassette = tmp_path / "c.jsonl"
    rec = RecordingBackend(inner, cassette_path=cassette, mode="record")

    rec.chat(system_prompt="sys", messages=[{"role": "user", "content": "hi"}])
    rec.chat(system_prompt="sys", messages=[{"role": "user", "content": "hi"}])

    entries = [json.loads(line) for line in cassette.read_text().splitlines() if line.strip()]
    # Same key → second response overwrites first; one entry total.
    assert len(entries) == 1


def test_replay_serves_recorded_response(tmp_path: pathlib.Path) -> None:
    """Record once, then replay against a fresh (empty) backend; the
    recorded response must come back without ever invoking the inner
    backend."""
    cassette = tmp_path / "c.jsonl"
    recorder = RecordingBackend(
        _ScriptedBackend(["recorded"]),
        cassette_path=cassette,
        mode="record",
    )
    recorder.chat(system_prompt="sys", messages=[{"role": "user", "content": "x"}])

    class _RaisingBackend:
        name = "raising"

        def refine(self, **kw):  # type: ignore[no-untyped-def]
            raise AssertionError("should not be called in replay mode")

        def chat(self, *, system_prompt, messages):  # type: ignore[no-untyped-def]
            raise AssertionError("should not be called in replay mode")

    player = RecordingBackend(_RaisingBackend(), cassette_path=cassette, mode="replay")
    out = player.chat(
        system_prompt="sys",
        messages=[{"role": "user", "content": "x"}],
    )
    assert out == "recorded"


def test_replay_raises_on_cassette_miss(tmp_path: pathlib.Path) -> None:
    cassette = tmp_path / "empty.jsonl"
    cassette.write_text("")
    player = RecordingBackend(
        _ScriptedBackend([]), cassette_path=cassette, mode="replay"
    )
    with pytest.raises(CassetteMiss, match="Re-record"):
        player.chat(
            system_prompt="sys", messages=[{"role": "user", "content": "x"}]
        )


def test_cassette_key_is_stable_across_dict_orderings() -> None:
    k1 = _cassette_key("sys", [{"role": "user", "content": "x"}])
    k2 = _cassette_key("sys", [{"content": "x", "role": "user"}])
    assert k1 == k2


def test_cassette_key_changes_with_message_content() -> None:
    k1 = _cassette_key("sys", [{"role": "user", "content": "x"}])
    k2 = _cassette_key("sys", [{"role": "user", "content": "y"}])
    assert k1 != k2


def test_wrap_with_cassette_pass_through_when_env_unset(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("IAM_JIT_LLM_RECORD", raising=False)
    monkeypatch.delenv("IAM_JIT_LLM_REPLAY", raising=False)
    inner = _ScriptedBackend(["x"])
    out = wrap_with_cassette(inner, cassette_path=tmp_path / "c.jsonl")
    assert out is inner  # identity — no wrap


def test_wrap_with_cassette_record_mode_via_env(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("IAM_JIT_LLM_RECORD", "1")
    monkeypatch.delenv("IAM_JIT_LLM_REPLAY", raising=False)
    inner = _ScriptedBackend(["recorded"])
    cassette = tmp_path / "c.jsonl"
    wrapped = wrap_with_cassette(inner, cassette_path=cassette)
    assert isinstance(wrapped, RecordingBackend)
    assert wrapped.mode == "record"
    wrapped.chat(system_prompt="sys", messages=[{"role": "user", "content": "x"}])
    assert cassette.exists()


def test_wrap_with_cassette_replay_mode_via_env(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("IAM_JIT_LLM_REPLAY", "1")
    monkeypatch.delenv("IAM_JIT_LLM_RECORD", raising=False)
    cassette = tmp_path / "c.jsonl"
    cassette.write_text("")
    wrapped = wrap_with_cassette(_ScriptedBackend([]), cassette_path=cassette)
    assert isinstance(wrapped, RecordingBackend)
    assert wrapped.mode == "replay"


def test_wrap_with_cassette_rejects_both_record_and_replay(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("IAM_JIT_LLM_RECORD", "1")
    monkeypatch.setenv("IAM_JIT_LLM_REPLAY", "1")
    with pytest.raises(ValueError, match="mutually exclusive"):
        wrap_with_cassette(_ScriptedBackend([]), cassette_path=tmp_path / "c.jsonl")
