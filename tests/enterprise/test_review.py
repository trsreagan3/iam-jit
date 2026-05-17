"""Unit tests for Phase 3 (operator review + apply).

Covers:
  - apply_proposal writes the YAML + an audit row
  - apply_proposal backs up an existing config (creates-never-mutates
    invariant: the file we modified is the iam-jit config file,
    not anything in AWS IAM)
  - review_loop "y" path: writes config + audit
  - review_loop "n" path: writes audit but no config
  - review_loop "edit" path: spawns the editor, re-parses the edited
    YAML, re-prompts on accept
  - review_loop "edit" with invalid YAML: re-prompts without
    losing the original proposal
"""

from __future__ import annotations

import json
import pathlib


from iam_jit.enterprise.proposal import (
    AccountLLMPolicyChoice,
    ProposedConfig,
)
from iam_jit.enterprise.review import (
    apply_proposal,
    diff_against_current,
    review_loop,
)


def _proposal() -> ProposedConfig:
    return ProposedConfig(
        org_context_name="acme",
        account_llm_policies=(
            AccountLLMPolicyChoice(
                account_id="111111111111",
                llm_policy="deterministic_only",
                reason="initial",
            ),
        ),
        recommended_cluster_arns=(),
        recommended_profiles=("dev-only",),
        recommended_bouncer_mode_per_account={"111111111111": "read_write_swap"},
        notes="test",
    )


def test_apply_proposal_writes_config_and_audit(tmp_path: pathlib.Path) -> None:
    cfg = tmp_path / "config.yaml"
    aud = tmp_path / "audit.jsonl"
    decision = apply_proposal(
        _proposal(),
        config_path=cfg,
        audit_path=aud,
        actor="test-operator",
    )
    assert decision.accepted is True
    assert decision.written_config_path == cfg
    assert cfg.exists()
    assert "org_context_name: acme" in cfg.read_text()
    # Audit row is a valid JSON object on a single line.
    lines = aud.read_text().splitlines()
    assert len(lines) == 1
    row = json.loads(lines[0])
    assert row["event"] == "enterprise_bootstrap_review"
    assert row["accepted"] is True
    assert row["actor"] == "test-operator"
    assert row["proposal"]["org_context_name"] == "acme"


def test_apply_proposal_backs_up_existing_config(tmp_path: pathlib.Path) -> None:
    cfg = tmp_path / "config.yaml"
    cfg.write_text("old: content\n")
    aud = tmp_path / "audit.jsonl"
    apply_proposal(
        _proposal(),
        config_path=cfg,
        audit_path=aud,
        actor="op",
    )
    backup = cfg.with_suffix(cfg.suffix + ".bak")
    assert backup.exists()
    assert backup.read_text() == "old: content\n"
    # New config replaced.
    assert "org_context_name: acme" in cfg.read_text()


def test_diff_against_current_when_no_current(tmp_path: pathlib.Path) -> None:
    cfg = tmp_path / "config.yaml"
    diff = diff_against_current(_proposal(), cfg)
    # When there's no current file, the diff still produces SOMETHING
    # showing the new content as added lines.
    assert "+" in diff


def test_diff_against_current_with_existing(tmp_path: pathlib.Path) -> None:
    cfg = tmp_path / "config.yaml"
    cfg.write_text("org_context_name: old\n")
    diff = diff_against_current(_proposal(), cfg)
    assert "-org_context_name: old" in diff
    assert "+org_context_name: acme" in diff


class _Prompter:
    """Replays a scripted list of answers; raises if exhausted."""

    def __init__(self, answers: list[str]) -> None:
        self._answers = list(answers)
        self.calls = 0

    def __call__(self, _q: str) -> str:
        self.calls += 1
        if not self._answers:
            raise AssertionError(
                f"prompter exhausted at call {self.calls}; q={_q!r}"
            )
        return self._answers.pop(0)


class _Echo:
    def __init__(self) -> None:
        self.lines: list[str] = []

    def __call__(self, s: str) -> None:
        self.lines.append(s)


def test_review_loop_accept(tmp_path: pathlib.Path) -> None:
    cfg = tmp_path / "config.yaml"
    aud = tmp_path / "audit.jsonl"
    prompter = _Prompter(["y"])
    echo = _Echo()
    decision = review_loop(
        _proposal(),
        config_path=cfg,
        audit_path=aud,
        actor="op",
        prompt=prompter,
        echo=echo,
    )
    assert decision.accepted is True
    assert cfg.exists()
    rows = aud.read_text().splitlines()
    assert len(rows) == 1
    assert json.loads(rows[0])["accepted"] is True


def test_review_loop_reject(tmp_path: pathlib.Path) -> None:
    cfg = tmp_path / "config.yaml"
    aud = tmp_path / "audit.jsonl"
    prompter = _Prompter(["n"])
    echo = _Echo()
    decision = review_loop(
        _proposal(),
        config_path=cfg,
        audit_path=aud,
        actor="op",
        prompt=prompter,
        echo=echo,
    )
    assert decision.accepted is False
    assert not cfg.exists()  # rejection writes NO config
    rows = aud.read_text().splitlines()
    assert len(rows) == 1
    audit = json.loads(rows[0])
    assert audit["accepted"] is False
    assert audit["rejection_reason"] == "operator rejected"


def test_review_loop_edit_then_accept(tmp_path: pathlib.Path) -> None:
    cfg = tmp_path / "config.yaml"
    aud = tmp_path / "audit.jsonl"
    prompter = _Prompter(["edit", "y"])
    echo = _Echo()

    def fake_editor(argv: list[str]) -> int:
        path = pathlib.Path(argv[-1])
        # Mutate the YAML: rename the org_context.
        original = path.read_text()
        path.write_text(original.replace("acme", "renamed-by-operator"))
        return 0

    decision = review_loop(
        _proposal(),
        config_path=cfg,
        audit_path=aud,
        actor="op",
        prompt=prompter,
        echo=echo,
        editor_spawn=fake_editor,
        editor_cmd="fake-editor",
    )
    assert decision.accepted is True
    assert decision.final_config is not None
    assert decision.final_config.org_context_name == "renamed-by-operator"
    assert "renamed-by-operator" in cfg.read_text()


def test_review_loop_edit_with_garbage_reprompts(tmp_path: pathlib.Path) -> None:
    cfg = tmp_path / "config.yaml"
    aud = tmp_path / "audit.jsonl"
    # Operator picks edit → editor produces unparseable YAML → loop
    # re-prompts → operator picks accept on the ORIGINAL proposal.
    prompter = _Prompter(["edit", "y"])
    echo = _Echo()

    def bad_editor(argv: list[str]) -> int:
        pathlib.Path(argv[-1]).write_text("not: : : valid: yaml: [unclosed")
        return 0

    decision = review_loop(
        _proposal(),
        config_path=cfg,
        audit_path=aud,
        actor="op",
        prompt=prompter,
        echo=echo,
        editor_spawn=bad_editor,
        editor_cmd="fake-editor",
    )
    assert decision.accepted is True
    # Final config is the original (edit discarded).
    assert decision.final_config is not None
    assert decision.final_config.org_context_name == "acme"
    assert any("failed to parse" in line.lower() for line in echo.lines)


def test_review_loop_invalid_answer_reprompts(tmp_path: pathlib.Path) -> None:
    cfg = tmp_path / "config.yaml"
    aud = tmp_path / "audit.jsonl"
    prompter = _Prompter(["maybe", "y"])
    echo = _Echo()
    decision = review_loop(
        _proposal(),
        config_path=cfg,
        audit_path=aud,
        actor="op",
        prompt=prompter,
        echo=echo,
    )
    assert decision.accepted is True
    assert any("y, n, or edit" in line for line in echo.lines)
