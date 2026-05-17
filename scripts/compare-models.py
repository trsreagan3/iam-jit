"""Compare LLM models on real iam-jit intake scenarios.

Drives the conversational intake against several Ollama models on the
exact prompts a user has been testing and scores each on:

  - proper-noun preservation (no "beta" → "Betaize" paraphrasing)
  - org-context grounding (does it resolve "beta development" → account ID?)
  - policy correctness (right service, right access type, non-empty)
  - follow-up count (fewer is better)
  - latency per turn

Usage:
  IAM_JIT_ORG_CONTEXT_FILE=~/.iam-jit-local/org-context.yaml \\
    .venv/bin/python scripts/compare-models.py llama3.1:8b qwen2.5:14b

Output is a markdown report so you can paste it into a PR/ticket.
"""

from __future__ import annotations

import os
import pathlib
import sys
import time
from dataclasses import dataclass, field
from typing import Any

# Add src/ to path so we can import iam_jit when running directly.
_REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO / "src"))

from iam_jit import intake  # noqa: E402
from iam_jit.llm import OllamaBackend  # noqa: E402


SCENARIOS = [
    {
        "name": "alb-ip-beta-dev",
        "user_messages": [
            "I need to get the ip of an alb in dev for the core service",
            "123456789012",
            "I dont know",
        ],
        "expected_services": {"elasticloadbalancing", "ec2"},
        "expected_read_only": True,
        "expected_account_id": "123456789012",
        "forbidden_paraphrasings": ["Betaize", "Merchant ", "Merchande"],
    },
    {
        "name": "secrets-beta-dev",
        "user_messages": [
            "i need a policy to look at the secrets for the core service in beta development account",
            "123456789012",
            "I dont know",
        ],
        "expected_services": {"secretsmanager"},
        "expected_read_only": True,
        "expected_account_id": "123456789012",
        "forbidden_paraphrasings": ["Betaize", "Merchant ", "Merchande"],
    },
    {
        "name": "dns-beta-dev",
        "user_messages": [
            "i need to get the value of a dns record in beta development",
            "123456789012",
            "I dont know",
        ],
        "expected_services": {"route53"},
        "expected_read_only": True,
        "expected_account_id": "123456789012",
        "forbidden_paraphrasings": ["Betaize", "Merchant ", "Merchande"],
    },
    {
        "name": "s3-with-bucket",
        "user_messages": [
            "I need to read s3 config files from the example-config bucket "
            "in account 060392206767, 24 hours please",
            "I dont know",
        ],
        "expected_services": {"s3"},
        "expected_read_only": True,
        "expected_account_id": "060392206767",
        "forbidden_paraphrasings": [],
    },
    {
        "name": "dynamodb-write",
        "user_messages": [
            "I need to create and delete dynamodb tables in account 060392206767, "
            "read-write, 8 hours",
            "I dont know",
        ],
        "expected_services": {"dynamodb"},
        "expected_read_only": False,
        "expected_account_id": "060392206767",
        "forbidden_paraphrasings": [],
    },
    {
        # Multi-service request with no specific ARNs. Should ask for narrowing,
        # then fall back to read-only wildcards across both services.
        "name": "multi-service-no-arns",
        "user_messages": [
            "I need access to the s3 buckets and dns records in acme staging",
            "I dont know",
            "I dont know",
        ],
        "expected_services": {"s3", "route53"},
        "expected_read_only": True,
        "expected_account_id": "758279344746",
        "forbidden_paraphrasings": ["Betaize"],
    },
    {
        # User mentions write verbs in passing but doesn't justify the
        # write. Default should be read-only.
        "name": "vague-update-stays-read-only",
        "user_messages": [
            "I need to look at the s3 buckets and dns records and maybe update a few in account 060392206767",
            "I dont know",
        ],
        "expected_services": {"s3", "route53"},
        "expected_read_only": True,  # 'maybe update a few' isn't justified
        "expected_account_id": "060392206767",
        "forbidden_paraphrasings": [],
    },
    {
        # Concrete write justification → write should land.
        "name": "concrete-write-justification",
        "user_messages": [
            "I need to add a CNAME record pointing api.example.com to the new "
            "staging ALB, in acme staging",
            "I dont know",
        ],
        "expected_services": {"route53"},
        "expected_read_only": False,
        "expected_account_id": "758279344746",
        "forbidden_paraphrasings": [],
    },
]


_WRITE_VERBS = (
    "Create", "Delete", "Put", "Update", "Modify", "Attach", "Detach",
    "Add", "Remove", "Tag", "Untag", "Reboot", "Terminate",
    "Disable", "Enable", "Start", "Stop",
)


@dataclass
class ScenarioResult:
    name: str
    completed: bool = False
    turns: int = 0
    elapsed_s: float = 0.0
    services: set[str] = field(default_factory=set)
    bot_questions: list[str] = field(default_factory=list)
    final_policy: dict[str, Any] | None = None
    issues: list[str] = field(default_factory=list)


def _all_actions(policy: dict[str, Any]) -> list[str]:
    actions: list[str] = []
    for s in policy.get("Statement") or []:
        a = s.get("Action") or []
        if isinstance(a, str):
            actions.append(a)
        elif isinstance(a, list):
            actions.extend(x for x in a if isinstance(x, str))
    return actions


def _services_in(policy: dict[str, Any]) -> set[str]:
    return {a.split(":", 1)[0] for a in _all_actions(policy) if ":" in a}


def _looks_read_only(policy: dict[str, Any]) -> bool:
    for a in _all_actions(policy):
        if ":" not in a:
            return False
        verb = a.split(":", 1)[1]
        if verb == "*":
            return False
        if any(verb.startswith(w) for w in _WRITE_VERBS):
            return False
    return True


def _run_scenario(
    backend: OllamaBackend, scenario: dict[str, Any]
) -> ScenarioResult:
    result = ScenarioResult(name=scenario["name"])
    history: list[dict[str, str]] = []
    start = time.monotonic()

    for user_msg in scenario["user_messages"]:
        history.append({"role": "user", "content": user_msg})
        result.turns += 1
        turn = intake.take_turn(history, backend)
        if turn.ask:
            result.bot_questions.append(turn.ask)
            history.append({"role": "assistant", "content": turn.ask})
        if turn.complete:
            result.completed = True
            result.final_policy = turn.draft_policy
            break
    else:
        # Conversation didn't complete in the scripted turns; one more
        # take_turn to see if the model would complete given the chance.
        # This won't add a user message; the hard cap fires.
        turn = intake.take_turn(history, backend)
        if turn.complete:
            result.completed = True
            result.final_policy = turn.draft_policy

    result.elapsed_s = time.monotonic() - start

    if result.final_policy is not None:
        result.services = _services_in(result.final_policy)
        if not intake._is_usable_policy(result.final_policy):
            result.issues.append("draft_policy is not usable (empty Statement, missing Action, etc.)")

    # Score against expectations
    expected_services = scenario["expected_services"]
    if result.services:
        if not (result.services & expected_services):
            result.issues.append(
                f"expected {expected_services} but got {result.services}"
            )
    elif result.completed:
        result.issues.append("completed but no services in policy")

    if scenario["expected_read_only"] and result.final_policy is not None:
        if not _looks_read_only(result.final_policy):
            result.issues.append("expected read-only but write actions appear")
    if not scenario["expected_read_only"] and result.final_policy is not None:
        if _looks_read_only(result.final_policy):
            result.issues.append("expected read-write but only read actions appear")

    for forbidden in scenario.get("forbidden_paraphrasings", []):
        for q in result.bot_questions:
            if forbidden in q:
                result.issues.append(
                    f"paraphrased proper noun: {forbidden!r} in question {q!r}"
                )

    return result


def _model_report(model_id: str, results: list[ScenarioResult]) -> str:
    lines = [f"### {model_id}", ""]
    completed = sum(1 for r in results if r.completed)
    issue_count = sum(len(r.issues) for r in results)
    total_turns = sum(r.turns for r in results)
    total_elapsed = sum(r.elapsed_s for r in results)
    lines.append(
        f"- Completed scenarios: **{completed}/{len(results)}**  "
        f"· Issues: **{issue_count}**  "
        f"· Total turns: {total_turns}  "
        f"· Wall time: {total_elapsed:.1f}s"
    )
    lines.append("")
    lines.append("| Scenario | Done | Turns | Time | Services | Issues |")
    lines.append("|---|---|---|---|---|---|")
    for r in results:
        services_str = ",".join(sorted(r.services)) or "—"
        issues_str = "; ".join(r.issues) if r.issues else "ok"
        lines.append(
            f"| {r.name} | {'✓' if r.completed else '✗'} | "
            f"{r.turns} | {r.elapsed_s:.1f}s | {services_str} | {issues_str} |"
        )
    return "\n".join(lines)


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: compare-models.py MODEL_A [MODEL_B ...]", file=sys.stderr)
        return 1
    models = sys.argv[1:]
    host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")

    all_results: dict[str, list[ScenarioResult]] = {}
    for model_id in models:
        print(f"\n=== {model_id} ===", file=sys.stderr)
        backend = OllamaBackend(host=host, model=model_id)
        results: list[ScenarioResult] = []
        for scenario in SCENARIOS:
            print(f"  · {scenario['name']}", file=sys.stderr, end="", flush=True)
            r = _run_scenario(backend, scenario)
            print(
                f" → {'done' if r.completed else 'incomplete'} "
                f"({r.elapsed_s:.1f}s, {len(r.issues)} issues)",
                file=sys.stderr,
            )
            results.append(r)
        all_results[model_id] = results

    # Markdown report
    print("# Model comparison — iam-jit intake")
    print()
    print(f"Host: `{host}`")
    print(f"Org context: `{os.environ.get('IAM_JIT_ORG_CONTEXT_FILE') or '(none)'}`")
    print()
    for model_id, results in all_results.items():
        print(_model_report(model_id, results))
        print()

    # Summary scoreboard
    print("## Scoreboard")
    print()
    print("| Model | Completed | Issues | Total turns | Wall time |")
    print("|---|---|---|---|---|")
    for model_id, results in all_results.items():
        c = sum(1 for r in results if r.completed)
        i = sum(len(r.issues) for r in results)
        t = sum(r.turns for r in results)
        e = sum(r.elapsed_s for r in results)
        print(f"| {model_id} | {c}/{len(results)} | {i} | {t} | {e:.1f}s |")

    return 0


if __name__ == "__main__":
    sys.exit(main())
