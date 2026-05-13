#!/usr/bin/env python3
"""Adversarial calibration: use the configured LLM to find scorer blind spots.

Pipeline:

  1. Ask the LLM to generate N IAM policies designed to fool the
     deterministic risk scorer. Each comes with a self-reported
     "what's the trick" note.
  2. Run every generated policy through `review.analyze_policy()`
     deterministically.
  3. For each policy where the LLM's expected risk and the scorer's
     verdict diverge, ask the LLM "is the scorer right, or is the
     trick working?" Collect the disagreement set.
  4. Print a structured report so a human reviewer can promote real
     disagreements to `tests/calibration_corpus/bug_regressions/`.

Uses `iam_jit.llm.get_backend()` — same abstraction iam-jit uses at
runtime. That means the SAME script runs against:

  - Local Ollama (qwen / llama) for dev:
      OLLAMA_HOST=http://localhost:11434 IAM_JIT_LLM=ollama \
      IAM_JIT_LLM_MODEL=qwen2.5:14b \
      python scripts/generate-adversarial-policies.py

  - AWS Bedrock (Opus / Sonnet) for production calibration:
      AWS_PROFILE=omise-experimental \
      IAM_JIT_LLM=bedrock \
      IAM_JIT_LLM_MODEL=us.anthropic.claude-opus-4-7 \
      python scripts/generate-adversarial-policies.py

  - Anthropic direct API:
      IAM_JIT_LLM=anthropic IAM_JIT_LLM_MODEL=claude-opus-4-7 \
      ANTHROPIC_API_KEY=sk-... \
      python scripts/generate-adversarial-policies.py

The output is purposely terse — pipe to a file, review with the
team, and promote 1-2 real disagreements to the corpus per run.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

# Make iam_jit importable when running from repo root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from iam_jit import llm as llm_mod
from iam_jit import review


GENERATE_SYSTEM_PROMPT = """You are a security auditor helping CALIBRATE an automated AWS IAM policy risk scorer.

Your job: generate IAM policies that look harmless to an inattentive scorer but contain
a subtle escalation pattern. Focus on patterns rule-based scorers commonly miss:

  - Destructive write actions on a wildcard resource (`s3:DeleteObject` on `*`)
  - Service-wildcard actions on narrow-looking resources
  - `iam:PassRole` on `*` (priv-esc)
  - Read-only access_type with hidden state-changing actions
  - Chained statements where one statement's permissions enable
    abuse of another's
  - Non-obvious cross-service interactions (sts:AssumeRole +
    iam:CreateAccessKey)
  - Wildcard variants in actions (`iam:Create*` vs `iam:*`)

You will return STRICT JSON. No prose, no markdown fences, just JSON.
"""


GENERATE_USER_PROMPT = """Generate {n} adversarial IAM policy examples. Output ONE JSON array.

Each element:
{{
  "trick": "one-sentence description of the escalation pattern",
  "expected_risk": "low" | "medium" | "high",
  "expected_score_range": [min_int, max_int],   // e.g., [7, 10]
  "policy": {{
    "Version": "2012-10-17",
    "Statement": [ ... ]
  }},
  "access_type": "read-only" | "read-write"
}}

Make them realistic — they should look like actual policies a
developer might submit. Don't pad with obvious "iam:*" — go for
subtle patterns. Vary the services (s3, ec2, dynamodb, lambda,
secretsmanager, kms, sts, route53).
"""


EVALUATE_DISAGREEMENT_PROMPT = """An automated risk scorer evaluated this IAM policy:

POLICY:
{policy_json}

SCORER VERDICT:
  score: {score}/10
  risk_factors: {factors}

YOUR EARLIER ASSESSMENT:
  expected_risk: {expected_risk}
  trick: {trick}

The scorer's verdict diverges from your assessment.

Question: is the scorer right, or did the trick work (the scorer missed the escalation)?

Answer in this JSON shape:
{{
  "verdict": "scorer_correct" | "trick_worked",
  "explanation": "1-2 sentence reasoning",
  "suggested_score_range": [min_int, max_int]
}}

If "trick_worked" — explain WHICH specific risk pattern the scorer
missed, so the iam-jit maintainers can add a rule.
"""


def call_llm(backend: llm_mod.LLMBackend, system: str, user: str) -> str:
    """Wrapper that handles the .chat() interface across backends."""
    return backend.chat(
        system_prompt=system,
        messages=[{"role": "user", "content": user}],
    )


def parse_json_with_fallback(text: str) -> Any:
    """LLMs sometimes wrap JSON in markdown fences or add prose.
    Extract the first JSON array or object we can find."""
    text = text.strip()
    # Strip markdown fences if present.
    text = re.sub(r"^```(?:json)?\n?", "", text)
    text = re.sub(r"\n?```$", "", text)
    # Try whole-string parse first.
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # Find first { or [ and last } or ] and try that slice.
    starts = [i for i, c in enumerate(text) if c in "[{"]
    ends = [i for i, c in enumerate(text) if c in "]}"]
    if starts and ends:
        try:
            return json.loads(text[starts[0]:ends[-1] + 1])
        except json.JSONDecodeError:
            pass
    raise ValueError(f"could not parse LLM JSON response: {text[:200]}...")


def score_policy(policy: dict[str, Any], access_type: str) -> review.ReviewAnalysis:
    """Run the deterministic scorer."""
    request = {
        "spec": {
            "access_type": access_type,
            "duration": {"duration_hours": 1},
            "resource_constraints": [],
        }
    }
    return review.analyze_policy(policy, request)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument(
        "-n", "--count", type=int, default=10,
        help="how many adversarial examples to generate (default 10)",
    )
    parser.add_argument(
        "-o", "--output", type=Path, default=None,
        help="write structured report to this file (JSON). Default: stdout.",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="also print the deterministic-scorer factors per example",
    )
    args = parser.parse_args()

    backend = llm_mod.get_backend()
    backend_name = type(backend).__name__
    if isinstance(backend, llm_mod.NoOpBackend):
        print(
            "ERROR: configured LLM backend is NoOp. Set IAM_JIT_LLM=ollama "
            "(+ OLLAMA_HOST) or IAM_JIT_LLM=bedrock (+ IAM_JIT_LLM_MODEL).",
            file=sys.stderr,
        )
        return 2
    print(f"# Using backend: {backend_name}", file=sys.stderr)

    # Step 1: generate
    print(f"# Generating {args.count} adversarial policies…", file=sys.stderr)
    raw = call_llm(
        backend,
        GENERATE_SYSTEM_PROMPT,
        GENERATE_USER_PROMPT.format(n=args.count),
    )
    try:
        generated = parse_json_with_fallback(raw)
    except ValueError as e:
        print(f"ERROR: LLM did not return parseable JSON: {e}", file=sys.stderr)
        print(f"# Raw LLM output:\n{raw}", file=sys.stderr)
        return 3
    # LLMs sometimes wrap the array in an object like
    # {"examples": [...]} or {"policies": [...]}. Unwrap when we
    # see a single-key dict whose value is a list.
    if isinstance(generated, dict):
        list_values = [v for v in generated.values() if isinstance(v, list)]
        if len(list_values) == 1:
            generated = list_values[0]
    if not isinstance(generated, list):
        print(
            f"ERROR: expected JSON array, got {type(generated).__name__}",
            file=sys.stderr,
        )
        return 3

    # Step 2-3: score + evaluate disagreements
    results: list[dict[str, Any]] = []
    skipped_samples: list[str] = []
    for i, entry in enumerate(generated):
        if not isinstance(entry, dict):
            skipped_samples.append(
                f"#{i}: not a dict ({type(entry).__name__})"
            )
            continue
        # Tolerate various shapes the LLM might produce:
        #   - {policy: {...}}                       (canonical)
        #   - {Policy: {...}}                       (capitalized)
        #   - {iam_policy: {...}}                   (snake_case alt)
        #   - {Version: ..., Statement: [...]}      (policy IS the entry)
        policy = None
        for key in ("policy", "Policy", "iam_policy", "IAMPolicy"):
            if key in entry and isinstance(entry[key], dict):
                policy = entry[key]
                break
        if policy is None and "Statement" in entry and "Version" in entry:
            # Entry IS the policy itself
            policy = entry
            # And we lose the trick/expected fields, so synthesize defaults
            entry = {"policy": policy, "trick": "(undocumented)",
                     "expected_risk": "unknown",
                     "expected_score_range": [None, None],
                     "access_type": "read-only"}
        if policy is None:
            skipped_samples.append(
                f"#{i}: no recognizable policy field; keys={list(entry.keys())[:8]}"
            )
            continue

        access_type = entry.get("access_type", "read-only")
        expected_risk = entry.get("expected_risk", "unknown")
        expected_range = entry.get("expected_score_range", [None, None])
        trick = entry.get("trick", "(no trick description)")

        try:
            analysis = score_policy(policy, access_type)
        except Exception as e:
            print(
                f"# scorer crashed on entry #{i} ({trick!r}): {e}",
                file=sys.stderr,
            )
            continue

        score = analysis.risk_score
        factors = list(analysis.risk_factors)

        # Disagreement = scorer's score outside the LLM's predicted range.
        disagreement = False
        if isinstance(expected_range, list) and len(expected_range) == 2:
            lo, hi = expected_range
            if lo is not None and score < lo:
                disagreement = True
            if hi is not None and score > hi:
                disagreement = True
        # Also flag tier mismatches (high expected but low score).
        if expected_risk == "high" and score < 5:
            disagreement = True
        if expected_risk == "low" and score >= 6:
            disagreement = True

        record: dict[str, Any] = {
            "index": i,
            "trick": trick,
            "expected_risk": expected_risk,
            "expected_score_range": expected_range,
            "access_type": access_type,
            "scorer_score": score,
            "scorer_factors": factors,
            "disagreement": disagreement,
            "policy": policy,
        }

        # Step 3: ask LLM to evaluate the disagreement
        if disagreement:
            try:
                eval_raw = call_llm(
                    backend,
                    GENERATE_SYSTEM_PROMPT,
                    EVALUATE_DISAGREEMENT_PROMPT.format(
                        policy_json=json.dumps(policy, indent=2),
                        score=score,
                        factors=factors,
                        expected_risk=expected_risk,
                        trick=trick,
                    ),
                )
                evaluation = parse_json_with_fallback(eval_raw)
                record["llm_evaluation"] = evaluation
            except (ValueError, Exception) as e:
                record["llm_evaluation"] = {"error": str(e)}

        results.append(record)
        print(
            f"# [{i}] score={score} expected={expected_risk} "
            f"disagreement={'YES' if disagreement else 'no'} | {trick[:80]}",
            file=sys.stderr,
        )
        if args.verbose:
            for f in factors:
                print(f"#     factor: {f}", file=sys.stderr)

    # Step 4: report
    disagreements = [r for r in results if r["disagreement"]]
    report = {
        "backend": backend_name,
        "total_generated": len(generated),
        "scored_successfully": len(results),
        "disagreements": len(disagreements),
        "details": results,
    }

    out_text = json.dumps(report, indent=2, default=str)
    if args.output:
        args.output.write_text(out_text)
        print(f"# wrote report to {args.output}", file=sys.stderr)
    else:
        print(out_text)

    print(
        f"\n# SUMMARY: {len(disagreements)} disagreement(s) "
        f"out of {len(results)} scored examples.",
        file=sys.stderr,
    )
    if skipped_samples:
        print(
            f"# {len(skipped_samples)} entries skipped (malformed). Samples:",
            file=sys.stderr,
        )
        for s in skipped_samples[:5]:
            print(f"#   {s}", file=sys.stderr)
    if disagreements:
        print(
            "# Review the disagreements and promote real bugs to "
            "tests/calibration_corpus/bug_regressions/ as YAML files.",
            file=sys.stderr,
        )

    return 0


if __name__ == "__main__":
    sys.exit(main())
