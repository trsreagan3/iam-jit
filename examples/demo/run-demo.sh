#!/usr/bin/env bash
# Score every demo policy and print the expected narrative beats.
# Run from the repo root: bash examples/demo/run-demo.sh
#
# If the scores diverge from what the demo scripts narrate, the
# scorer has shifted and the scenario files need a refresh
# BEFORE recording.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

CLI=".venv/bin/python -m iam_jit.cli_score"

score() {
  local file="$1"
  local label="$2"
  local expected="$3"
  local extra="${4:-}"
  echo
  echo "── $label"
  echo "   expected: $expected"
  echo "   policy:   examples/demo/$file"
  echo
  # shellcheck disable=SC2086
  $CLI --offline "examples/demo/$file" --threshold 5 --access-type read-write $extra | sed 's/^/   /'
  echo
}

echo "═══════════════════════════════════════════════════════════════════"
echo "  iam-jit demo policy scoreboard"
echo "═══════════════════════════════════════════════════════════════════"

echo
echo "▶ Scenario A — 'from file-a-ticket to flow'"
score "01-initial-grant.json"             "Scene 3 — augmented mode initial grant"  "3/10 (low) · auto-approve threshold"
score "02-amendment-with-prod-write.json" "Scene 5 — amendment crosses threshold"   "8/10 (high) · routes to admin review"

echo
echo "▶ Scenario B — 'compromised CI pipeline'"
score "04-cicd-baseline.json"             "Scene 1 — admin-approved pipeline baseline"  "6/10 (high) · admin-approved one-time"
score "05-cicd-compromised-amendment.json" "Scene 2 — attacker amendment attempt"        "9/10 (high) · refused, baseline revoked"

echo
echo "▶ Scenario C — 'incentive loop'"
score "02-amendment-with-prod-write.json" "Scene 1 — first attempt (broad, blocked)"  "8/10 (high) · admin review queued"
score "03-tightened-resubmit.json"        "Scene 3 — tightened resubmit"               "3/10 (low) · auto-approves"

echo
echo "▶ Scenario D — '5 minutes to rotate a secret'"
score "06-secrets-rotation.json"          "Scene 2 — secret-rotation request"  "5/10 (medium) · borderline, admin reviews once"

echo
echo "▶ Scenario E — 'the agent guardrail'"
score "07-agent-read-bucket.json"             "Tool-call 1 — read a bucket"                 "1/10 (low) · auto-approved 15-min role"
score "08-agent-update-lambda.json"           "Tool-call 2 — update one Lambda"              "6/10 (high) · admin reviews"
score "09-agent-hallucinated-iam-star.json"   "Tool-call 3 — hallucinated iam:* request"     "9/10 (high) · refused at the gate"

echo
echo "═══════════════════════════════════════════════════════════════════"
echo "  Done. If any score differs from 'expected', the scorer has"
echo "  drifted and the scenario file's voiceover needs an update."
echo "═══════════════════════════════════════════════════════════════════"
