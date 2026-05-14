# iam-jit demo package

Three story-driven scenarios you can record straight from this
script. Each scenario has:

- **Voiceover** (what to narrate)
- **On-screen text** (what to overlay on the recording)
- **Commands** (what to run in the terminal — outputs match the
  example policies in `examples/demo/`)
- **UI panel** (mock screenshots of the iam-jit admin view; spec
  in each scenario file)

The policies in `examples/demo/` are real and reproducible — score
them locally with the offline CLI to confirm the numbers match
the script before recording.

## The four scenarios

1. **Scenario A — "from file-a-ticket to flow"** (flagship,
   3-4 min). Opens with the OLD workflow (Slack ticket, 2-hour
   round-trip), then shows iam-jit's two modes: *augmented*
   (same humans, faster loop) and *transparent* (low-risk
   grants happen in-flow, only the high-risk amendments page
   a human). The point: iam-jit meets your existing workflow
   where it is.

2. **Scenario B — "the compromised CI pipeline"** (2 min).
   A CI/CD role with narrow, admin-approved permissions is
   hijacked (stolen runner token). The attacker tries to amend
   the role with IAM-escalation primitives. iam-jit re-scores
   the FULL effective policy. Score jumps from 6 to 9.
   Auto-approve refused, admin alerted with the diff. Enterprise
   / security-buyer hook.

3. **Scenario C — "the incentive loop"** (90 sec). A developer's
   first amendment crosses the threshold and routes to admin.
   They don't want to wait. They look at the score breakdown,
   tighten the scope (specific prefix instead of wildcard),
   resubmit. The new request auto-approves. The product
   *trains* hygiene by rewarding tight scope with speed.

4. **Scenario D — "5 minutes to rotate a secret"** (90 sec).
   SRE needs to update one named secret. Today the choices are
   standing `secretsmanager:*` (audit nightmare) or filing a
   ticket and waiting. iam-jit makes the 5-minute just-in-time
   grant routine. Compliance / SRE / DevOps audience.

5. **Scenario E — "The agent guardrail"** (2 min). Developer
   wants to let an AI agent operate on AWS but is worried it
   will break something. With iam-jit: agent has zero standing
   credentials; asks iam-jit per tool-call; low-risk auto-
   approves, medium routes to human, hallucinated escalation
   gets refused at the gate. The single strongest framing for
   the current AI moment.

## How to run the demo locally

```bash
# Score the policies referenced in each scene:
cd ~/repos/iam-roles
bash examples/demo/run-demo.sh
```

Each scenario file under `docs/demo/` is a complete shot list.
Pair with the policy files under `examples/demo/` for the
terminal-output portion of each scene.

## Why this set, in this order

- Scenario A is the **opening hook**: every dev recognizes the
  "blocked by permissions" pain. Lead with it.
- Scenario B is the **enterprise hook**: the security buyer
  needs to know iam-jit is not just convenience — it's a real
  defense layer. The compromise-recovery story sells that.
- Scenario C is the **product moat**: most access-management
  tools punish risk-takers. iam-jit *rewards* hygiene. That's
  the deepest part of the pitch.

Run all three in a single 5-7 minute video if launching with one
flagship demo. Or split into three short clips (90s each) for
landing-page hero, security-team page, and developer-tools page.
