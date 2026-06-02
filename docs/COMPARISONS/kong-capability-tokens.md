# Kong AI Gateway (Capability Token + AIIC) vs. iam-jit

**What this doc is.** A positioning piece for sales conversations. It draws
the conceptual parallel between Kong AI Gateway's **Capability Token** +
**AI Infrastructure Contracts (AIIC)** model and iam-jit's short-lived,
scoped, per-operation IAM roles — and is honest about where the two actually
differ.

**One-line thesis.** Kong and iam-jit ship the *same idea* — a capability is
a narrow, declared, time-bound grant rather than standing access — at two
*different planes*. Kong governs the **LLM / MCP / A2A orchestration plane**
as a commercial product (publicly listed enterprise pricing in the tens of
thousands of dollars per year). iam-jit governs the **cloud-resource plane**
(AWS IAM actions on real ARNs) as free, open-source software you self-host.
They compose; they don't compete.

> Honest framing per [[ibounce-honest-positioning]], [[competitive-positioning]],
> and [[onecli-competitive-positioning]]: we do not claim Kong is unnecessary,
> nor that iam-jit replaces it. Where the two genuinely differ, this doc states
> the difference factually.

---

## The conceptual mapping

The two products use different vocabulary for structurally similar primitives:

| Kong AI Gateway | iam-jit | What's shared |
|---|---|---|
| **Capability Token** — a scoped, time-bound grant authorizing a specific operation set | **Scoped IAM role + TTL + per-operation grant** — a short-lived principal authorizing exactly the requested AWS actions on the requested ARNs | Both replace standing credentials with a narrow grant issued per task and expiring on its own |
| **AI Infrastructure Contracts (AIIC)** — a declarative statement of which capabilities an agent/workload may hold, enforced at the gateway | **Ambient-config declaration + deterministic scorer + applicability framework** — the declared profile of what a principal may request, gated by a calibrated 1-10 risk score | Both turn "what is this actor allowed to do" into a declarative artifact that a control plane evaluates, rather than a static long-lived policy |
| Token issuance at the gateway (request → policy check → mint) | Request submission → deterministic score → auto-approve gate or human queue ([USE-CASES.md](../USE-CASES.md)) | Both gate issuance on an evaluation step, and both can auto-grant the narrow case and escalate the broad one |
| Orchestration plane: LLM calls, MCP tool calls, agent-to-agent (A2A) | Cloud-resource plane: SigV4-signed AWS API actions on specific ARNs | Both decode the *operation*, not just the destination, before deciding |

The insight worth carrying into a sales conversation: **a customer who already
believes the Kong Capability Token / AIIC story already believes the iam-jit
story.** It is the same principle — capability-as-narrow-declared-grant — applied
one layer down, to the AWS resources the agent's tools eventually touch.

---

## Side-by-side: the same request, two planes

A single agent task — "read one prod config object to debug a flag" — crosses
both planes. Here is how each governs it.

**Kong (orchestration plane).** The agent's call to an MCP tool / LLM endpoint
is checked against its AIIC; the gateway mints (or refuses) a Capability Token
authorizing that tool invocation for a bounded window.

**iam-jit (cloud-resource plane).** When the tool actually needs AWS, the agent
submits the minimal policy:

```jsonc
// What the agent asks iam-jit for
{
  "actions": ["s3:GetObject"],
  "resources": ["arn:aws:s3:::prod-config/feature-flags.json"],
  "ttl_minutes": 60
}
```

iam-jit scores the request deterministically (1-10), and — if it is below the
configured threshold and the environment profile allows — mints a short-lived
role scoped to exactly that one object for 60 minutes, then lets it expire. A
broad request (e.g. `s3:GetObject` on `*`) scores higher and routes to a human
queue instead of auto-granting. See [USE-CASES.md](../USE-CASES.md) for the
auto-approve calibration examples.

Same shape, different wire surface: Kong decides "may this agent call this
tool?"; iam-jit decides "may this principal perform this AWS action on this
ARN, and for how long?"

---

## Where they genuinely differ

Stated factually, not as advantage-claims:

- **Plane.** Kong sits at the LLM / MCP / A2A orchestration boundary. iam-jit
  sits at the AWS IAM action boundary. A Capability Token that authorizes an
  MCP tool call says nothing about which AWS ARNs the downstream code may touch;
  an iam-jit role scoped to one ARN says nothing about which LLM/tool calls the
  agent may make. These are different controls covering different blast radii.
- **Commercial model.** Kong AI Gateway is a commercial product with enterprise
  pricing publicly described in the tens of thousands of dollars per year.
  iam-jit is free and open-source, self-hosted, with zero billing dependency on
  us for the self-hosted path ([[self-host-zero-billing-dependency]]).
- **Enforcement strength.** iam-jit *creates* short-lived scoped principals; the
  real boundary is AWS IAM evaluating those credentials, not iam-jit
  ([[creates-never-mutates]]). We do not claim to be an inline network boundary
  for AWS traffic. (The local-proxy bouncers — ibounce — are an honest
  *deterrent* and dev-loop feedback layer, not a boundary; see
  [[ibounce-honest-positioning]] and [IBOUNCE.md](../IBOUNCE.md).)
- **Scoring vs. contracts.** Kong's AIIC is a declarative contract. iam-jit adds
  a *calibrated deterministic score* on top of the declaration, so a narrow grant
  can auto-approve while a broad one escalates — the latency asymmetry is the
  design lever ([USE-CASES.md](../USE-CASES.md)).

We do **not** claim iam-jit is "the only" capability-token model, nor that it
beats Kong on the orchestration plane — Kong does things at the LLM/MCP/A2A
layer that iam-jit does not attempt.

---

## When to use which

- **Use Kong (or any orchestration-plane gateway)** when the control you need is
  over *which LLM endpoints, MCP tools, or peer agents* a workload may invoke,
  and when you want a commercial, supported gateway product for that plane.
- **Use iam-jit** when the control you need is over *which AWS actions on which
  ARNs, for how long* a principal may perform — issued just-in-time, scored, and
  auto-expiring — at no cost and fully self-hosted.
- **Use both** when an agent both orchestrates (LLM/tool/A2A) *and* eventually
  reaches AWS resources. They cover non-overlapping blast radii.

---

## The "both layers" recipe (defense-in-depth)

The two products are independent controls, which is the point
([[independence-as-security-property]]):

```
Agent task
  │
  ├─ Orchestration plane ─ Kong Capability Token / AIIC
  │     "may this agent call this LLM / MCP tool / peer agent?"
  │
  └─ Cloud-resource plane ─ iam-jit scoped role + TTL
        "may this principal perform this AWS action on this ARN, for 60 min?"
```

A Capability Token that an agent obtains at the orchestration plane does not
widen what iam-jit will grant at the AWS plane, and vice versa. If a
prompt-injection attempt slips a tool call past the orchestration layer, the
AWS-plane grant is still scoped to one ARN with a TTL; if an over-broad AWS
request is submitted, iam-jit's score routes it to a human regardless of what
the orchestration layer allowed. Two independent gates, two independent failure
modes.

This is the same complementary posture we take toward agent harnesses
([[onecli-competitive-positioning]]): iam-jit composes *alongside* the
orchestration-plane control rather than replacing it.

---

## What not to claim about this comparison

- Don't claim iam-jit "replaces" Kong AI Gateway, or that Kong is unnecessary.
  They operate on different planes.
- Don't claim iam-jit is an inline boundary for AWS API traffic — it *creates*
  scoped principals; AWS IAM is the boundary ([[creates-never-mutates]]).
- Don't cite specific Kong pricing as fact beyond the publicly described
  enterprise range; pricing changes and is best confirmed against Kong's current
  published terms at the time of the conversation.
- Don't represent the orchestration-plane and cloud-resource-plane controls as
  redundant — they cover different blast radii.

## See also

- [USE-CASES.md](../USE-CASES.md) — the iam-jit just-in-time scoped-grant workflow
- [IBOUNCE.md](../IBOUNCE.md) — the honest-deterrent local proxy layer
- [COMPETITIVE-PI-ANOMALY-2026-05-24.md](../COMPETITIVE-PI-ANOMALY-2026-05-24.md) — broader competitive scan with the same honest-framing discipline
- [ROADMAP.md](../ROADMAP.md) — where iam-jit is headed
