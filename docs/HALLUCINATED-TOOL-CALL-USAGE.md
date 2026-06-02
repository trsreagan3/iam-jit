# Hallucinated-Tool-Call Validator — Operator Guide

Task: #729 (BUILD-8) — validate outbound agent tool-call shapes against
a known-tool schema corpus.

This is the operator-facing companion to
[`HALLUCINATED-TOOL-CALL-DESIGN.md`](HALLUCINATED-TOOL-CALL-DESIGN.md).
The design memo covers the threat model + algorithm; this doc covers
how to turn it on + how to read what it reports.

## What it does

The validator inspects outbound HTTP request bodies that look like
tool calls (MCP `tools/call`, OpenAI `tool_calls` / `function_call`,
Anthropic `tool_use`) and reports calls whose:

1. **name** isn't in the known-tool corpus (the agent hallucinated a
   tool that doesn't exist) — `hallucinated-tool-name` indicator
2. **arguments** are missing a required schema field —
   `missing-required-arg`
3. **arguments** include a placeholder credential like `"YOUR_API_KEY"`
   or `"REPLACE_ME"` — `placeholder-credential`
4. **arguments** include a field not in the schema — `unexpected-arg`
5. **name** mixes snake_case and camelCase — `naming-style-mix`

## Where it runs

Three deployment surfaces:

| Surface | Where to enable |
|---|---|
| gbounce MITM mode (the default) | `validate_tool_calls.enabled: true` in profile YAML |
| Agent harness pre-flight | Call MCP tool `iam_jit_validate_tool_call` before emitting the call |
| Python library (any service) | `from iam_jit.tool_call_validator import validate` |

The gbounce wire-up is the canonical deployment for v1.0. The MCP tool
is the defense-in-depth path: even when no bouncer is in line, the
agent itself can self-validate before emitting a call.

## Enabling in gbounce

Add a `validate_tool_calls` block to the relevant profile in
`~/.gbounce/profiles.yaml`:

```yaml
profiles:
  prod-strict:
    description: "Production — deny hallucinated tool calls"
    validate_tool_calls:
      enabled: true
      action: deny  # warn | strip | deny
      min_confidence_for_deny: 0.7
      allowlist_patterns:
        - my_org_internal_tool_   # regex
```

Start gbounce in MITM mode + select the profile:

```
gbounce run --mode mitm --profile prod-strict --port 8769
```

Confirm the feature is active:

```
curl http://127.0.0.1:8769/admin/features | jq '.features[] | select(.name == "validate_tool_calls")'
```

Expected (right after start, before any traffic):

```json
{
  "name": "validate_tool_calls",
  "enabled": true,
  "fire_count_total": 0,
  "configured_but_never_fired": true,
  "detail_hint": "enable in profile + send a hallucinated MCP/OpenAI/Anthropic tool-call JSON body through the MITM proxy"
}
```

After a hallucinated call has been intercepted, `fire_count_total > 0`
and `configured_but_never_fired: false`.

## Action modes

| Mode | What happens |
|---|---|
| `warn` | Request forwarded as-is; `X-IAM-JIT-Hallucinated-Tool-Call` header added; audit event has `tool_call_validator_detected=true` |
| `strip` | The hallucinated call sub-structure is replaced with a redaction marker in the body; the sanitized body is forwarded to upstream |
| `deny` | The request never reaches upstream; gbounce returns `422 Unprocessable Entity` with a structured `caught_by_bouncer` JSON body |

`deny` is the strongest signal — the harness sees the 422 + can prompt
the agent to self-correct. `warn` is observability-only. `strip` is
useful when you want forward progress (the upstream tool runner rejects
the marker shape itself, so the agent sees an honest "no such tool"
error rather than a silent hijack).

### Confidence floor

`min_confidence_for_deny` (default 0.7) downgrades `deny` to `warn`
when the validator's confidence is below the floor. The confidence
table is in the design memo:

- 2+ high indicators → confidence 0.95
- 1 high + 1+ medium → 0.85
- 1 high → 0.80
- 2+ medium → 0.55
- 1 medium → 0.35 (always treated as `allow` by the suggested-action)

A tool name not in the corpus with a placeholder credential in its
arguments fires TWO high indicators → confidence 0.95 → always denies.

## Reading the deny body

```
HTTP/1.1 422 Unprocessable Entity
Content-Type: application/json

{
  "caught_by_bouncer": "gbounce",
  "reason": "hallucinated_tool_call_shape",
  "host": "api.openai.com",
  "confidence": 0.95,
  "indicators": [
    {
      "rule": "hallucinated-tool-name",
      "shape": "openai",
      "tool_name": "exfiltrate_secrets",
      "severity": "high",
      "source": "iam-jit",
      "reason": "tool 'exfiltrate_secrets' not in known openai corpus (4 known tools)"
    },
    {
      "rule": "placeholder-credential",
      "shape": "openai",
      "tool_name": "exfiltrate_secrets",
      "severity": "high",
      "source": "iam-jit",
      "reason": "argument 'api_key' value looks like an LLM placeholder ('YOUR_API_KEY')"
    }
  ],
  "extracted_calls": [
    {"shape": "openai", "name": "exfiltrate_secrets"}
  ],
  "deny_source": "tool_call_validator"
}
```

Forwarding agents read `caught_by_bouncer` to recognize this is a
gbounce-injected response, `reason` to know the category, and the
`indicators` list to surface a self-correctable error to the LLM.

## Reading the audit event

The OCSF event for a fired validator carries these extra fields under
`unmapped.iam_jit.ext`:

- `tool_call_validator_detected: true`
- `tool_call_validator_action: "warn" | "strip" | "deny"`
- `tool_call_validator_confidence: 0.0-1.0`
- `tool_call_validator_indicators: [...]`
- `tool_call_validator_extracted_calls: [...]`

Query a SIEM for these fields to track which agents/sessions fired the
validator + which tools were hallucinated.

## Custom corpus

The baked-in corpus covers MCP standard methods + the OpenAI and
Anthropic built-in tools each provider documents. Operators with
custom tools have two choices:

1. **Allowlist** — add a regex to `allowlist_patterns` so calls
   matching it skip the validator entirely.
2. **Custom corpus** (v1.1+) — set `schema_corpus_path` to a YAML /
   JSON file with your tool catalog. The runtime loader for this
   field is still TBD; for v1.0 the corpus override path is honored
   only by the Python lib + the MCP tool (`iam_jit_validate_tool_call`
   with `schema_corpus_path=...`).

Corpus file format:

```yaml
tools:
  - name: my_org_send_email
    shape: mcp     # or openai | anthropic
    required: [to, subject]
    optional: [body, attachments]
    source: my-org-tool-catalog
    note: Internal email-sending tool
  - name: my_org_query_db
    shape: openai
    required: [query]
    optional: [max_rows]
    source: my-org-tool-catalog
```

Operator entries WIN on collision with the baked-in corpus.

## Using the MCP tool for pre-flight

Agents can pre-flight a planned call BEFORE emitting it. From the
agent's tool palette:

```
iam_jit_validate_tool_call(
  body='{"jsonrpc":"2.0","method":"tools/call","params":{"name":"send_email","arguments":{"to":"x@y.com"}}}',
  mode='warn'
)
```

Response:

```json
{
  "detected": true,
  "indicators": [
    {
      "rule": "hallucinated-tool-name",
      "shape": "mcp",
      "tool_name": "send_email",
      "severity": "high",
      "source": "iam-jit",
      "reason": "tool 'send_email' not in known mcp corpus (8 known tools)"
    }
  ],
  "confidence": 0.8,
  "suggested_action": "warn",
  "decided_action": "warn",
  "extracted_calls": [["mcp", "send_email"]]
}
```

The agent sees the indicators + can adjust the plan (look up real
tool names via `tools/list`, ask the user, etc.) before the failed
call burns conversation context.

## Honesty bar

Per [[ibounce-honest-positioning]]:

1. Every indicator carries `rule` + `shape` + `tool_name` + `severity`
   + `source` + a human-readable `reason`. No silent fails.
2. Baked-in corpus entries CITE the source documentation page in the
   `source` field. Operator-supplied entries inherit the operator's
   `source`.
3. The "95% catch rate" claim from the competitive-firewall PDF is
   INTENTIONALLY NOT in code/docs/marketing until we've calibrated
   against a real corpus of hallucinated vs. legitimate tool calls. A
   follow-up calibration task is filed; until it lands, treat catch
   rate as unmeasured.

## Out of scope (v1.0)

- Semantic aliasing (`send_email` → `Email.send`). The corpus is
  exact-string. Adding aliasing is a v1.1 calibration task.
- Streaming tool-use deltas on the Anthropic Messages stream. The
  validator inspects complete request bodies; partial streaming
  shapes are a v1.1 task.
- Full JSON-schema type validation. We validate presence/absence of
  field names, not field-value types. Type checking is a v1.1 task
  once we measure false-positive rates from the simpler check.
