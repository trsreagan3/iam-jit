# Hallucinated-Tool-Call Validator — Design Memo

Task: #729 (BUILD-8) — validate OUTBOUND agent tool-call shapes against a
known schema corpus and reject calls whose name + arguments don't match any
real tool.

## Background

The competitive-firewall landscape PDF ranks **hallucinated tool calls** as
the single highest individual catch-rate (~95%) of the differentiators it
profiles. The phenomenon:

1. LLM agents are good at *imagining* tool names that *should* exist
   ("`send_email`", "`get_credit_card`") when the upstream actually offers
   none of those, or offers a similarly-named one with a different schema
   ("`Email.send`" with `recipient` not `to`)
2. The agent emits the hallucinated call shape as if it were real
3. The tool runner either errors (best case — observable failure) or
   silently misbehaves (worst case — wrong-tool, right-error-code shape)
4. Even on error, the agent's downstream reasoning is polluted by the
   pretend-success or the confusing failure mode; the agent commonly
   doubles down rather than self-correcting

The fix is shape-validation BEFORE the call reaches the upstream: if the
call doesn't match a known tool schema, return a structured 4xx that the
harness surfaces to the agent with a clear reason. The agent then
self-corrects on its next turn.

This is the response-side / request-side mirror of BUILD-9 (#730 indirect
prompt-injection response scanner): BUILD-9 inspects the upstream's
response; BUILD-8 inspects the agent's outbound request. The two together
form the gbounce **request-and-response-body inspection cluster**.

## Threat model

| Threat | Surface | Catch |
|---|---|---|
| Hallucinated tool name (no real tool by that name) | MCP `tools/call`, OpenAI function-call, Anthropic tool-use | exact-name corpus check |
| Real tool, wrong arguments (missing required, extra disallowed) | same | per-tool JSON-schema check |
| Real tool, placeholder credentials (`"your_api_key"`, `"REPLACE_ME"`) | same | argument-value heuristics |
| Hallucination tell — camelCase/snake_case mix in a single name | same | name-shape heuristic |
| Forged tool envelope inside a non-tool POST body | any POST | envelope detection only when JSON shape matches |

Out of scope (deferred):
- Semantic-level "the arguments are valid for the schema but harmful"
  detection. That's what the existing dynamic-deny + structured-deny +
  injection-scanner stack covers; this validator is **structural**.
- LLM-based semantic match for tool aliasing (`send_email` →
  `Email.send`). The corpus is exact-string for v1.0; aliasing is a
  v1.1 follow-up.

## Wire shapes — what we inspect

### 1. MCP `tools/call`

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "tool_name_here",
    "arguments": { ... }
  }
}
```

- Validation: `params.name` is in `schema_corpus["mcp"]`; `params.arguments`
  is a dict whose keys are a subset of the tool's known properties plus
  all `required` properties present.

### 2. OpenAI function-call (Chat Completions API)

```json
{
  "model": "gpt-4o",
  "messages": [...],
  "tool_calls": [
    {
      "type": "function",
      "function": {
        "name": "send_email",
        "arguments": "{\"to\": \"...\"}"
      }
    }
  ]
}
```

- `function.arguments` is a STRINGIFIED JSON object. We `json.loads` then
  validate same as MCP. Note: `tool_calls` is the new-shape; the legacy
  `function_call` (singular) is still seen in older agents and follows
  the same `name`/`arguments` shape — we validate both.

### 3. Anthropic tool-use (Messages API)

Inside `content` blocks:
```json
{
  "type": "tool_use",
  "id": "toolu_xyz",
  "name": "send_email",
  "input": {"to": "..."}
}
```

- `input` is a dict (not a string — Anthropic differs from OpenAI here).
  Validation same as MCP/OpenAI on `name` + `input` keys.

### 4. Custom / unknown shapes

If the body doesn't match any of (1)-(3), the validator returns
`detected=False, skipped_reason="no-tool-call-shape"`. Operators who want
to extend the recognized shapes ship custom rules via a v1.1 hook (out of
scope for v1.0).

## Detection algorithm

```
def validate(body, schema_corpus, allowlist_patterns) -> ValidationResult:
    text = decode(body)
    if not text or len(text) < 4:
        return ValidationResult(detected=False)
    if any(allowlist.match(text)): return skipped("allowlist")
    if size > max_body_bytes: text = text[:max_body_bytes], truncated=True

    parsed = try_parse_json(text)
    if not parsed: return ValidationResult(detected=False, skipped="not-json")

    calls = extract_tool_calls(parsed)  # returns list of (shape, name, args)
    if not calls: return ValidationResult(detected=False, skipped="no-tool-call-shape")

    indicators = []
    for shape, name, args in calls:
        # Layer 1 — name lookup
        tool_schema = schema_corpus.lookup(shape, name)
        if tool_schema is None:
            indicators.append(Indicator(
                rule="hallucinated-tool-name",
                shape=shape,
                tool_name=name,
                severity="high",
                source="iam-jit",
                reason=f"tool '{name}' not in known {shape} corpus"))
            # name-shape heuristic
            if has_naming_mix(name):
                indicators.append(Indicator(rule="naming-style-mix", ...))
            continue

        # Layer 2 — schema validation against the known tool
        for missing in required_minus_present(tool_schema, args):
            indicators.append(Indicator(rule="missing-required-arg", ...))
        for extra in present_minus_allowed(tool_schema, args):
            indicators.append(Indicator(rule="unexpected-arg", ...))

        # Layer 3 — value heuristics
        for k, v in args.items():
            if is_placeholder_value(v):
                indicators.append(Indicator(rule="placeholder-credential", ...))

    if not indicators:
        return ValidationResult(detected=False)

    confidence, suggested = compute_confidence(indicators)
    return ValidationResult(detected=True, indicators=..., confidence=..., suggested_action=...)
```

### Confidence weighting

Per `[[scorer-is-ground-truth]]` this MUST NOT be tuned post-hoc.

| High count | Medium count | Confidence | Suggested action |
|---|---|---|---|
| ≥2 | * | 0.95 | deny |
| 1 | ≥1 | 0.85 | warn |
| 1 | 0 | 0.80 | warn |
| 0 | ≥2 | 0.55 | warn |
| 0 | 1 | 0.35 | allow (low-confidence) |
| 0 | 0 | 0.00 | allow |

High = `hallucinated-tool-name` | `placeholder-credential` | `missing-required-arg`.
Medium = `unexpected-arg` | `naming-style-mix`.

### Honesty bar

Per `[[ibounce-honest-positioning]]`:
- Every indicator carries `rule` + `shape` + `tool_name` + `severity` +
  `source` + `reason` (a human-readable phrase). No silent fails.
- Confidence < 0.5 → `low_confidence_explanation` populated.
- The competitive PDF's "95% catch rate" claim is INTENTIONALLY NOT in
  code/docs until we validate against a real corpus. A follow-up task is
  filed.

## Profile schema

YAML field name mirrors BUILD-9's pattern exactly:

```yaml
profiles:
  staging-validate-tools:
    description: "validate every outbound tool call shape"
    validate_tool_calls:
      enabled: true
      action: warn  # warn | strip | deny | allow
      schema_corpus_path: ""  # optional; defaults to baked-in corpus
      allowlist_patterns: []
      max_body_bytes: 65536
      min_confidence_for_deny: 0.7
```

Defaults are SAFE-OFF — same posture as BUILD-9.

## Schema corpus

The baked-in corpus (`iam_jit.tool_call_validator.corpus`) ships:

- **MCP standard tools** — the minimal set from the MCP spec
  (`tools/list`, `resources/read`, `prompts/list`, etc.).
- **OpenAI common tools** — `code_interpreter`, `file_search`,
  `web_search` (drawn from OpenAI Assistants API public docs).
- **Anthropic common tools** — `computer`, `text_editor`, `bash`
  (drawn from Anthropic Tools API public docs).

CITATIONS in source comments point at the doc page each tool is sourced
from. Per `[[ibounce-honest-positioning]]` we do NOT invent tool names;
unknown-tool reports are honest.

Operators override via `schema_corpus_path` pointing at a YAML/JSON file
of the same shape. The runtime corpus is the union of baked-in + operator
override, with operator entries winning on name collision.

## Wire-up

### Python lib (iam-roles)

`src/iam_jit/tool_call_validator/`
- `__init__.py` — public API
- `config.py` — `ProfileConfig` dataclass + `from_dict`
- `corpus.py` — baked-in schema corpus + `SchemaCorpus` dataclass + `load`
- `rules.py` — name-shape + value-shape heuristics
- `validator.py` — `validate(body, corpus, allowlist)` + `ValidationResult`
  + `decide_action` + `apply_strip`

### Go port (gbounce)

`internal/toolcallvalidator/`
- `validator.go` — same surface, lock-step rule set
- `corpus.go` — baked-in corpus mirroring Python
- `validator_test.go`

### MCP tool

`iam_jit_validate_tool_call(body, mode, allowlist_patterns,
min_confidence_for_deny)` — agent-callable pre-flight; PURE-LOCAL (no
HTTP).

### gbounce wire-up

When the active profile has `validate_tool_calls.enabled=true`, gbounce
intercepts the REQUEST body on its MITM POST path:
- if invalid + action=`deny`: return 422 Unprocessable Entity with a
  `caught_by_bouncer`-shaped JSON body (mirrors BUILD-9's deny shape but
  with `reason="hallucinated_tool_call_shape"`).
- if invalid + action=`warn`: add `X-IAM-JIT-Hallucinated-Tool-Call`
  header + audit + forward.
- if invalid + action=`strip`: replace the body with a sanitized version
  whose hallucinated calls are removed; forward the rest.

`/admin/features` gets a `validate_tool_calls` feature row with the same
fire-count + last-fired-ts + configured-but-never-fired shape BUILD-9
uses. The integration tests treat the fire-count tick as the canonical
"is this actually doing anything" assertion per
`[[uat-tests-setup-end-to-end]]`.

## Why 422 instead of 403

422 Unprocessable Entity is the semantically-correct code for "the
request is syntactically valid but the contents fail validation". 403
would imply the agent's identity / authorization was rejected; 422
correctly signals the agent that the *shape* is wrong, which is the
self-correction signal we want. BUILD-9 uses 403 (correct — the response
is from an upstream that's been compromised); BUILD-8 uses 422 (correct
— the request from the agent is malformed).

## Out of scope (v1.0)

- LLM-based aliasing / semantic match (`send_email` → `Email.send`)
- Streaming-response inspection (Anthropic streaming `tool_use` deltas)
- Multimodal tool-call shapes (image inputs)
- The "95% catch rate" marketing claim. Initial PR ships detection +
  tests + an honest "calibration deferred to follow-up" note in the
  CHANGELOG.

## Follow-up tasks

- File a calibration corpus task — collect 100+ real hallucinated tool
  calls + 100+ real legitimate ones, measure catch rate honestly.
- File a v1.1 task for LLM-based semantic aliasing once the calibration
  baseline exists.
- File a v1.1 task for streaming-shape inspection on the Anthropic
  Messages stream.
