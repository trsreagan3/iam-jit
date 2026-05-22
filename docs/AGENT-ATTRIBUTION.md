# Agent attribution across the Bounce suite

Every Bounce product (ibounce / kbounce / dbounce / gbounce) stamps
agent identity onto every OCSF audit event under
`unmapped.iam_jit.agent` (#266). Cross-product queries — "show me
every call this agent session made anywhere in our environment last
night" — work because the four products agree on:

- **The field shape** (`agent.name`, `agent.session_id`,
  `agent.detected_from`)
- **The wire location** (`unmapped.iam_jit.agent.*` in the OCSF
  event)
- **The detection signal** that fed it

This doc covers the **transport layer** for that signal — how an
agent runtime communicates its identity to a Bounce. For the
**consumption** side (querying the resulting events from a SIEM or
the `iam-jit audit query` CLI), see
[QUERYING-AUDIT-LOGS.md](QUERYING-AUDIT-LOGS.md).

## Why this matters

iam-jit's safety value collapses to "audit trail you can pivot on
quickly" per
`[[security-team-positioning-safety-not-surveillance]]`. When an
incident lands at 02:00, the on-call who pulls the audit log needs to
answer **"which agent did this"** in seconds — not "which IP" or
"which IAM role" (the agent shares those with every other agent
running on the same box). Without `agent.session_id` the only honest
answer is "we don't know."

This is **attribution for investigation**, not surveillance. The
session id binds an agent's actions across products so an on-call can
say "Claude Code session 01968d... touched the database AND the
GitHub API in the same five-minute window" — and pivot from there to
the prompt / file / human that started it. The data lives **on the
operator's own machine** (`[[self-host-zero-billing-dependency]]`);
no Bounce product phones it home.

## The two headers

For HTTP-shaped Bouncers (gbounce, ibounce's AWS-API proxy mode,
kbounce), the agent supplies attribution via two HTTP request headers:

| Header               | Purpose                                      | Validation                                    |
|----------------------|----------------------------------------------|-----------------------------------------------|
| `X-Agent-Session-Id` | Stable per-session id (UUID v7 recommended)  | `[A-Za-z0-9_-]{1,128}` — alphanumeric + `_` + `-`, max 128 chars |
| `X-Agent-Name`       | Canonical agent name (e.g. `claude-code`)    | `[A-Za-z0-9._-]{1,64}` — alphanumeric + `.`/`_`/`-`, max 64 chars |

Validation runs at the proxy. **A header that fails validation is
treated as if it were absent** — the value is **never** stamped into
the audit event (shell-injection payloads can't pivot through the
audit log). The rejection counter surfaces via `/healthz`
(`total_agent_headers_rejected`); the rejection itself is logged to
stderr with the truncated raw value so an operator debugging
attribution drift can spot the bad header.

When **both** headers are absent (raw curl from a script with no
attribution knowledge), the event surfaces as
`name="anonymous"` + `detected_from="unknown"`. This makes
unattributed traffic a first-class filterable signal:

```bash
# Show me every anonymous call that hit the SaaS APIs last night
iam-jit audit query \
  --bouncer gbounce \
  --since "2026-05-21T22:00:00Z" \
  --until "2026-05-22T06:00:00Z" \
  --filter unmapped.iam_jit.agent.name=anonymous
```

## Wire-shape examples

### Attributed event (X-Agent-* headers supplied)

```json
{
  "unmapped": {
    "iam_jit": {
      "agent": {
        "name": "claude-code",
        "session_id": "01968d6a-9c12-7a4b-b6f8-3b8e4c0d1aef",
        "detected_from": "http_header"
      }
    }
  }
}
```

### Anonymous event (no headers)

```json
{
  "unmapped": {
    "iam_jit": {
      "agent": {
        "name": "anonymous",
        "detected_from": "unknown"
      }
    }
  }
}
```

`session_id` is **omitted** (not empty-string) when no header was
supplied — JSON consumers can distinguish "we don't know" from "we
saw a session_id of empty-string".

## SQL connections (dbounce) — `application_name` convention

dbounce sees the PostgreSQL / MySQL wire protocol, not HTTP — there's
nowhere to attach an `X-Agent-*` header. The functionally-equivalent
attribution channel is the **`application_name` startup parameter**
(every PG client SDK + libpq + JDBC supports it; MySQL clients send
the equivalent under `_program_name` in the connection-attributes
block).

dbounce parses `application_name` and recognises the canonical agent
tag shape:

```
application_name = iam-jit-agent:NAME:SESSIONID
```

When dbounce sees this shape it splits on `:`, validates `NAME` against
the same `[A-Za-z0-9._-]{1,64}` regex used for `X-Agent-Name`, and
validates `SESSIONID` against the same `[A-Za-z0-9_-]{1,128}` regex
used for `X-Agent-Session-Id`. The parsed pieces land on the same
`unmapped.iam_jit.agent.{name, session_id, detected_from}` block as the
HTTP path; `detected_from=pg_app_name` so a SIEM filter can
distinguish SQL-attributed from HTTP-attributed events.

### Setting `application_name` per agent runtime

**libpq (Python `psycopg2` / `psycopg3` / Go `pgx`):**

```bash
# PG connection-string parameter
DATABASE_URL="postgresql://user@host/db?application_name=iam-jit-agent:claude-code:01968d6a-9c12-7a4b-b6f8-3b8e4c0d1aef"
```

```python
# psycopg3
import psycopg
conn = psycopg.connect(
    "host=localhost dbname=app user=app",
    application_name=f"iam-jit-agent:claude-code:{uuid.uuid4()}",
)
```

**JDBC (`postgresql-driver`):**

```
jdbc:postgresql://host:5432/db?ApplicationName=iam-jit-agent:claude-code:01968d6a-9c12-7a4b-b6f8-3b8e4c0d1aef
```

**MySQL (Connector/J + `mysqlclient`):**

```
jdbc:mysql://host:3306/db?connectionAttributes=program_name:iam-jit-agent:claude-code:01968d6a-9c12-7a4b-b6f8-3b8e4c0d1aef
```

A non-matching `application_name` (e.g. plain `psql` or
`PostgreSQL JDBC Driver`) falls through to dbounce's existing
known-client map (records `name=psql` / `name=pg-jdbc` with
`detected_from=pg_app_name` but no session_id). Malformed
`iam-jit-agent:` tags (invalid characters, oversize fields) bump the
same `total_agent_headers_rejected` counter as HTTP rejections — one
unified surface across the suite per
`[[cross-product-agent-parity]]`.

## Setting the headers per agent runtime

### Claude Code (Anthropic SDK / Anthropic CLI)

The `ibounce mcp install-claude-code` / `gbounce mcp install-*`
installers (where gbounce ships an MCP server in a future slice) set
the env var that wires the headers automatically. For a manual setup,
add the headers to your Anthropic SDK configuration:

```bash
# Bash / zsh: set before launching the agent
export ANTHROPIC_HEADERS='{"X-Agent-Name":"claude-code","X-Agent-Session-Id":"'"$(uuidgen)"'"}'
```

The session id should be **regenerated per agent invocation** —
treat it like a request id: stable for the lifetime of one
conversation / one task, freshly minted on the next.

### Cursor

Cursor's HTTP client config supports custom request headers via
`cursor.requestHeaders` in `~/.cursor/config.json`:

```json
{
  "cursor.requestHeaders": {
    "X-Agent-Name": "cursor",
    "X-Agent-Session-Id": "${session.id}"
  }
}
```

The `${session.id}` placeholder is expanded by Cursor's runtime to a
fresh UUID per session.

### Codex CLI (OpenAI)

Codex configures HTTP headers via the `extra_headers` block in
`~/.codex/config.toml`:

```toml
[http]
extra_headers = [
  { name = "X-Agent-Name",       value = "openai-codex" },
  { name = "X-Agent-Session-Id", value = "{{session_id}}" },
]
```

### Devin / custom harnesses

For any agent harness with an HTTP client config, set the two headers
globally. The Python `httpx` pattern (used by many custom harnesses)
is:

```python
import os, uuid

session_id = os.environ.setdefault("AGENT_SESSION_ID", str(uuid.uuid4()))
agent_name = os.environ.setdefault("AGENT_NAME", "my-harness")

http_client = httpx.Client(
    headers={
        "X-Agent-Name": agent_name,
        "X-Agent-Session-Id": session_id,
    },
)
```

For agents built on the Anthropic SDK directly:

```python
import anthropic, os, uuid
client = anthropic.Anthropic(
    default_headers={
        "X-Agent-Name": "my-harness",
        "X-Agent-Session-Id": os.environ.get("AGENT_SESSION_ID", str(uuid.uuid4())),
    },
)
```

### OpenClaw / NanoClaw

Both ship native support via the `agent.identity` config block:

```yaml
# openclaw.yaml / nanoclaw.yaml
agent:
  identity:
    name: openclaw           # or nanoclaw
    session_id_strategy: uuidv7   # mints a fresh v7 per agent run
```

The runtime wires this onto every outbound HTTP request as the two
`X-Agent-*` headers. See
[INTEGRATION-OPENCLAW-NANOCLAW.md](INTEGRATION-OPENCLAW-NANOCLAW.md)
for the OpenClaw `#47876` session-monitoring gap that this closes.

## Cross-product correlation

Once an agent stamps the same `session_id` on every outbound call,
the `iam-jit audit query` CLI (#271) merges the per-bouncer streams
into one sorted output:

```bash
iam-jit audit query \
  --filter unmapped.iam_jit.agent.session_id=01968d6a-9c12-7a4b-b6f8-3b8e4c0d1aef \
  --format ocsf-bundle > session-bundle.json
```

Default fan-out probes all four bouncers on loopback ports
(`ibounce` 8767, `kbounce` 8766, `dbounce` 8768, `gbounce` 8769) and
merges the JSONL output. For remote bouncers pass `--bouncer
NAME=URL` overrides.

## Why "session" not "user"

The session id is **not** an end-user identifier. It identifies one
agent **process / conversation / task**, not the human who started
it. The human's identity lives elsewhere:

- For SaaS-API access (ibounce + AWS), the AWS principal / IAM role
  carries the human via STS source identity (`[[mfa-compliance-
  strategy]]`).
- For K8s access (kbounce), the K8s subject carries the human via
  the OIDC token.
- For database access (dbounce), the DB role carries the human via
  the connecting JWT.

The agent session id binds the agent's **technical** identity to a
single conversation. The investigation pivot is:

> session_id → which agent runtime → which conversation log → which
> prompt → which human

…not session_id → human directly. This is intentional per
`[[security-team-positioning-safety-not-surveillance]]` — we record
what's needed to investigate, not a richer profile than necessary.

## Failure modes + their honest framing

| What happened                                       | What the audit event says                                  |
|-----------------------------------------------------|------------------------------------------------------------|
| Agent didn't set the headers                        | `name=anonymous`, `detected_from=unknown`, no session_id   |
| Agent set a malformed header                       | `name=anonymous`, `detected_from=unknown`, `/healthz` counter +1, stderr log line |
| Agent rotated session_id mid-task                  | Two distinct session_ids; the operator pivot still works (each is fully audited) |
| Operator bypasses the proxy entirely (`NO_PROXY=*`) | No event recorded at all (the bouncer is honest about its boundary per `[[ibounce-honest-positioning]]`) |

Per `[[ibounce-honest-positioning]]`: the Bouncers are **not** a
deny boundary an adversary can't circumvent. They're a fast audit
trail + a configuration deterrent. An operator who controls the
agent's network can route around them; the value sits in catching
**accidents**, not adversaries.

## Spec-level validation rules

The validation regexes are deliberately tight so the audit log can be
processed by ordinary shell pipelines without escape-handling:

- **No spaces, tabs, newlines** — single-line shell safe
- **No quotes / backticks / dollar signs** — shell-injection safe
- **No path separators** — can't double as a filesystem path
- **No SQL meta-characters** — safe to embed in a SQL `WHERE` clause
- **Bounded length** — log lines + DB columns can size predictably

Names that fit but aren't in our canonical table (e.g. a custom
harness called `acme-internal-agent`) are accepted verbatim and
surface in the audit log unchanged. Operators can build their own
filters against names they've seen in their environment.

## Related

- `[[agent-identity-in-audit]]` memo (#266) — the canonical
  cross-bouncer agent block convention
- [QUERYING-AUDIT-LOGS.md](QUERYING-AUDIT-LOGS.md) — SIEM examples
  for filtering on `agent.*`
- [INTEGRATION-OPENCLAW-NANOCLAW.md](INTEGRATION-OPENCLAW-NANOCLAW.md)
  — the OpenClaw session-gap this closes
- [KNOWN-CAVEATS.md](KNOWN-CAVEATS.md) §A9 — the gbounce-specific
  fix that completes cross-bouncer parity (#308)
- `[[security-team-positioning-safety-not-surveillance]]` — the
  framing: attribution for investigation, not surveillance
