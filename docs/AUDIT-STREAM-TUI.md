# Live audit stream TUI (`iam-jit audit stream`)

`iam-jit audit stream` is a k9s-style terminal UI that subscribes to
every reachable Bounce-suite bouncer's `GET /audit/events` endpoint
(#271) and renders one merged, sorted, colourised table that updates
live as new events land. Pairs with the per-bouncer web UI served at
`GET /` on each bouncer's mgmt port (also #272).

Issue: #272 - "live agent-activity stream UI".

## What it shows

```
iam-jit audit stream | total=14 | dbounce=2 | gbounce=0 (skip) | ibounce=7 | kbounce=5

  time      bouncer  sev    event_type      actor                  operation              verdict
 ---------- -------- ------ --------------- ---------------------- ---------------------- -----------
  14:21:09  ibounce  Info   DECISION        alice                  iam:GetRole            ALLOWED
  14:21:11  kbounce  Info   DECISION        sa-prod-deploy         kube:get pods          ALLOWED
  14:21:12  ibounce  High   DECISION        claude-code            iam:DeleteUser         DENIED
  14:21:13  dbounce  Info   DECISION        analytics-svc          pg:SELECT users        ALLOWED
  14:21:15  ibounce  Info   ADMIN_GRANT     ops@example.com        profile:install        ADMIN GRANT
  14:21:18  ibounce  Info   HEARTBEAT       -                      -                      HEARTBEAT
  14:21:20  kbounce  Med    DECISION        sa-prod-deploy         kube:delete service    DENIED

 +------------------------------------------------------------------------------------+
 |  [/] filter   [p] pause/resume   [t] toggle bouncer col   [c] clear   [q] quit     |
 +------------------------------------------------------------------------------------+
```

Title-bar fields: total event count, per-bouncer breakdown (with
`(skip)` next to any bouncer that's currently unreachable — matches
`iam-jit audit query`'s skip semantics).

Row colours (matches the cross-product SIEM convention used by the
web UI shipped alongside this TUI):

| Verdict / event type | Colour |
| --- | --- |
| `DENIED` | bold red |
| `ALLOWED` | green |
| `ADMIN_*` event_type | bold blue |
| `HEARTBEAT` event_type | grey |
| Unknown verdict | white |

## Keyboard shortcuts

| Key | Action |
| --- | --- |
| `/` | Edit the filter expression. Same syntax as `iam-jit audit query --filter` (`field=value` / `field~regex` / `field>=N` / `field<=N`). Forwarded to each bouncer's `/audit/events?filter=` so the filter runs server-side. A blank line clears the filter. |
| `p` | Pause / resume polling. While paused the table is frozen; no HTTP calls are made. |
| `t` | Toggle the per-bouncer column. Useful when you've narrowed to one bouncer and want more horizontal space for the operation column. |
| `c` | Clear the table + counters. The dedupe set is cleared too so subsequent polls re-fill the table from the current cursor onward. |
| `q` | Quit. Restores the terminal + cancels the background fetcher cleanly. `Ctrl-C` works too. |

## How to access

```bash
# Default: probe all four bouncers on their standard mgmt ports
# (ibounce 8767, kbounce 8766, dbounce 8768, gbounce 8769).
iam-jit audit stream

# Subscribe to a subset.
iam-jit audit stream --bouncer ibounce --bouncer kbounce

# Override one bouncer's URL (e.g. kbounce on a remote mgmt host).
iam-jit audit stream --bouncer kbounce=http://10.0.0.5:8766

# Start with a server-side filter applied.
iam-jit audit stream --filter unmapped.iam_jit.verdict=DENY

# Bearer token when any subscribed bouncer is externally bound.
iam-jit audit stream --audit-events-token "$AUDIT_EVENTS_TOKEN"

# Faster refresh.
iam-jit audit stream --poll 1
```

## Per-bouncer column toggle

The `[t]` key toggles the `bouncer` column on / off:

- **on** (default): each row carries the originating bouncer name so
  the operator can correlate across products at a glance. Use this
  when subscribing to more than one bouncer.
- **off**: drops the column to free horizontal space for the
  operation field. Use this when narrowed to one bouncer (e.g.
  `--bouncer ibounce`) since the column would be redundant.

## Auth model

The TUI inherits the same trust anchor as `iam-jit audit query`:

- **Loopback bouncers (the default)** — no `Authorization` header
  required. The mgmt port refuses non-loopback binds without
  `--audit-events-token` at the bouncer's `run` time, so reaching the
  endpoint at all implies a trusted local subscriber.
- **External-bind bouncers** — pass `--audit-events-token TOKEN` to
  the TUI. The same token is forwarded to every subscribed bouncer
  (per `[[cross-product-agent-parity]]` they all accept the same
  Bearer header shape). If a single bouncer needs a different token,
  start one TUI per token.

## Read-only by design

Per `[[creates-never-mutates]]` the TUI is a **viewer**, not a
controller. No keystroke mutates bouncer state — there is no "kill
session" / "pause profile" / "approve request" key. To act on what
you see, use the per-product `audit` / `profile` / `pause` CLI
subcommands directly (cross-linked from each event's actor field).

## Skip semantics

Unreachable bouncers (connection refused, timeout, HTTP 5xx) are
marked `(skip)` in the title bar; the rest of the stream keeps
flowing. The TUI re-probes each `--poll` tick, so a bouncer that
comes back online starts contributing events again without an
operator action. This matches `iam-jit audit query` (#271).

## Stack note

The TUI is built on `rich.live` rather than `textual`. `rich` ships
transitively via `click` so iam-roles takes no new direct
dependency; `textual` would pull in 5+ additional packages
(`markdown-it-py`, `mdit-py-plugins`, `linkify-it-py`, ...) for what
is a read-only table with five colour classes. If a future feature
needs textual's widget model (forms, multi-pane layouts) the switch
is a single-file replacement — the wire shape + state machine
remain unchanged.

## Cross-links

- [`docs/IAM-JIT-AUDIT-QUERY.md`](IAM-JIT-AUDIT-QUERY.md) — the
  one-shot sibling. Same `--bouncer` / `--filter` /
  `--audit-events-token` flags; the TUI is the live tail, the query
  CLI is the headless dump.
- [`docs/QUERYING-AUDIT-LOGS.md`](QUERYING-AUDIT-LOGS.md) — the
  full filter-language reference + supported-field catalog.
- [`docs/INVESTIGATE-WITH-CLAUDE.md`](INVESTIGATE-WITH-CLAUDE.md)
  (#273) — when you spot something in the live stream, this is how
  you turn it into a Claude-ready evidence pack.

## Web UI sibling

Each bouncer also serves a minimal vanilla-JS web UI at `GET /` on
its own mgmt port. Same colour conventions, same filter syntax;
useful when you want to share a live view via URL or pin it on a
secondary monitor. See each product's `QUERYING-AUDIT-LOGS.md`
section on `GET /` for the per-bouncer "how to access" snippet.
