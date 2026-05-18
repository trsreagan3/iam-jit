# Session recording + replay (#285)

> Auditor-grade walkthrough for any Bounce-product session, with optional
> "what would have happened" re-evaluation against an alternate profile.

## What this is

Every Bounce product (`ibounce` / `kbouncer` / `dbounce` / `gbounce`) can
record one NDJSON file per agent session when run with
`--record-sessions-dir`. The cross-product `iam-jit session replay <FILE>`
CLI then walks the recording event-by-event, optionally pausing in real
time, optionally filtering, and optionally re-evaluating each event
against a different profile to see what _would_ have happened.

Two use cases drive the shape:

1. **Auditor walkthrough** — a security engineer reproducing what a
   given agent session did, in the order it happened, with full timing
   preserved (`--realtime`).
2. **What-if profile diff** — "If we had been running profile X instead
   of the one we were actually running, what would the verdicts have
   been?" This is the killer auditor question; it surfaces a clean diff
   between the recorded verdict and the what-if verdict.

## Quick start

Record:

```
ibounce run --record-sessions-dir ~/.iam-jit/sessions
# (or via the convenience flag on the other products)
kbounce run --record-sessions-dir ~/.kbouncer/sessions
```

List what you have:

```
ibounce session list
SESSION_ID                                AGENT          EVENTS  START                  END
01956c44-c5c1-7c31-9bca-7c0aaa000001     claude-code    142     2026-05-18T10:14:22Z   2026-05-18T11:02:00Z
01956c44-c5c1-7c31-9bca-7c0aaa000099     cursor         60      2026-05-18T11:30:01Z   2026-05-18T11:42:18Z
```

Show a summary:

```
ibounce session show 01956c44-c5c1-7c31-9bca-7c0aaa000001
```

Export as portable OCSF Detection Finding (the same shape `iam-jit
investigate` consumes, per #273):

```
ibounce session export 01956c44-c5c1-7c31-9bca-7c0aaa000001 --out /tmp/session.json
```

Replay (cross-product CLI — consumes any product's recording):

```
iam-jit session replay ~/.iam-jit/sessions/01956c44-c5c1-7c31-9bca-7c0aaa000001.ndjson
```

## Replay flags

```
iam-jit session replay <FILE> \
    [--realtime] \
    [--what-if-profile NAME] \
    [--filter EXPR] \
    [--max-events N] \
    [--json]
```

- `--realtime` — sleep between events so the replay feels live. Useful
  for demos + auditor walkthroughs.
- `--what-if-profile NAME` — re-evaluate each event against the named
  local profile and report verdict differences. **Currently supported
  for ibounce recordings only**; the cross-product gap is below.
- `--filter EXPR` — conjunctive filter expression. Tokens are
  `key=value`, `key!=value`, `key~regex`; join with `&&`. Keys are
  dotted paths into the OCSF event. Examples:
    - `api.service.name=s3 && unmapped.iam_jit.verdict=deny`
    - `unmapped.iam_jit.agent.name~^claude`
- `--max-events N` — cap the number of events processed.
- `--json` — emit one JSON object per event instead of the default
  human format. Pipe-friendly.

## What-if profile diff — sample output

```
$ iam-jit session replay session-abc.ndjson --what-if-profile readonly
replaying session 01956c44... (agent=claude-code, bouncer=ibounce, started=2026-05-18T10:14:22Z, events=4)
what-if profile loaded: readonly
  [   0.000s ]  s3:ListBuckets                  verdict=allow       profile=full-user
  [   0.245s ]  s3:GetObject                    verdict=allow       profile=full-user
  [   1.103s ]  s3:DeleteBucket                 verdict=allow       profile=full-user
  [   0.500s ]  s3:PutObject                    verdict=allow       profile=full-user

replay complete: 4 event(s) printed
what-if vs recorded: 2 matched, 2 differed
differences:
  s3:DeleteBucket                 recorded=allow       -> what-if=deny       (action s3:DeleteBucket not in allow_baseline aws_managed_readonly_access)
  s3:PutObject                    recorded=allow       -> what-if=deny       (action s3:PutObject not in allow_baseline aws_managed_readonly_access)
```

The killer use case: the operator was running `full-user` (passthrough)
during the recorded session; the auditor asks "would the `readonly`
profile have stopped the destructive calls?" — and the answer is right
there.

## Cross-product replay vs what-if scope

The `replay` CLI consumes recordings from any of the four Bounce
products uniformly (single on-disk shape per
[[cross-product-agent-parity]]). The `--what-if-profile` path is
currently wired only for `ibounce` recordings because the ibounce
profile evaluator is a pure-Python library callable in-process. The
Go bouncers' profile evaluators live behind their respective binaries
and aren't callable from the replay CLI without a subprocess hop.

When you point `--what-if-profile` at a non-ibounce recording, the CLI
emits a yellow stderr note and continues with the replay sans the diff:

```
--what-if-profile is only wired for ibounce recordings; this
recording is from 'kbouncer'. Replay continues without re-evaluation.
See docs/SESSION-REPLAY.md for the cross-product gap + plan.
```

**Plan:** the kbouncer / dbounce / gbounce bouncers will each ship a
`--what-if-evaluate` subcommand that takes a recording file +
profile-name + emits a verdict-diff JSON. The replay CLI will shell
out to the right product based on the recording's
`_meta.bouncer_product` field. Tracked separately; ibounce remains the
v1.0 what-if surface.

## File format

Each per-session file is NDJSON. First line is a `_meta` header; every
subsequent line is one OCSF event:

```
{"_meta":{"recording_schema_version":"1.0","session_id":"01956c44-...","agent_name":"claude-code","bouncer_product":"ibounce","recording_started_at":"2026-05-18T10:14:22Z"}}
{"metadata":{...},"time":1716029062000,"class_uid":6003,"api":{...},"unmapped":{"iam_jit":{"verdict":"allow",...}}}
...
```

File suffix is `.ndjson.partial` while the session is in-flight. The
recorder atomic-renames to `.ndjson` on:

- A clean shutdown (`session stop` / Ctrl-C),
- Heartbeat timeout (default 5 minutes of session-idle), or
- Next `Start()` recovery for files left behind by SIGKILL.

File mode is **0o600** (owner-read-only). Recording files carry agent
identity + operation details; treat them like audit logs.

## Retention

Operator owns retention by default — recordings live forever until
explicitly purged. Recommended retention is **30 days** for the
auditor use case (long enough to cover the incident-investigation
window; short enough that the operator's disk isn't drowning).

Purge:

```
ibounce session purge --older-than 30d --dry-run    # preview
ibounce session purge --older-than 30d              # do it
kbounce session purge --older-than 30d              # same shape across products
```

Purge skips `.partial` files — those represent active or
recently-killed sessions; the recorder's recovery path is the right
place to deal with them.

## Permissions

Recording files are mode **0o600** (owner-read-only). Recordings
contain the OCSF event stream verbatim, which means:

- agent identity (`unmapped.iam_jit.agent.name` + `.session_id`)
- operation detail (`api.operation`, `resources[].uid`)
- verdict + matched-rule reasons

If you ship recordings to a SIEM, treat the bytes as sensitive — the
same way you treat audit logs.

## Relationship to other audit surfaces

- **#271 `iam-jit audit query`** — entity-axis (what did this principal
  do across every session). Replay is the time-axis complement
  (everything ONE session did, in order).
- **#272 `iam-jit audit stream`** — live tail of cross-bouncer events.
  Replay is the post-hoc analogue (snapshot vs live).
- **#273 `iam-jit investigate`** — Claude-driven analysis over an
  evidence bundle. The `session export` Detection Finding shape is
  byte-compatible with the investigate bundle so you can feed a single
  session into `iam-jit investigate` and ask Claude open-ended
  questions about it.

## Constraints

Per [[creates-never-mutates]]: recording is additive (tees the
existing event stream); the replay CLI is read-only over the recording
file + the local profile store.

Per [[self-host-zero-billing-dependency]]: entirely local file system;
no phone-home.

Per [[security-team-positioning-safety-not-surveillance]]: user-facing
strings do not contain "violation" / "infraction" / "unauthorized".
The recorder is operator-visibility for compliance + incident
response, not adversary-defense.
