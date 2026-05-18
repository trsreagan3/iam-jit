# ibounce diagnostics bundle

`ibounce diagnostics bundle` produces a single ZIP a support engineer
(or the operator themselves) can attach to a bug report or paste to a
Claude agent for analysis. The bundle is **safe to share** — every
section is redacted on the way in. No tokens, no webhook URLs, no
hostnames, no user identifiers, no env-var values, no certs, no
private keys, no absolute paths under `$HOME` leave the host.

Per `[[cross-product-agent-parity]]` the sibling agents in
[kbounce](https://github.com/trsreagan3/kbouncer) (commit `50a8a44`)
and [dbounce](https://github.com/trsreagan3/dbounce) (commit
`a15b148`) ship the same subcommand shape + flag names, so one
`{product} diag bundle --out ./bundle.zip` invocation works across
all three.

## When to use it

- **Debugging a hang**: `ibounce run` looks alive but isn't gating
  the calls you expect. The bundle captures `/healthz`, the last 200
  audit events, version, OS, and the active profile fingerprint —
  everything a support engineer needs to reproduce.
- **Sharing with support**: filing a ticket with the bundle attached
  saves the multi-step manual collection of version + config + log
  tail + system info that an operator would otherwise hand-assemble.
- **Sharing with a Claude agent for analysis**
  (per `[[investigate-with-claude]]`): the bundle's README + manifest
  give an LLM the context it needs to triage without the operator
  having to copy-paste fragments. Every section is small enough to
  fit in a single prompt.

The bundle is the **"safe to share"** complement to the #279 SQLite
backup. They serve different purposes:

| | `diagnostics bundle` | `#279 SQLite backup` |
|--|--|--|
| Purpose | Debug a deployment | Preserve full audit trail |
| Secrets | Redacted | Carried verbatim |
| Distribution | Public OK (support ticket, Claude paste) | Trusted channel only |
| Format | ZIP with 10 redacted files | SQLite `.db` dump |
| Audit trail | Last 200 events (user IDs hashed) | Every row, untouched |

## Usage

```sh
# Default: ./ibounce-diagnostics-{UTC-timestamp}.zip in CWD.
ibounce diagnostics bundle

# Named output:
ibounce diagnostics bundle --out /tmp/bug-report.zip

# Shorter alias (matches kbounce + dbounce):
ibounce diag bundle --out /tmp/bug-report.zip

# Skip the audit-tail section entirely (paranoid mode):
ibounce diagnostics bundle --no-audit

# Include more audit context (default 200):
ibounce diagnostics bundle --include-audit-tail 1000

# Include a captured stderr / panic-log:
ibounce diagnostics bundle --panic-log /var/log/ibounce.stderr

# Dev-cert deployments:
ibounce diagnostics bundle --insecure-skip-verify

# Point at a non-default /healthz URL:
ibounce diagnostics bundle --healthz-url http://127.0.0.1:9999/healthz
```

## What's in the bundle

| File | Contents |
|--|--|
| `00-README.txt` | Top-level explainer + redaction notes |
| `01-version.txt` | ibounce version + Python + platform metadata |
| `02-config-redacted.json` | Operator config (REUSES `#275 config export` redactor; webhook URL additionally nulled) |
| `03-active-profile.json` | Loaded profile pointer + `profiles.yaml` sha256 + size_bytes |
| `04-audit-tail.jsonl` | Last N audit events (default 200); user identifiers stably hashed |
| `05-healthz.json` | Local `/healthz` snapshot (or `"unreachable"` + reason) |
| `06-system.txt` | OS / Python / hostname-as-hash + env-var KEY names (no values) |
| `07-listener.json` | Wire port + healthz URL probed (NEVER remote addresses) |
| `08-panics.txt` | Optional panic-log capture (URLs / IPs / token-shapes scrubbed) |
| `09-manifest.json` | Bundle version + format string + per-file sha256 |

Inspect the bundle without unpacking:

```sh
unzip -l /tmp/bug-report.zip
unzip -p /tmp/bug-report.zip 00-README.txt
unzip -p /tmp/bug-report.zip 09-manifest.json | jq .
```

## What MUST be redacted

The redaction contract (load-bearing — tests sweep the entire ZIP
for sentinel strings to prove the invariant):

- **Tokens**: HEC, API key, integration key, license content / bytes
  / pem, bearer tokens, any field whose key name contains `token`,
  `secret`, `api_key`, `password`, `bearer`, `authorization`,
  `private_key`
- **URLs**: webhook URL, alert-route destinations, any field whose
  key ends with `_url` or `_endpoint`
- **Hostnames / IPs**: the literal hostname is replaced with a stable
  `sha256:<12hex>` hash so cross-bundle correlation is possible
  without leaking the literal name; IPv4 / IPv6 literals are masked
  via regex pass
- **User identifiers**: every `name` / `user_name` / `username` / `uid`
  / `email` / `actor` / `started_by` / `approved_by` field in an audit
  row is replaced with `sha256:<12hex>` — cross-event correlation
  preserved, cleartext identity not revealed
- **Env var values**: `06-system.txt` lists `IAM_JIT_*` / `IBOUNCE_*`
  / `AWS_*` env-var KEY names; the VALUES never appear
- **Absolute paths under `$HOME`**: replaced with `<home>/...` so the
  bundle doesn't reveal the operator's home-dir layout
- **Free-text fields**: a final regex pass scrubs URLs, IPv4/IPv6
  literals, `Bearer ...` patterns, `token=...` pairs, and long
  base64-shaped strings

The redaction is **belt + suspenders**: the `02-config-redacted.json`
section reuses `#275 build_export` which already redacts, and the
diagnostics module additionally nulls `webhook_url` and runs a
defensive regex pass on every section before it lands in the ZIP.

## The `--no-audit` flag

`--no-audit` suppresses the audit-tail section entirely. Use it when
the audit log itself is the surface you don't want to share:

- Regulated environments where even user-ID-hashed events are
  considered sensitive
- Cases where the audit log carries OCSF fields a future ibounce
  release might add a sensitive value to (the redactor is allowlist-
  based for the categories above; a future addition might temporarily
  bypass it)

The other nine sections still ship; the bundle remains useful.

## Flags

| Flag | Default | Purpose |
|--|--|--|
| `--out PATH` | `./ibounce-diagnostics-{UTC-timestamp}.zip` | Output ZIP path |
| `--include-audit-tail N` | `200` | Audit events included (REDACTED) |
| `--no-audit` | off | Suppress audit-tail section |
| `--panic-log PATH` | unset | Path to captured stderr / panic file |
| `--insecure-skip-verify` | off | Skip TLS verify on `/healthz` GET |
| `--healthz-url URL` | `http://127.0.0.1:8767/healthz` | Local `/healthz` probe target |
| `--audit-log PATH` | `$IAM_JIT_BOUNCER_AUDIT_LOG_PATH` | JSONL audit log path |
| `--db PATH` | `~/.iam-jit/bouncer/state.db` | SQLite store path |
| `--profiles PATH` | `~/.iam-jit/bouncer/profiles.yaml` | Profiles YAML path |
| `--alert-rules PATH` | unset | Alert-rules YAML to inline into config |

## Read-only + zero-billing-dependency

Per `[[creates-never-mutates]]` the command is strictly read-only. It
never writes outside the output ZIP (and a sibling `.tmp` file we
rename atomically). Per `[[self-host-zero-billing-dependency]]` it
performs **one** network call: the local `/healthz` GET on the
loopback port. Failure of that GET degrades gracefully — the section
records `"health": "unreachable"` plus the error reason, and the
bundle still ships.

## Admin-action audit trail

Every bundle creation enqueues a `diagnostics.bundle` ADMIN_ACTION
OCSF event so a security team has a witness for "who pulled
diagnostics + when?" The event's `extra` carries:

- `out_path` — where the bundle landed
- `file_count` / `total_bytes` — bundle shape
- `audit_lines` — how many audit events shipped
- `no_audit` — whether the audit tail was suppressed
- `healthz_ok` — whether the local `/healthz` probe succeeded

The action id (`diagnostics.bundle`) matches the kbounce + dbounce
siblings verbatim per `[[cross-product-agent-parity]]`, so one
cross-product SIEM rule keyed on
`activity_name = "diagnostics.bundle"` catches the lifecycle event
across the three products.

## Cross-product siblings

- **kbounce**: `kbounce diagnostics bundle` —
  [commit `50a8a44`](https://github.com/trsreagan3/kbouncer/commit/50a8a44)
- **dbounce**: `dbounce diagnostics bundle` —
  [commit `a15b148`](https://github.com/trsreagan3/dbounce/commit/a15b148)
- **ibounce**: this command

The bundle's `09-manifest.json` carries `"format": "ibounce.diagnostics"`
so a recipient with a mixed inbox can disambiguate.
