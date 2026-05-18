# ibounce backup + restore (#279)

`ibounce backup` and `ibounce restore` ship an online SQLite backup +
gated structured restore so an operator can move ibounce state between
hosts, snapshot before a risky change, or recover from disaster.

Sibling commands `kbounce backup`/`restore` (kbouncer) and
`dbounce backup`/`restore` (dbounce) ship the same CLI shape + the
same metadata-table format. The product-namespaced metadata table
inside each backup file is `ibounce_backup_metadata` /
`kbounce_backup_metadata` / `dbounce_backup_metadata` so a single
shared tooling layer can tell which product produced the file.

## Why

- **Migration.** Move a hand-tuned dev-laptop ibounce onto a CI runner
  or sibling deployment without re-applying rules / profiles / task
  scopes by hand.
- **Disaster recovery.** Restore a deployment's state.db after a host
  loss, snapshot rotation, or accidental file deletion.
- **Audit-trail preservation.** Optional via `--include-audit` for
  scenarios where the SIEM pipeline isn't the only source of truth.

For per-bundle MERGE semantics (apply some rules + profiles onto an
existing deployment) use `ibounce config import` (#275) instead — its
`[[creates-never-mutates]]` semantics APPEND. `ibounce restore`
REPLACES the destination database wholesale.

## Backup is online; restore requires the proxy stopped

`ibounce backup` uses SQLite's `VACUUM INTO` primitive: the source
database is NOT locked, concurrent writers continue uninterrupted, and
the destination file is created atomically. You can back up a running
deployment.

`ibounce restore` REPLACES the destination database file. The command
probes the loopback management port (8767 by default) and refuses
with an actionable error if `ibounce run` is alive. Stop the running
process before restoring:

```
pkill -f 'ibounce run'        # or your service manager's stop verb
ibounce restore --in ibounce-backup-20260518T143000Z.db
```

If the probe port is held by an unrelated process, pass `--probe-skip`
after manually verifying ibounce is down. Or pass `--probe-port N` to
dial a non-default management port.

## Schema-version safety

Every backup file embeds the SCHEMA_VERSION the producing binary was
built against. `ibounce restore` refuses to restore a backup whose
`schema_version` does NOT match the running binary — even with
`--force`. Cross-schema restores require the (out-of-scope-for-#279)
`ibounce migrate` command.

ibounce-version mismatches WITHIN the same schema version are
supported as a soft gate: the restore prints a WARNING + requires
`--force` to proceed. Use this when restoring a v1.0.5 backup onto a
v1.1.0 binary.

## What ships in a backup

By default the backup file contains:

- `rules` — global allow/deny rules
- `tasks` — active task-scoped rule sets
- `pause_events` — pause history (active + expired)
- `plan_sessions` + `plan_calls` — plan-capture transcripts
- `schema_version` — for `ibounce restore`'s schema-version gate
- `ibounce_backup_metadata` — provenance row (ibounce_version,
  created_at, source_hostname_hash, schema_version, included_audit,
  included_prompts)

These tables are EXCLUDED by default + opt-in via flag:

- `decisions`, `config_events`, `pending_audit_events` — opt in via
  `--include-audit`. Bulky audit-firehose surfaces; usually shipped
  to the SIEM separately.
- `pending_prompts` — opt in via `--include-prompts`. Runtime state
  bound to in-flight proxy waiters that won't survive a restore.

## Sample session

Backup:

```
$ ibounce backup --out ibounce-backup-prod.db
wrote ibounce backup to ibounce-backup-prod.db (102400 bytes, sha256=a3f2...)
  schema_version=11  ibounce_version=1.0.0  created_at=2026-05-18T14:30:00Z
  source_hostname_hash=8b3c5d1f9a02  included_audit=False  included_prompts=False
  tables:
    ibounce_backup_metadata          6 rows
    pause_events                     12 rows
    plan_calls                       0 rows
    plan_sessions                    0 rows
    rules                            18 rows
    schema_version                   1 rows
    tasks                            3 rows
```

Restore onto a fresh host:

```
$ pkill -f 'ibounce run'
$ ibounce restore --in ibounce-backup-prod.db
restored ibounce state.db from ibounce-backup-prod.db
  destination: /home/op/.iam-jit/bouncer/state.db
  sha256: 4c8e91...
  row counts:
    ibounce_backup_metadata          6 rows
    pause_events                     12 rows
    plan_calls                       0 rows
    plan_sessions                    0 rows
    rules                            18 rows
    schema_version                   1 rows
    tasks                            3 rows
```

Cross-version restore (force required):

```
$ ibounce restore --in ibounce-backup-prod-v1.0.0.db --force
WARNING: ibounce_version mismatch — backup was created by ibounce
'1.0.0', running binary is the current build. Continuing under --force.
restored ibounce state.db from ibounce-backup-prod-v1.0.0.db
...
```

## Admin-action OCSF emission

Both subcommands enqueue an `ADMIN_ACTION` OCSF row via the same
pending_audit_events queue every other admin mutation uses (#278):

- `backup.create` — payload carries `{out_path, size_bytes, sha256,
  schema_version, ibounce_version, included_audit, included_prompts,
  source_hostname_hash}`.
- `backup.restore` — payload carries `{source_path, destination,
  sha256, force, probe_skipped, row_count_total, version_mismatch}`.

A SIEM dashboard keyed on `action="backup.restore"` catches the
DR-lifecycle event regardless of which product fired it — `kbounce`
and `dbounce` emit the same action ids per
[[cross-product-agent-parity]].

## Relationship to other operator surfaces

| Feature | Verb | Scope | Use when |
| --- | --- | --- | --- |
| `ibounce backup` / `restore` (#279) | Wholesale snapshot + DR replace | Whole SQLite file | Migration, disaster recovery, snapshot before risky change |
| `ibounce config export` / `import` (#275) | Shareable + redacted bundle, merge semantics | Profiles + rules + audit-webhook config | Move config between hosts; share with support; review changes |
| `ibounce diagnostics bundle` (#277) | Redacted support ZIP, read-only | Config + audit-tail + healthz snapshot | Share with support / paste to a Claude agent for analysis |

Backup = full, with-audit-trail option, restore-only. Config
export/import = redacted, shareable, merge-able. Diagnostics =
read-only, redacted, debugging artifact.

## Constraints

- Per [[creates-never-mutates]]: backup is read-only against the
  source database. Restore is the one CLI surface that DOES mutate an
  existing DB; the destructive verb is gated by the explicit
  subcommand name + the `--force` semantics + the running-process
  probe + the empty-destination check.
- Per [[self-host-zero-billing-dependency]]: no network calls. Both
  subcommands are pure file + SQLite operations.
- Per [[push-policy-public-repo]]: the metadata table records
  `source_hostname_hash` (sha256[:12] of the hostname) rather than
  the literal hostname so an operator can share a backup file for
  support purposes without leaking infra topology.

## Out of scope (for #279)

- Cross-schema-version restore (`ibounce migrate`). The
  schema_version-mismatch refusal is intentional — restoring across
  schema versions would leave the destination running against tables
  the binary doesn't know how to read.
- Encrypted backups. The destination file inherits 0o600 perms and
  the hostname hash is the only privacy primitive. Wrap in your own
  encryption layer (`gpg --symmetric` / `age` / `aws s3 cp --sse`)
  when shipping backups across trust boundaries.
- Incremental backups. Each `ibounce backup` invocation is a full
  snapshot. The state.db is small enough + VACUUM INTO is fast
  enough that incrementals aren't worth the recovery complexity.
