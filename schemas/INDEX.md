# iam-jit JSON Schema Index

Cross-product JSON Schema registry for the iam-jit / Bounce suite. Every
config artifact + every audit-event shape that crosses a process / repo
/ binary boundary ships with a published JSON Schema so a third-party
tool (SIEM ingest mapping, restore-checker, GitOps validator, agent
introspection) can validate the payload identically.

Per [[cross-product-agent-parity]]: the COMMON SUBSET of fields
(`schema_version`, `product`, `exported_at`, `source_hostname_hash`)
is identical across every Bounce product so one cross-product backup /
ingest / triage script reads identically across the suite.

## Per-product config schemas

| Product   | Schema (in-repo)                                              | Wire ID                                                         |
|-----------|---------------------------------------------------------------|------------------------------------------------------------------|
| ibounce   | `iam-roles/schemas/ibounce-config.schema.json`                | `https://iam-jit.dev/schemas/ibounce-config.v1.json`             |
| kbounce   | `kbouncer/schemas/kbounce-config.schema.json`                 | `https://github.com/trsreagan3/kbouncer/blob/main/schemas/kbounce-config.schema.json` |
| dbounce   | `dbounce/schemas/dbounce-config.schema.json`                  | `https://github.com/trsreagan3/dbounce/schemas/dbounce-config.schema.json` |
| gbounce   | `gbounce/schemas/gbounce-config.schema.json`                  | `https://github.com/trsreagan3/gbounce/blob/main/schemas/gbounce-config.schema.json` |

## iam-jit ambient-config declaration schema

The operator-authored ambient-config declaration (consumed by
`iam_jit_setup_from_config` MCP + `iam-jit doctor apply-config` CLI per
[[ambient-autonomous-protection]]) has its own schema:

| Artifact                            | Schema (in-repo)                                | Wire ID                                                |
|-------------------------------------|-------------------------------------------------|--------------------------------------------------------|
| iam-jit ambient declaration (v1.0)  | `iam-roles/schemas/iam-jit-config.schema.json`  | `https://iam-jit.dev/schemas/iam-jit-config.v1.json`   |

This is the schema for the top-level `.iam-jit.yaml` / `CLAUDE.md`
codeblock declaration; it composes the per-product `bouncer_block` shape
inline rather than $ref-ing the per-product schemas above (the
declaration is operator-authored intent, not a per-bouncer export).

Each product also serves its config schema at `GET /schemas/config` on
the running bouncer's management port so an agent can fetch the
authoritative shape without reaching out to GitHub.

## Cross-product audit / artifact schemas

These schemas describe wire shapes that ALL audit-export Bounce
products (ibounce + kbounce + dbounce) emit identically. The
authoritative copy of each lives in this directory.

| Artifact                       | Schema                                                  |
|--------------------------------|---------------------------------------------------------|
| OCSF v1.1.0 audit event (6003) | `ocsf-iam-jit-audit-event.schema.json`                  |
| Admin-action audit event       | `admin-action-event.schema.json`                        |
| Diagnostics bundle manifest    | `diagnostics-manifest.schema.json`                      |
| Backup metadata table          | `backup-metadata.schema.json`                           |

## Cross-product common subset

Every config-export schema requires this minimum field set:

| Field                  | Type   | Description                                                                                  |
|------------------------|--------|----------------------------------------------------------------------------------------------|
| `schema_version`       | string | Wire-format version. Currently `"1.0"` across the suite per the #288 reconciliation.         |
| `product`              | string | Per-product magic — one of `ibounce`, `kbounce`, `dbounce`, `gbounce`. Gates cross-product import refusal. |
| `exported_at`          | string | RFC3339 UTC timestamp the export ran.                                                        |
| `source_hostname_hash` | string | sha256[:12] of the source host's hostname. Privacy-preserving provenance.                     |

Per-product binary-version fields (`ibounce_version`, `kbounce_version`,
`dbounce_version`, `gbounce_version`) are also required — exactly one
is present, matching the product magic.

## Per-product schema endpoint

Every Bounce product exposes its config schema over HTTP on the mgmt
port:

```
GET /schemas/config
Content-Type: application/schema+json
```

The body is the embedded `*bounce-config.schema.json` byte-for-byte —
the same bytes shipped in the repo. An agent that wants to validate a
proposed import payload against the LIVE bouncer's accepted shape
should fetch this rather than relying on a stale GitHub URL.

## Sample validation

Each per-product schema is exercised against a representative sample
in `testdata/` (`<product>-config.sample.json`). The sample MUST
validate (CI guard). Adding a new optional field bumps the description
only; bumping the wire version requires sample + matching docs update.

## Adding a new schema

1. Author the `*.schema.json` file (this directory for cross-product;
   `<repo>/schemas/` for product-local).
2. Add a representative sample under `testdata/` next to the schema.
3. Add a CI test that loads the schema + validates the sample.
4. Update this INDEX.md table.
5. If the schema describes a wire shape served over HTTP, add a
   `GET /schemas/<shape>` endpoint on the relevant mgmt port.

Per [[deliberate-feature-completion]]: tests + docs ship together
with the schema in the same commit.
