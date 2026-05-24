# L10 — Multi-machine config portability

## What this tests

`bounce config export` on machine A → `bounce config import` on
machine B → verify aligned state.

## Why this matters

The MRR-1 audit + the project-config-export-wire-divergence memory
flagged schema reconciliation between bouncers (kbounce + dbounce
ints vs ibounce string `schema_version`). This scenario exercises
the export/import path end-to-end so cross-machine portability
isn't a guess.

## Pass criteria

1. **Machine A setup**: bring up bouncer with a non-trivial config
   (profile installed, 3 dynamic-deny rules, custom port, threat-
   feed publisher pinned).
2. **Export**: `bounce config export --out /work/config.tgz` —
   exits 0, archive contains:
   * profile YAML
   * dynamic-denies.yaml
   * pinned publishers
   * version metadata (so import can reject incompatible schemas)
3. **Machine B setup**: separate scenario state dir (or separate
   container) with EMPTY config.
4. **Import**: `bounce config import --in /work/config.tgz` —
   exits 0; all files materialized at expected paths.
5. **Verify alignment**:
   * Profile YAML byte-identical.
   * Dynamic-denies YAML byte-identical (or semantically identical
     if sort order differs — assertion uses YAML-aware diff).
   * Threat-feed publishers pinned identically.
6. **Smoke**: drive a request that exercises the imported rules;
   confirm same behaviour as Machine A.

## Fail criteria

* Export missing any of the documented config slots.
* Import claims success but config not materialized (status-vs-
  state gap).
* Schema-version mismatch silently accepted (should reject + log).
* Cross-bouncer schema divergence not caught (the existing
  ibounce-vs-Go-bouncer gap).
* Smoke run on Machine B diverges from Machine A.

## Prerequisites

* L2 PASS.
* Two state dirs (or two containers).

## Supported isolation modes

* Mode A preferred (two parallel containers).
* Mode B acceptable with two state roots.

## Expected duration

~5-8 minutes.

## Evidence block schema

```json
{
  "export_exit_code": 0,
  "archive_contains_profile": true,
  "archive_contains_dynamic_denies": true,
  "archive_contains_publishers": true,
  "archive_contains_version_meta": true,
  "import_exit_code": 0,
  "profile_bytes_match": true,
  "denies_semantic_match": true,
  "publishers_match": true,
  "smoke_request_behaviour_match": true,
  "schema_version_check_present": true
}
```
