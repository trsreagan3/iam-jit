"""Cross-product JSON-Schema validation for #276.

Confirms every cross-product schema in `schemas/` validates against
its representative sample in `schemas/testdata/`. Run in CI on every
push so a schema-shape drift surfaces immediately.

Per [[cross-product-agent-parity]]: the four cross-product schemas
(OCSF audit-event, admin-action event, diagnostics manifest, backup
metadata) describe wire shapes EVERY Bounce product emits identically.
A breaking change here cascades across the whole suite.

Per [[deliberate-feature-completion]]: tests + docs + schemas ship
together; the schema files in `schemas/` are NEVER added without a
sample + a validation test in the same commit.
"""

from __future__ import annotations

import json
import pathlib

import jsonschema
import pytest

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
SCHEMAS_DIR = REPO_ROOT / "schemas"
TESTDATA_DIR = SCHEMAS_DIR / "testdata"


def _load(p: pathlib.Path) -> dict:
    return json.loads(p.read_text())


def _validator_with_local_refs(schema: dict) -> jsonschema.Draft202012Validator:
    """Build a Draft 2020-12 validator that resolves $ref against
    the local `schemas/` directory.

    The admin-action schema $refs ocsf-iam-jit-audit-event.schema.json;
    we wire up a registry so `jsonschema` resolves it from disk rather
    than reaching out to the network (per [[self-host-zero-billing-dependency]] —
    no network calls during the test suite).
    """
    try:
        # jsonschema >= 4.18 ships referencing.Registry.
        from referencing import Registry, Resource
        from referencing.jsonschema import DRAFT202012

        resources: list[tuple[str, Resource]] = []
        for path in SCHEMAS_DIR.glob("*.schema.json"):
            body = _load(path)
            resource = Resource(contents=body, specification=DRAFT202012)
            # Register under the bare filename so a relative $ref
            # like "ocsf-iam-jit-audit-event.schema.json" resolves,
            # AND under the $id so a wire-id $ref also resolves.
            resources.append((path.name, resource))
            sid = body.get("$id")
            if sid:
                resources.append((sid, resource))
        registry = Registry().with_resources(resources)
        return jsonschema.Draft202012Validator(schema, registry=registry)
    except ImportError:
        # Fall back to no-ref-resolution; admin-action sample will be
        # validated WITHOUT the OCSF base — better than no test at all.
        return jsonschema.Draft202012Validator(schema)


@pytest.mark.parametrize(
    "schema_file,sample_file",
    [
        ("ocsf-iam-jit-audit-event.schema.json", "ocsf-event-allow.sample.json"),
        ("admin-action-event.schema.json", "admin-action-event.sample.json"),
        ("diagnostics-manifest.schema.json", "diagnostics-manifest.sample.json"),
        ("backup-metadata.schema.json", "backup-metadata.sample.json"),
    ],
)
def test_cross_product_schema_validates_sample(
    schema_file: str, sample_file: str,
) -> None:
    """Each cross-product schema validates its representative sample
    in `schemas/testdata/`. Drift fails the test loudly so a schema
    edit that breaks the sample surface at PR time."""
    schema = _load(SCHEMAS_DIR / schema_file)
    sample = _load(TESTDATA_DIR / sample_file)
    # Rewrite admin-action's relative $ref to the absolute $id of the
    # referenced schema so the registry's $id-based lookup resolves
    # without needing a base_uri callable. Test-only mutation; the
    # on-disk schema keeps the human-friendly relative ref.
    if schema_file == "admin-action-event.schema.json":
        all_of = schema.get("allOf", [])
        for entry in all_of:
            if entry.get("$ref") == "ocsf-iam-jit-audit-event.schema.json":
                entry["$ref"] = "https://iam-jit.dev/schemas/ocsf-iam-jit-audit-event.v1.json"
    validator = _validator_with_local_refs(schema)
    errors = sorted(validator.iter_errors(sample), key=lambda e: list(e.absolute_path))
    assert errors == [], "\n".join(
        f"  {list(e.absolute_path)}: {e.message}" for e in errors
    )


def test_per_product_config_schemas_present() -> None:
    """Sanity: the four per-product config schemas exist + are
    well-formed JSON.

    The kbouncer / dbounce / gbounce config schemas live in their own
    repos; this test only confirms ibounce-config.schema.json is
    present here. Cross-repo sibling check is the per-repo CI's job.
    """
    ibounce = SCHEMAS_DIR / "ibounce-config.schema.json"
    assert ibounce.exists(), f"missing per-product schema: {ibounce}"
    body = _load(ibounce)
    assert body.get("$schema") == "https://json-schema.org/draft/2020-12/schema"
    assert "schema_version" in body.get("properties", {})
    sv = body["properties"]["schema_version"]
    # Post-#288: schema_version is the STRING semver "1.0".
    assert sv.get("type") == "string"
    assert sv.get("enum") == ["1.0"]


def test_index_md_lists_every_schema() -> None:
    """The schemas/INDEX.md table should mention every schema file
    in this directory. A new schema landed without an INDEX.md update
    fails this test (per [[deliberate-feature-completion]])."""
    index_body = (SCHEMAS_DIR / "INDEX.md").read_text()
    for schema_path in SCHEMAS_DIR.glob("*.schema.json"):
        name = schema_path.name
        # ibounce-config + ocsf + admin-action + diagnostics +
        # backup-metadata must all appear by filename in INDEX.md.
        # accounts.schema.json + users.schema.json + request.schema.json
        # are the pre-launch ones not part of the Bounce suite; skip.
        if name in {"accounts.schema.json", "users.schema.json", "request.schema.json"}:
            continue
        assert name in index_body, f"INDEX.md does not mention {name}"
