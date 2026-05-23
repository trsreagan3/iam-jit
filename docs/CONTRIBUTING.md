# Contributing

Per `[[tests-and-independent-uat-required]]` every feature ships with
both automated tests and an independent UAT pass. This document codifies
the single convention that has caught the most operator-visible bugs in
the v1.0 cycle, so future tests inherit the discipline by default.

For test infrastructure (tiers, markers, LocalStack, LLM cassettes) see
[docs/TESTING.md](TESTING.md). This document is the *what to assert*
counterpart to that *how to run* document.

## Testing Standards

### The state-verification convention

> **Every test that asserts a reported success status MUST also assert
> the observable state matches.**

A reported status (a return value, a CLI exit code, a JSON `status: "ok"`
field, a green log line) is a *claim* made by the code under test. The
test's job is to verify the claim is true — which means looking at the
side effect the success implies, not just at the message that asserts it
happened.

### Why this convention exists

In a 2-day v1.0 push the project's own UAT cadence caught **seven bugs
of identical shape**. They are listed here as engineering history per
`[[ibounce-honest-positioning]]` — the convention is not aspirational;
it is what the corpus of real failures demanded:

| # | Surface | What was claimed | What was actually observable |
|---|---|---|---|
| #326 | profile bridge | `status: installed` | empty profile on disk |
| #448 | `improve_profile` | `status: auto_installed` | zero rules persisted |
| #462 | `iam-jit digest` | `status: ok` ("0 denies") | 401 from token misconfig, real denies hidden |
| #463 | `updates revoke` | `status: revoked` in ledger | rule still present in `dynamic-denies.yaml` |
| #475 | synthesis flow | `audit_event_ids: [...]` returned | events were write-only; query returned empty |
| #476 | synthesis flow | `status: auto_approved` | `credentials: null` silently |
| #477 | synthesis flow | `evidence` block accepted | `codebase_references: []` (empty) passed validation |

Every one of these passed the pre-fix test suite because the test
asserted the **status string** was correct. None asserted the
**observable state** matched. The convention below is the minimum
discipline that would have failed each test loudly at PR time.

### Anti-pattern (DO NOT)

```python
def test_revoke_rule():
    result = updates_revoke("tf_official_001")
    assert result["status"] == "revoked"
    # ↑ passes even when the bouncer's remove failed and the rule is
    #   still live in dynamic-denies.yaml. This is the #463 shape.
```

```python
def test_install_profile():
    result = install_profile(payload)
    assert result["status"] == "installed"
    # ↑ passes even when zero rules were written to disk. This is the
    #   #326 + #448 shape.
```

```python
def test_synthesis_emits_audit_events():
    result = request_role_from_synthesis(payload)
    assert result["audit_event_ids"] == ["evt-1", "evt-2"]
    # ↑ passes even when the events are write-only and any subsequent
    #   query returns empty. This is the #475 shape.
```

### Pattern (DO)

```python
def test_revoke_rule_removes_from_dynamic_denies(tmp_path):
    # Setup: the rule is observably present BEFORE the action.
    initial = read_dynamic_denies_yaml(tmp_path)
    assert "tf_official_001" in initial

    result = updates_revoke("tf_official_001")

    # 1. Assert reported status (the claim).
    assert result["status"] == "revoked"

    # 2. Assert observable state matches the claim.
    final = read_dynamic_denies_yaml(tmp_path)
    assert "tf_official_001" not in final

    # 3. Assert the operator-facing output carries no embedded error
    #    that the green status string is masking.
    assert "error" not in (result.get("bouncer_remove_message") or "")
    assert "traceback" not in (result.get("bouncer_remove_message") or "").lower()
```

```python
def test_install_profile_persists_rules(tmp_path):
    result = install_profile(payload, target=tmp_path)
    assert result["status"] == "installed"

    # State verification: the file exists AND has non-zero rules.
    written = read_installed_profile(tmp_path)
    assert written is not None
    assert len(written["rules"]) > 0, (
        f"status was 'installed' but profile has zero rules; got: {written!r}"
    )
```

```python
def test_synthesis_emits_queryable_audit_events(tmp_path):
    result = request_role_from_synthesis(payload)
    assert result["status"] == "auto_approved"
    assert result["audit_event_ids"], "audit_event_ids must not be empty"

    # State verification: the events the response references can
    # actually be retrieved via the operator's normal query path.
    for eid in result["audit_event_ids"]:
        retrieved = audit_query.fetch(eid)
        assert retrieved is not None, (
            f"audit event {eid} was reported but is not queryable; "
            f"this is the #475 shape"
        )
```

### What counts as "observable state"

Anything an operator could check from outside the function under test:

- a file on disk (`dynamic-denies.yaml`, profile YAML, ledger JSONL)
- a row in the SQLite audit DB
- a record returned by the operator's normal query path
  (`iam-jit audit query`, `audit_query.fetch`, `fetch_recent_denies`)
- an HTTP response from a status endpoint (`/healthz`, `/events`)
- an entry in the §A25 pending-approval queue
- a fan-out hot-reload return value (count of bouncers reloaded)
- the absence of a previously-present record (revocation, removal)
- the embedded sub-payload of a "success" wrapper (a `bouncer_remove`
  block inside a `status: revoked` response — bug #463 hid here)

### When the convention applies

**Always**, on any test that touches an operator-facing success path:

- CLI tests whose top-level assertion is the exit code or the JSON
  `status` field
- MCP tool tests whose top-level assertion is the tool's return value
- Async / queue handlers that report "applied" / "completed" / "ok"
- Anything that ends in a notification, banner, or log line the
  operator sees

The convention does NOT apply to:

- Pure-function unit tests that have no operator-visible side effect
  (the return value *is* the observable state)
- Schema validation tests asserting input rejection
- Tests that assert *failure* — failure tests should still verify that
  the failed path left state untouched (which is a state-verification
  assertion of its own), but the "status string vs reality" mismatch
  that motivates this convention is a success-path bug

### Helpers to lean on

| You're verifying | Use |
|---|---|
| `dynamic-denies.yaml` contents | the YAML readers used by the threat-feed tests (`tests/threat_feed/test_cli_updates.py` exemplifies) |
| Recent denies surfaced to the operator | `fetch_recent_denies` from the digest module |
| An audit event is queryable end-to-end | the `iam-jit audit query` CLI path or its module-level entry point |
| A profile is materially installed | the profile-read helpers used by `tests/cli/test_profile_allow.py` |
| The §A25 pending queue contains/lacks an entry | the queue helpers in `improve/pipeline.py` |

If a helper for the surface you're verifying doesn't yet exist, write it
in the test module and graduate it to the production helper layer once
two tests need it.

### Real exemplars in this repo

Treat these as the canonical shape — copy their structure when you add a
new test in the same family:

- `tests/threat_feed/test_cli_updates.py::test_cli_updates_revoke_real_ledger_entry_removes_from_dynamic_denies`
  — pre-asserts the rule is present, calls revoke, asserts both the
  status field AND that the rule is gone from YAML AND that the ledger
  records both apply+revoke.
- `tests/threat_feed/test_cli_updates.py::test_cli_updates_revoke_human_output_has_no_embedded_error`
  — green-banner / embedded-error mismatch directly.
- `tests/cli/test_profile_allow.py::test_profile_allow_applies` —
  status `applied` + on-disk verification.

### Related standing disciplines

- `[[tests-and-independent-uat-required]]` — every feature ships with
  automated tests + an independent UAT pass; this convention is the
  test-side complement to UAT discipline.
- `[[ibounce-honest-positioning]]` — applied to test assertions: a
  reported success that doesn't match observable reality is dishonest
  in exactly the same way a green banner that hides a 401 is.
- `[[v1-deploy-readiness-gate]]` — state-verification gaps are a
  deploy-readiness gate, not a v1.1 nice-to-have.
- `[[creates-never-mutates]]` — when verifying state, prefer reading
  the persisted artifact directly to mutating it for setup; setup
  helpers should construct, not patch.

### v1.1 outlook

A linter that flags `status == "<success-string>"` assertions without a
nearby observable-state assertion is tracked separately (#467); the
intent here is to make the convention a first-class human discipline
that the linter later enforces mechanically. Don't wait for the linter
to land before adopting the convention.
