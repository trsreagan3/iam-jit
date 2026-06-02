# Silent-Degradation Linter

AST + grep-based linter that flags patterns where code swallows errors,
ignores parameters, or returns success-shapes on partial failure.

Runs as a **ratchet** in CI: existing baseline findings are allowed, new
findings are not.

---

## Rules

### SD-1 — Bare `except: pass`

Flags `except` handlers whose entire body is a single `pass` statement.
This silently discards exceptions — errors disappear with no log, no
counter-increment, no re-raise.

**Bad:**
```python
try:
    do_thing()
except Exception:
    pass        # <- SD-1
```

**Good:**
```python
try:
    do_thing()
except Exception as e:
    logger.warning("do_thing failed: %s", e)
```

---

### SD-2 — Ignored Function Parameters

Flags parameters that are declared in a function signature but never
referenced anywhere in the function body.

**Automatic opt-outs (never flagged):**
- `self` / `cls`
- Parameters with a `_` prefix (conventional unused marker: `_unused`)
- Stub / Protocol method bodies (`def f(x): ...` / `pass`)
- Methods decorated with `@abstractmethod` or `@overload`

**Bad:**
```python
def provision(account_id: str, region: str, dry_run: bool) -> dict:
    return _do_provision(account_id, region)  # dry_run never used <- SD-2
```

**Good:**
```python
def provision(account_id: str, region: str, dry_run: bool) -> dict:
    if dry_run:
        return {"status": "dry-run"}
    return _do_provision(account_id, region)
```

---

### SD-4 — Positive Return Inside `except` Block

Flags `return <positive-value>` inside an `except` handler, where the
caller receives a success shape on failure.

Positive values detected: `True`, `None` (bare `return`), `"ok"`,
`"success"`, `"done"`, `{"status": "ok"}`, `{"ok": True}`, etc.

**Bad:**
```python
def apply_config(cfg: dict) -> bool:
    try:
        _write(cfg)
    except OSError:
        return True   # <- SD-4: caller thinks it succeeded
```

**Good:**
```python
def apply_config(cfg: dict) -> bool:
    try:
        _write(cfg)
        return True
    except OSError as e:
        logger.error("apply_config failed: %s", e)
        return False
```

---

### SD-3 / SD-5 (Deferred)

- **SD-3** (`or`-default fallback without test coverage) — follow-up task #623
- **SD-5** (audit-without-response-check in tests) — follow-up task #624

---

## Suppression

### Inline `# noqa` comment

Add `# noqa: SD-N <human reason>` on the offending line:

```python
except Exception:  # noqa: SD-1 optional probe step; failure is non-fatal
    pass
```

```python
return {"status": "ok"}  # noqa: SD-4 caller checks via side-channel counter
```

The `<human reason>` is mandatory for clarity but not enforced by the tool.

### `.silent_degradation_ignore` file

Add paths or glob patterns to suppress entire files:

```
# Suppress specific file (legacy shim — no owner yet)
src/iam_jit/compat_legacy.py  legacy shim, tracked in #999

# Suppress a test directory
tests/dogfood/*  dogfood tests use intentional swallow patterns
```

---

## Baseline

The baseline file `tools/silent_degradation_linter/baseline.json` pins the
silent-degradation findings that existed when the ratchet was initialized.
These do **not** fail CI — only findings *beyond* the baseline do.

### Content-keyed signatures (schema v2)

Findings are keyed by a **stable content/context signature**, not by line
number. The signature is:

```
SD-N:<path>:<sha256(rule ⨁ path ⨁ normalized_message ⨁ normalized_context)>
```

where `normalized_context` is a small window (±2 lines) of the surrounding
source, whitespace-normalized, with blank lines dropped. The raw line number
is recorded only as informational metadata (in `--format=json`/`pretty`
output) and is **not** part of the identity.

**Why this matters:** previously findings were keyed `SD-N:path:LINE`, so any
unrelated edit that shifted line numbers made every downstream finding read as
"new" — every PR rebase required a `--baseline-update` re-pin. With
content-keying:

- A finding that merely **moves** (blank lines inserted above it, an unrelated
  edit elsewhere in the file) keeps the same signature → **not** flagged. This
  is the rebase false-positive that the line-keyed scheme produced.
- A **genuinely-new** silent-degradation in new/changed code produces a new
  signature (its surrounding context differs, or it is in a new location) →
  **still flagged**. Detection of real new debt is *not* weakened.
- A finding that **moves to a different file** has a different `path` in its
  signature → correctly treated as new (a finding in a new location is a new
  finding).

### Duplicate handling (multiset counts)

Identical findings in identical surrounding code legitimately collide on one
signature (e.g. the same `except Exception: pass` repeated in a file). The
baseline therefore pins each signature to a **count** (a multiset), and the
ratchet compares counts:

```json
{
  "schema": 2,
  "findings": {
    "SD-1:src/iam_jit/audit.py:621beafb74497c85": 1,
    "SD-2:tests/x_test.py:9b2c…": 4
  },
  "count": 1479
}
```

- Adding a **second** copy of an already-baselined finding pushes its count
  above what is pinned → the surplus occurrence is flagged as new.
- **Removing** one of two identical findings drops the count → tolerated (the
  ratchet only fails on *new* debt, never on debt reduction).

### Updating the baseline (accepting new debt)

Only update the baseline after a **deliberate decision** to accept the
existing findings as permanent debt. `--baseline-update` rewrites
`baseline.json` from the **current tree** in the v2 content-keyed schema:
every present finding's signature is recorded with its occurrence count. It is
safe to re-run after any code change; because keys are content-based, a pure
line-shift produces an **identical** baseline file (no churn).

```bash
# Review all findings first:
PYTHONPATH=tools python -m silent_degradation_linter --no-baseline

# Then write them all to the baseline:
PYTHONPATH=tools python -m silent_degradation_linter --baseline-update

# Commit:
git add tools/silent_degradation_linter/baseline.json
git commit -m "chore: accept SD-N debt in baseline — reason"
```

**Never add to baseline without a human decision.** That defeats the ratchet.

---

## CLI Reference

```bash
# Scan default paths (src/iam_jit/ + tests/)
PYTHONPATH=tools python -m silent_degradation_linter

# Scan specific paths
PYTHONPATH=tools python -m silent_degradation_linter src/iam_jit/provision.py

# Report ALL findings (ignore baseline)
PYTHONPATH=tools python -m silent_degradation_linter --no-baseline

# JSON output (for scripting)
PYTHONPATH=tools python -m silent_degradation_linter --format=json

# GitHub Actions annotations
PYTHONPATH=tools python -m silent_degradation_linter --format=github

# Only SD-1 and SD-4
PYTHONPATH=tools python -m silent_degradation_linter --rules=SD-1,SD-4

# Update the baseline
PYTHONPATH=tools python -m silent_degradation_linter --baseline-update

# Use a custom baseline file
PYTHONPATH=tools python -m silent_degradation_linter --baseline /path/to/baseline.json
```

**Exit codes:** `0` = clean (no new findings), `1` = new findings detected, `2` = internal error.

---

## CI Integration

The ratchet runs as the `silent-degradation-lint` GitHub Actions workflow
(`.github/workflows/silent-degradation-lint.yml`). It triggers on:

- Pull requests touching `src/**`, `tests/**`, or `tools/silent_degradation_linter/**`
- Pushes to `main`

The workflow:
1. Runs `pytest tests/test_silent_degradation_clean.py` (the ratchet test)
2. On failure, runs the linter in `--format=github` mode to produce inline
   PR annotations

---

## Adding New Rules

1. Add a `SD<N>Visitor` class in `tools/silent_degradation_linter/lint.py`
   following the existing visitor pattern.
2. Wire it into `scan_file()` with an `if "SD-N" in rules:` guard.
3. Add fixture files:
   - `tools/silent_degradation_linter/tests/fixtures/sd<n>_positive.py`
   - `tools/silent_degradation_linter/tests/fixtures/sd<n>_negative.py`
4. Add test cases in `tools/silent_degradation_linter/tests/test_rules.py`.
5. Update this doc.
6. Run `--baseline-update` to baseline any existing debt.

---

## Baseline Count

The baseline pins a multiset of content signatures totalling the current
debt. These represent pre-existing debt: they are not blocked by CI — only
*new* findings beyond this baseline will fail the ratchet. To see the live
breakdown by rule:

```bash
PYTHONPATH=tools python -m silent_degradation_linter --no-baseline --format=json \
  | python -c "import json,sys,collections; print(collections.Counter(f['rule'] for f in json.load(sys.stdin)))"
```
