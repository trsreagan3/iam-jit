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

The baseline file `tools/silent_degradation_linter/baseline.json` lists
finding keys (`SD-N:path:line`) that existed when the ratchet was
initialized. These do **not** fail CI.

### Updating the baseline (accepting new debt)

Only update the baseline after a **deliberate decision** to accept the
existing findings as permanent debt.

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

## Baseline Count (as of v1 init)

| Rule | Existing findings |
|------|------------------|
| SD-1 | 312              |
| SD-2 | 961              |
| SD-4 | 156              |
| **Total** | **1429**    |

These represent pre-existing debt. They are not blocked by CI — only *new*
findings beyond this baseline will fail the ratchet.
