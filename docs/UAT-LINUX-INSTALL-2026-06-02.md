# UAT: Linux Install-Bootstrap — 2026-06-02

Task: #740 — Linux install-loop end-to-end verification  
Agent: Independent UAT (Claude Sonnet 4.6)  
Branch: `feat/740-linux-install-uat`

## Summary

Verified the full install-bootstrap loop on three Linux platforms via `docker run`.
Found and fixed one critical cross-platform bug (`datetime.UTC` Python 3.10
compatibility). All three platforms pass after the fix.

## Platform Results

| Platform | Python | pip install | ibounce init | ibounce run | decisions_count tick | iam-jit init | Result |
|---|---|---|---|---|---|---|---|
| Ubuntu 22.04 | 3.10.12 | ✅ | ✅ (after fix) | ✅ | ✅ | ✅ | **PASS** |
| Debian 12 (bookworm) | 3.12.13 | ✅ | ✅ | ✅ | ✅ | ✅ | **PASS** |
| Fedora 40 | 3.12.8 | ✅ | ✅ | ✅ | ✅ | ✅ | **PASS** |

## Bug Found and Fixed

### CRIT: `datetime.UTC` not available on Python 3.10 (Ubuntu 22.04)

**Symptom:** `ibounce init` crashed with:

```
AttributeError: module 'datetime' has no attribute 'UTC'
  File "iam_jit/bouncer/store.py", line 538, in add_rule
    _isoformat_z(_dt.datetime.now(_dt.UTC)),
```

**Root cause:** `datetime.UTC` (a convenient alias for `datetime.timezone.utc`)
was added in Python 3.11 (PEP 689). Ubuntu 22.04 ships Python 3.10. The
`pyproject.toml` declares `requires-python = ">=3.10"` but the code used
`datetime.UTC` throughout 101 call sites.

**Impact chain:**
1. `ibounce init` crashes → no default rules applied to SQLite DB
2. `ibounce run` starts but the HTTP proxy crashes on every request with
   `500 Internal Server Error` (`Server got itself in trouble`)
3. `decisions_count` never ticks because requests are not processed
4. Any boto3 call gets `ResponseParserError` instead of a proper AWS error

**Fix:** Added a Python 3.10 compatibility shim to `src/iam_jit/__init__.py`:

```python
import datetime as _dt_compat
if not hasattr(_dt_compat, "UTC"):
    _dt_compat.UTC = _dt_compat.timezone.utc  # type: ignore[attr-defined]
```

This runs at package-import time (before any submodule uses `_dt.UTC`),
so all 101 call sites in `bouncer/store.py`, `bouncer/proxy.py`, and 
other modules automatically work on Python 3.10+.

**Verification:** `test_datetime_utc_compat_py310` explicitly verifies
the patch on all three platforms including Ubuntu 22.04 (Python 3.10).

## Install Sequence Verified

```
# Step 1: pip upgrade (PEP 668 fix) + install from repo
python3 -m venv /opt/venv && source /opt/venv/bin/activate
python3 -m pip install --upgrade pip
pip install /workspace   # volume-mount of the repo

# Step 2: ibounce init (SQLite state + 17 default rules)
ibounce init

# Step 3: ibounce run (HTTP proxy on :8767)
ibounce run --port 8767 --mode cooperative &

# Step 4: boto3 STS call through ibounce
AWS_ACCESS_KEY_ID=AKIAFAKEKEY... boto3 STS call → decisions_count ticks

# Step 5: iam-jit init (writes ~/.iam-jit/iam-jit.yaml)
iam-jit init --non-interactive --no-doctor-check --skip-mcp-install \
  --bouncers ibounce --data-dir /tmp/iam-jit-data --overwrite
```

## Notes

- `ibounce init --quiet` does NOT exist (no `--quiet` flag). Tests use
  `| head -N` to truncate output.
- `ibounce run` mode names: `cooperative` (observe-only, equivalent to
  `discovery` in `iam-jit init` terminology), `transparent` (enforcement),
  `plan-capture`.
- Fake AWS credentials (`AKIAFAKEKEY000001`) are sufficient to trigger
  `decisions_count` — boto3 builds a valid SigV4 HTTP request, ibounce
  parses it, records the decision, and forwards to AWS which rejects the
  fake creds. The ibounce decision is recorded BEFORE the upstream response.
- Ubuntu 22.04 requires a venv (system pip blocks `--break-system-packages`
  for Python packages installed via apt in some configurations).
- Fedora 40 lacks `which` by default; tests use `command -v` or check
  PATH directly.

## Test Files Added

- `tests/integration/test_linux_install_e2e.py` — 6 tests (3 platforms × 2 test functions):
  - `test_linux_install_e2e[ubuntu-22.04]` ✅
  - `test_linux_install_e2e[debian-12]` ✅
  - `test_linux_install_e2e[fedora-40]` ✅
  - `test_datetime_utc_compat_py310[ubuntu-22.04]` ✅
  - `test_datetime_utc_compat_py310[debian-12]` ✅
  - `test_datetime_utc_compat_py310[fedora-40]` ✅

## Code Changes

- `src/iam_jit/__init__.py` — adds `datetime.UTC` shim for Python 3.10
- `tests/integration/test_linux_install_e2e.py` — new integration test suite
- `docs/UAT-LINUX-INSTALL-2026-06-02.md` — this document
- `.github/workflows/linux-install-matrix.yml` — nightly CI for all 3 platforms
