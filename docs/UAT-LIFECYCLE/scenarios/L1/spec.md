# L1 — Fresh install on clean system

## What this tests

The very-first-time operator experience: `pip install` + `go install`
on a system with NO leftover iam-jit state. Confirms the install
creates the right directories with the right permissions, the
binaries land on PATH, and no daemon starts uninvited.

## Why this matters

The most common day-1 failure for any tool is "install succeeded but
the binary isn't where it should be" or "first run crashed because a
parent dir doesn't exist + the code assumed it did." The MRR-1 audit
flagged use case 30 (`iam-jit init` interview not shipped) as a CRIT;
this scenario gives operators the deterministic floor regardless of
whether the interview ships.

## Pass criteria

1. `pip install -e .` from `/src/iam-roles` exits 0 with no resolution
   errors.
2. `go install ./cmd/...` from `/src/gbounce` exits 0.
3. `iam-jit --version` exits 0 and reports a SemVer.
4. `gbounce --version` exits 0 and reports a SemVer.
5. `~/.iam-jit/` is NOT created merely by importing the package; it is
   created lazily on first state-writing command.
6. `iam-jit posture` works on a clean machine (zero state) and reports
   `mode: neither` honestly.
7. No background process is started by the install itself.

## Fail criteria

* Any of the above steps exits non-zero.
* `~/.iam-jit/` is created prematurely (eager directory creation =
  bug; install shouldn't claim user storage).
* `iam-jit --version` prints a Python traceback (means import-time
  side effect failed).
* `gbounce --version` reports an empty / `unknown` version (the
  version-constant-didn't-bump pattern from
  `[[canary-redeploys-on-every-update]]`).

## Prerequisites

* Clean Ubuntu 22.04 container (Mode A) OR ephemeral state dir on
  host with `IAM_JIT_HOME` pointed away from real `~/.iam-jit/`
  (Mode B).
* Python 3.12+ available in the container/host.
* Go 1.22+ available in the container/host.
* `/src/iam-roles` + `/src/gbounce` mounted read-only.

## Supported isolation modes

* **Mode A (Docker)**: preferred. Guarantees a truly clean system.
* **Mode B (ephemeral dir)**: acceptable. Won't catch
  partially-installed-from-previous-attempt regressions.

## Expected duration

~3-5 minutes (dominated by `pip install` + `go install`).

## Evidence block schema

```json
{
  "pip_install_exit_code": 0,
  "go_install_exit_code": 0,
  "iam_jit_version": "0.x.y",
  "gbounce_version": "0.x.y",
  "iam_jit_home_created_at_import": false,
  "iam_jit_home_created_after_state_cmd": true,
  "posture_reported_mode": "neither",
  "background_processes_started": []
}
```

## Composes with

* `[[canary-redeploys-on-every-update]]` — install path is part of
  the redeploy loop; this scenario validates the cold-start half.
* `docs/CONTRIBUTING.md` — state-verification: assertions check the
  observable on-disk state, not just `pip` exit codes.
