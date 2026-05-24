# L11 recipe — clean uninstall

Harness-primary. Agent may help interpret "did the uninstall doc
match what the command did" — operators should be able to predict
what uninstall touches before running it.

## Steps for the operator's agent

1. **Pre-check**: confirm `iam-jit uninstall` (or equivalent) is
   shipped via `iam-jit --help`. If not, harness will SKIP and the
   agent should propose filing MRR-4 dependency task.
2. Run `deterministic-harness.sh`.
3. If PASS: verify the uninstall doc accurately describes what was
   removed — operator should not be surprised.
4. If FAIL on leftover-state: surface immediately + recommend
   manual cleanup script per `docs/MRR-4-...` (when it lands).

## MCP tools

| Tool | Purpose |
|---|---|
| `iam_jit_posture` | Pre-uninstall (mode active) + post-reinstall (mode neither) |

No LLM reasoning required for the binary verdict.
