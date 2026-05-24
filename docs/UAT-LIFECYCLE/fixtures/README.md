# UAT Lifecycle Fixtures

Shared test data for the 15 lifecycle scenarios. All fixtures are
SYNTHETIC — no real-AWS responses, no operator-identifying data, no
real credentials.

## Per `[[push-policy-public-repo]]`

Every fixture in this tree is safe to commit to a public repo
because:

* AWS credentials are clearly-marked test patterns (`AKIATEST...`).
* Test threat-feed payloads are signed with a publicly-known test
  keypair (private key committed under
  `threat-feed/PUBLISHER-TEST-KEY-DO-NOT-USE-IN-PROD.priv` with the
  loud warning).
* Workflow templates use generic example.com / docs.python.org
  URLs.
* Audit-event generators produce realistic shapes but fictional
  account IDs (`000000000000` or `111111111111`).
* Mock cred sources rotate `AKIATEST...` patterns only.

## Subdirectories

| Dir | Scenarios | Purpose |
|---|---|---|
| `canary-yaml/` | L2 | Hand-written `.iam-jit.yaml` files for bring-up tests. |
| `audit-events/` | L5, L9 | Synthetic audit-event generators (Python scripts that emit OCSF-shaped JSON). |
| `mock-creds/` | L1, L13, L14 | Mock AWS + LLM credentials. |
| `workflows/` | L5 | Realistic NL workflow templates for profile generation. |
| `threat-feed/` | L6 | Signed test threat-feed payloads + test public key. |
| `mock-llm/` | L13 | Mock LLM HTTP server fixture for cred-rotation testing. |
| `state-snapshots/` | L7, L9 | Pre-state snapshots restored at scenario start. |

## Stage A status

Stage A creates the directory structure + this README. **The
individual fixture files are Stage B deliverables** — they need
careful construction (signing test keypairs, generating realistic
audit shapes, etc.) which is better done by the agents implementing
each scenario than pre-built generically.

Stage B agents pick fixture file paths from the scenario specs
(`scenarios/L{N}/spec.md` lists `fixtures_needed`).
