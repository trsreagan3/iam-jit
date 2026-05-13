# End-to-end tests

Tier 3 in the testing system: full stack via `docker-compose.test.yml` plus the iam-jit Lambda invoked via `sam local`. These tests submit a fake role request, watch it move through approval → provisioning (LocalStack IAM) → expiry, and assert the request file ends up in the right state.

These tests land in **Phase 2**, when `provision.py` and the SAM template exist. Until then this directory is a placeholder so the layout is in place.

Run with:

```
scripts/test-local.sh e2e
```
