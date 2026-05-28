#!/usr/bin/env bash
# Copy repo-root data files into the package directory so the
# Lambda bundle (CodeUri=src/) ships them alongside the code.
#
# Background: schema.py, users_store.py, accounts_store.py, and
# onboarding.py call iam_jit._resources.find() to locate JSON
# schemas and the destination CloudFormation template. The resolver
# checks several candidate layouts; this script keeps the
# `src/iam_jit/schemas/...` and `src/iam_jit/infrastructure/...`
# layouts populated for the Lambda build.
#
# Idempotent. Run before `sam build`. Also wired into `make
# deploy-dry-run` and `make sam-build` (if those targets exist).

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PKG_DIR="${REPO_ROOT}/src/iam_jit"

# Schemas
mkdir -p "${PKG_DIR}/schemas"
cp -f "${REPO_ROOT}/schemas/"*.json "${PKG_DIR}/schemas/"

# CFN templates. `destination-account-roles.yaml` is loaded at runtime
# by onboarding.py; other templates (e.g. `ci-nightly-dogfood.yaml`
# from #700 / #703) are CI-only and don't need to ship in the wheel,
# but mirroring them keeps the test_packaged_data_in_sync.py drift
# guard (#699) honest without per-file allowlists. ~8KB / file cost
# in the wheel is negligible vs the maintenance footgun of explicit
# allowlists that future devs forget to update.
mkdir -p "${PKG_DIR}/infrastructure/cloudformation"
cp -f "${REPO_ROOT}/infrastructure/cloudformation/"*.yaml \
  "${PKG_DIR}/infrastructure/cloudformation/"

echo "synced data files into ${PKG_DIR}"
