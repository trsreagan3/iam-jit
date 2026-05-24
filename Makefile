PY := .venv/bin/python
PYTEST := .venv/bin/pytest
CFN_LINT := .venv/bin/cfn-lint

# Suppress a benign deprecation warning from `samtranslator` (a
# cfn-lint dependency) emitted on Python 3.14: "Core Pydantic V1
# functionality isn't compatible with Python 3.14 or greater." The
# library still works; the warning is just stderr noise. A
# first-time operator running `make deploy-dry-run` shouldn't have
# to wonder whether they need to fix it before continuing.
export PYTHONWARNINGS = ignore::UserWarning:samtranslator.compat

.PHONY: test recordings recordings-clean deploy-dry-run sync-lambda-data claim-bootstrap

# One-shot operator command — run immediately after deploying the
# destination-account CFN (`infrastructure/cloudformation/destination-
# account-roles.yaml`). Auto-claims the bootstrap admin, opens the
# operator's browser signed in, and (when the magic-link is clicked)
# narrows the ALB security group from 0.0.0.0/0 to the operator's
# actual IP.
#
# Zero flags = use defaults from env / .iam-jit-local. Override with:
#   make claim-bootstrap PROFILE=foo STACK=bar REGION=us-west-2
claim-bootstrap:
	$(PY) scripts/claim-bootstrap.py \
	  $(if $(PROFILE),--profile $(PROFILE)) \
	  $(if $(STACK),--stack $(STACK)) \
	  $(if $(REGION),--region $(REGION))

test:
	$(PYTEST) tests -q --ignore=tests/integration --ignore=tests/e2e

# Round-by-round convergence snapshot. Run after every adversarial-loop
# closure or when verifying that recent commits haven't regressed.
.PHONY: round-stats
round-stats:
	$(PY) scripts/round-stats.py

# Overall corpus histogram — bucket counts per risk-score band.
.PHONY: histogram
histogram:
	$(PY) scripts/corpus-histogram.py

# Both side-by-side
.PHONY: convergence
convergence: histogram round-stats

# Run JUST the data-driven calibration corpus (fast, no LLM).
# Use this in the inner loop when iterating on src/iam_jit/review.py
# — it's faster than the full suite and surfaces calibration shifts
# immediately. CI runs it on every commit.
calibrate:
	$(PYTEST) tests/test_calibration_corpus.py -v

# Run the calibration corpus AGAINST the LLM backend (deterministic
# scorer still drives the score; LLM contributes narrative). Used
# to confirm LLM narratives are populating + that the deterministic
# safety contract holds. Slow because each example invokes the LLM.
calibrate-llm:
	OLLAMA_HOST=$${OLLAMA_HOST:-http://localhost:11434} \
	IAM_JIT_LLM_MODEL=$${IAM_JIT_LLM_MODEL:-qwen2.5:14b} \
	IAM_JIT_LLM=$${IAM_JIT_LLM:-ollama} \
	$(PYTEST) tests/test_calibration_corpus.py tests/integration -v -m integration

# Test the no-LLM path explicitly. The deterministic scorer + auto-
# approve gate + lifecycle must all work with `IAM_JIT_LLM=none`.
# Set the env var explicitly so a developer who has IAM_JIT_LLM
# exported in their shell doesn't accidentally test the LLM path
# under the wrong label.
test-noai:
	IAM_JIT_LLM=none \
	OLLAMA_HOST= \
	IAM_JIT_LLM_MODEL= \
	$(PYTEST) tests -q --ignore=tests/integration --ignore=tests/e2e

# Test the LLM-narrative path against the local Ollama. Requires
# the operator to be running Ollama with the model available.
# Default model is qwen2.5:14b — override with IAM_JIT_LLM_MODEL=...
# when running. The integration suite under tests/integration/
# verifies the LLM-narrative shape + the deterministic-scorer
# safety contract holds even with the LLM in play (score is
# fully deterministic, LLM contributes only narrative + suggestions).
test-llm:
	OLLAMA_HOST=$${OLLAMA_HOST:-http://localhost:11434} \
	IAM_JIT_LLM_MODEL=$${IAM_JIT_LLM_MODEL:-qwen2.5:14b} \
	IAM_JIT_LLM=ollama \
	$(PYTEST) tests/integration -v -m integration

# Composite: run BOTH modes end-to-end. Use this in CI / pre-deploy
# to confirm the dual-mode contract holds. Each mode is tested with
# its own pytest invocation so a regression in one doesn't mask the
# other.
test-all-modes: test-noai test-llm
	@echo "Both NoAI + LLM modes passed."

# Copy schemas + destination-account CFN into src/iam_jit/ so the
# pip-installable wheel ships them alongside the package. Idempotent.
# (Previously this also fed the hosted Lambda bundle; the hosted
# Lambda was dropped 2026-05-24 per [[no-hosted-saas]] restoration.
# The script remains useful for sdist/wheel packaging.)
sync-lambda-data:
	./scripts/sync-lambda-data.sh

# `sam-build` + `deploy-mvp` targets were removed on 2026-05-24
# when the hosted iam-risk-score Lambda was dropped per
# [[no-hosted-saas]] restoration. Self-host operators deploy the
# destination-account roles via
# `infrastructure/cloudformation/destination-account-roles.yaml`
# directly; see docs/DEPLOYMENT.md for the supported install paths.

recordings:
	$(PY) recordings/run_all.py

recordings-clean:
	rm -rf recordings/output/*.webm recordings/output/*.mp4

# ----------------------------------------------------------------------
# Local integration-test infrastructure (#215, [[local-test-infra-spec]])
# ----------------------------------------------------------------------
#
# Spins LocalStack + Keycloak (real OIDC IdP) via docker compose, runs
# the build-tagged integration suite, tears down. Integration tests
# SKIP CLEANLY when their target service isn't reachable, so this
# Makefile target is the convenient wrapper — the integration suite
# itself is always safe to run with `pytest tests/integration -v`.
#
# Closes the "AWS-account-verify blocked" excuse pattern per
# [[local-test-infra-unblocks-aws-wait]]. See docs/LOCAL-TEST-INFRA.md
# for what's covered locally vs what still needs the real AWS account.
.PHONY: test-integration test-integration-clean
test-integration:
	docker compose -f docker-compose.test.yml up -d
	LOCALSTACK_ENDPOINT=http://127.0.0.1:4566 \
	IAM_JIT_KEYCLOAK_URL=http://127.0.0.1:8088 \
	OLLAMA_HOST=$${OLLAMA_HOST:-http://127.0.0.1:11434} \
	$(PYTEST) tests/integration -v
	docker compose -f docker-compose.test.yml down

test-integration-clean:
	docker compose -f docker-compose.test.yml down -v

# Validate the destination-account template locally before any AWS
# write. Catches the majority of "deploy fails at AWS" issues in
# under 30 seconds. No AWS credentials needed.
#
# (The hosted SAM template was dropped 2026-05-24 — see the
# `sync-lambda-data` comment block above.)
deploy-dry-run: sync-lambda-data
	@echo "==> cfn-lint: destination-account template"
	# Suppressions live in .cfnlintrc at the repo root so the Makefile
	# and tests/test_cfn_lint.py share one config (no drift).
	$(CFN_LINT) infrastructure/cloudformation/destination-account-roles.yaml
	@echo "==> structural CFN parse tests"
	$(PYTEST) tests/test_cloudformation_templates.py tests/test_cfn_lint.py -q
	@echo ""
	@echo "✓ destination-account template parses + lints clean."
