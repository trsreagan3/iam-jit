"""NanoClaw integration robustness tests — verify Paths A/B/C end-to-end.

Per task #312 (founder direction 2026-05-22) + the openclaw-nanoclaw-architecture memo.

These tests are integration-only (skipped in regular CI) — they require
Docker + a free LocalStack on :4566 + kind on the standard kubeconfig +
postgres on :5432, plus a working build of every bouncer binary.

Bring local infrastructure up with:

    docker compose -f ${HOME}/repos/dogfood/docker-compose.yml up -d

Run with:

    pytest tests/integration/nanoclaw_paths -m integration -v
"""
