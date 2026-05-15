"""Test-support modules — NOT part of the production runtime contract.

Anything in this package is importable for tests, smoke-rigs, local
dev tools, and CI E2E harnesses. It must NOT be imported from
production code paths (app.py, routes/, middleware.py, etc.).
"""
