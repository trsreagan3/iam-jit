"""Backend registry + selection.

Selection precedence for `default_score_backend()`:

  1. Explicit `IAM_JIT_LLM_BACKEND` env var
     ("bedrock" | "anthropic" | "openai" | "ollama").
     Unknown name → ValueError listing available backends.
  2. Existing `IAM_JIT_LLM` env var (back-compat with the old
     selection contract — `anthropic` / `bedrock` / `ollama`).
  3. First available backend in the deterministic preference order:
     anthropic → openai → bedrock → ollama. We prefer hosted-API
     backends ahead of Bedrock because the AWS Bedrock model-access
     gate currently has a 30-60 day approval lead time (see
     [[aws-account-verification]]) — when a customer has BOTH a key
     and Bedrock enabled, the hosted API is the friendlier default.

A "per-request override" comes from either the
`preferred_backend=` kwarg or the per-account
`llm_account_policy` decision. Overrides gate on `is_available()`
— if the chosen backend has no creds, we log + fall back to the
default chain rather than failing the whole scoring call.
"""

from __future__ import annotations

import logging
import os
from typing import Any, Protocol

from .backends import anthropic as _b_anthropic
from .backends import bedrock as _b_bedrock
from .backends import ollama as _b_ollama
from .backends import openai as _b_openai
from .types import ScoreContext, ScoreResponse

logger = logging.getLogger("iam_jit.llm.registry")


class _Backend(Protocol):
    name: str

    def score_policy(
        self, policy: dict[str, Any], context: ScoreContext
    ) -> ScoreResponse: ...

    def is_available(self) -> bool: ...

    def estimate_cost_per_1k(
        self, input_tokens: int, output_tokens: int
    ) -> float: ...


# Module-style backends — each module exposes `name`, `score_policy`,
# `is_available`, `estimate_cost_per_1k`. We treat the module itself
# as the backend object; the registry never has to instantiate a class.
_BACKENDS: dict[str, Any] = {
    _b_bedrock.name: _b_bedrock,
    _b_anthropic.name: _b_anthropic,
    _b_openai.name: _b_openai,
    _b_ollama.name: _b_ollama,
}

# Default order for "first-available" autoselect (see module docstring).
_AUTOSELECT_ORDER: tuple[str, ...] = ("anthropic", "openai", "bedrock", "ollama")


def available_backends() -> list[str]:
    """Sorted list of registered backend names."""
    return sorted(_BACKENDS.keys())


def get_score_backend(name: str) -> Any:
    """Return the backend module for `name`. Raises ValueError if unknown.

    Does NOT check `is_available()` — that's the caller's choice
    (registry consumers may want the module for `estimate_cost_per_1k`
    even when the backend isn't currently configured).
    """
    backend = _BACKENDS.get((name or "").strip().lower())
    if backend is None:
        raise ValueError(
            f"unknown LLM backend: {name!r}. "
            f"Available: {', '.join(available_backends())}."
        )
    return backend


def default_score_backend(
    *,
    preferred: str | None = None,
) -> Any | None:
    """Pick a backend for the current call.

    Precedence (highest first):
      - `preferred` argument (per-request override; usually from the
        per-account `llm_policy.preferred_backend`)
      - `IAM_JIT_LLM_BACKEND` env var
      - `IAM_JIT_LLM` env var (back-compat alias)
      - first-available in `_AUTOSELECT_ORDER`

    Returns the backend module, or None when no backend is available
    in this environment (callers fall back to deterministic-only).
    """
    # Per-request override (preferred from caller, e.g. account policy)
    if preferred:
        try:
            backend = get_score_backend(preferred)
        except ValueError as e:
            logger.warning(
                "llm.backend.select preferred=%s rejected: %s; falling back",
                preferred, e,
            )
        else:
            if backend.is_available():
                logger.info(
                    "llm.backend.select source=preferred name=%s", backend.name
                )
                return backend
            logger.info(
                "llm.backend.select preferred=%s not available; falling back",
                preferred,
            )

    # Explicit env var
    explicit = (os.environ.get("IAM_JIT_LLM_BACKEND") or "").strip().lower()
    if explicit:
        try:
            backend = get_score_backend(explicit)
        except ValueError as e:
            logger.warning(
                "llm.backend.select IAM_JIT_LLM_BACKEND=%s rejected: %s",
                explicit, e,
            )
        else:
            if backend.is_available():
                logger.info(
                    "llm.backend.select source=env name=%s", backend.name
                )
                return backend
            logger.info(
                "llm.backend.select env=%s not available; falling back",
                explicit,
            )

    # Back-compat: honor the legacy IAM_JIT_LLM if it names a real backend
    legacy = (os.environ.get("IAM_JIT_LLM") or "").strip().lower()
    if legacy and legacy in _BACKENDS:
        backend = _BACKENDS[legacy]
        if backend.is_available():
            logger.info(
                "llm.backend.select source=legacy_env name=%s", backend.name
            )
            return backend

    # First-available in deterministic order
    for cand_name in _AUTOSELECT_ORDER:
        backend = _BACKENDS[cand_name]
        if backend.is_available():
            logger.info(
                "llm.backend.select source=autoselect name=%s", backend.name
            )
            return backend

    logger.info("llm.backend.select no backend available; deterministic-only")
    return None
