"""Local AWS identity heuristics for `iam-jit posture`.

Per the §A42 spec: the posture surface must report whether the
current AWS identity is iam-jit-issued WITHOUT making any AWS API
call (would leak credentials + add latency + miss the disconnected-
operator case).

Three sources of evidence, applied in this order:

1. ``IAM_JIT_ASSUMED_ROLE_ARN`` env var — set by `iam-jit assume` /
   `iam-jit request --print-creds-env` when an operator activates a
   jit-issued role in their shell. Authoritative if present.

2. Path-prefix heuristic on any ARN we can find in the env — the
   default CREATE-NOT-ASSUME path is ``/iam-jit/`` so any role ARN
   with that segment is almost certainly jit-issued.

3. Local cached state at ``~/.iam-jit/last-issued-role.json`` — the
   most recent role iam-jit minted (with TTL) the operator may still
   be using. Cross-checked against the active ARN when known.

When NO evidence applies but an ARN is visible we report
``scoped_role_active="unknown"`` (per [[ibounce-honest-positioning]]:
never claim ``False`` without positive evidence). When no ARN is
visible at all we report ``"unknown"`` with source-detection notes.
"""

from __future__ import annotations

import json
import os
import pathlib
import time
from typing import Any

# Env-var names we consult.
_ENV_JIT_ROLE_ARN = "IAM_JIT_ASSUMED_ROLE_ARN"
_ENV_AWS_PROFILE = "AWS_PROFILE"
_ENV_AWS_DEFAULT_PROFILE = "AWS_DEFAULT_PROFILE"
_ENV_AWS_ACCESS_KEY_ID = "AWS_ACCESS_KEY_ID"
_ENV_AWS_ROLE_ARN = "AWS_ROLE_ARN"

# Path on disk that `iam-jit request` is expected to refresh on each
# successful issuance. Not load-bearing — its absence just means we
# fall back to env-var-only detection.
_LAST_ISSUED_PATH = pathlib.Path.home() / ".iam-jit" / "last-issued-role.json"

# Substring that marks an ARN as iam-jit-issued. Matches both the
# default CREATE-NOT-ASSUME prefix + the optional ``/iam-jit/`` path
# segment custom roles can use.
_JIT_PATH_MARKER = "/iam-jit/"

# Session-tag-based marker (only visible via `aws sts
# get-session-token` AND the operator's local cache; not generally
# inspectable from env vars). Documented here so the field is named.
_JIT_SESSION_TAG_NAME = "iam-jit:issued"


def _read_last_issued() -> dict[str, Any] | None:
    """Read the local last-issued-role cache. Returns None on any
    failure (missing, malformed, unreadable) — we never crash posture
    capture on cache shape drift."""
    try:
        text = _LAST_ISSUED_PATH.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    try:
        data = json.loads(text)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    return data


def _ambient_credential_source() -> str:
    """Best-effort: where is the ambient AWS credential coming from?

    Detection order matches the AWS SDK's own credential-chain order:
      1. Explicit env vars (``AWS_ACCESS_KEY_ID``)
      2. Profile name (``AWS_PROFILE`` / ``AWS_DEFAULT_PROFILE``)
      3. IMDS / instance metadata (we can't probe without network IO;
         report "unknown" rather than guessing)

    Returns a HUMAN string the posture renderer prints verbatim —
    deliberately NOT a key from a controlled vocab, since this is for
    operator legibility.
    """
    if os.environ.get(_ENV_AWS_ACCESS_KEY_ID):
        return "env-vars (AWS_ACCESS_KEY_ID set)"
    prof = os.environ.get(_ENV_AWS_PROFILE) or os.environ.get(
        _ENV_AWS_DEFAULT_PROFILE
    )
    if prof:
        return f"AWS_PROFILE={prof}"
    # If we got here, neither env vars nor a profile is set. Could be
    # IMDS / SSO / web-identity / nothing. Honest "unknown".
    return "unknown (no AWS_ACCESS_KEY_ID / AWS_PROFILE; may be IMDS / SSO)"


def _arn_from_env() -> str | None:
    """Find any AWS role ARN exposed in the env, in priority order."""
    # Most specific first: iam-jit's own pin.
    for name in (_ENV_JIT_ROLE_ARN, _ENV_AWS_ROLE_ARN):
        v = os.environ.get(name, "").strip()
        if v.startswith("arn:aws"):
            return v
    return None


def detect_iam_jit_role(now_epoch: float | None = None) -> dict[str, Any]:
    """Return the iam-jit-issued-role detection block for the posture
    snapshot.

    Schema (matches the §A42 spec):

      {
        "scoped_role_active": true | false | "unknown",
        "role_arn": "<arn or null>",
        "iam_jit_issued_evidence": ["..."],
        "ambient_credential_source": "<human string>",
        "notes": ["..."]
      }

    ``scoped_role_active`` reasoning:
      * ``True`` iff we have positive evidence (env pin matches, path
        marker matches, or local cache says so + still within TTL).
      * ``False`` ONLY if we have positive evidence the active role is
        NOT iam-jit-issued (the role ARN is set and lacks the path
        marker AND no env pin AND no cache hit).
      * ``"unknown"`` otherwise — per [[ibounce-honest-positioning]],
        no false negatives.
    """
    now = now_epoch if now_epoch is not None else time.time()
    arn = _arn_from_env()
    pinned = os.environ.get(_ENV_JIT_ROLE_ARN, "").strip()
    evidence: list[str] = []
    notes: list[str] = []

    # Evidence 1: explicit env pin
    if pinned and pinned.startswith("arn:aws"):
        evidence.append(f"{_ENV_JIT_ROLE_ARN} set in env")

    # Evidence 2: path marker on whatever ARN we see
    if arn and _JIT_PATH_MARKER in arn:
        evidence.append(f"role ARN path contains {_JIT_PATH_MARKER!r}")

    # Evidence 3: local cache
    cache = _read_last_issued()
    if cache is not None:
        cached_arn = cache.get("role_arn") or cache.get("arn")
        expires_at = cache.get("expires_at_epoch") or cache.get(
            "expires_at"
        )
        if isinstance(expires_at, (int, float)) and expires_at > now:
            if isinstance(cached_arn, str) and cached_arn:
                # Cache says "we issued THIS arn; it expires later".
                if arn is None or cached_arn == arn:
                    evidence.append(
                        f"local cache at {_LAST_ISSUED_PATH} "
                        f"(expires in {int(expires_at - now)}s)"
                    )
                    # If env didn't surface an ARN, surface the cached one.
                    if arn is None:
                        arn = cached_arn
                else:
                    notes.append(
                        f"local cache has different ARN ({cached_arn}) "
                        f"than active env ({arn}); cache may be stale"
                    )

    # Resolve scoped_role_active.
    if evidence:
        scoped: Any = True
    elif arn and _JIT_PATH_MARKER not in arn:
        # We CAN see the ARN; it lacks the marker; no pin; no cache.
        # That's positive evidence the role is NOT iam-jit-issued.
        scoped = False
    else:
        scoped = "unknown"
        if arn is None:
            notes.append(
                "no AWS role ARN visible in env; cannot confirm or "
                "rule out iam-jit issuance without an AWS API call"
            )

    return {
        "scoped_role_active": scoped,
        "role_arn": arn,
        "iam_jit_issued_evidence": evidence,
        "ambient_credential_source": _ambient_credential_source(),
        "session_tag_marker": _JIT_SESSION_TAG_NAME,
        "notes": notes,
    }
