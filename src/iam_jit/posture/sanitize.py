"""Credential-leak guard for posture JSON output.

Per the §A42 spec + [[push-policy-public-repo]]: posture output may
include role ARNs, env-var NAMES, and bouncer URLs — those are
identifiers, NOT secrets. But the snapshot must NEVER include:

* AWS access keys (``AKIA*`` / ``ASIA*`` / ``aws_secret_access_key``)
* Session tokens (``aws_session_token`` / ``SessionToken``)
* Bearer tokens / API keys / passwords
* Any value of an env var whose NAME ends in ``_TOKEN`` / ``_SECRET`` /
  ``_KEY`` / ``_PASSWORD`` / ``_PASSWD``

The sanitizer is conservative: it scans the assembled posture dict
just before emit + redacts anything that LOOKS credential-shaped. A
``redacted`` marker stays in place so the operator can tell something
was scrubbed (rather than silently dropped).
"""

from __future__ import annotations

import re
from typing import Any

# ---- Patterns -----------------------------------------------------------
# AWS access key id prefixes per
# https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_identifiers.html
_AWS_AK_RE = re.compile(r"\b(?:AKIA|ASIA|AROA|AIDA)[0-9A-Z]{16,}\b")

# Long base64-ish blobs (40+ chars) are almost always secrets.
_LONG_B64_RE = re.compile(r"\b[A-Za-z0-9+/]{40,}={0,2}\b")

# Hex-encoded secrets (32+ chars).
_LONG_HEX_RE = re.compile(r"\b[0-9a-fA-F]{32,}\b")

# Env-var name suffixes that indicate the VALUE is a credential.
_CREDENTIAL_NAME_SUFFIXES = (
    "_TOKEN",
    "_SECRET",
    "_KEY",
    "_PASSWORD",
    "_PASSWD",
    "_API_KEY",
    "_BEARER",
)

# Env-var name exact matches that are credentials.
_CREDENTIAL_NAME_EXACT = {
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_SECURITY_TOKEN",
    "AWS_ACCESS_KEY_ID",  # ID is less sensitive than secret but conservatively scrub
}

_REDACTED = "[REDACTED]"


def is_credential_env_name(name: str) -> bool:
    """Return True if an env var NAME suggests its VALUE is a secret."""
    upper = name.upper()
    if upper in _CREDENTIAL_NAME_EXACT:
        return True
    return any(upper.endswith(sfx) for sfx in _CREDENTIAL_NAME_SUFFIXES)


def scrub_value(value: str) -> str:
    """Redact credential-shaped substrings inside a single string value.

    ARNs, role names, env var names, port numbers, and bouncer URLs
    pass through unchanged — they're identifiers, not secrets. The
    function only redacts AWS key id patterns + long opaque tokens.
    """
    if not isinstance(value, str):
        return value
    # Order matters: AWS key id first (specific), then long base64,
    # then hex. Each `re.sub` replaces in-place.
    out = _AWS_AK_RE.sub(_REDACTED, value)
    # Only redact long base64 / hex blobs OUTSIDE of arn:aws: contexts
    # (an ARN can contain a 32-char-looking principal id but is safe
    # to share). Cheap check: if the substring is inside an ARN, skip.
    if "arn:aws" not in out.lower():
        out = _LONG_B64_RE.sub(_REDACTED, out)
        out = _LONG_HEX_RE.sub(_REDACTED, out)
    return out


def sanitize_posture(snapshot: Any) -> Any:
    """Deep-walk a posture snapshot + redact credential-shaped values.

    Conservative + recursive:
      * dict -> recurse on every value, AND if the KEY is credential-
        named, force the value to ``[REDACTED]`` regardless of shape.
      * list / tuple -> recurse on each element.
      * str -> ``scrub_value``.
      * other (int / bool / None) -> pass through unchanged.
    """
    if isinstance(snapshot, dict):
        out: dict[str, Any] = {}
        for k, v in snapshot.items():
            if isinstance(k, str) and is_credential_env_name(k):
                # Whole-value redact regardless of shape.
                out[k] = _REDACTED
                continue
            out[k] = sanitize_posture(v)
        return out
    if isinstance(snapshot, list):
        return [sanitize_posture(x) for x in snapshot]
    if isinstance(snapshot, tuple):
        return tuple(sanitize_posture(x) for x in snapshot)
    if isinstance(snapshot, str):
        return scrub_value(snapshot)
    return snapshot
