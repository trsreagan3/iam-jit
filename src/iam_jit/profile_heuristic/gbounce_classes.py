# Phase 1 — gbounce (HTTP) method + path tables.
"""gbounce action classification.

The bouncer's audit event surfaces HTTP as either a bare method
(``GET`` / ``POST`` / ``PUT`` / ``PATCH`` / ``DELETE``) or a prefixed
form (``http:GET``). The optional ``resource`` is typically the host or
URL — a few well-known IMDS / STS hosts force ADMIN regardless of
method per `docs/PROFILE-GENERATION-DESIGN.md` §2.1.

Per design §2.1:

* READ: GET, HEAD, OPTIONS
* WRITE_DATA: POST, PUT, PATCH
* ADMIN: CONNECT to IMDS / *.aws.amazon.com/sts
* DESTRUCTIVE_DATA: DELETE method
"""

from __future__ import annotations


READ_METHODS: frozenset[str] = frozenset({
    "GET", "HEAD", "OPTIONS", "TRACE",
})


WRITE_METHODS: frozenset[str] = frozenset({
    "POST", "PUT", "PATCH",
})


# DELETE is always destructive-data per design.
DESTRUCTIVE_METHODS: frozenset[str] = frozenset({
    "DELETE",
})


# CONNECT + admin-shape methods.
ADMIN_METHODS: frozenset[str] = frozenset({
    "CONNECT",
})


# Resource hosts/paths that force ADMIN (any method) per design §2.1
# admin row: "CONNECT to IMDS / *.aws.amazon.com/sts". Case-insensitive
# substring match.
ADMIN_RESOURCE_HINTS: tuple[str, ...] = (
    "169.254.169.254",  # EC2 IMDS
    "100.100.100.200",  # Alibaba IMDS
    "metadata.google.internal",  # GCP IMDS
    "metadata.azure.com",  # Azure IMDS
    "sts.amazonaws.com",
    "sts.aws.amazon.com",
    ".sts.amazonaws.com",
    "iam.amazonaws.com",
    "secretsmanager.",
)


def normalize_method(action: str) -> str:
    """Return the bare HTTP method. Handles ``http:GET`` → ``GET`` and
    ``GET`` → ``GET``. Anything unparseable returns the upper-case
    input so the UNKNOWN classifier path runs."""
    if not action:
        return ""
    s = action.strip()
    if ":" in s:
        prefix, _, tail = s.partition(":")
        if prefix.lower() in ("http", "https", "g", "gbounce", "gbouncer"):
            s = tail
    return s.strip().upper()


__all__ = [
    "READ_METHODS",
    "WRITE_METHODS",
    "ADMIN_METHODS",
    "DESTRUCTIVE_METHODS",
    "ADMIN_RESOURCE_HINTS",
    "normalize_method",
]
