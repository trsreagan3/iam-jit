"""Shared DynamoDB helper utilities.

Centralizes the "did this exception come from a conditional-check
failure?" detection so the same fragile string-match doesn't get
copy-pasted across every DDB-backed store. Round-5/round-6 audits
called this out as a sibling-miss pattern; this module is the
single source of truth.
"""

from __future__ import annotations


def is_conditional_check_failed(exc: Exception) -> bool:
    """Return True iff `exc` is a boto3 ConditionalCheckFailedException.

    Handles two failure modes:
    1. The properly-structured `ClientError` with
       `response["Error"]["Code"] == "ConditionalCheckFailedException"`
       (the common case under live boto3).
    2. Fallback string-match on `str(exc)` (for synthetic mocks in
       tests, or future boto3 layer changes that move the code
       location).
    """
    err = getattr(exc, "response", None)
    if isinstance(err, dict):
        code = err.get("Error", {}).get("Code")
        if code == "ConditionalCheckFailedException":
            return True
    return "ConditionalCheckFailedException" in str(exc)
