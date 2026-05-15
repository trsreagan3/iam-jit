"""Shared DynamoDB helper utilities.

Centralizes the "did this exception come from a conditional-check
failure?" detection so the same fragile string-match doesn't get
copy-pasted across every DDB-backed store. Round-5/round-6 audits
called this out as a sibling-miss pattern; this module is the
single source of truth.
"""

from __future__ import annotations


_CCFE = "ConditionalCheckFailedException"


def is_conditional_check_failed(exc: Exception) -> bool:
    """Return True iff `exc` is a boto3 ConditionalCheckFailedException.

    Detection order:
    1. The properly-structured `ClientError` with
       `response["Error"]["Code"] == "ConditionalCheckFailedException"`
       (the common case under live boto3).
    2. The exception class itself is named `ConditionalCheckFailedException`
       (matches the modern resource-typed boto3 exception, e.g.
       `dynamodb.meta.client.exceptions.ConditionalCheckFailedException`).
    3. Anchored substring match on `str(exc)` — either at the start
       of the string OR wrapped in parens (the shape botocore's
       `ClientError.__str__` produces: `"An error occurred
       (ConditionalCheckFailedException) when calling the …"`).

    WB7F-08 closure: previous version did an unanchored substring
    check on str(exc), which could match wrapper / chained exception
    text that merely mentioned the phrase. The anchored form still
    satisfies the synthetic-mock test fixtures (which raise an
    exception whose message starts with the code name) while
    rejecting noise from wrappers that embed the phrase elsewhere
    in their message.
    """
    err = getattr(exc, "response", None)
    if isinstance(err, dict):
        code = err.get("Error", {}).get("Code")
        if code == _CCFE:
            return True
    if type(exc).__name__ == _CCFE:
        return True
    s = str(exc)
    if s.startswith(_CCFE):
        return True
    if f"({_CCFE})" in s:
        return True
    return False
