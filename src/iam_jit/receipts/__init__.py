"""Cryptographically-receipted denials + persistent nonce store —
#731 / BUILD-10.

On a DENY the bouncer can mint an Ed25519-signed *denial receipt*:
tamper-evident proof of iam-jit's RECORD that it denied action X at
time T for reason R. A persistent nonce store (durable across restart)
makes replays detectable. An operator/auditor verifies offline with
``iam-jit audit verify-receipt <file>``.

Honest framing (``[[ibounce-honest-positioning]]``): the receipt proves
the DENIAL RECORD, not that the agent couldn't act through some other
channel. See :mod:`iam_jit.receipts.signer`.

Crypto reuses the #427 signed-manifest pattern (same keypair mgmt,
canonical JSON, URL-safe base64). Composes with #443 structured-deny
(shared ``deny_id``) and #463 audit-verify CLI.
"""

from __future__ import annotations

from .nonce_store import (
    DEFAULT_MAX_ENTRIES,
    DEFAULT_NONCE_DB_NAME,
    InMemoryNonceStore,
    NonceCheck,
    SqliteNonceStore,
    open_nonce_store,
)
from .signer import (
    DEFAULT_RECEIPT_KEY_NAME,
    RECEIPT_SCHEMA_VERSION,
    RECEIPT_VERDICT,
    DenialReceipt,
    ReceiptSigner,
    verify_receipt,
)

__all__ = [
    "DEFAULT_MAX_ENTRIES",
    "DEFAULT_NONCE_DB_NAME",
    "DEFAULT_RECEIPT_KEY_NAME",
    "RECEIPT_SCHEMA_VERSION",
    "RECEIPT_VERDICT",
    "DenialReceipt",
    "InMemoryNonceStore",
    "NonceCheck",
    "ReceiptSigner",
    "SqliteNonceStore",
    "open_nonce_store",
    "verify_receipt",
]
