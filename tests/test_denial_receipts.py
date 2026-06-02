"""Denial-receipt + persistent-nonce-store tests — #731 / BUILD-10.

Covers the security-load-bearing behaviours that UAT + the security
audit will scrutinise:

  * a minted receipt verifies (signature)
  * tampering ANY signed field → verify fails (loud)
  * replay (same nonce presented twice) → detected (loud)
  * the nonce store SURVIVES restart (the headline trust signal:
    Signet-style in-memory stores reopen a replay window on restart;
    ours doesn't)
  * signing failure is FAIL-SOFT (sign_deny returns None, never raises)
  * a nonce-store write failure is fail-soft (receipt still issued)
  * persistence (a fresh SqliteNonceStore on the same file sees prior
    nonces)
  * the CLI `iam-jit audit verify-receipt` round-trips + flags replay
"""

from __future__ import annotations

import dataclasses
import json
import pathlib

import pytest

from iam_jit.receipts import (
    DenialReceipt,
    InMemoryNonceStore,
    ReceiptSigner,
    SqliteNonceStore,
    open_nonce_store,
    verify_receipt,
)
from iam_jit.receipts.signer import RECEIPT_SCHEMA_VERSION


# --------------------------------------------------------------------------
# fixtures
# --------------------------------------------------------------------------


@pytest.fixture
def keydir(tmp_path: pathlib.Path) -> pathlib.Path:
    d = tmp_path / "audit-keys"
    return d


@pytest.fixture
def nonce_db(tmp_path: pathlib.Path) -> pathlib.Path:
    return tmp_path / "nonces.sqlite3"


@pytest.fixture
def signer(keydir: pathlib.Path, nonce_db: pathlib.Path) -> ReceiptSigner:
    store = open_nonce_store(str(nonce_db))
    return ReceiptSigner(nonce_store=store, keypair_dir=str(keydir))


# --------------------------------------------------------------------------
# signing + verification
# --------------------------------------------------------------------------


def test_receipt_signs_and_verifies(signer: ReceiptSigner) -> None:
    r = signer.sign_deny(
        deny_id="deny-abc",
        action="s3:DeleteBucket",
        reason="explicit-deny rule",
        agent_session="sess-1",
        resource="arn:aws:s3:::prod-bucket",
    )
    assert r is not None
    assert r.verdict == "deny"
    assert r.schema_version == RECEIPT_SCHEMA_VERSION
    assert r.nonce
    assert r.public_key_fingerprint
    ok, reason = verify_receipt(r)
    assert ok, reason
    assert reason is None
    assert signer.receipts_issued == 1
    assert signer.receipts_failed == 0


def test_receipt_roundtrips_through_dict(signer: ReceiptSigner) -> None:
    r = signer.sign_deny(deny_id="d", action="iam:CreateUser", reason="r")
    again = DenialReceipt.from_dict(r.to_dict())
    assert again == r
    ok, _ = verify_receipt(again)
    assert ok


@pytest.mark.parametrize(
    "field",
    ["deny_id", "action", "resource", "reason", "agent_session",
     "nonce", "timestamp", "bouncer_product"],
)
def test_tampering_any_signed_field_fails_verify(
    signer: ReceiptSigner, field: str
) -> None:
    r = signer.sign_deny(
        deny_id="d", action="s3:PutObject", reason="r",
        agent_session="s", resource="arn:aws:s3:::b/k",
    )
    tampered = dataclasses.replace(r, **{field: r.__dict__[field] + "X"})
    ok, reason = verify_receipt(tampered)
    assert not ok
    assert reason and "tamper" in reason.lower() or "signature" in reason.lower()


def test_tampering_signature_fails_verify(signer: ReceiptSigner) -> None:
    r = signer.sign_deny(deny_id="d", action="a", reason="r")
    # Flip a char in the signature.
    bad_sig = ("A" if r.signature_b64[0] != "A" else "B") + r.signature_b64[1:]
    tampered = dataclasses.replace(r, signature_b64=bad_sig)
    ok, _ = verify_receipt(tampered)
    assert not ok


def test_verify_rejects_non_deny_verdict(signer: ReceiptSigner) -> None:
    r = signer.sign_deny(deny_id="d", action="a", reason="r")
    tampered = dataclasses.replace(r, verdict="allow")
    ok, reason = verify_receipt(tampered)
    assert not ok
    assert "verdict" in reason.lower()


def test_verify_with_wrong_pinned_key_fails(
    signer: ReceiptSigner, tmp_path: pathlib.Path
) -> None:
    r = signer.sign_deny(deny_id="d", action="a", reason="r")
    other = ReceiptSigner(keypair_dir=str(tmp_path / "other-keys"))
    ok, reason = verify_receipt(r, public_key_override_b64=other.public_key_b64)
    assert not ok


def test_from_dict_rejects_unknown_schema_version(signer: ReceiptSigner) -> None:
    r = signer.sign_deny(deny_id="d", action="a", reason="r")
    raw = r.to_dict()
    raw["schema_version"] = 999
    with pytest.raises(ValueError, match="schema_version"):
        DenialReceipt.from_dict(raw)


# --------------------------------------------------------------------------
# nonce store: replay + persistence
# --------------------------------------------------------------------------


def test_replay_detected_same_nonce_twice(signer: ReceiptSigner) -> None:
    r = signer.sign_deny(deny_id="d", action="a", reason="r")
    store = signer.nonce_store
    first = store.check_and_consume(r.nonce)
    assert first.known and not first.replay and first.consume_count == 1
    second = store.check_and_consume(r.nonce)
    assert second.known and second.replay and second.consume_count == 2


def test_unknown_nonce_is_not_fresh(nonce_db: pathlib.Path) -> None:
    store = open_nonce_store(str(nonce_db))
    chk = store.check_and_consume("never-minted-nonce")
    assert not chk.known
    assert not chk.is_fresh()


def test_nonce_store_survives_restart(
    keydir: pathlib.Path, nonce_db: pathlib.Path
) -> None:
    # Mint via signer #1 against the on-disk db.
    store1 = open_nonce_store(str(nonce_db))
    signer1 = ReceiptSigner(nonce_store=store1, keypair_dir=str(keydir))
    r = signer1.sign_deny(deny_id="d", action="a", reason="r")
    # Legitimate first consume.
    assert store1.check_and_consume(r.nonce).replay is False
    store1.close()

    # Simulate a process RESTART: brand-new store object on the SAME
    # file. An in-memory store would forget r.nonce here; ours must not.
    store2 = open_nonce_store(str(nonce_db))
    after_restart = store2.check_and_consume(r.nonce)
    assert after_restart.known is True
    assert after_restart.replay is True, (
        "persistent nonce store must detect a replay across restart — "
        "this is the headline trust signal vs in-memory Signet-style stores"
    )


def test_persisted_entries_count(nonce_db: pathlib.Path) -> None:
    s = open_nonce_store(str(nonce_db))
    s.record_minted("n1", deny_id="d", ts="2026-06-03T00:00:00Z")
    s.record_minted("n2", deny_id="d", ts="2026-06-03T00:00:01Z")
    s.close()
    s2 = open_nonce_store(str(nonce_db))
    assert s2.count() == 2


def test_lru_eviction_bounds_store(nonce_db: pathlib.Path) -> None:
    s = SqliteNonceStore(str(nonce_db), max_entries=3)
    for i in range(6):
        s.record_minted(f"n{i}", ts=f"2026-06-03T00:00:0{i}Z")
    assert s.count() == 3
    assert s.evicted == 3
    # Oldest evicted → unrecognised; newest retained.
    assert s.check_and_consume("n0").known is False
    assert s.check_and_consume("n5").known is True


def test_in_memory_store_does_not_persist_conceptually() -> None:
    # The in-memory store is the explicitly-weaker fallback; a "restart"
    # (new object) forgets everything.
    s1 = InMemoryNonceStore()
    s1.record_minted("n1")
    assert s1.check_and_consume("n1").replay is False
    s2 = InMemoryNonceStore()  # "restart"
    assert s2.check_and_consume("n1").known is False


# --------------------------------------------------------------------------
# fail-soft
# --------------------------------------------------------------------------


def test_signing_failure_is_fail_soft(signer: ReceiptSigner) -> None:
    # Break the private key so .sign() raises; sign_deny must return
    # None (caller proceeds with a receipt-less deny), NEVER raise.
    class _Boom:
        def sign(self, *_a, **_k):
            raise RuntimeError("hsm offline")

    signer._private = _Boom()  # type: ignore[assignment]
    out = signer.sign_deny(deny_id="d", action="a", reason="r")
    assert out is None
    assert signer.receipts_failed == 1
    assert signer.receipts_issued == 0


def test_nonce_store_write_failure_is_fail_soft(
    keydir: pathlib.Path,
) -> None:
    # A nonce-store that raises on write must NOT void an already-good
    # signature: the receipt is still returned (operator loses replay
    # detection for that one nonce, never the deny or the signature).
    class _BadStore:
        def record_minted(self, *_a, **_k):
            raise RuntimeError("disk full")

    s = ReceiptSigner(nonce_store=_BadStore(), keypair_dir=str(keydir))
    r = s.sign_deny(deny_id="d", action="a", reason="r")
    assert r is not None
    ok, _ = verify_receipt(r)
    assert ok
    assert s.receipts_issued == 1
    assert s.receipts_failed == 1  # the store failure was counted


def test_signer_status_snapshot(signer: ReceiptSigner) -> None:
    signer.sign_deny(deny_id="d", action="a", reason="r")
    st = signer.status()
    assert st["configured"] is True
    assert st["receipts_issued"] == 1
    assert st["public_key_fingerprint"]
    assert st["nonce_store"]["backend"] == "sqlite"


# --------------------------------------------------------------------------
# CLI: iam-jit audit verify-receipt
# --------------------------------------------------------------------------


def _cli():
    import click

    from iam_jit.cli_audit_verify import register_audit_verify_receipt_command

    @click.group()
    def audit():
        pass

    return register_audit_verify_receipt_command(audit)


def test_cli_verify_receipt_ok(
    signer: ReceiptSigner, tmp_path: pathlib.Path
) -> None:
    from click.testing import CliRunner

    r = signer.sign_deny(
        deny_id="deny-1", action="s3:DeleteBucket", reason="explicit-deny",
        agent_session="sess", resource="arn:aws:s3:::b",
    )
    rfile = tmp_path / "receipt.json"
    rfile.write_text(json.dumps(r.to_dict()), encoding="utf-8")
    res = CliRunner().invoke(_cli(), [str(rfile)])
    assert res.exit_code == 0, res.output
    assert "signature: OK" in res.output
    assert "RESULT: ok" in res.output


def test_cli_verify_receipt_tampered_fails(
    signer: ReceiptSigner, tmp_path: pathlib.Path
) -> None:
    from click.testing import CliRunner

    r = signer.sign_deny(deny_id="d", action="a", reason="r")
    tampered = dataclasses.replace(r, action="iam:DeleteRole")
    rfile = tmp_path / "receipt.json"
    rfile.write_text(json.dumps(tampered.to_dict()), encoding="utf-8")
    res = CliRunner().invoke(_cli(), [str(rfile)])
    assert res.exit_code == 1
    assert "FAILED" in res.output


def test_cli_verify_receipt_detects_replay_via_nonce_db(
    keydir: pathlib.Path, nonce_db: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    from click.testing import CliRunner

    store = open_nonce_store(str(nonce_db))
    signer = ReceiptSigner(nonce_store=store, keypair_dir=str(keydir))
    r = signer.sign_deny(deny_id="d", action="a", reason="r")
    store.close()
    rfile = tmp_path / "receipt.json"
    rfile.write_text(json.dumps(r.to_dict()), encoding="utf-8")

    # First verify against the persistent db → fresh, consumes the nonce.
    res1 = CliRunner().invoke(_cli(), [str(rfile), "--nonce-db", str(nonce_db)])
    assert res1.exit_code == 0, res1.output
    assert "FRESH" in res1.output

    # Second verify of the SAME receipt → replay (nonce already consumed,
    # persisted across the separate store opens = restart-equivalent).
    res2 = CliRunner().invoke(_cli(), [str(rfile), "--nonce-db", str(nonce_db)])
    assert res2.exit_code == 1, res2.output
    assert "REPLAY" in res2.output


def test_cli_verify_receipt_no_consume_peek(
    keydir: pathlib.Path, nonce_db: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    from click.testing import CliRunner

    store = open_nonce_store(str(nonce_db))
    signer = ReceiptSigner(nonce_store=store, keypair_dir=str(keydir))
    r = signer.sign_deny(deny_id="d", action="a", reason="r")
    store.close()
    rfile = tmp_path / "receipt.json"
    rfile.write_text(json.dumps(r.to_dict()), encoding="utf-8")

    # --no-consume must NOT mark the nonce consumed → repeated peeks stay
    # fresh.
    for _ in range(3):
        res = CliRunner().invoke(
            _cli(), [str(rfile), "--nonce-db", str(nonce_db), "--no-consume"]
        )
        assert res.exit_code == 0, res.output
        assert "FRESH" in res.output


def test_cli_verify_receipt_json_output(
    signer: ReceiptSigner, tmp_path: pathlib.Path
) -> None:
    from click.testing import CliRunner

    r = signer.sign_deny(deny_id="d", action="a", reason="r")
    rfile = tmp_path / "receipt.json"
    rfile.write_text(json.dumps(r.to_dict()), encoding="utf-8")
    res = CliRunner().invoke(_cli(), [str(rfile), "--json"])
    assert res.exit_code == 0
    payload = json.loads(res.output)
    assert payload["ok"] is True
    assert payload["signature_ok"] is True
    assert "RECORD" in payload["proves"]
