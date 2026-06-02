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
    ok, reason, key_trust = verify_receipt(r, auto_pin_local=False)
    assert ok, reason
    assert reason is None
    assert key_trust == "embedded_unpinned"
    assert signer.receipts_issued == 1
    assert signer.receipts_failed == 0


def test_receipt_roundtrips_through_dict(signer: ReceiptSigner) -> None:
    r = signer.sign_deny(deny_id="d", action="iam:CreateUser", reason="r")
    again = DenialReceipt.from_dict(r.to_dict())
    assert again == r
    ok, _, _ = verify_receipt(again, auto_pin_local=False)
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
    ok, reason, _ = verify_receipt(tampered, auto_pin_local=False)
    assert not ok
    assert reason and "tamper" in reason.lower() or "signature" in reason.lower()


def test_tampering_signature_fails_verify(signer: ReceiptSigner) -> None:
    r = signer.sign_deny(deny_id="d", action="a", reason="r")
    # Flip a char in the signature.
    bad_sig = ("A" if r.signature_b64[0] != "A" else "B") + r.signature_b64[1:]
    tampered = dataclasses.replace(r, signature_b64=bad_sig)
    ok, _, _ = verify_receipt(tampered, auto_pin_local=False)
    assert not ok


def test_verify_rejects_non_deny_verdict(signer: ReceiptSigner) -> None:
    r = signer.sign_deny(deny_id="d", action="a", reason="r")
    tampered = dataclasses.replace(r, verdict="allow")
    ok, reason, _ = verify_receipt(tampered, auto_pin_local=False)
    assert not ok
    assert "verdict" in reason.lower()


def test_verify_with_wrong_pinned_key_fails(
    signer: ReceiptSigner, tmp_path: pathlib.Path
) -> None:
    r = signer.sign_deny(deny_id="d", action="a", reason="r")
    other = ReceiptSigner(keypair_dir=str(tmp_path / "other-keys"))
    ok, reason, key_trust = verify_receipt(
        r, public_key_override_b64=other.public_key_b64,
    )
    assert not ok
    assert key_trust == "pinned"


def test_from_dict_rejects_unknown_schema_version(signer: ReceiptSigner) -> None:
    r = signer.sign_deny(deny_id="d", action="a", reason="r")
    raw = r.to_dict()
    raw["schema_version"] = 999
    with pytest.raises(ValueError, match="schema_version"):
        DenialReceipt.from_dict(raw)


# --------------------------------------------------------------------------
# key_trust / issuer-trust establishment (MEDIUM security fix)
# --------------------------------------------------------------------------


def _forge_receipt(genuine: DenialReceipt, attacker: ReceiptSigner) -> DenialReceipt:
    """Re-sign a copy of ``genuine``'s payload with the ATTACKER's key and
    embed the attacker's public key. This is the self-signed forgery: a
    receipt that self-verifies against its OWN embedded key but was NOT
    issued by iam-jit."""
    import dataclasses as _dc

    unsigned = _dc.replace(
        genuine,
        public_key_fingerprint=attacker.public_key_fingerprint,
        signature_b64="",
        public_key_b64=attacker.public_key_b64,
    )
    sig = attacker._private.sign(unsigned.signing_payload())  # noqa: SLF001
    from iam_jit.receipts.signer import _b64u  # type: ignore

    return _dc.replace(unsigned, signature_b64=_b64u(sig))


def test_genuine_receipt_local_pinned_reports_key_trust_local(
    signer: ReceiptSigner, keydir: pathlib.Path
) -> None:
    # The local on-disk key matches the signer → auto-pin to local, ok.
    r = signer.sign_deny(deny_id="d", action="s3:Delete", reason="r")
    ok, reason, key_trust = verify_receipt(r, keypair_dir=str(keydir))
    assert ok, reason
    assert key_trust == "local"


def test_forged_receipt_fails_against_local_pinned_key(
    signer: ReceiptSigner, keydir: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    # A forged receipt: attacker keypair, self-consistent, embeds the
    # attacker's own pubkey. Verified against the LOCAL on-disk key it
    # MUST FAIL — the forged issuer is caught.
    genuine = signer.sign_deny(deny_id="d", action="s3:Delete", reason="r")
    attacker = ReceiptSigner(keypair_dir=str(tmp_path / "attacker-keys"))
    forged = _forge_receipt(genuine, attacker)
    # Self-verify (embedded) would pass — prove the gap exists...
    ok_embed, _, trust_embed = verify_receipt(forged, auto_pin_local=False)
    assert ok_embed is True
    assert trust_embed == "embedded_unpinned"
    # ...but auto-pinned to the local key it FAILS (forged issuer caught).
    ok, reason, key_trust = verify_receipt(forged, keypair_dir=str(keydir))
    assert ok is False
    assert key_trust == "local"
    assert reason and "different" in reason.lower()


def test_forged_receipt_embedded_unpinned_reports_caveat(
    signer: ReceiptSigner, tmp_path: pathlib.Path
) -> None:
    # No local key, no pin → falls back to the embedded key. A forged
    # receipt self-verifies but key_trust must flag the issuer is NOT
    # verified.
    from iam_jit.receipts.signer import EMBEDDED_UNPINNED_CAVEAT

    genuine = signer.sign_deny(deny_id="d", action="s3:Delete", reason="r")
    attacker = ReceiptSigner(keypair_dir=str(tmp_path / "attacker-keys"))
    forged = _forge_receipt(genuine, attacker)
    # Point at an EMPTY key dir so there's no local key to auto-pin to.
    empty_dir = tmp_path / "no-keys-here"
    empty_dir.mkdir()
    ok, reason, key_trust = verify_receipt(forged, keypair_dir=str(empty_dir))
    assert ok is True  # well-formed signature...
    assert key_trust == "embedded_unpinned"  # ...but issuer UNVERIFIED
    assert "issuer" in EMBEDDED_UNPINNED_CAVEAT.lower()


def test_cli_forged_receipt_embedded_unpinned_surfaces_caveat(
    signer: ReceiptSigner, tmp_path: pathlib.Path
) -> None:
    from click.testing import CliRunner

    genuine = signer.sign_deny(deny_id="d", action="s3:Delete", reason="r")
    attacker = ReceiptSigner(keypair_dir=str(tmp_path / "attacker-keys"))
    forged = _forge_receipt(genuine, attacker)
    rfile = tmp_path / "forged.json"
    rfile.write_text(json.dumps(forged.to_dict()), encoding="utf-8")
    empty_dir = tmp_path / "no-keys-here"
    empty_dir.mkdir()
    res = CliRunner().invoke(
        _cli(), [str(rfile), "--key-dir", str(empty_dir), "--json"]
    )
    payload = json.loads(res.output)
    assert payload["signature_ok"] is True
    assert payload["key_trust"] == "embedded_unpinned"
    assert payload["issuer_unverified"] is True
    assert "issuer" in payload["proves"].lower()
    assert "not verified" in payload["proves"].lower()


def test_cli_forged_receipt_fails_against_local_key(
    signer: ReceiptSigner, keydir: pathlib.Path, tmp_path: pathlib.Path
) -> None:
    from click.testing import CliRunner

    genuine = signer.sign_deny(deny_id="d", action="s3:Delete", reason="r")
    attacker = ReceiptSigner(keypair_dir=str(tmp_path / "attacker-keys"))
    forged = _forge_receipt(genuine, attacker)
    rfile = tmp_path / "forged.json"
    rfile.write_text(json.dumps(forged.to_dict()), encoding="utf-8")
    res = CliRunner().invoke(_cli(), [str(rfile), "--key-dir", str(keydir)])
    assert res.exit_code == 1, res.output
    assert "FAILED" in res.output
    assert "key trust: LOCAL" in res.output


def test_mcp_forged_receipt_embedded_unpinned_flags_issuer(
    signer: ReceiptSigner, tmp_path: pathlib.Path, monkeypatch
) -> None:
    # The MCP surface uses the DEFAULT key dir (no --key-dir). Point the
    # manifest module's DEFAULT_KEYPAIR_DIR at an empty dir so the MCP
    # path falls through to embedded_unpinned deterministically.
    import iam_jit.bouncer.audit_export.manifest as _m
    from iam_jit.mcp_server import _verify_denial_receipt_for_mcp

    empty_dir = tmp_path / "mcp-no-keys"
    empty_dir.mkdir()
    monkeypatch.setattr(_m, "DEFAULT_KEYPAIR_DIR", str(empty_dir))

    genuine = signer.sign_deny(deny_id="d", action="s3:Delete", reason="r")
    attacker = ReceiptSigner(keypair_dir=str(tmp_path / "attacker-keys"))
    forged = _forge_receipt(genuine, attacker)
    out = _verify_denial_receipt_for_mcp({"receipt": forged.to_dict()})
    assert out["signature_ok"] is True
    assert out["key_trust"] == "embedded_unpinned"
    assert out["issuer_unverified"] is True
    assert "issuer" in out["proves"].lower()


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
    ok, _, _ = verify_receipt(r, auto_pin_local=False)
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
    keydir = tmp_path / "audit-keys"
    res = CliRunner().invoke(_cli(), [str(rfile), "--key-dir", str(keydir)])
    assert res.exit_code == 0, res.output
    assert "signature: OK" in res.output
    assert "key trust: LOCAL" in res.output
    assert "RESULT: ok" in res.output


def test_cli_verify_receipt_tampered_fails(
    signer: ReceiptSigner, tmp_path: pathlib.Path
) -> None:
    from click.testing import CliRunner

    r = signer.sign_deny(deny_id="d", action="a", reason="r")
    tampered = dataclasses.replace(r, action="iam:DeleteRole")
    rfile = tmp_path / "receipt.json"
    rfile.write_text(json.dumps(tampered.to_dict()), encoding="utf-8")
    keydir = tmp_path / "audit-keys"
    res = CliRunner().invoke(_cli(), [str(rfile), "--key-dir", str(keydir)])
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
    res1 = CliRunner().invoke(
        _cli(), [str(rfile), "--key-dir", str(keydir), "--nonce-db", str(nonce_db)]
    )
    assert res1.exit_code == 0, res1.output
    assert "FRESH" in res1.output

    # Second verify of the SAME receipt → replay (nonce already consumed,
    # persisted across the separate store opens = restart-equivalent).
    res2 = CliRunner().invoke(
        _cli(), [str(rfile), "--key-dir", str(keydir), "--nonce-db", str(nonce_db)]
    )
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
            _cli(),
            [str(rfile), "--key-dir", str(keydir),
             "--nonce-db", str(nonce_db), "--no-consume"],
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
    keydir = tmp_path / "audit-keys"
    res = CliRunner().invoke(
        _cli(), [str(rfile), "--key-dir", str(keydir), "--json"]
    )
    assert res.exit_code == 0
    payload = json.loads(res.output)
    assert payload["ok"] is True
    assert payload["signature_ok"] is True
    assert payload["key_trust"] == "local"
    assert payload["issuer_unverified"] is False
    assert "RECORD" in payload["proves"]


# --------------------------------------------------------------------------
# Fix 2 — agent_session must be IN the signed payload + verify-receipt
# still passes after the field is populated.
#
# Root cause: proxy.py was reading "x-iam-jit-agent-session-id" (wrong
# header name) instead of "x-agent-session-id" (the canonical
# X-Agent-Session-Id header, per agent_context.AGENT_SESSION_ID_FIELD).
# Result: agent_session was ALWAYS "" in the denial receipt even when the
# agent sent a valid session id — a forensic gap in the signed payload.
#
# The fix propagates agent_session correctly from the request header into
# sign_deny(). These tests confirm:
#   (a) sign_deny() with a session id populates receipt.agent_session
#   (b) the signed payload includes agent_session (signing_payload())
#   (c) verify_receipt() still passes end-to-end with the field populated
#   (d) tampering the agent_session field AFTER signing FAILS verification
# --------------------------------------------------------------------------


def test_agent_session_propagated_into_signed_payload(
    signer: ReceiptSigner,
) -> None:
    """sign_deny(agent_session=...) must land in signing_payload() so it
    is tamper-protected by the Ed25519 signature."""
    session_id = "sid-abc123"
    r = signer.sign_deny(
        deny_id="deny-001",
        action="iam:CreateRole",
        reason="profile-deny",
        agent_session=session_id,
        resource="arn:aws:iam::123456789012:role/x",
    )
    assert r is not None, "sign_deny must succeed"

    # (a) receipt.agent_session is the value we passed in.
    assert r.agent_session == session_id, (
        f"agent_session on receipt must equal the input session id; "
        f"got {r.agent_session!r}"
    )

    # (b) agent_session is inside signing_payload() — tamper-protected.
    import json as _json
    payload_dict = _json.loads(r.signing_payload().decode("utf-8"))
    assert "agent_session" in payload_dict, (
        "agent_session must be a key in signing_payload() so it is "
        "covered by the Ed25519 signature; absent means the field is "
        "not tamper-protected"
    )
    assert payload_dict["agent_session"] == session_id


def test_verify_receipt_passes_with_agent_session_populated(
    signer: ReceiptSigner,
) -> None:
    """verify_receipt() must return OK on a receipt whose agent_session is
    non-empty — confirming that populating the field does not break the
    signing-payload canonicalization."""
    r = signer.sign_deny(
        deny_id="deny-002",
        action="s3:DeleteObject",
        reason="deny-classifier",
        agent_session="session-from-header-xyz",
        resource="arn:aws:s3:::prod-bucket/key",
    )
    assert r is not None
    assert r.agent_session == "session-from-header-xyz"

    ok, reason, key_trust = verify_receipt(r, auto_pin_local=False)
    assert ok, (
        f"verify_receipt must pass on a receipt with populated agent_session; "
        f"reason={reason!r}"
    )
    assert reason is None


def test_tampering_agent_session_fails_verify(
    signer: ReceiptSigner,
) -> None:
    """Mutating agent_session AFTER signing must fail verification — proving
    the field is inside the signed payload, not appended outside it."""
    r = signer.sign_deny(
        deny_id="deny-003",
        action="ec2:TerminateInstances",
        reason="explicit-deny",
        agent_session="legit-session-id",
    )
    assert r is not None

    # Tamper: change the session id to something else after signing.
    tampered = dataclasses.replace(r, agent_session="attacker-injected-id")

    ok, reason, _ = verify_receipt(tampered, auto_pin_local=False)
    assert not ok, (
        "tampering agent_session must invalidate the Ed25519 signature — "
        "the field must be inside signing_payload(), not appended outside"
    )
    assert reason is not None
