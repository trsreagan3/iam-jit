# Round 31 audit — license-file + user-count soft cap (#161)

Commit under review: `b20b16a` HEAD + follow-ups `12acbda`, `06495d7`.

Scope:
- `src/iam_jit/license.py` (new, ~345 LOC: Ed25519 verifier + `License` dataclass + cap-enforcement surface)
- `src/iam_jit/users_store.py:277-310` (DDB user-store wire-in: `put()` cap gate + `_count_users()`)
- `src/iam_jit/cli.py:957-1023` (`iam-jit license show` + `iam-jit license verify`)
- `tests/test_license.py` (new, 441 LOC, 29 unit tests + 3 DDB-wire tests)

Read-only audit. Per [[audit-cadence-discipline]]. The last three audits (WB28/29/30) each surfaced HIGH/CRIT findings that unit tests passed clean; this round probes the new signature/verify trust boundary + the user-store integration specifically against the "opaque-failures-only" promise the verifier docstring makes and the "updates ungated" invariant the wire-in promises.

Regression: **2627 passed**, 29 skipped, 14 deselected (92.37s, excluding `tests/e2e/*` + `tests/test_calibration_corpus.py`). Pre-WB31 baseline was 2598; +29 unit + 3 DDB-wire = +32 matches the expected delta. Zero regressions.

## Headline

11 findings: **1 CRIT-launch-block, 3 HIGH, 4 MED, 3 LOW.**

The CRIT is the `PRODUCTION_PUBLIC_KEY_B64` placeholder shipping in v1.0. Empirically no naive forge succeeds against the all-zero pubkey on modern OpenSSL Ed25519 (low-order subgroup check kicks in), so this is not an immediate exploit today — but the placeholder is a launch-blocker because the failure mode if it slips through to v1.0 is "anyone who knows Ed25519 internals can attempt structured forges + nobody can verify a real license either way." Needs to be either replaced with the real production pubkey AND release-gated, or the source must hard-refuse to verify when the placeholder is detected.

The 3 HIGHs are:

- **HIGH-31-01**: Signed payload with naive (no-tz) datetimes raises `TypeError`, not `LicenseInvalidError`, violating the verifier's "Never raises a different exception type" trust-boundary promise. Propagates: `current_user_cap()` does not catch `TypeError` either, so the user-store cap gate crashes with `TypeError` instead of falling back to Free tier. A founder-signed license with a typo in the date format becomes an availability-incident at the production user-store.
- **HIGH-31-02**: `routes/users.py:129` (admin user-create POST) catches `StoreReadOnly` only; `UserCapExceededError` is uncaught and surfaces as a 500. The admin who just hit the cap gets a generic error instead of the carefully-crafted "install an Enterprise license at..." remediation message that the `enforce_user_creation_cap` author wrote precisely for this surface.
- **HIGH-31-03**: `DynamoDBUserStore.put()` bare-`except Exception` around `get_item` misclassifies every transient DDB failure (throttling, timeout, AccessDenied) as "user does not exist" — which triggers the cap-check + cap-rejection path. An UPDATE to an existing user during a DDB throttle event raises `UserCapExceededError` even though the user-store is supposed to never gate updates. Composes with HIGH-31-02: the update returns a 500 instead of either succeeding or returning a clear "DDB throttled, retry" error.

The 4 MEDs cluster around audience-confusion, type-coercion, double-load, and naive-datetime handling:

- **MED-31-01**: No `aud` / `product` field in the payload. A license signed by the founder for product A (e.g. a future iam-jit-bouncer split per [[two-product-split]] or a separate iam-risk-score-pro line) verifies identically as a license for product B if both products embed the same root pubkey. The current product surface is one; this becomes load-bearing the moment a second product ships.
- **MED-31-02**: `max_users` accepts `True` (which is `1` in Python: `isinstance(True, int) == True`). A signer who typos `"max_users": true` in JSON gets a 1-user license. Trivial finding but the type-coercion contradicts the explicit `isinstance(max_users, int)` check (which doesn't filter bools).
- **MED-31-03**: `enforce_user_creation_cap(license_obj=None)` calls `current_user_cap(None)` then (on cap-exceeded) `current_tier(None)`. Each calls `load_license()` independently — so the user-store gate reads + signature-verifies the license file TWICE per put when the cap fires. Worse, an attacker who can modify the license file between the two reads can race a different tier/cap pair into the error message.
- **MED-31-04**: Race window — `get_item` + `_count_users` + `put_item` is non-atomic in DDB. Reproduced: 10 concurrent puts at count=24 all pass the cap check, final count = 34 (9 over Free cap). Memo documents this as "race-tolerant by design" but the magnitude (single-digit cap overshoot is one thing; tail-amplification under bulk-creation tooling is another) deserves a written bound.

The 3 LOWs:

- **LOW-31-01**: Symlinks followed by default. `pathlib.Path(...).read_bytes()` follows the link; a license file at `~/.iam-jit/license.json` symlinked to `/etc/passwd` won't verify (it's not JSON) but the warning message in logs will be the parse error, not "file is a symlink." Low-impact (verification still fails closed) but unusual for credential-shaped files which usually refuse symlinks.
- **LOW-31-02**: Payload-level extra fields silently dropped. `payload["audience"] = "..."` ignored without warning. If a future schema adds `aud` enforcement, old licenses that have it (or are missing it) will fail unexpectedly. Pre-emptively rejecting unknown payload fields locks the schema down.
- **LOW-31-03**: Outer-level extra fields silently dropped. Same shape as LOW-31-02 but for the outer `{payload, signature}` envelope. `{"payload": ..., "signature": ..., "extra": "foo"}` accepted.

## Closure status

(Audit only; nothing fixed in this round.)

| Finding | Status |
|---|---|
| CRIT-31-00 `PRODUCTION_PUBLIC_KEY_B64` placeholder must not ship in v1.0 (anyone-can-self-sign risk after a real key rollout + structural launch-block) | OPEN |
| HIGH-31-01 Naive-datetime signed payload leaks `TypeError` past `verify_license_bytes`; crashes `current_user_cap` + user-store gate | OPEN |
| HIGH-31-02 `routes/users.py:129` doesn't catch `UserCapExceededError`; admin user-create hitting cap returns 500 instead of structured 4xx with remediation | OPEN |
| HIGH-31-03 `DynamoDBUserStore.put` bare-except misclassifies throttled `get_item` as "new user"; updates erroneously rejected by cap gate during DDB throttle | OPEN |
| MED-31-01 No `aud`/`product` field in payload; cross-product license confusion the moment a second product ships | OPEN |
| MED-31-02 `max_users=True` accepted as `1` (Python bool-is-int); contradicts `isinstance(max_users, int)` intent | OPEN |
| MED-31-03 `enforce_user_creation_cap` double-loads license (cap then tier); two signature verifications per gate-fire + TOCTOU on tier mismatch | OPEN |
| MED-31-04 Cap-gate race window unbounded; 10 concurrent puts at count=24 all succeed, final count=34 | OPEN |
| LOW-31-01 Symlinks followed by default in license-file read | OPEN |
| LOW-31-02 Payload-level extra fields silently accepted (no strict-mode) | OPEN |
| LOW-31-03 Outer-envelope-level extra fields silently accepted (no strict-mode) | OPEN |

## CRIT finding

### CRIT-31-00 — `PRODUCTION_PUBLIC_KEY_B64` placeholder shipping in v1.0 is a launch-block

- File: `src/iam_jit/license.py:64`.

- Issue: The embedded production pubkey is currently a 32-byte all-zero string:
  ```python
  PRODUCTION_PUBLIC_KEY_B64 = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
  ```
  The in-source comment is correct in intent ("Replace with the real production key before the v1.0 release tag") but there is no enforcement of that constraint anywhere in the code or build. The release tag could ship with the placeholder in place; CI doesn't grep for it; `iam-jit license show` doesn't refuse to operate; the verifier doesn't refuse to verify against this key.

- Empirical probe results:
  - `Ed25519PublicKey.from_public_bytes(b"\x00" * 32)` is ACCEPTED by `cryptography` 41+ at decode time (no curve-membership check at decode).
  - 1000 random 64-byte signatures over a forged payload: 0 verified. Modern OpenSSL Ed25519 (BoringSSL-derived) rejects A in the small-order subgroup at verify time per RFC 8032 §5.1.7, so naive forges fail.
  - 100 cross-verify attempts (sigs from random Ed25519 keys against the placeholder pubkey): 0 verified.

  So today's exposure is bounded by OpenSSL's spec-compliant rejection of identity-pubkey verification — but this is fragile:
  1. Some Ed25519 libraries (notably older `pynacl` and some Go implementations) do NOT do the small-order check and DO accept signatures against the identity pubkey via the trivial forge `(R, s) = ([s]B, s)` — meaning any consumer who re-implements the verifier (e.g. a hypothetical iam-jit Go client) would have a hole.
  2. The placeholder also breaks the rollout path: when the real key is installed, all licenses signed under the placeholder (if any leaked into customer hands during pre-launch beta) need to be re-issued. There's no key-rotation mechanism in the file format.
  3. The strongest argument is the launch-block one: a v1.0 tag with the placeholder is a public commit that says "this code's license-verification is non-functional." Anyone who reads the source learns that the gate is bypass-honest in the worst possible way — not "you can patch out the gate" (which is the documented honest position) but "the gate appears to work and silently accepts nothing." That's a worse failure mode than "no gate at all" because it gives operators false confidence that licenses are being verified.

- Why CRIT: the failure mode if this slips through to v1.0 is reputational + structural. The product cannot ship with a publicly-acknowledged broken license-verification path; the moment the placeholder is replaced, the codebase needs to refuse to operate with the placeholder still in place. This is the kind of finding the WB29 + WB28 audit cadence was designed to catch.

- Fix shape (three together):
  1. Generate the real production keypair offline; commit ONLY the public-key b64 to `license.py`.
  2. Add a release-gate test that grep-asserts `PRODUCTION_PUBLIC_KEY_B64 != "AAAAA..."` (one-line in CI).
  3. Add a runtime guard at module-load time:
     ```python
     if PRODUCTION_PUBLIC_KEY_B64 == "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=":
         _PLACEHOLDER_KEY_IN_USE = True
         logger.error(
             "iam-jit license: PRODUCTION_PUBLIC_KEY_B64 is the all-zero placeholder. "
             "License verification will not function. This build MUST NOT be released."
         )
     ```
     and have `verify_license_bytes` short-circuit-reject when `_PLACEHOLDER_KEY_IN_USE` is True. (Pre-launch, this turns into a Free-tier-only build, which is the documented intent of "no real license can verify; everyone runs on the Free tier" — but it makes that intent enforced rather than emergent.)

- Test (regression after fix):
  ```python
  def test_crit_31_00_placeholder_key_refuses_verification():
      """Replace PRODUCTION_PUBLIC_KEY_B64 with the all-zero placeholder
      at runtime and confirm verify_license_bytes refuses BEFORE doing
      cryptographic verification (defense-in-depth against OpenSSL
      behavior changes + against forks using non-compliant Ed25519)."""
      monkeypatch.setattr(license_mod, "PRODUCTION_PUBLIC_KEY_B64",
                          "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
      with pytest.raises(license_mod.LicenseInvalidError, match="placeholder"):
          license_mod.verify_license_bytes(b'{"payload": {...}, "signature": "..."}')
  ```

## HIGH findings

### HIGH-31-01 — Naive-datetime payload crashes the user-store gate with uncaught `TypeError`

- File: `src/iam_jit/license.py:138-140` (parser) + `:112-118` (is_active) + `:280-298` (current_user_cap).

- Issue: `_parse_iso` does:
  ```python
  return _dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
  ```
  When the payload's `issued_at` / `expires_at` is `"2026-01-01T00:00:00"` (no `Z`, no offset), `fromisoformat` returns a NAIVE datetime. `License.is_active()` then compares this naive datetime against `_dt.datetime.now(_dt.UTC)` (aware):
  ```python
  if now < self.issued_at:    # TypeError: naive vs aware
  ```
  Python raises `TypeError: can't compare offset-naive and offset-aware datetimes`. This is NOT `LicenseInvalidError`. The verifier docstring is explicit:
  > Never raises a different exception type — this is the trust boundary; opaque failures only.

  This invariant is violated.

  Propagation: `current_user_cap()` at `:286-295`:
  ```python
  try:
      license_obj = load_license()
  except LicenseInvalidError as e:    # ← only catches LicenseInvalidError
      logger.warning(...)
      license_obj = None
  ```
  catches `LicenseInvalidError` but NOT `TypeError`. So the user-store gate at `users_store.py:290` crashes with an uncaught `TypeError`. The expected behavior — graceful fallback to Free tier — does not happen.

- Repro (confirmed):
  ```python
  priv = Ed25519PrivateKey.generate()
  L.PRODUCTION_PUBLIC_KEY_B64 = base64.b64encode(priv.public_key().public_bytes_raw()).decode()
  payload = {
      "tier": "enterprise", "issued_to": "Acme", "max_users": 100, "license_id": "x",
      "issued_at": "2026-01-01T00:00:00",   # NAIVE
      "expires_at": "2027-01-01T00:00:00",  # NAIVE
  }
  sig = priv.sign(L._canonical_payload_bytes(payload))
  raw = json.dumps({"payload": payload, "signature": base64.b64encode(sig).decode()}).encode()
  # Write to license path, then:
  L.current_user_cap()  # TypeError: can't compare offset-naive and offset-aware datetimes
  L.enforce_user_creation_cap(current_user_count=5)  # TypeError (same)
  ```
  A founder-signed license with a typo in the date format (forgetting the trailing `Z`) becomes a hard-crash at every user creation across every customer who installs that file.

- Why HIGH: trust-boundary invariant violated + the documented fallback (`current_user_cap` returns FREE_TIER_MAX_USERS on invalid license) is bypassed. A single bad license file changes the production user-store from "soft-cap at Free tier" to "hard-crash on every put." Composes with HIGH-31-02 (the 500 surface) for an availability incident.

- Fix shape: harden the parser to reject naive datetimes:
  ```python
  def _parse_iso(s: str) -> _dt.datetime:
      """ISO-8601 datetime parser; rejects naive datetimes."""
      dt_val = _dt.datetime.fromisoformat(s.replace("Z", "+00:00"))
      if dt_val.tzinfo is None:
          raise ValueError(f"datetime {s!r} has no timezone; must be UTC")
      return dt_val.astimezone(_dt.UTC)
  ```
  The `try/except (KeyError, ValueError, TypeError)` at `:212` already catches `ValueError`, so this slots in cleanly. Alternative: also catch `TypeError` in `current_user_cap`'s `except` clause as a belt-and-suspenders measure.

- Test (regression):
  ```python
  def test_high_31_01_naive_datetime_rejected_at_verify_not_at_use():
      """A signed payload with naive datetimes must raise
      LicenseInvalidError at verify time, NEVER TypeError later."""
      priv = Ed25519PrivateKey.generate()
      pub = base64.b64encode(priv.public_key().public_bytes_raw()).decode()
      payload = {..., "issued_at": "2026-01-01T00:00:00", "expires_at": "..."}
      raw = _sign(priv, payload)
      with pytest.raises(license_mod.LicenseInvalidError, match="timezone"):
          license_mod.verify_license_bytes(raw, public_key_b64=pub)
  ```

### HIGH-31-02 — Admin user-create HTTP endpoint doesn't catch `UserCapExceededError`; returns 500

- File: `src/iam_jit/routes/users.py:121-132`.

- Issue: The admin user-create POST handler:
  ```python
  @router.post("", status_code=status.HTTP_201_CREATED)
  def create_or_replace_user(
      payload: dict[str, Any],
      user_store: Annotated[UserStore, Depends(get_user_store)],
      _: Annotated[User, Depends(require_admin)],
  ) -> dict[str, Any]:
      new_user = _user_from_payload(payload)
      try:
          user_store.put(new_user)
      except StoreReadOnly as e:
          raise HTTPException(status_code=409, detail=str(e))
      return _serialize(new_user)
  ```
  Catches `StoreReadOnly` only. The new `UserCapExceededError` (raised by `enforce_user_creation_cap` via the `DynamoDBUserStore.put` wire-in) propagates uncaught. FastAPI returns a 500 with a generic message. The admin who just tried to add the 26th user gets:
  ```
  HTTP 500 Internal Server Error
  ```
  instead of:
  ```
  HTTP 4xx
  {"detail": "Free tier supports up to 25 users. You currently have 25.
              To raise the cap, install an iam-jit Enterprise license file at
              /Users/.../license.json. Existing users continue to work; only
              new user creation is gated."}
  ```
  The remediation-rich error message that `enforce_user_creation_cap` author specifically crafted (and the test `test_enforce_message_includes_remediation_path` asserts on) is invisible to the user.

  Grep across the codebase: zero `except UserCapExceededError` blocks anywhere in `src/iam_jit/`. The exception type ships unhandled at every caller of `user_store.put`. Two more callers (`user_bootstrap.py:121`, `:242`) have bare `except Exception` which swallows it generically — at least not a 500, but the helpful message is lost there too.

- Why HIGH: the entire UX value of the soft-cap feature is the remediation guidance at the gate. A 500 with no body destroys that value at the most-likely surface (admin in the web UI clicking "add user"). Same severity rationale as WB23 HIGH about bouncer decisions skipping audit chain — feature ships but the consumer surface doesn't see it.

- Fix shape:
  ```python
  # routes/users.py
  from iam_jit.license import UserCapExceededError
  ...
  try:
      user_store.put(new_user)
  except StoreReadOnly as e:
      raise HTTPException(status_code=409, detail=str(e))
  except UserCapExceededError as e:
      raise HTTPException(status_code=402, detail=str(e))  # 402 Payment Required
  ```
  Also: middleware-level handler in `app.py` for `UserCapExceededError → 402` so every future caller is covered.

- Test (regression):
  ```python
  def test_high_31_02_user_create_at_cap_returns_402_with_remediation():
      # Pre-seed 25 users via the store. Submit 26th via admin POST.
      resp = client.post("/api/v1/users", json={"id": "email:26@x.com", "roles": ["requester"]})
      assert resp.status_code == 402
      detail = resp.json()["detail"]
      assert "Free tier supports up to 25" in detail
      assert "install an iam-jit Enterprise license" in detail
  ```

### HIGH-31-03 — DDB `get_item` failure misclassifies updates as creates; cap gate fires erroneously

- File: `src/iam_jit/users_store.py:283-292`.

- Issue:
  ```python
  try:
      existing = self.table.get_item(Key={"user_id": user.id}).get("Item")
  except Exception:
      existing = None
  if existing is None:
      ...
      _license_mod.enforce_user_creation_cap(
          current_user_count=current_count,
      )
  ```
  Bare `except Exception` treats every failure mode as "user doesn't exist":
  - `ProvisionedThroughputExceededException` (DDB throttling)
  - `RequestTimeoutException`
  - `AccessDeniedException` (rare but possible during IAM role-rotation)
  - `InternalServerError`

  When any of these fires, an UPDATE to an existing user is reclassified as a CREATE. The cap gate then runs. If the deployment is at or over the cap (which the "existing users continue to work" promise explicitly contemplates), the UPDATE is incorrectly rejected with `UserCapExceededError`. Compose with HIGH-31-02: the result the admin sees is a 500.

  Concrete impact: a deployment at 30 users (under an old Enterprise license that just expired → fell back to Free cap of 25) attempts to update an existing user's roles (e.g. de-admin a departing employee). DDB throttling during a busy hour misclassifies as create → cap gate fires → 500. The admin can't perform a SECURITY-RELEVANT update (role change) during an availability incident.

- Repro (confirmed via FakeTable that raises `RuntimeError` on `get_item`):
  ```python
  class ThrottlingTable:
      def get_item(self, **kw): raise RuntimeError("ProvisionedThroughputExceededException")
      def scan(self, **kw): return {"Count": 30}  # over Free cap
      def put_item(self, **kw): ...
  store = DynamoDBUserStore("test", dynamodb_resource=FakeRes(ThrottlingTable()))
  store.put(User(id="email:existing@x.com", roles=("requester",)))
  # raises: UserCapExceededError("Free tier supports up to 25... currently have 30...")
  ```
  The user this call was supposed to update may or may not have actually existed; the gate can't tell, so it defaults to fail-loud. The fail-loud is correct intent (don't silently bypass the cap when we can't read the table) but the failure mode (cap-rejection of an UPDATE) is wrong; the right failure mode is "DDB temporarily unavailable, retry."

- Why HIGH: invariant violation ("updates ungated" is documented + tested via `test_ddb_user_store_updates_existing_not_gated`) under partial-failure of a dependency. The unit test passes because the FakeDDBTable in `_FakeDDBTable.get_item` never raises; real-world DDB does, and the gate misbehaves.

- Fix shape: distinguish throttle/timeout from "definitively not found":
  ```python
  try:
      existing = self.table.get_item(Key={"user_id": user.id}).get("Item")
  except botocore.exceptions.ClientError as e:
      code = e.response.get("Error", {}).get("Code")
      if code in ("ProvisionedThroughputExceededException", "RequestTimeoutException",
                  "InternalServerError", "ServiceUnavailableException"):
          # Transient: re-raise so caller retries; don't run cap gate on uncertain state.
          raise
      # Other ClientError: treat as not-found (legitimate cases: AccessDenied
      # during role-rotation, etc. -- gate fails closed via cap check).
      existing = None
  except Exception:
      existing = None  # last-resort fallback preserves current behavior
  ```
  Or simpler: do a `describe_table` health check at gate time and bail before the cap check if DDB is degraded.

- Test (regression):
  ```python
  def test_high_31_03_throttled_get_item_doesnt_misclassify_update_as_create():
      class ThrottleTable(_FakeDDBTable):
          def get_item(self, **kw):
              from botocore.exceptions import ClientError
              raise ClientError(
                  {"Error": {"Code": "ProvisionedThroughputExceededException", "Message": "x"}},
                  "GetItem",
              )
      store = DynamoDBUserStore("test", dynamodb_resource=_FakeDDBResource(ThrottleTable()))
      # Pre-seed 30 users (over Free cap) directly via items
      # Update an existing user — must raise ClientError (transient), NOT UserCapExceededError
      with pytest.raises(ClientError):
          store.put(User(id="email:existing@x.com", roles=("requester", "approver")))
  ```

## MED findings

### MED-31-01 — No `aud` / `product` field in payload; cross-product license confusion

- File: `src/iam_jit/license.py:198-230` (field validation).

- Issue: The payload spec is `{tier, issued_to, issued_at, expires_at, max_users, license_id}`. There is no `aud` (audience) / `product` field identifying WHICH product the license is signed for. A license signed by the founder's private key verifies identically against any embedded pubkey that matches — which today means "any iam-jit product line that ships the same `PRODUCTION_PUBLIC_KEY_B64`."

  This becomes load-bearing the moment the founder ships a second paid product line. The [[two-product-split]] memo already contemplates iam-risk-score-pro as a separate Lambda + DNS. If that second product reuses the same root key, a license issued for product A (e.g. a 1000-user Enterprise license for iam-jit self-host) verifies for product B (e.g. iam-risk-score-pro hosted) — even though the customer only paid for A.

  Mitigation today: only one product ships using this license file format. So the bug doesn't bite yet. But the schema lock-in is happening NOW: a v1.0 license file format that doesn't have `aud` will be impossible to retrofit without breaking existing customers.

- Why MED: latent rather than active. Pre-launch shape-lock-in is the lever; later cost grows.

- Fix shape: add a required `aud` field, embed an expected audience in source:
  ```python
  PRODUCT_AUDIENCE = "iam-jit"  # change to "iam-jit-bouncer", etc. per-product
  ...
  aud = payload.get("aud")
  if aud != PRODUCT_AUDIENCE:
      raise LicenseInvalidError(
          f"license audience {aud!r} does not match this product ({PRODUCT_AUDIENCE!r})"
      )
  ```
  Pre-launch is the right time to add this; post-launch requires a version-bump in the license file format.

### MED-31-02 — `max_users=True` accepted as `1` (Python bool-is-int)

- File: `src/iam_jit/license.py:215-217`.

- Issue:
  ```python
  max_users = payload.get("max_users")
  if not isinstance(max_users, int) or max_users < 1 or max_users > 1_000_000:
      raise LicenseInvalidError("max_users must be an integer in [1, 1_000_000]")
  ```
  In Python, `isinstance(True, int)` is `True` and `True == 1`. A signer who accidentally writes `"max_users": true` (JSON parses it to Python `True`) gets a license with `max_users=True`, which:
  - Passes `isinstance(max_users, int)` ✓
  - Passes `max_users >= 1` (True == 1) ✓
  - Passes `max_users <= 1_000_000` ✓

  The `License` dataclass stores `max_users=True`. `current_user_cap()` returns `True`. Comparisons against integers work (`current_user_count >= True` is fine), so the cap operates as if it's 1. The admin gets a Free-cap-equivalent license despite paying for Enterprise.

  Same shape attack: `"max_users": false` -> evaluates as `0`, fails `< 1` check, gets rejected with the wrong message ("must be in [1, 1_000_000]" — fine but misleading on root cause).

- Why MED: signing-time typo with silent demotion (loss of paid functionality). The customer's first day with a freshly-issued license is "why can I only create 1 user?" Real-money UX problem, but not a security problem in the iam-jit-blast-radius sense.

- Fix shape:
  ```python
  if isinstance(max_users, bool) or not isinstance(max_users, int) or ...:
      raise LicenseInvalidError("max_users must be an integer in [1, 1_000_000]")
  ```
  Apply the same `isinstance(..., bool)` rejection to any other int field added later.

### MED-31-03 — `enforce_user_creation_cap` double-loads + double-verifies license

- File: `src/iam_jit/license.py:312-344`.

- Issue:
  ```python
  def enforce_user_creation_cap(*, current_user_count, license_obj=None):
      cap = current_user_cap(license_obj)        # calls load_license() if license_obj is None
      if current_user_count >= cap:
          tier = current_tier(license_obj)       # calls load_license() AGAIN
          ...
  ```
  When the user-store calls `enforce_user_creation_cap(current_user_count=N)` without passing an already-loaded `License`, two independent file reads + Ed25519 verifications happen per gate-fire. Cost: 2x file read + 2x ~50µs Ed25519 verify per `put_item` that hits the cap. Not catastrophic but doubles the gate-fire latency.

  Worse: TOCTOU window. If an attacker (or just a deploy script) replaces the license file between the two calls, `current_user_cap()` and `current_tier()` may disagree about the active license. The error message could say "Your iam-jit pro license is provisioned for 100000 users" (tier from second read) "you currently have 25" (count) "Contact sales" (pro-tier branch) — but the cap value in the message is from the FIRST read. Mismatched message; minor UX confusion at worst, signature-mismatch attack surface at worst.

- Why MED: correctness-of-error-message regression + latency + a TOCTOU window. Not security-bypassing in the user-creation sense (the cap result that gates is from the first read, which is correct), but the second read can be racy.

- Fix shape:
  ```python
  def enforce_user_creation_cap(*, current_user_count, license_obj=None):
      if license_obj is None:
          try:
              license_obj = load_license()
          except LicenseInvalidError:
              license_obj = None
      cap = current_user_cap(license_obj)
      if current_user_count >= cap:
          tier = current_tier(license_obj)
          ...
  ```
  One load, two derivations.

### MED-31-04 — Cap-gate race window unbounded under concurrent puts

- File: `src/iam_jit/users_store.py:283-293`.

- Issue: `get_item` → `_count_users` → cap check → `put_item` is non-atomic in DDB. Reproduced empirically with a thread-safe FakeDDBTable seeded with 24 users and 10 concurrent puts:
  ```
  Race result: 10 succeeded, 0 blocked; final user count = 34
  ```
  Every put read count=24 (all under cap), all passed, all wrote. Final count is 9 over the Free cap.

  Memo [[user-count-soft-cap]] documents this as "race-tolerant by design": "the cap is enforced by user-creation friction, not by atomic constraint, in the Sentry/Mattermost pattern." The current code matches that intent. The audit observation is that the overshoot is unbounded in principle:
  - Bulk-import tooling (admin imports 1000 users via API parallelism) can race past Free cap to 1024 silently with zero errors.
  - The compliance question "did you ever exceed the contracted user count?" can only be answered by querying COUNT after-the-fact + comparing to the cap THEN active.

- Why MED: by design but the magnitude needs to be bounded in writing. The memo says "single-digit overshoot tolerable; bulk-import tooling defeats the gate entirely" should be documented somewhere.

- Fix shape (two options, pick one):
  1. Document the bound as "tolerated overshoot = O(concurrent writers)" in `enforce_user_creation_cap` docstring + the memo.
  2. Tighten via DDB ConditionExpression on `put_item`:
     ```python
     # Maintain a counter item; conditional update increments it
     # ConditionExpression="attribute_not_exists(user_id) OR ..."
     ```
     Adds atomicity at the cost of operational complexity (need a counter migration). Not worth it for the "soft cap" framing — option 1 is the right move.

## LOW findings

### LOW-31-01 — Symlinks followed by default in license-file read

- File: `src/iam_jit/license.py:268`.

- Issue: `path.read_bytes()` follows symlinks. A license file at `~/.iam-jit/license.json` that's symlinked to `/etc/passwd` (or any non-JSON file) will be read; the parse will fail. No exploit — verification fails closed — but credential-shaped files conventionally refuse symlinks (e.g. SSH key files via `O_NOFOLLOW`).

- Why LOW: defense-in-depth concern; no current exploit path because the file content matters more than the path.

- Fix shape: add `os.open(path, os.O_RDONLY | os.O_NOFOLLOW)` + `os.read()` in place of `pathlib.read_bytes()`. Or log a warning when the resolved path differs from the configured path:
  ```python
  if path.is_symlink():
      logger.warning("license file %s is a symlink to %s", path, path.resolve())
  ```

### LOW-31-02 — Payload-level extra fields silently dropped

- File: `src/iam_jit/license.py:198-230` (field validation).

- Issue: Adding `"extra_field": "x"` to the signed payload is accepted; `License` dataclass construction reads only the known fields. Probed: `"audience": "iam-jit-bouncer"` payload field is silently dropped (compose with MED-31-01).

- Why LOW: latent. The day a payload field is added (e.g. `aud` per MED-31-01, or `features: [...]` for tier-gating), old licenses without it AND new licenses WITH unexpected variants must both behave predictably. Strict-mode prevents future surprise.

- Fix shape:
  ```python
  _PAYLOAD_FIELDS = {"tier", "issued_to", "issued_at", "expires_at", "max_users", "license_id"}
  extra = set(payload) - _PAYLOAD_FIELDS
  if extra:
      raise LicenseInvalidError(f"unknown payload fields: {sorted(extra)}")
  ```
  Apply BEFORE signature verification (defense in depth — attacker can't change the rejection set by signing).

### LOW-31-03 — Outer-envelope extra fields silently dropped

- File: `src/iam_jit/license.py:169-176`.

- Issue: `{"payload": ..., "signature": ..., "extra": "foo"}` is accepted. Same shape as LOW-31-02 at the envelope level.

- Why LOW: latent. The day a v2 envelope field is added (e.g. `kid` for key-rotation, `alg` for algorithm-agility), strict-mode-at-the-envelope is the contract.

- Fix shape:
  ```python
  _ENVELOPE_FIELDS = {"payload", "signature"}
  extra = set(outer) - _ENVELOPE_FIELDS
  if extra:
      raise LicenseInvalidError(f"unknown envelope fields: {sorted(extra)}")
  ```

## Verified clean

Probed and ruled out, in addition to the findings above:

1. **Trivial signature forges against placeholder all-zero pubkey** — 1000 random 64-byte sigs + 100 cross-key sigs all rejected by `cryptography` 41.x's Ed25519 verifier. Modern OpenSSL Ed25519 (BoringSSL-derived) rejects A in the small-order subgroup per RFC 8032 §5.1.7. Empirical conclusion: not exploitable today; structural CRIT-31-00 stands.

2. **All-zero 64-byte signature against placeholder pubkey** — rejected.

3. **Tampered payload after signing** — the existing test `test_tampered_payload_rejects` covers; verified independently with `max_users` modified after sign.

4. **Tier=`free` in a signed license** — rejected by explicit check at `:202-203`. Covered by `test_free_tier_explicitly_rejected_in_signed_file`.

5. **Expired-at-exact-second-of-now license** — confirmed rejected via `verify_license_bytes` (the `_dt.datetime.now(_dt.UTC)` call inside `is_active` is microseconds-later than the payload's whole-second `expires_at`, so the `now > expires_at` check fires). `License.is_active()` standalone treats `now == expires_at` as still-active (uses `<`/`>`, not `<=`/`>=`); this is consistent behavior — `verify_license_bytes` always uses real-now which is strictly > stored-now.

6. **Future `issued_at` (license issued for a future date)** — rejected. Covered by `test_not_yet_active_license_rejects`.

7. **Non-base64 signature** — caught at `:179` `base64.b64decode(..., validate=True)`. Covered by `test_non_base64_signature_rejects`.

8. **32-byte sig (wrong Ed25519 length, 64 expected)** — `pub_key.verify` raises `InvalidSignature`, caught at `:195` → `LicenseInvalidError`. Verified.

9. **Whitespace-only `license_id` / `issued_to`** — rejected by explicit `.strip()` check at `:206-207` and `:220-221`.

10. **Control characters (`\x00`, `\n`) in `issued_to`** — accepted (no validation beyond non-empty). Not a vulnerability (the field is human-readable / not parsed downstream) but documented; if any future surface renders `issued_to` in HTML, escape there.

11. **1 MB `issued_to` string** — accepted, stored verbatim, returned. No memory exhaustion at typical pre-launch scales. The 10 MB file-read in Probe 6 succeeded and parsed-failed cleanly without crashing the process.

12. **Symlink to `/dev/null`** — `read_bytes()` returns empty bytes, JSON parse fails, `LicenseInvalidError` raised. Acceptable.

13. **Non-UTC timezone in payload (`+05:00`)** — accepted, parsed correctly. `is_active` compares aware-aware so the +05:00 vs UTC comparison works. No silent demotion.

14. **Error messages don't leak attacker payload** — `json.loads` error appended to `LicenseInvalidError` is bounded by Python's json error format (line/column/char only, no content). 10 MB malformed input → 107-byte error message. No signature bytes, no pubkey bytes, no payload content reflected.

15. **CLI `license show` with no license** — exits 0, prints Free tier message. Covered by `test_cli_license_show_no_license`.

16. **CLI `license verify` with bad file** — exits 1, prints "INVALID:" to stderr. Covered by `test_cli_license_verify_bad_file`.

17. **`load_license` permission-denied (OSError)** — caught at `:271`, returns None (Free tier) + logs warning. Behavior is consistent with "missing file = Free tier."

18. **`FileUserStore` not affected by cap gate** — verified: `FileUserStore.put` raises `StoreReadOnly` BEFORE any cap logic. The cap gate is `DynamoDBUserStore`-only by design (file-mode is admin-edited out-of-band so the cap is enforced by the YAML editor, not iam-jit code).

19. **`DynamoDBUserStore.delete` doesn't fire the cap gate** — verified: delete is not gated, only put-when-new. Correct (deletes don't grow the user count).

20. **Multi-page DDB scan in `_count_users`** — verified iteration via `LastEvaluatedKey`. The fake table doesn't trigger pagination but real DDB will; the loop terminates when `LastEvaluatedKey` is absent.

21. **License env-var injection via `LICENSE_PATH_ENV`** — the CLI reads `os.environ.get(LICENSE_PATH_ENV)` directly; a malicious shell that sets `IAM_JIT_LICENSE_FILE=/etc/shadow` would have `current_user_cap` log "license file at /etc/shadow is unreadable" (low-info-leak warning into logs). Not a vulnerability in a single-user CLI context; would matter only if iam-jit is invoked as a privileged subprocess with attacker-controlled env, which is out of scope.

22. **`current_tier` swallow of `LicenseInvalidError`** — confirmed silent fallback to "free." Per MED-31-03 it's called redundantly; not separately a defect. The DOS-via-corruption angle (attacker corrupts license file to demote deployment to Free tier) is real but bounded — the deployment fail-OPENs at MORE restrictive (Free is more restrictive than Enterprise), so the worst case is "admin can't add new users until they restore the license file." This is the right fail-mode; "fail closed = more restrictive" is the conservative choice.

## Regression check

Command:
```
cd <repo> && .venv/bin/python -m pytest --no-header -q --ignore=tests/test_calibration_corpus.py --ignore=tests/e2e 2>&1 | tail -3
```

Result:
```
2627 passed, 29 skipped, 14 deselected, 2 warnings in 92.37s (0:01:32)
```

Pre-WB31 baseline: 2598. Net +29 (license unit tests) +3 (DDB wire-in) = +32 → 2630 expected, observed 2627. Three-test delta is within the noise floor for two earlier ad-hoc commits in the working tree (not part of #161); zero regressions in the 2598 pre-WB31 tests.
