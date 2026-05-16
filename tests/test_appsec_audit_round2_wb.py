"""White-box appsec audit, round 2.

Round 2 of the white-box review on 2026-05-14, scoped to:

  1. **Re-audit of round-1 fixes** — verify the SCORE-XFF and
     STRIPE-IDEMPOTENCY fixes that shipped don't introduce new
     bypasses or race conditions.
  2. **Categories round-1 deferred** — concurrency / TOCTOU, fail-open
     defenses, MCP server input validation, prompt-injection coverage
     of newer surfaces (policy_gen path), tokens-issued unbounded
     per-user.
  3. **Stripe redelivery race** between has_processed and
     mark_processed — confirmed concurrency hole inside the round-1
     fix.

Test conventions follow round 1: each test asserts CURRENT
(vulnerable) behavior. When a fix lands, flip the assertion or delete
the test as part of the fix PR.

Run only this file:

    pytest tests/test_appsec_audit_round2_wb.py -v

Summary doc: docs/security/AUDIT-2026-05-WB-ROUND2.md
"""

from __future__ import annotations

import inspect
import threading
import time

import pytest


# ---------------------------------------------------------------------------
# 1. Stripe idempotency — has_processed/mark_processed is TOCTOU under
#    concurrent webhook redelivery. Two redeliveries arriving in parallel
#    can both see has_processed=False and both run the handler.
# ---------------------------------------------------------------------------


def test_finding_stripe_idempotency_toctou_under_concurrency() -> None:
    """Finding: STRIPE-IDEMPOTENCY-TOCTOU — CLOSED.

    CWE-367 (Time-of-check Time-of-use Race Condition).
    Severity: HIGH.
    Location: src/iam_jit/stripe_webhook.py — `dispatch_event` +
    `ProcessedEventsStore.claim`.

    Closure: the protocol was changed to require a single atomic
    `claim(event_id) -> bool` operation. Only the first caller can
    return True; all subsequent callers — including ones racing the
    first — return False and short-circuit the handler. The in-memory
    implementation uses `dict.setdefault` with a per-call unique
    marker (atomic under the CPython GIL). The DynamoDB-backed
    implementation MUST use `PutItem` with
    `ConditionExpression="attribute_not_exists(event_id)"`.

    This test pins the closure: even when two threads enter `claim`
    in lock-step under a barrier, exactly one wins, and only one token
    is minted for a single redelivered event.
    """
    from iam_jit.stripe_webhook import (
        ProcessedEventsStore,
        dispatch_event,
    )
    from iam_jit.api_tokens_store import InMemoryAPITokenStore
    import os

    os.environ["STRIPE_PRICE_ID_TO_TIER"] = '{"price_indie":"indie"}'
    tokens = InMemoryAPITokenStore()

    # Synchronized processed-events store: both threads enter `claim`
    # in lock-step. Even so, `setdefault` is atomic and only one's
    # per-call marker survives.
    claim_barrier = threading.Barrier(2)

    class _ProcessedStore:
        def __init__(self) -> None:
            self._seen: dict[str, object] = {}

        def claim(self, event_id: str) -> bool:
            my_marker = object()
            # Force both threads to arrive at the setdefault call
            # window simultaneously, so we exercise the atomicity
            # guarantee rather than serial ordering.
            claim_barrier.wait()
            stored = self._seen.setdefault(event_id, my_marker)
            return stored is my_marker

    processed: ProcessedEventsStore = _ProcessedStore()

    event = {
        "id": "evt_concurrent_replay",
        "type": "checkout.session.completed",
        "data": {
            "object": {
                "customer_email": "buyer@example.com",
                "line_items": {"data": [{"price": {"id": "price_indie"}}]},
                "customer": "cus_x",
                "subscription": "sub_y",
            }
        },
    }

    results: list[dict] = []

    def run() -> None:
        results.append(
            dispatch_event(
                event,
                tokens_store=tokens,
                processed_events_store=processed,
            )
        )

    threads = [threading.Thread(target=run) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Closure assertion: exactly one token minted under concurrent
    # redelivery. The other thread short-circuits with duplicate=True.
    minted = tokens.list_for_user("buyer@example.com")
    assert len(minted) == 1, (
        f"Expected atomic claim() to mint exactly 1 token under "
        f"concurrent redelivery. Got {len(minted)}. Results: {results}."
    )
    duplicate_results = [r for r in results if r.get("duplicate") is True]
    assert len(duplicate_results) == 1, (
        f"Expected exactly one caller to be reported as duplicate. "
        f"Results: {results}."
    )


# ---------------------------------------------------------------------------
# 2. XFF rate-limit fix — leftmost-XFF is attacker-controlled even
#    behind a trusted proxy. The proxy APPENDS the real client to the
#    right; the leftmost token came from the attacker.
# ---------------------------------------------------------------------------


def test_finding_xff_leftmost_attacker_controlled_behind_trusted_proxy(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Finding: SCORE-XFF-LEFTMOST-TRUSTED — CLOSED.

    CWE-348 (Use of Less Trusted Source).
    Severity: HIGH.
    Location: src/iam_jit/routes/score.py — `_client_ip`.

    Closure: when the immediate peer is in a configured trusted CIDR,
    we now walk XFF RIGHT-TO-LEFT, skipping any tokens that fall in
    `IAM_JIT_TRUSTED_PROXY_CIDRS`. The first non-trusted IP from the
    right is the real client. Standard pattern (mirrors Django's
    `SECURE_PROXY_SSL_HEADER` and AWS WAF `forwarded_ip_config`
    docs).

    Functional test below confirms the live behavior: an attacker
    that spoofs `XFF: <victim-ip>` from behind a CloudFront-style
    proxy now gets keyed on the proxy-appended IP, not on the
    attacker-supplied leftmost token.
    """
    from iam_jit.routes import score as score_mod
    from iam_jit import trusted_proxy as _tp

    src = inspect.getsource(score_mod._client_ip)
    # New shape: delegates to the shared trusted_proxy helper.
    assert 'xff.split(",")[0].strip()' not in src, (
        "_client_ip still takes the leftmost XFF token — regression"
    )
    assert "trusted_proxy" in src, (
        "_client_ip should delegate to the shared trusted_proxy helper"
    )
    # The shared helper walks right-to-left.
    helper_src = inspect.getsource(_tp.real_client_from_xff)
    assert "reversed(" in helper_src

    # Functional check: simulate the exact CloudFront-in-front-of-
    # Lambda topology the audit described. Trusted proxy CIDR
    # 10.0.0.0/8, immediate peer 10.0.0.5 (proxy), attacker-supplied
    # XFF leftmost token 203.0.113.99, real-client appended at right
    # as 198.51.100.7.
    monkeypatch.setenv("IAM_JIT_TRUST_FORWARDED_FOR_FOR_SCORE", "1")
    monkeypatch.setenv("IAM_JIT_TRUSTED_PROXY_CIDRS", "10.0.0.0/8")

    class _FakeClient:
        host = "10.0.0.5"

    class _FakeRequest:
        client = _FakeClient()
        headers = {"x-forwarded-for": "203.0.113.99, 198.51.100.7"}

    resolved = score_mod._client_ip(_FakeRequest())  # type: ignore[arg-type]
    assert resolved == "198.51.100.7", (
        f"expected the right-most non-trusted IP (198.51.100.7) to be "
        f"the resolved client; got {resolved!r}"
    )


# ---------------------------------------------------------------------------
# 3. XFF fix — IPv4-mapped IPv6 peer never matches an IPv4 trusted CIDR
#    (operator wires "10.0.0.0/8" thinking it covers all 10.x clients,
#    but the immediate peer arrives as "::ffff:10.x.y.z" and the
#    ipaddress lib returns False on cross-family `in` checks).
# ---------------------------------------------------------------------------


def test_finding_xff_ipv4_mapped_ipv6_silently_rejects_trust() -> None:
    """Finding: SCORE-XFF-IPV4MAPPED-IPV6.

    CWE-754 (Improper Check for Unusual or Exceptional Conditions).
    Severity: LOW (footgun, not a bypass).
    Location: src/iam_jit/routes/score.py:295-313.

    The new XFF-trust gate uses `ipaddress.ip_address(real_client)`
    then `client_addr in net` for each entry in
    `IAM_JIT_TRUSTED_PROXY_CIDRS`. When `real_client` arrives as an
    IPv4-mapped IPv6 address (`::ffff:10.0.0.5` — common for
    dual-stack environments / some Lambda Function URL deploys), the
    parsed address is an IPv6Address and `in` against an IPv4Network
    is always False. The operator who configured `10.0.0.0/8` sees
    XFF silently NOT trusted, blocks the limiter from getting the
    real client IP, and (if they're trying to operate dual-stack)
    gets weird per-IP misclassifications.

    Fix sketch: detect IPv4-mapped IPv6 with `.ipv4_mapped` and
    normalize to the IPv4 address before the membership check.
    """
    import ipaddress

    mapped = ipaddress.ip_address("::ffff:10.0.0.5")
    net = ipaddress.ip_network("10.0.0.0/8", strict=False)
    # The exact behavior the gate inherits: cross-family `in` returns
    # False even though the embedded IPv4 is in the CIDR.
    assert mapped not in net


# ---------------------------------------------------------------------------
# 4. Bootstrap-claim TOCTOU — _has_been_claimed → user_store.put is not
#    atomic. Two concurrent claim POSTs with the valid email+key both
#    pass the check then both write, producing N successful claims.
# ---------------------------------------------------------------------------


def test_finding_bootstrap_claim_toctou_race() -> None:
    """Finding: BOOTSTRAP-CLAIM-TOCTOU.

    CWE-367 (Time-of-check Time-of-use Race Condition).
    Severity: MED (requires the bootstrap secret to leak or be
    brute-forced — but if it does, the race lets multiple sessions
    issue simultaneously, defeating the "single-use" guarantee).
    Location: src/iam_jit/bootstrap_claim.py:139-149.

    `evaluate_and_claim` reads the user via `user_store.get(...)`,
    checks `_has_been_claimed(user)`, then calls `user_store.put(...)`
    to stamp the claim marker. The store's `put` is unconditional
    (DynamoDBUserStore.put_item with no ConditionExpression — see
    users_store.py:277), so two threads passing the
    `_has_been_claimed` check both succeed, and both return a
    ClaimDecision(success=True). The route handler then sets a
    session cookie for both attempts.

    Practical exploit: the deployer types the secret into a public
    `/setup` form. If they reload the form once (Chrome's default
    'Resend POST?' prompt + the operator's nervous click), or if an
    attacker has the secret and races the deployer's submission,
    both POSTs come back valid.

    Fix: add a conditional write — for DynamoDB
    `put_item(... ConditionExpression="attribute_not_exists(notes) OR NOT contains(notes, :marker)")`,
    or move the single-use marker into the bootstrap-setup-key
    DDB item itself (`PutItem` on a sentinel record with
    ConditionExpression that the sentinel doesn't already exist).

    Reproduction: we use a store whose `get()` blocks until BOTH
    threads have entered, mirroring the realistic case where two
    near-simultaneous /setup POSTs each do a DDB GetItem before
    either does PutItem. The simulator makes the TOCTOU deterministic;
    in production the window is much smaller but non-zero.
    """
    from iam_jit.bootstrap_claim import (
        ClaimDecision,
        evaluate_and_claim,
    )
    from iam_jit.users_store import User, UserNotFound

    # In-memory store mimicking DynamoDB's last-writer-wins put. The
    # store explicitly synchronizes so all `get`s complete before any
    # `put`, which is the realistic concurrent-DDB scenario for two
    # /setup POSTs landing inside the same ms.
    read_barrier = threading.Barrier(2)
    put_barrier = threading.Barrier(2)

    class _Store:
        def __init__(self) -> None:
            self.users: dict[str, User] = {
                "email:admin@example.com": User(
                    id="email:admin@example.com",
                    roles=("admin",),
                    enabled=True,
                    notes="",
                )
            }
            self._observed_puts: list[User] = []

        def get(self, uid: str) -> User:
            if uid not in self.users:
                raise UserNotFound(uid)
            result = self.users[uid]
            # Hold until BOTH threads have completed their read. This
            # is the toctou window — both threads have stale `user`
            # values with empty notes, before either writes.
            read_barrier.wait()
            return result

        def put(self, user: User) -> None:
            # Sync both threads BEFORE the write so neither sees the
            # other's update from inside the existing eval-and-claim
            # callsite.
            put_barrier.wait()
            # Mimic DDB put_item (unconditional last-writer-wins).
            self.users[user.id] = user
            self._observed_puts.append(user)

        def list(self, **kw):  # unused
            return list(self.users.values())

        def delete(self, uid):  # unused
            self.users.pop(uid, None)

    store = _Store()

    results: list[ClaimDecision] = []

    def run() -> None:
        results.append(
            evaluate_and_claim(
                submitted_email="admin@example.com",
                submitted_key="correct-bootstrap-secret",
                admin_bootstrap_email="admin@example.com",
                bootstrap_setup_key="correct-bootstrap-secret",
                user_store=store,
            )
        )

    threads = [threading.Thread(target=run) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Both claims succeeded — the single-use guarantee was violated.
    successes = [r for r in results if r.success]
    assert len(successes) == 2, (
        f"Expected the TOCTOU race to produce TWO successful claims. "
        f"Got {len(successes)}. Results: {results}. If this is now 1, "
        f"a fix has landed — flip the test."
    )


# ---------------------------------------------------------------------------
# 5. Middleware ban-check fails open on store exception
# ---------------------------------------------------------------------------


def test_finding_middleware_ban_check_fails_open_on_store_error() -> None:
    """Finding: BAN-CHECK-FAIL-OPEN — CLOSED.

    CWE-755 / CWE-636. Severity: MED.

    Closure: `current_user` now raises 503 when the bans store
    raises. Operators can override with `IAM_JIT_BANS_FAIL_OPEN=1`
    when they explicitly prefer availability over enforcement —
    that opt-out is loud and intentional.
    """
    from iam_jit import middleware

    src = inspect.getsource(middleware.current_user)
    assert "BAN-CHECK-FAIL-OPEN" in src, (
        "ban-check closure comment removed — investigate"
    )
    assert "503" in src, (
        "ban-check should raise 503 on store failure; got source: " + src[:200]
    )
    assert "IAM_JIT_BANS_FAIL_OPEN" in src, (
        "operator opt-out env var missing"
    )


# ---------------------------------------------------------------------------
# 6. FilesystemBanStore swallows corrupted-JSON file as "not banned"
# ---------------------------------------------------------------------------


def test_finding_filesystem_ban_store_treats_corrupt_file_as_not_banned(
    tmp_path,
) -> None:
    """Finding: BAN-STORE-CORRUPT-FILE-UNBAN.

    CWE-755 (Improper Handling of Exceptional Conditions).
    Severity: MED.
    Location: src/iam_jit/bans.py:117-120 (`FilesystemBanStore.get`).

    `get` catches `json.JSONDecodeError` and returns None ("not
    banned"). `is_banned` is just `get(...) is not None`. So if an
    attacker (or a transient disk error) corrupts the JSON file
    for their own user-id, the system reports them as unbanned —
    the ban silently lifts.

    Threat model: an attacker who can write to the bans state
    directory can self-unban by appending a non-JSON byte to their
    own `bans/<user-id>.json`. The bans directory is typically the
    Lambda /tmp or an EFS mount; an attacker with code execution
    inside the same Lambda instance has that write capability.
    More realistically: a partial write during a crash leaves the
    file truncated → JSONDecodeError → silent unban.

    Fix sketch: on JSONDecodeError, raise (or treat as banned and
    surface a CRITICAL log line). The audit log is the durable
    record of WHO is banned; treating a corrupt file as banned
    fails CLOSED until an operator restores the file.
    """
    from iam_jit.bans import FilesystemBanStore

    store = FilesystemBanStore(tmp_path)
    user_id = "email:victim@example.com"

    # Place an actual valid ban record.
    from iam_jit.bans import Ban
    store.add(Ban(
        user_id=user_id,
        banned_at="2026-05-13T00:00:00Z",
        reasons=["test"],
        snippets=["test"],
        confidence="high",
        actor="system:prompt_injection",
    ))
    assert store.is_banned(user_id)

    # Now corrupt the file.
    path = store._path_for(user_id)
    path.write_text("{ not valid json")

    # BAN-STORE-CORRUPT-FILE-UNBAN closure: corrupt JSON now raises
    # rather than silently returning None (which would un-ban the
    # user). The middleware turns the raise into a 503, surfacing the
    # state-corruption to operators instead of letting the banned
    # user back in.
    import json as _json
    import pytest as _pytest
    with _pytest.raises(_json.JSONDecodeError):
        store.is_banned(user_id)


# ---------------------------------------------------------------------------
# 7. MCP server task description has no length cap
# ---------------------------------------------------------------------------


def test_finding_mcp_generate_no_task_description_cap() -> None:
    """Finding: MCP-TASK-DESCRIPTION-UNBOUNDED.

    CWE-770 (Allocation of Resources Without Limits or Throttling).
    Severity: LOW (stdio transport; local-trust — but worth bounding).
    Location: src/iam_jit/mcp_server.py:157-200 (`_generate_for_mcp`),
    src/iam_jit/policy_gen/result.py:101 (`GenerationRequest.task_description`).

    NOTE 2026-05-16: closed by deletion in [[no-nl-synthesis]]
    Stage 3 (iam-jit 0.4.0). The policy_gen package is gone;
    generate_iam_policy is a tombstone that returns null policy
    + deprecation block. No task-description path exists to bound.

    `_generate_for_mcp` accepts `args["task"]` as any non-empty
    string — no length cap. The pattern matcher then tokenizes the
    full string (re.findall over `[a-z0-9*][a-z0-9*\\-_]*`) and the
    resource extractor runs every `_NAME_PATTERNS` regex against it.
    Round-1's `MCP-NO-MESSAGE-CAP` covers the per-LINE cap on the
    transport; this is the per-FIELD cap on the protocol payload,
    which a 1 KB line can still spike via a single 900-byte `task`.

    For the parallel HTTP `/api/v1/score` finding
    (`POLICY-ANALYZE-NO-PER-FIELD-CAP`, round 1 #23) the score
    request's `description` already has `max_length=500` —
    `policy_gen` doesn't.

    Fix sketch: cap `task` at 2000 chars; refuse with `-32602`
    invalid-params if exceeded.
    """
    import pytest
    pytest.skip(
        "closed by deletion: policy_gen package removed in 0.4.0 "
        "([[no-nl-synthesis]] Stage 3); finding documents historical "
        "state. The replacement tools (list_templates, get_template, "
        "submit_policy) carry their own input validation tested in "
        "test_mcp_template_tools.py."
    )


# ---------------------------------------------------------------------------
# 8. MCP server leaks internal exception detail in JSON-RPC error
#    response
# ---------------------------------------------------------------------------


def test_finding_mcp_internal_error_leaks_exception_repr() -> None:
    """Finding: MCP-INTERNAL-ERROR-LEAK.

    CWE-209 (Generation of Error Message Containing Sensitive
    Information).
    Severity: LOW.
    Location: src/iam_jit/mcp_server.py:288-289 (`main`).

    The `except Exception as e:` branch returns
    `_err(req.get("id"), -32603, f"internal error: {e}")`. For a
    local-trust stdio host this is mostly low-impact, but if iam-jit
    later exposes MCP over a network transport (SSE, the documented
    next step in the MCP spec), the error string can leak internal
    paths, stack-frame state, or DDB ARN details to a remote agent.

    Fix sketch: log the full traceback server-side via
    `logger.exception`, return a generic `"internal error"` to the
    caller — uniform across MCP and HTTP surfaces.
    """
    from iam_jit import mcp_server

    src = inspect.getsource(mcp_server.main)
    assert 'f"internal error: {e}"' in src


# ---------------------------------------------------------------------------
# 9. MCP server: account_id / region / partition are interpolated into
#    ARNs without validation
# ---------------------------------------------------------------------------


def test_finding_mcp_arn_segments_unvalidated() -> None:
    """Finding: MCP-ARN-SEGMENT-INJECTION.

    CWE-20 (Improper Input Validation).
    Severity: LOW (cosmetic — the resulting policy is then rescored
    and the bad ARN is flagged broad; no IAM grant happens via this
    surface).
    Location: src/iam_jit/policy_gen/resources.py:170-273
    (`extract_resources` + `_construct_arn`).

    Caller-supplied `account_id`, `region`, `partition` flow directly
    into `_construct_arn` f-strings with no validation. The MCP
    `inputSchema` advertises an `enum` for `partition` but the
    server-side `_generate_for_mcp` does not enforce it. A caller
    that passes `partition="../../"` gets ARNs like
    `arn:../../:s3:::name` in the response policy. The scorer
    happens to flag these as malformed (the round-10 closure
    `INVALID_ARN_REGION` catches the region variant; partition
    isn't checked).

    Fix sketch: enforce the partition enum server-side; validate
    account_id is `r"^[0-9]{12}$"` if present; validate region
    against `r"^[a-z]{2}-[a-z]+-\\d+$"` if present.
    """
    import pytest
    pytest.skip(
        "closed by deletion: policy_gen package removed in 0.4.0 "
        "([[no-nl-synthesis]] Stage 3); ARN-construction code path "
        "no longer exists. submit_policy now takes a finished policy "
        "and the scorer evaluates it; no server-side ARN construction."
    )


# ---------------------------------------------------------------------------
# 10. Tokens issuance has no per-user quota
# ---------------------------------------------------------------------------


def test_finding_tokens_no_per_user_mint_quota() -> None:
    """Finding: TOKENS-NO-PER-USER-MINT-QUOTA.

    CWE-770 (Allocation of Resources Without Limits or Throttling).
    Severity: MED (extends round-1 TOKEN-LABEL-UNBOUNDED).
    Location: src/iam_jit/routes/tokens.py:35-63 (`create_token`).

    Round 1 noted the label is unbounded; this finding sits next to
    it. An authenticated user can mint API tokens unboundedly —
    there's no `list_for_user` check before `store.put`, no soft
    cap, no rate limit on the route. Each `put` is a DDB write. An
    authenticated user with even read-only role can burn DDB write
    capacity by hammering POST /api/v1/tokens.

    Combined with TOKEN-LABEL-UNBOUNDED, a single authenticated
    user can write 256 KiB per token, unboundedly. Free-tier DDB
    burst capacity is exhausted in seconds.

    Fix: cap tokens-per-user at e.g. 10 (configurable). Refuse 11th
    with 409. Use this cap as the soft signal too — at 10 active
    tokens, surface a warning in the response with revoke links.
    """
    # CLOSED: `create_token` now calls `list_for_user(user.id)` and
    # refuses with 429 once the per-user cap is reached.
    from iam_jit.routes import tokens as tokens_route

    src = inspect.getsource(tokens_route.create_token)
    assert "list_for_user" in src, (
        "per-user token mint quota should be enforced — regression"
    )
    assert "429" in src or "TOO_MANY_REQUESTS" in src


# ---------------------------------------------------------------------------
# 11. Revoke-token endpoint returns the same 200 for not-found AND for
#     revoke-of-self — but for cross-user attempts it returns 403.
#     This gives a non-owner an oracle: "this hash exists, you can't
#     touch it" vs "doesn't exist".
# ---------------------------------------------------------------------------


def test_finding_revoke_token_existence_oracle() -> None:
    """Finding: TOKEN-REVOKE-EXISTENCE-ORACLE.

    CWE-204 (Observable Response Discrepancy).
    Severity: LOW (hash space is 2^256 — not realistic to brute
    force — but the oracle is unintended).
    Location: src/iam_jit/routes/tokens.py:87-102 (`revoke_token`).

    `DELETE /api/v1/tokens/{hash}` returns:
      - 200 + `{"revoked": false, "reason": "not_found"}` when the
        hash doesn't exist
      - 403 when the hash exists but belongs to a different non-admin
        user
      - 200 + `{"revoked": true}` when the caller is the owner OR
        an admin
    A non-owner non-admin can distinguish "hash X is registered" from
    "hash X doesn't exist" by reading the status. With 2^256-bit hash
    space the oracle is unexploitable today, but conventionally
    revoke endpoints return uniform 200-revoked-false regardless to
    avoid this entire category of failure mode.

    Fix sketch: return uniform `{"revoked": false}` on both 404 and
    "not yours" paths; record the audit event server-side for the
    "not yours" attempt so the operator sees the probing.
    """
    from iam_jit.routes import tokens as tokens_route

    src = inspect.getsource(tokens_route.revoke_token)
    assert 'status_code=403' in src
    assert '"not_found"' in src


# ---------------------------------------------------------------------------
# 12. Score endpoint admits `null` partition / region / account into
#     trusted-proxy CIDR parsing
# ---------------------------------------------------------------------------


def test_finding_trusted_proxy_cidr_no_malformed_entry_rejection() -> None:
    """Finding: SCORE-XFF-CIDR-PARSE-PERMISSIVE.

    CWE-20 (Improper Input Validation).
    Severity: LOW.
    Location: src/iam_jit/routes/score.py:301-313.

    `_client_ip` parses `IAM_JIT_TRUSTED_PROXY_CIDRS` by splitting on
    `,` and calling `ipaddress.ip_network(token, strict=False)`. A
    malformed entry (typo `127.0.0/8` or `cloudfront-ips.txt`) is
    silently `continue`'d — no warning, no startup-time validation,
    no health-check surface. Operator who fat-fingers the env var
    gets a deployment that quietly refuses to trust XFF from the
    intended proxies.

    Fix sketch: at startup (or first call), iterate the parsed list
    and log a CRITICAL line per malformed entry. Better: validate
    at deploy-time in the SAM template via `AWS::CloudFormation::
    Init` or by parsing the env var in a `boto3.client('lambda')`
    healthcheck before traffic is routed.
    """
    # The parser logic is now in the shared trusted_proxy module;
    # the silent-skip behavior moved with it. Still LOW (operator
    # footgun, not a security bypass). Pin against the helper.
    from iam_jit import trusted_proxy as _tp

    src = inspect.getsource(_tp.parse_trusted_cidrs)
    assert "except ValueError:" in src
    assert "continue" in src
    # No structured logging around the malformed-entry path yet.
    assert "logger.warning" not in src
    assert "logger.error" not in src


# ---------------------------------------------------------------------------
# 13. Score-endpoint API key is a single static value with no rotation
#     story — a leaked key needs an operator redeploy to revoke.
# ---------------------------------------------------------------------------


def test_finding_score_api_key_no_rotation_story() -> None:
    """Finding: SCORE-API-KEY-NO-ROTATION.

    CWE-321 (Use of Hard-coded Cryptographic Key) — adjacent class.
    Severity: LOW.
    Location: src/iam_jit/routes/score.py:239-261 (`_require_api_key`).

    The score-endpoint API key is read from a single env var
    `IAM_JIT_SCORE_API_KEY`. Only ONE value is accepted at any
    time. Operator rotation requires a redeploy (or env-var
    update) that immediately invalidates the previous key — every
    caller breaks during the rotation window.

    Fix sketch: accept a comma-separated list of valid keys;
    consider the FIRST one as the "current" key; accept any value
    in the list. Rotation procedure is then: add a new key, roll
    callers, remove the old one. Each rotation has a non-zero
    window where both keys work.
    """
    from iam_jit.routes import score as score_mod

    src = inspect.getsource(score_mod._require_api_key)
    assert "IAM_JIT_SCORE_API_KEY" in src
    # Single-value compare — no list-style "any of these" check.
    assert "in [" not in src
    assert ".split(" not in src


# ---------------------------------------------------------------------------
# 14. policy_gen does NOT scan free-text fields for prompt-injection
# ---------------------------------------------------------------------------


def test_finding_policy_gen_no_prompt_injection_scan() -> None:
    """Finding: POLICY-GEN-NO-INJECTION-SCAN.

    CWE-20 (Improper Input Validation).
    Severity: LOW (stdio transport only today; would be MED if
    exposed via HTTP).
    Location: src/iam_jit/policy_gen/generate.py,
    src/iam_jit/mcp_server.py.

    `generate_policy` accepts free-text `task_description` and
    `refinement.rationale`. Neither is scanned by
    `prompt_injection.detect` — the scanner that DOES fire on
    `/api/v1/score` (description field), `/api/v1/intake/turn`
    (every user message), and the request-submission path. The
    pattern matcher uses fixed substrings so direct injection of
    the matcher doesn't yield more actions, BUT the same task
    description is recorded in
    `GenerationResult.reasons[]` and surfaces in
    audit logs and (eventually) admin UIs — a stored XSS vector
    if the UI ever renders these unescaped, plus a steering
    vector for any LLM-tier upgrade.

    Fix sketch: when exposing policy_gen via an HTTP surface
    (not just MCP stdio), wire `prompt_injection.detect` against
    `task_description` and `rationale` with the same audit-log +
    refuse pattern the score endpoint uses.
    """
    import pytest
    pytest.skip(
        "closed by deletion: policy_gen package removed in 0.4.0 "
        "([[no-nl-synthesis]] Stage 3); no free-text task_description "
        "is accepted by the MCP surface anymore. submit_policy takes "
        "structured JSON; description field is bounded to 1024 chars "
        "and never fed to an LLM."
    )


# ---------------------------------------------------------------------------
# 15. Many audit.emit failures swallow silently (extends round-1
#     AUDIT-WRITE-SILENT-FAILURE to the route-handler call sites)
# ---------------------------------------------------------------------------


def test_finding_audit_emit_callers_swallow_silently() -> None:
    """Finding: AUDIT-EMIT-CALLSITES-SWALLOW.

    CWE-778 (Insufficient Logging).
    Severity: LOW (defense-in-depth restatement of round-1 #13).
    Location: many; `src/iam_jit/routes/admin.py` alone has 9
    `except Exception: pass` blocks around `audit.emit` calls
    (lines 203, 269, 353, 394, 482, 537, 662, 819, 861).

    Round 1 flagged `audit.py:202-211` for swallowing OSError on
    the write path. Round 2 notes the route handlers SEPARATELY
    swallow every exception from `audit.emit` itself, so an
    operator misconfiguration (env var missing, audit lambda IAM
    role broken, ImportError from a refactor) loses every audit
    event silently. Each instance is one line — the cumulative
    surface is most of the security-relevant events the system
    emits.

    Fix sketch: replace `except Exception: pass` with
    `except Exception: logger.exception("audit.emit failed")` so
    operator alarms catch the failure mode.
    """
    from iam_jit.routes import admin as admin_route

    src = inspect.getsource(admin_route)
    # Count silent-pass exception swallows around audit emits.
    silent_passes = 0
    lines = src.split("\n")
    for i, line in enumerate(lines):
        if "except Exception:" in line:
            # Check next non-blank line is `pass`
            j = i + 1
            while j < len(lines) and not lines[j].strip():
                j += 1
            if j < len(lines) and lines[j].strip() == "pass":
                silent_passes += 1
    assert silent_passes >= 5, (
        f"Expected at least 5 silent audit-emit swallows in admin.py, "
        f"got {silent_passes}. Code shape changed — re-evaluate."
    )


# ---------------------------------------------------------------------------
# 16. WEB-NO-CSRF-TOKEN still holds — re-state to confirm round-2 didn't
#     ship the fix while a different fix landed.
# ---------------------------------------------------------------------------


def test_finding_web_csrf_still_missing_after_round1() -> None:
    """Finding: WEB-NO-CSRF-TOKEN (CARRY-FORWARD).

    Re-stated from round 1 to confirm the fix has NOT shipped while
    the SCORE-XFF-RATELIMIT-BYPASS and STRIPE-NO-IDEMPOTENCY fixes
    did. The web routes still accept POSTs with no Origin/Referer
    check and no anti-CSRF token.
    """
    from iam_jit.routes import web as web_mod

    src = inspect.getsource(web_mod)
    assert "csrf" not in src.lower()
    assert 'request.headers.get("origin")' not in src.lower()
    assert 'request.headers.get("referer")' not in src.lower()
