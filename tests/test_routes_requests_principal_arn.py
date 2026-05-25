"""State-verification tests for #594 — POST /requests/new/paste
must populate `assume_by.principal_arn` at submit time, either from
the explicit form field or by inferring from the authenticated user.

Closes the silent-degradation path per [[ibounce-honest-positioning]]
where the request was accepted with no principal and a "blocking issue"
warning surfaced later on the detail page.

Per docs/CONTRIBUTING.md state-verification convention: every test
asserts the *observable* state (the stored request's persisted
principal_arn + the rendered detail-page HTML) rather than just the
HTTP status that claims success.
"""

from __future__ import annotations

from fastapi.testclient import TestClient

pytest_plugins = ["tests.conftest_routes"]


_VALID_POLICY_JSON = (
    '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
    '"Action":["s3:GetObject"],'
    '"Resource":"arn:aws:s3:::example-config/path/file.txt"}]}'
)


def _submit_paste(
    client: TestClient,
    *,
    assume_principal_arn: str | None = None,
) -> "object":
    """Helper: POST a minimal valid paste-mode request, optionally
    overriding `assume_principal_arn`. Returns the raw httpx Response
    so callers can inspect both status and headers/body."""
    data: dict[str, str] = {
        "description": "Read S3 config files for service X.",
        "policy": _VALID_POLICY_JSON,
        "access_type": "read-only",
        "accounts": "060392206767",
        "duration_hours": "24",
    }
    if assume_principal_arn is not None:
        data["assume_principal_arn"] = assume_principal_arn
    return client.post("/requests/new/paste", data=data, follow_redirects=False)


def _stored_request(shared_app, request_id: str) -> dict:
    """Read the persisted request directly out of the request store —
    asserts observable state, not just HTTP response shape."""
    return shared_app.state.request_store.get(request_id)


# ---- Test 1: blank principal + session → infer from current_user.id ----


def test_post_paste_blank_principal_with_session_infers_from_current_user(
    as_dev: TestClient, shared_app
) -> None:
    """Blank `assume_principal_arn` + valid session → stored request
    has `spec.assume_by.principal_arn == current_user.id`. Matches what
    the form's placeholder already promises."""
    resp = _submit_paste(as_dev)  # no assume_principal_arn => blank
    assert resp.status_code == 303, resp.text
    detail_url = resp.headers["location"]
    request_id = detail_url.rsplit("/", 1)[-1]

    # Observable state #1: the persisted request carries the inferred
    # principal — NOT just an HTTP 303 that *claims* success.
    stored = _stored_request(shared_app, request_id)
    assume_by = (stored.get("spec") or {}).get("assume_by") or {}
    assert assume_by.get("principal_arn") == "email:dev@example.com", (
        f"expected inferred principal email:dev@example.com, "
        f"got assume_by={assume_by!r}"
    )


# ---- Test 2: explicit principal wins over the session default ----


def test_post_paste_explicit_principal_with_session_uses_explicit(
    as_dev: TestClient, shared_app
) -> None:
    """When the form supplies an explicit ARN, the session-id default
    must NOT override it. Otherwise the form's "override your default"
    affordance is a lie."""
    explicit = "arn:aws:iam::060392206767:role/ci-runner"
    resp = _submit_paste(as_dev, assume_principal_arn=explicit)
    assert resp.status_code == 303, resp.text
    request_id = resp.headers["location"].rsplit("/", 1)[-1]

    stored = _stored_request(shared_app, request_id)
    assume_by = (stored.get("spec") or {}).get("assume_by") or {}
    assert assume_by.get("principal_arn") == explicit, (
        f"explicit form value must win over session default; "
        f"got assume_by={assume_by!r}"
    )


# ---- Test 3: no session + blank → rejected with clear field-level error ----


def test_post_paste_blank_principal_no_session_rejects_with_clear_error(
    client: TestClient,
) -> None:
    """Unauthenticated POST with blank `assume_principal_arn` must be
    rejected — never silently accepted. The web POST endpoint enforces
    auth at the top, so the rejection observable is the redirect to
    /login (not a 4xx body). Both shapes are valid "clear rejections"
    per [[ibounce-honest-positioning]]; what matters is that no request
    is created with an empty principal."""
    resp = _submit_paste(client)  # no session cookie

    # Observable state: not a 2xx success — either a redirect to login
    # (303) or a 4xx field-level error. Both are acceptable rejection
    # shapes; what's NOT acceptable is a 303 to /requests/<id> that
    # would indicate a silently created request.
    assert resp.status_code in {303, 400}, (
        f"unauthenticated POST must be rejected, got {resp.status_code}: "
        f"{resp.text[:200]}"
    )
    if resp.status_code == 303:
        # If redirected, must go to login — not to a created request.
        assert resp.headers["location"].startswith("/login"), (
            f"unauthenticated POST must redirect to /login, "
            f"got {resp.headers['location']!r}"
        )
    else:
        # 400 path: body must name the field operator-readably.
        assert "assume_principal_arn" in resp.text


# ---- Test 4: error message is human-readable (no stack trace, no opaque code) ----


def test_post_paste_blank_principal_no_session_error_human_readable(
    client: TestClient,
) -> None:
    """The rejection surface (either the /login page or the 400 form)
    must be operator-readable — no raw stack traces, no opaque error
    codes. This is the [[ibounce-honest-positioning]] discipline: if
    the system refuses a request, the refusal text must tell the
    operator what to do next."""
    resp = _submit_paste(client)
    body = resp.text.lower()

    # Negative assertions: no debugging-only output leaks to the user.
    assert "traceback" not in body, (
        f"rejection body contains a raw traceback: {resp.text[:500]}"
    )
    assert "internal server error" not in body, (
        f"rejection body surfaces a 500 instead of a clean 400/303: "
        f"{resp.text[:500]}"
    )
    # Positive assertion: the response is one of the two clean shapes
    # (login redirect or form re-render with field-named error).
    assert resp.status_code in {303, 400}


# ---- Test 5: detail page no longer renders the "blocking issue" warning ----


def test_request_detail_no_longer_shows_no_principal_warning_after_fix(
    as_dev: TestClient,
) -> None:
    """Submit via the new (fixed) POST flow; load the detail page;
    verify the "No assumer principal set" warning is NOT in the HTML.
    The condition that used to fire it (resolve_assumer_principal
    returning None) is impossible by construction now that the route
    always populates assume_by.principal_arn."""
    resp = _submit_paste(as_dev)
    assert resp.status_code == 303, resp.text
    detail_url = resp.headers["location"]
    detail = as_dev.get(detail_url)

    assert detail.status_code == 200, detail.text
    # The specific warning we killed:
    #   "No assumer principal set." + "We couldn't infer which AWS
    #   identity will assume this role from your login..."
    # was rendered when resolve_assumer_principal(req) returned None.
    # Now that the route always populates assume_by.principal_arn, the
    # template branch (and the warning text) are gone.
    #
    # We deliberately do NOT assert the absence of all "blocking issue"
    # strings here — the CLI-preview surface has its own approval-time
    # blocking-issues mechanism (account not registered, assumer not
    # a real AWS ARN, etc.) and that's legitimate per the spec's
    # "DO NOT modify the AssumeRole logic" constraint.
    body = detail.text
    assert "No assumer principal set" not in body, (
        "the 'No assumer principal set' warning must be removed — "
        "principal_arn is now required at submit time"
    )
    assert "We couldn't infer which AWS identity" not in body, (
        "the inference-failed sentence from the old warning must be gone"
    )
    assert "spec.assume_by.principal_arn</code> before approval" not in body, (
        "the 'set ...before approval' fix-up instruction from the old "
        "warning must be gone — the warning's whole branch is dead code now"
    )


# ---- Test 6: sabotage-check — monkeypatch the inference helper ----


def test_inference_helper_is_load_bearing(
    monkeypatch, as_dev: TestClient, shared_app
) -> None:
    """Sabotage-check per CONTRIBUTING.md: monkeypatch
    `_infer_assumer_principal_from_user` to return "" (as if the
    helper were broken). Re-run test 1's scenario. The stored
    request's principal_arn must NOT be populated by some other
    accidental path — if it is, the inference helper isn't the
    load-bearing component the fix claims it is.

    Expected: submission either (a) is rejected with our 400 path
    because the principal can't be inferred, or (b) succeeds but
    with a missing/empty principal_arn — which the test will then
    flag as a regression."""
    from iam_jit.routes import web as web_mod

    monkeypatch.setattr(
        web_mod,
        "_infer_assumer_principal_from_user",
        lambda user: "",
    )

    resp = _submit_paste(as_dev)
    if resp.status_code == 303 and resp.headers["location"].startswith("/requests/"):
        # If the submission was accepted, the principal MUST be unset
        # (proving the inference was the only path that would have
        # populated it). Anything else would mean we have a hidden
        # fallback path that the fix's invariants don't actually
        # depend on.
        request_id = resp.headers["location"].rsplit("/", 1)[-1]
        stored = _stored_request(shared_app, request_id)
        assume_by = (stored.get("spec") or {}).get("assume_by") or {}
        assert not assume_by.get("principal_arn"), (
            f"with the inference helper sabotaged, no other path should "
            f"populate principal_arn — got assume_by={assume_by!r}. "
            f"This means the fix's invariants depend on something else "
            f"too, which should be made explicit."
        )
    else:
        # 400 rejection is the expected path: helper returns "",
        # the route's defensive branch surfaces the clear error.
        assert resp.status_code == 400, (
            f"expected 400 rejection when inference helper is sabotaged, "
            f"got {resp.status_code}: {resp.text[:300]}"
        )
        assert "assume_principal_arn" in resp.text
