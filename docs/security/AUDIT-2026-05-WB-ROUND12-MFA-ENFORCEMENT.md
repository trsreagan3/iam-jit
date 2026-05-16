# WB Audit Round 12 — MFA + self-approve enforcement landing (commit `056deea`)

Scope: the just-landed phase-1 enforcement of [[mfa-compliance-strategy]] Layer C
and [[self-approve-reductions]], specifically:

- `src/iam_jit/routes/requests.py::_apply_mfa_and_self_approve_enforcement` (new helper)
- `src/iam_jit/routes/requests.py` lines 634–745 (helper wiring inside `submit_request`)
- `src/iam_jit/routes/requests.py` lines 850–907 (history append + response body)
- `src/iam_jit/mfa_gate.py` (verify backing the MFA branch)
- `src/iam_jit/self_approve_reductions.py` (evaluator backing the override)
- `tests/test_mfa_self_approve_enforcement.py` (do the tests cover the gaps?)

Findings keyed `WB12-NN`. Severities: **CRIT** = launch-blocking, gate is silently a no-op
in production; **HIGH** = real bypass / escalation primitive; **MED** = hardening; **LOW** /
**INFO** = nice-to-have.

---

## WB12-01 — CRIT — `from ..auth import _get_secret` is a wrong-module import; MFA gate is silently dead in production

**Location**: `routes/requests.py` line 680.

```python
try:
    from .. import mfa_gate as _mfa_gate
    from ..auth import _get_secret as _auth_secret_getter  # type: ignore[attr-defined]
    mfa_cookie = request.cookies.get("iam_jit_session_mfa") if hasattr(request, "cookies") else None
    mfa_secret = _auth_secret_getter()
    ...
    _mfa_audit = {... "would_require_mfa": _mfa_gate.is_high_risk(...), **mfa_result.as_audit_dict()}
except Exception:
    pass
```

`_get_secret` does not exist in `iam_jit.auth`. It lives in `iam_jit.middleware`
(verified by grep + runtime: `ImportError: cannot import name '_get_secret' from
'iam_jit.auth'`). The `# type: ignore[attr-defined]` actually flags the bug to the
reader, but the broad `except Exception: pass` swallows the `ImportError` at request
time. Effect: `_mfa_audit` stays `{"mfa_gate_evaluated": False}` for **every**
production request — the MFA branch in the helper checks
`mfa_audit.get("would_require_mfa") is True`, which is False for the missing key,
so the MFA enforcement **never fires**.

Reproduced live in this audit:

```python
mfa_audit = {"mfa_gate_evaluated": False}        # what the route actually produces today
decision, actor, block = _apply_mfa_and_self_approve_enforcement(
    AutoApproveDecision(auto_approve=True, reason="success", details={"score": 9}),
    mfa_audit=mfa_audit,
    self_approve_audit={"self_approve_evaluated": False},
    analysis_score=9,
    user_id="email:alice@example.com",
)
# decision.auto_approve == True  ← a score-9 grant with NO MFA cookie auto-approves
# actor == "system:auto-approver"
# block is None
```

The unit tests in `tests/test_mfa_self_approve_enforcement.py` only call the helper
directly with a hand-crafted `mfa_audit` dict that already includes `would_require_mfa:
True` + `mfa_present: False`. They **never exercise the `submit_request` route end-to-end**,
so the broken import is not caught. The "blanket fuzz coverage" added in 6956a05 calls
the route with random JSON but doesn't assert anything about whether MFA was checked,
so it doesn't catch this either.

This is the same shape as WB11-05 ("MFA gate exists but no route consumes it"). The
fix landed but with the wrong import, silently reverting Round-11's closure. The
docstring + `[[mfa-compliance-strategy]]` memo + `COMPLIANCE-MAPPING.md` all promise
score≥7 grants need fresh MFA. None of that promise is delivered.

**Fix**: change line 680 to `from ..middleware import _get_secret as _auth_secret_getter`,
remove the misleading `# type: ignore[attr-defined]`, and add an integration test that
posts a score-9 request with no MFA cookie through `TestClient` and asserts:
- response 201 with `auto_approve_decision.auto_approve == False`
- response body contains `mfa_step_up.redirect_to`
- request state stayed at `pending`
- audit row has `kind="request.auto_approve_skipped"` with `reason="mfa_required_for_high_risk"`

Once that test is in place, this finding can never silently regress again.

**Bonus fix**: replace `except Exception: pass` with `except Exception as e: logger.warning("mfa gate failed: %s", e, exc_info=True)`. The "fail open silently" pattern is the only reason this CRIT shipped — a logged warning would have surfaced it on the first staging request.

---

## WB12-02 — CRIT — Self-approve evaluator reads `metadata.owner` but route writes owner to `status.owner`; gate is silently dead in production

**Location**: `self_approve_reductions.py` lines 119–125; `lifecycle.py` `init_status` line 99.

`init_status` (called from `submit_request` line 623) writes:

```python
request["status"]["owner"] = owner.id
```

But `self_approve_reductions.evaluate` (called from `submit_request` line 705 with the
same request dict) reads:

```python
metadata = request.get("metadata") or {}
owner = metadata.get("owner") or ""
if owner != user_id:
    return SelfApproveDecision(self_approved=False, reason="not_owner", ...)
```

There is **no code anywhere** that writes `metadata.owner`. The result is that
`evaluate` always returns `not_owner` for every request submitted through the route —
even for an admin owner running in solo mode requesting on their own behalf. Reproduced:

```python
req = {"spec": {"policy": {"Statement": [{"Effect": "Allow", "Action": "s3:*"}]}},
       "metadata": {"requester": {"email": "alice@example.com"}},
       "status":   {"owner": "email:alice@example.com"}}    # owner is in status, not metadata
d = self_approve_reductions.evaluate(
    request=req, user_id="email:alice@example.com",
    user_is_admin=True, blocked_services=())
# d.self_approved == False
# d.reason == "not_owner"
# d.details == {"owner": "", "requesting_user": "email:alice@example.com"}
```

Effect: `_self_approve_audit["self_approve_eligible"]` is always False on the live
route. The override branch in `_apply_mfa_and_self_approve_enforcement` (line 121)
never fires. The "solo mode admins skip approval on their own reductions" promise
from `[[self-approve-reductions]]` is a complete no-op in production — solo-dev users
still see every request stuck at `pending`.

The unit tests don't catch this because they pass a hand-crafted `self_approve_audit`
dict with `self_approve_eligible=True` directly to the helper, bypassing the
evaluator entirely.

**Fix**: read from `status.owner` (the load-bearing field). One-line change:

```python
status_block = request.get("status") or {}
owner = status_block.get("owner") or ""
```

OR — preserved-for-compatibility — try `status.owner` first, fall back to
`metadata.owner` (handles a hypothetical future migration). Add an integration test
that asserts `IAM_JIT_DEPLOYMENT_MODE=solo` + admin + own-request → request lands
at `provisioning` with actor `self_approve_reduction:<id>` in the history.

---

## WB12-03 — HIGH — `IAM_JIT_MFA_STEP_UP_AT_SCORE` accepts `999`, `0`, and negative values; no sanity floor

**Location**: `mfa_gate.py` `_high_risk_score_floor` lines 141–146.

This is WB11-07 (MED) escalated to HIGH because (a) the gate is a CRIT-blocked no-op
today (WB12-01) and the env-var foot-gun becomes the next-line-of-defense once
WB12-01 is fixed, and (b) the recent `auto_approve.py` floor-clamp work
(WB10-02) established the pattern of "operator overrides must clamp to safe bounds"
that this code does not follow. Verified live:

```
IAM_JIT_MFA_STEP_UP_AT_SCORE=999  → floor=999, is_high_risk(10)=False  (gate disabled)
IAM_JIT_MFA_STEP_UP_AT_SCORE=-5   → floor=-5,  is_high_risk(0)=True   (gate on every request)
IAM_JIT_MFA_STEP_UP_AT_SCORE=abc  → floor=7   (default; OK)
IAM_JIT_MFA_STEP_UP_AT_SCORE=""   → floor=7   (default; OK)
```

Worst case: an operator setting `999` (or a compromised env var) silently disables the
entire Layer C MFA gate. The compliance-mapping doc still claims the gate is on. PCI
auditor reviewing the YAML would not catch this.

**Fix**: clamp to `1..10` at read time. Out-of-band values → log WARNING + use default.
If the operator wants to disable the gate, force them to set a separate explicit
`IAM_JIT_MFA_STEP_UP_DISABLED=1` flag — the disable path should be loud, not "set the
threshold to a number IAM scores can't reach." Same shape as WB10-02's floor clamp.

---

## WB12-04 — HIGH — `would_require_mfa` is a `bool`-typed read but the `is True` comparison rejects truthy-but-not-True values; brittle

**Location**: `routes/requests.py` `_apply_mfa_and_self_approve_enforcement` line 93.

```python
mfa_audit.get("would_require_mfa") is True
mfa_audit.get("mfa_present") is False
```

`is True` / `is False` is the right defensive shape against truthy-int / truthy-str
poisoning of the audit dict — but it's also fragile in the OTHER direction. Verified:
if `mfa_gate.is_high_risk(...)` ever returned a truthy int instead of a bool (it
doesn't today, but it's not type-checked), the gate silently disables. Reproduced
with a poisoned audit dict:

```python
mfa_audit = {"would_require_mfa": 1, "mfa_present": 0, "mfa_reason": "mfa_too_stale"}
# helper returns auto_approve=True (no override) — silent bypass
```

Defense in depth: the dict is built locally in `submit_request` lines 689–698, so
external poisoning is not the threat here. The threat is a future code change to
`mfa_gate` (e.g., adding short-circuit `return 1` or `return None` for "unknown")
that silently disables the gate. The `is True` comparison treats those as equivalent
to "not high-risk."

**Fix**: tighten the check by also asserting the keys are PRESENT before
unwrapping: `mfa_audit.get("mfa_gate_evaluated") is True and mfa_audit.get("would_require_mfa") is True and mfa_audit.get("mfa_present") is False`. The `mfa_gate_evaluated` gate makes the failure mode "gate didn't run → fail-closed" instead of "gate didn't run → ignore." Also: type-annotate `is_high_risk` and `as_audit_dict` so a future return-type drift trips mypy.

---

## WB12-05 — HIGH — `/preview` does not run the enforcement helper; UI shows `would_auto_approve=True` for grants that submit will block

**Location**: `routes/requests.py` `preview_request` lines 327–504.

`/preview` runs `auto_approve.evaluate` (line 447) and returns `would_auto_approve`
straight from the result. It does NOT call `_apply_mfa_and_self_approve_enforcement`
and does NOT inspect the user's MFA cookie. Effect: a high-risk request that the
submit path WILL block for stale MFA shows `would_auto_approve=True` in the preview
panel.

This is a UX trust-rot issue (the preview dial lies) and a security issue (an attacker
with an admin session but stale MFA gets a confirmation that "yes, this will auto-
approve" right before the actual submission gets blocked — the dial becomes a
reconnaissance tool for "what scores would have qualified if I had fresh MFA?").

The shape mirrors WB11-18 (a documented feature whose route doesn't plumb it through).

**Fix**: in `preview_request`, after `auto_decision = auto_approve_mod.evaluate(...)`,
call the same MFA + self-approve enforcement helper with the same inputs, and use
the post-override decision in the response. Also add `mfa_step_up_required` and
`self_approve_eligible` booleans to the response body so the UI can render an
explicit "you need fresh MFA before this will auto-approve" hint instead of just
flipping the dial silently.

---

## WB12-06 — MED — Broad `except Exception: pass` around the MFA + self-approve eval blocks (lines 699, 716) is the WHY this audit found two CRITs

**Location**: `routes/requests.py` lines 678–700, 702–717.

```python
try:
    from .. import mfa_gate as _mfa_gate
    from ..auth import _get_secret as _auth_secret_getter   # WRONG module — see WB12-01
    ...
except Exception:
    pass

_self_approve_audit = {"self_approve_evaluated": False}
try:
    from .. import self_approve_reductions as _sar
    ...
except Exception:
    pass
```

The intent is documented at line 674: "Each block is wrapped in try/except so a bug in
the gate code never blocks a grant — failure mode is 'annotation missing', not
'request stuck'." That intent is correct for a CALIBRATION-grade gate (you don't want
a typo in the scoring path to wedge every request). But it's wrong for an
ENFORCEMENT-grade gate: failing open on the MFA gate means "PCI compliance silently
disabled until someone notices."

The pattern is structurally why WB12-01 + WB12-02 both shipped to main without anyone
noticing: a smoke test that probes "submit a high-risk request without MFA, was it
blocked?" would have caught both, but the silent-swallow design makes those tests
boring (everything always returns 201) so they don't get written.

**Fix**:
1. Replace `except Exception: pass` with structured logging:
   `except Exception as e: logger.exception("mfa_gate evaluation failed; failing closed for high-risk grants")`
2. Distinguish ImportError from other failures. ImportError on a load-bearing gate is
   a deployment misconfiguration and should LOUDLY 500, not silently degrade. Move the
   imports to module top-level so the failure surfaces at app startup, not per-request.
3. For high-risk requests specifically, FAIL CLOSED if the MFA gate didn't evaluate
   (i.e., treat `mfa_gate_evaluated=False` + `score >= 7` as "block, route to human
   review with reason=`mfa_gate_unavailable`"). The current code fails open in that
   exact scenario.

---

## WB12-07 — MED — Helper signature uses string-quoted `"Any"` for `auto_decision`; future type drift on `AutoApproveDecision` won't surface

**Location**: `routes/requests.py` line 56.

```python
def _apply_mfa_and_self_approve_enforcement(
    auto_decision: "Any",  # AutoApproveDecision; quoted to dodge late-binding
    ...
```

The comment is misleading: `Any` doesn't need to be quoted to dodge late-binding (it's
imported at module top). The quoting + `Any` together amount to "no type checking on
the most security-critical input to this helper." A future refactor that changes
`AutoApproveDecision` from a dataclass to e.g. a TypedDict would silently break
`getattr(auto_decision, "auto_approve", False)` (which would always return False on a
dict, silently DENYING all auto-approves). mypy would not catch it.

**Fix**: import `AutoApproveDecision` at the top of `routes/requests.py` (or use
`if TYPE_CHECKING: from ..auto_approve import AutoApproveDecision`) and annotate the
parameter as `AutoApproveDecision`. Drop the misleading comment.

---

## WB12-08 — MED — Strict-mode reasons (`strict_mode_action_wildcard`, `strict_mode_admin_fallback`) cannot be self-approve-overridden, but this is undocumented

**Location**: `routes/requests.py` line 120; `auto_approve.py` (WB10-04 + WB11-02 closures).

`_apply_mfa_and_self_approve_enforcement` checks `getattr(auto_decision, "reason", "") == "above_threshold"` to decide whether to fire the self-approve override.
WB10-04 (strict-mode action wildcard) and WB11-02 (NotAction) emit reasons starting
with `strict_mode_*`. Effect: an admin in solo mode CANNOT self-approve a strict-mode-
blocked request — which is the right answer (strict mode shouldn't be bypassable),
but it is undocumented, and a future maintainer adding a new strict-mode rule with
reason `strict_mode_xyz` will silently inherit the correct behavior without realizing
it.

This is the inverse failure mode of WB12-01: today the gate fails CLOSED for a
non-obvious reason (wrong reason string), and a future maintainer might "fix" it by
changing the comparison to `getattr(auto_decision, "reason", "") in {"above_threshold", "strict_mode_*"}` — which would re-open the strict-mode bypass.

**Fix**: turn the reason comparison into a positive allow-list with a docstring:

```python
# Self-approve override fires ONLY when the ONLY reason the score gate denied
# was "above_threshold". Strict-mode denials, blocklist denials, quota denials,
# and feature-disabled denials must NOT be reachable via self-approve — they
# represent platform-team floors that even admin reductions cannot route around.
_SELF_APPROVE_OVERRIDABLE_REASONS = frozenset({"above_threshold"})
if (
    getattr(auto_decision, "auto_approve", False) is False
    and getattr(auto_decision, "reason", "") in _SELF_APPROVE_OVERRIDABLE_REASONS
    and self_approve_audit.get("self_approve_eligible") is True
):
    ...
```

Also add a regression test that asserts `strict_mode_action_wildcard`,
`service_blocked`, `over_quota`, `feature_disabled`, `floor_clamped`, and
`no_policy` all flow through unchanged when self-approve is otherwise eligible.

---

## WB12-09 — MED — `audit_actor_for(user_id)` returns `self_approve_reduction:email:alice@example.com` (double colon); downstream parsers that do `actor.split(":", 1)` see `("self_approve_reduction", "email:alice@example.com")` — mostly OK, but no test pins the contract

**Location**: `self_approve_reductions.py` line 167; `routes/requests.py` line 851 (history `actor` field), line 758 (audit `actor` field).

The actor string contains TWO colons when the user_id is the typical
`email:<address>` shape. Today no consumer in `src/iam_jit/` splits the actor on
colon (verified by grep), so this is INFO-grade. But the audit format docs in
`docs/compliance/COMPLIANCE-MAPPING.md` show actor strings without internal colons,
and a future SIEM ingester writing `actor_kind, actor_id = actor.split(":", 1)` would
get the right answer ONLY because of `split(":", 1)`'s maxsplit — drop the maxsplit
and the parse breaks.

The history event AND the audit_mod.emit DO match (both use
`_auto_audit_actor` from the same helper return), so the cross-event consistency
called out in the threat model is fine.

**Fix**: either (a) document the actor format in COMPLIANCE-MAPPING.md as
`<actor_kind>:<user_id>` where `<user_id>` may itself contain colons, with an
explicit "consumers MUST use `split(':', 1)`" warning, or (b) hash the user_id
(`f"self_approve_reduction:{sha256(user_id)[:16]}"`) so the actor field is
single-segment. Option (a) is cheaper; (b) is more robust for SIEM ingestion. Add
a test that pins the actor format with two example user_ids
(`email:a@b.com` and `iam:arn:aws:iam::123:user/x`) so a future change is loud.

---

## WB12-10 — LOW — `mfa_step_up.redirect_to` is a hardcoded literal; safe today but a future config-driven version would need URL allow-listing

**Location**: `routes/requests.py` line 112.

```python
block_response = {
    "mfa_step_up_required": True,
    "reason": mfa_audit.get("mfa_reason"),
    "redirect_to": "/api/v1/auth/oidc/login",
}
```

The literal is safe — there's no way for an attacker to manipulate this string from a
request body. INFO-grade except as a forward-looking note: when iam-jit eventually
supports per-tenant OIDC providers (Pro tier roadmap per
`[[contractor-auditor-access-use-case]]`), this string will become config-driven, at
which point it MUST flow through the same OIDC redirect_uri allow-list that
`oidc.py` uses for the post-login bounce. Otherwise an attacker who can edit a
tenant's settings can set `redirect_to: "https://evil.com"` and capture the OAuth
code on the rebound.

**Fix today**: leave as-is + add a comment marker
`# WB12-10: when this becomes config-driven, validate against `oidc._allowed_redirect_uris()`.`
**Fix when it becomes dynamic**: validate the string is either a relative path
starting with `/` or a fully-qualified URL whose origin is in the OIDC allow-list.

---

## WB12-11 — LOW — Response-body leak: `auto_decision.details` (returned in response.body.auto_approve_decision.details) includes the full `score` and the original `policy_size_chars` etc. — modest oracle for an attacker probing policy structure

**Location**: `routes/requests.py` lines 893–899.

The submit response always includes `auto_approve_decision.details` in the body, which
contains the deterministic score (e.g., `8`) plus internal threshold / safety-mode
context. The MFA-blocked path adds `mfa_reason: "mfa_too_stale"` etc. An attacker
submitting requests in a loop and varying the policy can use the score in the response
to reverse-engineer the scoring rubric — same shape as a JIT compilation oracle.

This is LOW because (a) the scorer is open source (the rubric is in `review.py`), and
(b) showing the score is the entire point of the iterative-tightening UX. INFO except
that the MFA-blocked branch ALSO includes `original_reason` in the details, which
leaks "what would have happened if MFA had been fresh" — i.e., "yes you have admin
authority but you need to step up." That last bit is a useful oracle for an attacker
with stolen-but-stale MFA to know they have a viable path forward.

**Fix**: split the response into a "client-facing" subset (what to show the user)
vs the full audit detail (server-side only). For the MFA-blocked case, omit
`original_reason` and `score` from the response body — the audit log keeps them, but
the API consumer doesn't need them. The body should say "step up MFA and resubmit"
without confirming "yes you would have qualified."

---

## WB12-12 — LOW — Helper does dynamic `from ..auto_approve import AutoApproveDecision` inside the function body twice (lines 96, 123)

**Location**: `routes/requests.py` lines 96, 123.

Style nit: the helper imports `AutoApproveDecision` lazily inside the function. The
comment on line 56 says "quoted to dodge late-binding," which suggests the author
was working around a circular-import risk, but the actual repo has no circular
import here (`auto_approve` doesn't import `routes/`). Lazy imports inside a hot
path also make the helper marginally slower per call.

**Fix**: top-of-module `from ..auto_approve import AutoApproveDecision`. Removes the
two in-function imports and lets the type annotation in WB12-07 work properly.

---

## WB12-13 — INFO — `is_admin` is sourced from `users_store.User.is_admin`, which is a Python `@property` reading `"admin" in self.roles`; safe but worth a regression test against role-list shape mutation

**Location**: `users_store.py` line 44; consumed at `routes/requests.py` line 708 via `getattr(user, "is_admin", False)`.

Threat model question 2.1 ("can a non-admin escalate by spoofing user.is_admin?")
traces:

```
middleware.py current_user → user_store.get(user_id) → User dataclass
User.is_admin → @property: return "admin" in self.roles
```

Roles come from the YAML user store (or DDB), which the request handler cannot
mutate. A non-admin cannot become an admin by anything in the request body — the
attribute is read from the AUTHENTICATED principal's persisted record. Fine.

The `getattr(user, "is_admin", False)` defensive default at line 708 is correct: if
the user store is misconfigured and returns an object without `is_admin`, the gate
fails closed (admin=False → not_admin → no self-approve). Good.

**Fix**: nothing required. Add a brief "trust chain" note to the helper docstring:
"`user_is_admin` derives from the persisted user record loaded by middleware; not
client-controllable."

---

## WB12-14 — INFO — Tests at `tests/test_mfa_self_approve_enforcement.py` are unit-only against the helper; no integration test exercises the route, which is exactly why WB12-01 + WB12-02 shipped

**Location**: entire test file.

Every test in the suite calls `_apply_mfa_and_self_approve_enforcement` directly with
hand-constructed `mfa_audit` and `self_approve_audit` dicts. The dicts contain keys
the live route's broken code paths CAN'T produce (`would_require_mfa`,
`self_approve_eligible`). Result: the suite gives 100% coverage of the helper and 0%
coverage of the route's wiring. Both CRITs (WB12-01, WB12-02) sit in the wiring.

**Fix**: add a single integration test class that uses `fastapi.testclient.TestClient`
+ a real user store + a real settings store, and posts:

1. A score-9 request with NO MFA cookie → assert response 201 + body has
   `mfa_step_up.redirect_to == "/api/v1/auth/oidc/login"`, request state stayed at
   `pending`, audit row exists with `kind="request.auto_approve_skipped"` and
   `reason="mfa_required_for_high_risk"`.
2. A score-9 request WITH a fresh MFA cookie (signed by the test secret) →
   request state advanced to `provisioning`, no `mfa_step_up` in body.
3. A score-8 request from an admin in `IAM_JIT_DEPLOYMENT_MODE=solo` →
   request state advanced to `provisioning`, history actor =
   `self_approve_reduction:<id>`, audit row has actor matching.
4. A score-8 request from a non-admin in solo mode → request stays `pending`,
   no self-approve actor in history.

Steps 1 and 3 would fail TODAY against the bugs in WB12-01 and WB12-02.

---

## Headline summary

Fourteen findings. Two are launch-blocking CRITs that make the entire phase-1
enforcement landing a no-op in production:

- **WB12-01 (CRIT)**: the route imports `_get_secret` from the wrong module; the
  `ImportError` is silently swallowed by a broad `except Exception: pass`, so the MFA
  gate never evaluates for ANY request. A score-9 grant with no MFA cookie at all
  auto-approves today. Reproduced live in this audit.
- **WB12-02 (CRIT)**: `self_approve_reductions.evaluate` reads the request owner from
  `metadata.owner`, but the route writes it to `status.owner`. The owner check
  always returns `not_owner`, so the self-approve override never fires for any
  admin-in-solo-mode request. Reproduced live in this audit.

The unit tests pass because they call the helper directly with hand-crafted audit
dicts that the route can't actually produce — there is no integration test that
exercises `submit_request` end-to-end with MFA + self-approve enforcement
(WB12-14). One TestClient-backed integration test would have caught both CRITs
before commit.

The structural reason both CRITs shipped is the broad `except Exception: pass` around
the MFA + self-approve eval blocks (WB12-06), which is correct for calibration-grade
annotations but wrong for enforcement-grade gates. The fix has three parts: (a)
log the swallowed exception, (b) move the imports to module-top so deployment-time
misconfiguration crashes loudly at startup, and (c) for HIGH-RISK requests
specifically, fail-CLOSED when the MFA gate did not evaluate.

After the CRITs: WB12-03 (env-var foot-gun, no clamp on the high-risk floor),
WB12-04 (brittle `is True` comparison), and WB12-05 (preview lies about
`would_auto_approve` because the helper isn't wired into /preview) are the
HIGH-priority follow-ups. WB12-06/07/08/09 are MED hardening. WB12-10/11/12 are
LOW. WB12-13/14 are INFO.

Recommended ship order:

1. Fix WB12-01 (1-line import fix) + add the WB12-14 integration test for MFA gate.
2. Fix WB12-02 (1-line read-from-status.owner fix) + extend WB12-14 integration
   test to cover self-approve.
3. Replace `except Exception: pass` with structured logging + fail-closed for
   high-risk (WB12-06).
4. Clamp `IAM_JIT_MFA_STEP_UP_AT_SCORE` to `1..10` with explicit-disable env var
   (WB12-03).
5. Wire the helper into `/preview` (WB12-05).
6. Tighten the `is True` comparison + type the helper signature (WB12-04 + WB12-07).
7. Convert reason gate to positive allow-list with docstring (WB12-08).
8. Document or hash the actor string format (WB12-09).
9. Cosmetic + future-proofing (WB12-10/11/12).

Until WB12-01 + WB12-02 are closed, the `[[mfa-compliance-strategy]]` Layer C and
`[[self-approve-reductions]]` rows in `COMPLIANCE-MAPPING.md` should be marked
**"implemented but not enforced — see AUDIT-2026-05-WB-ROUND12"** so a customer
PCI auditor doesn't get the wrong answer in the interim.
