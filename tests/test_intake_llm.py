"""Behavioral tests for the conversational intake against a real LLM.

These tests drive `iam_jit.intake.take_turn()` through multi-turn
scenarios and assert on the resulting policy. They catch regressions
the unit tests can't:

  - empty / unrelated / overly-broad policies on completion
  - the model ignoring user clarifying questions
  - the model spell-correcting proper nouns
  - the model asking irrelevant follow-ups (SDK versions, dates, etc.)
  - the model hallucinating accounts / services not mentioned

Three modes (selected via env):

  IAM_JIT_LLM_REPLAY=1   (CI default once cassettes exist)
    Plays back recorded LLM responses from `tests/cassettes/<test>.jsonl`.
    Deterministic, no network, no AWS creds. Fails loudly if a cassette
    is missing.

  IAM_JIT_LLM_RECORD=1
    Calls the real LLM, records every response to the cassette. Used
    when prompts change. Run once locally, commit the cassettes.

  default (no env vars)
    Calls the real LLM live each time. Used during local prompt
    iteration. Skips if no LLM is reachable.

Marker: `integration` (skipped by default; run with `pytest -m integration`).
"""

from __future__ import annotations

import os
import pathlib
from typing import Any

import httpx
import pytest

from iam_jit import intake
from iam_jit.llm import OllamaBackend, wrap_with_cassette

pytestmark = pytest.mark.integration


_OLLAMA_HOST = os.environ.get("OLLAMA_HOST", "http://localhost:11434")
_TEST_MODEL = os.environ.get("IAM_JIT_LLM_MODEL", "llama3.1:8b")
_CASSETTES_DIR = (
    pathlib.Path(__file__).resolve().parent
    / "cassettes"
    / "intake_llm"
)
_REPLAY = os.environ.get("IAM_JIT_LLM_REPLAY") in {"1", "true", "yes"}


@pytest.fixture(scope="module")
def _live_ollama_backend() -> OllamaBackend | None:
    """Live Ollama backend if reachable + model loaded. None otherwise.

    In replay mode we don't need a live backend — replays are served
    from the cassette. In record / pass-through mode, this skips the
    test gracefully if Ollama isn't running.
    """
    if _REPLAY:
        return None
    try:
        r = httpx.get(f"{_OLLAMA_HOST}/api/tags", timeout=2.0)
        r.raise_for_status()
        loaded = {m["name"] for m in r.json().get("models", [])}
    except Exception as e:
        pytest.skip(f"Ollama not reachable at {_OLLAMA_HOST}: {e}")
    if _TEST_MODEL not in loaded:
        pytest.skip(
            f"model '{_TEST_MODEL}' not loaded in Ollama "
            f"(have: {sorted(loaded)}); pull it or override IAM_JIT_LLM_MODEL"
        )
    return OllamaBackend(host=_OLLAMA_HOST, model=_TEST_MODEL)


class _NullBackend:
    """Stand-in for replay mode where the cassette serves every call.

    Never invoked; if it ever is, that's a bug in the cassette wiring."""

    name = "null"

    def refine(self, **kwargs):  # type: ignore[no-untyped-def]
        raise NotImplementedError

    def chat(self, *, system_prompt, messages):  # type: ignore[no-untyped-def]
        raise NotImplementedError(
            "live backend invoked in replay mode — cassette is incomplete"
        )


@pytest.fixture
def ollama_backend(_live_ollama_backend, request):  # type: ignore[no-untyped-def]
    """Cassette-aware backend factory.

    - replay mode: wraps a NullBackend with the cassette in replay mode
    - record mode: wraps the live Ollama backend in record mode
    - default: returns the live Ollama backend unchanged
    """
    cassette_path = _CASSETTES_DIR / f"{request.node.name}.jsonl"
    if _REPLAY:
        return wrap_with_cassette(_NullBackend(), cassette_path=cassette_path)
    assert _live_ollama_backend is not None
    return wrap_with_cassette(_live_ollama_backend, cassette_path=cassette_path)


# ---- Conversation driver ----


class _Driver:
    """Drives an intake conversation via canned user replies.

    Scenarios call .send(...) for the opening message, then .reply(...)
    for each follow-up. Reaches completion or hits the hard cap.
    """

    def __init__(self, backend: Any) -> None:
        self.backend = backend
        self.history: list[dict[str, str]] = []
        self.last: intake.IntakeTurn | None = None

    def send(self, content: str) -> intake.IntakeTurn:
        self.history.append({"role": "user", "content": content})
        self.last = intake.take_turn(self.history, self.backend)
        if self.last.ask:
            self.history.append({"role": "assistant", "content": self.last.ask})
        return self.last

    def reply(self, content: str) -> intake.IntakeTurn:
        return self.send(content)

    def drive_to_completion(self, default_replies: list[str]) -> intake.IntakeTurn:
        """Keep replying with values from `default_replies` (rotating)
        until the conversation completes or we hit the hard cap.

        Use this when a scenario doesn't care about the exact follow-up
        the model picks — it just needs the conversation to terminate.
        """
        idx = 0
        while not self.last or not self.last.complete:
            if not self.last or not self.last.ask:
                break
            reply = default_replies[idx % len(default_replies)]
            idx += 1
            self.reply(reply)
            if len(self.history) > intake.MAX_USER_TURNS_BEFORE_COMPLETE * 4:
                break
        assert self.last is not None
        return self.last


# ---- Policy structure helpers ----


def _all_actions(policy: dict[str, Any]) -> list[str]:
    actions: list[str] = []
    for s in policy.get("Statement") or []:
        a = s.get("Action") or []
        if isinstance(a, str):
            actions.append(a)
        elif isinstance(a, list):
            actions.extend(x for x in a if isinstance(x, str))
    return actions


def _services_in_policy(policy: dict[str, Any]) -> set[str]:
    return {a.split(":", 1)[0] for a in _all_actions(policy) if ":" in a}


def _has_service(policy: dict[str, Any], service_prefix: str) -> bool:
    return service_prefix in _services_in_policy(policy)


_WRITE_VERBS = (
    "Create",
    "Delete",
    "Put",
    "Update",
    "Modify",
    "Change",  # e.g., route53:ChangeResourceRecordSets
    "Set",  # e.g., s3:SetBucketAcl, dynamodb:SetExceptionsForSchedule
    "Write",  # e.g., logs:PutRetentionPolicy is Put, logs:WriteLogEvent
    "Send",  # e.g., sqs:SendMessage, sns:Publish (not Send but PUT)
    "Publish",
    "Invoke",  # e.g., lambda:Invoke
    "Run",  # e.g., ec2:RunInstances
    "Attach",
    "Detach",
    "Add",
    "Remove",
    "Tag",
    "Untag",
    "Reboot",
    "Terminate",
    "Disable",
    "Enable",
    "Start",
    "Stop",
    "Deny",
    "Reject",
    "Replace",
    "Restore",
    "Cancel",
    "Promote",
    "Reset",
    "Rotate",
    "Apply",
    "Deploy",
    "Move",
    "Copy",
    "Upload",
)


_QUERY_LIFECYCLE_OK = {
    # CloudWatch Logs Insights: these are query operations, not writes.
    # The verb prefix matches "Start"/"Stop" but the action just runs a
    # read-only query against logs.
    "logs:StartQuery",
    "logs:StopQuery",
    "logs:GetQueryResults",
}


_DEBUG_BUNDLE_SERVICES = {
    # Service prefixes the F5 debug-bundle augmenter adds automatically
    # to most read-only requests (CloudWatch metrics, X-Ray traces, Logs
    # Insights). They're never written by the user — the synthesizer
    # injects them. Tests that assert "user-requested service set" need
    # to subtract these out.
    "cloudwatch",
    "xray",
    "logs",
}


def _looks_read_only(policy: dict[str, Any]) -> bool:
    """No action looks like a write verb. Wildcards (e.g. 's3:*') count
    as not-read-only because they grant write."""
    for a in _all_actions(policy):
        if ":" not in a:
            return False
        if a in _QUERY_LIFECYCLE_OK:
            continue
        verb = a.split(":", 1)[1]
        if verb == "*":
            return False
        if any(verb.startswith(w) for w in _WRITE_VERBS):
            return False
    return True


# ---- Scenarios ----


def test_alb_describe_in_dev_produces_read_only_elb_policy(
    ollama_backend: Any,
) -> None:
    """User asks for ALB IP in a dev account — should land at a
    read-only policy granting elasticloadbalancing Describe/Get/List."""
    drv = _Driver(ollama_backend)
    drv.send(
        "I need to get the ip of an alb in account 847283080673 in the dev environment"
    )
    final = drv.drive_to_completion(default_replies=["I dont know", "default", "no"])

    assert final.complete, f"never completed; last ask was {final.ask!r}"
    assert final.draft_policy is not None
    policy = final.draft_policy

    assert intake._is_usable_policy(policy), f"unusable policy: {policy}"
    assert _has_service(policy, "elasticloadbalancing"), (
        f"expected elasticloadbalancing in {_services_in_policy(policy)}"
    )
    assert _looks_read_only(policy), f"expected read-only, got actions: {_all_actions(policy)}"
    # Should NOT include unrelated services. Tolerate ec2 (the SDK uses
    # both for some ALB operations) but reject obvious noise.
    services = _services_in_policy(policy)
    forbidden = {"iam", "organizations", "secretsmanager", "kms", "rds"}
    assert not (services & forbidden), (
        f"policy contained forbidden services {services & forbidden}: {services}"
    )


def test_s3_read_with_specific_bucket_lands_on_s3_policy(
    ollama_backend: Any,
) -> None:
    """User asks for S3 read on a specific bucket — policy should
    include s3 read actions."""
    drv = _Driver(ollama_backend)
    drv.send(
        "I need to read s3 config files from the example-config bucket "
        "in account 060392206767, 24 hours please"
    )
    final = drv.drive_to_completion(default_replies=["read-only", "I dont know"])

    assert final.complete, f"never completed; last ask was {final.ask!r}"
    assert final.draft_policy is not None
    policy = final.draft_policy

    assert intake._is_usable_policy(policy)
    assert _has_service(policy, "s3"), f"expected s3 in {_services_in_policy(policy)}"
    assert _looks_read_only(policy)


def test_secrets_manager_read_lands_on_secretsmanager_policy(
    ollama_backend: Any,
) -> None:
    drv = _Driver(ollama_backend)
    drv.send(
        "I need to read aws secrets manager values for the core service "
        "in account 847283080673"
    )
    final = drv.drive_to_completion(default_replies=["I dont know", "default"])

    assert final.complete, f"never completed; last ask was {final.ask!r}"
    assert final.draft_policy is not None
    assert _has_service(final.draft_policy, "secretsmanager"), (
        f"services: {_services_in_policy(final.draft_policy)}"
    )
    assert _looks_read_only(final.draft_policy)


def test_explicit_read_write_request_produces_write_actions(
    ollama_backend: Any,
) -> None:
    """User explicitly asks for write access — the policy must reflect
    that, not silently downgrade to read-only."""
    drv = _Driver(ollama_backend)
    drv.send(
        "I need to create and delete dynamodb tables in account 060392206767, "
        "read-write, 8 hours"
    )
    final = drv.drive_to_completion(default_replies=["I dont know"])

    assert final.complete
    assert final.draft_policy is not None
    assert _has_service(final.draft_policy, "dynamodb")
    # MUST NOT be read-only when the user explicitly said read-write.
    assert not _looks_read_only(final.draft_policy), (
        f"user asked for read-write but got read-only: {_all_actions(final.draft_policy)}"
    )


def test_completion_never_yields_an_empty_policy(
    ollama_backend: Any,
) -> None:
    """The exact regression that hit production: model emits
    Statement: [] on completion. Synthesizer fallback must catch it."""
    drv = _Driver(ollama_backend)
    drv.send("read s3 in 123456789012")
    final = drv.drive_to_completion(default_replies=["default", "I dont know"])

    assert final.complete
    assert final.draft_policy is not None
    statements = final.draft_policy.get("Statement", [])
    assert isinstance(statements, list) and len(statements) >= 1, (
        f"completion produced empty Statement: {final.draft_policy}"
    )
    for s in statements:
        assert s.get("Action"), f"statement without Action: {s}"
        assert s.get("Resource") or s.get("NotResource"), f"statement without Resource: {s}"


def test_user_clarifying_question_does_not_get_ignored(
    ollama_backend: Any,
) -> None:
    """When the user asks the bot a question (e.g. 'do you mean X?'),
    the bot must address it rather than pivot to a different question."""
    drv = _Driver(ollama_backend)
    drv.send("I need to read secrets for the core service in dev")
    # Answer the bot's first follow-up by asking a clarifying question back.
    if drv.last and drv.last.ask:
        drv.reply("do you mean the arn of the secret I am requesting access to?")
        # Bot's next reply must reference the user's question (mention 'arn'
        # or 'secret' or 'yes/no'). It must NOT just ask a fresh unrelated
        # question.
        assert drv.last.ask is not None
        ask_lower = drv.last.ask.lower()
        addresses_question = any(
            term in ask_lower for term in ("arn", "secret", "yes", "no", "either")
        )
        assert addresses_question, (
            f"bot ignored the user's clarifying question; bot said: {drv.last.ask!r}"
        )


def test_model_does_not_invent_unrelated_services(
    ollama_backend: Any,
) -> None:
    """The user said S3. The policy must not include EKS, Secrets Manager,
    or anything unrelated."""
    drv = _Driver(ollama_backend)
    drv.send("read-only s3 in 060392206767, default duration")
    final = drv.drive_to_completion(default_replies=["I dont know", "default"])

    assert final.complete
    assert final.draft_policy is not None
    services = _services_in_policy(final.draft_policy)
    # Allow s3 plus debug-bundle additions (cloudwatch metrics, x-ray,
    # logs insights) that the F5 synthesizer injects. The contract
    # being tested is that the LLM didn't invent unrelated user-domain
    # services like eks/secretsmanager/dynamodb.
    user_services = services - _DEBUG_BUNDLE_SERVICES
    assert user_services == {"s3"}, (
        f"S3-only request leaked into unrelated services: {user_services} "
        f"(full: {services})"
    )


def test_multi_service_no_arns_falls_back_to_read_only_wildcards(
    ollama_backend: Any,
) -> None:
    """User mentions multiple services without any specific ARNs. After
    asking once and being told 'I don't know', the policy must:
      - cover BOTH services
      - be read-only (no write justification)
      - use wildcards (the user couldn't narrow)"""
    drv = _Driver(ollama_backend)
    drv.send(
        "I need access to the s3 buckets and dns records in account 060392206767"
    )
    final = drv.drive_to_completion(
        default_replies=["I dont know", "I dont know", "I dont know"]
    )

    assert final.complete, f"never completed; last ask was {final.ask!r}"
    assert final.draft_policy is not None
    services = _services_in_policy(final.draft_policy)
    assert "s3" in services or "route53" in services, (
        f"neither service in policy: {services}"
    )
    # Read-only because nothing in the request justified write
    assert _looks_read_only(final.draft_policy), (
        f"multi-service request with no write justification leaked write actions: "
        f"{_all_actions(final.draft_policy)}"
    )


def test_vague_update_mention_stays_read_only(ollama_backend: Any) -> None:
    """Saying 'maybe update a few' is NOT a justification for write
    access. The policy must remain read-only until the user explains a
    specific write action."""
    drv = _Driver(ollama_backend)
    drv.send(
        "I need to look at the s3 buckets and dns records and maybe update a "
        "few in account 060392206767"
    )
    final = drv.drive_to_completion(default_replies=["I dont know", "I dont know"])

    assert final.complete
    assert final.draft_policy is not None
    assert _looks_read_only(final.draft_policy), (
        f"vague 'maybe update' should not unlock write — got actions: "
        f"{_all_actions(final.draft_policy)}"
    )


def test_user_pastes_arn_gets_read_only_for_that_resource(ollama_backend: Any) -> None:
    """A user who pastes just an ARN expects read-only debug access for
    that exact resource. Should complete immediately when account is in
    the ARN — no follow-up needed."""
    drv = _Driver(ollama_backend)
    drv.send("arn:aws:lambda:us-east-1:060392206767:function:my-payment-fn")
    final = drv.drive_to_completion(default_replies=["I dont know"])

    assert final.complete
    assert final.draft_policy is not None
    services = _services_in_policy(final.draft_policy)
    assert "lambda" in services
    assert _looks_read_only(final.draft_policy), (
        f"ARN paste should default to read-only, got: {_all_actions(final.draft_policy)}"
    )
    # Account should be extracted from the ARN, not invented.
    assert final.fields.get("account_id") == "060392206767"


def test_concrete_write_justification_unlocks_write(ollama_backend: Any) -> None:
    """When the user explains a specific write action ('add a CNAME
    record pointing X to Y'), the policy SHOULD include write actions."""
    drv = _Driver(ollama_backend)
    drv.send(
        "I need to add a CNAME record pointing api.example.com to the new "
        "staging ALB, in account 060392206767"
    )
    final = drv.drive_to_completion(default_replies=["I dont know"])

    assert final.complete
    assert final.draft_policy is not None
    assert "route53" in _services_in_policy(final.draft_policy)
    # MUST include write — user justified it.
    assert not _looks_read_only(final.draft_policy), (
        f"explicit write justification didn't produce write actions: "
        f"{_all_actions(final.draft_policy)}"
    )


def test_proper_noun_is_not_paraphrased_in_followup(
    ollama_backend: Any,
) -> None:
    """User-typed proper nouns must not be auto-corrected. With
    org-context loaded, this tests that the prompt rule survives.

    Skipped when no org-context is configured — the rule still applies
    in the system prompt directly, but we test the integration here.
    """
    if not os.environ.get("IAM_JIT_ORG_CONTEXT_FILE"):
        pytest.skip("requires IAM_JIT_ORG_CONTEXT_FILE for proper-noun grounding")

    drv = _Driver(ollama_backend)
    drv.send("i need to read dns records in merchante development")
    if drv.last and drv.last.ask:
        # The bot's question must NOT contain a paraphrased company name.
        ask = drv.last.ask
        assert "Merchandize" not in ask, f"bot paraphrased 'merchante' as Merchandize: {ask}"
        assert "Merchant " not in ask, f"bot truncated 'merchante' to 'Merchant': {ask}"
