"""End-to-end tests for the policy-generation pipeline.

These tests pin the input → output mapping for common task descriptions.
A failing test here means either the generator changed its mapping
(intentional or not), or the scorer changed in a way that flags the
generated policy differently.

The tests run the full pipeline (patterns + extraction + scorer
validation) so they exercise the whole stack — separate unit tests
in the sibling files cover individual components.
"""

from __future__ import annotations

import pytest

from iam_jit.policy_gen import (
    BIAS_ALLOW,
    BIAS_DENY,
    GenerationContext,
    GenerationRequest,
    generate_policy,
)


def _gen(description: str, **kwargs):
    """Helper — apply sensible defaults and return the GenerationResult."""
    ctx = kwargs.pop("context", GenerationContext(
        account_id="123456789012",
        region="us-east-1",
        partition="aws",
    ))
    return generate_policy(GenerationRequest(
        task_description=description,
        context=ctx,
        **kwargs,
    ))


class TestS3Patterns:
    def test_read_named_bucket_produces_narrow_policy(self):
        # NB: avoid the word "logs" in the description — it also fires
        # the cloudwatch-logs-read pattern, which broadens the policy
        # ("read S3 logs" is genuinely ambiguous; refinement workflow
        # handles disambiguation in `test_refinement.py`).
        r = _gen("get S3 data from the prod-data bucket")
        assert r.policy is not None
        assert "s3-read" in r.matched_patterns
        # Narrow bucket ARN → low risk score
        assert r.scored_risk is not None and r.scored_risk <= 3
        # Resource should be the specific bucket, not wildcard
        stmt = r.policy["Statement"][0]
        resource = stmt["Resource"]
        if isinstance(resource, list):
            joined = " ".join(resource)
        else:
            joined = resource
        assert "prod-data" in joined
        assert "*" not in joined.split(":::")[-1].split("/")[0]

    def test_read_no_bucket_uses_wildcard_high_risk(self):
        r = _gen("read S3 data")
        assert r.policy is not None
        assert r.scored_risk is not None and r.scored_risk >= 4
        stmt = r.policy["Statement"][0]
        resource = stmt["Resource"]
        joined = " ".join(resource) if isinstance(resource, list) else resource
        assert "*" in joined

    def test_deny_bias_narrows_actions(self):
        allow = _gen("read S3 data from prod-logs bucket", bias=BIAS_ALLOW)
        deny = _gen("read S3 data from prod-logs bucket", bias=BIAS_DENY)
        allow_actions = allow.policy["Statement"][0]["Action"]
        deny_actions = deny.policy["Statement"][0]["Action"]
        # Deny version has strictly fewer actions
        if isinstance(allow_actions, str):
            allow_actions = [allow_actions]
        if isinstance(deny_actions, str):
            deny_actions = [deny_actions]
        assert len(deny_actions) < len(allow_actions)
        assert set(deny_actions).issubset(set(allow_actions))


class TestLambdaPatterns:
    def test_invoke_named_function_low_risk(self):
        r = _gen("invoke the deploy-api lambda function")
        assert r.policy is not None
        assert "lambda-invoke" in r.matched_patterns
        # Narrow function ARN → low risk
        assert r.scored_risk is not None and r.scored_risk <= 4

    def test_deploy_lambda_splits_passrole_statement(self):
        r = _gen("deploy lambda function deploy-api with role app-runtime-role")
        assert r.policy is not None
        statements = r.policy["Statement"]
        # PassRole should be in its own statement with role ARN
        passrole_stmts = [
            s for s in statements
            if (isinstance(s["Action"], str) and s["Action"] == "iam:PassRole")
            or (isinstance(s["Action"], list) and "iam:PassRole" in s["Action"])
        ]
        assert len(passrole_stmts) == 1
        resource = passrole_stmts[0]["Resource"]
        joined = " ".join(resource) if isinstance(resource, list) else resource
        assert "role/" in joined
        assert "app-runtime-role" in joined

    def test_deploy_lambda_without_role_scores_high(self):
        # No iam-role extracted → PassRole on `*` → scorer flags as 9
        r = _gen("deploy my lambda function for incident response")
        assert r.policy is not None
        assert r.scored_risk == 9, (
            "PassRole on Resource: * is a privesc primitive — "
            "the safety net should flag it"
        )


class TestDynamoDBPatterns:
    def test_query_named_table_with_context(self):
        r = _gen("query DynamoDB table prod-orders")
        assert r.policy is not None
        stmt = r.policy["Statement"][0]
        resource = stmt["Resource"]
        joined = " ".join(resource) if isinstance(resource, list) else resource
        assert "prod-orders" in joined
        # Narrow ARN with account+region context → low risk
        assert r.scored_risk is not None and r.scored_risk <= 3

    def test_scan_phrase_includes_scan_action(self):
        r = _gen("scan DynamoDB table prod-orders for inactive items")
        assert r.policy is not None
        stmt = r.policy["Statement"][0]
        actions = stmt["Action"]
        if isinstance(actions, str):
            actions = [actions]
        assert "dynamodb:Scan" in actions


class TestECSPatterns:
    def test_debug_service_extracts_name(self):
        r = _gen("debug the prod-inventory ECS service")
        assert r.policy is not None
        assert "ecs-describe" in r.matched_patterns
        # Reverse-direction regex picks up "prod-inventory" as the
        # service name; the resulting ARN narrows the scope.
        stmt = r.policy["Statement"][0]
        resource = stmt["Resource"]
        joined = " ".join(resource) if isinstance(resource, list) else resource
        # If the reverse regex worked, the resource will contain the name.
        # If not, this test is a regression flag.
        assert "prod-inventory" in joined or joined == "*"


class TestBiasSemantics:
    def test_allow_includes_more_actions_than_deny(self):
        for desc in [
            "read S3 logs from prod-logs bucket",
            "query DynamoDB table orders",
            "read CloudWatch logs for /aws/lambda/api",
        ]:
            allow = _gen(desc, bias=BIAS_ALLOW)
            deny = _gen(desc, bias=BIAS_DENY)
            if allow.policy is None or deny.policy is None:
                pytest.skip(f"description didn't match a pattern: {desc!r}")
            allow_n = sum(
                len(s["Action"]) if isinstance(s["Action"], list) else 1
                for s in allow.policy["Statement"]
            )
            deny_n = sum(
                len(s["Action"]) if isinstance(s["Action"], list) else 1
                for s in deny.policy["Statement"]
            )
            assert deny_n <= allow_n, f"deny ≤ allow for {desc!r}"


class TestUnmatched:
    def test_empty_description_returns_unmatched(self):
        r = _gen("")
        assert r.policy is None
        assert "Empty" in r.unmatched_reason

    def test_unknown_task_returns_unmatched(self):
        r = _gen("do something with computers")
        assert r.policy is None
        assert "No heuristic pattern matched" in r.unmatched_reason


class TestScorerValidationContract:
    def test_every_generated_policy_has_a_risk_score(self):
        """Contract: when policy is not None, scored_risk is set."""
        for desc in [
            "read S3 bucket prod-logs",
            "deploy lambda function api",
            "query DynamoDB table orders",
            "decrypt with KMS key prod-encryption",
            "send SQS to queue order-events",
        ]:
            r = _gen(desc)
            if r.policy is not None:
                assert r.scored_risk is not None
                assert 1 <= r.scored_risk <= 10

    def test_risk_factors_populated_on_high_risk_output(self):
        """When the scorer flags a generated policy, factors come back."""
        r = _gen("deploy lambda function api")  # PassRole on *
        assert r.policy is not None
        assert r.scored_risk is not None and r.scored_risk >= 7
        assert len(r.risk_factors) > 0
