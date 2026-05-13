"""Structural tests for the CloudFormation / SAM templates.

Goals:
  - Catch typos before `aws cloudformation deploy` does.
  - Pin the security-relevant Rules/Parameters/Conditions so they
    can't be silently dropped during refactoring.
  - Document the expected shape of the destination-account roles
    (least-privilege, tag-scoped, name-scoped).

These tests do NOT call AWS. They parse the YAML with a custom loader
that ignores CFN intrinsic tags (`!Ref`, `!Sub`, `!Equals`, etc.) and
walk the resulting Python dict. For a deeper structural check the
operator can additionally run `cfn-lint` locally — these tests are
the always-on minimum.
"""

from __future__ import annotations

import pathlib
from typing import Any

import pytest
import yaml


_REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
_SAM_TEMPLATE = _REPO_ROOT / "infrastructure" / "sam" / "template.yaml"
_DESTINATION_TEMPLATE = (
    _REPO_ROOT / "infrastructure" / "cloudformation"
    / "destination-account-roles.yaml"
)


def _load_cfn(path: pathlib.Path) -> dict[str, Any]:
    """Parse a CFN/SAM template YAML, ignoring intrinsic tags so the
    structural shape is inspectable as plain Python dicts."""
    class _CFNLoader(yaml.SafeLoader):
        pass

    def _ignore(loader: yaml.Loader, tag_suffix: str, node: Any) -> Any:
        if isinstance(node, yaml.ScalarNode):
            return loader.construct_scalar(node)
        if isinstance(node, yaml.SequenceNode):
            return loader.construct_sequence(node)
        if isinstance(node, yaml.MappingNode):
            return loader.construct_mapping(node)
        return None

    _CFNLoader.add_multi_constructor("!", _ignore)
    with path.open() as f:
        return yaml.load(f, Loader=_CFNLoader)  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# SAM hub template
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def sam_template() -> dict[str, Any]:
    return _load_cfn(_SAM_TEMPLATE)


def test_sam_template_has_serverless_transform(sam_template: dict[str, Any]) -> None:
    assert sam_template["Transform"] == "AWS::Serverless-2016-10-31"


def test_sam_template_declares_required_parameters(
    sam_template: dict[str, Any],
) -> None:
    """Every parameter we wire into env vars or Rules must exist by
    name. Catches a refactor that removes a parameter without updating
    its consumers."""
    params = sam_template.get("Parameters") or {}
    required = {
        "StateBucketName",
        "ProvisionerRoleArns",
        "DiscoveryRoleArns",
        "LLMBackend",
        "AuthMode",
        "UserConfigSource",
        "MagicLinkSecret",
        "AdminBootstrapEmail",
        "AllowPublicNetworkExposure",
        "CorsAllowedOrigins",
        "AllowedSourceCidrs",
        "TokenInactivityDays",
    }
    missing = required - set(params.keys())
    assert not missing, f"missing SAM parameters: {missing}"


def test_sam_rules_block_security_critical_combinations(
    sam_template: dict[str, Any],
) -> None:
    """The CFN Rules section is the only deploy-time guardrail. Each
    of these foot-guns MUST be blocked."""
    rules = sam_template.get("Rules") or {}
    assert "RefuseWildcardCorsOrigin" in rules, (
        "wildcard CORS origin rule was removed — public deploys can "
        "now ship with `*` allowed"
    )
    assert "RequireSourceCidrsForPublicExposure" in rules, (
        "AllowPublicNetworkExposure=true without AllowedSourceCidrs "
        "must be refused at deploy time"
    )
    assert "RequireAdminBootstrapForDynamoDBUsers" in rules, (
        "DynamoDB user store deploys must require AdminBootstrapEmail "
        "or the system is unreachable post-deploy"
    )
    assert "RequireAlbIngressCidrWhenPublicALB" in rules, (
        "EnablePublicALB=true with empty AlbIngressCidr must be "
        "refused at deploy time — otherwise the agent ships an "
        "open-to-internet ALB on accident. The decision must be "
        "explicit (workstation IP, VPN egress, or 0.0.0.0/0 with "
        "deliberate operator acknowledgment), not a default."
    )


def test_sam_token_inactivity_default_is_180_days(
    sam_template: dict[str, Any],
) -> None:
    """Pin the default to 180 days. If product wants to change it,
    they have to update this test too — visible decision."""
    p = sam_template["Parameters"]["TokenInactivityDays"]
    assert p["Default"] == 180
    assert p["MinValue"] == 1
    assert p["MaxValue"] == 3650


def test_sam_default_user_store_is_dynamodb(sam_template: dict[str, Any]) -> None:
    p = sam_template["Parameters"]["UserConfigSource"]
    assert p["Default"] == "dynamodb"
    assert set(p["AllowedValues"]) == {"dynamodb", "file"}


def test_sam_public_exposure_default_is_false(sam_template: dict[str, Any]) -> None:
    """The opt-in-public-exposure default is the conservative one."""
    p = sam_template["Parameters"]["AllowPublicNetworkExposure"]
    assert p["Default"] == "false"


def test_sam_lambda_env_includes_bootstrap_and_acl_vars(
    sam_template: dict[str, Any],
) -> None:
    """The runtime needs these env vars to honor the bootstrap +
    network-ACL flags. A regression where SAM passes the parameters
    but doesn't expose them to the Lambda is silent at deploy time."""
    env = (
        sam_template["Globals"]["Function"]["Environment"]["Variables"]
    )
    assert "IAM_JIT_ADMIN_BOOTSTRAP_EMAIL" in env
    assert "IAM_JIT_ALLOWED_SOURCE_CIDRS" in env
    assert "IAM_JIT_TOKEN_INACTIVITY_DAYS" in env
    assert "IAM_JIT_PUBLIC_EXPOSURE_OPT_IN" in env


def test_sam_state_bucket_blocks_public(sam_template: dict[str, Any]) -> None:
    """The state bucket holds request YAML, audit logs, etc. — must
    never be public."""
    bucket = sam_template["Resources"]["StateBucket"]["Properties"]
    pab = bucket["PublicAccessBlockConfiguration"]
    assert pab["BlockPublicAcls"] is True
    assert pab["BlockPublicPolicy"] is True
    assert pab["IgnorePublicAcls"] is True
    assert pab["RestrictPublicBuckets"] is True
    # Encryption.
    enc = bucket["BucketEncryption"]
    assert enc["ServerSideEncryptionConfiguration"][0][
        "ServerSideEncryptionByDefault"
    ]["SSEAlgorithm"] == "AES256"


def test_sam_rules_block_uses_only_cfn_supported_intrinsics() -> None:
    """Regression for a real post-deploy bug: CFN's Rules section
    accepts a strict subset of intrinsics, narrower than what cfn-lint
    checks against. Using e.g. `Fn::Join` inside an Assertion produces
    a template-parse error at `aws cloudformation create-changeset`
    time, AFTER buckets/secrets are already provisioned in earlier
    stages of the deploy. The error message ("Following functions are
    not supported in the Rules block ...") is non-obvious and the
    fix (rewriting to Fn::EachMemberEquals etc.) is invisible to local
    validation.

    Per the CFN docs, the Rules section supports ONLY:
      Ref, Fn::And, Fn::Contains, Fn::EachMemberEquals,
      Fn::EachMemberIn, Fn::Equals, Fn::If, Fn::Not, Fn::Or,
      Fn::RefAll, Fn::ValueOf, Fn::ValueOfAll.

    We slice out the Rules block as raw text and scan for any `!<Tag>`
    shorthand that isn't on the allowlist. Catching this here means
    the deploy never gets far enough to roll back."""
    text = _SAM_TEMPLATE.read_text()
    # Find the Rules: block. It ends at the next top-level key (column
    # 0). Naive but the template is small.
    import re
    rules_match = re.search(r"(?m)^Rules:\n(.*?)(?=\n^[A-Za-z]\S*:|\Z)", text, re.DOTALL)
    assert rules_match, "template has no Rules: block"
    rules_text = rules_match.group(1)

    allowed_tags = {
        "Ref",
        "And", "Contains", "EachMemberEquals", "EachMemberIn",
        "Equals", "If", "Not", "Or", "RefAll", "ValueOf", "ValueOfAll",
    }
    # Match `!Tag` short-form intrinsics. Strip the leading `!` and the
    # trailing whitespace/brackets.
    used_tags = set(re.findall(r"!([A-Za-z]\w*)", rules_text))
    forbidden = used_tags - allowed_tags
    assert not forbidden, (
        f"CFN Rules block uses intrinsics that the Rules processor "
        f"will reject at deploy time: {sorted(forbidden)}. "
        f"Allowed set: {sorted(allowed_tags)}. "
        f"This is a deploy-blocker that cfn-lint does NOT catch."
    )


def test_lambda_resource_paths_resolve_in_isolated_layout() -> None:
    """Regression for a real post-deploy bug: schema.py / users_store.py
    / accounts_store.py / onboarding.py all computed
    `Path(__file__).resolve().parents[2]` to find data files at repo
    root. That works in the source tree (parents[2] = repo root) but
    NOT in the Lambda bundle (parents[2] = `/var`, the schemas live at
    `/var/task/schemas/`). The result was a FileNotFoundError on
    every /api/v1/requests POST, /api/v1/users PUT, and /api/v1/accounts/onboarding/preview.

    Two-part fix:
      (a) modules use `_resources.find(*parts)` which walks several
          candidate ancestors;
      (b) `scripts/sync-lambda-data.sh` copies the data files into
          the package dir so the Lambda bundle has them.

    This test exercises (a) and (b) together: walk the directory the
    helper falls back to in Lambda and assert every required file is
    present. If the sync script is skipped or the resolver regresses,
    the assertion fires locally.
    """
    pkg_root = (
        pathlib.Path(__file__).resolve().parents[1] / "src" / "iam_jit"
    )
    required_files = [
        pkg_root / "schemas" / "request.schema.json",
        pkg_root / "schemas" / "users.schema.json",
        pkg_root / "schemas" / "accounts.schema.json",
        pkg_root / "infrastructure" / "cloudformation"
            / "destination-account-roles.yaml",
    ]
    missing = [str(p) for p in required_files if not p.exists()]
    assert not missing, (
        f"Lambda-bundle data files missing under {pkg_root}: {missing}. "
        "Run `scripts/sync-lambda-data.sh` (or `make sam-build`) before "
        "deploying — a fresh clone or a refactor of the data layout "
        "needs the sync to repopulate these paths."
    )


def test_lambda_resource_paths_resolve_via_helper() -> None:
    """The `_resources.find()` helper is the runtime safety net. Each
    of its named data files MUST be findable when only the
    package-local layout exists — that's the path-resolution mode the
    Lambda runs in. Simulates the production layout by forcing the
    helper to use only `parent` candidates."""
    from iam_jit import _resources

    # If we can find each of these via the helper, the production
    # behavior is locked in. (We can't easily simulate parents[2]
    # being absent without a chroot; this test relies on the
    # sync-lambda-data.sh step having populated the package-local
    # layout, which the previous test asserts.)
    paths = [
        _resources.find("schemas", "request.schema.json"),
        _resources.find("schemas", "users.schema.json"),
        _resources.find("schemas", "accounts.schema.json"),
        _resources.find(
            "infrastructure", "cloudformation",
            "destination-account-roles.yaml",
        ),
    ]
    for p in paths:
        assert p.exists(), f"_resources.find returned non-existent path {p}"


def test_sam_function_url_has_invoke_permission(
    sam_template: dict[str, Any],
) -> None:
    """Regression for a real post-deploy bug: declaring a
    FunctionUrlConfig on AWS::Serverless::Function does NOT auto-add
    the resource-based policy that lets the public URL endpoint route
    to the function. Without an AWS::Lambda::Permission with
    Action=lambda:InvokeFunctionUrl and Principal=*, every request to
    the Function URL returns AWS-layer 403 (AccessDeniedException) —
    even with AuthType: NONE.

    The fix is template-side (declare the permission explicitly), and
    this test pins it so a refactor that deletes the permission
    resource fails locally before the deploy ever happens."""
    resources = sam_template["Resources"]
    url_functions = [
        (name, props["Properties"])
        for name, props in resources.items()
        if props.get("Type") == "AWS::Serverless::Function"
        and "FunctionUrlConfig" in (props.get("Properties") or {})
    ]
    assert url_functions, (
        "template has no AWS::Serverless::Function with FunctionUrlConfig "
        "— the test premise no longer applies; either remove this test "
        "or update it to whatever shape replaced Function URLs."
    )

    # Build the set of Lambda::Permission resources keyed by which
    # function they target.
    permissions = [
        props["Properties"]
        for name, props in resources.items()
        if props.get("Type") == "AWS::Lambda::Permission"
    ]
    invoke_url_permissions = [
        p for p in permissions
        if p.get("Action") == "lambda:InvokeFunctionUrl"
        and p.get("Principal") == "*"
    ]
    assert invoke_url_permissions, (
        "FunctionUrlConfig is declared but no AWS::Lambda::Permission "
        "grants lambda:InvokeFunctionUrl to Principal=* — the URL will "
        "return 403 from the AWS layer for every caller."
    )


def test_sam_alb_resources_declared_under_condition(
    sam_template: dict[str, Any],
) -> None:
    """The public-ALB deployment shape provisions five resources, all
    guarded by the `UsePublicALB` condition so the default deploy
    doesn't create them (and isn't billed for an ALB it doesn't need).

    Resources verified:
      - AWS::EC2::SecurityGroup            (ingress on 80/443)
      - AWS::ElasticLoadBalancingV2::LoadBalancer (the ALB)
      - AWS::ElasticLoadBalancingV2::TargetGroup  (Lambda target)
      - AWS::Lambda::Permission           (ELB principal)
      - AWS::ElasticLoadBalancingV2::Listener (HTTP listener)
    The HTTPS listener is additionally gated on `AlbHasCertificate`
    so HTTPS is opt-in via the AlbCertificateArn parameter."""
    resources = sam_template["Resources"]

    sg = resources.get("IAMJitAlbSecurityGroup")
    assert sg is not None, "missing ALB security group"
    assert sg["Type"] == "AWS::EC2::SecurityGroup"
    assert sg.get("Condition") == "UsePublicALB"
    ingress = sg["Properties"]["SecurityGroupIngress"]
    ports = {i["FromPort"] for i in ingress}
    assert {80, 443}.issubset(ports), (
        "ALB SG must permit inbound 80 and 443 so HTTP and HTTPS "
        "listeners both work"
    )

    alb = resources.get("IAMJitAlb")
    assert alb is not None and alb["Type"] == "AWS::ElasticLoadBalancingV2::LoadBalancer"
    assert alb.get("Condition") == "UsePublicALB"
    assert alb["Properties"]["Type"] == "application"
    assert alb["Properties"]["Scheme"] == "internet-facing"

    tg = resources.get("IAMJitAlbTargetGroup")
    assert tg is not None and tg["Type"] == "AWS::ElasticLoadBalancingV2::TargetGroup"
    assert tg.get("Condition") == "UsePublicALB"
    assert tg["Properties"]["TargetType"] == "lambda", (
        "Target type MUST be `lambda` — `instance` or `ip` would "
        "require EC2 backends iam-jit doesn't have"
    )

    perm = resources.get("IAMJitAlbInvokePermission")
    assert perm is not None and perm["Type"] == "AWS::Lambda::Permission"
    assert perm.get("Condition") == "UsePublicALB"
    assert perm["Properties"]["Action"] == "lambda:InvokeFunction", (
        "MUST be `lambda:InvokeFunction` — `InvokeFunctionUrl` "
        "would re-trigger the SCP this whole ALB path exists to avoid"
    )
    assert perm["Properties"]["Principal"] == "elasticloadbalancing.amazonaws.com"

    listener = resources.get("IAMJitAlbListenerHttp")
    assert listener is not None and listener["Type"] == "AWS::ElasticLoadBalancingV2::Listener"
    assert listener.get("Condition") == "UsePublicALB"
    assert listener["Properties"]["Port"] == 80
    assert listener["Properties"]["Protocol"] == "HTTP"

    https_listener = resources.get("IAMJitAlbListenerHttps")
    assert https_listener is not None
    assert https_listener.get("Condition") == "AlbHasCertificate", (
        "HTTPS listener must be opt-in via AlbCertificateArn — "
        "without it we'd fail to deploy when no cert is provided"
    )


def test_sam_alb_security_group_ingress_is_parameterized(
    sam_template: dict[str, Any],
) -> None:
    """Regression for the deploy-time bug "ALB SG was 0.0.0.0/0 by
    default; first-time deployers couldn't lock the surface without
    manual console work." The SG ingress MUST be sourced from the
    `AlbIngressCidr` parameter, not a hardcoded string — otherwise
    deployers have to either accept open-to-internet or post-deploy
    `authorize-security-group-ingress` (which gets reverted on the
    next `sam deploy`).
    """
    sg = sam_template["Resources"]["IAMJitAlbSecurityGroup"]
    ingress = sg["Properties"]["SecurityGroupIngress"]
    for rule in ingress:
        cidr = rule.get("CidrIp")
        # `_load_cfn` strips intrinsic tags but keeps the resolved
        # value. !Ref AlbIngressCidr becomes "AlbIngressCidr" (the
        # parameter name as a string) under that loader.
        assert cidr == "AlbIngressCidr", (
            f"ALB SG ingress port {rule.get('FromPort')} hardcodes "
            f"CidrIp={cidr!r} instead of !Ref AlbIngressCidr. "
            "Restore the parameter reference; deployers need a way "
            "to tighten the network surface without console ops."
        )


def test_sam_alb_target_group_circular_dependency_avoided(
    sam_template: dict[str, Any],
) -> None:
    """A Lambda-targeted target group requires the Lambda permission
    to exist first; CFN doesn't infer this from the Targets list, so
    we declare it via DependsOn. Regression: omitting the DependsOn
    fails the deploy with `The IAM authorization header is not valid
    for the ARN`, which is non-obvious to debug."""
    tg = sam_template["Resources"]["IAMJitAlbTargetGroup"]
    depends_on = tg.get("DependsOn")
    if isinstance(depends_on, str):
        depends_on = [depends_on]
    assert depends_on and "IAMJitAlbInvokePermission" in depends_on, (
        "TargetGroup must DependsOn the Lambda::Permission resource; "
        "without it CFN tries to register the Lambda target before "
        "ELB has permission to invoke and the deploy fails."
    )


def test_sam_public_base_url_output_swaps_to_alb(
    sam_template: dict[str, Any],
) -> None:
    """`PublicBaseUrl` and `BootstrapClaimUrl` outputs must
    conditionally point at the ALB DNS name when EnablePublicALB
    is true — otherwise operators get a Function URL that's
    unreachable when the SCP blocks public Function URLs."""
    outputs = sam_template["Outputs"]
    assert "PublicBaseUrl" in outputs
    assert "BootstrapClaimUrl" in outputs
    import json
    for output_name in ("PublicBaseUrl", "BootstrapClaimUrl"):
        val_repr = json.dumps(outputs[output_name]["Value"])
        assert "UsePublicALB" in val_repr or "IAMJitAlb" in val_repr, (
            f"{output_name} output doesn't branch on EnablePublicALB — "
            f"it will always emit the Function URL, which is "
            f"unreachable in accounts with the public Function-URL SCP"
        )


def test_bootstrap_claim_url_ends_in_setup_without_double_slash() -> None:
    """Regression for a fresh-deploy ergonomics issue: the
    BootstrapClaimUrl output is constructed differently per surface —

      - Function URL:  !Sub "${IAMJitFunctionUrl.FunctionUrl}setup"
                       (FunctionUrl always ends in `/`, so this
                       resolves to `https://...lambda-url.../setup`)
      - ALB HTTP:      !Sub "http://${IAMJitAlb.DNSName}/setup"
      - ALB HTTPS:     !Sub "https://${IAMJitAlb.DNSName}/setup"

    A misplaced slash in any of these would either 404 the bootstrap
    flow or send the operator to `/setup/` (which FastAPI doesn't
    serve). We can't actually resolve the !Sub at lint time, but we
    can pin the SHAPE — every leaf string in the BootstrapClaimUrl
    !If expression must end in `setup` with no `//` before it.
    """
    import re

    raw = _SAM_TEMPLATE.read_text()
    # Pull the BootstrapClaimUrl Value block. Match the indentation
    # so we get the entire !If tree until the next Output key.
    m = re.search(
        r"^  BootstrapClaimUrl:\n(?:    .+\n)+",
        raw, re.MULTILINE,
    )
    assert m, "BootstrapClaimUrl output not found"
    block = m.group(0)

    # Every literal URL fragment in this block must terminate `/setup`
    # — not `//setup`, not `/setup/`, not `setup/`.
    # Function URL form: `${IAMJitFunctionUrl.FunctionUrl}setup` is
    # legitimate because FunctionUrl values from CFN end in `/`.
    # ALB form: explicit `/setup`.
    setup_terminators = re.findall(r"\"[^\"]*setup\"", block)
    assert setup_terminators, (
        "no `setup`-ending URL literal found — did the output get "
        "renamed or restructured?"
    )
    for term in setup_terminators:
        # Strip surrounding quotes
        url = term.strip("\"")
        assert url.endswith("setup"), f"URL doesn't end in `setup`: {url!r}"
        assert "//setup" not in url, (
            f"URL has `//setup` (double slash before setup), which "
            f"will 404: {url!r}"
        )
        assert not url.endswith("setup/"), (
            f"URL ends in `setup/` (trailing slash), which FastAPI "
            f"doesn't serve: {url!r}"
        )


def test_sam_template_no_cloudfront_residue(sam_template: dict[str, Any]) -> None:
    """The CloudFront path was the prior attempt at solving the SCP
    block — it doesn't bypass the Omise org SCP because the SCP
    denies `lambda:InvokeFunctionUrl` broadly, not just
    `FunctionUrlAuthType=NONE`. The ALB path uses `InvokeFunction`
    instead. After removing CloudFront support, no residual CF
    resources / conditions / parameters should remain or future
    deploys will fail at `aws cloudformation create-changeset` time
    with an unresolved-reference error."""
    import json
    payload = json.dumps(sam_template)
    forbidden = [
        "AWS::CloudFront",
        "EnableCloudFront",
        "UseCloudFront",
        "CloudFrontPriceClass",
        "IAMJitDistribution",
        "IAMJitOAC",
        "OriginAccessControl",
    ]
    leaked = [needle for needle in forbidden if needle in payload]
    assert not leaked, (
        f"CloudFront residue in template: {leaked}. The ALB swap "
        "intentionally removes all CF resources; leftover references "
        "will fail to parse."
    )


def test_sam_dynamodb_tables_have_pitr_enabled(
    sam_template: dict[str, Any],
) -> None:
    """Regression for an operational-invariant turned into a template
    invariant: every iam-jit DDB table MUST have Point-in-Time
    Recovery enabled. Without PITR, an accidental write/delete is
    unrecoverable. The old SecurityChecklistReminder flagged this as
    a manual step; we now enforce it at the IaC layer."""
    tables = ["ApiTokensTable", "UsersTable", "RequestsTable", "CidrsTable"]
    for name in tables:
        t = sam_template["Resources"][name]["Properties"]
        pitr = t.get("PointInTimeRecoverySpecification") or {}
        assert pitr.get("PointInTimeRecoveryEnabled") is True, (
            f"{name} doesn't have PITR enabled. Accidental data "
            f"corruption / table-replace would be unrecoverable. "
            f"Restore the PointInTimeRecoverySpecification."
        )


def test_sam_data_resources_have_retain_policy(
    sam_template: dict[str, Any],
) -> None:
    """Persistence invariant: every data-bearing resource (DDB
    tables + state bucket) carries DeletionPolicy=Retain AND
    UpdateReplacePolicy=Retain so a `cloudformation delete-stack`
    or stack-replace doesn't take the data with it. A fresh
    `sam deploy` after a delete will adopt the existing resources.
    """
    data_resources = [
        "StateBucket",
        "ApiTokensTable",
        "UsersTable",
        "RequestsTable",
        "CidrsTable",
    ]
    resources = sam_template["Resources"]
    for name in data_resources:
        r = resources[name]
        assert r.get("DeletionPolicy") == "Retain", (
            f"{name} is missing DeletionPolicy=Retain. A stack delete "
            f"would destroy the data. Add `DeletionPolicy: Retain` to "
            f"the resource."
        )
        assert r.get("UpdateReplacePolicy") == "Retain", (
            f"{name} is missing UpdateReplacePolicy=Retain. A replace-"
            f"required update (e.g., renaming the table) would "
            f"destroy the data. Add `UpdateReplacePolicy: Retain`."
        )


def test_sam_cidrs_table_wired_to_lambda(
    sam_template: dict[str, Any],
) -> None:
    """The runtime CIDR allowlist must be persisted via DynamoDB
    (not in-memory) for production. Verify the env var routing the
    cidr_store to the CidrsTable is set on the Lambda."""
    env = (
        sam_template["Globals"]["Function"]["Environment"]["Variables"]
    )
    assert "IAM_JIT_CIDRS_TABLE" in env, (
        "Lambda env is missing IAM_JIT_CIDRS_TABLE — the runtime "
        "CIDR store will fall back to in-memory and lose admin-"
        "added entries on every cold-start."
    )


def test_sam_lambda_log_group_has_explicit_retention(
    sam_template: dict[str, Any],
) -> None:
    """Regression for the silent-bill-growth bug: AWS Lambda
    auto-creates `/aws/lambda/iam-jit` with retention=Never if the
    template doesn't declare the log group explicitly. The fix
    pairs an AWS::Logs::LogGroup with the function's LoggingConfig
    so retention is bounded and the log group is IaC-owned."""
    resources = sam_template["Resources"]

    log_group = resources.get("IAMJitLogGroup")
    assert log_group is not None, (
        "Lambda log group must be declared explicitly — Lambda's "
        "auto-created group has retention=Never and the bill grows "
        "linearly."
    )
    assert log_group["Type"] == "AWS::Logs::LogGroup"
    assert log_group["Properties"].get("RetentionInDays"), (
        "IAMJitLogGroup must have RetentionInDays set (parameterized "
        "via LogRetentionDays)."
    )
    assert log_group["Properties"].get("LogGroupName") == "/aws/lambda/iam-jit", (
        "LogGroupName must match the Lambda's auto-created name "
        "(/aws/lambda/<function-name>) for the explicit group to "
        "replace it."
    )

    # Function must reference the explicit group via LoggingConfig.
    function = resources["IAMJitFunction"]["Properties"]
    logging_config = function.get("LoggingConfig")
    assert logging_config, (
        "Function must declare LoggingConfig referencing the explicit "
        "log group; otherwise it auto-creates a separate retention-"
        "Never group and the explicit one stays empty."
    )


def test_sam_dynamodb_tables_use_pay_per_request(
    sam_template: dict[str, Any],
) -> None:
    """Pin billing mode — provisioned capacity would silently rack up
    bills on idle deployments."""
    tables = ["ApiTokensTable", "UsersTable", "RequestsTable"]
    for name in tables:
        t = sam_template["Resources"][name]["Properties"]
        assert t["BillingMode"] == "PAY_PER_REQUEST", name


# ---------------------------------------------------------------------------
# Destination-account template
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def destination_template() -> dict[str, Any]:
    return _load_cfn(_DESTINATION_TEMPLATE)


def test_destination_template_provisioner_role_exists(
    destination_template: dict[str, Any],
) -> None:
    res = destination_template["Resources"]
    assert "ProvisionerRole" in res
    assert res["ProvisionerRole"]["Type"] == "AWS::IAM::Role"


def test_destination_template_provisioner_external_id_required(
    destination_template: dict[str, Any],
) -> None:
    """Trust policy must require sts:ExternalId — defense against
    confused-deputy if the hub Lambda role is ever compromised."""
    role = destination_template["Resources"]["ProvisionerRole"]["Properties"]
    statements = role["AssumeRolePolicyDocument"]["Statement"]
    found = any(
        "sts:ExternalId" in (s.get("Condition") or {}).get("StringEquals", {})
        for s in statements
    )
    assert found, "ProvisionerRole trust policy is missing sts:ExternalId"


def test_destination_template_classic_iam_policy_is_path_scoped(
    destination_template: dict[str, Any],
) -> None:
    """iam:CreateRole / DeleteRole / etc. must be scoped to the
    `/iam-jit/*` path so the role can't touch unrelated IAM
    resources."""
    res = destination_template["Resources"]
    policy = res.get("ProvisionerClassicIAMPolicy") or {}
    statements = (
        policy.get("Properties", {})
        .get("PolicyDocument", {})
        .get("Statement", [])
    )
    iam_modify_actions = {
        "iam:CreateRole",
        "iam:PutRolePolicy",
        "iam:DeleteRole",
        "iam:DeleteRolePolicy",
        "iam:UpdateAssumeRolePolicy",
        "iam:GetRole",
        "iam:GetRolePolicy",
        "iam:ListRolePolicies",
        "iam:ListAttachedRolePolicies",
        "iam:ListRoleTags",
        "iam:TagRole",
    }
    for stmt in statements:
        actions = stmt.get("Action") or []
        if isinstance(actions, str):
            actions = [actions]
        # Only check statements that touch IAM mutation. The ReadIAMState
        # block uses Resource=* and that's intentional.
        if any(a in iam_modify_actions for a in actions) and stmt.get("Sid") != "ReadIAMState":
            resource = stmt.get("Resource")
            resource_str = resource if isinstance(resource, str) else str(resource)
            assert "/iam-jit/" in resource_str, (
                f"statement {stmt.get('Sid')} is not path-scoped to "
                f"/iam-jit/: resource={resource}"
            )


def test_destination_template_create_role_requires_managed_by_tag(
    destination_template: dict[str, Any],
) -> None:
    """At creation time, role must already carry managed-by=iam-jit."""
    res = destination_template["Resources"]
    statements = (
        res["ProvisionerClassicIAMPolicy"]["Properties"]
        ["PolicyDocument"]["Statement"]
    )
    create_stmt = next(
        s for s in statements if s.get("Sid") == "CreateOnlyTaggedRoles"
    )
    cond = create_stmt["Condition"]
    assert cond["StringEquals"]["aws:RequestTag/managed-by"] == "iam-jit"


def test_destination_template_modify_only_managed_by_tag(
    destination_template: dict[str, Any],
) -> None:
    """Modify operations require the role to already have the tag."""
    res = destination_template["Resources"]
    statements = (
        res["ProvisionerClassicIAMPolicy"]["Properties"]
        ["PolicyDocument"]["Statement"]
    )
    modify_stmt = next(
        s for s in statements if s.get("Sid") == "ModifyOnlyTaggedRoles"
    )
    cond = modify_stmt["Condition"]
    assert cond["StringEquals"]["aws:ResourceTag/managed-by"] == "iam-jit"


def test_destination_template_allowed_tag_keys_match_provision_module(
    destination_template: dict[str, Any],
) -> None:
    """The CFN ForAllValues:StringEquals on aws:TagKeys must include
    every key the provision module emits (otherwise create_role fails
    with `AccessDenied: tag key not allowed`)."""
    from iam_jit.provision import _build_tags

    expected_keys = set(
        _build_tags(
            request_id="rq-x",
            requester_email="dev@example.com",
            approver_id="email:approver@example.com",
            expires_at="2030-01-01T00:00:00Z",
            provisioned_at="2026-01-01T00:00:00Z",
            access_type="read-only",
        ).keys()
    )

    res = destination_template["Resources"]
    statements = (
        res["ProvisionerClassicIAMPolicy"]["Properties"]
        ["PolicyDocument"]["Statement"]
    )
    create_stmt = next(
        s for s in statements if s.get("Sid") == "CreateOnlyTaggedRoles"
    )
    cond = create_stmt["Condition"]
    allowed_keys = set(
        cond["ForAllValues:StringEquals"]["aws:TagKeys"]
    )

    missing = expected_keys - allowed_keys
    assert not missing, (
        f"provision._build_tags emits tag keys not allowed by the "
        f"destination ProvisionerRole policy: {sorted(missing)}. "
        f"Update the CFN template's ForAllValues list."
    )


def test_destination_template_outputs_provisioner_arn(
    destination_template: dict[str, Any],
) -> None:
    outs = destination_template["Outputs"]
    assert "ProvisionerRoleArn" in outs
    assert "ProvisionerExternalId" in outs


def test_destination_template_does_not_grant_iam_passrole(
    destination_template: dict[str, Any],
) -> None:
    """iam:PassRole would let the provisioner attach itself elsewhere
    — verify it's not anywhere in the policy."""
    import json as _json

    text = _json.dumps(destination_template["Resources"])
    assert "iam:PassRole" not in text, (
        "destination ProvisionerRole has iam:PassRole — that breaks the "
        "scoping invariant"
    )
