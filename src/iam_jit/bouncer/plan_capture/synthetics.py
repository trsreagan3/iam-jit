"""Synthetic AWS API response shapes for plan-capture mode.

When the proxy is running in plan-capture mode, every inbound
request is parsed + audited + RETURNED-WITH-SYNTHETIC-SUCCESS
rather than forwarded to AWS. This module curates the response
shapes for the operations a typical agent workflow touches.

Two response wire-formats:
  - JSON: modern services (DynamoDB, STS, IAM via query/JSON-aware
    parsers, Lambda, Bedrock, ...).
  - XML: classic services (S3, EC2, IAM query API) where the SDK
    expects a service-specific XML body.

For each registered (service, action) we produce:
  - HTTP status (always 200 for "would have succeeded")
  - Content-Type
  - Body bytes (rendered from a hand-curated template; resource
    names from the inbound request are echoed back where they
    matter for the agent's next call to make sense — e.g. an
    iam:CreateRole returns a synthetic RoleArn that includes the
    requested role name)

For operations we DON'T have a shape for we surface a clear
SDK-style error that names the unsupported operation + tells the
operator how to proceed (switch to cooperative if it's read-only,
or transparent if they want it gated-but-executed). The error
body is shaped so boto3 surfaces it as a typed exception rather
than a confused parse error.

Per [[creates-never-mutates]]: nothing in this module talks to
AWS, generates real ARNs, or touches credentials. Synthetic ARNs
use a sentinel account id (`000000000000` — invalid as a real
account per AWS docs) so any leak into downstream tooling is
obviously fake.

Per [[ibounce-honest-positioning]]: a sophisticated agent can
detect plan-capture via these shapes (the sentinel account id is
a tell, response latencies are sub-ms, etc.). That's an accepted
trade-off — plan-capture is for cooperative operator preview,
not adversarial defense.
"""

from __future__ import annotations

import dataclasses
import json
import re
import uuid
from typing import Any

# Sentinel account id used in every synthetic ARN. AWS reserves
# 000000000000 as non-allocatable, so a leak into downstream code
# (terraform state, audit pipeline, etc.) is obviously not a real
# resource. Per [[ibounce-honest-positioning]] making the synthesis
# detectable is a feature, not a bug.
PLAN_CAPTURE_ACCOUNT_ID = "000000000000"

# AWS request-id sentinel — `plan-capture` literal prefix so an
# operator grepping CloudTrail (or anywhere else) for one of these
# ids immediately knows it came from plan-capture mode and was
# never sent to AWS.
_REQUEST_ID_PREFIX = "plan-capture"


def _synthetic_request_id() -> str:
    """Generate a synthetic x-amz-request-id value. UUID4 hex tail
    so concurrent calls produce distinct ids."""
    return f"{_REQUEST_ID_PREFIX}-{uuid.uuid4().hex[:24]}"


@dataclasses.dataclass(frozen=True)
class PlanCaptureSynthetic:
    """One synthetic SDK-shaped response.

    `status`, `headers`, `body` are what the proxy returns on the
    wire. `would_have_returned` is a small structured summary
    persisted in the audit log so post-hoc review can show "this
    call would have returned <X>" without re-parsing the raw body.
    """

    status: int
    headers: dict[str, str]
    body: bytes
    would_have_returned: dict[str, Any]


# Operations that explicitly are NOT in the registry get this
# error shape back. SDKs surface 400 + an error JSON object as a
# typed client-error exception; an operator running their agent
# under plan-capture sees a clear "this op isn't synthesized" hint.
def _build_unsupported_response(
    *, service: str, action: str, host: str,
) -> PlanCaptureSynthetic:
    """The shape returned for any (service, action) not in the
    registry. Includes a `__plan_capture` flag so consumers
    (logs, test assertions) can distinguish unsupported from any
    real AWS 400."""
    payload = {
        "__plan_capture": True,
        "Error": {
            "Code": "PlanCaptureUnsupportedOperation",
            "Message": (
                f"ibounce plan-capture mode does not have a synthetic shape "
                f"for {service}:{action}. The call was NOT forwarded to AWS "
                f"(plan-capture never forwards). Switch to --mode cooperative "
                f"to forward + audit, or --mode transparent to forward + gate."
            ),
            "Service": service,
            "Action": action,
        },
        "RequestId": _synthetic_request_id(),
    }
    body = json.dumps(payload).encode("utf-8")
    return PlanCaptureSynthetic(
        status=400,
        headers={
            "content-type": "application/x-amz-json-1.1",
            "x-amzn-requestid": payload["RequestId"],
            "x-iam-jit-bouncer-plan-capture-unsupported": "true",
        },
        body=body,
        would_have_returned={
            "kind": "unsupported",
            "service": service,
            "action": action,
            "note": "plan-capture has no synthetic shape for this op",
        },
    )


# Sentinel returned from `synthesize_response` for the unsupported
# case so call-sites that want to gate behavior (e.g. "skip the
# audit `would_have_returned` payload if unsupported") have a
# single import to reference rather than parsing the dataclass.
UNSUPPORTED_OP_SHAPE = "unsupported"

# #145 — sentinel for the writes-rejected synthetic shape. The proxy
# calls `build_writes_rejected_response` when the session phase is
# `writes_rejected` (either via --write-switch-notify=reject, or via
# an operator's explicit reject on the plan-write prompt).
WRITES_REJECTED_SHAPE = "writes_rejected"


def build_writes_rejected_response(
    *, service: str, action: str,
) -> PlanCaptureSynthetic:
    """Return a synthetic SDK-shaped ERROR response for a write call
    in a session whose phase is `writes_rejected` (#145).

    Distinct from the unsupported-op response: this is NOT "we don't
    know how to fake it"; it's "the operator told us to reject any
    write in this session." Surfaces a typed error code
    `PlanCaptureWritesRejected` + a clear message so the agent's SDK
    raises a recognizable client error.

    Stays in the JSON-RPC error envelope (vs an XML-style error)
    because the SDK clients across the registered services all
    surface `Error.Code` from JSON bodies, while only a subset rely
    on XML; the JSON envelope is the broadest-compatible shape. The
    400 status code matches the `_build_unsupported_response`
    precedent so callers that already handle "plan-capture
    advisory error" see this through the same path.

    Per [[creates-never-mutates]]: this response is still a SYNTHETIC.
    Nothing reaches AWS regardless of the operator's decision.
    """
    payload = {
        "__plan_capture": True,
        "Error": {
            "Code": "PlanCaptureWritesRejected",
            "Message": (
                f"ibounce plan-capture: operator REJECTED write calls in "
                f"this session. {service}:{action} was NOT forwarded to "
                f"AWS (plan-capture never forwards). Re-run with "
                f"--write-switch-notify=manual + answer 'approve' on "
                f"the plan-write prompt to allow writes, or switch to "
                f"--mode transparent / cooperative if you want the call "
                f"to execute against AWS."
            ),
            "Service": service,
            "Action": action,
        },
        "RequestId": _synthetic_request_id(),
    }
    body = json.dumps(payload).encode("utf-8")
    return PlanCaptureSynthetic(
        status=400,
        headers={
            "content-type": "application/x-amz-json-1.1",
            "x-amzn-requestid": payload["RequestId"],
            "x-iam-jit-bouncer-plan-capture-writes-rejected": "true",
        },
        body=body,
        would_have_returned={
            "kind": WRITES_REJECTED_SHAPE,
            "service": service,
            "action": action,
            "note": (
                "plan-capture session is in writes_rejected phase; the "
                "operator's reject answer (or --write-switch-notify=reject) "
                "blocked this write at the proxy"
            ),
        },
    )


# ---------------------------------------------------------------------------
# Per-service synthesizers
#
# Each synthesizer receives (action, host, body, query) and returns a
# PlanCaptureSynthetic. They're tiny by design — the registry's job
# is COVERAGE + audit-friendliness, not full SDK fidelity. Where the
# SDK would otherwise crash because a response field is missing
# (e.g. CreateRole expects a Role object with an Arn), we hand-craft
# the minimum field set.
# ---------------------------------------------------------------------------


# Match `s3:GetObject` / `s3:PutObject` / etc. path-style + virtual-
# host-style. Used to echo the requested key back to the operator
# in the audit row.
_S3_OBJECT_KEY_RE = re.compile(r"^/(?:[^/]+/)?(?P<key>.+)$")


def _s3_synth(
    action: str, host: str, path: str, body: bytes, query: dict[str, Any],
) -> PlanCaptureSynthetic:
    """S3 covers: ListBuckets, ListObjects(V2), GetObject, PutObject,
    HeadObject, DeleteObject. XML wire format."""
    rid = _synthetic_request_id()
    headers = {
        "content-type": "application/xml",
        "x-amz-request-id": rid,
    }
    if action in ("ListBuckets", "ListAllMyBuckets"):
        body_xml = (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<ListAllMyBucketsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
            b"<Owner><ID>plan-capture-owner</ID>"
            b"<DisplayName>plan-capture</DisplayName></Owner>"
            b"<Buckets></Buckets>"
            b"</ListAllMyBucketsResult>"
        )
        return PlanCaptureSynthetic(
            status=200, headers=headers, body=body_xml,
            would_have_returned={"Buckets": [], "Owner": "plan-capture-owner"},
        )
    if action in ("ListObjects", "ListObjectsV2"):
        body_xml = (
            b'<?xml version="1.0" encoding="UTF-8"?>'
            b'<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">'
            b"<Name>plan-capture-bucket</Name><Prefix></Prefix>"
            b"<KeyCount>0</KeyCount><MaxKeys>0</MaxKeys>"
            b"<IsTruncated>false</IsTruncated>"
            b"</ListBucketResult>"
        )
        return PlanCaptureSynthetic(
            status=200, headers=headers, body=body_xml,
            would_have_returned={"Contents": [], "KeyCount": 0, "IsTruncated": False},
        )
    if action == "GetObject":
        # Return an empty body — the operator's audit row captures
        # the intent; the agent shouldn't be relying on the bytes
        # in plan-capture mode (and if it is, that's a signal to
        # the operator that the agent's flow has data-dependence
        # plan-capture can't satisfy honestly).
        empty_headers = dict(headers)
        empty_headers["content-type"] = "application/octet-stream"
        empty_headers["content-length"] = "0"
        return PlanCaptureSynthetic(
            status=200, headers=empty_headers, body=b"",
            would_have_returned={"Body": "<empty in plan-capture>"},
        )
    if action == "HeadObject":
        head_headers = dict(headers)
        head_headers["content-length"] = "0"
        head_headers["etag"] = '"plancapture00000000000000000000"'
        return PlanCaptureSynthetic(
            status=200, headers=head_headers, body=b"",
            would_have_returned={"ContentLength": 0, "ETag": "plancapture..."},
        )
    if action == "PutObject":
        put_headers = dict(headers)
        put_headers["etag"] = '"plancapture00000000000000000000"'
        return PlanCaptureSynthetic(
            status=200, headers=put_headers, body=b"",
            would_have_returned={"ETag": "plancapture..."},
        )
    if action == "DeleteObject":
        del_headers = dict(headers)
        del_headers["x-amz-delete-marker"] = "true"
        return PlanCaptureSynthetic(
            status=204, headers=del_headers, body=b"",
            would_have_returned={"DeleteMarker": True},
        )
    # Fall through to unsupported — every other S3 op (CopyObject,
    # multipart, bucket-policy edits, ...) needs explicit registry
    # coverage. The error tells the operator to switch modes if they
    # need it.
    return _build_unsupported_response(service="s3", action=action, host=host)


# Pull RoleName out of an iam:CreateRole body so the synthetic
# response's Arn includes the requested name (helps agents that
# chain CreateRole -> AttachRolePolicy by name).
_IAM_ROLE_NAME_RE = re.compile(
    r"RoleName=(?P<name>[^&]+)", re.IGNORECASE,
)


def _iam_synth(
    action: str, host: str, path: str, body: bytes, query: dict[str, Any],
) -> PlanCaptureSynthetic:
    """IAM covers: CreateRole, AttachRolePolicy, PassRole (passrole
    is checked-not-called so no synthetic needed for AWS-side, but
    we surface a synthetic OK for completeness). XML wire format
    (IAM query API)."""
    rid = _synthetic_request_id()
    headers = {
        "content-type": "text/xml",
        "x-amzn-requestid": rid,
    }
    body_str = body.decode("utf-8", errors="replace") if body else ""
    role_match = _IAM_ROLE_NAME_RE.search(body_str)
    role_name = (
        role_match.group("name") if role_match else "plan-capture-role"
    )
    if action == "CreateRole":
        synthetic_arn = f"arn:aws:iam::{PLAN_CAPTURE_ACCOUNT_ID}:role/{role_name}"
        body_xml = (
            f'<?xml version="1.0" encoding="UTF-8"?>'
            f'<CreateRoleResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">'
            f"<CreateRoleResult><Role>"
            f"<Path>/</Path>"
            f"<RoleName>{role_name}</RoleName>"
            f"<RoleId>AROAPLANCAPTUREROLEID00</RoleId>"
            f"<Arn>{synthetic_arn}</Arn>"
            f"<CreateDate>2026-01-01T00:00:00Z</CreateDate>"
            f"</Role></CreateRoleResult>"
            f"<ResponseMetadata><RequestId>{rid}</RequestId></ResponseMetadata>"
            f"</CreateRoleResponse>"
        ).encode("utf-8")
        return PlanCaptureSynthetic(
            status=200, headers=headers, body=body_xml,
            would_have_returned={"Arn": synthetic_arn, "RoleName": role_name},
        )
    if action == "AttachRolePolicy":
        body_xml = (
            f'<?xml version="1.0" encoding="UTF-8"?>'
            f'<AttachRolePolicyResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">'
            f"<ResponseMetadata><RequestId>{rid}</RequestId></ResponseMetadata>"
            f"</AttachRolePolicyResponse>"
        ).encode("utf-8")
        return PlanCaptureSynthetic(
            status=200, headers=headers, body=body_xml,
            would_have_returned={"AttachedTo": role_name},
        )
    if action == "PassRole":
        # PassRole is a permission check, not a wire call — but
        # cover it for completeness in case an SDK invokes it
        # explicitly via the IAM query API.
        body_xml = (
            f'<?xml version="1.0" encoding="UTF-8"?>'
            f'<PassRoleResponse xmlns="https://iam.amazonaws.com/doc/2010-05-08/">'
            f"<ResponseMetadata><RequestId>{rid}</RequestId></ResponseMetadata>"
            f"</PassRoleResponse>"
        ).encode("utf-8")
        return PlanCaptureSynthetic(
            status=200, headers=headers, body=body_xml,
            would_have_returned={"PassedRole": role_name},
        )
    return _build_unsupported_response(service="iam", action=action, host=host)


def _sts_synth(
    action: str, host: str, path: str, body: bytes, query: dict[str, Any],
) -> PlanCaptureSynthetic:
    """STS covers: AssumeRole. Returns synthetic credentials that
    OBVIOUSLY don't work (key id starts with `ASIAPLANCAPTURE`)."""
    rid = _synthetic_request_id()
    headers = {
        "content-type": "text/xml",
        "x-amzn-requestid": rid,
    }
    if action == "AssumeRole":
        # The synthetic credential key id is intentionally obvious so
        # any leak into agent logs / a downstream tool is unambiguous.
        body_xml = (
            f'<?xml version="1.0" encoding="UTF-8"?>'
            f'<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">'
            f"<AssumeRoleResult>"
            f"<Credentials>"
            f"<AccessKeyId>ASIAPLANCAPTURE000000</AccessKeyId>"
            f"<SecretAccessKey>plan-capture-synthetic-not-a-real-secret</SecretAccessKey>"
            f"<SessionToken>plan-capture-synthetic-session-token</SessionToken>"
            f"<Expiration>2026-01-01T01:00:00Z</Expiration>"
            f"</Credentials>"
            f"<AssumedRoleUser>"
            f"<AssumedRoleId>AROAPLANCAPTURE000000:plan-capture-session</AssumedRoleId>"
            f"<Arn>arn:aws:sts::{PLAN_CAPTURE_ACCOUNT_ID}:assumed-role/plan-capture/plan-capture-session</Arn>"
            f"</AssumedRoleUser>"
            f"</AssumeRoleResult>"
            f"<ResponseMetadata><RequestId>{rid}</RequestId></ResponseMetadata>"
            f"</AssumeRoleResponse>"
        ).encode("utf-8")
        return PlanCaptureSynthetic(
            status=200, headers=headers, body=body_xml,
            would_have_returned={
                "Credentials": "synthetic-non-functional",
                "RoleArn": (
                    f"arn:aws:sts::{PLAN_CAPTURE_ACCOUNT_ID}:assumed-role/plan-capture/plan-capture-session"
                ),
            },
        )
    return _build_unsupported_response(service="sts", action=action, host=host)


def _ec2_synth(
    action: str, host: str, path: str, body: bytes, query: dict[str, Any],
) -> PlanCaptureSynthetic:
    """EC2 covers: DescribeInstances, RunInstances, TerminateInstances.
    XML wire format (EC2 query API)."""
    rid = _synthetic_request_id()
    headers = {
        "content-type": "text/xml",
        "x-amzn-requestid": rid,
    }
    if action == "DescribeInstances":
        body_xml = (
            f'<?xml version="1.0" encoding="UTF-8"?>'
            f'<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">'
            f"<requestId>{rid}</requestId>"
            f"<reservationSet></reservationSet>"
            f"</DescribeInstancesResponse>"
        ).encode("utf-8")
        return PlanCaptureSynthetic(
            status=200, headers=headers, body=body_xml,
            would_have_returned={"Reservations": []},
        )
    if action == "RunInstances":
        synthetic_instance_id = f"i-{uuid.uuid4().hex[:17]}"
        body_xml = (
            f'<?xml version="1.0" encoding="UTF-8"?>'
            f'<RunInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">'
            f"<requestId>{rid}</requestId>"
            f"<reservationId>r-plancapture</reservationId>"
            f"<ownerId>{PLAN_CAPTURE_ACCOUNT_ID}</ownerId>"
            f"<instancesSet>"
            f"<item>"
            f"<instanceId>{synthetic_instance_id}</instanceId>"
            f"<imageId>ami-plancapture</imageId>"
            f"<instanceState><code>0</code><name>pending</name></instanceState>"
            f"<privateDnsName/><dnsName/>"
            f"<reason/><amiLaunchIndex>0</amiLaunchIndex>"
            f"<productCodes/>"
            f"<instanceType>plan.capture</instanceType>"
            f"<launchTime>2026-01-01T00:00:00.000Z</launchTime>"
            f"<placement><availabilityZone>plan-capture-az</availabilityZone></placement>"
            f"<monitoring><state>disabled</state></monitoring>"
            f"</item>"
            f"</instancesSet>"
            f"</RunInstancesResponse>"
        ).encode("utf-8")
        return PlanCaptureSynthetic(
            status=200, headers=headers, body=body_xml,
            would_have_returned={"Instances": [synthetic_instance_id]},
        )
    if action == "TerminateInstances":
        body_xml = (
            f'<?xml version="1.0" encoding="UTF-8"?>'
            f'<TerminateInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/">'
            f"<requestId>{rid}</requestId>"
            f"<instancesSet>"
            f"<item>"
            f"<instanceId>i-plancapture-target</instanceId>"
            f"<currentState><code>32</code><name>shutting-down</name></currentState>"
            f"<previousState><code>16</code><name>running</name></previousState>"
            f"</item>"
            f"</instancesSet>"
            f"</TerminateInstancesResponse>"
        ).encode("utf-8")
        return PlanCaptureSynthetic(
            status=200, headers=headers, body=body_xml,
            would_have_returned={
                "TerminatingInstances": ["i-plancapture-target"],
            },
        )
    return _build_unsupported_response(service="ec2", action=action, host=host)


def _lambda_synth(
    action: str, host: str, path: str, body: bytes, query: dict[str, Any],
) -> PlanCaptureSynthetic:
    """Lambda covers: Invoke, CreateFunction. JSON wire format
    (Lambda REST API)."""
    rid = _synthetic_request_id()
    headers = {
        "content-type": "application/json",
        "x-amzn-requestid": rid,
    }
    if action == "Invoke":
        # Lambda Invoke returns the payload as the response body
        # (NOT wrapped in JSON). An empty `{}` payload is the
        # least-disruptive synthetic return.
        invoke_headers = dict(headers)
        invoke_headers["x-amz-executed-version"] = "$LATEST"
        return PlanCaptureSynthetic(
            status=200, headers=invoke_headers, body=b"{}",
            would_have_returned={"Payload": "{}", "StatusCode": 200},
        )
    if action == "CreateFunction":
        function_name = "plan-capture-function"
        # Lambda body shape per the CreateFunction API. Includes
        # FunctionArn so the agent's next call (AddPermission, etc.)
        # has something to chain off of.
        payload = {
            "FunctionName": function_name,
            "FunctionArn": (
                f"arn:aws:lambda:plan-capture-region:{PLAN_CAPTURE_ACCOUNT_ID}:"
                f"function:{function_name}"
            ),
            "Runtime": "plan-capture",
            "Role": (
                f"arn:aws:iam::{PLAN_CAPTURE_ACCOUNT_ID}:role/plan-capture-role"
            ),
            "Handler": "plan-capture.handler",
            "CodeSize": 0,
            "Description": "synthetic plan-capture function",
            "Timeout": 3,
            "MemorySize": 128,
            "LastModified": "2026-01-01T00:00:00.000+0000",
            "Version": "$LATEST",
            "State": "Pending",
        }
        body_bytes = json.dumps(payload).encode("utf-8")
        return PlanCaptureSynthetic(
            status=201, headers=headers, body=body_bytes,
            would_have_returned={
                "FunctionArn": payload["FunctionArn"],
                "FunctionName": function_name,
            },
        )
    return _build_unsupported_response(service="lambda", action=action, host=host)


# Registry: (service, action) -> synthesizer function. Adding an
# entry here is the only change needed to "support" a new op in
# plan-capture. Coverage is intentionally minimal viable per the
# #132 spec; expand as agent-driven workflows demand it.
_REGISTRY: dict[tuple[str, str], Any] = {
    # S3 — both `ListBuckets` and `ListAllMyBuckets` are registered
    # because the iam-jit request_parser canonicalizes `GET /` to
    # `ListAllMyBuckets` (the historical AWS IAM action name) while
    # the SDK + IAM docs use `ListBuckets`. Either action lands on
    # the same synthesizer so both paths produce the same shape.
    ("s3", "ListBuckets"): _s3_synth,
    ("s3", "ListAllMyBuckets"): _s3_synth,
    ("s3", "ListObjects"): _s3_synth,
    ("s3", "ListObjectsV2"): _s3_synth,
    ("s3", "GetObject"): _s3_synth,
    ("s3", "HeadObject"): _s3_synth,
    ("s3", "PutObject"): _s3_synth,
    ("s3", "DeleteObject"): _s3_synth,
    # IAM
    ("iam", "CreateRole"): _iam_synth,
    ("iam", "AttachRolePolicy"): _iam_synth,
    ("iam", "PassRole"): _iam_synth,
    # STS
    ("sts", "AssumeRole"): _sts_synth,
    # EC2
    ("ec2", "DescribeInstances"): _ec2_synth,
    ("ec2", "RunInstances"): _ec2_synth,
    ("ec2", "TerminateInstances"): _ec2_synth,
    # Lambda
    ("lambda", "Invoke"): _lambda_synth,
    ("lambda", "CreateFunction"): _lambda_synth,
}


SUPPORTED_OPERATIONS: tuple[tuple[str, str], ...] = tuple(sorted(_REGISTRY.keys()))
"""Sorted tuple of every (service, action) covered. Public so the CLI
+ MCP tool can echo the registry to operators ("here's what plan-
capture knows how to fake")."""


def is_supported(service: str, action: str) -> bool:
    """True iff the registry has a synthesizer for (service, action).
    Case-sensitive on action (AWS action names are canonical-cased)."""
    return (service.lower(), action) in _REGISTRY


def synthesize_response(
    *,
    service: str,
    action: str,
    host: str,
    path: str,
    body: bytes | None,
    query: dict[str, Any] | None,
) -> PlanCaptureSynthetic:
    """Build the synthetic SDK-shaped response for an inbound call.

    Returns a `PlanCaptureSynthetic` either from the registered
    synthesizer or — for unregistered ops — from the shared
    `_build_unsupported_response` helper. The caller (proxy
    handler) writes status/headers/body to the wire and records
    `would_have_returned` in the audit log.
    """
    key = (service.lower(), action)
    handler = _REGISTRY.get(key)
    payload_body = body or b""
    payload_query = query or {}
    if handler is None:
        return _build_unsupported_response(
            service=service, action=action, host=host,
        )
    return handler(action, host, path, payload_body, payload_query)
