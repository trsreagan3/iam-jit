"""Wire-format parser for AWS API HTTP requests.

Given a raw HTTP request the bouncer's proxy server intercepted,
extract:
- service (e.g. "s3", "dynamodb", "iam", "lambda")
- action (e.g. "GetObject", "PutItem", "CreateRole")
- region (e.g. "us-east-1", "us-west-2", or None for global services)
- resource_hint (best-effort ARN or resource identifier; None when
  the service uses an inline body the bouncer doesn't deep-parse)

The parser does NOT validate SigV4 signatures. That's AWS's job at
the other end. We extract metadata to route the rule match; AWS
authenticates the actual call once we forward.

Three sources, in priority order:
1. `X-Amz-Target` header — JSON-RPC services (DynamoDB, Bedrock,
   STS, KMS, most modern services). Format: `<ServicePrefix>.<Action>`
   e.g. `DynamoDB_20120810.PutItem`. The action is unambiguous.
2. `Action=` query/form parameter — query-string services (EC2,
   IAM, SQS legacy). Action is unambiguous.
3. HTTP method + path — REST services (S3, Lambda, API Gateway).
   Service-specific; this slice ships heuristics for S3 + Lambda;
   other REST services fall through with action="<METHOD>" and
   the path as resource hint.

The service + region come from the SigV4 `Credential=...` field in
the `Authorization` header — that's the AWS-canonical source of
truth for which API endpoint the call targets.

Per [[creates-never-mutates]]: parsing is read-only. We don't modify
the request; the proxy server forwards it untouched (preserving the
SigV4 signature, which is what makes AWS auth still work).
"""

from __future__ import annotations

import dataclasses
import re
import urllib.parse
from typing import Any

# Authorization: AWS4-HMAC-SHA256
#   Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request,
#   SignedHeaders=host;range;x-amz-date,
#   Signature=fe5f80f77d5fa3beca038a248ff027d0445342fe2855ddc963176630326f1024
_SIGV4_AUTH_RE = re.compile(
    r"AWS4-HMAC-SHA256\s+Credential=[^/]+/\d+/(?P<region>[^/]+)/(?P<service>[^/]+)/aws4_request",
    re.IGNORECASE,
)

# Some services are global (region in Credential is `us-east-1` by
# convention but the API itself is regionless). Surface the actual
# Credential-encoded region as-is; the bouncer rule scope can decide
# how strict to be.
_GLOBAL_SERVICES = frozenset({"iam", "organizations", "cloudfront", "route53", "support"})


@dataclasses.dataclass(frozen=True)
class ParsedRequest:
    """The bouncer's view of an AWS API request."""

    service: str  # lowercase service prefix, e.g. "s3"
    action: str  # canonical action name, e.g. "GetObject"
    region: str | None  # None for global services; otherwise the SigV4 region
    resource_hint: str | None = None  # best-effort ARN or resource identifier
    # Raw extracted bits, surfaced for the audit log + the Stage 2
    # interactive prompt UX. Kept opaque so the rule matcher doesn't
    # depend on them.
    raw_method: str = ""
    raw_host: str = ""
    raw_path: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "service": self.service,
            "action": self.action,
            "region": self.region,
            "resource_hint": self.resource_hint,
            "raw_method": self.raw_method,
            "raw_host": self.raw_host,
            "raw_path": self.raw_path,
        }


def extract_service_and_region(
    authorization: str | None,
) -> tuple[str, str] | None:
    """Pull (service, region) out of the SigV4 Authorization header.

    Returns None if header is missing / malformed (e.g. anonymous
    S3 calls). Bouncer's policy for unsigned requests is the
    caller's choice (Stage 2 will gate them by default).
    """
    if not authorization or not isinstance(authorization, str):
        return None
    m = _SIGV4_AUTH_RE.search(authorization)
    if m is None:
        return None
    service = m.group("service").lower()
    region = m.group("region")
    return service, region


def parse_request(
    *,
    method: str,
    host: str,
    path: str,
    headers: dict[str, str],
    body: bytes | str | None = None,
    query: dict[str, str] | None = None,
) -> ParsedRequest | None:
    """Build a ParsedRequest from raw HTTP request parts.

    Returns None if we can't even identify the service (no SigV4
    auth header). The proxy server treats that as "bouncer can't
    classify — fall through to default-policy DENY in enforce mode."

    `headers` is case-insensitive in HTTP but we accept whatever
    casing the caller passes; we lowercase keys for lookup.
    """
    headers_lc = {k.lower(): v for k, v in (headers or {}).items()}
    extracted = extract_service_and_region(headers_lc.get("authorization"))
    if extracted is None:
        return None
    service, region = extracted
    if service in _GLOBAL_SERVICES:
        # Global service: region in the SigV4 cred is conventional
        # (always us-east-1 for IAM). Surface None so rules don't
        # accidentally narrow by region.
        region = None

    action, resource_hint = _resolve_action_and_resource(
        service=service,
        method=method,
        host=host,
        path=path,
        headers_lc=headers_lc,
        body=body,
        query=query or {},
    )

    return ParsedRequest(
        service=service,
        action=action,
        region=region,
        resource_hint=resource_hint,
        raw_method=method.upper() if method else "",
        raw_host=host or "",
        raw_path=path or "",
    )


# ---------------------------------------------------------------------------
# Action / resource extraction
# ---------------------------------------------------------------------------


def _resolve_action_and_resource(
    *,
    service: str,
    method: str,
    host: str,
    path: str,
    headers_lc: dict[str, str],
    body: bytes | str | None,
    query: dict[str, str],
) -> tuple[str, str | None]:
    """Return (action, resource_hint). Action is best-effort canonical
    (matching the IAM `<service>:<Action>` shape); resource_hint is
    best-effort and may be None.

    Strategy:
    - X-Amz-Target header → JSON-RPC services
    - Action= param → query-string services
    - method+path → REST services (S3 special-cased; others fall
      back to a generic `<METHOD>` action)
    """
    # 1. X-Amz-Target — JSON-RPC services
    target = headers_lc.get("x-amz-target")
    if target:
        # Format: `<ServiceTarget>.<Action>` (e.g. "DynamoDB_20120810.PutItem")
        if "." in target:
            action = target.rsplit(".", 1)[-1]
            return action, _extract_resource_from_json_body(service, action, body)
        return target, None

    # 2. Action= form / query param — query-string services
    action_param = query.get("Action") or _parse_form_action(body)
    if action_param:
        return action_param, _extract_resource_from_form_body(service, body, query)

    # 3. REST services — service-specific dispatch
    if service == "s3":
        return _s3_action_and_resource(method=method, host=host, path=path, query=query)
    if service == "lambda":
        return _lambda_action_and_resource(method=method, path=path)

    # 4. Generic REST fallback
    return method.upper() or "Unknown", _generic_resource_hint(host, path)


def _parse_form_action(body: bytes | str | None) -> str | None:
    """Some services (legacy IAM, EC2, STS) put `Action=Foo&...` in
    application/x-www-form-urlencoded request bodies."""
    if body is None:
        return None
    if isinstance(body, bytes):
        try:
            body_str = body.decode("utf-8", errors="replace")
        except Exception:
            return None
    else:
        body_str = body
    if "Action=" not in body_str:
        return None
    parsed = urllib.parse.parse_qs(body_str, keep_blank_values=False)
    actions = parsed.get("Action")
    if actions and actions[0]:
        return actions[0]
    return None


def _extract_resource_from_form_body(
    service: str, body: bytes | str | None, query: dict[str, str]
) -> str | None:
    """Best-effort: pull a resource identifier out of form-encoded body.
    Currently surfaces well-known fields (RoleName, UserName, etc.)
    when present. Don't synthesize ARNs — the rule matcher uses what
    it sees."""
    if not body:
        return query.get("RoleName") or query.get("UserName") or None
    if isinstance(body, bytes):
        try:
            body_str = body.decode("utf-8", errors="replace")
        except Exception:
            return None
    else:
        body_str = body
    if "=" not in body_str:
        return None
    try:
        parsed = urllib.parse.parse_qs(body_str, keep_blank_values=False)
    except Exception:
        return None
    for key in ("RoleName", "UserName", "PolicyArn", "GroupName"):
        vals = parsed.get(key)
        if vals and vals[0]:
            return vals[0]
    return None


def _extract_resource_from_json_body(
    service: str, action: str, body: bytes | str | None
) -> str | None:
    """Best-effort: pull a resource identifier out of a JSON-RPC body.
    Common shape: TableName, FunctionName, Bucket, Key, etc.
    """
    if not body:
        return None
    if isinstance(body, bytes):
        try:
            body_str = body.decode("utf-8", errors="replace")
        except Exception:
            return None
    else:
        body_str = body
    import json

    try:
        data = json.loads(body_str)
    except (ValueError, TypeError):
        return None
    if not isinstance(data, dict):
        return None
    for key in (
        "TableName",
        "FunctionName",
        "Bucket",
        "Key",
        "QueueUrl",
        "TopicArn",
        "RoleName",
        "Identifier",
    ):
        v = data.get(key)
        if isinstance(v, str) and v:
            return v
    return None


def _generic_resource_hint(host: str, path: str) -> str | None:
    """For REST services we don't special-case: return the path so
    the audit log shows what was hit, but don't try to fake an ARN."""
    if path and path != "/":
        return path
    return host or None


# ---------------------------------------------------------------------------
# S3-specific dispatch
# ---------------------------------------------------------------------------


def _s3_action_and_resource(
    *, method: str, host: str, path: str, query: dict[str, str]
) -> tuple[str, str | None]:
    """Map S3 HTTP method + path → IAM-style action.

    S3 has two URL styles:
    - Path-style:    https://s3.amazonaws.com/<bucket>/<key>
    - Virtual-hosted: https://<bucket>.s3.amazonaws.com/<key>

    This handles the common operations admins gate on; for less-
    common ones (multipart, replication, etc.) it falls through to
    a generic `<METHOD>Object|Bucket` action.
    """
    bucket, key = _split_s3_bucket_and_key(host=host, path=path)
    m = (method or "").upper()

    # Sub-resource queries (?policy, ?acl, ?lifecycle, etc.) imply
    # specific S3 operations. Order matters: check sub-resources first.
    for sr_param, get_action, put_action, del_action in (
        ("policy", "GetBucketPolicy", "PutBucketPolicy", "DeleteBucketPolicy"),
        ("acl", "GetObjectAcl" if key else "GetBucketAcl",
                "PutObjectAcl" if key else "PutBucketAcl",
                None),
        ("lifecycle", "GetLifecycleConfiguration", "PutLifecycleConfiguration", "DeleteLifecycle"),
        ("versioning", "GetBucketVersioning", "PutBucketVersioning", None),
        ("encryption", "GetEncryptionConfiguration", "PutEncryptionConfiguration", "DeleteEncryption"),
    ):
        if sr_param in query:
            action_map = {"GET": get_action, "PUT": put_action, "DELETE": del_action}
            action = action_map.get(m)
            if action:
                return action, _s3_resource_arn(bucket, key if key else None)

    # Standard operations
    if key:
        op = {
            "GET": "GetObject",
            "HEAD": "HeadObject",
            "PUT": "PutObject",
            "DELETE": "DeleteObject",
            "POST": "PostObject",
        }.get(m, m)
        return op, _s3_resource_arn(bucket, key)

    if bucket:
        op = {
            "GET": "ListBucket",
            "HEAD": "HeadBucket",
            "PUT": "CreateBucket",
            "DELETE": "DeleteBucket",
        }.get(m, m)
        return op, _s3_resource_arn(bucket, None)

    # No bucket, no key — ListAllMyBuckets-shaped call
    if m == "GET":
        return "ListAllMyBuckets", None
    return m, None


def _split_s3_bucket_and_key(*, host: str, path: str) -> tuple[str | None, str | None]:
    """Resolve (bucket, key) from S3 URL parts. Returns (None, None)
    for the empty service-root request."""
    host_lc = (host or "").lower()
    path = path or ""
    if "s3" in host_lc and not host_lc.startswith("s3"):
        # Virtual-hosted: <bucket>.s3.<...>.amazonaws.com
        bucket = host_lc.split(".s3", 1)[0]
        key = path.lstrip("/") or None
        return bucket, key
    # Path-style: /<bucket>/<key...>
    stripped = path.lstrip("/")
    if not stripped:
        return None, None
    parts = stripped.split("/", 1)
    bucket = parts[0]
    key = parts[1] if len(parts) > 1 and parts[1] else None
    return bucket, key


def _s3_resource_arn(bucket: str | None, key: str | None) -> str | None:
    if not bucket:
        return None
    if key:
        return f"arn:aws:s3:::{bucket}/{key}"
    return f"arn:aws:s3:::{bucket}"


# ---------------------------------------------------------------------------
# Lambda-specific dispatch (minimal — enough for the common cases)
# ---------------------------------------------------------------------------


def _lambda_action_and_resource(*, method: str, path: str) -> tuple[str, str | None]:
    """Lambda uses REST; the common path shapes are:
      POST /2015-03-31/functions/<name>/invocations  → Invoke
      GET  /2015-03-31/functions/<name>              → GetFunction
      DELETE /2015-03-31/functions/<name>            → DeleteFunction
    """
    m = (method or "").upper()
    parts = (path or "").strip("/").split("/")
    name: str | None = None
    if len(parts) >= 3 and parts[1] == "functions":
        name = parts[2]
    if path.endswith("/invocations"):
        action = "InvokeFunction"
    elif m == "GET" and name:
        action = "GetFunction"
    elif m == "DELETE" and name:
        action = "DeleteFunction"
    elif m == "PUT" and name:
        action = "UpdateFunctionCode"
    elif m == "POST" and len(parts) >= 2 and parts[1] == "functions":
        action = "CreateFunction"
    else:
        action = m or "Unknown"
    return action, name
