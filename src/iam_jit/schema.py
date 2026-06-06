import datetime as _dt
import io
import json
import os
import pathlib
from typing import Any

import jsonschema
from ruamel.yaml import YAML

_yaml = YAML(typ="rt")
_yaml.indent(mapping=2, sequence=4, offset=2)
_yaml.preserve_quotes = True

from . import _resources

_SCHEMA_PATH = _resources.find("schemas", "request.schema.json")


def _load_schema() -> dict[str, Any]:
    return json.loads(_SCHEMA_PATH.read_text())


def load_request(path: pathlib.Path) -> dict[str, Any]:
    with path.open() as f:
        return _yaml.load(f)


def dump_request(request: dict[str, Any]) -> str:
    buf = io.StringIO()
    _yaml.dump(request, buf)
    return buf.getvalue()


def _normalize(obj: Any) -> Any:
    """Coerce ruamel-parsed types (TimeStamp, CommentedMap, etc.) to JSON-native ones."""
    return json.loads(json.dumps(obj, default=str))


def validate_request(request: dict[str, Any]) -> list[str]:
    schema = _load_schema()
    validator = jsonschema.Draft202012Validator(schema)
    errors = [
        f"{'/'.join(str(p) for p in err.absolute_path) or '<root>'}: {err.message}"
        for err in validator.iter_errors(_normalize(request))
    ]
    errors.extend(_deployment_policy_errors(request))
    return errors


def _deployment_policy_errors(request: dict[str, Any]) -> list[str]:
    """Per-deployment requirements that aren't expressible as JSON Schema.

    Currently: when `IAM_JIT_REQUIRE_TICKET=1`, every submission must carry
    `spec.ticket` matching the configured allow-list of host patterns (env
    `IAM_JIT_TICKET_HOST_PATTERN`, comma-separated; default: any URL).
    """
    out: list[str] = []
    require = (os.environ.get("IAM_JIT_REQUIRE_TICKET") or "").lower() in {"1", "true", "yes"}
    if not require:
        return out
    spec = request.get("spec") or {}
    ticket = spec.get("ticket")
    if not ticket:
        out.append(
            "spec/ticket: required by this deployment "
            "(IAM_JIT_REQUIRE_TICKET=1). Provide the URL of the change, "
            "incident, or access ticket authorizing this request."
        )
        return out
    allowed = [p.strip() for p in (os.environ.get("IAM_JIT_TICKET_HOST_PATTERN") or "").split(",") if p.strip()]
    if allowed and not any(pat in ticket for pat in allowed):
        out.append(
            f"spec/ticket: URL must match one of the allowed host patterns "
            f"({', '.join(allowed)}) configured by IAM_JIT_TICKET_HOST_PATTERN."
        )
    return out


def scaffold_request(
    *,
    description: str,
    accounts: list[str],
    duration_hours: int,
    access_type: str = "read-only",
) -> str:
    now = _dt.datetime.now(_dt.UTC)
    initial_actions = ["read", "list"] if access_type == "read-only" else ["read", "list"]
    request = {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "RoleRequest",
        "metadata": {
            "requester": {"name": "FILL_IN", "email": "FILL_IN@example.com"},
            "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        "spec": {
            "description": description,
            "access_type": access_type,
            "task_intent": {"services": [], "actions": initial_actions},
            "accounts": [{"account_id": acct, "regions": ["us-east-1"]} for acct in accounts],
            "duration": {"duration_hours": duration_hours},
            "policy": None,
            "provisioning": {"mode": "identity_center"},
        },
    }
    return dump_request(request)


def scaffold_github_request(
    *,
    org: str,
    repositories: list[str],
    permissions: dict[str, str],
    duration_minutes: int = 60,
    description: str | None = None,
    requester_name: str = "FILL_IN",
    requester_email: str = "FILL_IN@example.com",
) -> dict[str, Any]:
    """Build a GitHubTokenRequest dict (validated by request.schema.json's
    GitHubTokenRequest branch). `permissions` is the GitHub {category: read|write}
    map passed straight to the token mint; `duration_minutes` caps at 60 (GitHub's
    1h ceiling) — sub-hour is enforced via an early revoke."""
    now = _dt.datetime.now(_dt.UTC)
    github: dict[str, Any] = {
        "org": org,
        "repositories": list(repositories),
        "permissions": dict(permissions),
    }
    if duration_minutes:
        github["duration_minutes"] = int(duration_minutes)
    spec: dict[str, Any] = {"github": github}
    if description is not None:
        spec["description"] = description
    return {
        "apiVersion": "iam-jit.dev/v1alpha1",
        "kind": "GitHubTokenRequest",
        "metadata": {
            "requester": {"name": requester_name, "email": requester_email},
            "created_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        },
        "spec": spec,
    }
