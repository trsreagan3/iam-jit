from typing import Any

from policy_sentry.querying.actions import get_actions_with_access_level
from policy_sentry.querying.all import get_all_service_prefixes

from .llm import LLMBackend, NoOpBackend, get_backend

_LEVEL_TO_PS: dict[str, str] = {
    "read": "Read",
    "list": "List",
    "write": "Write",
    "tagging": "Tagging",
    "permissions-management": "Permissions management",
}


def suggest_policy(
    request: dict[str, Any], *, use_llm: bool = True, backend: LLMBackend | None = None
) -> dict[str, Any]:
    """Return a least-privilege IAM policy for the given role request.

    Pipeline:
      1. (optional, with a configured LLM backend) refine (services, action-levels)
         from the user's free-text description.
      2. Validate services against `policy_sentry.querying.all.get_all_service_prefixes()`
         — untrusted LLM output cannot introduce a service that doesn't exist.
      3. Expand (service, level) pairs into the deterministic IAM action list
         using `policy_sentry`'s action database.
      4. Emit a standard IAM policy document with the resulting actions.

    The LLM only refines bounded enums; it never emits IAM actions, ARNs, or
    policy JSON. `policy_sentry` is the deterministic backbone.
    """
    intent = request["spec"].get("task_intent") or {}
    services: list[str] = [s for s in (intent.get("services") or []) if isinstance(s, str)]
    actions: list[str] = [a for a in (intent.get("actions") or []) if a in _LEVEL_TO_PS]

    # Honor the coarse-grained `access_type` toggle: read-only restricts to
    # read+list regardless of what task_intent.actions says.
    access_type = (request["spec"].get("access_type") or "read-only").strip().lower()
    if access_type == "read-only":
        actions = [a for a in actions if a in {"read", "list"}]
        if not actions:
            actions = ["read", "list"]

    if use_llm:
        chosen = backend if backend is not None else get_backend()
        if not isinstance(chosen, NoOpBackend):
            services, actions = chosen.refine(
                description=request["spec"].get("description") or "",
                initial_services=services,
                initial_actions=actions,
            )
        # Re-apply the read-only constraint: even an LLM that proposes
        # write-level can't override the explicit access_type toggle.
        if access_type == "read-only":
            actions = [a for a in actions if a in {"read", "list"}] or ["read", "list"]

    valid_services = set(get_all_service_prefixes())
    services = sorted({s for s in services if s in valid_services})
    if not services:
        raise ValueError(
            "No valid AWS service prefixes after filtering. "
            "Set spec.task_intent.services to known AWS service prefixes (e.g. 's3', 'eks')."
        )
    actions = sorted({a for a in actions if a in _LEVEL_TO_PS}) or ["read"]

    constraints_by_service: dict[str, list[str]] = {
        c["service"]: list(c["arn_patterns"])
        for c in (request["spec"].get("resource_constraints") or [])
        if c.get("service") and c.get("arn_patterns")
    }

    statements: list[dict[str, Any]] = []
    for service in services:
        service_actions: list[str] = []
        for level_lower in actions:
            service_actions.extend(
                get_actions_with_access_level(service, _LEVEL_TO_PS[level_lower])
            )
        service_actions = sorted(set(service_actions))
        if not service_actions:
            continue
        resources = constraints_by_service.get(service, ["*"])
        statements.append(
            {
                "Effect": "Allow",
                "Action": service_actions,
                "Resource": resources[0] if len(resources) == 1 else resources,
            }
        )

    if not statements:
        raise ValueError(
            f"policy_sentry returned no actions for services={services} levels={actions}."
        )

    return {"Version": "2012-10-17", "Statement": statements}
