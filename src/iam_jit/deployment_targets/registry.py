# #437 / §A71 — deployment-target lookup.
"""Pure-function lookup for the ``deployment_targets`` block of a
loaded ``.iam-jit.yaml`` declaration.

Mirrors the shape of :mod:`iam_jit.resource_map.mapper` (loaders +
list helper + frozen dataclass) so the CLI + MCP surfaces compose
without re-walking the declaration dict.
"""

from __future__ import annotations

import dataclasses
from typing import Any


class DeploymentTargetError(LookupError):
    """Raised when a named deployment-target lookup fails (missing or
    malformed). Carries a ``code`` so the CLI + MCP surfaces can
    re-emit it as structured JSON."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "deployment_target_not_found",
    ) -> None:
        super().__init__(message)
        self.message = message
        self.code = code


_VALID_BOUNCERS = frozenset({"ibounce", "kbouncer", "dbounce", "gbounce"})

_CLASSIFIER_DIMENSIONS = (
    "clusters",
    "accounts",
    "regions",
    "namespaces",
    "hosts",
    "databases",
)


@dataclasses.dataclass(frozen=True)
class DeploymentTarget:
    """One named deployment-target (e.g. ``prod-k8s``) from the
    operator's declaration.

    The ``classifier`` is the scope-dimension dict the agent passes as
    ``--scope-filter`` to ``iam-jit audit query --since 2y`` (#436)
    when synthesising a per-target bouncer config.
    """

    name: str
    bouncer: str
    classifier: dict[str, list[str]]
    description: str = ""

    def as_dict(self) -> dict[str, Any]:
        """Stable shape for CLI / MCP JSON output."""
        out: dict[str, Any] = {
            "name": self.name,
            "bouncer": self.bouncer,
            "classifier": {
                k: list(v) for k, v in self.classifier.items()
            },
        }
        if self.description:
            out["description"] = self.description
        return out

    @classmethod
    def from_dict(cls, name: str, raw: dict[str, Any]) -> "DeploymentTarget":
        if not isinstance(raw, dict):
            raise DeploymentTargetError(
                f"deployment_targets.{name} must be a mapping; got "
                f"{type(raw).__name__}",
                code="invalid_deployment_target",
            )
        bouncer = raw.get("bouncer")
        if not isinstance(bouncer, str) or bouncer not in _VALID_BOUNCERS:
            raise DeploymentTargetError(
                f"deployment_targets.{name}.bouncer must be one of "
                f"{sorted(_VALID_BOUNCERS)}; got {bouncer!r}",
                code="invalid_deployment_target_bouncer",
            )
        raw_classifier = raw.get("classifier") or {}
        if not isinstance(raw_classifier, dict):
            raise DeploymentTargetError(
                f"deployment_targets.{name}.classifier must be a "
                f"mapping; got {type(raw_classifier).__name__}",
                code="invalid_deployment_target_classifier",
            )
        classifier: dict[str, list[str]] = {}
        for dim in _CLASSIFIER_DIMENSIONS:
            value = raw_classifier.get(dim)
            if value is None:
                continue
            if not isinstance(value, list) or not all(
                isinstance(v, str) and v for v in value
            ):
                raise DeploymentTargetError(
                    f"deployment_targets.{name}.classifier.{dim} must "
                    f"be a non-empty list of strings",
                    code="invalid_classifier_dimension",
                )
            classifier[dim] = list(value)
        # Any unknown classifier keys are silently dropped (forward-
        # compat with future schema bumps).
        description = raw.get("description")
        if description is not None and not isinstance(description, str):
            raise DeploymentTargetError(
                f"deployment_targets.{name}.description must be a "
                f"string when present",
                code="invalid_deployment_target_description",
            )
        return cls(
            name=name,
            bouncer=bouncer,
            classifier=classifier,
            description=description or "",
        )


def _block(declaration: dict[str, Any]) -> dict[str, Any]:
    iam_jit = declaration.get("iam-jit") or {}
    if not isinstance(iam_jit, dict):
        return {}
    targets = iam_jit.get("deployment_targets") or {}
    if not isinstance(targets, dict):
        return {}
    return targets


def load_deployment_target(
    declaration: dict[str, Any],
    name: str,
) -> DeploymentTarget:
    """Resolve a named deployment-target. Raises
    :class:`DeploymentTargetError` when the name is missing — the
    error carries the available names so the agent can re-ask."""
    targets = _block(declaration)
    if not targets:
        raise DeploymentTargetError(
            "no deployment_targets defined in declaration",
            code="no_deployment_targets",
        )
    raw = targets.get(name)
    if raw is None:
        available = sorted(targets.keys())
        raise DeploymentTargetError(
            f"deployment-target {name!r} not defined; available: "
            f"{available or '(none)'}",
            code="deployment_target_not_found",
        )
    return DeploymentTarget.from_dict(name, raw)


def list_deployment_targets(
    declaration: dict[str, Any],
) -> list[DeploymentTarget]:
    """Return every declared deployment-target. Sorted by name for
    stable CLI + MCP output. Malformed entries raise; the operator's
    declaration is supposed to validate at load time so a malformed
    entry here is a programmer error, not a runtime expectation."""
    targets = _block(declaration)
    out: list[DeploymentTarget] = []
    for name in sorted(targets.keys()):
        out.append(DeploymentTarget.from_dict(name, targets[name]))
    return out


__all__ = [
    "DeploymentTarget",
    "DeploymentTargetError",
    "list_deployment_targets",
    "load_deployment_target",
]
