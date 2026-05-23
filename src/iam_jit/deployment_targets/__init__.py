# #437 / §A71 — Phase G deployment-target taxonomy.
"""Operator-declared deployment-target taxonomy.

The taxonomy is purely DECLARATIVE: operator authors named scope
classifiers in ``.iam-jit.yaml`` and the agent reads them to build
filters for long-range audit queries (#436) when synthesising
per-target bouncer configs.

Per [[bouncer-informs-agent-informs-iam-jit]] iam-jit just provides
the taxonomy + the log-access plumbing; the AGENT does the synthesis.
This module is the look-up layer — no inference, no scoring.
"""

from __future__ import annotations

from .registry import (
    DeploymentTarget,
    DeploymentTargetError,
    list_deployment_targets,
    load_deployment_target,
)

__all__ = [
    "DeploymentTarget",
    "DeploymentTargetError",
    "list_deployment_targets",
    "load_deployment_target",
]
