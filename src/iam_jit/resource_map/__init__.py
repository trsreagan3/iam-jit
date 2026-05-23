# #420 / §A59 — declarative resource-mapping helper.
"""Backend for ``iam-jit resource-map`` CLI + ``iam_jit_resource_map``
MCP tool.

Phase E of [[bouncer-informs-agent-informs-iam-jit]]. Operator declares
account/region/name substitutions; this module applies them to a
permission set extracted from one environment (e.g. staging) to
produce the corresponding shape for another environment (e.g. prod).

Per [[scorer-is-ground-truth]] this module performs PURE textual
substitution defined by the operator's declarative mapping — it does
not infer prod-ness from staging audit, does not call an LLM, does not
look at code. The agent that called it composed the mapping name from
its understanding of the operator intent + the available declarative
mappings.

Per [[recommender-context-boundary]] no new context channel: the
mapping lives in the existing ambient config file
(``.iam-jit.yaml`` or codeblock).
"""

from __future__ import annotations

from .mapper import (
    ResourceMapping,
    apply_resource_mapping,
    apply_resource_mapping_to_permissions,
    list_mappings_in_config,
    load_mapping_from_config,
    map_observed_scope,
)

__all__ = [
    "ResourceMapping",
    "apply_resource_mapping",
    "apply_resource_mapping_to_permissions",
    "list_mappings_in_config",
    "load_mapping_from_config",
    "map_observed_scope",
]
