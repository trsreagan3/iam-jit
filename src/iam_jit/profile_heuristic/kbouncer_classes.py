# Phase 1 — kbouncer (Kubernetes) verb tables.
"""kbouncer action classification.

K8s actions in the bouncer's audit shape are typically the K8s verb
itself (``get`` / ``list`` / ``watch`` / ``create`` / ``update`` /
``patch`` / ``delete``). The resource string (when supplied) lets us
escalate ``delete`` on high-blast resources (``deployment`` /
``namespace`` / ``clusterrolebinding``) to ``DESTRUCTIVE_DATA``.

Per `docs/PROFILE-GENERATION-DESIGN.md` §2.1:

* READ: get / list / watch
* WRITE_DATA: update / patch / apply
* ADMIN: RBAC verbs, create clusterrolebinding
* DESTRUCTIVE_DATA: delete deployment, delete pod, delete namespace
"""

from __future__ import annotations


# Verbs that are unambiguously read on any resource.
READ_VERBS: frozenset[str] = frozenset({
    "get", "list", "watch",
})


# Verbs that mutate data but stay within the workload.
WRITE_VERBS: frozenset[str] = frozenset({
    "update", "patch", "apply", "create",
})


# RBAC + cluster-admin verbs — admin regardless of resource.
ADMIN_VERBS: frozenset[str] = frozenset({
    "impersonate", "escalate", "bind", "approve",
})


# RBAC-shape resource substrings — when present in the resource path,
# the action escalates to ADMIN even for read verbs (RBAC discovery is
# itself sensitive). The match is case-insensitive substring.
ADMIN_RESOURCE_HINTS: tuple[str, ...] = (
    "clusterrolebinding",
    "rolebinding",
    "clusterrole",
    "role",  # matches K8s Role (RBAC), not "container role" etc.
    "serviceaccount",
    "podsecuritypolicy",
    "validatingwebhookconfiguration",
    "mutatingwebhookconfiguration",
    "customresourcedefinition",
    "namespace",  # namespace create/delete is admin
    "secret",
)


# Resource substrings that — combined with `delete` (or `delete-collection`)
# — escalate to DESTRUCTIVE_DATA. Case-insensitive substring.
DESTRUCTIVE_RESOURCE_HINTS: tuple[str, ...] = (
    "deployment",
    "statefulset",
    "daemonset",
    "replicaset",
    "pod",
    "node",
    "persistentvolume",
    "persistentvolumeclaim",
    "namespace",
    "job",
    "cronjob",
)


# Delete-shape verbs — combined with DESTRUCTIVE_RESOURCE_HINTS to
# classify as DESTRUCTIVE_DATA. Otherwise still WRITE_DATA.
DELETE_VERBS: frozenset[str] = frozenset({
    "delete", "deletecollection", "delete-collection",
})


__all__ = [
    "READ_VERBS",
    "WRITE_VERBS",
    "ADMIN_VERBS",
    "ADMIN_RESOURCE_HINTS",
    "DESTRUCTIVE_RESOURCE_HINTS",
    "DELETE_VERBS",
]
