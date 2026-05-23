"""F.5 — MITRE ATLAS technique tagging for flagged anomalies.

Per ``[[anomaly-detection-mode-phase-h]]`` industry-research addition
F.5 (Falco Feeds pattern): every flagged anomaly carries one or more
MITRE ATLAS technique IDs so compliance buyers (PCI / SOC 2 / HIPAA)
get audit-friendly framing.

We ship a STATIC catalog that maps common adversarial action shapes
to ATLAS technique IDs. The mapping is conservative: we only tag an
action when the shape is unambiguous; otherwise we return an empty
list (no false-positive tagging).

The catalog covers:
  * MITRE ATLAS (AI / agent security) — the primary framework for the
    iam-jit use case.
  * MITRE ATT&CK (general adversary tactics) — included for actions
    that pre-date the AI agent vocabulary (IAM persistence, S3 exfil,
    etc.).

Per ``[[scorer-is-ground-truth]]`` the catalog is DETERMINISTIC: a
substring match on action verb + service prefix. No LLM. This keeps
the tagging explainable + cheap.

This catalog is intentionally a single source of truth so calibration
work (#404 deny-classifier + #407 threat-feed entries) can reference
the same identifiers. When in doubt, the threat-feed's
``compliance_tags`` list overrides + extends per-entry.
"""

from __future__ import annotations

import re

# ---------------------------------------------------------------------------
# Public catalog
# ---------------------------------------------------------------------------
#
# Mapping shape:
#   { canonical_pattern: (technique_id, technique_name) }
#
# Where ``canonical_pattern`` is a lowercase substring matched against
# the action string (or a regex when we need word-boundary precision).
# Returned tags are LISTS so a single action can carry multiple
# techniques (e.g. iam:CreateAccessKey covers BOTH persistence +
# valid-accounts).
#
# IDs use the MITRE convention: ``T#####`` for ATT&CK + ATLAS shares
# the prefix. We label per entry whether it's ATT&CK or ATLAS so
# auditors can filter by framework.

_CATALOG: dict[str, list[tuple[str, str, str]]] = {
    # ---------- IAM persistence (ATT&CK + ATLAS overlap) -----------------
    "iam:createaccesskey": [
        ("T1098.001", "Account Manipulation: Additional Cloud Credentials",
         "ATT&CK"),
        ("T1078.004", "Valid Accounts: Cloud Accounts", "ATT&CK"),
    ],
    "iam:createuser": [
        ("T1136.003", "Create Account: Cloud Account", "ATT&CK"),
    ],
    "iam:createloginprofile": [
        ("T1098.001", "Account Manipulation: Additional Cloud Credentials",
         "ATT&CK"),
    ],
    "iam:updateloginprofile": [
        ("T1098.001", "Account Manipulation: Additional Cloud Credentials",
         "ATT&CK"),
    ],
    "iam:attachuserpolicy": [
        ("T1098.003", "Account Manipulation: Additional Cloud Roles",
         "ATT&CK"),
    ],
    "iam:putuserpolicy": [
        ("T1098.003", "Account Manipulation: Additional Cloud Roles",
         "ATT&CK"),
    ],
    "iam:addusertogroup": [
        ("T1098.003", "Account Manipulation: Additional Cloud Roles",
         "ATT&CK"),
    ],
    "iam:passrole": [
        ("T1078.004", "Valid Accounts: Cloud Accounts", "ATT&CK"),
    ],
    "iam:deactivatemfadevice": [
        ("T1556.006", "Modify Authentication Process: Multi-Factor "
                       "Authentication", "ATT&CK"),
    ],
    # ---------- Cover-tracks --------------------------------------------
    "cloudtrail:stoplogging": [
        ("T1562.008", "Impair Defenses: Disable or Modify Cloud Logs",
         "ATT&CK"),
    ],
    "cloudtrail:deletetrail": [
        ("T1562.008", "Impair Defenses: Disable or Modify Cloud Logs",
         "ATT&CK"),
    ],
    "config:deleteconfigurationrecorder": [
        ("T1562.008", "Impair Defenses: Disable or Modify Cloud Logs",
         "ATT&CK"),
    ],
    "guardduty:deletedetector": [
        ("T1562.001", "Impair Defenses: Disable or Modify Tools",
         "ATT&CK"),
    ],
    "logs:deleteloggroup": [
        ("T1070.004", "Indicator Removal: File Deletion", "ATT&CK"),
    ],
    # ---------- Destruction ---------------------------------------------
    "s3:deletebucket": [
        ("T1485", "Data Destruction", "ATT&CK"),
    ],
    "kms:schedulekeydeletion": [
        ("T1485", "Data Destruction", "ATT&CK"),
        ("T1486", "Data Encrypted for Impact", "ATT&CK"),
    ],
    # ---------- Data exfil shape ----------------------------------------
    "s3:putbucketpolicy": [
        ("T1537", "Transfer Data to Cloud Account", "ATT&CK"),
    ],
    "s3:putobjectacl": [
        ("T1537", "Transfer Data to Cloud Account", "ATT&CK"),
    ],
    "ec2:modifysnapshotattribute": [
        ("T1537", "Transfer Data to Cloud Account", "ATT&CK"),
    ],
    "rds:modifydbsnapshotattribute": [
        ("T1537", "Transfer Data to Cloud Account", "ATT&CK"),
    ],
    # ---------- ATLAS — AI agent specific -------------------------------
    # ATLAS T0051 (LLM Prompt Injection) — surfaced when classifier
    # flagged the action as appears_adversarial AND the action came
    # via an MCP / agent-context channel. Detector adds this tag when
    # the cold-start fallback or classifier signal fires.
    "_atlas_prompt_injection": [
        ("AML.T0051", "LLM Prompt Injection", "ATLAS"),
    ],
    # ATLAS T0053 (LLM Plugin Compromise) — agent-driven supply chain.
    "_atlas_plugin_compromise": [
        ("AML.T0053", "LLM Plugin Compromise", "ATLAS"),
    ],
    # ATLAS T0017 (Develop Capabilities) — abnormal agent self-extension
    # (e.g. an agent creating new IAM identities to extend its reach).
    "_atlas_develop_capabilities": [
        ("AML.T0017", "Develop Capabilities", "ATLAS"),
    ],
}


# Regex-based patterns for things like "DROP TABLE" that don't have a
# stable verb prefix. Each entry: (compiled_pattern, list_of_(id,name,fw))
_REGEX_PATTERNS: list[tuple[re.Pattern[str], list[tuple[str, str, str]]]] = [
    (
        re.compile(r"\bdrop\s+(table|database|schema)\b", re.IGNORECASE),
        [("T1485", "Data Destruction", "ATT&CK")],
    ),
    (
        re.compile(r"\btruncate\s+table\b", re.IGNORECASE),
        [("T1485", "Data Destruction", "ATT&CK")],
    ),
    (
        re.compile(r"\bdelete\s+from\s+\w+\s*(;|$)", re.IGNORECASE),
        [("T1485", "Data Destruction", "ATT&CK")],
    ),
    (
        re.compile(r"\bkubectl\s+delete\s+(namespace|--all)\b", re.IGNORECASE),
        [("T1485", "Data Destruction", "ATT&CK")],
    ),
]


def map_action_to_atlas_techniques(
    action: str,
    *,
    include_atlas_ai_signals: bool = False,
) -> list[dict[str, str]]:
    """Return the list of MITRE technique tags that apply to ``action``.

    Each tag is a dict shaped::

        {"id": "T1098.001", "name": "Account Manipulation: ...",
         "framework": "ATT&CK"}

    When ``include_atlas_ai_signals`` is True we also append ATLAS AI-
    specific tags that aren't action-derived (e.g. AML.T0051 prompt
    injection). The detector turns this on when the cold-start fallback
    or the #404 classifier flagged the action as adversarial — so the
    audit trail carries the AI-side framing alongside the IAM-shape
    framing.

    Returns an empty list when no pattern matches; never raises.
    """
    if not action:
        return []
    norm = action.strip().lower()
    tags: list[dict[str, str]] = []
    seen: set[str] = set()

    direct = _CATALOG.get(norm)
    if direct:
        for tid, tname, fw in direct:
            if tid not in seen:
                tags.append({"id": tid, "name": tname, "framework": fw})
                seen.add(tid)

    for pat, entries in _REGEX_PATTERNS:
        if pat.search(action):
            for tid, tname, fw in entries:
                if tid not in seen:
                    tags.append({"id": tid, "name": tname, "framework": fw})
                    seen.add(tid)

    if include_atlas_ai_signals:
        for tid, tname, fw in _CATALOG["_atlas_prompt_injection"]:
            if tid not in seen:
                tags.append({"id": tid, "name": tname, "framework": fw})
                seen.add(tid)

    return tags


__all__ = ["map_action_to_atlas_techniques"]
