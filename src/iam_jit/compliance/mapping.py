# ADOPT-2 / #716 — curated compliance-control mapping data.
"""The curated, honest mapping from iam-jit *decision signals* to
compliance-framework control references.

This module is DATA + tiny pure matchers — no I/O, no LLM, no
inference. Every mapping entry asserts a *genuine, defensible*
correspondence between something iam-jit observes in the audit log
(a deny reason, a privilege-escalation action pattern, a write to a
gated resource, an MFA-gated grant, the mere existence of a
tamper-evident audit record, …) and a specific control in a published
framework. Per [[ibounce-honest-positioning]] we map ONLY where the
correspondence is real; where coverage is partial we say so via the
:data:`PARTIAL_COVERAGE_NOTES` and each control's ``rationale``.

Frameworks + versions covered (cited verbatim so an auditor can pin
the exact revision):

* ``owasp``     — OWASP Agentic AI Top 10 (2026)
* ``mitre``     — MITRE ATT&CK (Enterprise) techniques
* ``nist``      — NIST SP 800-53 Rev. 5
* ``soc2``      — SOC 2 Trust Services Criteria (2017, rev. 2022)
* ``eu-ai-act`` — EU AI Act (Regulation (EU) 2024/1689) articles

What this is NOT:

* It is NOT a certification. iam-jit-the-company holds no third-party
  attestations at v1.0 (see ``docs/compliance/COMPLIANCE-MAPPING.md``).
  This overlay maps OBSERVED bouncer/IAM activity to the controls that
  activity touches — evidence of technical-control exercise, not a
  compliance claim.
* It is NOT exhaustive per framework. Many controls (physical security,
  governance, training, data-subject rights) are simply not observable
  from a bouncer audit log; those are out of scope and named so in
  :data:`PARTIAL_COVERAGE_NOTES`.
"""

from __future__ import annotations

import dataclasses
import re


# ---------------------------------------------------------------------------
# Framework registry — id -> (display name, cited version)
# ---------------------------------------------------------------------------

FRAMEWORKS: dict[str, dict[str, str]] = {
    "owasp": {
        "name": "OWASP Agentic AI Top 10",
        "version": "2026",
    },
    "mitre": {
        "name": "MITRE ATT&CK (Enterprise)",
        "version": "ATT&CK Enterprise",
    },
    "nist": {
        "name": "NIST SP 800-53",
        "version": "Rev. 5",
    },
    "soc2": {
        "name": "SOC 2 Trust Services Criteria",
        "version": "TSC 2017 (rev. 2022)",
    },
    "eu-ai-act": {
        "name": "EU AI Act",
        "version": "Regulation (EU) 2024/1689",
    },
}

FRAMEWORK_IDS: tuple[str, ...] = tuple(FRAMEWORKS.keys())


# ---------------------------------------------------------------------------
# Control reference catalog
# ---------------------------------------------------------------------------


@dataclasses.dataclass(frozen=True)
class ControlRef:
    """One framework control + the human rationale for the mapping.

    ``framework`` is one of :data:`FRAMEWORK_IDS`; ``control`` is the
    canonical tag emitted in the overlay (e.g. ``NIST-AC-6``,
    ``OWASP-AGENTIC-T01``, ``MITRE-T1078``). ``title`` is the control's
    published name; ``rationale`` states WHY this iam-jit signal maps
    to it (the honesty contract — a reader can judge the mapping).
    """

    framework: str
    control: str
    title: str
    rationale: str

    def as_dict(self) -> dict[str, str]:
        return {
            "framework": self.framework,
            "control": self.control,
            "title": self.title,
            "rationale": self.rationale,
        }


def _c(framework: str, control: str, title: str, rationale: str) -> ControlRef:
    return ControlRef(
        framework=framework, control=control, title=title, rationale=rationale
    )


# The control catalog. Keyed by tag so an entry is defined once and
# reused across signals. Tags are stable, grep-friendly identifiers.
CONTROLS: dict[str, ControlRef] = {
    # --- OWASP Agentic AI Top 10 (2026) ---
    "OWASP-AGENTIC-T01": _c(
        "owasp", "OWASP-AGENTIC-T01", "Excessive Agency / Permissions",
        "An agent granted or attempting more authority than its task "
        "needs. iam-jit's least-privilege scoring + a DENY of an "
        "out-of-scope action are direct counter-measures.",
    ),
    "OWASP-AGENTIC-T02": _c(
        "owasp", "OWASP-AGENTIC-T02", "Privilege Compromise / Escalation",
        "An agent attempting to widen its own privileges (IAM policy "
        "attach, role assume-into-broader, trust-policy edit). A DENY "
        "of such an action is the control in action.",
    ),
    "OWASP-AGENTIC-T05": _c(
        "owasp", "OWASP-AGENTIC-T05", "Cascading / Unbounded Action Risk",
        "Destructive or mass-mutation operations (delete, drop, "
        "terminate) whose blast radius an agent may not bound. iam-jit "
        "gates these so a single agent step cannot cascade unchecked.",
    ),
    "OWASP-AGENTIC-T06": _c(
        "owasp", "OWASP-AGENTIC-T06", "Sensitive Data / Resource Exposure",
        "Reads or exfil-shaped access to credential stores, secrets, or "
        "sensitive datastores. Gating + audit of these accesses maps "
        "here.",
    ),
    "OWASP-AGENTIC-T08": _c(
        "owasp", "OWASP-AGENTIC-T08", "Insufficient Monitoring / Traceability",
        "Every gated decision iam-jit records (allow OR deny, with "
        "actor, action, resource, verdict, timestamp) is the positive "
        "control: the agent's actions are observable + attributable.",
    ),
    # --- MITRE ATT&CK (Enterprise) ---
    "MITRE-T1078": _c(
        "mitre", "MITRE-T1078", "Valid Accounts",
        "Use of valid credentials/roles for access. iam-jit issuing + "
        "auditing short-lived scoped credentials, and denying use "
        "outside scope, is the detection/mitigation surface.",
    ),
    "MITRE-T1098": _c(
        "mitre", "MITRE-T1098", "Account Manipulation",
        "Modifying accounts/policies to maintain or widen access "
        "(IAM PutUserPolicy, AttachRolePolicy, CreateAccessKey, trust "
        "edits). A DENY of these is detection + prevention.",
    ),
    "MITRE-T1548": _c(
        "mitre", "MITRE-T1548", "Abuse Elevation Control Mechanism",
        "Privilege-elevation attempts (assume a broader role, "
        "PassRole into escalation). iam-jit's gate is the elevation "
        "control; a deny is the abuse caught.",
    ),
    "MITRE-T1530": _c(
        "mitre", "MITRE-T1530", "Data from Cloud Storage",
        "Bulk reads from cloud object storage / databases. Gating + "
        "audit of S3/datastore reads maps to detection of this "
        "technique.",
    ),
    "MITRE-T1485": _c(
        "mitre", "MITRE-T1485", "Data Destruction",
        "Destructive operations (delete-bucket, drop-table, "
        "terminate-instance). iam-jit gating these and recording the "
        "verdict is the control.",
    ),
    "MITRE-T1110": _c(
        "mitre", "MITRE-T1110", "Brute Force",
        "An anomaly-flagged event the bouncer surfaced (a single "
        "boundary-probe / out-of-pattern access) is recorded as "
        "candidate brute-force / enumeration behaviour. This overlay "
        "tags the individual flagged event; it does not itself correlate "
        "repetition across events.",
    ),
    # --- NIST SP 800-53 Rev. 5 ---
    "NIST-AC-2": _c(
        "nist", "NIST-AC-2", "Account Management",
        "iam-jit creates short-lived, scoped principals per task and "
        "audits their lifecycle; account-manipulation attempts are "
        "gated.",
    ),
    "NIST-AC-3": _c(
        "nist", "NIST-AC-3", "Access Enforcement",
        "Every gated call is an access-enforcement decision: the "
        "bouncer/IAM authority allows or denies per policy.",
    ),
    "NIST-AC-6": _c(
        "nist", "NIST-AC-6", "Least Privilege",
        "Denying out-of-scope / over-broad actions and recommending "
        "narrowed policies directly enforces least privilege.",
    ),
    "NIST-AU-2": _c(
        "nist", "NIST-AU-2", "Event Logging",
        "Every gated decision is recorded as an auditable event with "
        "the required content.",
    ),
    "NIST-AU-12": _c(
        "nist", "NIST-AU-12", "Audit Record Generation",
        "iam-jit/bouncer generate the structured OCSF audit record for "
        "each decision; this overlay is itself a projection of those "
        "records.",
    ),
    "NIST-SI-4": _c(
        "nist", "NIST-SI-4", "System Monitoring",
        "Anomaly-scored events + repeated-deny patterns surfaced in the "
        "audit stream constitute monitoring of agent activity.",
    ),
    # --- SOC 2 Trust Services Criteria ---
    "SOC2-CC6.1": _c(
        "soc2", "SOC2-CC6.1", "Logical Access Security Controls",
        "The gate (allow/deny per scored policy) restricting logical "
        "access to information assets.",
    ),
    "SOC2-CC6.3": _c(
        "soc2", "SOC2-CC6.3", "Access Based on Least Privilege / Roles",
        "Scoped, time-bounded grants + denial of out-of-scope actions "
        "implement role-/least-privilege-based access.",
    ),
    "SOC2-CC6.6": _c(
        "soc2", "SOC2-CC6.6", "Protection Against External Threats",
        "MFA-gated grants + denial of credential-manipulation attempts "
        "protect access boundaries.",
    ),
    "SOC2-CC7.2": _c(
        "soc2", "SOC2-CC7.2", "Anomaly / Security Event Monitoring",
        "Audit-stream monitoring + anomaly scoring of agent actions.",
    ),
    "SOC2-CC7.3": _c(
        "soc2", "SOC2-CC7.3", "Evaluation of Security Events",
        "Repeated-deny / boundary-probe detection evaluates events for "
        "whether they represent a security incident.",
    ),
    # --- EU AI Act (Regulation (EU) 2024/1689) ---
    "EU-AI-ACT-ART12": _c(
        "eu-ai-act", "EU-AI-ACT-ART12", "Record-Keeping / Logging",
        "Art. 12 requires automatic logging of events over a "
        "high-risk AI system's lifetime. iam-jit's per-decision audit "
        "record is exactly such automatic logging for agent actions.",
    ),
    "EU-AI-ACT-ART14": _c(
        "eu-ai-act", "EU-AI-ACT-ART14", "Human Oversight",
        "Art. 14 requires effective human oversight. iam-jit's "
        "approval gate + a DENY that forces a human decision are the "
        "oversight mechanism for agent actions.",
    ),
    "EU-AI-ACT-ART15": _c(
        "eu-ai-act", "EU-AI-ACT-ART15", "Accuracy, Robustness & Cybersecurity",
        "Art. 15 requires resilience against attempts to alter use or "
        "behaviour. Denying privilege-escalation + destructive actions "
        "is a cybersecurity safeguard for the agent system.",
    ),
}


# ---------------------------------------------------------------------------
# Decision-signal -> control mapping
# ---------------------------------------------------------------------------
#
# A "signal" is something we can detect off a single audit event with
# pure logic. Each MappingRule names the signal, the controls it maps
# to, and (where relevant) the protocols it applies to. The overlay
# walks every event, fires the matching rules, and tags the event with
# the union of the controls.


# Signal kinds (the rule's matcher dimension).
SIGNAL_DENY = "deny"                       # event verdict == deny
SIGNAL_ALLOW = "allow"                     # event verdict == allow
SIGNAL_ANY = "any"                         # any recorded decision
SIGNAL_ACTION_RE = "action_regex"          # action matches a regex
SIGNAL_ANOMALOUS = "anomalous"             # anomaly_verdict == anomalous
SIGNAL_MFA_GATED = "mfa_gated"             # event carries mfa-present signal


@dataclasses.dataclass(frozen=True)
class MappingRule:
    """One signal -> controls mapping.

    ``signal`` is a SIGNAL_* kind. For ``action_regex`` rules,
    ``action_pattern`` is a compiled, case-insensitive regex matched
    against the event's ``service:Action`` string. ``protocols`` (when
    non-empty) restricts the rule to events from those protocol kinds
    (``aws`` / ``k8s`` / ``sql`` / ``http``); empty == all protocols.
    ``category`` is a short operator-facing label for the report.
    """

    rule_id: str
    signal: str
    controls: tuple[str, ...]
    category: str
    action_pattern: re.Pattern[str] | None = None
    protocols: tuple[str, ...] = ()

    def control_refs(self) -> tuple[ControlRef, ...]:
        return tuple(CONTROLS[c] for c in self.controls)


def _re(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


# Action-pattern catalog. Patterns are deliberately cross-protocol:
# AWS IAM actions, K8s verbs/resources, SQL statements, and HTTP
# methods/paths all flow through `service:Action` form, so one regex
# family can match the dangerous shape regardless of bouncer.
#
# Privilege-escalation / account-manipulation shapes.
_PRIV_ESC_RE = _re(
    r"(?:"
    # AWS IAM mutation of policies / keys / trust
    r"iam:(?:Put.*Policy|Attach.*Policy|PutRolePolicy|CreateAccessKey|"
    r"UpdateAssumeRolePolicy|CreatePolicyVersion|SetDefaultPolicyVersion|"
    r"AddUserToGroup|CreateLoginProfile|UpdateLoginProfile)"
    r"|sts:AssumeRole.*"
    r"|iam:PassRole"
    # K8s RBAC widening
    r"|.*:(?:create|update|patch).*(?:clusterrolebinding|rolebinding|"
    r"clusterrole)"
    # SQL grant / privilege widening
    r"|(?:sql|postgres|mysql):.*(?:GRANT|ALTER\s+ROLE|CREATE\s+ROLE|"
    r"ALTER\s+USER)"
    r")"
)

# Destructive / cascading shapes.
_DESTRUCTIVE_RE = _re(
    r"(?:"
    r".*:(?:Delete|Terminate|Destroy|Purge|RemovePermission)"
    r"|.*:(?:delete|deletecollection)"            # K8s delete verbs
    r"|(?:sql|postgres|mysql):.*(?:DROP|TRUNCATE|DELETE\s+FROM)"
    r"|(?:DELETE|PUT)$"                            # bare HTTP destructive methods
    r")"
)

# Sensitive-data / secrets / bulk-read shapes.
_SENSITIVE_READ_RE = _re(
    r"(?:"
    r"secretsmanager:GetSecretValue|ssm:GetParameter.*|kms:Decrypt"
    r"|s3:GetObject|s3:ListBucket|dynamodb:(?:Scan|Query|GetItem|BatchGetItem)"
    r"|.*:(?:get|list|watch).*secret"             # K8s secret reads
    r"|(?:sql|postgres|mysql):.*SELECT"
    r")"
)


MAPPING_RULES: tuple[MappingRule, ...] = (
    # Every recorded decision is an auditable, traceable event.
    MappingRule(
        rule_id="audit_traceability",
        signal=SIGNAL_ANY,
        controls=(
            "OWASP-AGENTIC-T08",
            "NIST-AU-2",
            "NIST-AU-12",
            "SOC2-CC6.1",
            "EU-AI-ACT-ART12",
        ),
        category="audit/traceability",
    ),
    # Any ALLOW is an access-enforcement decision that ran.
    MappingRule(
        rule_id="access_enforced_allow",
        signal=SIGNAL_ALLOW,
        controls=("NIST-AC-3", "SOC2-CC6.1"),
        category="access-enforcement",
    ),
    # Any DENY is least-privilege enforcement + human-oversight trigger.
    MappingRule(
        rule_id="least_privilege_deny",
        signal=SIGNAL_DENY,
        controls=(
            "OWASP-AGENTIC-T01",
            "NIST-AC-3",
            "NIST-AC-6",
            "SOC2-CC6.3",
            "EU-AI-ACT-ART14",
        ),
        category="least-privilege",
    ),
    # Privilege-escalation / account-manipulation attempt.
    MappingRule(
        rule_id="privilege_escalation",
        signal=SIGNAL_ACTION_RE,
        action_pattern=_PRIV_ESC_RE,
        controls=(
            "OWASP-AGENTIC-T02",
            "MITRE-T1098",
            "MITRE-T1548",
            "NIST-AC-2",
            "NIST-AC-6",
            "SOC2-CC6.6",
            "EU-AI-ACT-ART15",
        ),
        category="privilege-escalation",
    ),
    # Destructive / cascading action.
    MappingRule(
        rule_id="destructive_action",
        signal=SIGNAL_ACTION_RE,
        action_pattern=_DESTRUCTIVE_RE,
        controls=(
            "OWASP-AGENTIC-T05",
            "MITRE-T1485",
            "NIST-AC-6",
            "EU-AI-ACT-ART15",
        ),
        category="destructive-action",
    ),
    # Sensitive data / secrets / bulk read.
    MappingRule(
        rule_id="sensitive_read",
        signal=SIGNAL_ACTION_RE,
        action_pattern=_SENSITIVE_READ_RE,
        controls=(
            "OWASP-AGENTIC-T06",
            "MITRE-T1530",
            "NIST-AC-6",
        ),
        category="sensitive-data-access",
    ),
    # Valid-account use: any decision against a credentialed action is
    # the Valid-Accounts surface (allow = use; deny = misuse caught).
    MappingRule(
        rule_id="valid_accounts",
        signal=SIGNAL_ANY,
        controls=("MITRE-T1078",),
        category="valid-accounts",
    ),
    # Anomalous event (pre-scored by the anomaly hook).
    MappingRule(
        rule_id="anomaly_monitoring",
        signal=SIGNAL_ANOMALOUS,
        controls=(
            "NIST-SI-4",
            "SOC2-CC7.2",
            "SOC2-CC7.3",
            "MITRE-T1110",
        ),
        category="anomaly-monitoring",
    ),
    # MFA-gated grant (event carries an mfa-present assertion).
    MappingRule(
        rule_id="mfa_gated",
        signal=SIGNAL_MFA_GATED,
        controls=("SOC2-CC6.6",),
        category="mfa",
    ),
)


# ---------------------------------------------------------------------------
# Honest partial-coverage disclosure
# ---------------------------------------------------------------------------
#
# Per [[ibounce-honest-positioning]]: name exactly what this overlay
# does NOT cover, per framework. A bouncer audit log cannot evidence
# governance, training, physical security, or data-subject-rights
# controls; saying so is the honesty contract.

PARTIAL_COVERAGE_NOTES: dict[str, str] = {
    "owasp": (
        "Covers the Top-10 risks observable as agent ACTIONS (excessive "
        "agency, privilege compromise, cascading actions, data exposure, "
        "traceability). Risks rooted in model internals / prompt content "
        "(e.g. memory poisoning, goal manipulation) are NOT observable "
        "from the bouncer audit log and are out of scope here."
    ),
    "mitre": (
        "Maps techniques whose on-the-wire shape a bouncer sees "
        "(Valid Accounts, Account Manipulation, Abuse Elevation, Data "
        "from Cloud Storage, Data Destruction, anomaly-flagged "
        "boundary-probe events). It is NOT a full ATT&CK coverage "
        "matrix; many "
        "techniques (initial access, C2, lateral movement off-path) "
        "leave no signal in this audit stream."
    ),
    "nist": (
        "Maps the access-control (AC) + audit (AU) + monitoring (SI-4) "
        "family controls that a per-decision audit log evidences. "
        "Controls outside that observable surface (e.g. CM, CP, MP, PE, "
        "PL families) are NOT addressed by this overlay."
    ),
    "soc2": (
        "Maps the CC6 (logical access) + CC7 (operations/monitoring) "
        "criteria the gate + audit log evidence. Other Trust Services "
        "criteria (availability, processing integrity, confidentiality "
        "of stored data, privacy) are NOT evidenced by this overlay."
    ),
    "eu-ai-act": (
        "Maps Art. 12 (record-keeping), Art. 14 (human oversight via "
        "the approval/deny gate), and Art. 15 (cybersecurity safeguards). "
        "Other obligations (risk management system Art. 9, data "
        "governance Art. 10, transparency Art. 13, conformity "
        "assessment) are organisational/process controls NOT evidenced "
        "from a bouncer audit log."
    ),
}


# ---------------------------------------------------------------------------
# Catalog accessors (used by the overlay + report)
# ---------------------------------------------------------------------------


def controls_for_framework(framework: str) -> list[ControlRef]:
    """Every catalog control belonging to ``framework`` (sorted)."""
    return sorted(
        (c for c in CONTROLS.values() if c.framework == framework),
        key=lambda c: c.control,
    )


def validate_catalog() -> None:
    """Sanity-check that every rule references a defined control and
    every control names a registered framework. Called by the test
    suite; cheap enough to run at import-time guard if desired."""
    for rule in MAPPING_RULES:
        for c in rule.controls:
            if c not in CONTROLS:
                raise ValueError(
                    f"rule {rule.rule_id!r} references unknown control {c!r}"
                )
    for tag, ref in CONTROLS.items():
        if ref.control != tag:
            raise ValueError(
                f"control catalog key {tag!r} != ControlRef.control "
                f"{ref.control!r}"
            )
        if ref.framework not in FRAMEWORKS:
            raise ValueError(
                f"control {tag!r} names unknown framework {ref.framework!r}"
            )


def framework_meta(framework: str) -> dict[str, str]:
    """Return ``{id, name, version}`` for a framework id."""
    meta = FRAMEWORKS[framework]
    return {"id": framework, "name": meta["name"], "version": meta["version"]}
