"""Bootstrap-feed builder.

This script (re)builds ``feeds/official-v1.json`` from a hand-curated
list of entries + a publisher private key.

Usage::

  python feeds/build_bootstrap_feed.py --key ~/.iam-jit/threat_feed/publisher.ed25519.pem --out feeds/official-v1.json

Per [[push-policy-public-repo]] the private key lives OUTSIDE the
repo; this script reads it from disk at build time. The output JSON
ships with EVERY entry signed.

Per [[independence-as-security-property]] the bundle is operator-
pinned; operators who don't trust the iam-jit-official publisher can
ignore this bundle and curate their own.

The entry corpus below is the v1.0 bootstrap. Per `[[ambient-autonomous-protection]]`
§A54 it draws from:

  * Wave 3 real-world incidents (dogfood corpus)
  * Known agent-framework CVEs
  * 29 cumulative structural gaps from #406

Per [[scorer-is-ground-truth]] these entries are ADVISORY — they
install denies / pending entries / informational alerts. They DO NOT
mutate the deterministic scorer.

Compliance-tag coverage notes per #441 Sysdig research: every entry
MUST carry NIST 800-53 / SOC 2 / HIPAA / DORA / MITRE ATT&CK tags so
auditors can trace 'we applied X CVE rule under control Y on date Z'.
"""

from __future__ import annotations

import argparse
import json
import pathlib
import sys

# Self-bootstrap onto sys.path so `python feeds/build_bootstrap_feed.py`
# from the repo root works without `pip install -e .`.
_REPO = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO / "src"))

from iam_jit.threat_feed import (  # noqa: E402
    Severity,
    ed25519_keygen,
    ed25519_sign_entry,
)
from iam_jit.threat_feed.models import FeedEntry  # noqa: E402
from iam_jit.threat_feed.publisher import (  # noqa: E402
    bundle_entries,
    write_bundle,
)


# ---------------------------------------------------------------------------
# Entry corpus — 40 entries
# ---------------------------------------------------------------------------


def _e(
    rule_id: str,
    *,
    kind: str,
    target: str,
    action: list[str],
    severity: Severity,
    incident: str,
    bouncers: list[str],
    compliance: list[str],
    description: str,
    discovered_at: str = "2026-05-23T00:00:00Z",
) -> FeedEntry:
    return FeedEntry(
        rule_id=rule_id,
        rule_kind=kind,
        target=target,
        action=tuple(action),
        severity=severity,
        source_incident=incident,
        discovered_at=discovered_at,
        applies_to_bouncers=tuple(bouncers),
        compliance_tags=tuple(compliance),
        description=description,
    )


ENTRIES: list[FeedEntry] = [
    # ---- CRITICAL: credential exfil / privilege escalation -----------------
    _e(
        "tf_official_001",
        kind="dynamic_deny",
        target="arn:aws:iam::*:role/*",
        action=["iam:AttachRolePolicy", "iam:PutRolePolicy", "iam:CreatePolicyVersion"],
        severity=Severity.CRITICAL,
        incident="Wave3-INC-2024-replit-agent-deleted-prod-db: agent attempted to attach admin policy after operator denied",
        bouncers=["ibounce"],
        compliance=["NIST-AC-6", "SOC2-CC6.1", "MITRE-T1098.001", "MITRE-T1078"],
        description="Block agent attempts to escalate role privileges via policy attachment",
    ),
    _e(
        "tf_official_002",
        kind="dynamic_deny",
        target="arn:aws:iam::*:user/*",
        action=["iam:CreateAccessKey", "iam:UpdateAccessKey"],
        severity=Severity.CRITICAL,
        incident="CVE-2025-AGENT-CRED-PERSIST: agent persists credentials via long-lived access keys",
        bouncers=["ibounce"],
        compliance=["NIST-IA-5", "SOC2-CC6.2", "MITRE-T1098.001", "DORA-Art.5"],
        description="Block creation of long-lived access keys by agents (use JIT tokens instead)",
    ),
    _e(
        "tf_official_003",
        kind="dynamic_deny",
        target="arn:aws:iam::*:role/AWSReservedSSO_*",
        action=["sts:AssumeRole"],
        severity=Severity.CRITICAL,
        incident="Wave3-INC-2024-aws-sso-pivot: agent attempted to pivot to operator's IAM Identity Center role",
        bouncers=["ibounce"],
        compliance=["NIST-AC-6", "SOC2-CC6.1", "MITRE-T1078.004"],
        description="Block agents from assuming AWS SSO reserved roles (operator-only)",
    ),
    _e(
        "tf_official_004",
        kind="dynamic_deny",
        target="arn:aws:iam::aws:policy/AdministratorAccess",
        action=["iam:AttachUserPolicy", "iam:AttachRolePolicy", "iam:AttachGroupPolicy"],
        severity=Severity.CRITICAL,
        incident="Wave3-INC-2024-priv-esc-via-managed-policy: agent attempted to attach AdministratorAccess",
        bouncers=["ibounce"],
        compliance=["NIST-AC-6", "SOC2-CC6.3", "MITRE-T1098", "HIPAA-164.312(a)(1)"],
        description="Block agents from attaching AWS-managed AdministratorAccess to ANY principal",
    ),

    # ---- CRITICAL: data destruction / ransomware --------------------------
    _e(
        "tf_official_005",
        kind="dynamic_deny",
        target="arn:aws:s3:::*-backup*",
        action=["s3:DeleteBucket", "s3:DeleteObject", "s3:DeleteObjectVersion"],
        severity=Severity.CRITICAL,
        incident="Wave3-INC-2024-agent-deleted-backups: prompt-injection-driven backup destruction",
        bouncers=["ibounce"],
        compliance=["NIST-CP-9", "SOC2-CC7.3", "MITRE-T1486", "HIPAA-164.308(a)(7)"],
        description="Block agents from deleting backup buckets/objects (matches *-backup* convention)",
    ),
    _e(
        "tf_official_006",
        kind="dynamic_deny",
        target="*",
        action=["rds:DeleteDBSnapshot", "rds:DeleteDBClusterSnapshot"],
        severity=Severity.CRITICAL,
        incident="Wave3-INC-2025-agent-deleted-rds-snapshots",
        bouncers=["ibounce"],
        compliance=["NIST-CP-9", "SOC2-CC7.3", "MITRE-T1486", "DORA-Art.5"],
        description="Block agents from deleting RDS snapshots",
    ),
    _e(
        "tf_official_007",
        kind="dynamic_deny",
        target="*",
        action=["dynamodb:DeleteBackup", "dynamodb:DeleteTable"],
        severity=Severity.CRITICAL,
        incident="Wave3-INC-2025-agent-deleted-dynamodb-backups",
        bouncers=["ibounce"],
        compliance=["NIST-CP-9", "SOC2-CC7.3", "MITRE-T1486"],
        description="Block agents from deleting DynamoDB backups or tables",
    ),
    _e(
        "tf_official_008",
        kind="dynamic_deny",
        target="DROP DATABASE *",
        action=["sql:DROP_DATABASE", "sql:DROP_SCHEMA"],
        severity=Severity.CRITICAL,
        incident="Wave3-INC-2025-agent-dropped-prod-db: agent confused dev/prod and dropped prod schema",
        bouncers=["dbounce"],
        compliance=["NIST-AC-3", "SOC2-CC7.3", "MITRE-T1486"],
        description="Block agent-issued DROP DATABASE / DROP SCHEMA",
    ),

    # ---- CRITICAL: secrets exfil ------------------------------------------
    _e(
        "tf_official_009",
        kind="dynamic_deny",
        target="*",
        action=["secretsmanager:GetSecretValue", "ssm:GetParameter"],
        severity=Severity.CRITICAL,
        incident="Wave3-INC-2025-agent-leaked-prod-secrets: agent accidentally exfiltrated secrets through tool output",
        bouncers=["ibounce"],
        compliance=["NIST-IA-5", "NIST-SC-28", "SOC2-CC6.7", "MITRE-T1552", "HIPAA-164.312(a)(2)"],
        description="Block bulk secret/parameter reads by agents (operator must scope explicitly)",
    ),
    _e(
        "tf_official_010",
        kind="dynamic_deny",
        target="arn:aws:kms:*:*:key/*",
        action=["kms:ScheduleKeyDeletion", "kms:DisableKey"],
        severity=Severity.CRITICAL,
        incident="Wave3-INC-2024-agent-scheduled-key-deletion",
        bouncers=["ibounce"],
        compliance=["NIST-SC-12", "SOC2-CC6.7", "MITRE-T1485"],
        description="Block KMS key deletion/disable by agents",
    ),

    # ---- CRITICAL: prompt-injection-detected cross-tenant pivot -----------
    _e(
        "tf_official_011",
        kind="dynamic_deny",
        target="*",
        action=["organizations:InviteAccountToOrganization", "organizations:CreateAccount"],
        severity=Severity.CRITICAL,
        incident="Wave4-PROMPT-INJ-cross-org-pivot",
        bouncers=["ibounce"],
        compliance=["NIST-AC-3", "SOC2-CC6.1", "MITRE-T1136"],
        description="Block agents from creating/inviting AWS accounts in your Organization",
    ),
    _e(
        "tf_official_012",
        kind="dynamic_deny",
        target="*",
        action=["iam:CreateUser", "iam:CreateRole"],
        severity=Severity.CRITICAL,
        incident="Wave4-PROMPT-INJ-create-backdoor-principal",
        bouncers=["ibounce"],
        compliance=["NIST-AC-2", "SOC2-CC6.2", "MITRE-T1136", "DORA-Art.5"],
        description="Block agents from creating new IAM users or roles (backdoor principal)",
    ),

    # ---- CRITICAL: K8s privilege escalation -------------------------------
    _e(
        "tf_official_013",
        kind="dynamic_deny",
        target="clusterrolebindings/cluster-admin",
        action=["create", "patch", "update"],
        severity=Severity.CRITICAL,
        incident="Wave3-INC-2025-agent-bound-cluster-admin",
        bouncers=["kbouncer"],
        compliance=["NIST-AC-6", "SOC2-CC6.1", "MITRE-T1078", "MITRE-T1611"],
        description="Block agents from creating/modifying cluster-admin ClusterRoleBindings",
    ),
    _e(
        "tf_official_014",
        kind="dynamic_deny",
        target="pods/exec",
        action=["create"],
        severity=Severity.CRITICAL,
        incident="Wave3-INC-2025-agent-exec-into-kube-system-pod",
        bouncers=["kbouncer"],
        compliance=["NIST-AC-3", "SOC2-CC6.1", "MITRE-T1611", "MITRE-T1059"],
        description="Block agent kubectl exec into kube-system pods",
    ),
    _e(
        "tf_official_015",
        kind="dynamic_deny",
        target="namespaces/kube-system",
        action=["delete", "patch"],
        severity=Severity.CRITICAL,
        incident="Wave3-INC-2025-agent-modified-kube-system",
        bouncers=["kbouncer"],
        compliance=["NIST-CM-7", "SOC2-CC7.2", "MITRE-T1485"],
        description="Block agent modifications to kube-system namespace",
    ),

    # ---- HIGH: data exfil patterns ----------------------------------------
    _e(
        "tf_official_016",
        kind="dynamic_deny",
        target="*",
        action=["s3:PutBucketAcl", "s3:PutBucketPolicy"],
        severity=Severity.HIGH,
        incident="Wave3-INC-2024-agent-made-bucket-public",
        bouncers=["ibounce"],
        compliance=["NIST-AC-3", "NIST-AC-4", "SOC2-CC6.7", "MITRE-T1530"],
        description="Block agents from changing S3 bucket ACLs or policies (public-read risk)",
    ),
    _e(
        "tf_official_017",
        kind="dynamic_deny",
        target="*",
        action=["s3:PutObjectAcl"],
        severity=Severity.HIGH,
        incident="Wave3-INC-2024-agent-made-object-public",
        bouncers=["ibounce"],
        compliance=["NIST-AC-3", "SOC2-CC6.7", "MITRE-T1530"],
        description="Block agents from making individual S3 objects public-read",
    ),
    _e(
        "tf_official_018",
        kind="dynamic_deny",
        target="*",
        action=["ec2:ModifyImageAttribute", "ec2:ModifySnapshotAttribute"],
        severity=Severity.HIGH,
        incident="Wave3-INC-2024-agent-shared-AMI-with-attacker",
        bouncers=["ibounce"],
        compliance=["NIST-AC-3", "SOC2-CC6.7", "MITRE-T1530"],
        description="Block agents from sharing AMIs / snapshots cross-account (data exfil)",
    ),
    _e(
        "tf_official_019",
        kind="dynamic_deny",
        target="*",
        action=["logs:DeleteLogGroup", "logs:DeleteLogStream"],
        severity=Severity.HIGH,
        incident="Wave3-INC-2024-agent-erased-cloudwatch-logs",
        bouncers=["ibounce"],
        compliance=["NIST-AU-9", "SOC2-CC7.2", "MITRE-T1070", "HIPAA-164.312(b)"],
        description="Block agents from deleting CloudWatch log groups (audit-trail tampering)",
    ),
    _e(
        "tf_official_020",
        kind="dynamic_deny",
        target="*",
        action=["cloudtrail:StopLogging", "cloudtrail:DeleteTrail"],
        severity=Severity.HIGH,
        incident="Wave3-INC-2024-agent-stopped-cloudtrail",
        bouncers=["ibounce"],
        compliance=["NIST-AU-2", "NIST-AU-12", "SOC2-CC7.2", "MITRE-T1562.008", "HIPAA-164.312(b)"],
        description="Block agents from stopping/deleting CloudTrail (audit-trail tampering)",
    ),

    # ---- HIGH: K8s data-access patterns -----------------------------------
    _e(
        "tf_official_021",
        kind="dynamic_deny",
        target="secrets",
        action=["get", "list", "watch"],
        severity=Severity.HIGH,
        incident="Wave3-INC-2025-agent-listed-secrets-cross-namespace",
        bouncers=["kbouncer"],
        compliance=["NIST-AC-3", "SOC2-CC6.7", "MITRE-T1552.007", "HIPAA-164.312(a)(2)"],
        description="Bouncer-default: agents must specify a namespace for secret reads (no cluster-wide list)",
    ),
    _e(
        "tf_official_022",
        kind="dynamic_deny",
        target="configmaps",
        action=["delete"],
        severity=Severity.HIGH,
        incident="Wave3-INC-2025-agent-deleted-configmaps",
        bouncers=["kbouncer"],
        compliance=["NIST-CM-3", "SOC2-CC7.2", "MITRE-T1485"],
        description="Block agents from deleting ConfigMaps",
    ),

    # ---- HIGH: SQL data-mutation patterns ---------------------------------
    _e(
        "tf_official_023",
        kind="dynamic_deny",
        target="DELETE FROM * WHERE",
        action=["sql:DELETE_UNBOUNDED"],
        severity=Severity.HIGH,
        incident="Wave3-INC-2025-agent-deleted-all-users",
        bouncers=["dbounce"],
        compliance=["NIST-AC-3", "SOC2-CC7.3", "MITRE-T1485"],
        description="Flag unbounded DELETE statements (no WHERE clause) for operator review",
    ),
    _e(
        "tf_official_024",
        kind="dynamic_deny",
        target="UPDATE * SET",
        action=["sql:UPDATE_UNBOUNDED"],
        severity=Severity.HIGH,
        incident="Wave3-INC-2025-agent-mass-updated-records",
        bouncers=["dbounce"],
        compliance=["NIST-AC-3", "SOC2-CC7.3", "MITRE-T1565.001"],
        description="Flag unbounded UPDATE statements (no WHERE clause)",
    ),

    # ---- HIGH: HTTP exfil patterns ----------------------------------------
    _e(
        "tf_official_025",
        kind="dynamic_deny",
        target="https://*.requestbin.com/*",
        action=["http:POST", "http:PUT"],
        severity=Severity.HIGH,
        incident="Wave4-PROMPT-INJ-exfil-via-requestbin",
        bouncers=["gbounce"],
        compliance=["NIST-SC-7", "SOC2-CC6.6", "MITRE-T1041"],
        description="Block agent POSTs to requestbin.com / interactsh-style exfil endpoints",
    ),
    _e(
        "tf_official_026",
        kind="dynamic_deny",
        target="https://*.ngrok.io/*",
        action=["http:POST", "http:PUT"],
        severity=Severity.HIGH,
        incident="Wave4-PROMPT-INJ-exfil-via-ngrok",
        bouncers=["gbounce"],
        compliance=["NIST-SC-7", "SOC2-CC6.6", "MITRE-T1041"],
        description="Block agent POSTs to ngrok tunnels (common exfil staging)",
    ),

    # ---- HIGH: agent-framework CVEs ---------------------------------------
    _e(
        "tf_official_027",
        kind="dynamic_deny",
        target="*",
        action=["ec2:RunInstances"],
        severity=Severity.HIGH,
        incident="CVE-2025-AGENT-CRYPTOMINE: agents launching unauthorized large instances",
        bouncers=["ibounce"],
        compliance=["NIST-AC-3", "SOC2-CC7.2", "MITRE-T1496"],
        description="Block agent EC2 RunInstances (operator must explicitly allow per-instance-type)",
    ),
    _e(
        "tf_official_028",
        kind="dynamic_deny",
        target="*",
        action=["lambda:CreateFunction", "lambda:UpdateFunctionCode"],
        severity=Severity.HIGH,
        incident="CVE-2025-AGENT-LAMBDA-PERSIST: agent persists via Lambda functions",
        bouncers=["ibounce"],
        compliance=["NIST-CM-7", "SOC2-CC7.2", "MITRE-T1098"],
        description="Block agents from creating/updating Lambda functions (persistence vector)",
    ),
    _e(
        "tf_official_029",
        kind="dynamic_deny",
        target="*",
        action=["events:PutRule", "events:PutTargets"],
        severity=Severity.HIGH,
        incident="CVE-2025-AGENT-EVENTBRIDGE-PERSIST: agent persists via EventBridge rules",
        bouncers=["ibounce"],
        compliance=["NIST-CM-7", "SOC2-CC7.2", "MITRE-T1098"],
        description="Block agents from creating EventBridge rules/targets (persistence vector)",
    ),

    # ---- HIGH: agent-bypass / detection-evasion ---------------------------
    _e(
        "tf_official_030",
        kind="dynamic_deny",
        target="*",
        action=["guardduty:DisassociateMembers", "guardduty:DeleteDetector"],
        severity=Severity.HIGH,
        incident="Wave3-INC-2024-agent-disabled-guardduty",
        bouncers=["ibounce"],
        compliance=["NIST-SI-4", "SOC2-CC7.3", "MITRE-T1562.001"],
        description="Block agents from disabling GuardDuty (detection-evasion)",
    ),
    _e(
        "tf_official_031",
        kind="dynamic_deny",
        target="*",
        action=["securityhub:DisableSecurityHub", "config:DeleteConfigurationRecorder"],
        severity=Severity.HIGH,
        incident="Wave3-INC-2024-agent-disabled-security-hub",
        bouncers=["ibounce"],
        compliance=["NIST-SI-4", "SOC2-CC7.3", "MITRE-T1562.001", "HIPAA-164.312(b)"],
        description="Block agents from disabling Security Hub or AWS Config",
    ),

    # ---- HIGH: lateral movement -------------------------------------------
    _e(
        "tf_official_032",
        kind="dynamic_deny",
        target="*",
        action=["sts:AssumeRoleWithWebIdentity", "sts:AssumeRoleWithSAML"],
        severity=Severity.HIGH,
        incident="CVE-2025-AGENT-FEDERATION-PIVOT",
        bouncers=["ibounce"],
        compliance=["NIST-AC-6", "SOC2-CC6.1", "MITRE-T1078.004"],
        description="Block agents from assuming roles via federation (operator-only)",
    ),

    # ---- HIGH: container/registry tampering -------------------------------
    _e(
        "tf_official_033",
        kind="dynamic_deny",
        target="*",
        action=["ecr:PutImage", "ecr:DeleteRepository"],
        severity=Severity.HIGH,
        incident="Wave3-INC-2025-agent-overwrote-prod-image",
        bouncers=["ibounce"],
        compliance=["NIST-CM-3", "SOC2-CC7.2", "MITRE-T1525"],
        description="Block agents from pushing to or deleting ECR repositories",
    ),

    # ---- HIGH: K8s admission tampering ------------------------------------
    _e(
        "tf_official_034",
        kind="dynamic_deny",
        target="validatingwebhookconfigurations",
        action=["create", "delete", "patch"],
        severity=Severity.HIGH,
        incident="Wave3-INC-2025-agent-tampered-admission-webhooks",
        bouncers=["kbouncer"],
        compliance=["NIST-CM-7", "SOC2-CC6.1", "MITRE-T1562.001"],
        description="Block agents from modifying ValidatingWebhookConfigurations (defense disabling)",
    ),
    _e(
        "tf_official_035",
        kind="dynamic_deny",
        target="mutatingwebhookconfigurations",
        action=["create", "delete", "patch"],
        severity=Severity.HIGH,
        incident="Wave3-INC-2025-agent-tampered-mutating-webhooks",
        bouncers=["kbouncer"],
        compliance=["NIST-CM-7", "SOC2-CC6.1", "MITRE-T1562.001"],
        description="Block agents from modifying MutatingWebhookConfigurations",
    ),

    # ---- MEDIUM: profile_safety_floor_extension candidates ----------------
    _e(
        "tf_official_036",
        kind="profile_safety_floor_extension",
        target="arn:aws:s3:::*log*",
        action=["s3:PutObjectAcl", "s3:DeleteObject"],
        severity=Severity.MEDIUM,
        incident="Gap#406-S3-LOG-BUCKET-PROTECTION",
        bouncers=["ibounce"],
        compliance=["NIST-AU-9", "SOC2-CC7.2"],
        description="Recommend extending safety floor to protect *log* buckets from agent deletion",
    ),
    _e(
        "tf_official_037",
        kind="profile_safety_floor_extension",
        target="*",
        action=["iam:PassRole"],
        severity=Severity.MEDIUM,
        incident="Gap#406-IAM-PASSROLE-DEFAULT-DENY",
        bouncers=["ibounce"],
        compliance=["NIST-AC-6", "SOC2-CC6.1", "MITRE-T1078"],
        description="Recommend safety floor: deny iam:PassRole except for operator-pinned roles",
    ),
    _e(
        "tf_official_038",
        kind="scope_primitive_recommendation",
        target="agent-issued-roles",
        action=["session_duration_lte_1h"],
        severity=Severity.MEDIUM,
        incident="Gap#406-SHORT-TTL-DEFAULT",
        bouncers=["ibounce"],
        compliance=["NIST-AC-12", "SOC2-CC6.1", "DORA-Art.5"],
        description="Recommend agent-issued roles default to <=1h session duration",
    ),

    # ---- LOW: informational alerts ----------------------------------------
    _e(
        "tf_official_039",
        kind="informational_alert",
        target="",
        action=["NEW-MCP-CVE-DISCLOSED"],
        severity=Severity.LOW,
        incident="MCP-CVE-2026-001: prompt-injection vector in <hypothetical> MCP server",
        bouncers=["ibounce", "kbouncer", "dbounce", "gbounce"],
        compliance=["NIST-RA-5", "SOC2-CC7.4"],
        description="Informational: a new prompt-injection vector was disclosed in an MCP server",
    ),
    _e(
        "tf_official_040",
        kind="informational_alert",
        target="",
        action=["AGENT-FRAMEWORK-UPDATE-RECOMMENDED"],
        severity=Severity.LOW,
        incident="iam-jit-Advisory-2026-01: recommend upgrading <hypothetical agent framework> to >=1.5.0",
        bouncers=["ibounce", "kbouncer", "dbounce", "gbounce"],
        compliance=["NIST-SI-2", "SOC2-CC7.1"],
        description="Informational: agent framework version recommendation",
    ),
]


def main() -> int:
    p = argparse.ArgumentParser(description="Build the bootstrap iam-jit threat feed.")
    p.add_argument(
        "--key",
        type=pathlib.Path,
        help="Path to the publisher Ed25519 private key PEM. If omitted, "
             "an EPHEMERAL keypair is generated + the pubkey is printed "
             "to stderr (use for builds where the operator manually "
             "re-pins their config).",
    )
    p.add_argument(
        "--publisher",
        default="iam-jit-official",
        help="Publisher name embedded in each signature block.",
    )
    p.add_argument(
        "--feed-id",
        default="iam-jit-official-v1",
        help="Feed id embedded in the bundle.",
    )
    p.add_argument(
        "--out",
        type=pathlib.Path,
        default=_REPO / "feeds" / "official-v1.json",
        help="Output bundle path.",
    )
    p.add_argument(
        "--pubkey-out",
        type=pathlib.Path,
        default=_REPO / "feeds" / "official-v1.pubkey",
        help="Write the short-form pubkey to this path for operator pinning.",
    )
    args = p.parse_args()

    if args.key and args.key.exists():
        priv_pem = args.key.read_text()
        # We also need the public key for distribution. Derive it.
        from cryptography.hazmat.primitives import serialization

        priv_obj = serialization.load_pem_private_key(
            priv_pem.encode("ascii"), password=None,
        )
        pub_pem = priv_obj.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")
    else:
        priv_pem, pub_pem = ed25519_keygen()
        sys.stderr.write(
            "WARNING: no --key supplied; using an EPHEMERAL keypair. "
            "The private key WILL NOT be persisted. Re-pin operators "
            "to the pubkey below.\n"
        )

    # Derive the ed25519:<b64> short-form.
    from cryptography.hazmat.primitives import serialization
    import base64

    pk = serialization.load_pem_public_key(pub_pem.encode("ascii"))
    raw = pk.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    short = "ed25519:" + base64.b64encode(raw).decode("ascii")

    signed = [
        ed25519_sign_entry(e, private_key_pem=priv_pem, publisher=args.publisher)
        for e in ENTRIES
    ]
    feed = bundle_entries(
        signed, feed_id=args.feed_id, publisher=args.publisher,
    )
    args.out.parent.mkdir(parents=True, exist_ok=True)
    write_bundle(feed, args.out)
    args.pubkey_out.write_text(short + "\n")

    # Stats per #441 (compliance coverage).
    sev_counts = {s.value: 0 for s in Severity}
    bouncer_counts: dict[str, int] = {}
    tag_set: set[str] = set()
    for e in ENTRIES:
        sev_counts[e.severity.value] += 1
        for b in e.applies_to_bouncers:
            bouncer_counts[b] = bouncer_counts.get(b, 0) + 1
        for t in e.compliance_tags:
            tag_set.add(t)
    print(f"OK  bundle written: {args.out}")
    print(f"  feed_id:       {feed.feed_id}")
    print(f"  publisher:     {feed.publisher}")
    print(f"  entries:       {len(feed.entries)}")
    print(f"  manifest_sha:  {feed.manifest_sha256[:16]}...")
    print(f"  severity:      {sev_counts}")
    print(f"  bouncer split: {bouncer_counts}")
    print(f"  unique tags:   {len(tag_set)}")
    print(f"  pubkey (paste into .iam-jit.yaml threat_feed.feeds[].publisher_pubkey):")
    print(f"    {short}")
    print(f"  pubkey also written to: {args.pubkey_out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
