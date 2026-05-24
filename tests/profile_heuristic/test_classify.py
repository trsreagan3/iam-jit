"""Phase 1 — tests for profile_heuristic.classify.

Per CONTRIBUTING.md state-verification: every test asserts the
ACTUAL classification returned by ``classify_action`` against an
expected ``ActionClass`` value — never against a status string.
The classifier is a pure function, so the return value IS the
observable state.

Covers per-bouncer prefix-table coverage (5+ examples per
ActionClass per bouncer) + the KNOWN_ADVERSARIAL_PATTERNS override
+ cross-bouncer behaviour + malformed-input safety.
"""

from __future__ import annotations

import pytest

from iam_jit.deny_classifier.prompts import KNOWN_ADVERSARIAL_PATTERNS
from iam_jit.profile_heuristic import ActionClass, classify_action


# ---------------------------------------------------------------------------
# ibounce (AWS)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("action,expected", [
    ("s3:GetObject", ActionClass.READ),
    ("s3:ListBucket", ActionClass.READ),
    ("ec2:DescribeInstances", ActionClass.READ),
    ("sts:GetCallerIdentity", ActionClass.READ),
    ("dynamodb:Query", ActionClass.READ),
    ("dynamodb:Scan", ActionClass.READ),
])
def test_ibounce_read_classification(action, expected) -> None:
    assert classify_action("ibounce", action) is expected


@pytest.mark.parametrize("action,expected", [
    ("s3:PutObject", ActionClass.WRITE_DATA),
    ("dynamodb:UpdateItem", ActionClass.WRITE_DATA),
    ("lambda:InvokeFunction", ActionClass.WRITE_DATA),
    ("s3:CopyObject", ActionClass.WRITE_DATA),
    ("ec2:StartInstances", ActionClass.WRITE_DATA),
    ("sns:Publish", ActionClass.WRITE_DATA),
])
def test_ibounce_write_data_classification(action, expected) -> None:
    assert classify_action("ibounce", action) is expected


@pytest.mark.parametrize("action,expected", [
    # iam:* writes are admin even though "Update*" / "Put*" prefix
    # also matches WRITE_DATA — DESTRUCTIVE check first, ADMIN second,
    # WRITE third.
    ("iam:UpdateAssumeRolePolicy", ActionClass.ADMIN),
    ("iam:AttachRolePolicy", ActionClass.ADMIN),
    ("iam:PutRolePolicy", ActionClass.ADMIN),
    ("ec2:AuthorizeSecurityGroupIngress", ActionClass.ADMIN),
    ("cloudtrail:StopLogging", ActionClass.ADMIN),
    ("route53:ChangeResourceRecordSets", ActionClass.ADMIN),
])
def test_ibounce_admin_classification(action, expected) -> None:
    assert classify_action("ibounce", action) is expected


@pytest.mark.parametrize("action,expected", [
    ("s3:DeleteObject", ActionClass.DESTRUCTIVE_DATA),
    ("dynamodb:DeleteItem", ActionClass.DESTRUCTIVE_DATA),
    ("dynamodb:DeleteTable", ActionClass.DESTRUCTIVE_DATA),
    ("rds:DeleteDBInstance", ActionClass.DESTRUCTIVE_DATA),
    ("ec2:DeleteVolume", ActionClass.DESTRUCTIVE_DATA),
    ("lambda:DeleteFunction", ActionClass.DESTRUCTIVE_DATA),
])
def test_ibounce_destructive_classification(action, expected) -> None:
    assert classify_action("ibounce", action) is expected


@pytest.mark.parametrize("action", [
    "foobar",                       # no colon → not AWS shape
    "noservice:",                   # empty action half
    ":noaction",                    # empty service half
    "weirdservice:NoMatchingVerb",  # legitimate shape but unmapped
    "made-up:Xyzzy",
])
def test_ibounce_unknown_classification(action) -> None:
    assert classify_action("ibounce", action) is ActionClass.UNKNOWN


# ---------------------------------------------------------------------------
# kbouncer (Kubernetes)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("verb,resource,expected", [
    ("get", "configmap", ActionClass.READ),
    ("list", "pods", ActionClass.READ),
    ("watch", "deployments", ActionClass.READ),
    ("get", "events", ActionClass.READ),
    ("list", "endpoints", ActionClass.READ),
])
def test_kbouncer_read_classification(verb, resource, expected) -> None:
    assert classify_action("kbouncer", verb, resource) is expected


@pytest.mark.parametrize("verb,resource,expected", [
    ("update", "configmap", ActionClass.WRITE_DATA),
    ("patch", "configmap", ActionClass.WRITE_DATA),
    ("apply", "configmap", ActionClass.WRITE_DATA),
    ("create", "configmap", ActionClass.WRITE_DATA),
    # delete without destructive-resource hint stays WRITE_DATA
    ("delete", "configmap", ActionClass.WRITE_DATA),
])
def test_kbouncer_write_data_classification(verb, resource, expected) -> None:
    assert classify_action("kbouncer", verb, resource) is expected


@pytest.mark.parametrize("verb,resource,expected", [
    # RBAC-shape resource forces admin even on read verbs.
    ("get", "clusterrolebinding", ActionClass.ADMIN),
    ("list", "serviceaccount", ActionClass.ADMIN),
    ("create", "clusterrolebinding", ActionClass.ADMIN),
    ("get", "secret", ActionClass.ADMIN),
    # admin verbs.
    ("impersonate", "system:admin", ActionClass.ADMIN),
    ("bind", "clusterrole/cluster-admin", ActionClass.ADMIN),
])
def test_kbouncer_admin_classification(verb, resource, expected) -> None:
    assert classify_action("kbouncer", verb, resource) is expected


@pytest.mark.parametrize("verb,resource,expected", [
    # NOTE: ``delete namespace`` is in KNOWN_ADVERSARIAL_PATTERNS and
    # short-circuits to ADMIN — see
    # ``test_known_adversarial_kubectl_delete_namespace_is_admin``.
    # Destructive-classification cases below pick resources NOT in the
    # adversarial catalogue so the per-bouncer table is exercised.
    ("delete", "deployment/api", ActionClass.DESTRUCTIVE_DATA),
    ("delete", "pod/web-1", ActionClass.DESTRUCTIVE_DATA),
    ("delete", "statefulset/db", ActionClass.DESTRUCTIVE_DATA),
    ("delete", "persistentvolume/data-0", ActionClass.DESTRUCTIVE_DATA),
    ("deletecollection", "pods", ActionClass.DESTRUCTIVE_DATA),
    ("delete-collection", "jobs", ActionClass.DESTRUCTIVE_DATA),
])
def test_kbouncer_destructive_classification(verb, resource, expected) -> None:
    assert classify_action("kbouncer", verb, resource) is expected


@pytest.mark.parametrize("verb", [
    "",
    "nonsenseverb",
    "FOO BAR BAZ",
    "xxxx",
    "exec123",  # exec is borderline; not in any table → UNKNOWN
])
def test_kbouncer_unknown_classification(verb) -> None:
    assert classify_action("kbouncer", verb, "deployment") is ActionClass.UNKNOWN


# ---------------------------------------------------------------------------
# dbounce (SQL)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("stmt,expected", [
    ("SELECT", ActionClass.READ),
    ("select", ActionClass.READ),
    ("psql:Select", ActionClass.READ),
    ("SHOW TABLES", ActionClass.READ),
    ("EXPLAIN", ActionClass.READ),
    ("DESCRIBE users", ActionClass.READ),
])
def test_dbounce_read_classification(stmt, expected) -> None:
    assert classify_action("dbounce", stmt) is expected


@pytest.mark.parametrize("stmt,expected", [
    ("INSERT", ActionClass.WRITE_DATA),
    ("UPDATE", ActionClass.WRITE_DATA),
    ("mysql:Insert", ActionClass.WRITE_DATA),
    ("MERGE", ActionClass.WRITE_DATA),
    ("COPY", ActionClass.WRITE_DATA),
    ("UPSERT", ActionClass.WRITE_DATA),
])
def test_dbounce_write_data_classification(stmt, expected) -> None:
    assert classify_action("dbounce", stmt) is expected


@pytest.mark.parametrize("stmt,expected", [
    ("GRANT", ActionClass.ADMIN),
    ("REVOKE", ActionClass.ADMIN),
    ("ALTER", ActionClass.ADMIN),
    ("CREATE", ActionClass.ADMIN),
    ("VACUUM", ActionClass.ADMIN),
    ("postgres:Grant", ActionClass.ADMIN),
])
def test_dbounce_admin_classification(stmt, expected) -> None:
    assert classify_action("dbounce", stmt) is expected


@pytest.mark.parametrize("stmt,expected", [
    ("DELETE", ActionClass.DESTRUCTIVE_DATA),
    ("DROP", ActionClass.DESTRUCTIVE_DATA),
    ("TRUNCATE", ActionClass.DESTRUCTIVE_DATA),
    ("psql:Delete", ActionClass.DESTRUCTIVE_DATA),
    ("RENAME", ActionClass.DESTRUCTIVE_DATA),
])
def test_dbounce_destructive_classification(stmt, expected) -> None:
    assert classify_action("dbounce", stmt) is expected


@pytest.mark.parametrize("stmt", [
    "",
    "ZZZ",
    "NONSENSE",
    "psql:",
    "unknown_keyword 123",
])
def test_dbounce_unknown_classification(stmt) -> None:
    assert classify_action("dbounce", stmt) is ActionClass.UNKNOWN


# ---------------------------------------------------------------------------
# gbounce (HTTP)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("method,resource,expected", [
    ("GET", "https://api.example.com/v1/users", ActionClass.READ),
    ("HEAD", "https://api.example.com/v1/health", ActionClass.READ),
    ("OPTIONS", "https://api.example.com/v1/users", ActionClass.READ),
    ("http:GET", "https://example.com/", ActionClass.READ),
    ("get", "https://example.com/", ActionClass.READ),
])
def test_gbounce_read_classification(method, resource, expected) -> None:
    assert classify_action("gbounce", method, resource) is expected


@pytest.mark.parametrize("method,resource,expected", [
    ("POST", "https://api.example.com/v1/users", ActionClass.WRITE_DATA),
    ("PUT", "https://api.example.com/v1/users/123", ActionClass.WRITE_DATA),
    ("PATCH", "https://api.example.com/v1/users/123", ActionClass.WRITE_DATA),
    ("http:POST", "https://example.com/api", ActionClass.WRITE_DATA),
    ("post", "https://example.com/", ActionClass.WRITE_DATA),
])
def test_gbounce_write_data_classification(method, resource, expected) -> None:
    assert classify_action("gbounce", method, resource) is expected


@pytest.mark.parametrize("method,resource,expected", [
    # IMDS host forces ADMIN even on GET
    ("GET", "http://169.254.169.254/latest/meta-data/", ActionClass.ADMIN),
    ("GET", "http://metadata.google.internal/computeMetadata/", ActionClass.ADMIN),
    ("POST", "https://sts.amazonaws.com/", ActionClass.ADMIN),
    ("GET", "https://iam.amazonaws.com/?Action=ListUsers", ActionClass.ADMIN),
    ("CONNECT", "tunnel.example.com:443", ActionClass.ADMIN),
])
def test_gbounce_admin_classification(method, resource, expected) -> None:
    assert classify_action("gbounce", method, resource) is expected


@pytest.mark.parametrize("method,resource,expected", [
    ("DELETE", "https://api.example.com/v1/users/123", ActionClass.DESTRUCTIVE_DATA),
    ("delete", "https://api.example.com/v1/posts/9", ActionClass.DESTRUCTIVE_DATA),
    ("http:DELETE", "https://api.example.com/v1/x", ActionClass.DESTRUCTIVE_DATA),
    ("DELETE", "https://example.com/items/42", ActionClass.DESTRUCTIVE_DATA),
    ("DELETE", "https://example.com/", ActionClass.DESTRUCTIVE_DATA),
])
def test_gbounce_destructive_classification(method, resource, expected) -> None:
    assert classify_action("gbounce", method, resource) is expected


@pytest.mark.parametrize("method", [
    "",
    "BREW",       # RFC 2324
    "PROPFIND",   # WebDAV (not in tables)
    "MKCOL",
    "WEIRDMETHOD",
])
def test_gbounce_unknown_classification(method) -> None:
    assert (
        classify_action("gbounce", method, "https://example.com/")
        is ActionClass.UNKNOWN
    )


# ---------------------------------------------------------------------------
# KNOWN_ADVERSARIAL_PATTERNS defense-in-depth — design §2.3 + §7 safeguard #2
# ---------------------------------------------------------------------------


def test_known_adversarial_iam_create_access_key_is_admin() -> None:
    """iam:CreateAccessKey is in the adversarial catalogue. It would
    classify as ADMIN via the ibounce table anyway, but the override
    short-circuits BEFORE the table lookup so the catalogue cannot
    drift from the classifier without the test failing."""
    assert "iam:CreateAccessKey" in KNOWN_ADVERSARIAL_PATTERNS
    assert classify_action("ibounce", "iam:CreateAccessKey", "*") is ActionClass.ADMIN


def test_known_adversarial_s3_delete_bucket_is_admin_not_destructive() -> None:
    """``s3:DeleteBucket`` is in the adversarial catalogue. The
    catalogue override forces ADMIN (the "very tight + count >= 3 required"
    disposition) rather than DESTRUCTIVE_DATA. Per design §2.3, the
    safety floor catches it in the deterministic generator regardless;
    the test pins the override behaviour so future changes to the
    catalogue surface here."""
    assert "s3:DeleteBucket" in KNOWN_ADVERSARIAL_PATTERNS
    assert classify_action("ibounce", "s3:DeleteBucket", "arn:aws:s3:::bkt") is ActionClass.ADMIN


def test_known_adversarial_cloudtrail_stop_logging_is_admin() -> None:
    assert "cloudtrail:StopLogging" in KNOWN_ADVERSARIAL_PATTERNS
    assert classify_action("ibounce", "cloudtrail:StopLogging") is ActionClass.ADMIN


def test_known_adversarial_kubectl_delete_namespace_is_admin() -> None:
    """The catalogue carries phrase-level K8s patterns. Verify the
    classifier recognises ``delete`` + ``namespace`` resource as a
    catalogue match and forces ADMIN — which beats the
    DESTRUCTIVE_DATA classification that the kbouncer-only table would
    otherwise return."""
    assert "kubectl delete namespace" in KNOWN_ADVERSARIAL_PATTERNS
    assert classify_action("kbouncer", "delete", "namespace/staging") is ActionClass.ADMIN


def test_known_adversarial_drop_table_is_admin() -> None:
    """SQL ``DROP TABLE`` is in the adversarial catalogue. Without the
    catalogue override it would classify DESTRUCTIVE_DATA via the
    dbounce table. With the override it classifies ADMIN."""
    assert "DROP TABLE" in KNOWN_ADVERSARIAL_PATTERNS
    assert classify_action("dbounce", "DROP TABLE", "users") is ActionClass.ADMIN


def test_known_adversarial_truncate_table_is_admin() -> None:
    assert "TRUNCATE TABLE" in KNOWN_ADVERSARIAL_PATTERNS
    assert classify_action("dbounce", "TRUNCATE TABLE", "orders") is ActionClass.ADMIN


def test_known_adversarial_unbounded_delete_from_users_is_admin() -> None:
    """``DELETE FROM users`` is in the catalogue as the unbounded-delete
    canary. Verify the classifier recognises ``DELETE`` + ``users``
    resource as a phrase match."""
    assert "DELETE FROM users" in KNOWN_ADVERSARIAL_PATTERNS
    assert classify_action("dbounce", "DELETE", "FROM users") is ActionClass.ADMIN


# ---------------------------------------------------------------------------
# Cross-bouncer + malformed-input safety
# ---------------------------------------------------------------------------


def test_classify_same_action_different_bouncer_routes_correctly() -> None:
    """``GET`` is a valid action in BOTH gbounce (HTTP) and kbouncer
    (K8s verb). Verify the bouncer dispatch picks the right table."""
    # gbounce GET (HTTP method) → READ
    assert classify_action("gbounce", "GET", "https://example.com/") is ActionClass.READ
    # kbouncer GET (K8s verb) → READ on pods (lower-case verb path)
    assert classify_action("kbouncer", "get", "pods/web-1") is ActionClass.READ


def test_classify_aliases_normalise() -> None:
    """``kbounce`` / ``ibouncer`` / ``dbouncer`` aliases route to the
    same classifier as ``kbouncer`` / ``ibounce`` / ``dbounce``."""
    assert (
        classify_action("kbounce", "get", "pods")
        is classify_action("kbouncer", "get", "pods")
    )
    assert (
        classify_action("ibouncer", "s3:GetObject")
        is classify_action("ibounce", "s3:GetObject")
    )


def test_classify_empty_action_returns_unknown_safely() -> None:
    """Per design §6 Phase 1 acceptance: empty action returns UNKNOWN;
    no crash."""
    assert classify_action("ibounce", "") is ActionClass.UNKNOWN
    assert classify_action("kbouncer", "") is ActionClass.UNKNOWN
    assert classify_action("dbounce", "") is ActionClass.UNKNOWN
    assert classify_action("gbounce", "") is ActionClass.UNKNOWN


def test_classify_unknown_bouncer_returns_unknown_safely() -> None:
    """An unknown bouncer name returns UNKNOWN; no crash."""
    assert classify_action("frobnicator", "anything") is ActionClass.UNKNOWN
    assert classify_action("", "s3:GetObject") is ActionClass.UNKNOWN


def test_classify_non_string_inputs_return_unknown_safely() -> None:
    """Defensive: non-string input doesn't crash."""
    assert classify_action(None, "s3:GetObject") is ActionClass.UNKNOWN  # type: ignore[arg-type]
    assert classify_action("ibounce", None) is ActionClass.UNKNOWN  # type: ignore[arg-type]


def test_classifier_is_pure_function_stable_repeats() -> None:
    """Pure-function discipline: same inputs → same output every call.

    State-verification: identity comparison across 100 calls catches
    accidental classifier-state mutation (e.g. caches that key wrong).
    """
    results = [classify_action("ibounce", "s3:DeleteObject", "arn:aws:s3:::b") for _ in range(100)]
    assert all(r is ActionClass.DESTRUCTIVE_DATA for r in results)
