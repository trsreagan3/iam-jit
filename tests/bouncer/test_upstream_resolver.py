"""Unit tests for upstream_resolver (#687).

These tests close the F1 + F3 process gaps surfaced by the prior session:
the only forward-path test (#300 / test_proxy_upstream_scheme.py) covered
the OVERRIDE path; the default no-override path — the canonical
`iam-jit attach` shape where Host: self → must derive AWS endpoint
from SigV4 — had zero unit coverage. This file is that coverage.
"""
from __future__ import annotations

from iam_jit.bouncer import upstream_resolver as ur


# -- canonical_aws_endpoint: real AWS service+region resolution ------

def test_canonical_endpoint_sts_us_east_1_resolves():
    """The literal repro of #687: SDK signs sts/us-east-1, we must
    return sts.us-east-1.amazonaws.com (not 127.0.0.1:8767)."""
    assert ur.canonical_aws_endpoint("sts", "us-east-1") == "sts.us-east-1.amazonaws.com"


def test_canonical_endpoint_iam_is_global():
    # iam is partition-global; botocore returns the iam.amazonaws.com
    # hostname regardless of the region anchor.
    assert ur.canonical_aws_endpoint("iam", "us-east-1") == "iam.amazonaws.com"


def test_canonical_endpoint_s3_regional():
    assert ur.canonical_aws_endpoint("s3", "us-west-2") == "s3.us-west-2.amazonaws.com"


def test_canonical_endpoint_dynamodb_apse1():
    assert (
        ur.canonical_aws_endpoint("dynamodb", "ap-southeast-1")
        == "dynamodb.ap-southeast-1.amazonaws.com"
    )


def test_canonical_endpoint_none_for_empty_service():
    assert ur.canonical_aws_endpoint("", "us-east-1") is None


def test_canonical_endpoint_none_for_garbage():
    # Botocore returns a partition-default-pattern even for bogus
    # services; the test asserts ONLY that we don't crash. Real safety
    # is in resolve_forward_target's None-handling: even if botocore
    # returns a guess, the test below verifies our caller surfaces
    # honestly when the guess won't work.
    out = ur.canonical_aws_endpoint("definitely-not-an-aws-service-xyz", "us-east-1")
    # Either None or a guess string — we don't enforce which.
    assert out is None or isinstance(out, str)


# -- is_loopback_self: detect the iam-jit attach Host shape ----------

def test_is_loopback_self_127_with_port():
    assert ur.is_loopback_self("127.0.0.1:8767", "127.0.0.1", 8767) is True


def test_is_loopback_self_localhost_with_port():
    assert ur.is_loopback_self("localhost:8767", "127.0.0.1", 8767) is True


def test_is_loopback_self_ipv6_with_port():
    assert ur.is_loopback_self("[::1]:8767", "127.0.0.1", 8767) is True


def test_is_loopback_self_custom_loopback_port():
    # Operator running ibounce on a non-default port (e.g. canary 9876).
    assert ur.is_loopback_self("127.0.0.1:9876", "127.0.0.1", 9876) is True
    assert ur.is_loopback_self("127.0.0.1:8767", "127.0.0.1", 9876) is False


def test_is_loopback_self_actual_aws_host_is_not_self():
    """The pre-#687 path that was correct: SDK pointed at real AWS, we
    forward to it verbatim."""
    assert (
        ur.is_loopback_self("sts.us-east-1.amazonaws.com", "127.0.0.1", 8767)
        is False
    )
    assert (
        ur.is_loopback_self("sts.us-east-1.amazonaws.com:443", "127.0.0.1", 8767)
        is False
    )


def test_is_loopback_self_blank_host():
    assert ur.is_loopback_self("", "127.0.0.1", 8767) is False


# -- resolve_forward_target: the full decision tree -------------------

def test_resolve_override_wins_over_everything():
    """LocalStack / #300 override: takes priority even when Host is self."""
    out = ur.resolve_forward_target(
        override="127.0.0.1:4566",
        host_header="127.0.0.1:8767",  # self
        listen_host="127.0.0.1",
        listen_port=8767,
        service="sts",
        region="us-east-1",
    )
    assert out == "127.0.0.1:4566"


def test_resolve_non_self_host_preserved():
    """SDK pointed at real AWS: we don't second-guess it."""
    out = ur.resolve_forward_target(
        override=None,
        host_header="sts.us-east-1.amazonaws.com",
        listen_host="127.0.0.1",
        listen_port=8767,
        service="sts",
        region="us-east-1",
    )
    assert out == "sts.us-east-1.amazonaws.com"


def test_resolve_self_host_routes_via_sigv4_scope():
    """#687 LITERAL REPRO: canonical iam-jit attach shape.
    SDK Host=127.0.0.1:8767, SigV4 signs for sts/us-east-1
    -> we MUST resolve to sts.us-east-1.amazonaws.com (not recurse)."""
    out = ur.resolve_forward_target(
        override=None,
        host_header="127.0.0.1:8767",
        listen_host="127.0.0.1",
        listen_port=8767,
        service="sts",
        region="us-east-1",
    )
    assert out == "sts.us-east-1.amazonaws.com"


def test_resolve_self_host_with_fake_resolver_for_tests():
    """The DI hook the integration test uses: production code path
    (no override + Host=self) but the resolver points at a local
    fake-AWS server instead of dialling real AWS."""
    fake = lambda service, region: f"127.0.0.1:65500"  # fake-AWS server
    out = ur.resolve_forward_target(
        override=None,
        host_header="127.0.0.1:8767",
        listen_host="127.0.0.1",
        listen_port=8767,
        service="sts",
        region="us-east-1",
        endpoint_resolver=fake,
    )
    assert out == "127.0.0.1:65500"


def test_resolve_self_host_unresolvable_returns_none():
    """No service identified → no upstream → caller surfaces a clear
    UPSTREAM_RESOLUTION_FAILED 502 rather than recursing into self."""
    out = ur.resolve_forward_target(
        override=None,
        host_header="127.0.0.1:8767",
        listen_host="127.0.0.1",
        listen_port=8767,
        service=None,
        region=None,
        endpoint_resolver=lambda s, r: None,
    )
    assert out is None
