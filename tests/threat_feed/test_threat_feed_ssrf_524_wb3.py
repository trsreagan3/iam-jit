"""#524 WB-3 — Threat-feed fetcher SSRF gate.

From #484 BB+WB security audit WB-3: the threat-feed fetcher accepted
an operator-configured URL and called ``urllib.request.urlopen`` without
SSRF protection. Signature verification on the payload mitigated RCE
but the fetcher itself could be coerced to probe internal IPs /
metadata services / private network addresses. Standard SSRF risk.

Fix: thread the URL through the SSRF helper primitives the webhook +
``profile install --from URL`` surfaces already use
(``_hostname_has_internal_suffix`` + ``_is_internal_ip``). Reject
categories named in the error per [[ibounce-honest-positioning]].

Tests follow ``docs/CONTRIBUTING.md`` state-verification convention:
each test asserts BOTH (a) the gate's reject decision AND (b) that NO
network call was attempted (we monkeypatch ``urllib.request.urlopen``
to sentinel-raise — the test fails if the gate let the request through).
"""

from __future__ import annotations

import json
import pathlib
import urllib.request

import pytest

from iam_jit.threat_feed import FeedFetchError, fetch_feed
from iam_jit.threat_feed.fetcher import _validate_feed_url_ssrf


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


class _NetworkAttempted(AssertionError):
    """Sentinel raised by the patched urlopen — surfaces as a clear test
    failure when the SSRF gate let a request through that it shouldn't
    have."""


def _patch_urlopen_to_fail(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace urllib.request.urlopen with a sentinel-raiser.

    Per the state-verification convention we don't just assert the gate
    raised — we also assert NO network call was attempted. If the gate
    fails open + the test code proceeds to urlopen, this sentinel
    surfaces as a distinct exception type (not FeedFetchError) so the
    test fails loudly."""
    def _explode(*args, **kwargs):  # type: ignore[no-untyped-def]
        raise _NetworkAttempted(
            f"SSRF gate did not block the request; urlopen called with "
            f"args={args!r} kwargs={kwargs!r}"
        )
    monkeypatch.setattr(urllib.request, "urlopen", _explode)


def _feed_payload(rule_id: str = "tf_ssrf_test") -> dict:
    return {
        "schema_version": "1.0",
        "feed_id": "ssrf-test-v1",
        "publisher": "ssrf-test",
        "generated_at": "2026-05-25T10:00:00Z",
        "entries": [{
            "rule_id": rule_id,
            "rule_kind": "informational_alert",
            "severity": "LOW",
            "compliance_tags": ["SOC2-CC6.1"],
        }],
        "manifest_sha256": "x",
    }


# ---------------------------------------------------------------------------
# Test 1 — HTTPS public URL passes the gate + proceeds to network
# ---------------------------------------------------------------------------


def test_https_public_url_passes_gate_and_proceeds(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: pathlib.Path,
):
    """A normal https:// URL with a resolvable public IP must pass the
    gate. We don't make a real network call — we patch the SSRF helper
    to accept + patch urlopen to return a fake response — but the test
    asserts the fetcher PROCEEDED past the gate (i.e. urlopen WAS
    called). This is the inverse of the rejection tests below."""
    called: list[str] = []

    def _accept(url, *, allow_internal):  # type: ignore[no-untyped-def]
        called.append(f"gate:{url}")

    monkeypatch.setattr(
        "iam_jit.threat_feed.fetcher._validate_feed_url_ssrf",
        _accept,
    )

    class _FakeResponse:
        status = 200

        def __init__(self, body: bytes) -> None:
            self._body = body

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return None

        def getcode(self):
            return 200

        def geturl(self):
            return "https://feeds.example.com/threat.json"

        def read(self, n: int = -1) -> bytes:
            return self._body

    body = json.dumps(_feed_payload()).encode("utf-8")

    def _fake_urlopen(req, *, timeout):  # type: ignore[no-untyped-def]
        called.append("urlopen")
        return _FakeResponse(body)

    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)

    result = fetch_feed("https://feeds.example.com/threat.json")

    # State observation: gate ran AND urlopen ran AND a parsed feed was
    # returned. This proves the gate is non-blocking on public URLs.
    assert "gate:https://feeds.example.com/threat.json" in called
    assert "urlopen" in called
    assert result.feed is not None
    assert result.feed.feed_id == "ssrf-test-v1"
    assert result.error == ""


# ---------------------------------------------------------------------------
# Test 2 — Loopback `http://127.0.0.1/...` rejected
# ---------------------------------------------------------------------------


def test_loopback_http_rejected_with_no_network_call(
    monkeypatch: pytest.MonkeyPatch,
):
    """http://127.0.0.1/feed.json must be refused by the SSRF gate
    BEFORE any network call. The error must name the category +
    include the URL per [[ibounce-honest-positioning]]."""
    _patch_urlopen_to_fail(monkeypatch)

    url = "http://127.0.0.1:8080/feed.json"
    with pytest.raises(FeedFetchError) as exc:
        # allow_insecure_http=True so the scheme check passes — we want
        # to exercise the SSRF gate, not the scheme gate.
        fetch_feed(url, allow_insecure_http=True)

    msg = str(exc.value)
    assert url in msg, f"error must surface the offending URL: {msg!r}"
    assert "loopback" in msg.lower(), (
        f"error must name 'loopback' per [[ibounce-honest-positioning]]: {msg!r}"
    )
    # And — most importantly — _NetworkAttempted was NOT raised. The
    # SSRF gate fired before urlopen got a chance.


# ---------------------------------------------------------------------------
# Test 3 — AWS metadata IP `http://169.254.169.254/...` rejected
# ---------------------------------------------------------------------------


def test_aws_metadata_ip_rejected_with_link_local_category(
    monkeypatch: pytest.MonkeyPatch,
):
    """http://169.254.169.254/latest/meta-data/ — the classic SSRF
    pivot — must be refused as link-local. The error must name the
    category."""
    _patch_urlopen_to_fail(monkeypatch)

    url = "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
    with pytest.raises(FeedFetchError) as exc:
        fetch_feed(url, allow_insecure_http=True)

    msg = str(exc.value)
    assert url in msg, f"error must include the URL: {msg!r}"
    # 169.254/16 is link-local; the helper labels it "link-local" and
    # the fetcher's category name explicitly mentions AWS metadata.
    assert "link-local" in msg.lower() or "metadata" in msg.lower(), (
        f"error must name 'link-local' or 'metadata': {msg!r}"
    )


# ---------------------------------------------------------------------------
# Test 4 — Private RFC1918 `http://10.0.0.5/...` rejected
# ---------------------------------------------------------------------------


def test_private_rfc1918_rejected(monkeypatch: pytest.MonkeyPatch):
    """http://10.0.0.5/feed.json must be refused as private."""
    _patch_urlopen_to_fail(monkeypatch)

    url = "http://10.0.0.5/feed.json"
    with pytest.raises(FeedFetchError) as exc:
        fetch_feed(url, allow_insecure_http=True)

    msg = str(exc.value)
    assert url in msg, f"error must include the URL: {msg!r}"
    assert "private" in msg.lower(), (
        f"error must name 'private' for RFC1918: {msg!r}"
    )


# ---------------------------------------------------------------------------
# Test 5 — IPv6 ULA `http://[fd00::1]/...` rejected
# ---------------------------------------------------------------------------


def test_ipv6_ula_rejected(monkeypatch: pytest.MonkeyPatch):
    """IPv6 unique local addresses (fc00::/7) must be refused. The
    underlying ``socket.gethostbyname_ex`` primitive doesn't parse IPv6
    literals — they hit the resolver path. Per [[scorer-is-ground-truth]]
    the gate fails CLOSED on unresolvable hosts, so the URL is STILL
    rejected (no network call) even though the error message names
    "unresolvable" rather than "private". The security outcome (no
    network call) is what matters; the message-shape limitation is a
    documented property of the underlying helper which is out of
    scope for this fix per #524 WB-3 scope guardrails."""
    _patch_urlopen_to_fail(monkeypatch)

    url = "http://[fd00::1]/feed.json"
    with pytest.raises(FeedFetchError) as exc:
        fetch_feed(url, allow_insecure_http=True)

    msg = str(exc.value)
    assert url in msg, f"error must include the URL: {msg!r}"
    # Accept either the IP-category rejection (preferred) OR the
    # fail-CLOSED unresolvable-host rejection. Both prove the request
    # was refused; both prove urlopen was NOT called (we patched it to
    # raise _NetworkAttempted — a non-FeedFetchError).
    assert (
        "private" in msg.lower()
        or "ula" in msg.lower()
        or "could not resolve" in msg.lower()
        or "ssrf gate" in msg.lower()
    ), f"error must name IPv6 private/ULA OR unresolvable-fail-closed: {msg!r}"


# ---------------------------------------------------------------------------
# Test 6 — Intranet hostname suffix rejected (belt-and-braces for DNS
# rebinding / corporate DNS that resolves .internal to a public CDN IP)
# ---------------------------------------------------------------------------


def test_intranet_suffix_rejected(monkeypatch: pytest.MonkeyPatch):
    """A hostname ending in .internal must be refused EVEN IF DNS
    resolves it to a public IP. This is the structural-classifier
    backstop the webhook helper documents: corporate DNS sometimes
    points .internal at a CDN frontend; the suffix denylist refuses
    those before the IP check runs."""
    _patch_urlopen_to_fail(monkeypatch)

    url = "http://feeds.example.internal/threat.json"
    with pytest.raises(FeedFetchError) as exc:
        fetch_feed(url, allow_insecure_http=True)

    msg = str(exc.value)
    assert url in msg, f"error must include the URL: {msg!r}"
    assert ".internal" in msg or "intranet" in msg.lower(), (
        f"error must name the intranet suffix category: {msg!r}"
    )


# ---------------------------------------------------------------------------
# Test 7 — CLI surface (`iam-jit updates dry-run`) rejects same way
# ---------------------------------------------------------------------------


def test_cli_updates_dry_run_rejects_ssrf_url(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture,
):
    """End-to-end via the CLI worker (``_do_dry_run``): an HTTPS feed
    URL pointing at a private RFC1918 IP must be refused by the SSRF
    gate with a clear stderr message naming the category + URL.

    We use ``https://10.0.0.5/...`` here (NOT loopback http://) because
    the CLI calls ``fetch_feed(url)`` without ``allow_insecure_http``,
    so a loopback ``http://`` URL would fail the scheme check BEFORE
    the SSRF gate runs — which is a legitimate defence too, but it's
    not the gate under test here. An HTTPS URL pointed at a private
    IP exercises specifically the SSRF gate through the CLI codepath.

    We bypass the "pinned-in-config" precondition by stubbing
    ``_load_subscriptions`` — the unit-under-test for THIS test is the
    fetcher gate firing through the CLI worker, not the pin check
    (which is exercised elsewhere)."""
    from iam_jit import cli_updates
    from iam_jit.threat_feed import Subscription
    from iam_jit.threat_feed.models import Severity

    _patch_urlopen_to_fail(monkeypatch)

    url = "https://10.0.0.5/threat-feed.json"
    fake_sub = Subscription(
        url=url,
        publisher_pubkey="dummy-pubkey-for-ssrf-test",
        verification_mode="ed25519",
        severity_auto_apply_threshold=Severity.HIGH,
    )

    def _fake_load_subscriptions(config_path, cwd):  # type: ignore[no-untyped-def]
        return ([fake_sub], {}, "<test>")

    monkeypatch.setattr(cli_updates, "_load_subscriptions", _fake_load_subscriptions)

    exit_code = cli_updates._do_dry_run(
        url,
        config_path=None,
        cwd=None,
        as_json=False,
    )

    captured = capsys.readouterr()
    combined = (captured.err or "") + (captured.out or "")

    # State observation: non-zero exit + URL surfaced + SSRF category
    # named in the operator-visible output.
    assert exit_code != 0, (
        f"CLI worker must return non-zero on SSRF reject; "
        f"got {exit_code} with output={combined!r}"
    )
    assert "10.0.0.5" in combined, (
        f"CLI output must surface the offending URL: {combined!r}"
    )
    assert (
        "private" in combined.lower()
        or "ssrf" in combined.lower()
    ), f"CLI output must name the SSRF/private category: {combined!r}"


# ---------------------------------------------------------------------------
# Test 8 — Sabotage check: gate is load-bearing
# ---------------------------------------------------------------------------


def test_sabotage_disabling_gate_lets_loopback_through(
    monkeypatch: pytest.MonkeyPatch,
):
    """Sabotage check per the state-verification convention: if we
    monkeypatch the SSRF gate to a no-op, the loopback URL from Test 2
    is no longer refused. This proves the gate IS the thing blocking
    the request (not some unrelated check that happened to fire)."""
    # Replace the SSRF gate with a pass-through.
    def _noop(url, *, allow_internal):  # type: ignore[no-untyped-def]
        return None

    monkeypatch.setattr(
        "iam_jit.threat_feed.fetcher._validate_feed_url_ssrf",
        _noop,
    )

    # Replace urlopen so we don't actually hit the network; instead
    # observe that it WAS called (i.e. the request got past the gate).
    called: list[str] = []

    def _fake_urlopen(req, *, timeout):  # type: ignore[no-untyped-def]
        called.append("urlopen")
        # Raise a generic URLError so the fetcher records error_reason
        # rather than crashing — we just need to confirm it tried.
        raise urllib.request.URLError("test-only — request reached urlopen")

    monkeypatch.setattr(urllib.request, "urlopen", _fake_urlopen)

    url = "http://127.0.0.1:8080/feed.json"
    result = fetch_feed(url, allow_insecure_http=True)

    # State observation: urlopen WAS called (gate was disabled).
    assert "urlopen" in called, (
        "sabotage check failed: with the SSRF gate disabled, the "
        "loopback URL should reach urlopen — if it didn't, some OTHER "
        "guard is blocking the request and the gate isn't load-bearing"
    )
    # And the fetcher returned a result with the URLError as error
    # (proving the request flow reached the network layer).
    assert result.feed is None
    assert "test-only" in result.error or "network_error" in result.error


# ---------------------------------------------------------------------------
# Test 9 — Direct helper unit test (smoke check for the gate primitive)
# ---------------------------------------------------------------------------


def test_validate_helper_accepts_when_allow_internal_true():
    """``allow_internal=True`` is the documented opt-out for legitimate
    internal distribution servers. The helper must short-circuit before
    any DNS / suffix check when this is passed."""
    # No exception raised even for a loopback URL.
    _validate_feed_url_ssrf(
        "http://127.0.0.1/feed.json",
        allow_internal=True,
    )


def test_validate_helper_rejects_missing_hostname():
    """A URL with no hostname (malformed) must fail-CLOSED per
    [[scorer-is-ground-truth]]."""
    with pytest.raises(FeedFetchError) as exc:
        _validate_feed_url_ssrf("http:///no-host", allow_internal=False)
    assert "missing hostname" in str(exc.value).lower()
