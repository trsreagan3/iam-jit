"""§A100 — `iam-jit profile install --from URL` SSRF gate.

The install surface accepts an operator-supplied URL. Pre-§A100 the
URL was opened with ``urllib.request.urlopen`` with no SSRF check, so
a malicious profile distributor (or an agent that controls the URL
flag) could point the install at:

  * ``http://169.254.169.254/latest/meta-data/...`` to exfiltrate the
    EC2 / GCP / Azure instance-metadata document
  * ``http://127.0.0.1:<port>/...`` to scan / poke services on the
    operator's localhost
  * ``http://10.x.x.x/...`` / ``http://192.168.x.x/...`` /
    ``http://172.16-31.x.x/...`` to pivot inside the operator's
    private network
  * any hostname ending in ``.internal`` / ``.local`` / ``.home.arpa``
    / ``.lan`` / ``.intranet`` / ``.corp`` / ``.localhost``

Post-§A100 the install runs the URL through ``_validate_install_url_
ssrf`` (which reuses the same SSRF helper the webhook surface ships
with, ``_is_internal_ip`` + ``_hostname_has_internal_suffix``).
Opt-out: ``--allow-internal-source`` for legitimate intranet
distribution servers.

State-verified per ``docs/CONTRIBUTING.md`` — every test asserts
EITHER (a) the install was refused AND no attacker-sourced profile
was written to disk, OR (b) the install was permitted AND the
profile is observable in ``load_profiles()``. The exit-code claim
is matched against the on-disk state.

Note: ``load_profiles()`` always includes a small set of built-in
defaults (``full-user``, ``none``, ``measurement-test-f1``); we
check that no ADDITIONAL profile from the attacker-controlled URL
landed (via the per-test profile name asserted absent or via the
``source`` field check).
"""

from __future__ import annotations

import socket
from contextlib import contextmanager
from unittest import mock

import pytest
import yaml
from click.testing import CliRunner

from iam_jit.bouncer.profiles import load_profiles
from iam_jit.bouncer_cli import main


@pytest.fixture()
def profiles_path(tmp_path, monkeypatch):
    p = tmp_path / "profiles.yaml"
    monkeypatch.setenv("IAM_JIT_BOUNCER_PROFILES_FILE", str(p))
    return p


def _invoke(args, env):
    runner = CliRunner()
    return runner.invoke(main, args, env=env, catch_exceptions=False)


@contextmanager
def _mock_resolver(host_to_ips: dict[str, list[str]]):
    """Patch ``socket.gethostbyname_ex`` so tests don't need real DNS.

    Unknown hosts raise ``socket.gaierror`` — which the SSRF gate
    translates to a refusal (fail-closed per the helper)."""
    def fake(host):
        if host in host_to_ips:
            return (host, [], host_to_ips[host])
        raise socket.gaierror(f"unknown host {host!r}")

    with mock.patch("socket.gethostbyname_ex", side_effect=fake):
        yield


def _assert_no_attacker_profile(profile_name: str) -> None:
    """Assert that no profile with the given name landed on disk.

    Built-in defaults (full-user / none / measurement-test-f1) are
    ignored — only attacker-controlled names count."""
    profs = load_profiles()
    assert profile_name not in profs, (
        f"§A100 regression: a refused install left profile "
        f"{profile_name!r} on disk. Profiles present: "
        f"{sorted(profs.keys())}"
    )


# ---------------------------------------------------------------------------
# Refusals: cloud-metadata + RFC1918 + loopback + link-local + suffix denylist
# ---------------------------------------------------------------------------


def test_refuses_aws_imds_169_254_169_254(profiles_path) -> None:
    """The single highest-impact SSRF target: AWS / GCP / Azure
    instance-metadata service at 169.254.169.254 (link-local)."""
    with _mock_resolver({"metadata.attacker.com": ["169.254.169.254"]}):
        result = _invoke(
            ["profile", "install", "--from",
             "https://metadata.attacker.com/x.yaml"],
            env={"IAM_JIT_BOUNCER_PROFILES_FILE": str(profiles_path)},
        )
    assert result.exit_code == 2, result.output
    assert "internal" in result.output.lower() or "refusing" in result.output.lower()
    # State verification: attacker payload would have named the
    # profile something — but since fetch was refused BEFORE the
    # payload was even retrieved, no new profile can be present.
    # We check by source: no profile should reference the attacker
    # hostname.
    profs = load_profiles()
    bad = [n for n, p in profs.items()
           if p.source and "attacker" in p.source]
    assert not bad, f"§A100 regression: refused install left {bad}"


def test_refuses_rfc1918_10_x(profiles_path) -> None:
    with _mock_resolver({"internal-svc.attacker.com": ["10.0.0.5"]}):
        result = _invoke(
            ["profile", "install", "--from",
             "https://internal-svc.attacker.com/x.yaml"],
            env={"IAM_JIT_BOUNCER_PROFILES_FILE": str(profiles_path)},
        )
    assert result.exit_code == 2, result.output
    profs = load_profiles()
    bad = [n for n, p in profs.items()
           if p.source and "attacker" in p.source]
    assert not bad, f"§A100 regression: refused install left {bad}"


def test_refuses_rfc1918_192_168_x(profiles_path) -> None:
    with _mock_resolver({"router.attacker.com": ["192.168.1.1"]}):
        result = _invoke(
            ["profile", "install", "--from",
             "https://router.attacker.com/x.yaml"],
            env={"IAM_JIT_BOUNCER_PROFILES_FILE": str(profiles_path)},
        )
    assert result.exit_code == 2, result.output
    profs = load_profiles()
    bad = [n for n, p in profs.items()
           if p.source and "attacker" in p.source]
    assert not bad, f"§A100 regression: refused install left {bad}"


def test_refuses_loopback_via_dns(profiles_path) -> None:
    """An attacker can register a public hostname that resolves to
    127.0.0.1 ('dns rebinding'). The gate's IP check fires."""
    with _mock_resolver({"loopback.attacker.com": ["127.0.0.1"]}):
        result = _invoke(
            ["profile", "install", "--from",
             "https://loopback.attacker.com/x.yaml"],
            env={"IAM_JIT_BOUNCER_PROFILES_FILE": str(profiles_path)},
        )
    assert result.exit_code == 2, result.output
    profs = load_profiles()
    bad = [n for n, p in profs.items()
           if p.source and "attacker" in p.source]
    assert not bad, f"§A100 regression: refused install left {bad}"


def test_refuses_internal_suffix(profiles_path) -> None:
    """The suffix denylist fires BEFORE DNS resolution, so a
    hostname like ``host.internal`` is refused even if it resolves
    to a public IP."""
    with _mock_resolver({"profiles.internal": ["8.8.8.8"]}):
        result = _invoke(
            ["profile", "install", "--from",
             "https://profiles.internal/x.yaml"],
            env={"IAM_JIT_BOUNCER_PROFILES_FILE": str(profiles_path)},
        )
    assert result.exit_code == 2, result.output
    assert "intranet" in result.output.lower() or "internal" in result.output.lower()
    profs = load_profiles()
    bad = [n for n, p in profs.items()
           if p.source and "profiles.internal" in p.source]
    assert not bad, f"§A100 regression: refused install left {bad}"


def test_refuses_local_suffix(profiles_path) -> None:
    """Bonjour / Avahi (.local) — used by mDNS-discovered devices on
    a LAN. An agent that controls --from could pivot to a local
    printer / NAS / router."""
    with _mock_resolver({"printer.local": ["8.8.8.8"]}):
        result = _invoke(
            ["profile", "install", "--from",
             "https://printer.local/x.yaml"],
            env={"IAM_JIT_BOUNCER_PROFILES_FILE": str(profiles_path)},
        )
    assert result.exit_code == 2, result.output
    profs = load_profiles()
    bad = [n for n, p in profs.items()
           if p.source and "printer.local" in p.source]
    assert not bad, f"§A100 regression: refused install left {bad}"


# ---------------------------------------------------------------------------
# Permitted: real public host (mocked DNS) + valid payload
# ---------------------------------------------------------------------------


def test_permits_public_resolving_host(profiles_path) -> None:
    """A hostname that resolves to a public IP + serves valid YAML
    installs successfully + appears on disk."""
    payload = yaml.safe_dump({
        "profiles": {"good": {"description": "ok"}},
    }).encode()

    class _Resp:
        def read(self): return payload
        def geturl(self): return "https://cdn.example.com/x.yaml"
        def __enter__(self): return self
        def __exit__(self, *a): return False

    with _mock_resolver({"cdn.example.com": ["93.184.216.34"]}), \
         mock.patch("urllib.request.urlopen", return_value=_Resp()):
        result = _invoke(
            ["profile", "install", "--from",
             "https://cdn.example.com/x.yaml"],
            env={"IAM_JIT_BOUNCER_PROFILES_FILE": str(profiles_path)},
        )
    assert result.exit_code == 0, result.output
    # State verification: the profile was actually persisted.
    profs = load_profiles()
    assert "good" in profs


# ---------------------------------------------------------------------------
# Opt-out: --allow-internal-source bypasses the gate (operator-acknowledged)
# ---------------------------------------------------------------------------


def test_allow_internal_source_bypasses_gate_for_intranet(
    profiles_path,
) -> None:
    """The escape hatch for legitimate intranet distribution servers.
    With ``--allow-internal-source`` the gate is skipped and an
    RFC1918 IP becomes a permitted fetch target."""
    payload = yaml.safe_dump({
        "profiles": {"intra": {"description": "from intranet"}},
    }).encode()

    class _Resp:
        def read(self): return payload
        def geturl(self): return "https://profiles.corp.example/x.yaml"
        def __enter__(self): return self
        def __exit__(self, *a): return False

    with _mock_resolver({"profiles.corp.example": ["10.0.0.5"]}), \
         mock.patch("urllib.request.urlopen", return_value=_Resp()):
        result = _invoke(
            ["profile", "install", "--from",
             "https://profiles.corp.example/x.yaml",
             "--allow-internal-source"],
            env={"IAM_JIT_BOUNCER_PROFILES_FILE": str(profiles_path)},
        )
    assert result.exit_code == 0, result.output
    # State verification: opt-out actually installed the profile.
    profs = load_profiles()
    assert "intra" in profs


# ---------------------------------------------------------------------------
# Redirect handling: urlopen follows redirects; the final-URL gate fires.
# ---------------------------------------------------------------------------


def test_refuses_when_redirect_lands_on_internal_ip(profiles_path) -> None:
    """An attacker can serve a public URL that 302s to
    http://169.254.169.254/... — by the time urlopen returns, the
    redirect chain is complete. The final-URL gate refires + refuses.

    State verification: even though urlopen returned a payload, the
    profile MUST NOT land on disk because the SSRF gate fired
    post-fetch."""
    payload = yaml.safe_dump({
        "profiles": {"bad-redirect": {"description": "redirected"}},
    }).encode()

    class _Resp:
        def read(self): return payload
        # The redirect chain landed on the IMDS endpoint.
        def geturl(self):
            return "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        def __enter__(self): return self
        def __exit__(self, *a): return False

    with _mock_resolver({
        "cdn.example.com": ["93.184.216.34"],
        # The redirect target is parsed; its hostname is the IP
        # literal "169.254.169.254" which `socket.gethostbyname_ex`
        # passes through verbatim.
        "169.254.169.254": ["169.254.169.254"],
    }), mock.patch("urllib.request.urlopen", return_value=_Resp()):
        result = _invoke(
            ["profile", "install", "--from",
             "https://cdn.example.com/x.yaml"],
            env={"IAM_JIT_BOUNCER_PROFILES_FILE": str(profiles_path)},
        )
    # The install MUST be refused (exit_code 2 = SSRF refusal per
    # the convention in _InstallFetchError).
    assert result.exit_code == 2, result.output
    # State verification: nothing from the redirected payload
    # landed on disk.
    _assert_no_attacker_profile("bad-redirect")
