"""#524 WB-5 — refuse loose-perms object-storage credentials files.

Per the #484 BB+WB audit WB-5: the object-storage credentials file
(used by the S3-compatible NDJSON sink from #317) had no perm-check
enforcement. SSH (``ssh -i ~/.ssh/id_ed25519``) refuses keys with
broad perms; the AWS CLI (``~/.aws/credentials``) warns / refuses
similarly. iam-jit silently accepted a 0o644 creds file.

The fix introduces two surfaces in
``src/iam_jit/bouncer/audit_export/object_storage.py``:

* :class:`InsecureCredentialsError` — subclass of
  :class:`ObjectStorageCredentialsError` so the proxy startup path
  (which catches the parent) surfaces the refusal through its
  existing channel while specific callers can still narrow.
* ``_enforce_creds_file_perms(path, who=...)`` — stats the file +
  raises when any of mask ``0o077`` is set. Error message names the
  offending mode and gives the exact remediation command
  (``chmod 600 <path>``).

The helper is invoked from ``_load_credentials_file`` BEFORE the
file is parsed (insecure file's contents never enter process memory
through this path).

Per ``docs/CONTRIBUTING.md`` state-verification convention every
test below asserts the ACTUAL ``stat.st_mode`` on disk before the
load call (the precondition the refusal hinges on), not just the
exception type. A sabotage check confirms the gate is load-bearing:
monkeypatching ``_enforce_creds_file_perms`` to a no-op makes the
positive-rejection test fall back to silent-accept, proving the
helper carries the security invariant.

Skipped on Windows where POSIX mode bits are simulated by the
runtime and don't reflect real ACL state — same Windows skip as
the #524 WB-4 canary-perms test.
"""

from __future__ import annotations

import os
import pathlib
import platform
import stat

import pytest

from iam_jit.bouncer.audit_export import (
    InsecureCredentialsError,
    ObjectStorageCredentialsError,
    load_object_storage_credentials,
)
from iam_jit.bouncer.audit_export import object_storage as os_mod


pytestmark = pytest.mark.skipif(
    platform.system() == "Windows",
    reason=(
        "POSIX mode bits on Windows are simulated by the runtime and "
        "do not reflect ACL-backed access control; the WB-5 posture "
        "is a POSIX-only invariant by design (mirrors #524 WB-4 + "
        "local_server.py + cli_canary.py)."
    ),
)


YAML_BODY = (
    "access_key_id: key-from-file\n"
    "secret_access_key: secret-from-file\n"
)
INI_BODY = (
    "[default]\n"
    "access_key_id=key-from-ini\n"
    "secret_access_key=secret-from-ini\n"
)


def _mode(path: pathlib.Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def _write_creds(
    tmp_path: pathlib.Path,
    *,
    mode: int,
    body: str = YAML_BODY,
    name: str = "object-storage-credentials.yaml",
) -> pathlib.Path:
    """Write a creds file at the requested mode + verify it landed."""
    p = tmp_path / name
    p.write_text(body, encoding="utf-8")
    os.chmod(p, mode)
    # State verification: the test's PRECONDITION (the mode that
    # triggers the load-time refusal) is observably true on disk.
    assert _mode(p) == mode, (
        f"fixture failed to set mode 0o{mode:o}; got 0o{_mode(p):o} "
        f"(likely a umask / filesystem issue — test is invalid)"
    )
    return p


# ---------------------------------------------------------------------------
# Tight-perms files load cleanly (no false positives)
# ---------------------------------------------------------------------------


def test_load_credentials_with_0o600_perms_succeeds(
    tmp_path: pathlib.Path,
) -> None:
    """The canonical tight perms (owner read+write) loads cleanly."""
    p = _write_creds(tmp_path, mode=0o600)
    c = load_object_storage_credentials(str(p), env={})
    # Both the credential payload AND the on-disk mode are observable;
    # we assert both so a regression that silently swaps the precondition
    # (e.g. broadening the mask) doesn't pass without also breaking the
    # mode invariant.
    assert c.access_key_id == "key-from-file"
    assert c.secret_access_key == "secret-from-file"
    assert _mode(p) == 0o600


def test_load_credentials_with_0o400_perms_succeeds(
    tmp_path: pathlib.Path,
) -> None:
    """Owner-read-only (no group / world bits) loads cleanly."""
    p = _write_creds(tmp_path, mode=0o400)
    c = load_object_storage_credentials(str(p), env={})
    assert c.access_key_id == "key-from-file"
    assert _mode(p) == 0o400


def test_load_credentials_with_0o600_ini_file_succeeds(
    tmp_path: pathlib.Path,
) -> None:
    """INI shape at 0o600 loads cleanly (perms gate is parser-agnostic)."""
    p = _write_creds(
        tmp_path, mode=0o600, body=INI_BODY,
        name="object-storage-credentials.ini",
    )
    c = load_object_storage_credentials(str(p), env={})
    assert c.access_key_id == "key-from-ini"


# ---------------------------------------------------------------------------
# Loose-perms files refused with operator-actionable message
# ---------------------------------------------------------------------------


def test_load_credentials_with_0o644_perms_refused(
    tmp_path: pathlib.Path,
) -> None:
    """World-readable (the SSH-refusal canonical case) is refused.

    Per ``[[ibounce-honest-positioning]]`` the error names the
    offending mode + gives the exact remediation command so the
    operator can fix it without docs.
    """
    p = _write_creds(tmp_path, mode=0o644)
    # State precondition: the file IS world-readable on disk before
    # the load attempt (the bug shape — silent accept — would also
    # observe this same precondition).
    assert _mode(p) == 0o644
    with pytest.raises(InsecureCredentialsError) as exc_info:
        load_object_storage_credentials(str(p), env={})
    msg = str(exc_info.value)
    # Error message names the offending mode.
    assert "0o644" in msg, f"expected mode in message; got: {msg!r}"
    # Error message gives the exact remediation command.
    assert "chmod 600" in msg, (
        f"expected remediation 'chmod 600' in message; got: {msg!r}"
    )
    # Error message references the file path so the operator knows
    # which file to fix.
    assert str(p) in msg, f"expected file path in message; got: {msg!r}"
    # State verification: the refusal didn't somehow mutate the file
    # (creates-never-mutates posture — load-time refusal is read-only).
    assert _mode(p) == 0o644


def test_load_credentials_with_0o640_perms_refused(
    tmp_path: pathlib.Path,
) -> None:
    """Group-readable (no world bit) is also refused — mask 0o077."""
    p = _write_creds(tmp_path, mode=0o640)
    assert _mode(p) == 0o640
    with pytest.raises(InsecureCredentialsError) as exc_info:
        load_object_storage_credentials(str(p), env={})
    msg = str(exc_info.value)
    assert "0o640" in msg, f"expected mode in message; got: {msg!r}"
    assert "chmod 600" in msg


def test_load_credentials_with_0o604_perms_refused(
    tmp_path: pathlib.Path,
) -> None:
    """World-readable only (no group bit) is also refused — mask 0o077."""
    p = _write_creds(tmp_path, mode=0o604)
    assert _mode(p) == 0o604
    with pytest.raises(InsecureCredentialsError) as exc_info:
        load_object_storage_credentials(str(p), env={})
    msg = str(exc_info.value)
    assert "0o604" in msg, f"expected mode in message; got: {msg!r}"
    assert "chmod 600" in msg


def test_load_credentials_with_0o666_perms_refused(
    tmp_path: pathlib.Path,
) -> None:
    """World-writable + readable (egregious case) is refused."""
    p = _write_creds(tmp_path, mode=0o666)
    assert _mode(p) == 0o666
    with pytest.raises(InsecureCredentialsError):
        load_object_storage_credentials(str(p), env={})


# ---------------------------------------------------------------------------
# Subclass invariant — proxy startup catches the parent + still refuses
# ---------------------------------------------------------------------------


def test_insecure_creds_error_is_subclass_of_credentials_error(
    tmp_path: pathlib.Path,
) -> None:
    """``InsecureCredentialsError`` MUST be a subclass of
    ``ObjectStorageCredentialsError`` so the proxy startup path
    (``bouncer/proxy.py`` catches the parent type via the existing
    try/except around the credentials probe) surfaces insecure-perms
    refusals through the same channel as other creds failures.

    A regression that decouples the inheritance would silently route
    insecure-perms errors past the existing handler.
    """
    assert issubclass(InsecureCredentialsError, ObjectStorageCredentialsError)

    # State verification at the call site: a 0o644 file raises an
    # exception that the parent-catching handler WOULD catch.
    p = _write_creds(tmp_path, mode=0o644)
    try:
        load_object_storage_credentials(str(p), env={})
    except ObjectStorageCredentialsError as e:
        assert isinstance(e, InsecureCredentialsError)
    else:
        pytest.fail("expected ObjectStorageCredentialsError subtype to raise")


# ---------------------------------------------------------------------------
# End-to-end via the proxy startup wiring shape
# ---------------------------------------------------------------------------


def test_load_credentials_end_to_end_path_used_by_proxy_startup(
    tmp_path: pathlib.Path,
) -> None:
    """The proxy's ``start_proxy`` (``bouncer/proxy.py:4428``) calls
    ``load_object_storage_credentials(config.audit_object_storage_credentials_file)``.

    Reproduce that exact code path with a 0o644 fixture and assert the
    bouncer would refuse to start. The state verification here is the
    raised exception itself — the proxy's startup is short-circuited
    before any S3 client / bucket probe / writer-start happens, which
    is precisely the WB-5 invariant.
    """
    p = _write_creds(tmp_path, mode=0o644)
    # Mirror the exact call shape the proxy uses at proxy.py:4428.
    with pytest.raises(ObjectStorageCredentialsError) as exc_info:
        load_object_storage_credentials(str(p))
    # The narrower subtype carries the WB-5 invariant.
    assert isinstance(exc_info.value, InsecureCredentialsError)


def test_load_credentials_end_to_end_path_with_tight_perms_proceeds(
    tmp_path: pathlib.Path,
) -> None:
    """Companion to the previous test: with 0o600 the proxy's call
    shape returns usable creds (the next stage — bucket probe — would
    proceed; the WB-5 gate doesn't get in the way of the happy path)."""
    p = _write_creds(tmp_path, mode=0o600)
    c = load_object_storage_credentials(str(p))
    assert c.access_key_id == "key-from-file"
    assert c.secret_access_key == "secret-from-file"


# ---------------------------------------------------------------------------
# Sabotage check — proves the helper is load-bearing
# ---------------------------------------------------------------------------


def test_sabotage_disabling_perm_check_makes_loose_perms_accepted(
    tmp_path: pathlib.Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Sabotage check: if ``_enforce_creds_file_perms`` is replaced
    with a no-op, a 0o644 creds file is silently accepted.

    This proves the gate is the load-bearing piece (per #463 / #475
    state-verification discipline: a "perm-check" assertion that
    passes without the perm check actively rejecting is a #326-shape
    bug). The positive-rejection test above (0o644 refused) means
    nothing without this counterfactual.
    """
    p = _write_creds(tmp_path, mode=0o644)
    # Baseline: with the real helper, loading is refused.
    with pytest.raises(InsecureCredentialsError):
        load_object_storage_credentials(str(p), env={})
    # Sabotage: replace the helper with a no-op.
    monkeypatch.setattr(os_mod, "_enforce_creds_file_perms", lambda *a, **k: None)
    # Now the same 0o644 file loads silently — proves the helper
    # carries the WB-5 invariant. If this assertion ever fails it
    # means the perm check has moved elsewhere (which is fine — but
    # update this test so the load-bearing surface stays explicitly
    # named).
    c = load_object_storage_credentials(str(p), env={})
    assert c.access_key_id == "key-from-file"
    # State verification: the fixture's mode is still loose on disk
    # (the sabotage didn't accidentally tighten it as a side effect).
    assert _mode(p) == 0o644


# ---------------------------------------------------------------------------
# Helper-direct tests — pinpoint the gate's contract
# ---------------------------------------------------------------------------


def test_enforce_creds_file_perms_with_0o600_is_noop(
    tmp_path: pathlib.Path,
) -> None:
    """Direct helper test: 0o600 returns cleanly with no exception."""
    p = tmp_path / "creds"
    p.write_text("x", encoding="utf-8")
    os.chmod(p, 0o600)
    # No raise == pass.
    os_mod._enforce_creds_file_perms(p)


def test_enforce_creds_file_perms_with_0o644_raises_with_who_label(
    tmp_path: pathlib.Path,
) -> None:
    """Direct helper test: the ``who`` label appears in the error
    message so the operator can tell WHICH credentials surface is
    misconfigured (useful when a future caller plumbs the helper
    into a second creds source)."""
    p = tmp_path / "creds"
    p.write_text("x", encoding="utf-8")
    os.chmod(p, 0o644)
    with pytest.raises(InsecureCredentialsError) as exc_info:
        os_mod._enforce_creds_file_perms(p, who="some_other_creds_surface")
    assert "some_other_creds_surface" in str(exc_info.value)


def test_enforce_creds_file_perms_missing_file_is_noop(
    tmp_path: pathlib.Path,
) -> None:
    """Missing file: the helper returns cleanly (the caller's parse
    path raises its own ``file not found`` via ``ObjectStorageCredentialsError``
    using the same error type the test for missing files expects)."""
    p = tmp_path / "definitely-not-there"
    os_mod._enforce_creds_file_perms(p)


def test_load_credentials_missing_file_still_raises_credentials_error(
    tmp_path: pathlib.Path,
) -> None:
    """Companion to the helper's missing-file behaviour: at the
    public surface the error type is still ``ObjectStorageCredentialsError``
    (NOT the insecure-perms subtype) — file-not-found and
    loose-perms are distinct failure modes the operator distinguishes
    via the message + type."""
    p = tmp_path / "not-there.yaml"
    with pytest.raises(ObjectStorageCredentialsError) as exc_info:
        load_object_storage_credentials(str(p), env={})
    assert not isinstance(exc_info.value, InsecureCredentialsError)
    assert "not found" in str(exc_info.value)
