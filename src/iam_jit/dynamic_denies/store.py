# #324e — Writer-side store for ``~/.iam-jit/dynamic-denies.yaml``.
"""Atomic + permission-enforcing writer for the cross-product
dynamic-deny YAML file.

The reader half lives in :mod:`loader` (#324a). The writer half here
handles every ``iam-jit deny add | remove`` mutation.

Contract:

  * Path resolved via :func:`resolve_default_path` (mirrors the
    loader's path resolution + ``$IAM_JIT_DYNAMIC_DENIES_PATH``
    override).
  * File permissions enforced to **0600** on every write.
  * Atomic write: ``write -> fsync -> rename`` so a concurrent
    bouncer's fsevents/inotify watcher always sees either the OLD or
    NEW file — never a half-written truncate.
  * ULID-suffixed ids (``dd_<26-char-Crockford-base32>``) generated
    here.
  * The YAML serialisation goes through ``ruamel.yaml`` (already a
    dep; round-trip-safe) so operator comments survive a future
    "edit in place" workflow.

Per ``[[creates-never-mutates]]`` the writer NEVER modifies a rule
in-place — every mutation creates a fresh file from the desired list.

Per ``[[ibounce-honest-positioning]]`` the writer fails-CLOSED on
permission errors: a 0644 file refuses to load AND refuses to write
(emits a structured ``DynamicDenyWriteError`` the CLI surfaces to the
operator).
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import hashlib
import io
import os
import pathlib
import platform
import re
import secrets
import time
import typing

from .loader import (
    BOUNCER_NAME as _IBOUNCE_LOADER_NAME,
    DEFAULT_PATH_ENV,
    DEFAULT_REL_PATH,
    PRODUCT_MAGIC,
    SCHEMA_VERSION,
    DynamicDenyLoadError,
    _parse_iso8601 as parse_iso8601,
    resolve_default_path,
)
from .types import Rule

# ULID Crockford base32 alphabet — same as the schema's `dd_<ULID>` regex
# (`[0-9A-HJKMNP-TV-Z]`). Lower-letter-shape duplicates (I/L/O/U) are
# excluded; we emit upper-case for byte-for-byte schema match.
_ULID_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

# Re-validated rule-id pattern (mirrors the schema). Kept here so the
# writer can self-check before flushing the file.
_RULE_ID_PATTERN = re.compile(r"^dd_[0-9A-HJKMNP-TV-Z]{26}$")

# Duration pattern (mirrors loader + schema).
_DURATION_PATTERN = re.compile(r"^(permanent|[0-9]+(s|m|h|d|w))$")

# Default file-permission gate. 0600 — owner read/write only. The
# loader's permission check (when wired) is the matching read side.
_REQUIRED_MODE = 0o600


class DynamicDenyWriteError(RuntimeError):
    """A structured write-side error. Carries a ``stage`` field so the
    CLI can surface a specific failure mode (permission /
    serialisation / atomic-rename) without grepping the message."""

    def __init__(
        self,
        message: str,
        *,
        stage: str,
        path: str | None = None,
        cause: Exception | None = None,
    ) -> None:
        super().__init__(message)
        self.stage = stage
        self.path = path
        self.__cause__ = cause


# ---------------------------------------------------------------------------
# ULID generator
# ---------------------------------------------------------------------------


def new_rule_id() -> str:
    """Generate a fresh ``dd_<ULID>`` id.

    Uses the canonical ULID layout — 48-bit timestamp in ms +
    80-bit random — encoded as 26 chars of Crockford base32. We
    don't pull a third-party `ulid` package because the spec is
    small (one ms timestamp + 10 random bytes) and the schema's
    regex is the only contract we have to satisfy.

    Per `[[self-host-zero-billing-dependency]]` keeping the dep
    surface small is a feature.
    """
    ts_ms = int(time.time() * 1000) & ((1 << 48) - 1)
    rand = secrets.token_bytes(10)
    rand_int = int.from_bytes(rand, "big") & ((1 << 80) - 1)

    encoded = _encode_crockford_48(ts_ms) + _encode_crockford_80(rand_int)
    return f"dd_{encoded}"


def _encode_crockford_48(value: int) -> str:
    """Encode a 48-bit int as 10 chars of Crockford base32 (the ULID
    timestamp segment shape)."""
    chars: list[str] = []
    for _ in range(10):
        chars.append(_ULID_ALPHABET[value & 0x1F])
        value >>= 5
    return "".join(reversed(chars))


def _encode_crockford_80(value: int) -> str:
    """Encode an 80-bit int as 16 chars of Crockford base32 (the ULID
    randomness segment shape)."""
    chars: list[str] = []
    for _ in range(16):
        chars.append(_ULID_ALPHABET[value & 0x1F])
        value >>= 5
    return "".join(reversed(chars))


# ---------------------------------------------------------------------------
# Duration parsing
# ---------------------------------------------------------------------------


def parse_duration(value: str) -> _dt.timedelta | None:
    """Parse a duration string (Go-style: ``30m``, ``3h``, ``7d``,
    ``1w``) into a :py:class:`timedelta`. Returns ``None`` for the
    ``permanent`` literal so the caller knows ``expires_at`` is null.

    Raises :class:`ValueError` for an unparseable string — callers
    (CLI / MCP) catch + surface a structured error matching the
    schema's duration regex.
    """
    if not isinstance(value, str):
        raise ValueError(f"duration must be a string, got {type(value).__name__}")
    s = value.strip()
    if not s:
        raise ValueError("duration must be non-empty")
    if not _DURATION_PATTERN.match(s):
        raise ValueError(
            f"duration {value!r} does not match `permanent` or `N{{s|m|h|d|w}}`",
        )
    if s == "permanent":
        return None
    unit = s[-1]
    qty = int(s[:-1])
    if qty <= 0:
        raise ValueError(f"duration {value!r} must be a positive quantity")
    if unit == "s":
        return _dt.timedelta(seconds=qty)
    if unit == "m":
        return _dt.timedelta(minutes=qty)
    if unit == "h":
        return _dt.timedelta(hours=qty)
    if unit == "d":
        return _dt.timedelta(days=qty)
    if unit == "w":
        return _dt.timedelta(weeks=qty)
    # Should be unreachable given the regex.
    raise ValueError(f"unknown duration unit {unit!r} in {value!r}")


# ---------------------------------------------------------------------------
# Operator identity
# ---------------------------------------------------------------------------


def resolve_operator() -> str:
    """Best-effort operator identity discovery.

    Mirrors ``audit_export.admin_action.resolve_operator()`` so the
    same identity lands in both the YAML file's ``added_by`` AND the
    OCSF audit event's ``actor``. Falls back to ``username@hostname``
    when the env var isn't set.
    """
    explicit = os.environ.get("IAM_JIT_BOUNCER_ACTOR", "").strip()
    if explicit:
        return explicit
    try:
        user = os.environ.get("USER") or os.environ.get("USERNAME") or ""
        if not user:
            import getpass
            user = getpass.getuser()
    except Exception:
        user = "local-operator"
    host = platform.node() or "localhost"
    return f"{user}@{host}" if user else "local-operator"


def hostname_hash_12() -> str:
    """12-hex-char hash of the writer's hostname. Mirrors the schema's
    ``source_hostname_hash`` field — privacy-preserving provenance per
    ``[[cross-product-agent-parity]]``.
    """
    host = (platform.node() or "localhost").encode("utf-8")
    return hashlib.sha256(host).hexdigest()[:12]


# ---------------------------------------------------------------------------
# File-on-disk model
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class StoreFile:
    """In-memory representation of the YAML file the store reads +
    writes.

    Field names mirror the schema. ``denies`` is a list of dicts so
    a future round-trip writer can preserve operator comments
    associated with each rule.
    """

    rules: list[dict[str, typing.Any]] = dataclasses.field(default_factory=list)
    """Per-rule dicts. Each rule dict carries the schema's fields
    verbatim — easy round-trip to ruamel."""

    source_path: str = ""
    """Path the file was read from. Used by the writer to write
    back to the same location."""

    @classmethod
    def empty(cls, path: str) -> "StoreFile":
        return cls(rules=[], source_path=path)

    def rule_index(self, rule_id: str) -> int | None:
        """Linear scan — the rule list is small (operator-managed,
        not a database). Returns the first match or ``None``.
        """
        for i, r in enumerate(self.rules):
            if r.get("id") == rule_id:
                return i
        return None

    def remove_by_id(self, rule_id: str) -> dict[str, typing.Any] | None:
        """Pop the rule with id ``rule_id`` (returns the popped dict
        or ``None`` when no such id is present)."""
        idx = self.rule_index(rule_id)
        if idx is None:
            return None
        return self.rules.pop(idx)


# ---------------------------------------------------------------------------
# Read path (writer-side, distinct from `loader.load_file`)
# ---------------------------------------------------------------------------
#
# The loader filters down to ibounce-applicable rules + drops expired
# entries. The writer needs to see EVERY rule (otherwise a `remove`
# of a kbouncer-only rule would silently fail because the loader
# never returned it). So we re-parse the file here in writer-shape.


def read_store(path: str | None = None) -> StoreFile:
    """Read the YAML file into a :class:`StoreFile`. Missing file ->
    empty store. Parse / structural errors raise
    :class:`DynamicDenyLoadError` so the CLI surfaces "your file is
    corrupt" without writing on top of it.
    """
    resolved = (path or "").strip() or resolve_default_path()
    if not resolved:
        return StoreFile.empty(path="")

    p = pathlib.Path(resolved)
    if not p.exists():
        return StoreFile.empty(path=str(p))

    # Permission check: refuse to load a file with loose perms. The
    # loader emits an admin-action event on this; the writer aborts.
    # Skipped on platforms that don't carry POSIX mode bits (Windows).
    if hasattr(os, "stat") and platform.system() != "Windows":
        try:
            st = p.stat()
            mode = st.st_mode & 0o777
            if mode & 0o077:
                raise DynamicDenyWriteError(
                    f"refusing to read {p}: file mode {oct(mode)} is loose "
                    f"(required: 0600)",
                    stage="perms_loose",
                    path=str(p),
                )
        except DynamicDenyWriteError:
            raise
        except OSError:
            pass

    try:
        raw = p.read_text(encoding="utf-8")
    except OSError as e:
        raise DynamicDenyLoadError(
            f"failed to read {p}: {e}", stage="read", path=str(p), cause=e,
        ) from e

    try:
        from ruamel.yaml import YAML
        yaml_loader = YAML(typ="safe", pure=True)
        data = yaml_loader.load(raw)
    except Exception as e:
        raise DynamicDenyLoadError(
            f"YAML parse error in {p}: {e}", stage="parse",
            path=str(p), cause=e,
        ) from e

    if data is None:
        return StoreFile.empty(path=str(p))
    if not isinstance(data, dict):
        raise DynamicDenyLoadError(
            f"{p}: top-level value must be an object",
            stage="structure", path=str(p),
        )

    sv = data.get("schema_version")
    if sv and sv != SCHEMA_VERSION:
        raise DynamicDenyLoadError(
            f"{p}: unsupported schema_version {sv!r} "
            f"(this iam-jit build accepts {SCHEMA_VERSION!r} only)",
            stage="structure", path=str(p),
        )
    raw_denies = data.get("denies") or []
    if not isinstance(raw_denies, list):
        raise DynamicDenyLoadError(
            f"{p}: `denies` must be a list",
            stage="structure", path=str(p),
        )

    rules: list[dict[str, typing.Any]] = []
    for r in raw_denies:
        if isinstance(r, dict):
            rules.append(dict(r))
        # Skip non-dict entries silently — the structural validator
        # would have caught them in the read path; on the write side
        # we prefer "writer doesn't propagate junk" over "refuse to
        # remove a valid rule because of an unrelated typo nearby".

    return StoreFile(rules=rules, source_path=str(p))


# ---------------------------------------------------------------------------
# Write path
# ---------------------------------------------------------------------------


def write_store(
    store: StoreFile,
    *,
    path: str | None = None,
    enforce_perms: bool = True,
) -> str:
    """Serialise ``store`` to disk atomically.

    Returns the absolute path that was written. Raises
    :class:`DynamicDenyWriteError` on serialisation /
    permission / rename failure (preserves a structured ``stage`` so
    the CLI can surface specifically which step failed).
    """
    resolved = (
        (path or "").strip()
        or store.source_path
        or resolve_default_path()
    )
    if not resolved:
        raise DynamicDenyWriteError(
            "no dynamic-denies.yaml path could be resolved "
            "(HOME unset + IAM_JIT_DYNAMIC_DENIES_PATH unset)",
            stage="resolve_path",
        )
    p = pathlib.Path(resolved)
    parent = p.parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        raise DynamicDenyWriteError(
            f"failed to create parent directory {parent}: {e}",
            stage="mkdir", path=str(p), cause=e,
        ) from e

    # On POSIX, also 0700 the parent dir when we created it fresh
    # (mirrors the schema doc's permission contract).
    if enforce_perms and platform.system() != "Windows":
        try:
            os.chmod(parent, 0o700)
        except OSError:
            # If chmod fails (e.g. operator pre-created the dir with
            # specific perms) honor their choice + continue.
            pass

    body = serialise(store)

    # Write to a temp file in the same directory + rename. tempfile
    # guarantees a unique name; we explicitly set mode 0600 before
    # rename so the destination file's permission floor is enforced
    # even on platforms where umask would loosen the default.
    import tempfile
    fd, tmp_path = tempfile.mkstemp(
        prefix=".dynamic-denies-",
        suffix=".yaml.tmp",
        dir=str(parent),
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(body)
            fh.flush()
            try:
                os.fsync(fh.fileno())
            except OSError:
                # Not all FS support fsync (some test mounts,
                # tmpfs in CI). Honest + non-fatal.
                pass
        if enforce_perms and platform.system() != "Windows":
            os.chmod(tmp_path, _REQUIRED_MODE)
        os.replace(tmp_path, p)
    except Exception as e:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        if isinstance(e, DynamicDenyWriteError):
            raise
        raise DynamicDenyWriteError(
            f"failed to write {p}: {e}",
            stage="atomic_write", path=str(p), cause=e,
        ) from e

    # Belt-and-braces: re-enforce 0600 on the final path. Pre-rename
    # the chmod was on tmp_path; some filesystems carry the temp
    # file's mode through rename, but a few platforms reset it.
    if enforce_perms and platform.system() != "Windows":
        try:
            os.chmod(p, _REQUIRED_MODE)
        except OSError as e:
            raise DynamicDenyWriteError(
                f"failed to enforce 0600 on {p}: {e}",
                stage="perms", path=str(p), cause=e,
            ) from e

    return str(p)


def serialise(store: StoreFile) -> str:
    """Render the store to a YAML string. Returns the body; does not
    touch disk. Useful for tests + `--dry-run` mode in the CLI."""
    payload: dict[str, typing.Any] = {
        "schema_version": SCHEMA_VERSION,
        "product": PRODUCT_MAGIC,
        "exported_at": _utc_now_iso_z(),
        "source_hostname_hash": hostname_hash_12(),
        "denies": [_normalise_rule_for_disk(r) for r in store.rules],
    }
    from ruamel.yaml import YAML
    yaml_writer = YAML(typ="safe", pure=True)
    yaml_writer.default_flow_style = False
    yaml_writer.indent(mapping=2, sequence=4, offset=2)
    buf = io.StringIO()
    yaml_writer.dump(payload, buf)
    return buf.getvalue()


def _normalise_rule_for_disk(rule: dict[str, typing.Any]) -> dict[str, typing.Any]:
    """Return a copy of ``rule`` with fields ordered + cleaned for
    on-disk presentation. The order mirrors the design doc's sample
    YAML so a human-edited file stays diff-friendly.
    """
    out: dict[str, typing.Any] = {}
    for k in (
        "id", "targets", "reason", "duration", "added_by", "added_at",
        "expires_at", "applied_to", "applies_to_recommender", "source",
        "org_distributed_url",
    ):
        if k in rule:
            out[k] = rule[k]
    # Drop org_distributed_url when None — keeps the on-disk file
    # quiet for CLI/MCP-authored rules.
    if out.get("org_distributed_url") is None:
        out.pop("org_distributed_url", None)
    # Don't strip applies_to_recommender — it's a meaningful default
    # the on-disk file should make explicit.
    if "applies_to_recommender" not in out:
        out["applies_to_recommender"] = True
    return out


# ---------------------------------------------------------------------------
# Rule construction
# ---------------------------------------------------------------------------


def build_rule_dict(
    *,
    targets: typing.Sequence[str],
    reason: str,
    duration: str,
    applied_to: typing.Sequence[str],
    applies_to_recommender: bool = True,
    source: str = "cli",
    rule_id: str | None = None,
    added_by: str | None = None,
    added_at: _dt.datetime | None = None,
    org_distributed_url: str | None = None,
) -> dict[str, typing.Any]:
    """Construct a new rule dict ready to land on the
    :class:`StoreFile.rules` list.

    Computes ``expires_at`` from ``duration`` at WRITE time so a
    bouncer on a different host doesn't extend the deny window via
    clock drift (mirrors the schema's expires_at contract).
    """
    rid = (rule_id or new_rule_id()).strip()
    if not _RULE_ID_PATTERN.match(rid):
        raise DynamicDenyWriteError(
            f"generated rule id {rid!r} does not match required shape",
            stage="rule_id",
        )

    delta = parse_duration(duration)  # raises ValueError on bad shape
    now = added_at or _dt.datetime.now(_dt.timezone.utc)
    if now.tzinfo is None:
        now = now.replace(tzinfo=_dt.timezone.utc)
    if delta is None:
        expires_at_str: str | None = None
    else:
        expires_at_str = _iso_z(now + delta)

    if not reason or not reason.strip():
        raise DynamicDenyWriteError(
            "rule `reason` must be a non-empty string",
            stage="rule_reason",
        )
    if not targets:
        raise DynamicDenyWriteError(
            "rule `targets` must contain at least one entry",
            stage="rule_targets",
        )
    if not applied_to:
        raise DynamicDenyWriteError(
            "rule `applied_to` must contain at least one bouncer name",
            stage="rule_applied_to",
        )

    rule = {
        "id": rid,
        "targets": list(targets),
        "reason": reason.strip(),
        "duration": duration,
        "added_by": (added_by or resolve_operator()),
        "added_at": _iso_z(now),
        "expires_at": expires_at_str,
        "applied_to": list(applied_to),
        "applies_to_recommender": bool(applies_to_recommender),
        "source": source,
    }
    if org_distributed_url:
        rule["org_distributed_url"] = org_distributed_url
    return rule


# ---------------------------------------------------------------------------
# Time helpers
# ---------------------------------------------------------------------------


def _utc_now_iso_z() -> str:
    return _iso_z(_dt.datetime.now(_dt.timezone.utc))


def _iso_z(dt: _dt.datetime) -> str:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=_dt.timezone.utc)
    else:
        dt = dt.astimezone(_dt.timezone.utc)
    s = dt.isoformat()
    if s.endswith("+00:00"):
        s = s[: -len("+00:00")] + "Z"
    return s


__all__ = [
    "DEFAULT_PATH_ENV",
    "DEFAULT_REL_PATH",
    "DynamicDenyWriteError",
    "StoreFile",
    "build_rule_dict",
    "hostname_hash_12",
    "new_rule_id",
    "parse_duration",
    "read_store",
    "resolve_operator",
    "serialise",
    "write_store",
]
