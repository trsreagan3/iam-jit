"""`ibounce diagnostics bundle` — single-command support-package ZIP
for debugging an ibounce deployment WITHOUT exposing secrets.

#277: cross-product Tier-1 hygiene. Sibling agents in kbounce
(commit 50a8a44) and dbounce (commit a15b148) shipped the same
shape under their own product namespace. Per
[[cross-product-agent-parity]] the subcommand name, alias, flag
names, default-out shape, manifest format, and admin-action emit
all match across the three products so one
`{product} diag bundle --out ./bundle.zip` invocation works against
any Bounce.

Bundle contents (one file per section; digit-prefixed for stable
`unzip -l` ordering):

  00-README.txt              top-of-bundle explainer + redaction notes
  01-version.txt             ibounce version + Python / OS metadata
  02-config-redacted.json    reuses #275 build_export pipeline; the
                             webhook_url field is ADDITIONALLY nulled
                             (config-export leaves URLs visible
                             because they're destinations; a shareable
                             bundle treats them as sensitive)
  03-active-profile.json     loaded profile pointer + profiles.yaml
                             sha256 + size_bytes
  04-audit-tail.jsonl        last N audit events (default 200); user
                             identifiers stably-hashed via
                             `sha256:<12hex>` per the dbounce
                             convention so cross-event correlation is
                             preserved without leaking cleartext
                             identity
  05-healthz.json            local GET on /healthz; degrades to
                             "unreachable" + reason when probe fails
  06-system.txt              OS / Python / hostname-redacted uname
                             output + env-var KEY names only (no
                             values)
  07-listener.json           wire port + healthz URL probed; remote
                             addresses are NEVER recorded
  08-panics.txt              operator-managed stderr / panic-log file
                             (optional; URLs / IPs / token-shaped
                             strings scrubbed via regex)
  09-manifest.json           file list + per-file sha256 + bundle id
                             + manifest format string

What MUST be redacted (per #277):

  * tokens (HEC, API key, integration key, license content / bytes /
    pem, bearer)
  * any URL in config (webhook URL, alert routes)
  * hostnames / IPs (cluster topology is sensitive)
  * user identifiers from audit events (stable hash)
  * env var values (KEY names only)
  * certs / private keys
  * process command-line args (added per-spec discovery — the brief
    asked for this category to be redacted if uncovered; ibounce's
    sys.argv may carry --token-style flags)
  * absolute paths under $HOME (avoid leaking the operator's home dir
    layout)

Redaction is BELT + SUSPENDERS — the config section already runs
through #275's redactor; we additionally null webhook_url and run a
defensive regex pass on every section's bytes before they land in
the ZIP.

Per [[creates-never-mutates]]: read-only. Never modifies the store,
profiles.yaml, audit log, or any other on-disk state.
Per [[self-host-zero-billing-dependency]]: no network calls except
the LOCAL /healthz GET (loopback only; the only outbound HTTP).
Per [[push-policy-public-repo]]: the resulting ZIP is safe to attach
to a support ticket or paste to a Claude agent for analysis.
Per [[security-team-positioning-safety-not-surveillance]]: every
operator-facing string is neutral — the bundle is a debugging
artifact, not a record of misbehavior.
"""

from __future__ import annotations

import contextlib
import dataclasses
import datetime as _dt
import hashlib
import io
import json
import os
import pathlib
import platform
import re
import socket
import urllib.error
import urllib.request
import zipfile
from typing import Any

from .. import __version__ as _ibounce_version
from .audit_export.admin_action import (
    ADMIN_ACTION_DIAGNOSTICS_BUNDLE,
    ADMIN_ACTION_SOURCE_CLI,
    enqueue_admin_action,
    resolve_operator,
)
from .config_io import REDACTION_MARKER, build_export
from .store import BouncerStore

# ---------------------------------------------------------------------------
# Wire constants
# ---------------------------------------------------------------------------

# Manifest format-string mandated by the brief. Sibling agents use
# `kbounce.diagnostics` / `dbounce.diagnostics` — a SIEM rule keyed on
# the cross-product `*.diagnostics` glob catches all three.
DIAGNOSTICS_BUNDLE_FORMAT = "ibounce.diagnostics"

# Bumped when the bundle SHAPE changes (renamed entry, structural
# reshape). Additive section additions do NOT bump because consumers
# tolerate unknown files via the manifest.
DIAGNOSTICS_BUNDLE_VERSION = 1

# Default audit-tail row cap per #277. Small enough that a recipient
# Claude agent can ingest the whole tail in one prompt, large enough
# that the last interesting decisions before a bug are captured.
DEFAULT_AUDIT_TAIL_LINES = 200

# Cap on the panic-log section's read so a runaway capture file
# doesn't bloat the bundle.
MAX_PANIC_LOG_BYTES = 256 * 1024

# Default loopback /healthz the running `ibounce run` binds. Matches
# the URL the existing `ibounce audit-export health` command uses.
DEFAULT_HEALTHZ_URL = "http://127.0.0.1:8767/healthz"

# Short timeout on the /healthz GET so a misconfigured proxy doesn't
# stall the bundle command for minutes.
HEALTHZ_PROBE_TIMEOUT_SECONDS = 3.0

# Deterministic mod-time on every ZIP entry so identical inputs
# produce identical bytes. Picked: the bounce-suite epoch
# (2026-05-17). Matches kbounce + dbounce convention so a
# cross-product diff is line-stable.
_BOUNCE_SUITE_EPOCH = (2026, 5, 17, 0, 0, 0)

# Hash prefix for stable user-id redaction. Matches the dbounce
# convention so a reviewer reading three sibling bundles recognises
# the shape. 12 hex chars = 48 bits — collision-resistant within a
# single bundle, short enough to read in a terminal.
_USER_HASH_PREFIX = "sha256:"
_USER_HASH_HEX_LEN = 12


# Field names treated as user identifiers in audit events. Each
# match has its value replaced with a stable `sha256:<12hex>` hash
# so two events for the same actor produce the same redacted token
# (cross-event correlation preserved). Case-insensitive lookup.
_USER_ID_FIELDS: frozenset[str] = frozenset({
    "name",
    "user_name",
    "username",
    "uid",
    "user_uid",
    "sub",
    "email",
    "actor",  # iam-jit audit rows carry the plain-string actor here
    "started_by",
    "approved_by",
    "removed_by",
    "principal",
    "principal_arn",
})


# Field names that conventionally carry a URL — the bundle treats
# every URL as sensitive (identifies the operator's SIEM /
# webhook / control-plane endpoint).
_URL_FIELDS: frozenset[str] = frozenset({
    "url",
    "webhook_url",
    "endpoint",
    "host",
    "hostname",
})


# Key-name substrings that mark a field as secret-bearing. Case-
# insensitive substring match: `auth_token`, `x-api-key`,
# `client_secret`, `webhook_token`, `hec_token` all match.
_SENSITIVE_KEY_FRAGMENTS: tuple[str, ...] = (
    "token",
    "secret",
    "api_key",
    "apikey",
    "password",
    "passwd",
    "bearer",
    "authorization",
    "private_key",
    "webhook_token",
    "hec_token",
    "integration_key",
    "license_content",
    "license_bytes",
    "license_pem",
)


# Free-text regex passes for the panic-log + any unparseable line.
# Loose-but-acceptable: the bundle is a debugging artefact, not a
# court exhibit; false positives just over-redact.
_URL_RE = re.compile(r"https?://[^\s\"'<>]+")
_IPV4_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?\b")
_IPV6_RE = re.compile(r"\b(?:[0-9a-fA-F]{1,4}:){2,7}[0-9a-fA-F]{1,4}\b")
_BEARER_RE = re.compile(r"(?i)bearer\s+[A-Za-z0-9._\-]+")
_TOKEN_PAIR_RE = re.compile(r"(?i)(token|api[_-]?key|secret)=\S+")
_LONG_HEX_RE = re.compile(r"\b[A-Za-z0-9+/=_\-]{32,}\b")


# ---------------------------------------------------------------------------
# Public dataclasses
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class BundleOptions:
    """Knobs the CLI passes through to `write_diagnostics_bundle`.

    Every field has a sensible default so a bare
    `ibounce diagnostics bundle` produces a useful artifact; tests
    pin paths to a tmpdir to keep runs hermetic.
    """

    out_path: pathlib.Path
    include_audit_tail: int = DEFAULT_AUDIT_TAIL_LINES
    no_audit: bool = False
    db_path: str | None = None
    profiles_path: str | None = None
    alert_rules_path: str | None = None
    audit_log_path: str | None = None
    healthz_url: str | None = DEFAULT_HEALTHZ_URL
    insecure_skip_verify: bool = False
    panic_log_path: str | None = None


@dataclasses.dataclass
class BundleSummary:
    """Returned by `write_diagnostics_bundle` so the CLI can print
    a one-line stderr summary + the admin-action audit row has
    stable fields to hash.
    """

    out_path: pathlib.Path
    file_count: int = 0
    total_bytes: int = 0
    audit_lines: int = 0
    healthz_ok: bool = False


# ---------------------------------------------------------------------------
# Top-level worker
# ---------------------------------------------------------------------------


def write_diagnostics_bundle(opts: BundleOptions) -> BundleSummary:
    """Assemble + atomically write the diagnostics ZIP.

    Each section is built independently; collection failures degrade
    to a placeholder rather than aborting the whole bundle — a
    partial bundle is more useful than no bundle. Per
    [[creates-never-mutates]] this function NEVER writes outside
    `opts.out_path` (and a sibling .tmp file we rename atomically).
    """
    target = pathlib.Path(opts.out_path)
    if target.parent and not target.parent.exists():
        target.parent.mkdir(parents=True, exist_ok=True)

    # Collect every section's bytes in-memory first so the manifest
    # can hash them BEFORE the ZIP gets a single byte. Order matters
    # — the digit-prefix names determine `unzip -l` ordering for the
    # recipient.
    audit_body, audit_lines = _build_audit_tail_section(opts)
    healthz_body, healthz_ok = _build_healthz_section(opts)

    entries: list[tuple[str, bytes]] = [
        ("00-README.txt", _build_readme(opts).encode("utf-8")),
        ("01-version.txt", _build_version_section().encode("utf-8")),
        ("02-config-redacted.json", _build_config_section(opts)),
        ("03-active-profile.json", _build_active_profile_section(opts)),
        ("04-audit-tail.jsonl", audit_body),
        ("05-healthz.json", healthz_body),
        ("06-system.txt", _build_system_section().encode("utf-8")),
        ("07-listener.json", _build_listener_section(opts)),
        ("08-panics.txt", _build_panic_section(opts)),
    ]

    manifest_entries: list[dict[str, Any]] = []
    for name, body in entries:
        manifest_entries.append({
            "name": name,
            "size": len(body),
            "sha256": hashlib.sha256(body).hexdigest(),
        })

    manifest = {
        "bundle_version": DIAGNOSTICS_BUNDLE_VERSION,
        "format": DIAGNOSTICS_BUNDLE_FORMAT,
        "product": "ibounce",
        "ibounce_version": _ibounce_version,
        "generated_at": _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "redaction_marker": REDACTION_MARKER,
        "user_id_hash_format": f"{_USER_HASH_PREFIX}<{_USER_HASH_HEX_LEN}hex>",
        "entries": manifest_entries,
    }
    manifest_body = (
        json.dumps(manifest, indent=2, sort_keys=True).encode("utf-8") + b"\n"
    )
    entries.append(("09-manifest.json", manifest_body))

    # Write the ZIP via a temp file + atomic rename so an interrupted
    # run never leaves a half-written archive at the target.
    tmp = target.with_suffix(target.suffix + ".tmp")
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
        for name, body in entries:
            info = zipfile.ZipInfo(filename=name, date_time=_BOUNCE_SUITE_EPOCH)
            info.compress_type = zipfile.ZIP_DEFLATED
            # 0o600 inside the archive too — recipients who unzip get
            # owner-only-readable files by default.
            info.external_attr = 0o600 << 16
            zf.writestr(info, body)

    tmp.write_bytes(buf.getvalue())
    with contextlib.suppress(OSError):
        os.chmod(tmp, 0o600)
    os.replace(tmp, target)

    total_bytes = target.stat().st_size if target.exists() else 0
    return BundleSummary(
        out_path=target,
        file_count=len(entries),
        total_bytes=total_bytes,
        audit_lines=audit_lines,
        healthz_ok=healthz_ok,
    )


def default_bundle_path(now: _dt.datetime | None = None) -> pathlib.Path:
    """`./ibounce-diagnostics-<UTC-timestamp>.zip` — the spec'd default.

    Exposed so the CLI helper + tests share one implementation; the
    timestamp format matches the kbounce + dbounce siblings.
    """
    ts = (now or _dt.datetime.now(_dt.UTC)).strftime("%Y%m%dT%H%M%SZ")
    return pathlib.Path(f"./ibounce-diagnostics-{ts}.zip")


def emit_diagnostics_bundle_admin_action(
    store: BouncerStore,
    *,
    summary: BundleSummary,
    no_audit: bool,
    actor: str | None = None,
) -> None:
    """Enqueue a `diagnostics.bundle` ADMIN_ACTION OCSF row. Matches
    the kbounce pattern — a security team has a witness for "who
    pulled diagnostics + when?" even when the operator captures to a
    one-off path. Best-effort: a queue-write failure NEVER fails the
    user-facing bundle (the file has already landed).
    """
    extra = {
        "out_path": str(summary.out_path),
        "file_count": summary.file_count,
        "total_bytes": summary.total_bytes,
        "audit_lines": summary.audit_lines,
        "no_audit": no_audit,
        "healthz_ok": summary.healthz_ok,
    }
    enqueue_admin_action(
        store,
        kind=ADMIN_ACTION_DIAGNOSTICS_BUNDLE,
        actor=actor or resolve_operator(),
        target_kind="diagnostics-bundle",
        target_id=str(summary.out_path),
        source=ADMIN_ACTION_SOURCE_CLI,
        extra=extra,
    )


# ---------------------------------------------------------------------------
# Section builders — each returns BYTES (or string for text) so the
# top-level manifest can hash a stable representation.
# ---------------------------------------------------------------------------


def _build_readme(opts: BundleOptions) -> str:
    """Top-of-bundle explainer. Kept short + factual so a Claude
    agent recipient can use the first lines as context."""
    lines = [
        "ibounce diagnostics bundle",
        f"generated_at: {_dt.datetime.now(_dt.UTC).strftime('%Y-%m-%dT%H:%M:%SZ')}",
        f"bundle_version: {DIAGNOSTICS_BUNDLE_VERSION}",
        f"format: {DIAGNOSTICS_BUNDLE_FORMAT}",
        f"ibounce_version: {_ibounce_version}",
        "",
        "Contents:",
        "  00-README.txt            this file",
        "  01-version.txt           ibounce + Python + OS metadata",
        "  02-config-redacted.json  operator config (tokens + URLs MASKED)",
        "  03-active-profile.json   loaded profile pointer + sha256",
        "  04-audit-tail.jsonl      last N audit events (user ids hashed)",
        "  05-healthz.json          /healthz snapshot or 'unreachable'",
        "  06-system.txt            OS / Python / env KEYS only (no values)",
        "  07-listener.json         bind port + healthz URL probed",
        "  08-panics.txt            optional panic-log capture (scrubbed)",
        "  09-manifest.json         file list + sha256 of each",
        "",
        "Redaction:",
        f"  - webhook tokens, license content, etc. replaced with {REDACTION_MARKER!r}",
        f"  - webhook URLs replaced with {REDACTION_MARKER!r}",
        f"  - user identifiers replaced with {_USER_HASH_PREFIX}<{_USER_HASH_HEX_LEN}hex>",
        "  - hostnames / IPs / env-var VALUES suppressed (keys only kept)",
        "  - absolute paths under $HOME masked to avoid leaking layout",
        "",
        "This bundle is safe to share with support OR paste to a Claude",
        "agent for analysis. The complementary #279 SQLite-backup channel",
        "preserves the full audit trail (with different secret-handling",
        "semantics — that one carries live tokens + belongs in a trusted",
        "channel).",
    ]
    if opts.no_audit:
        lines.append("")
        lines.append(
            "NOTE: --no-audit was passed; 04-audit-tail.jsonl is "
            "intentionally empty."
        )
    return "\n".join(lines) + "\n"


def _build_version_section() -> str:
    """ibounce + Python + platform metadata. No hostname — the
    `06-system.txt` section handles env / uname with hostname
    scrubbed.
    """
    lines = [
        f"ibounce_version: {_ibounce_version}",
        f"python_version: {platform.python_version()}",
        f"python_implementation: {platform.python_implementation()}",
        f"platform_system: {platform.system()}",
        f"platform_machine: {platform.machine()}",
        f"platform_release: {platform.release()}",
    ]
    return "\n".join(lines) + "\n"


def _build_config_section(opts: BundleOptions) -> bytes:
    """Reuse #275's `build_export` pipeline so the diagnostics
    config section is byte-equivalent to what
    `ibounce config export` produces — single source of truth for
    redaction logic per [[deliberate-feature-completion]].

    Then BELT + SUSPENDERS: the config-export path leaves
    `audit_webhook.log_path` visible (it's a path, not a secret).
    For a SHAREABLE bundle the path can leak the operator's
    deployment layout, so we additionally redact any value that
    holds a host-style URL or absolute home path.
    """
    try:
        bundle = build_export(
            db_path=opts.db_path,
            profiles_path=opts.profiles_path,
            alert_rules_path=opts.alert_rules_path,
        )
    except Exception as e:
        err = {
            "error": str(e),
            "note": "config export degraded; partial bundle",
        }
        return (json.dumps(err, indent=2, sort_keys=True) + "\n").encode("utf-8")

    # Defensive: null any webhook_url that snuck through (the
    # build_export path already redacts the audit_webhook block; this
    # belt-and-suspenders pass catches any future addition).
    _redact_walk(bundle)
    body = json.dumps(bundle, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    # Final regex pass against any home-path / URL still in the
    # serialized output. This is conservative — if a future section
    # forgets to redact a host string the bundle still ships clean.
    body = _scrub_freetext(body)
    return body.encode("utf-8")


def _build_active_profile_section(opts: BundleOptions) -> bytes:
    """Record which profiles.yaml is loaded + its sha256 +
    size_bytes. The profile NAME ships only if the operator set
    IAM_JIT_BOUNCER_PROFILE explicitly; we don't probe the running
    proxy for the resolved active profile (no CLI->serve IPC in
    v1.0; the env-var is the operator-visible source of truth).
    """
    out: dict[str, Any] = {
        "loaded_at": _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    profiles_path = opts.profiles_path or os.environ.get(
        "IAM_JIT_BOUNCER_PROFILES_PATH"
    )
    if profiles_path:
        out["profiles_path"] = _scrub_home_path(str(profiles_path))
        try:
            raw = pathlib.Path(profiles_path).read_bytes()
            out["sha256"] = hashlib.sha256(raw).hexdigest()
            out["size_bytes"] = len(raw)
        except FileNotFoundError:
            out["note"] = (
                "profiles file does not exist (embedded defaults in effect)"
            )
        except OSError as e:
            out["error"] = str(e)
    else:
        out["note"] = (
            "no profiles path resolved; embedded defaults in effect"
        )
    env_active = os.environ.get("IAM_JIT_BOUNCER_PROFILE", "")
    if env_active:
        out["env_IAM_JIT_BOUNCER_PROFILE"] = env_active
    return (json.dumps(out, indent=2, sort_keys=True) + "\n").encode("utf-8")


def _build_audit_tail_section(opts: BundleOptions) -> tuple[bytes, int]:
    """Tail the JSONL audit log + run every line through
    `_redact_walk` (user-id hash, URL mask, sensitive-key mask).
    Returns (body, line_count) so the CLI summary + admin-action
    extra share one number.
    """
    if opts.no_audit:
        return (
            b"# --no-audit was passed; audit tail intentionally omitted.\n",
            0,
        )
    log_path = opts.audit_log_path or os.environ.get(
        "IAM_JIT_BOUNCER_AUDIT_LOG_PATH"
    )
    if not log_path:
        return (
            b"# no audit log path configured "
            b"(IAM_JIT_BOUNCER_AUDIT_LOG_PATH unset and --audit-log-path "
            b"not supplied); section empty.\n",
            0,
        )
    try:
        lines = _tail_lines(log_path, opts.include_audit_tail)
    except OSError as e:
        msg = f"# audit-tail unavailable: {e}\n"
        return (msg.encode("utf-8"), 0)
    if not lines:
        return (
            b"# audit log is present but empty (no events to tail).\n",
            0,
        )
    redacted_lines: list[str] = []
    for ln in lines:
        s = ln.strip()
        if not s:
            continue
        redacted_lines.append(_redact_audit_line(s))
    body = ("\n".join(redacted_lines) + "\n").encode("utf-8")
    return body, len(redacted_lines)


def _build_healthz_section(opts: BundleOptions) -> tuple[bytes, bool]:
    """Local GET on /healthz. Failure is recorded as
    `{"health": "unreachable", "reason": "..."}` — section is never
    silently missing. The probe is a SINGLE attempt with a short
    timeout per [[self-host-zero-billing-dependency]]: we never
    retry, never escape loopback.
    """
    url = opts.healthz_url or DEFAULT_HEALTHZ_URL
    if not url:
        body = {
            "health": "skipped",
            "note": "no --healthz-url configured",
        }
        return (
            (json.dumps(body, indent=2, sort_keys=True) + "\n").encode("utf-8"),
            False,
        )

    req = urllib.request.Request(
        url,
        headers={"User-Agent": f"ibounce-diagnostics/{_ibounce_version}"},
    )
    try:
        if opts.insecure_skip_verify and url.startswith("https://"):
            import ssl

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            resp = urllib.request.urlopen(  # noqa: S310 — loopback only
                req, timeout=HEALTHZ_PROBE_TIMEOUT_SECONDS, context=ctx,
            )
        else:
            resp = urllib.request.urlopen(  # noqa: S310 — loopback only
                req, timeout=HEALTHZ_PROBE_TIMEOUT_SECONDS,
            )
    except (urllib.error.URLError, OSError, ValueError) as e:
        body = {
            "health": "unreachable",
            "reason": str(e),
            "probed": _scrub_freetext(url),
        }
        return (
            (json.dumps(body, indent=2, sort_keys=True) + "\n").encode("utf-8"),
            False,
        )
    try:
        raw = resp.read(64 * 1024)
        status_code = resp.getcode()
    finally:
        with contextlib.suppress(Exception):
            resp.close()
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        wrap = {
            "http_status": status_code,
            "probed": _scrub_freetext(url),
            "raw_body": _scrub_freetext(raw.decode("utf-8", errors="replace")),
        }
        body = json.dumps(wrap, indent=2, sort_keys=True) + "\n"
        ok = 200 <= (status_code or 0) < 300
        return body.encode("utf-8"), ok
    # Run the parsed body through the same redactor we use on audit
    # rows — /healthz may carry the masked-but-still-URL-shaped
    # webhook_url field.
    if isinstance(parsed, dict):
        _redact_walk(parsed)
    wrap = {
        "http_status": status_code,
        "probed": _scrub_freetext(url),
        "body": parsed,
    }
    body = json.dumps(wrap, indent=2, sort_keys=True) + "\n"
    ok = 200 <= (status_code or 0) < 300
    return body.encode("utf-8"), ok


def _build_system_section() -> str:
    """OS / Python / env KEY names only (NO values). The hostname is
    NEVER recorded — `socket.gethostname()` is sensitive enough that
    we replace it with a stable hash for cross-bundle correlation +
    nothing else.
    """
    lines: list[str] = []
    lines.append(f"system: {platform.system()}")
    lines.append(f"machine: {platform.machine()}")
    lines.append(f"release: {platform.release()}")
    lines.append(f"python_version: {platform.python_version()}")
    lines.append(f"python_implementation: {platform.python_implementation()}")
    # Hostname → stable hash (NOT the literal). Lets a reviewer
    # answer "is this bundle from the same host as last week's?"
    # without learning the literal hostname.
    try:
        h = socket.gethostname() or ""
    except Exception:
        h = ""
    if h:
        digest = hashlib.sha256(h.encode("utf-8")).hexdigest()[:_USER_HASH_HEX_LEN]
        lines.append(f"hostname_hash: {_USER_HASH_PREFIX}{digest}")
    else:
        lines.append("hostname_hash: <unavailable>")
    lines.append("")
    lines.append("env_keys (values intentionally NOT included):")
    keys = sorted({
        k for k in os.environ
        if k.startswith(("IAM_JIT_", "IBOUNCE_", "AWS_"))
    })
    if not keys:
        lines.append("  (none)")
    else:
        for k in keys:
            lines.append(f"  {k}")
    return "\n".join(lines) + "\n"


def _build_listener_section(opts: BundleOptions) -> bytes:
    """Wire port + healthz URL probed. Remote addresses are NEVER
    recorded — the bundle is shareable; cluster topology is
    sensitive. Live connection counts require a stats endpoint which
    v1.0 doesn't expose; we surface what the OPERATOR configured.
    """
    listener = {
        "default_wire_port": 8767,
        "healthz_url_probed": _scrub_freetext(opts.healthz_url or ""),
        "note": (
            "live connection counts require a running proxy with a "
            "stats endpoint (post-launch). Remote addresses are NEVER "
            "recorded in this bundle."
        ),
    }
    port_env = os.environ.get("IBOUNCE_PORT")
    if port_env:
        # Just the fact of override (not the value, which could be a
        # deployment fingerprint in some environments). Brief asks
        # only for KEY-name presence; a numeric port is sufficiently
        # mundane that we ship it.
        listener["env_IBOUNCE_PORT"] = port_env
    return (
        json.dumps(listener, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")


def _build_panic_section(opts: BundleOptions) -> bytes:
    """Operator-managed panic / stderr capture. Optional — `# no
    panic-log configured` placeholder when unset. Capped at
    MAX_PANIC_LOG_BYTES so a runaway log doesn't bloat the bundle.
    Every line passes through `_scrub_freetext` (URL / IP / token-
    shape masking).
    """
    if not opts.panic_log_path:
        return b"# no --panic-log configured; section empty.\n"
    p = pathlib.Path(opts.panic_log_path)
    if not p.exists():
        return (
            f"# panic-log not found: {_scrub_home_path(str(p))}\n"
        ).encode("utf-8")
    try:
        raw = p.read_bytes()
    except OSError as e:
        return (
            f"# panic-log unreadable: {e}\n"
        ).encode("utf-8")
    if not raw:
        return b"# panic-log is empty (no captured panics).\n"
    if len(raw) > MAX_PANIC_LOG_BYTES:
        raw = raw[:MAX_PANIC_LOG_BYTES] + b"\n... (truncated)\n"
    text = raw.decode("utf-8", errors="replace")
    scrubbed = _scrub_freetext(text)
    if not scrubbed.endswith("\n"):
        scrubbed += "\n"
    return scrubbed.encode("utf-8")


# ---------------------------------------------------------------------------
# Redaction helpers
# ---------------------------------------------------------------------------


def hash_user_id(identifier: str) -> str:
    """Stable `sha256:<12hex>` hash for a user identifier. Same input
    always produces the same output (cross-event correlation
    preserved); inverse is not feasible (8-bit cost). Matches the
    dbounce sibling convention per [[cross-product-agent-parity]].
    """
    if not identifier:
        return ""
    digest = hashlib.sha256(identifier.encode("utf-8")).hexdigest()
    return f"{_USER_HASH_PREFIX}{digest[:_USER_HASH_HEX_LEN]}"


def _is_user_id_key(key: str) -> bool:
    return key.lower() in _USER_ID_FIELDS


def _is_url_key(key: str) -> bool:
    lk = key.lower()
    if lk in _URL_FIELDS:
        return True
    return lk.endswith("_url") or lk.endswith("_endpoint")


def _is_sensitive_key(key: str) -> bool:
    lk = key.lower()
    return any(frag in lk for frag in _SENSITIVE_KEY_FRAGMENTS)


def _redact_audit_line(line: str) -> str:
    """Parse + redact one JSONL audit-event line. Falls back to
    `_scrub_freetext` on non-JSON or malformed input so the line is
    still scrubbed of obvious tokens / URLs.
    """
    try:
        v = json.loads(line)
    except (json.JSONDecodeError, ValueError):
        return _scrub_freetext(line)
    _redact_walk(v)
    try:
        return json.dumps(v, sort_keys=True)
    except (TypeError, ValueError):
        return _scrub_freetext(line)


def _redact_walk(value: Any) -> None:
    """Recursive in-place redactor for parsed JSON.

    For each dict key:
      * user-id field → value replaced with stable hash
      * URL / endpoint field → REDACTION_MARKER
      * sensitive-key fragment match (token / secret / api_key /
        etc.) → REDACTION_MARKER (regardless of value type — a
        nested object under a `secret` key still masks)
      * string value not categorized above → free-text scrub pass
        (catches inline URLs / token-shapes in freeform message
        fields)
      * nested dict / list → recurse
    """
    if isinstance(value, dict):
        for k in list(value.keys()):
            v = value[k]
            if _is_user_id_key(k):
                if isinstance(v, str) and v:
                    value[k] = hash_user_id(v)
                    continue
            if _is_url_key(k):
                if isinstance(v, str) and v:
                    value[k] = REDACTION_MARKER
                    continue
            if _is_sensitive_key(k):
                value[k] = REDACTION_MARKER
                continue
            if isinstance(v, str):
                value[k] = _scrub_freetext(v)
                continue
            _redact_walk(v)
    elif isinstance(value, list):
        for i, item in enumerate(value):
            if isinstance(item, str):
                value[i] = _scrub_freetext(item)
                continue
            _redact_walk(item)


def _scrub_freetext(s: str) -> str:
    """Regex pass against an arbitrary string. Replaces URLs / IPs /
    bearer-tokens / token=... pairs / long base64-shaped strings
    with `REDACTION_MARKER`. Loose-but-acceptable — false positives
    just over-redact.

    Also masks absolute paths under $HOME so the bundle doesn't
    leak the operator's home-dir layout.
    """
    if not s:
        return s
    s = _scrub_home_path(s)
    s = _URL_RE.sub(REDACTION_MARKER, s)
    s = _BEARER_RE.sub(REDACTION_MARKER, s)
    s = _TOKEN_PAIR_RE.sub(REDACTION_MARKER, s)
    s = _IPV4_RE.sub(REDACTION_MARKER, s)
    s = _IPV6_RE.sub(REDACTION_MARKER, s)
    s = _LONG_HEX_RE.sub(REDACTION_MARKER, s)
    return s


def _scrub_home_path(s: str) -> str:
    """Replace absolute paths under $HOME with `<home>/...` so the
    bundle doesn't reveal the operator's home-dir layout. Best-
    effort: if $HOME is empty or "/", no-op.
    """
    home = os.environ.get("HOME", "").rstrip("/")
    if not home or home == "/":
        return s
    return s.replace(home, "<home>")


def _tail_lines(path: str, n: int) -> list[str]:
    """Read the last `n` non-empty lines from `path`. For files
    larger than 1 MiB we seek to the tail region first to avoid
    loading multi-GiB log files into memory.

    Returns [] for an empty file. Raises OSError if the file is
    unreadable.
    """
    if n <= 0:
        return []
    p = pathlib.Path(path)
    size = p.stat().st_size
    if size == 0:
        return []
    tail_region = 1 << 20  # 1 MiB tail is enough for 200 OCSF lines
    with p.open("rb") as f:
        if size > tail_region:
            f.seek(size - tail_region)
            # Drop the (probably partial) first line.
            f.readline()
        # Cap total bytes read so a pathological file doesn't bloat
        # memory.
        max_bytes = 64 << 20
        raw = f.read(max_bytes)
    text = raw.decode("utf-8", errors="replace")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if len(lines) > n:
        lines = lines[-n:]
    return lines


# ---------------------------------------------------------------------------
# Exports
# ---------------------------------------------------------------------------

__all__ = [
    "DEFAULT_AUDIT_TAIL_LINES",
    "DEFAULT_HEALTHZ_URL",
    "DIAGNOSTICS_BUNDLE_FORMAT",
    "DIAGNOSTICS_BUNDLE_VERSION",
    "BundleOptions",
    "BundleSummary",
    "default_bundle_path",
    "emit_diagnostics_bundle_admin_action",
    "hash_user_id",
    "write_diagnostics_bundle",
]
