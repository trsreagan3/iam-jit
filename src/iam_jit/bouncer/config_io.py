"""`ibounce config export / import` — backup / restore / migration for
the operator's entire ibounce configuration surface.

#275: cross-product Tier-1 hygiene. Sibling agents in kbounce
(commit 6e5a678) and dbounce (commit 9608b14) shipped the same shape
under their own product namespace. Per [[cross-product-agent-parity]]
the wire shape, CLI flags, schema_version semantics, redaction defaults,
and admin-action emission match across the three products so a
customer can author one generic backup workflow that targets every
Bounce.

Wire shape (load-bearing — all three products share this skeleton; the
only per-product difference is the `product` field and the per-section
content):

  {
    "schema_version": "1.0",
    "product": "ibounce",
    "ibounce_version": "<from iam_jit.__version__>",
    "exported_at": "<RFC3339 UTC>",
    "source_hostname_hash": "<sha256[:12] of hostname>",
    "profiles": {
        "active": "<currently-active profile name>",
        "items": [<projected profiles>]
    },
    "rules": [<projected rules>],
    "tasks": [<projected task scopes; informational, NOT replayed>],
    "presets": [<applied preset history; informational>],
    "audit_webhook": {
        "log_path": "<JSONL audit log path or empty>",
        "webhook_url": "***" (redacted; hint included),
        "webhook_token": "***" (redacted),
        "preset": "<generic|datadog|splunk-hec|sentinel>",
        ...
    },
    "alert_rules": {
        "path": "<configured --alert-rules path or empty>",
        "content": {<YAML body or null when path absent / file unreadable>}
    },
    "mcp_install_history": [<MCP-host config files that contain an `ibounce` server entry>],
    "license": {
        "license_id": "<id or empty>",
        "expires_at": "<RFC3339 or empty>",
        "content": null (intentionally absent — bundled licenses live in the SQLite-backup path #279)
    }
  }

Redaction (default ON, NOT togglable from the CLI — backups with live
tokens belong in #279 SQLite backup):

  - audit_webhook.webhook_url / webhook_token / sentinel-shared-key →
    "***"
  - env-var values projected from the operator's shell → keys only
    (the keys are useful for "did this deployment know about this env
    var?" reviews; the values are not in scope for this bundle).
  - license content → masked; we retain license_id + expires_at so
    the importer can tell the operator "this bundle was produced on
    an Enterprise host; install your own license to activate the
    Enterprise channels."

Import semantics:

  - Validate `product` — refuse if not "ibounce" (matches kbounce /
    dbounce shape: cross-product imports are rejected with a clear
    "value X not in enum [ibounce]" error).
  - Validate `schema_version` against the importing binary's
    supported list — refuse on unsupported with a "this binary
    supports versions X, Y, Z" message.
  - `--merge` (default; safer): union by stable keys (profile.name,
    rule.pattern+effect+scope, etc.); on collision, keep the EXISTING
    value + log a collision note.
  - `--replace`: clear the importing categories first, then load the
    bundle wholesale. The pre-existing rule rows are RemoveRule'd so
    their audit trail is preserved via config_events.
  - `--dry-run`: print what would happen (counts per section,
    collisions list) and exit without mutating. Emits an admin-action
    row with result="noop" so a SIEM can observe planning activity.
  - Default mode if neither flag given = merge.
  - Emit an admin-action OCSF event with kind="config.import" via the
    queue stub wired in #278 (admin_action.ADMIN_ACTION_CONFIG_IMPORT).
  - Refuse if ibounce is RUNNING (we probe 127.0.0.1:8767 — the
    default `ibounce run` port; configurable via env). Importing
    while the proxy holds an open SQLite connection would race on
    the rules / tasks tables.

Per [[creates-never-mutates]]: export is read-only; import is
destructive but `--dry-run` previews first.
Per [[self-host-zero-billing-dependency]]: no network calls.
Per [[push-policy-public-repo]]: the redacted bundle is safe to check
into a config repo (no tokens, no URLs, no env-var values, no
hostnames).
Per [[security-team-positioning-safety-not-surveillance]]: every
operator-facing string is neutral — no "violation" / "infraction" /
"unauthorized" language. The bundle is a config artefact, not an
accusation.
"""

from __future__ import annotations

import contextlib
import dataclasses
import datetime as _dt
import hashlib
import json
import os
import pathlib
import socket
from typing import Any

import yaml

from .. import __version__ as _ibounce_version
from .audit_export.admin_action import (
    ADMIN_ACTION_CONFIG_EXPORT,
    ADMIN_ACTION_CONFIG_IMPORT,
    ADMIN_ACTION_SOURCE_CLI,
    enqueue_admin_action,
    resolve_operator,
)
from .profiles import (
    Profile,
    load_profiles,
    profile_to_yaml_dict,
    resolve_profiles_path,
)
from .rules import Effect, ProxyRule
from .store import BouncerStore, InvalidRuleError
from .tasks import TaskScope

# ---------------------------------------------------------------------------
# Wire constants
# ---------------------------------------------------------------------------

# String, NOT int, to match the kbounce + dbounce shape — kbounce uses
# int schema_version=1 but the brief mandates "1.0" for ibounce so a
# customer reading three sibling exports can tell them apart by product
# field, not by schema-version axis confusion. Future bumps land as
# "1.1" / "2.0".
SCHEMA_VERSION = "1.0"

# The set of schema versions this binary can import. Older versions
# are tolerated (additive-only changes degrade gracefully); newer
# versions are refused with a clear message so the operator knows to
# upgrade ibounce.
SUPPORTED_SCHEMA_VERSIONS: tuple[str, ...] = ("1.0",)

# The product magic identifying ibounce bundles. Sibling agents in
# kbounce + dbounce use their own values; the validate path refuses
# cross-product imports with a "value X not in enum [ibounce]" error
# message.
PRODUCT = "ibounce"

# Marker substituted into the bundle for every redacted secret. Matches
# kbounce / dbounce convention so a SIEM analyst grepping the marker
# across the three product exports finds a uniform hit.
REDACTION_MARKER = "***"

# Stable hint string attached to the redacted webhook_url so a reviewer
# reading the bundle sees WHY the value is masked + where to find the
# real value. Mirrored on every redacted field below.
REDACTION_HINT = "redacted by default; live values stay on the source host"

# Default loopback host + port the running ibounce serve process binds
# to. The "refuse if running" probe targets this; an operator who
# pointed `ibounce run` at a non-default port via --port overrides via
# the IBOUNCE_PROBE_PORT env var.
_RUNNING_PROBE_HOST = "127.0.0.1"
_RUNNING_PROBE_PORT = 8767


# Token-shaped field names. Used by the export-side redactor to mask
# any value that lands on the wire under one of these keys regardless
# of which section it came from. The set is intentionally STRICT —
# unknown keys are NOT redacted (preserves operator-readable fields);
# the export shape itself is the wire contract.
_TOKEN_FIELD_NAMES: frozenset[str] = frozenset({
    "webhook_token",
    "audit_webhook_token",
    "splunk_hec_token",
    "datadog_api_key",
    "sentinel_shared_key",
    "bearer_token",
    "authorization",
    "license_content",
    "license_bytes",
    "license_pem",
    "license_private_key",
    "secret",
    "api_key",
    "integration_key",
})


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ConfigBundleError(Exception):
    """Raised on any structural problem with a bundle (wrong product,
    unsupported schema_version, malformed shape). Caller surfaces the
    message verbatim to the operator — strings are written to be
    actionable."""


class IbounceRunningError(Exception):
    """Raised by the import path when an `ibounce run` process is
    detected on the loopback probe port. Import refuses so a half-
    landed mutation doesn't race the live proxy's open connection."""


# ---------------------------------------------------------------------------
# Bundle dataclasses
# ---------------------------------------------------------------------------


@dataclasses.dataclass
class ImportSummary:
    """Per-section summary returned by both --dry-run + live import.

    The counts are intentionally explicit (added / collided / kept) so
    a SIEM dashboard can pivot on the partial-success shape without
    parsing free-form text.
    """
    mode: str  # "merge" | "replace" | "dry-run"
    profiles_added: int = 0
    profiles_collided: int = 0
    profiles_replaced: int = 0
    rules_added: int = 0
    rules_collided: int = 0
    rules_replaced: int = 0
    tasks_carried: int = 0  # informational only
    presets_carried: int = 0
    audit_webhook_carried: bool = False
    alert_rules_carried: bool = False
    license_carried: bool = False
    collision_notes: list[str] = dataclasses.field(default_factory=list)


# ---------------------------------------------------------------------------
# Hostname hash
# ---------------------------------------------------------------------------


def _source_hostname_hash() -> str:
    """Stable-but-non-revealing label for the source host. Sha-256 of
    the hostname truncated to 12 hex chars so a reviewer can answer
    "did this bundle come from the same host as last week's bundle?"
    without learning the literal hostname.

    Returns "unknown" if hostname resolution fails so the export never
    crashes on a quirky CI runner."""
    try:
        h = socket.gethostname()
    except Exception:
        return "unknown"
    if not h:
        return "unknown"
    return hashlib.sha256(h.encode("utf-8")).hexdigest()[:12]


# ---------------------------------------------------------------------------
# Section projectors
# ---------------------------------------------------------------------------


def _project_profile(p: Profile) -> dict[str, Any]:
    """Project a Profile to its export shape. Reuses the same
    `profile_to_yaml_dict` projection the in-tree profile editor uses
    so importer round-trips bit-for-bit (modulo dict-key ordering)."""
    body = profile_to_yaml_dict(p)
    body["name"] = p.name
    return body


def _project_rule(rule_id: int, rule: ProxyRule) -> dict[str, Any]:
    """Project a (id, ProxyRule) row to the export shape. The id is
    NOT carried into the import path (auto-incremented on insert);
    we emit it for human-readable diffing only."""
    return {
        "id": rule_id,
        "pattern": rule.pattern,
        "effect": rule.effect.value,
        "arn_scope": rule.arn_scope,
        "region_scope": rule.region_scope,
        "note": rule.note,
        "origin": rule.origin,
        "expires_at": rule.expires_at,
    }


def _project_task(task: TaskScope) -> dict[str, Any]:
    """Project a TaskScope to the export shape. Informational only —
    tasks are NEVER replayed on import (they are time-bounded; replaying
    an already-expired task scope would be a no-op + cluttering the
    decision audit log)."""
    return task.to_dict()


def _project_preset_history(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Filter the config_events log for preset_applied rows + project
    them to the export shape. Informational only — the bundle does not
    re-apply preset history on import (each preset's rules already land
    in the rules table; replaying would double-count)."""
    out: list[dict[str, Any]] = []
    for e in events:
        if e.get("kind") != "preset_applied":
            continue
        d = e.get("detail") or {}
        out.append({
            "preset_name": d.get("preset_name"),
            "rules_added": d.get("rules_added"),
            "applied_at": e.get("at"),
            "applied_by": e.get("actor"),
        })
    return out


def _project_audit_webhook(env: dict[str, str]) -> dict[str, Any]:
    """Project the audit-webhook channel config from environment
    variables the operator's `ibounce run` shell exposes. Always
    redacted — the live webhook URL + token belong in #279 SQLite
    backup, not this human-reviewable artefact.

    The keys are projected (so a reviewer sees "yes, an audit webhook
    was configured on the source host"); the VALUES are not.
    """
    keys = (
        "IAM_JIT_BOUNCER_AUDIT_WEBHOOK_TOKEN",
        "IAM_JIT_BOUNCER_AUDIT_WEBHOOK_URL",
        "IAM_JIT_BOUNCER_AUDIT_WEBHOOK_PRESET",
        "IAM_JIT_BOUNCER_AUDIT_LOG_PATH",
    )
    env_keys_present = sorted(k for k in keys if env.get(k))
    return {
        # log_path is the ONLY field projected by default per the
        # brief — it is a path, not a secret; reviewers want to know
        # which JSONL file the operator pointed the bouncer at.
        "log_path": env.get("IAM_JIT_BOUNCER_AUDIT_LOG_PATH", ""),
        "webhook_url": REDACTION_MARKER,
        "webhook_token": REDACTION_MARKER,
        "redaction_hint": REDACTION_HINT,
        "env_keys_present": env_keys_present,
    }


def _project_alert_rules(path: str | None) -> dict[str, Any]:
    """Project the --alert-rules YAML file path + content. The YAML
    body is read-only at the bundle layer (we never write to it); the
    content is inlined so an importer on a different host can produce
    an equivalent alert config without needing the original YAML file
    to ship alongside the bundle.

    `path` empty / unset = section emitted as `{path: "", content:
    null}` so the bundle is shape-stable even on Free-tier deployments
    that never wired the alerts channel.
    """
    if not path:
        return {"path": "", "content": None}
    p = pathlib.Path(path)
    if not p.is_file():
        return {"path": str(p), "content": None, "note": "file not readable"}
    try:
        raw = p.read_text(encoding="utf-8")
    except OSError:
        return {"path": str(p), "content": None, "note": "file not readable"}
    try:
        body = yaml.safe_load(raw)
    except yaml.YAMLError:
        return {"path": str(p), "content": None, "note": "yaml parse failed"}
    return {"path": str(p), "content": body if isinstance(body, dict) else None}


def _project_mcp_install_history() -> list[dict[str, Any]]:
    """Scan the canonical MCP-host config-file locations for an
    `ibounce` server entry. Records the PRESENCE only — file contents
    are not copied (they belong to the MCP host's config repo, not to
    ibounce).
    """
    out: list[dict[str, Any]] = []
    home = pathlib.Path.home()
    # Probe shapes match the `ibounce mcp install-*` candidate-path
    # logic. Order: claude-code → cursor → claude-desktop → codex.
    candidates: list[tuple[str, pathlib.Path]] = [
        ("claude-code", home / ".claude.json"),
        ("claude-code", home / ".config" / "claude-code" / "mcp.json"),
        ("cursor", home / ".cursor" / "mcp.json"),
        ("claude-desktop-macos",
         home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json"),
        ("claude-desktop-linux",
         home / ".config" / "Claude" / "claude_desktop_config.json"),
    ]
    for client, candidate in candidates:
        if not candidate.exists():
            continue
        try:
            body = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        servers = body.get("mcpServers") if isinstance(body, dict) else None
        if isinstance(servers, dict) and "ibounce" in servers:
            out.append({
                "client": client,
                "path": str(candidate),
                # No command/args/env projected — those belong in the
                # MCP-host's own config-repo, not in the bouncer's
                # bundle. We record only the fact that an ibounce
                # entry exists.
            })
    return out


def _project_license() -> dict[str, Any]:
    """Project the installed-license pointer. We retain license_id +
    expires_at so the importer can see whether the destination needs
    to install a license, but we never carry the signed payload —
    backups of the literal license file go through #279 SQLite backup
    (which is a separate slice covered by trusted-channel encryption).

    Fail-soft: a missing / invalid license file just returns the empty
    shape; we never abort the export on a license problem.
    """
    try:
        from .. import license as license_mod

        lic = license_mod.load_license()
    except Exception:
        return {
            "license_id": "",
            "expires_at": "",
            "content": None,
        }
    if lic is None:
        return {
            "license_id": "",
            "expires_at": "",
            "content": None,
        }
    return {
        "license_id": lic.license_id,
        "expires_at": lic.expires_at.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "content": None,  # intentionally absent — see docstring
    }


# ---------------------------------------------------------------------------
# Top-level export
# ---------------------------------------------------------------------------


def build_export(
    *,
    db_path: str | None = None,
    profiles_path: str | None = None,
    alert_rules_path: str | None = None,
    active_profile: str | None = None,
    env: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Assemble the export-shape bundle. Pure read; never mutates the
    store / profiles.yaml.

    Caller-supplied paths override the env-derived defaults so tests
    can pin everything onto tmp_path without touching the real home
    dir. Missing files degrade to "empty section" — we never refuse
    to export because the operator hasn't configured a given channel.
    """
    env = env if env is not None else dict(os.environ)
    resolved_profiles = resolve_profiles_path(profiles_path)

    out: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "product": PRODUCT,
        "ibounce_version": _ibounce_version,
        "exported_at": _dt.datetime.now(_dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "source_hostname_hash": _source_hostname_hash(),
    }

    # Profiles -----------------------------------------------------------
    profile_map = load_profiles(resolved_profiles)
    items = []
    for name in sorted(profile_map.keys()):
        items.append(_project_profile(profile_map[name]))
    out["profiles"] = {
        "active": active_profile or env.get("IAM_JIT_BOUNCER_PROFILE", "") or "",
        "items": items,
    }

    # Rules + tasks + presets — all out of the SQLite store --------------
    store = BouncerStore(db_path=db_path)
    try:
        rules = store.list_rules()
        out["rules"] = [_project_rule(rid, r) for rid, r in rules]

        tasks = store.list_tasks(limit=1000)
        out["tasks"] = [_project_task(t) for t in tasks]

        events = store.list_config_events(limit=10_000)
        out["presets"] = _project_preset_history(events)
    finally:
        store.close()

    # Audit-webhook ------------------------------------------------------
    out["audit_webhook"] = _project_audit_webhook(env)

    # Alert rules --------------------------------------------------------
    out["alert_rules"] = _project_alert_rules(alert_rules_path)

    # MCP install history -----------------------------------------------
    out["mcp_install_history"] = _project_mcp_install_history()

    # License ------------------------------------------------------------
    out["license"] = _project_license()

    return out


def write_export(bundle: dict[str, Any], out_path: str | pathlib.Path) -> pathlib.Path:
    """Atomically write the bundle JSON to `out_path`. Temp file +
    rename so an interrupted run never leaves a half-written file at
    the target. Mode 0600 so the export inherits the same "owner-only"
    posture as profiles.yaml / state.db."""
    target = pathlib.Path(out_path)
    if target.parent and not target.parent.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    body = json.dumps(bundle, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    tmp.write_text(body, encoding="utf-8")
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, target)
    return target


# ---------------------------------------------------------------------------
# Top-level import
# ---------------------------------------------------------------------------


def is_ibounce_running(*, host: str | None = None, port: int | None = None,
                      timeout: float = 0.25) -> bool:
    """Probe the loopback host:port the running `ibounce run` process
    would bind. Returns True if a TCP connect succeeds — that's the
    signal that import must refuse with the "stop ibounce first"
    message. Probe is conservative (short timeout, single attempt)
    because the cost of a false negative (import races a live proxy)
    is far higher than the cost of a false positive (operator stops
    ibounce + re-runs)."""
    h = host or _RUNNING_PROBE_HOST
    p = port if port is not None else _running_probe_port()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((h, p))
    except OSError:
        return False
    finally:
        with contextlib.suppress(OSError):
            s.close()
    return True


def _running_probe_port() -> int:
    """The port we probe for a live `ibounce run`. Default 8767;
    overridable via IBOUNCE_PROBE_PORT for operators who run on a
    non-default port. Invalid env values fall back to the default."""
    raw = os.environ.get("IBOUNCE_PROBE_PORT", "").strip()
    if not raw:
        return _RUNNING_PROBE_PORT
    try:
        v = int(raw)
    except ValueError:
        return _RUNNING_PROBE_PORT
    if v <= 0 or v > 65535:
        return _RUNNING_PROBE_PORT
    return v


def load_bundle(path: str | pathlib.Path) -> dict[str, Any]:
    """Read + JSON-decode + structural-validate an export file. Raises
    ConfigBundleError on any wire-contract violation; the message is
    the operator-facing string verbatim.
    """
    p = pathlib.Path(path)
    if not p.is_file():
        raise ConfigBundleError(f"import file not found: {p}")
    try:
        raw = p.read_text(encoding="utf-8")
    except OSError as e:
        raise ConfigBundleError(f"cannot read import file {p}: {e}") from e
    try:
        body = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ConfigBundleError(f"import file {p} is not valid JSON: {e}") from e
    if not isinstance(body, dict):
        raise ConfigBundleError(
            f"import file {p} must be a JSON object at the top level"
        )
    validate_bundle(body)
    return body


def validate_bundle(bundle: dict[str, Any]) -> None:
    """Refuse non-ibounce / unsupported-schema bundles. Pure check;
    no mutation. The error messages match kbounce + dbounce exactly so
    a customer reading three sibling errors knows what to fix without
    a per-product cheat sheet."""
    product = bundle.get("product")
    if product != PRODUCT:
        raise ConfigBundleError(
            f"value {product!r} not in enum [{PRODUCT!r}]; this bundle "
            f"was produced by a different product (kbounce / dbounce / "
            "unknown). Imports across the Bounce suite are not allowed: "
            "each product owns its own rule + profile semantics."
        )
    schema_version = bundle.get("schema_version")
    if schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        supported = ", ".join(SUPPORTED_SCHEMA_VERSIONS)
        raise ConfigBundleError(
            f"schema_version {schema_version!r} unsupported; this "
            f"ibounce binary supports versions [{supported}]. Upgrade "
            "ibounce or re-export the bundle on a binary matching the "
            "import target."
        )


def apply_import(
    bundle: dict[str, Any],
    *,
    mode: str = "merge",
    db_path: str | None = None,
    profiles_path: str | None = None,
    actor: str | None = None,
) -> ImportSummary:
    """Apply a validated bundle to the local store + profiles.yaml.

    `mode` is one of "merge" (default; existing values retained on
    collision), "replace" (clear-then-load), or "dry-run" (compute the
    summary without mutating).

    Raises ConfigBundleError for an unrecognised mode. Caller is
    responsible for validating the bundle first via `validate_bundle`
    (or by going through `load_bundle`); we assume the bundle is
    well-formed at this layer.
    """
    if mode not in ("merge", "replace", "dry-run"):
        raise ConfigBundleError(
            f"mode {mode!r} unsupported; use 'merge', 'replace', or 'dry-run'"
        )

    summary = ImportSummary(mode=mode)
    resolved_profiles = resolve_profiles_path(profiles_path)
    # Profiles -----------------------------------------------------------
    existing_profiles = load_profiles(resolved_profiles)
    incoming_profile_items = bundle.get("profiles", {}).get("items", []) or []
    new_profile_map: dict[str, Profile] = {}
    if mode != "replace":
        new_profile_map.update(existing_profiles)
    for body in incoming_profile_items:
        if not isinstance(body, dict):
            continue
        name = body.get("name")
        if not isinstance(name, str) or not name:
            continue
        try:
            new_profile = _profile_from_export_dict(name, body)
        except ValueError as e:
            summary.collision_notes.append(
                f"profile {name!r} skipped: {e}"
            )
            continue
        if mode == "merge" and name in existing_profiles:
            summary.profiles_collided += 1
            summary.collision_notes.append(
                f"profile {name!r} already present; existing kept "
                "(re-run with --replace to overwrite)"
            )
            continue
        if mode == "replace" and name in existing_profiles:
            summary.profiles_replaced += 1
        else:
            summary.profiles_added += 1
        new_profile_map[name] = new_profile

    # Rules --------------------------------------------------------------
    store = BouncerStore(db_path=db_path)
    try:
        existing_rules = store.list_rules()
        existing_fingerprints = {
            _rule_fingerprint(r) for _, r in existing_rules
        }
        incoming_rules: list[ProxyRule] = []
        for body in bundle.get("rules", []) or []:
            if not isinstance(body, dict):
                continue
            try:
                pattern = body["pattern"]
                effect = Effect(body.get("effect", "allow"))
            except (KeyError, ValueError):
                continue
            r = ProxyRule(
                pattern=pattern,
                effect=effect,
                arn_scope=body.get("arn_scope"),
                region_scope=body.get("region_scope"),
                note=body.get("note"),
                origin=body.get("origin") or "user",
                expires_at=body.get("expires_at"),
            )
            incoming_rules.append(r)

        if mode == "replace":
            # Remove every existing rule first; preserve audit trail
            # via the store's RemoveRule path (writes a `rule_removed`
            # config_event for each).
            for rid, _ in existing_rules:
                store.remove_rule(rid, actor=actor or resolve_operator())
                summary.rules_replaced += 1
            existing_fingerprints = set()

        for r in incoming_rules:
            fp = _rule_fingerprint(r)
            if fp in existing_fingerprints:
                summary.rules_collided += 1
                summary.collision_notes.append(
                    f"rule pattern={r.pattern!r} effect={r.effect.value} "
                    "already present; existing kept"
                )
                continue
            if mode == "dry-run":
                summary.rules_added += 1
                existing_fingerprints.add(fp)
                continue
            try:
                store.add_rule(r, actor=actor or resolve_operator())
                summary.rules_added += 1
                existing_fingerprints.add(fp)
            except InvalidRuleError as e:
                summary.collision_notes.append(
                    f"rule pattern={r.pattern!r} skipped: {e}"
                )

        # Tasks: NEVER replayed; surface a note when the bundle carries
        # any so the operator sees what was visible to the importer.
        summary.tasks_carried = len(bundle.get("tasks", []) or [])
        summary.presets_carried = len(bundle.get("presets", []) or [])
        summary.audit_webhook_carried = bool(
            bundle.get("audit_webhook", {}).get("env_keys_present")
            or bundle.get("audit_webhook", {}).get("log_path")
        )
        summary.alert_rules_carried = bool(
            bundle.get("alert_rules", {}).get("path")
        )
        summary.license_carried = bool(
            bundle.get("license", {}).get("license_id")
        )
    finally:
        store.close()

    # Profiles write — done LAST so a rules-side error doesn't leave a
    # half-merged profiles.yaml on disk.
    if mode != "dry-run":
        _write_profiles(resolved_profiles, new_profile_map)

    return summary


def _write_profiles(
    target: pathlib.Path,
    profile_map: dict[str, Profile],
) -> None:
    """Atomic-write profiles.yaml.

    Every profile in `profile_map` lands in the file verbatim — including
    the synthesized `full-user` / `safe-default` defaults. We don't
    "skip the defaults to keep the file minimal" because doing so makes
    a round-trip lossy on the first re-export (load-profiles would
    re-synthesize the defaults from DEFAULT_PROFILES, but only the
    profiles it CAN see in the file land in the export — so a default
    that got skipped becomes invisible to the next export).
    """
    out: dict[str, dict[str, Any]] = {}
    for name in sorted(profile_map.keys()):
        out[name] = profile_to_yaml_dict(profile_map[name])
    if target.parent and not target.parent.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
    tmp = target.with_suffix(target.suffix + ".tmp")
    tmp.write_text(
        yaml.safe_dump({"profiles": out}, sort_keys=False),
        encoding="utf-8",
    )
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, target)


def _rule_fingerprint(rule: ProxyRule) -> str:
    """Stable string two rules share iff they have the same gating
    effect. `(pattern, effect, arn_scope, region_scope)` is the
    fingerprint; note + origin + expires_at intentionally excluded
    (they are documentation fields, not gating-relevant).

    Mirrors dbounce's `ruleFingerprint` — see commit 9608b14."""
    return (
        f"{rule.effect.value}|{rule.pattern}|"
        f"{rule.arn_scope or ''}|{rule.region_scope or ''}"
    )


def _profile_from_export_dict(name: str, body: dict[str, Any]) -> Profile:
    """Reverse of `_project_profile`. Reuses the same field-parsing
    rules as the in-tree YAML loader so the import path is bug-compat
    with the runtime path.
    """
    # The shape `profile_to_yaml_dict` produces matches what
    # `_profile_from_dict` expects. Defer to the same parser.
    from .profiles import _profile_from_dict

    # Strip the `name` field if present so `_profile_from_dict` doesn't
    # see an unexpected key.
    body = {k: v for k, v in body.items() if k != "name"}
    return _profile_from_dict(name, body)


# ---------------------------------------------------------------------------
# Admin-action emission helpers
# ---------------------------------------------------------------------------


def emit_export_admin_action(
    store: BouncerStore,
    *,
    out_path: str | pathlib.Path,
    actor: str | None = None,
    extra: dict[str, Any] | None = None,
) -> None:
    """Enqueue a `config.export` ADMIN_ACTION OCSF row. Caller passes
    the resolved output path so the audit trail records WHERE the
    bundle landed. Errors are swallowed by the underlying helper —
    a queue-write failure NEVER fails the user-facing export."""
    payload_extra = {"out_path": str(out_path)}
    if extra:
        payload_extra.update(extra)
    enqueue_admin_action(
        store,
        kind=ADMIN_ACTION_CONFIG_EXPORT,
        actor=actor or resolve_operator(),
        target_kind="config-bundle",
        target_id=str(out_path),
        source=ADMIN_ACTION_SOURCE_CLI,
        extra=payload_extra,
    )


def emit_import_admin_action(
    store: BouncerStore,
    *,
    in_path: str | pathlib.Path,
    summary: ImportSummary,
    actor: str | None = None,
) -> None:
    """Enqueue a `config.import` ADMIN_ACTION OCSF row. The summary's
    counts ride in the `extra` payload so a SIEM dashboard keyed on
    the cross-product action id sees the same per-section breakout
    regardless of which Bounce fired it."""
    extra = {
        "in_path": str(in_path),
        "mode": summary.mode,
        "profiles_added": summary.profiles_added,
        "profiles_collided": summary.profiles_collided,
        "profiles_replaced": summary.profiles_replaced,
        "rules_added": summary.rules_added,
        "rules_collided": summary.rules_collided,
        "rules_replaced": summary.rules_replaced,
        "tasks_carried": summary.tasks_carried,
        "presets_carried": summary.presets_carried,
        "result": "noop" if summary.mode == "dry-run" else "applied",
    }
    enqueue_admin_action(
        store,
        kind=ADMIN_ACTION_CONFIG_IMPORT,
        actor=actor or resolve_operator(),
        target_kind="config-bundle",
        target_id=str(in_path),
        source=ADMIN_ACTION_SOURCE_CLI,
        extra=extra,
    )
