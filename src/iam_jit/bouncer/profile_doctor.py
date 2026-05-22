"""ibounce profile-doctor: diff installed profile YAML against shipped
defaults + report missing fields without auto-overwriting.

Per task #321 / KNOWN-CAVEATS §A19 — the role-effectiveness eval
2026-05-22 surfaced silent profile-upgrade-blindness across the Bounce
suite: operators who installed a bouncer pre-#302 silently run WITHOUT
later-shipped safety floors because the bouncer NEVER overwrites the
operator's `~/.iam-jit/bouncer/profiles.yaml` once it exists (operator
edits must survive upgrades). That's the right default for operator-
customized state, but it turns into silent safety-claim degradation
when a new floor lands.

Architecture (cross-product symmetric with dbounce + kbouncer +
gbounce — same flag names + behavior per
`[[cross-product-agent-parity]]`):

- ``check(path)`` — compare installed profile YAML against shipped
  defaults; return :class:`Report` with one :class:`FieldGap` per
  absent field.
- ``apply(path)`` — additively merge missing fields into the on-disk
  profile; back up the prior file BEFORE write. NEVER overwrites
  operator-customized field VALUES (only adds absent KEYS). Per
  `[[creates-never-mutates]]`: additive only.
- ``acknowledge(path)`` — write a per-operator acknowledged-version
  stamp so the startup banner stays silent until a new shipped-
  defaults version ships.
- ``startup_banner_line(profiles_path)`` — fast predicate used by
  ``ibounce run`` to decide whether to emit the §A19 startup caveat
  (only fires for ``safety-floor`` gaps + skips when acknowledged).

Field categories (cross-product enum):

- ``safety-floor`` — denies that ENFORCE the safe-default guarantees.
  Missing one = the safety claim is silently false. Startup banner
  fires ONLY for these.
- ``detection`` — observation features (burst detection, etc).
- ``audit`` — telemetry-shape changes (preset versions, etc).
- ``convenience`` — defaults / naming / TTL. Pure-UX.

Per `[[security-team-positioning-safety-not-surveillance]]`: framed
as "your profile is behind" not "you are non-compliant."
"""

from __future__ import annotations

import dataclasses
import datetime as _dt
import enum
import json
import os
import pathlib
from typing import Any, Iterable

import yaml

from .profiles import resolve_profiles_path


class FieldCategory(str, enum.Enum):
    """Urgency classification for a missing default field. Bounded
    enum (cross-product); operators see these strings verbatim in
    the doctor output + JSON output."""

    SAFETY_FLOOR = "safety-floor"
    DETECTION = "detection"
    AUDIT = "audit"
    CONVENIENCE = "convenience"


_CATEGORY_RANK: dict[FieldCategory, int] = {
    FieldCategory.SAFETY_FLOOR: 0,
    FieldCategory.DETECTION: 1,
    FieldCategory.AUDIT: 2,
    FieldCategory.CONVENIENCE: 3,
}


@dataclasses.dataclass(frozen=True)
class FieldGap:
    """One missing or behind-default field in the operator's installed
    profile relative to the shipped defaults."""

    profile_name: str
    field: str
    category: FieldCategory
    why_matters: str
    added_in: str
    default_value: Any


@dataclasses.dataclass(frozen=True)
class Report:
    """Output of :func:`check`. ``missing_fields`` is ordered by
    category (safety-floor first), then catalog order."""

    missing_fields: tuple[FieldGap, ...]
    installed_path: str
    shipped_defaults_version: str

    def has_safety_floor_gap(self) -> bool:
        """True iff at least one missing field is ``safety-floor``."""
        return any(g.category is FieldCategory.SAFETY_FLOOR for g in self.missing_fields)


# Source-of-truth catalog of default fields the doctor knows about.
# Adding a new safety floor to ``DEFAULT_PROFILES`` REQUIRES adding
# a row here; the ``test_doctor_catalog_covers_defaults`` test
# enforces this so an engineer can't ship a new floor without wiring
# the upgrade notification.
#
# Stable order: by category (safety-floor first), then alphabetical
# by (profile_name, field). The fixed order makes test goldens
# deterministic + the operator-facing output predictable.
SHIPPED_DEFAULTS_CATALOG: tuple[FieldGap, ...] = (
    FieldGap(
        profile_name="safe-default",
        field="allow_baseline",
        category=FieldCategory.SAFETY_FLOOR,
        why_matters=(
            "Names the AWS-managed-readonly baseline that gates EVERY "
            "action through policy_sentry's Read+List classification. "
            "Without this, only deny_actions + deny_actions_with_condition "
            "run — any Write-classified action the deny list doesn't "
            "enumerate (sts:AssumeRole, lambda:Invoke, iam:PassRole, "
            "etc.) passes by default."
        ),
        added_in="ibounce 0.5.0 (#220, 2026-05-17)",
        default_value="aws_managed_readonly_access",
    ),
    FieldGap(
        profile_name="safe-default",
        field="deny_actions",
        category=FieldCategory.SAFETY_FLOOR,
        why_matters=(
            "Sensitive-Read carve-outs (kms:Decrypt, "
            "secretsmanager:GetSecretValue, ssm:GetParameter*, "
            "ec2:GetPasswordData, ec2:GetConsoleScreenshot, "
            "cognito-idp:AdminGetUser, cognito-idp:AdminListGroupsForUser). "
            "Belt-and-suspenders against a future policy_sentry "
            "reclassification silently making them flow through the "
            "allow_baseline."
        ),
        added_in="ibounce 0.5.0 (#220, 2026-05-17)",
        default_value=[
            "kms:Decrypt",
            "secretsmanager:GetSecretValue",
            "ssm:GetParameter",
            "ssm:GetParameters",
            "ssm:GetParametersByPath",
            "ec2:GetPasswordData",
            "ec2:GetConsoleScreenshot",
            "cognito-idp:AdminGetUser",
            "cognito-idp:AdminListGroupsForUser",
        ],
    ),
)


# Version stamp baked into the embedded defaults. Bump when
# DEFAULT_PROFILES changes in a way operators should re-acknowledge.
# The doctor stores this alongside ``--acknowledge`` so the next bump
# re-arms the warning.
SHIPPED_DEFAULTS_VERSION = "2026-05-22-321"


def check(path: str | pathlib.Path | None = None) -> Report:
    """Inspect the installed profile YAML at ``path`` against
    :data:`SHIPPED_DEFAULTS_CATALOG`. Returns a :class:`Report` with
    zero missing fields when the operator's file is current OR when
    the file doesn't exist yet (fresh install → no gap to report).
    """
    resolved = resolve_profiles_path(str(path) if path else None)
    installed_path = str(resolved)
    if not resolved.exists():
        return Report(
            missing_fields=(),
            installed_path=installed_path,
            shipped_defaults_version=SHIPPED_DEFAULTS_VERSION,
        )
    try:
        data = yaml.safe_load(resolved.read_text())
    except yaml.YAMLError as e:
        raise ValueError(f"ibounce: profile YAML at {resolved} is invalid: {e}") from e
    if not isinstance(data, dict):
        # Treat unparseable / non-object as "no profile to compare against";
        # the doctor isn't a YAML validator — `bouncer profile show` is.
        return Report(
            missing_fields=(),
            installed_path=installed_path,
            shipped_defaults_version=SHIPPED_DEFAULTS_VERSION,
        )
    profiles_obj = data.get("profiles") if isinstance(data.get("profiles"), dict) else {}

    missing: list[FieldGap] = []
    for want in SHIPPED_DEFAULTS_CATALOG:
        profile_body = profiles_obj.get(want.profile_name)
        if not isinstance(profile_body, dict):
            # Operator removed the profile entirely — that's an
            # intentional act; don't surface every catalog row for a
            # deleted profile as "missing" (would be noise).
            continue
        if want.field in profile_body:
            continue
        missing.append(want)
    # Sort: safety-floor first, then by catalog index.
    missing.sort(key=lambda g: _CATEGORY_RANK.get(g.category, 9))
    return Report(
        missing_fields=tuple(missing),
        installed_path=installed_path,
        shipped_defaults_version=SHIPPED_DEFAULTS_VERSION,
    )


@dataclasses.dataclass(frozen=True)
class ApplyResult:
    """Output of :func:`apply`. ``backup_path`` is the absolute path
    the prior YAML was copied to before merge; ``applied_fields`` is
    the subset of ``Report.missing_fields`` that ``apply`` actually
    added (some may have been skipped if a concurrent writer touched
    the file between check + apply)."""

    backup_path: str
    applied_fields: tuple[FieldGap, ...]


def apply(
    path: str | pathlib.Path | None = None,
    *,
    now: _dt.datetime | None = None,
) -> ApplyResult:
    """Additively merge missing default fields into the profile YAML
    at ``path``. NEVER overwrites a field the operator explicitly set
    (the merge skips any field already present in the raw YAML map).
    Backs up the prior file BEFORE writing.

    Per `[[creates-never-mutates]]`: ADDITIVE only. If the operator
    set ``allow_baseline: null`` deliberately, the field is PRESENT
    in the YAML → :func:`apply` skips it. The doctor cannot override
    an operator's explicit choice.

    Raises :class:`FileNotFoundError` if the profile YAML doesn't
    exist (use ``ibounce profile install-defaults`` first).
    """
    resolved = resolve_profiles_path(str(path) if path else None)
    if not resolved.exists():
        raise FileNotFoundError(
            f"ibounce: no profile YAML at {resolved} to apply against"
        )
    report = check(resolved)
    if not report.missing_fields:
        return ApplyResult(backup_path="", applied_fields=())

    raw_bytes = resolved.read_bytes()
    raw_text = raw_bytes.decode("utf-8")
    data = yaml.safe_load(raw_text) or {}
    if not isinstance(data, dict):
        raise ValueError(
            f"ibounce: profile YAML at {resolved} is not a YAML object"
        )
    profiles_obj = data.setdefault("profiles", {})
    if not isinstance(profiles_obj, dict):
        raise ValueError(
            f"ibounce: profile YAML at {resolved} 'profiles' must be a dict"
        )

    moment = now or _dt.datetime.now(_dt.timezone.utc)
    backup_path = _backup_path_for(resolved, moment)
    backup_path.write_bytes(raw_bytes)

    applied: list[FieldGap] = []
    for gap in report.missing_fields:
        profile_body = profiles_obj.get(gap.profile_name)
        if not isinstance(profile_body, dict):
            continue
        if gap.field in profile_body:
            continue
        profile_body[gap.field] = gap.default_value
        applied.append(gap)

    resolved.write_text(yaml.safe_dump(data, sort_keys=False))
    return ApplyResult(
        backup_path=str(backup_path),
        applied_fields=tuple(applied),
    )


def _backup_path_for(resolved: pathlib.Path, moment: _dt.datetime) -> pathlib.Path:
    stamp = moment.astimezone(_dt.timezone.utc).strftime("%Y%m%d-%H%M%S")
    return resolved.with_name(resolved.name + f".bak-{stamp}")


def acknowledged_version_path(
    path: str | pathlib.Path | None = None,
) -> pathlib.Path:
    """Per-operator acknowledged-version file path; lives next to
    profiles.yaml so a fresh install on a new machine doesn't carry
    over a prior acknowledgement."""
    resolved = resolve_profiles_path(str(path) if path else None)
    return resolved.with_name(".profiles-acknowledged-version")


def acknowledge(path: str | pathlib.Path | None = None) -> pathlib.Path:
    """Write the current :data:`SHIPPED_DEFAULTS_VERSION` to the
    acknowledged-version file. Future :func:`startup_banner_line`
    calls skip the warning until a new version bumps the stamp.
    Returns the path written."""
    ack = acknowledged_version_path(path)
    ack.parent.mkdir(parents=True, exist_ok=True)
    ack.write_text(SHIPPED_DEFAULTS_VERSION + "\n")
    return ack


def is_acknowledged(path: str | pathlib.Path | None = None) -> bool:
    """True iff the on-disk acknowledged-version matches the current
    :data:`SHIPPED_DEFAULTS_VERSION`."""
    ack = acknowledged_version_path(path)
    if not ack.exists():
        return False
    return ack.read_text().strip() == SHIPPED_DEFAULTS_VERSION


def startup_banner_line(
    path: str | pathlib.Path | None = None,
    *,
    product: str = "ibounce",
) -> str:
    """Return the one-line caveat ``ibounce run`` emits at startup
    when the installed profile is missing a ``safety-floor`` field
    AND the operator hasn't acknowledged the current shipped-defaults
    version. Returns ``""`` when no banner should fire.

    Per `[[security-team-positioning-safety-not-surveillance]]`:
    framed as "your profile is behind" — NOT "you are non-compliant."
    """
    try:
        if is_acknowledged(path):
            return ""
        report = check(path)
    except (OSError, ValueError):
        return ""
    if not report.has_safety_floor_gap():
        return ""
    return (
        "caveat: your safe-default profile is missing fields shipped in "
        f"this version — run `{product} profile doctor` for details "
        "(KNOWN-CAVEATS §A19)"
    )


def format_report(report: Report, *, product: str = "ibounce") -> str:
    """Render a :class:`Report` as the multi-line text shown by
    ``ibounce profile doctor``. Stable shape for test goldens."""
    if not report.missing_fields:
        return (
            f"{product}: profile doctor — installed profile matches shipped "
            f"defaults (version {SHIPPED_DEFAULTS_VERSION}).\n"
        )
    lines: list[str] = []
    lines.append(
        f"{product}: profile doctor — your installed profile is missing "
        f"{len(report.missing_fields)} field(s) that ship in this version "
        f"(defaults version {SHIPPED_DEFAULTS_VERSION}):\n"
    )
    for gap in report.missing_fields:
        lines.append(f"  - profile={gap.profile_name} field={gap.field}")
        lines.append(f"    category:   {gap.category.value}")
        lines.append(f"    why:        {gap.why_matters}")
        lines.append(f"    added in:   {gap.added_in}")
        lines.append(f"    default:    {gap.default_value!r}\n")
    lines.append(f"To accept the new defaults: {product} profile doctor --apply")
    lines.append(f"To suppress this warning:   {product} profile doctor --acknowledge")
    return "\n".join(lines) + "\n"


def report_to_json_str(report: Report) -> str:
    """JSON shape for ``ibounce profile doctor --json``. Stable
    contract: SIEM scripts can parse this without a flag-version
    check."""
    out = {
        "shipped_defaults_version": report.shipped_defaults_version,
        "installed_path": report.installed_path,
        "missing": [
            {
                "profile": g.profile_name,
                "field": g.field,
                "category": g.category.value,
                "why": g.why_matters,
                "added_in": g.added_in,
                "default": g.default_value,
            }
            for g in report.missing_fields
        ],
    }
    return json.dumps(out, indent=2)


__all__ = [
    "FieldCategory",
    "FieldGap",
    "Report",
    "ApplyResult",
    "SHIPPED_DEFAULTS_CATALOG",
    "SHIPPED_DEFAULTS_VERSION",
    "check",
    "apply",
    "acknowledge",
    "acknowledged_version_path",
    "is_acknowledged",
    "startup_banner_line",
    "format_report",
    "report_to_json_str",
]
