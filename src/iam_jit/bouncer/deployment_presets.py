"""Deployment presets — single-flag shortcuts for common ibounce
deployment shapes.

A deployment preset is a NAMED BUNDLE of run-command flag values.
`ibounce run --preset security-observe` is equivalent to typing out
the canonical 6-7 flags by hand; the preset just makes the common
deployment one-flag for the operator (+ documents intent).

This is ORTHOGONAL to bouncer.presets (rule-set baselines like
'readonly' / 'admin-minus-sensitive') — those are profile starting
points for rule authoring; THESE are run-command flag bundles.

Per [[cross-product-agent-parity]]: the same preset NAMES + same
HARD vs SOFT override semantics ship across ibounce / kbounce /
dbounce / gbounce. The HARD flag for `security-observe` is
`--mode` (the entire point of the preset is transparent mode); the
SOFT flags are the audit-export sinks (operators have different
SIEMs).

Per [[security-team-positioning-safety-not-surveillance]]: preset
descriptions use NEUTRAL language. No "violation" / "infraction" /
"unauthorized" — these are observability tools, not surveillance.
"""

from __future__ import annotations

import dataclasses
import os
from typing import Any


@dataclasses.dataclass(frozen=True)
class DeploymentPreset:
    """A named bundle of run-command flag values."""

    name: str
    description: str
    # Values keyed by the run_cmd parameter NAME (not the CLI flag).
    # Each entry is (value, override_policy) where override_policy is
    # "hard" (operator-supplied flag → error) or "soft" (operator
    # wins; preset value is the default-only).
    values: dict[str, tuple[Any, str]]


# Canonical product-specific audit-log default path.
# Honors $XDG_STATE_HOME / $HOME at runtime so no user-name path is
# ever baked into the binary.
def default_audit_log_path(product: str) -> str:
    """Per-product default JSONL audit-log path for the preset.

    Honors $XDG_STATE_HOME → $HOME/.iam-jit/audit/<product>.jsonl.
    Operator-supplied --audit-log-path overrides (SOFT).
    """
    xdg = os.environ.get("XDG_STATE_HOME")
    home = os.environ.get("HOME") or "."
    base = xdg or os.path.join(home, ".iam-jit")
    return os.path.join(base, "audit", f"{product}.jsonl")


def build_security_observe(product: str = "ibounce") -> DeploymentPreset:
    """The canonical 'security-team observation' deployment shape.

    What it activates:
      - transparent mode (observe + log; never enforce blocks the
        operator did not author)
      - JSONL audit-log export to a per-product default path (SOFT)
      - alert-rules engine with built-in defaults (admin_fallback_burst,
        pause_long, non_org_profile_install, unusual_high_risk_action,
        heartbeat_gap, audit_export_degraded) — SOFT (operator may
        point at a custom YAML)
      - heartbeat every 30s (per #264) — SOFT
      - default-policy=allow (transparent observation; do not block
        calls the security team has not yet decided about) — SOFT

    What it does NOT activate (operator wires explicitly):
      - audit-webhook-url + token (different SIEM per deployment;
        operator wires via flag / env / config)

    HARD override: --mode (preset is meaningless without transparent).
    SOFT overrides: audit-log-path, alert-rules, heartbeat-interval,
                    default-policy.
    """
    return DeploymentPreset(
        name="security-observe",
        description=(
            "security-team observation: transparent mode + JSONL audit + "
            "alert rules (defaults) + 30s heartbeat. Designed for the "
            "'gather data first; author profile second' starting shape "
            "per [[bouncer-mode-selection-for-agents]]. Use when the "
            "security team is establishing a baseline of agent behavior "
            "before deciding which calls to gate."
        ),
        values={
            # HARD: the whole point of this preset is transparent.
            # Operator passing --mode anything-else means they want a
            # different deployment shape; pick a different preset (or
            # none).
            "mode": ("transparent", "hard"),
            # SOFT: per-product default path. Operator points at their
            # own location.
            "audit_log_path": (default_audit_log_path(product), "soft"),
            # SOFT: built-in default alert rules. Operator may layer
            # their own YAML.
            "alert_rules_path": ("", "soft"),
            # SOFT: 30s heartbeat per #264 recommendation.
            "heartbeat_interval_seconds": (30, "soft"),
            # SOFT: default to ALLOW in transparent mode for the
            # observation use case — the security team is gathering
            # data, not gating yet. If they want default-deny they
            # author rules + use a different preset.
            "default_policy": ("allow", "soft"),
        },
    )


# Registry. Currently one preset; the spec explicitly defers
# `dev-loop` / `production-strict` / `compliance-audit` to later
# slices (per the #254 spec + [[deliberate-feature-completion]]).
def get_preset(name: str, product: str = "ibounce") -> DeploymentPreset | None:
    if name == "security-observe":
        return build_security_observe(product=product)
    return None


def list_preset_names() -> list[str]:
    return ["security-observe"]


class PresetOverrideError(ValueError):
    """Raised when an operator passes both --preset NAME and an
    explicit flag whose value the preset marks HARD."""


def apply_preset(
    preset: DeploymentPreset,
    operator_supplied: dict[str, Any],
    flag_defaults: dict[str, Any],
    skip_keys: set[str] | None = None,
) -> tuple[dict[str, Any], list[str], list[str]]:
    """Apply a preset's values to a starting flag dict.

    Args:
        preset: the preset to apply.
        operator_supplied: dict keyed by run_cmd parameter name with
            the VALUE the operator explicitly passed. Only keys present
            in this dict are considered operator-supplied; keys that
            equal the flag default but weren't passed should NOT be in
            this dict.
        flag_defaults: dict keyed by run_cmd parameter name with the
            default-if-unset value (so we can tell preset value from
            operator default).
        skip_keys: optional set of preset-value keys the calling
            product does not support (e.g. gbounce in G-Slice 1 has no
            alert_rules_path). Skipped keys land in the third return
            slot for the banner.

    Returns:
        (resolved_values, derived_keys, skipped_keys)
            resolved_values: the final flag dict, preset values merged
                with operator overrides.
            derived_keys: list of parameter names whose value came from
                the preset (used by the banner to show derivation).
            skipped_keys: list of parameter names the product skipped
                (banner annotates 'preset value not applied: <key>').

    Raises:
        PresetOverrideError when operator_supplied includes a key the
            preset marks HARD with a value different from the preset's.
    """
    skip_keys = skip_keys or set()
    resolved: dict[str, Any] = dict(flag_defaults)
    derived: list[str] = []
    skipped: list[str] = []

    for key, (value, policy) in preset.values.items():
        if key in skip_keys:
            skipped.append(key)
            continue
        if key in operator_supplied:
            op_value = operator_supplied[key]
            if policy == "hard" and op_value != value:
                raise PresetOverrideError(
                    f"--preset {preset.name} sets {key}={value!r} (HARD); "
                    f"cannot override with operator-supplied {key}={op_value!r}. "
                    f"Either drop the --preset flag, OR drop the explicit "
                    f"--{key.replace('_', '-')} flag."
                )
            # SOFT override OR HARD with matching value — operator wins.
            resolved[key] = op_value
            continue
        resolved[key] = value
        derived.append(key)

    # Pass through any flag values the operator supplied that aren't
    # in the preset (so the dict the caller gets is complete).
    for key, value in operator_supplied.items():
        if key not in preset.values:
            resolved[key] = value

    return resolved, derived, skipped


def format_banner(
    preset: DeploymentPreset,
    derived_keys: list[str],
    skipped_keys: list[str] | None = None,
) -> list[str]:
    """Format the startup-banner lines that announce the active preset.

    Returns a list of stderr lines (caller prints with click.echo /
    fmt.Fprintln). Format is identical across all four products
    (per [[cross-product-agent-parity]]).
    """
    lines = [f"deployment preset: {preset.name}"]
    if derived_keys:
        # Stable order: the dict-insertion order of preset.values.
        ordered = [k for k in preset.values.keys() if k in derived_keys]
        for key in ordered:
            value, policy = preset.values[key]
            cli_flag = "--" + key.replace("_", "-")
            lines.append(f"  {cli_flag} = {value!r} (from preset; {policy})")
    if skipped_keys:
        ordered_skip = [k for k in preset.values.keys() if k in skipped_keys]
        for key in ordered_skip:
            cli_flag = "--" + key.replace("_", "-")
            lines.append(
                f"  {cli_flag}: not applicable to this product (preset value skipped)"
            )
    return lines
