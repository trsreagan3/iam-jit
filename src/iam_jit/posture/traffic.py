"""Effective-protection roll-up per traffic class.

Given the bouncer detection block + the identity detection block,
this module decides what's actually protecting each traffic class
(AWS / K8s / DB / HTTP) right now. The answer is one of:

  * ``"intercepted_by": "ibounce" (mode=..., enforces_denials=...)``
  * ``"intercepted_by": null`` plus ``"warning": "DIRECT — ..."``

Per [[ibounce-honest-positioning]]:
  * Discovery mode is NOT enforcement — we surface that explicitly so
    agents don't assume "bouncer running == calls being denied".
  * "Bouncer not running" gets a loud DIRECT warning per traffic class.
  * Misconfigured env wiring (env points at down bouncer) is reported
    as DIRECT with a misconfig pointer (the SDK will fail-open or
    crash; either way it's NOT intercepted).
"""

from __future__ import annotations

from typing import Any


def _mode_enforces(mode: str | None) -> bool:
    """Return True if the named mode actually denies bad calls.

    cooperative  -> True  (writes a verdict; cooperative is the
                          permissive enforcement default for ibounce)
    transparent  -> True  (returns 403 on deny verdicts)
    discovery    -> False (observe + audit only, never denies)
    plan-capture -> False (NEVER forwards, but also never denies in
                          the security sense; returns synthetic OK)
    off          -> False
    unknown      -> False (treat unknown as "no proof of enforcement")
    """
    if not isinstance(mode, str):
        return False
    return mode.strip().lower() in ("cooperative", "transparent")


def _bouncer_intercepts(b: dict[str, Any]) -> bool:
    """Return True iff this bouncer block represents a live,
    correctly-wired interception path.

    Requires running=True AND env_var_pointing_here AND not misconfig.
    """
    return bool(
        b.get("running")
        and b.get("env_var_pointing_here")
        and not b.get("misconfig")
    )


def _summarize_one(
    *,
    name: str,
    bouncer: dict[str, Any],
    traffic_class: str,
    direct_advice: str,
) -> dict[str, Any]:
    """Build the per-traffic-class effective-protection block."""
    block: dict[str, Any] = {
        "intercepted_by": None,
        "mode": None,
        "enforces_denials": False,
        "audits": False,
        "warning": None,
    }
    if _bouncer_intercepts(bouncer):
        mode = bouncer.get("mode") or "unknown"
        enforces = _mode_enforces(mode)
        block.update(
            intercepted_by=name,
            mode=mode,
            enforces_denials=enforces,
            audits=True,  # all bouncers audit when running
        )
        if not enforces:
            block["warning"] = (
                f"{name} is in {mode!r} mode — observes + audits but "
                "does NOT enforce denials."
            )
    elif bouncer.get("misconfig"):
        block["warning"] = (
            f"DIRECT — {traffic_class} calls UNPROTECTED: {bouncer['misconfig']}. "
            f"{direct_advice}"
        )
    elif not bouncer.get("running"):
        block["warning"] = (
            f"DIRECT — {traffic_class} calls UNPROTECTED ({name} not running). "
            f"{direct_advice}"
        )
    else:
        # Bouncer is running but env var isn't wired to it.
        block["warning"] = (
            f"DIRECT — {traffic_class} calls UNPROTECTED ({name} is "
            "running but no env var is wired to it; SDK calls bypass it). "
            f"{direct_advice}"
        )
    return block


def summarize_traffic(bouncers: dict[str, Any]) -> dict[str, Any]:
    """Produce the ``effective_protection`` block of the posture
    snapshot, one entry per traffic class."""
    return {
        "aws_calls": _summarize_one(
            name="ibounce",
            bouncer=bouncers.get("ibounce", {}),
            traffic_class="AWS",
            direct_advice="To intercept: `ibounce run` + `AWS_ENDPOINT_URL=http://127.0.0.1:8767`.",
        ),
        "k8s_calls": _summarize_one(
            name="kbounce",
            bouncer=bouncers.get("kbounce", {}),
            traffic_class="K8s",
            direct_advice="To intercept: `kbounce run` + `KUBECONFIG=$(kbounce kubeconfig)`.",
        ),
        "db_calls": _summarize_one(
            name="dbounce",
            bouncer=bouncers.get("dbounce", {}),
            traffic_class="DB",
            direct_advice="To intercept: `dbounce run` + `PGHOST=127.0.0.1 PGPORT=5433`.",
        ),
        "http_calls": _summarize_one(
            name="gbounce",
            bouncer=bouncers.get("gbounce", {}),
            traffic_class="HTTP",
            direct_advice="To intercept: `gbounce run` + `HTTP_PROXY=http://127.0.0.1:8080`.",
        ),
    }


def derive_tips(
    *,
    identity: dict[str, Any],
    bouncers: dict[str, Any],
    effective: dict[str, Any],
) -> list[str]:
    """Suggest next-step commands the operator/agent should run to
    close obvious gaps. Conservative: one tip per gap, never more
    than ~5 total (keeps the human output scannable)."""
    tips: list[str] = []
    # iam-jit role tip.
    if identity.get("scoped_role_active") is False:
        tips.append(
            "AWS identity is NOT iam-jit-issued. To request a scoped role: "
            "`iam-jit request` (interactive) or via the MCP tool "
            "`submit_policy`."
        )
    # Per-traffic-class tips for DIRECT classes.
    if effective.get("aws_calls", {}).get("intercepted_by") is None:
        tips.append(
            "AWS calls are DIRECT. To intercept: `ibounce run` + "
            "`AWS_ENDPOINT_URL=http://127.0.0.1:8767`."
        )
    if effective.get("k8s_calls", {}).get("intercepted_by") is None:
        tips.append(
            "K8s calls are DIRECT. To intercept: `kbounce run` + "
            "`KUBECONFIG=$(kbounce kubeconfig)`."
        )
    # Discovery/plan-capture warning.
    aws = effective.get("aws_calls", {})
    if aws.get("intercepted_by") and not aws.get("enforces_denials"):
        tips.append(
            f"ibounce is in {aws.get('mode')!r} mode — observes + audits "
            "but does NOT deny. To enforce: switch to "
            "`--mode transparent` on the `ibounce run` command line."
        )
    # Misconfig surface — bubble up.
    for name, b in bouncers.items():
        if b.get("misconfig"):
            tips.append(
                f"{name} env-var MISCONFIG: {b['misconfig']}."
            )
    return tips


def derive_overall_mode(
    *,
    identity: dict[str, Any],
    effective: dict[str, Any],
) -> str:
    """Collapse the snapshot into the 4-mode matrix from the §A42 spec.

    Returns one of:
      "iam-jit + scoped role only"   — scoped role active, no
                                       bouncer intercepting
      "bouncer only"                 — at least one bouncer
                                       intercepting, no scoped role
      "both"                         — scoped role AND >= 1 bouncer
      "neither"                      — DIRECT — UNPROTECTED
      "unknown"                      — insufficient evidence
    """
    scoped = identity.get("scoped_role_active")
    any_intercept = any(
        v.get("intercepted_by") for v in effective.values()
    )
    if scoped is True and any_intercept:
        return "both"
    if scoped is True and not any_intercept:
        return "iam-jit + scoped role only"
    if scoped is False and any_intercept:
        return "bouncer only"
    if scoped is False and not any_intercept:
        return "neither"
    # scoped is "unknown" branch.
    if any_intercept:
        return "bouncer only (iam-jit role status unknown)"
    return "unknown"


def has_unprotected_traffic(effective: dict[str, Any]) -> bool:
    """True iff at least one traffic class is DIRECT — feeds
    `iam-jit posture --exit-1-on-unprotected`."""
    for v in effective.values():
        if v.get("intercepted_by") is None:
            return True
    return False
