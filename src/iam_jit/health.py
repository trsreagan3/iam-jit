"""System health surfacing.

Renders an admin-facing banner at the top of the web UI when something is
off — failed deletions, LLM unreachable, expiry sweep stale, etc.

The check is best-effort and never raises. Each call is fast (no network
calls beyond a quick TCP probe to the LLM endpoint when configured) so it
can run on every page load without measurable overhead.
"""

from __future__ import annotations

import os
import socket
from contextlib import closing
from dataclasses import dataclass
from typing import Any

from . import audit


@dataclass(frozen=True)
class HealthIssue:
    """One thing the admin should know about."""

    severity: str  # "info" | "warning" | "error"
    message: str
    detail: str | None = None


def _ollama_reachable(url: str, timeout: float = 0.5) -> bool:
    if "://" not in url:
        return False
    try:
        host_port = url.split("://", 1)[1].rstrip("/")
        host, _, port_str = host_port.partition(":")
        port = int(port_str) if port_str else 80
    except (ValueError, IndexError):
        return False
    with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
        except OSError:
            return False
        return True


def get_system_health(
    *,
    request_store: Any | None = None,
    expiry_failures_count: int | None = None,
) -> list[HealthIssue]:
    """Return the list of current health issues. Empty list = all green."""
    issues: list[HealthIssue] = []

    llm = (os.environ.get("IAM_JIT_LLM") or "none").lower()
    if llm == "ollama":
        host = os.environ.get("OLLAMA_HOST") or ""
        if host and not _ollama_reachable(host):
            issues.append(
                HealthIssue(
                    severity="warning",
                    message="LLM backend (Ollama) is unreachable.",
                    detail=(
                        f"Configured at {host}. Risk review and AI-assisted "
                        "policy generation are degraded; describe-mode will fall "
                        "back to NoAI behavior until Ollama is reachable again."
                    ),
                )
            )

    # Phase 3 will populate `expiry_failures_count` from the state bucket
    # (a per-grant `revocation_failed_at` field gets set when revocation
    # raises). Until then we trust the caller to pass the count.
    drift = audit.detect_context_drift()
    for d in drift:
        issues.append(
            HealthIssue(
                severity="error",
                message=(
                    f"LLM context input '{d['name']}' changed since boot — "
                    "review evaluations may have been silently biased."
                ),
                detail=(
                    f"Boot fingerprint {d['boot']}, current {d['current']}. "
                    "Restart the service after reviewing the change in version "
                    "control. The admin who last edited this input is recorded "
                    "in the audit log (kind=context.changed)."
                ),
            )
        )

    if expiry_failures_count and expiry_failures_count > 0:
        issues.append(
            HealthIssue(
                severity="error",
                message=f"{expiry_failures_count} expired grant(s) failed revocation.",
                detail=(
                    "Manual cleanup may be required. Even with revocation "
                    "stuck, the IAM time-condition baked into each policy "
                    "denies use after the configured expiry, so blast radius "
                    "is bounded — but the role records remain in IAM until "
                    "deleted."
                ),
            )
        )

    return issues
