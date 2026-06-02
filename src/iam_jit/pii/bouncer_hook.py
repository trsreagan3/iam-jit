# ADOPT-7 / #721 — wire custom PII detectors into the bouncer's
# existing audit-log redaction path.
"""Build an ``extra_redactor`` callable from an operator's custom-PII
config, suitable for passing to
``iam_jit.bouncer.audit_export.retention.redact_event_pii``.

This is the REUSE seam: rather than a parallel redaction system, the
custom-entity layer plugs into the SAME in-place event walk the
retention module already runs for credential/PII scrubbing. The bouncer
calls :func:`build_extra_redactor` once at startup (with the path to its
custom-PII config, if the operator declared one) and threads the
returned callable into ``redact_event_pii``.

Default-off / opt-in: returns ``None`` when no config path is given OR
when presidio-analyzer is absent. A ``None`` redactor means the audit
path behaves EXACTLY as before — the built-in credential/PII patterns
still run; the custom layer is simply not applied. No crash, no warning
spam: the caller logs the no-op reason once.
"""

from __future__ import annotations

import logging
import os
import pathlib
import threading
from typing import Callable

from .config import PiiConfigError, load_config
from .recognizers import presidio_available, redact_text

_log = logging.getLogger(__name__)

# Operator setting that turns the bouncer's custom-PII redaction ON. When
# this env var points at a custom-PII config file, the audit-log
# redaction path (gdpr_pii_purge) additively applies the operator's
# declared entities. Unset / empty => feature off => audit redaction
# behaves EXACTLY as before. Per [[lightweight-frictionless-principle]] +
# default-off opt-in.
CONFIG_ENV_VAR = "IAM_JIT_CUSTOM_PII_CONFIG"


def build_extra_redactor(
    config_path: str | pathlib.Path | None,
    *,
    threshold: float = 0.0,
) -> Callable[[str], str] | None:
    """Return a string->string redactor bound to the operator's custom
    PII config, or ``None`` when the feature is inactive.

    Returns ``None`` (clean no-op) when:
      * ``config_path`` is None / empty (operator declared no custom
        entities — feature is opt-in), OR
      * presidio-analyzer is not installed (optional extra absent).

    Raises :class:`PiiConfigError` when a config path IS supplied but the
    file is missing / malformed — a declared-but-broken config must fail
    LOUDLY at startup, never silently disable PII protection the operator
    asked for.
    """
    if not config_path:
        return None

    if not presidio_available():
        _log.warning(
            "custom-PII config %s declared but presidio-analyzer is not "
            "installed; custom entity redaction is DISABLED. Install the "
            "optional extra: pip install 'iam-jit[pii]'",
            config_path,
        )
        return None

    # Let PiiConfigError propagate: a declared config that won't parse is
    # an operator error we must surface at startup, not swallow.
    config = load_config(config_path)
    _log.info(
        "custom-PII detectors active: %d entit%s (%s)",
        len(config.entities),
        "y" if len(config.entities) == 1 else "ies",
        ", ".join(config.entity_names),
    )

    def _redactor(value: str) -> str:
        return redact_text(value, config, threshold=threshold)

    return _redactor


# --- Bouncer audit-path integration (config plumb + cache) ----------------
#
# The audit-log writer + the offline retention apply both redact events
# via ``redact_event_pii``. To extend that redaction with the operator's
# custom entities we build the extra_redactor ONCE (compiling recognizers
# is non-trivial; the audit worker must not pay it per event) and cache
# it. The cache key is the resolved config path so a test / reconfigure
# that changes the env var rebuilds.
_cache_lock = threading.Lock()
_cached_key: object = object()  # sentinel: "never built"
_cached_redactor: Callable[[str], str] | None = None
_warned_build_failure = False


def _resolve_config_path() -> str | None:
    """Read the operator's custom-PII config path from the environment.

    Returns ``None`` (feature off) when the env var is unset or empty.
    """
    val = os.environ.get(CONFIG_ENV_VAR, "").strip()
    return val or None


def get_audit_extra_redactor() -> Callable[[str], str] | None:
    """Return the cached custom-PII redactor for the bouncer audit path,
    building it once from :data:`CONFIG_ENV_VAR`.

    FAIL-SOFT: this is called from the audit-write hot path and from the
    offline retention scrub. It must NEVER raise — a misconfigured custom
    layer must not break audit writes (per [[ibounce-honest-positioning]]:
    rather emit a less-redacted event than drop a compliance row). On any
    build error we log ONCE and return ``None`` (the built-in
    credential/PII patterns still run).

    DEFAULT-OFF: no env var => ``None`` => unchanged behaviour. Presidio
    absent => :func:`build_extra_redactor` returns ``None`` (clean no-op).

    The returned callable is ALSO wrapped fail-soft: if applying the
    operator's patterns raises on some pathological value, we log once and
    return the value unchanged rather than corrupting the event or
    crashing the worker.
    """
    global _cached_key, _cached_redactor, _warned_build_failure

    key = _resolve_config_path()
    with _cache_lock:
        if key == _cached_key:
            return _cached_redactor
        # Config changed (or first call) — (re)build.
        _cached_key = key
        _warned_build_failure = False
        try:
            inner = build_extra_redactor(key)
        except Exception as exc:  # noqa: BLE001 — fail-soft by design
            if not _warned_build_failure:
                _log.error(
                    "custom-PII redactor build failed for %s: %s; "
                    "custom-entity audit redaction DISABLED (built-in "
                    "patterns still run)",
                    key,
                    exc,
                )
                _warned_build_failure = True
            _cached_redactor = None
            return None  # noqa: SD-4 — fail-soft: logged ERROR above; audit writes must not break

        if inner is None:
            _cached_redactor = None
            return None

        _cached_redactor = _wrap_fail_soft(inner)
        return _cached_redactor


def _wrap_fail_soft(
    inner: Callable[[str], str],
) -> Callable[[str], str]:
    """Wrap a redactor so a runtime error on one value never breaks the
    audit write — log once, return the value unchanged."""
    state = {"warned": False}

    def _safe(value: str) -> str:
        try:
            return inner(value)
        except Exception as exc:  # noqa: BLE001 — fail-soft by design
            if not state["warned"]:
                _log.error(
                    "custom-PII redactor raised at apply time: %s; "
                    "leaving value unredacted by the custom layer "
                    "(built-in patterns already applied)",
                    exc,
                )
                state["warned"] = True
            return value

    return _safe


def _reset_cache_for_tests() -> None:
    """Test hook: drop the cached redactor so a changed env var rebuilds."""
    global _cached_key, _cached_redactor, _warned_build_failure
    with _cache_lock:
        _cached_key = object()
        _cached_redactor = None
        _warned_build_failure = False


__all__ = [
    "build_extra_redactor",
    "get_audit_extra_redactor",
    "CONFIG_ENV_VAR",
    "PiiConfigError",
]
