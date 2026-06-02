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
import pathlib
from typing import Callable

from .config import PiiConfigError, load_config
from .recognizers import presidio_available, redact_text

_log = logging.getLogger(__name__)


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


__all__ = ["build_extra_redactor", "PiiConfigError"]
