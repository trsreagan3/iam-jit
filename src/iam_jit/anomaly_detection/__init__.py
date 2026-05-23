"""Phase H §A76-§A79 — per-agent behavioral baseline + anomaly detector.

This module ships the v1.0 anomaly-detection capability that operators
opt into via the ambient declaration:

  iam-jit:
    anomaly_detection:
      enabled: true
      mode: alert    # alert | block
      sensitivity: medium

The detector is ADVISORY per ``[[scorer-is-ground-truth]]``: the
deterministic deny floor (profile + dynamic-deny + safe-default) always
wins on conflict. Anomaly detection is an additive observability +
optional enforcement signal that composes with — but never replaces —
the existing scoring pipeline.

Per ``[[independence-as-security-property]]`` every per-agent baseline
stays local; nothing is sent anywhere. Per ``[[no-hosted-saas]]`` the
baseline runs in-bouncer with no centralised aggregation service.

Public surface:
  * ``score_anomaly(action, agent_identity, baseline_state, *, config)``
    pure function that returns an :class:`AnomalyResult`.
  * ``BaselineStore`` — DUAL-MODE rolling 14d window + exponential decay
    storage. SQLite-backed (sibling DB to the audit DB), additive new
    tables ``anomaly_baseline_per_agent`` + ``anomaly_baseline_decayed``.
  * ``AnomalyDetectionConfig`` — typed config block loaded from ambient.
  * ``HookResult`` + ``run_anomaly_hook()`` — the bouncer-side glue.
"""

from .baseline import (
    BaselineStore,
    BaselineSummary,
    DimensionStats,
)
from .config import (
    AnomalyDetectionConfig,
    ConfigError,
    SENSITIVITY_PRESETS,
    load_config,
)
from .detector import (
    AnomalyResult,
    Explanation,
    score_anomaly,
)
from .hook import (
    HookResult,
    install_anomaly_hook,
    run_anomaly_hook,
    uninstall_anomaly_hook,
)
from .mitre_atlas import (
    map_action_to_atlas_techniques,
)

__all__ = [
    "AnomalyDetectionConfig",
    "AnomalyResult",
    "BaselineStore",
    "BaselineSummary",
    "ConfigError",
    "DimensionStats",
    "Explanation",
    "HookResult",
    "SENSITIVITY_PRESETS",
    "install_anomaly_hook",
    "load_config",
    "map_action_to_atlas_techniques",
    "run_anomaly_hook",
    "score_anomaly",
    "uninstall_anomaly_hook",
]
