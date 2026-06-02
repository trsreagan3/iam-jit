"""§A77 #469 — anomaly detector + scoring.

Pure-function: ``score_anomaly(action, agent_identity, baseline_state)
→ AnomalyResult``.

Per ``[[scorer-is-ground-truth]]`` ADVISORY only — deterministic deny
floor still wins on conflict; this signal feeds the bouncer's
mode-handling layer (alert vs block per §A78).

Industry-research additions (per #488):
  * **F.1 Explainability surface** — per-dimension breakdown for every
    scored anomaly. Without it, operators get "blocked" with no
    actionable reason + turn the feature off (Splunk UBA / CalypsoAI /
    Lasso all ship this; z-score is inherently per-dimension
    explainable so cost is just surfacing what we already compute).
  * **F.2 Cold-start classifier fallback** — when the baseline has
    fewer than ``min_actions_for_baseline`` observations for the key,
    fall back to the #404 classifier + #407 threat-feed catalog so the
    operator gets adversarial-pattern detection from day 1.
  * **F.5 MITRE ATLAS tagging** — every flagged anomaly carries the
    technique IDs that apply (Falco Feeds pattern; audit-friendly for
    compliance buyers).

Ensemble: ``combined_score = max(z_score_anomaly, classifier_score)``.
Threat-feed entries marked HIGH+ severity bump the score upward.

DIVISION OF LABOR — anomaly detection vs. circuit breaker
----------------------------------------------------------
These two subsystems handle DIFFERENT threat shapes:

  * **Circuit breaker** (`iam_jit.circuit_breaker`) fires on HIGH VOLUME
    of any action — familiar or not. It counts cost/requests over a
    rolling window and trips when a threshold is breached. "This agent
    made 10 000 s3:GetObject calls in 60 s" is a circuit-breaker event.

  * **Anomaly detection** (this module) fires on NOVEL or RARE actions —
    actions that deviate from the per-agent baseline by z-score. "This
    agent never touches iam:CreateRole and just did" is an anomaly-
    detection event. High VOLUME of a FAMILIAR action scores as NORMAL
    here (a frequently observed action has a high baseline mean, so the
    z-score stays low).

Both signals are intentional and complementary:
    volume of familiar actions  →  circuit breaker
    novel / rare actions        →  anomaly detection

Operators seeing 0 anomaly alerts under high-volume familiar traffic is
correct behaviour — not a bug. The circuit breaker is the right tool
for rate-of-familiar-action concerns; check `iam-jit status --json`
→ `circuit_breaker` for that signal.
"""

from __future__ import annotations

import dataclasses
import logging
import math
from typing import Any, Literal

from .baseline import BaselineSummary, canonical_resource_pattern
from .config import AnomalyDetectionConfig
from .mitre_atlas import map_action_to_atlas_techniques

logger = logging.getLogger(__name__)


Verdict = Literal["normal", "anomalous", "insufficient_data"]


# Floor for the cold-start fallback when the classifier signal fires.
# Below this we mark the verdict as anomalous-with-cold-start-fallback;
# above this is just normal. 0.7 corresponds roughly to the deny-
# classifier's HIGH_CONFIDENCE_THRESHOLD (#404) scaled into our
# [0, 1] verdict space.
_COLD_START_FLAG_THRESHOLD = 0.7


@dataclasses.dataclass(frozen=True)
class Explanation:
    """F.1 — per-dimension explanation surfaced to operators.

    z-score is inherently per-dimension explainable; this dataclass
    just makes the surface honest about WHAT contributed and by HOW
    MUCH so the operator can pivot ("the agent never touches s3:Delete
    on prod" rather than "anomaly score 0.87").
    """

    dimension: str
    baseline_mean: float
    baseline_stddev: float
    observed: float
    sigma_distance: float
    contributing: bool
    """True when this dimension's z-score crossed the configured
    sigma threshold. Operators reading the explanation can scan
    `contributing: True` rows to find the actionable signal."""

    def to_dict(self) -> dict[str, Any]:
        return {
            "dimension": self.dimension,
            "baseline_mean": round(self.baseline_mean, 4),
            "baseline_stddev": round(self.baseline_stddev, 4),
            "observed": round(self.observed, 4),
            "sigma_distance": round(self.sigma_distance, 3),
            "contributing": self.contributing,
        }


@dataclasses.dataclass(frozen=True)
class AnomalyResult:
    """Detector output. Stable wire-shape consumed by the bouncer's
    mode handler (block vs alert) + the structured-deny builder +
    the audit-export anomaly_detected synthetic event.

    Fields:
      * ``anomaly_score`` — float in [0, 1]; threshold for the
        ``anomalous`` verdict depends on configured sensitivity.
      * ``verdict`` — ``normal`` | ``anomalous`` | ``insufficient_data``
        (the last fires when baseline < min AND cold-start fallback
        produced no signal).
      * ``explanations`` — F.1 per-dimension breakdown for every
        dimension considered (contributing AND non-contributing so
        the operator sees the full picture).
      * ``classifier_signal`` — when F.2 cold-start fallback fired,
        the result dict from the #404 classifier (else None).
      * ``mitre_atlas_techniques`` — F.5 tag list (always present;
        empty when no pattern matched).
      * ``cold_start_fallback_used`` — True when the F.2 path fired.
      * ``baseline_observations`` — sample size the score was
        computed against (for honest framing of low-confidence calls).
      * ``threat_feed_severity`` — when a threat-feed entry matched,
        its severity ("CRITICAL" / "HIGH" / "MEDIUM" / "LOW").
    """

    anomaly_score: float
    verdict: Verdict
    explanations: list[Explanation]
    classifier_signal: dict[str, Any] | None
    mitre_atlas_techniques: list[dict[str, str]]
    cold_start_fallback_used: bool
    baseline_observations: int
    threat_feed_severity: str | None = None
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "anomaly_score": round(float(self.anomaly_score), 4),
            "verdict": self.verdict,
            "explanations": [e.to_dict() for e in self.explanations],
            "classifier_signal": self.classifier_signal,
            "mitre_atlas_techniques": list(self.mitre_atlas_techniques),
            "cold_start_fallback_used": self.cold_start_fallback_used,
            "baseline_observations": int(self.baseline_observations),
            "threat_feed_severity": self.threat_feed_severity,
            "note": self.note,
        }


# ---------------------------------------------------------------------------
# Cold-start fallback (F.2)
# ---------------------------------------------------------------------------


def _try_classifier_fallback(
    action: str,
    resource: str,
    *,
    config: AnomalyDetectionConfig,
) -> tuple[dict[str, Any] | None, float]:
    """Invoke the #404 deny-classifier (always-on deterministic
    backstop layer) for the cold-start path.

    Returns ``(classifier_result_dict, fallback_score)``. The score is
    derived from the classifier verdict:

      * appears_adversarial + confidence ≥ 0.7 → score = max(conf, 0.9)
      * appears_adversarial + lower conf       → score = 0.7
      * everything else                         → score = 0.0

    The classifier itself has a hard backstop against
    ``KNOWN_ADVERSARIAL_PATTERNS`` (per #404 design notes) so even on
    Free tier this path still fires for the canonical adversarial
    catalog.
    """
    if not config.cold_start_fallback:
        return None, 0.0
    try:
        from ..deny_classifier import classify_deny as _classify
    except Exception:  # pragma: no cover — module always ships in v1.0
        return None, 0.0
    try:
        result = _classify(
            deny_event={
                "action": action,
                "resource": resource,
                "agent_prompt_context": "",
                "operator_recent_pattern": "",
            },
            backend=None,
            budget_usd=0.001,
        )
    except Exception as e:  # pragma: no cover
        logger.debug("anomaly detector classifier fallback raised: %s", e)
        return None, 0.0
    if not isinstance(result, dict):
        return None, 0.0
    cls = (result.get("classification") or "").lower()
    conf = float(result.get("confidence") or 0.0)
    if cls == "appears_adversarial":
        if conf >= _COLD_START_FLAG_THRESHOLD:
            return result, max(conf, 0.9)
        return result, 0.7
    return result, 0.0


# ---------------------------------------------------------------------------
# Threat-feed scoring contribution
# ---------------------------------------------------------------------------


_SEVERITY_TO_SCORE = {
    "CRITICAL": 1.0,
    "HIGH": 0.85,
    "MEDIUM": 0.55,
    "LOW": 0.30,
}


def _threat_feed_signal(
    action: str,
    resource: str,
    *,
    threat_feed_entries: list[dict[str, Any]] | None,
) -> tuple[str | None, float]:
    """If any threat-feed entry matches the (action, resource) the
    detector returns the entry's severity + a derived score. Multiple
    matches → highest severity wins.

    The entry shape mirrors :mod:`iam_jit.threat_feed.models`. We are
    intentionally permissive about the shape so callers can splat any
    dict-like entry (the threat-feed module's dataclass + the live-
    fetched JSON both work).
    """
    if not threat_feed_entries:
        return None, 0.0
    best_sev = None
    best_score = 0.0
    norm_action = (action or "").strip().lower()
    norm_resource = (resource or "").strip()
    for entry in threat_feed_entries:
        try:
            target = (entry.get("target") or entry.get("action") or "").lower()
            sev = (entry.get("severity") or "").upper()
            entry_action = (entry.get("action") or "").lower()
        except AttributeError:
            continue
        # Match action verb OR resource target glob. We deliberately
        # keep this loose; the threat-feed itself is the source of
        # truth + already publisher-signed.
        matched = False
        if entry_action and entry_action == norm_action:
            matched = True
        elif target and (target in norm_action or target in norm_resource.lower()):
            matched = True
        if not matched:
            continue
        s = _SEVERITY_TO_SCORE.get(sev, 0.0)
        if s > best_score:
            best_score = s
            best_sev = sev
    return best_sev, best_score


# ---------------------------------------------------------------------------
# Main scoring entry point
# ---------------------------------------------------------------------------


def _per_dimension_z(
    summary: BaselineSummary,
    *,
    observed_action_count: float | None = None,
    observed_hour: int | None = None,
    sigma_threshold: float,
) -> list[Explanation]:
    """Build the F.1 explanation list. Always returns one entry per
    dimension present in the baseline summary so the operator sees
    the FULL picture (contributing OR not).

    ``observed_action_count`` semantics: when None (the default),
    single-event scoring uses the baseline mean as the observed
    value, so action_frequency contributes 0σ. Callers that want
    spike detection pass the actual recent-window count (e.g. count
    of this action over the last minute) so a 500x spike vs a
    historical 5/min flags.
    """
    explanations: list[Explanation] = []
    for dim_name, stats in summary.dimensions.items():
        if "action_frequency" in dim_name:
            observed = (
                float(observed_action_count)
                if observed_action_count is not None
                else float(stats.mean)
            )
            z = stats.z_score(observed)
            explanations.append(Explanation(
                dimension=dim_name,
                baseline_mean=float(stats.mean),
                baseline_stddev=float(stats.stddev),
                observed=observed,
                sigma_distance=float(z),
                contributing=z >= sigma_threshold,
            ))
        elif "hour_of_day" in dim_name:
            if observed_hour is None:
                continue
            observed = float(observed_hour)
            z = stats.z_score(observed)
            explanations.append(Explanation(
                dimension=dim_name,
                baseline_mean=float(stats.mean),
                baseline_stddev=float(stats.stddev),
                observed=observed,
                sigma_distance=float(z),
                contributing=z >= sigma_threshold,
            ))
    return explanations


def _aggregate_z_to_score(explanations: list[Explanation]) -> float:
    """Combine per-dimension z-scores into a single anomaly score in
    [0, 1]. We use the max sigma_distance + a sigmoid squash so a
    single dimension at 5σ doesn't get masked by other dimensions at
    0σ. The squash centres at sigma=2 (medium-sensitivity threshold)
    so 2σ ≈ 0.5, 4σ ≈ 0.88, 6σ → 0.99.
    """
    if not explanations:
        return 0.0
    max_sig = max(e.sigma_distance for e in explanations)
    # Sigmoid centred at 2.0 with steepness 0.8
    return 1.0 / (1.0 + math.exp(-(max_sig - 2.0) * 0.8))


def score_anomaly(
    *,
    action: str,
    agent_identity: str,
    baseline_summary: BaselineSummary,
    config: AnomalyDetectionConfig,
    resource: str | None = None,
    observed_hour: int | None = None,
    observed_action_count: float | None = None,
    threat_feed_entries: list[dict[str, Any]] | None = None,
) -> AnomalyResult:
    """Score one (agent, action, resource) sample against the baseline.

    Pure function — no side effects. The caller owns observation
    (``BaselineStore.observe()``) BEFORE scoring if they want this
    event to count toward future baselines; the scorer itself does
    not mutate.

    Composition:
      1. Per-dimension z-scores → F.1 explanations.
      2. Combined z-score from explanations.
      3. Cold-start fallback (F.2) when sample size is below the
         configured threshold OR when the classifier signal beats the
         baseline signal.
      4. Threat-feed contribution — entries that match bump the
         combined score upward AND surface their severity.
      5. F.5 MITRE ATLAS tagging once the verdict is known.
      6. Combined score = max(z_score, classifier_score, feed_score).
    """
    sigma_threshold = config.sigma_threshold
    explanations = _per_dimension_z(
        baseline_summary,
        observed_action_count=observed_action_count,
        observed_hour=observed_hour,
        sigma_threshold=sigma_threshold,
    )
    z_score = _aggregate_z_to_score(explanations)

    rolling = baseline_summary.total_observations_rolling
    is_cold_start = rolling < config.min_actions_for_baseline

    # F.2 cold-start fallback path
    classifier_signal: dict[str, Any] | None = None
    fallback_score = 0.0
    cold_start_fallback_used = False
    if is_cold_start:
        classifier_signal, fallback_score = _try_classifier_fallback(
            action, resource or "*", config=config,
        )
        cold_start_fallback_used = classifier_signal is not None

    feed_severity, feed_score = _threat_feed_signal(
        action, resource or "*", threat_feed_entries=threat_feed_entries,
    )

    # Ensemble: max-pool the three signals.
    combined = max(z_score, fallback_score, feed_score)

    # Verdict bands. Convert sigma_threshold (e.g. 2.0) into an
    # equivalent score band via the same sigmoid the aggregator uses.
    score_band_for_anomalous = 1.0 / (1.0 + math.exp(-(sigma_threshold - 2.0) * 0.8))
    if is_cold_start and not cold_start_fallback_used and feed_score == 0.0:
        # Honest: not enough data + no fallback signal -> insufficient_data
        verdict: Verdict = "insufficient_data"
        note = (
            f"Baseline has {rolling} observations (< "
            f"{config.min_actions_for_baseline} required). Cold-start "
            f"fallback found no adversarial signal."
        )
    elif combined >= score_band_for_anomalous:
        verdict = "anomalous"
        note = ""
    else:
        verdict = "normal"
        note = ""

    # F.5 ATLAS tags. Only tag when verdict is anomalous (we don't
    # want to litter ATLAS IDs onto routine reads). Add the ATLAS AI
    # signals when cold-start fallback / classifier flagged the action.
    techniques: list[dict[str, str]] = []
    if verdict == "anomalous":
        techniques = map_action_to_atlas_techniques(
            action,
            include_atlas_ai_signals=cold_start_fallback_used and combined >= 0.7,
        )

    return AnomalyResult(
        anomaly_score=combined,
        verdict=verdict,
        explanations=explanations,
        classifier_signal=classifier_signal,
        mitre_atlas_techniques=techniques,
        cold_start_fallback_used=cold_start_fallback_used,
        baseline_observations=rolling,
        threat_feed_severity=feed_severity,
        note=note,
    )


__all__ = [
    "AnomalyResult",
    "Explanation",
    "score_anomaly",
]
