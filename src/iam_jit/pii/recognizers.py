# ADOPT-7 / #721 — compile declarative entities into Presidio
# recognizers, then scan + redact.
"""Build Presidio recognizers from a :class:`CustomPiiConfig`, run them
over text, and redact the matches.

Optional dependency
--------------------
``presidio-analyzer`` is an OPTIONAL extra. Everything in this module
guards the import: :func:`presidio_available` is a cheap probe, and the
scan/redact entry points raise a clear :class:`PresidioUnavailableError`
(with a pip hint) when it is absent. Callers (CLI / bouncer path) turn
that into a clean no-op + message rather than a crash.

Why we DON'T spin up the full AnalyzerEngine
--------------------------------------------
Presidio's ``AnalyzerEngine`` defaults to a spaCy NLP pipeline (a heavy
model download) to power its built-in NER recognizers and its
lemma-based context enhancer. Custom ``PatternRecognizer`` /
deny-list recognizers need NONE of that — they run standalone via
``recognizer.analyze(text, entities, nlp_artifacts=None)``. So we drive
the recognizers directly and apply a SIMPLE, HONEST proximity context
boost ourselves (see :func:`_apply_context_boost`). This keeps the only
required wheel ``presidio-analyzer`` (no spaCy model) and keeps the
feature lightweight per [[lightweight-frictionless-principle]].

Honesty
-------
Regex / keyword / deny-list detection has false positives and false
negatives. :data:`HONESTY_CAVEAT` is surfaced on every scan result; the
CLI prints it. This is operator-defined pattern matching, NOT ML-grade
NER. We never claim otherwise.
"""

from __future__ import annotations

import dataclasses
import logging
import re

from .config import CustomPiiConfig

_log = logging.getLogger(__name__)

# ReDoS / DoS input-size cap (defense-in-depth). Presidio's ``regex``
# engine already defeats classic catastrophic backtracking, but an
# operator-authored pattern run over a pathologically large value could
# still stall the (async) audit-redaction worker. Strings longer than
# this are SKIPPED (returned unchanged, with a logged note) before any
# recognizer touches them, capping the worst case. 256 KiB is far larger
# than any realistic audit string value while bounding scan cost.
MAX_SCAN_BYTES = 256 * 1024

# Surfaced on every scan result + printed by the CLI. Per
# [[ibounce-honest-positioning]].
HONESTY_CAVEAT = (
    "Custom PII detectors are operator-defined regex / keyword / "
    "deny-list matchers. They have false positives (over-redaction) AND "
    "false negatives (missed PII). This is pattern matching, NOT "
    "ML-grade named-entity recognition — tune your patterns and verify "
    "on real samples."
)

# pip hint reused in the unavailable-dependency message + CLI output.
_PIP_HINT = "pip install 'iam-jit[pii]'"

# Redaction placeholder, mirroring the style used by the existing
# credential/PII redactor in iam_jit.bouncer.audit_export.retention
# (``[REDACTED:<kind>]``) so output is consistent across the two layers.
REDACTION_PLACEHOLDER = "[REDACTED:{kind}]"

# How many characters on either side of a match count as "near" for the
# context-word proximity boost. A window, not a sentence parse — honest
# and dependency-free.
_CONTEXT_WINDOW = 40

# How much a nearby context word lifts a pattern match's score, and the
# ceiling it lifts toward. Mirrors the spirit of Presidio's default
# context-enhancer (which boosts toward ~0.4 minimum / +0.35) but kept
# deliberately simple.
_CONTEXT_BOOST = 0.35
_CONTEXT_MAX = 0.99


class PresidioUnavailableError(RuntimeError):
    """Raised when a scan/redact is attempted but presidio-analyzer is
    not importable. Carries a pip hint; callers render it as a clean
    no-op message, never a traceback."""

    def __init__(self, detail: str = "") -> None:
        msg = (
            "presidio-analyzer is not installed — custom PII detection "
            f"is unavailable. Install the optional extra: {_PIP_HINT}"
        )
        if detail:
            msg = f"{msg} ({detail})"
        super().__init__(msg)


@dataclasses.dataclass(frozen=True)
class PiiMatch:
    """One detected span."""

    entity: str
    start: int
    end: int
    score: float
    text: str
    """The matched substring (kept for scan reporting; NOT included in
    the redacted output)."""

    def to_dict(self) -> dict[str, object]:
        return {
            "entity": self.entity,
            "start": self.start,
            "end": self.end,
            "score": round(self.score, 4),
            "text": self.text,
        }


@dataclasses.dataclass(frozen=True)
class PiiScanResult:
    """Result of scanning one text with the custom recognizers."""

    matches: tuple[PiiMatch, ...]
    redacted: str
    """The input text with every match replaced by a placeholder."""

    entity_names: tuple[str, ...]
    """The entity labels that were active for this scan."""

    caveat: str = HONESTY_CAVEAT

    def to_dict(self) -> dict[str, object]:
        return {
            "matches": [m.to_dict() for m in self.matches],
            "redacted": self.redacted,
            "entity_names": list(self.entity_names),
            "match_count": len(self.matches),
            "caveat": self.caveat,
        }


def presidio_available() -> bool:
    """Cheap probe: True iff presidio-analyzer imports.

    Lets the CLI / bouncer path emit the friendly no-op message before
    any recognizer machinery is touched.
    """
    # Probe-only: an ImportError here IS the answer (the optional extra
    # is absent) — not an error to surface. The caller acts on the bool.
    try:
        import presidio_analyzer  # noqa: F401
    except Exception:
        return False
    return True


def build_recognizers(config: CustomPiiConfig) -> list[object]:
    """Compile each declared entity into Presidio recognizer object(s).

    Returns a flat list of ``PatternRecognizer`` instances (one for the
    entity's regex patterns, one for its deny-list, when present). Raises
    :class:`PresidioUnavailableError` when the extra is absent.

    This is the declarative-config -> Presidio-recognizer mapping. NO LLM
    is involved: every recognizer is built from the operator's literal
    ``patterns`` / ``deny_list`` / ``context`` / ``score`` fields.
    """
    if not presidio_available():
        raise PresidioUnavailableError()

    from presidio_analyzer import Pattern, PatternRecognizer

    recognizers: list[object] = []
    for entity in config.entities:
        context = list(entity.context) or None
        if entity.patterns:
            patterns = [
                Pattern(name=f"{entity.name}-{i}", regex=pat, score=entity.score)
                for i, pat in enumerate(entity.patterns)
            ]
            recognizers.append(
                PatternRecognizer(
                    supported_entity=entity.name,
                    patterns=patterns,
                    context=context,
                )
            )
        if entity.deny_list:
            recognizers.append(
                PatternRecognizer(
                    supported_entity=entity.name,
                    deny_list=list(entity.deny_list),
                    context=context,
                )
            )
    return recognizers


def _context_words_for(config: CustomPiiConfig) -> dict[str, frozenset[str]]:
    """Map entity name -> lowercased context-word set (for the proximity
    boost we apply ourselves, since we don't run the spaCy-backed
    AnalyzerEngine enhancer)."""
    return {
        e.name: frozenset(w.lower() for w in e.context)
        for e in config.entities
    }


def _apply_context_boost(
    text: str,
    matches: list[PiiMatch],
    context_by_entity: dict[str, frozenset[str]],
) -> list[PiiMatch]:
    """Lift a match's score when one of its entity's context words
    appears within ``_CONTEXT_WINDOW`` chars of the match.

    Simple, dependency-free, and HONEST about being a proximity heuristic
    rather than a dependency-parse. Deny-list matches (score already 1.0)
    are unaffected by the ceiling.
    """
    lowered = text.lower()
    boosted: list[PiiMatch] = []
    for m in matches:
        ctx = context_by_entity.get(m.entity)
        if not ctx:
            boosted.append(m)
            continue
        win_start = max(0, m.start - _CONTEXT_WINDOW)
        win_end = min(len(text), m.end + _CONTEXT_WINDOW)
        window = lowered[win_start:win_end]
        # Word-boundary match so "account" doesn't fire on "accountant".
        hit = any(
            re.search(rf"\b{re.escape(word)}\b", window) for word in ctx
        )
        if hit and m.score < _CONTEXT_MAX:
            new_score = min(_CONTEXT_MAX, m.score + _CONTEXT_BOOST)
            boosted.append(dataclasses.replace(m, score=new_score))
        else:
            boosted.append(m)
    return boosted


def _dedupe_and_sort(matches: list[PiiMatch]) -> list[PiiMatch]:
    """Drop exact-duplicate spans (same entity+start+end), keeping the
    highest score, then sort by start offset. Two recognizers for the
    same entity (patterns + deny_list) can land on the same span."""
    best: dict[tuple[str, int, int], PiiMatch] = {}
    for m in matches:
        key = (m.entity, m.start, m.end)
        prev = best.get(key)
        if prev is None or m.score > prev.score:
            best[key] = m
    return sorted(best.values(), key=lambda m: (m.start, m.end))


def _redact(text: str, matches: list[PiiMatch]) -> str:
    """Replace each match span with ``[REDACTED:<ENTITY>]``.

    Overlapping spans: we apply highest-score-first and skip any later
    span that overlaps an already-redacted region, so the output is never
    corrupted by nested replacements. Applied right-to-left so earlier
    offsets stay valid as we mutate.
    """
    if not matches:
        return text
    # Resolve overlaps: prefer higher score, then longer span.
    ordered = sorted(matches, key=lambda m: (-m.score, -(m.end - m.start)))
    chosen: list[PiiMatch] = []
    for m in ordered:
        if any(not (m.end <= c.start or m.start >= c.end) for c in chosen):
            continue
        chosen.append(m)
    # Apply right-to-left.
    chosen.sort(key=lambda m: m.start, reverse=True)
    out = text
    for m in chosen:
        placeholder = REDACTION_PLACEHOLDER.format(kind=m.entity)
        out = out[: m.start] + placeholder + out[m.end :]
    return out


def scan_text(
    text: str,
    config: CustomPiiConfig,
    *,
    threshold: float = 0.0,
) -> PiiScanResult:
    """Run the custom recognizers over ``text`` and return matches +
    a redacted copy.

    ``threshold`` filters out matches whose (post-context-boost) score is
    below the given floor — lets an operator demand higher confidence
    before redacting. Default 0.0 keeps everything the recognizers fire
    on.

    Raises :class:`PresidioUnavailableError` when the extra is absent;
    the caller decides whether to no-op or surface it.
    """
    entity_names = config.entity_names

    # ReDoS / DoS guard: skip oversized input BEFORE compiling/running any
    # recognizer regex over it. Returns the text unchanged (no matches) so
    # the redaction path leaves it as-is rather than stalling. The built-in
    # credential/PII patterns in the retention path are unaffected (this
    # caps only the custom-entity layer).
    if len(text.encode("utf-8", errors="ignore")) > MAX_SCAN_BYTES:
        _log.warning(
            "custom-PII scan skipped: input is %d bytes (> %d-byte cap); "
            "value left unscanned by the custom layer to bound scan cost",
            len(text.encode("utf-8", errors="ignore")),
            MAX_SCAN_BYTES,
        )
        return PiiScanResult(
            matches=(),
            redacted=text,
            entity_names=entity_names,
        )

    recognizers = build_recognizers(config)
    context_by_entity = _context_words_for(config)

    raw: list[PiiMatch] = []
    for rec in recognizers:
        # Standalone recognizer analysis — no NLP artifacts needed for
        # PatternRecognizer / deny-list recognizers.
        results = rec.analyze(  # type: ignore[attr-defined]
            text=text,
            entities=list(entity_names),
            nlp_artifacts=None,
        )
        for r in results or []:
            raw.append(
                PiiMatch(
                    entity=r.entity_type,
                    start=r.start,
                    end=r.end,
                    score=float(r.score),
                    text=text[r.start : r.end],
                )
            )

    boosted = _apply_context_boost(text, raw, context_by_entity)
    if threshold > 0.0:
        boosted = [m for m in boosted if m.score >= threshold]
    deduped = _dedupe_and_sort(boosted)
    redacted = _redact(text, deduped)
    return PiiScanResult(
        matches=tuple(deduped),
        redacted=redacted,
        entity_names=entity_names,
    )


def redact_text(
    text: str,
    config: CustomPiiConfig,
    *,
    threshold: float = 0.0,
) -> str:
    """Convenience wrapper returning only the redacted text.

    This is the entry point the bouncer's redaction path uses to extend
    credential/PII scrubbing with operator-defined entities — it returns
    a redacted string in the same shape as the existing
    ``REDACTION_PLACEHOLDER`` output, so it composes with the retention
    module's ``_redact_in_place`` style.
    """
    return scan_text(text, config, threshold=threshold).redacted
