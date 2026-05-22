"""Discoverability surfaces for KNOWN-CAVEATS.md (§B) entries.

Per task #304 + the founder direction 2026-05-22: caveats must be
easily discoverable to users + agents, not buried in
``docs/KNOWN-CAVEATS.md``. This module centralizes the ibounce-relevant
§B entries so the startup banner, ``iam-jit doctor caveats``, MCP tool
descriptions, and 403/4xx error response bodies all surface the same
short summary + a link to the canonical doc.

Mirrors the Go ``internal/caveats`` package shipping in
gbounce / kbounce / dbounce per ``[[cross-product-agent-parity]]``;
the ibounce surface is Python so the bouncer_cli + mcp_server can
both import it cheaply.

The canonical caveat content lives in
https://github.com/trsreagan3/iam-jit/blob/main/docs/KNOWN-CAVEATS.md.
THIS module does NOT duplicate the full content — only the short
summary + the anchor — because:

* the canonical doc is owned by the iam-roles repo (concurrent edit
  hazard if we copy verbatim across four repos);
* the one-line banner + the doctor's short blurb is enough to point an
  operator at the linked anchor for the full read.

Per ``[[security-team-positioning-safety-not-surveillance]]``: language
across the banner + doctor + error surfaces is helpful ("here's where
to read more"), never accusatory.
"""

from __future__ import annotations

from dataclasses import dataclass

CANONICAL_DOC_URL = (
    "https://github.com/trsreagan3/iam-jit/blob/main/docs/KNOWN-CAVEATS.md"
)


@dataclass(frozen=True)
class Entry:
    """One row from KNOWN-CAVEATS §B that ibounce surfaces."""

    id: str
    anchor: str
    # ``banner_line`` is the SINGLE LINE the startup banner emits when
    # this caveat's triggering config is detected. Empty when the
    # entry has no banner surface (some caveats only appear in
    # ``doctor caveats``).
    banner_line: str
    # ``doctor_blurb`` is the 2-3 sentence explanation
    # ``iam-jit doctor caveats`` prints. Kept short on purpose — the
    # linked anchor is the canonical source.
    doctor_blurb: str

    @property
    def url(self) -> str:
        return f"{CANONICAL_DOC_URL}#{self.anchor}"


# ibounce-relevant §B entries. Per task #304:
#   - product-specific: B1, B2, B3, B4, B10, B11, B12
#   - cross-product: B13, B14, B15
#
# Top 3 for the README live-list per the founder's "top 3 per README"
# directive: B1, B3, B4 (the ones operators most commonly hit
# in-context).
ENTRIES: tuple[Entry, ...] = (
    Entry(
        id="B1",
        anchor="b1-ibounce-sigv4-only-request-classification-design",
        banner_line=(
            "  caveat: ibounce gates SigV4-signed AWS-SDK calls; bare "
            "GET requests return 403 (see KNOWN-CAVEATS §B1)"
        ),
        doctor_blurb=(
            "ibounce gates AWS SDK calls. AWS SDKs always sign with "
            "SigV4. A bare GET to the listener returns 403 'no SigV4 "
            "Authorization header.' Browsers get the UI via the "
            "Accept-header content negotiation (text/html → UI, "
            "application/json → proxy path)."
        ),
    ),
    Entry(
        id="B2",
        anchor="b2-ibounce-aws-only-scope-design",
        banner_line="",
        doctor_blurb=(
            "ibounce gates AWS calls ONLY. K8s → kbounce. DB → dbounce. "
            "HTTP → gbounce. Each product is a separate listener; "
            "they share vocabulary (profiles, modes, rules, tasks) "
            "per [[four-products-one-brand]]."
        ),
    ),
    Entry(
        id="B3",
        anchor="b3-ibounce-safe-default--readonly-admin-minus-design",
        banner_line=(
            "  caveat: safe-default profile = readonly-admin-minus "
            "(reads allowed except sensitive prefixes; writes prompt; "
            "see KNOWN-CAVEATS §B3)"
        ),
        doctor_blurb=(
            "The safe-default profile is 'readonly-admin-minus': reads "
            "are allowed except on sensitive prefixes (KMS, "
            "SecretsManager, IAM creds); writes prompt. Use "
            "--profile strict-admin for stricter (block all writes) "
            "or run --profile full-user for passthrough audit-only."
        ),
    ),
    Entry(
        id="B4",
        anchor="b4-ibounce-safe-default-catches-are-verb-level-not-content-aware-design--v11-enhancement",
        banner_line="",
        doctor_blurb=(
            "ibounce's safe-default catches are VERB-level by default. "
            "Scoped `iam:CreateRole` and wildcard `iam:*` are denied "
            "by the SAME rule — catches of legit + malicious writes "
            "look identical at the verb layer. For content-aware "
            "decisions, add iam-jit to the path (Variant C); iam-jit "
            "provides scope-aware risk scoring; ibounce provides the "
            "atomic gate. v1.1 plan: ibounce calls into iam-jit's "
            "scorer inline."
        ),
    ),
    Entry(
        id="B10",
        anchor="b10-iam-jit-aws-only-scope-design",
        banner_line="",
        doctor_blurb=(
            "iam-jit (the AWS IAM risk scorer that ships in the same "
            "repo as ibounce) is AWS-only. K8s/DB/HTTP unaffected."
        ),
    ),
    Entry(
        id="B11",
        anchor="b11-iam-jit-deterministic-floor-never-lowered-by-llm-design",
        banner_line="",
        doctor_blurb=(
            "iam-jit's LLM-Pro overrides go UP, never DOWN, relative "
            "to the deterministic floor. Per "
            "[[scorer-is-ground-truth]]."
        ),
    ),
    Entry(
        id="B12",
        anchor="b12-iam-jit-iam-score-9-collision-calibration--medium-not-launch-blocking",
        banner_line="",
        doctor_blurb=(
            "iam-jit's IAM scorer: scoped `iam:CreateRole` and "
            "wildcard `iam:*` both score 9. Distinguishable via the "
            "`factors` list but not via the numeric score. "
            "Threshold-based auto-approval still works correctly; "
            "v1.0.x calibration sweep tightens within-band-9 "
            "resolution."
        ),
    ),
    Entry(
        id="B13",
        anchor="b13-cross-product-1-3-concurrent-terminals-in-v10-gap--v11-raises-to-20",
        banner_line="",
        doctor_blurb=(
            "ibounce shares the cross-product 1-3 concurrent terminal "
            "limit with kbounce + dbounce + gbounce. "
            "active-mcp-session.json is single-entry; profile + pause "
            "state are global. v1.1 task #296 raises this to 20."
        ),
    ),
    Entry(
        id="B14",
        anchor="b14-cross-product-defense-in-depth--unified-product-design-per-four-products-one-brand",
        banner_line="",
        doctor_blurb=(
            "ibounce is one of four Bounce products under one brand. "
            "~10% of decisions show TRUE multi-layer composition per "
            "UAT. The honest framing per "
            "[[ibounce-honest-positioning]]: complementary products, "
            "not a single integrated suite."
        ),
    ),
    Entry(
        id="B15",
        anchor="b15-cross-product-no-unified-deny-prompt-ui-in-v10-gap--v11",
        banner_line="",
        doctor_blurb=(
            "Each bouncer (ibounce / kbounce / dbounce / gbounce) "
            "prompts independently in v1.0. v1.1 brings a unified "
            "prompt-inbox UI across the suite."
        ),
    ),
)


def by_id(entry_id: str) -> Entry | None:
    """Return the entry whose ``id`` matches, or ``None``."""
    for e in ENTRIES:
        if e.id == entry_id:
            return e
    return None


def link_suffix(entry_id: str) -> str:
    """Return ``" (see KNOWN-CAVEATS §<id>: <url>)"`` for the entry id.

    Used to append a helpful pointer to an HTTP error response body so
    an operator hitting a deny lands on the doc immediately. Empty
    string when the id isn't recognized — callers still emit the bare
    error rather than a malformed link.
    """
    e = by_id(entry_id)
    if e is None:
        return ""
    return f" (see KNOWN-CAVEATS §{e.id}: {e.url})"


@dataclass(frozen=True)
class Trigger:
    """Runtime conditions that drive the banner's per-line output.

    Per the founder direction: only emit a banner line when the
    triggering config actually fires — don't spam the operator with
    every §B entry on every run.
    """

    # ``always_sigv4_only`` is True because ibounce's SigV4-only shape
    # is structural — every ibounce instance gates SigV4-signed calls,
    # so §B1 always applies. Fielded as a Trigger property anyway so
    # tests can swap it off and a future "ibounce accepts pre-signed
    # URLs too" mode can wire through cleanly.
    always_sigv4_only: bool = True
    # ``safe_default_profile`` is True when the active profile is
    # ``safe-default``. Triggers §B3.
    safe_default_profile: bool = False


def banner_lines(trigger: Trigger) -> list[str]:
    """Return the banner lines to print for the given trigger."""
    out: list[str] = []
    if trigger.always_sigv4_only:
        e = by_id("B1")
        if e and e.banner_line:
            out.append(e.banner_line)
    if trigger.safe_default_profile:
        e = by_id("B3")
        if e and e.banner_line:
            out.append(e.banner_line)
    return out


def doctor_entries() -> tuple[Entry, ...]:
    """All ibounce-relevant entries, in declaration order."""
    return ENTRIES
