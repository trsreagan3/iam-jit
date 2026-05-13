"""Prompt-injection detection for chat / intake input.

Why: a malicious user (or upstream agent feeding iam-jit user-shaped
content) might try to coerce the LLM into emitting permissions or
provisioning JSON it shouldn't. Even though iam-jit is human-gated at
the approval step — no LLM output ever bypasses an explicit `approve`
transition by an authorized approver — we still treat detected
injection attempts as a serious signal: they imply the user is
adversarially probing the system, and we want to stop interacting
with them rather than continue refining their prompt.

Detection rules are intentionally regex-based, not LLM-based:

  - Detection itself must not be vulnerable to the attack we're
    detecting. A meta-LLM that classifies "is this an injection?" is
    just another injection target.
  - Conservative regex patterns produce occasional false positives
    (legitimate prompt about "ignore the previous statement of
    intent…"); we surface these to admins via the ban audit log so
    they can review and unban if warranted.

Obfuscation-resistance: adversarial tooling exists that converts
prompt-injection text into leetspeak, base64, binary, pig latin,
scrambled words, and Unicode circled/squared "emoji" letters before
sending it to the LLM. To catch those, `detect()` runs the full rule
set against the raw text AND against a set of decoded variants:

  - NFKC-normalized + custom homoglyph fold (catches circled/squared
    letters, fullwidth, mathematical alphanumerics, etc.)
  - leetspeak reversal (4→a, 3→e, 0→o, 5→s, 7→t, 1→i/l, 6→g, 8→b)
  - base64 decode (any ≥16-char [A-Za-z0-9+/=] substring)
  - binary decode (any ≥48-char [01 ]+ run, treating each 8-bit group
    as ASCII)
  - hex decode (any ≥16-char [0-9a-f]+ substring)
  - ROT13
  - reversed text
  - pig latin reversal (heuristic — drops trailing 'ay' / 'way')

Plus a new high-signal pattern that fires on the **structural shape**
of an encoded blob (long base64, long binary, runs of homoglyphs)
even when the decoded form happens to be benign — because using
encoding to reach an LLM is itself adversarial in a permissions
context. False-positive blast radius is contained by the same
admin-can-unban mechanism.

When detected, the caller gets:
  - `reasons`: list of which patterns matched, used for the audit log
  - `confidence`: "high" if multiple patterns match or one of the
    high-signal ones (system-prompt impersonation, tool-call forging),
    "medium" otherwise

Banning policy (enforced at the route layer, not here):
  - high → immediate ban + 403
  - medium → reject the message but don't ban (allow correction)

This keeps the false-positive blast radius small while still catching
the obvious attacks.
"""

from __future__ import annotations

import base64
import codecs
import re
import unicodedata
from dataclasses import dataclass


# High-signal: structural / role-confusion attempts. These are
# uncommon in normal chat about IAM and rarely appear by accident.
_HIGH_SIGNAL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "role-impersonation",
        re.compile(
            r"(?im)^\s*(system|assistant|tool|developer)\s*[:>\-=]\s*",
        ),
    ),
    (
        "system-prompt-override",
        re.compile(
            # Verb close to a qualifier close to a keyword. Up to a few
            # filler words allowed between each pair so heuristic
            # decoders (pig-latin reverser, leet) that inject extra
            # tokens don't break the chain. Filler is `\w+\W+`, capped
            # at 5 + 3 hops to avoid catching "ignore the noise" — that
            # has no qualifier+keyword pair within range.
            r"(?i)\b(ignore|disregard|forget|override|bypass|skip|drop|remove)\b\W+"
            r"(?:\w+\W+){0,12}?"
            r"\b(your|the|all|previous|prior|earlier|above|any)\b\W+"
            r"(?:\w+\W+){0,8}?"
            r"\b(instruction|prompt|rule|guideline|directive|system\s*prompt|"
            r"safety|constraint|context)s?\b"
        ),
    ),
    (
        "fake-tool-call",
        re.compile(
            r"(?is)<\s*(tool_use|function_call|invoke|tool_call)\b|"
            r"```(?:json|tool|function)\s*\{\s*\"name\"\s*:\s*\"(provision|create_role|"
            r"approve|grant_admin|escalate)\"",
        ),
    ),
    (
        "approve-forgery",
        # The first alternative used to be a bare `auto[-\s]?approve` —
        # which false-positived on legitimate descriptions that just
        # mentioned the iam-jit feature by name (e.g. "the previous
        # auto-approve grant expired"). Now require a coercive VERB
        # to be present nearby. The other alternatives (skip approval,
        # bypass approval, act as approver, impersonate approver,
        # pretend to be admin) are already verb-anchored and stay.
        re.compile(
            r"(?i)(?:"
              # auto-approve must be paired with an attacker-verb to fire.
              # Accept morphological variants (approve/approving/approved/approval).
              r"\b(?:trigger|force|trick|coerce|cause|grant\s+me|"
              r"give\s+me|make\s+it|get\s+it\s+to)\b\W+"
              r"(?:\w+\W+){0,6}?"
              r"\bauto[-\s]?approv(?:e|ed|es|ing|al)\b"
              r"|"
              r"skip\s+approval|bypass\s+approval|"
              r"act\s+as\s+(an\s+)?approver|impersonate\s+approver|"
              r"pretend\s+(you\s+are|to\s+be)\s+(an\s+)?(admin|approver|root)"
            r")"
        ),
    ),
    (
        "exfil-request",
        re.compile(
            r"(?i)\b(reveal|print|output|expose|disclose|leak|show)\b\W+"
            r"(?:\w+\W+){0,10}?"
            r"\b(your|the)\b\W+"
            r"(?:\w+\W+){0,8}?"
            r"\b(system\s*prompt|instructions|secret|api\s*key|token|"
            r"credential|external[-\s]?id)\b"
        ),
    ),
    (
        "policy-replacement",
        re.compile(
            r"(?i)\b(your|the)\b\W+"
            r"(?:\w+\W+){0,8}?"
            r"\bnew\b\W+"
            r"(?:\w+\W+){0,8}?"
            r"\b(instruction|rule|directive|prompt|policy)s?\b\W+"
            r"(?:\w+\W+){0,8}?"
            r"\b(is|are|now)\b"
        ),
    ),
    (
        "wildcard-coercion",
        # Asking to grant Action: "*" / Resource: "*" — explicit attempts
        # to escalate. These DO appear in legitimate context too (admin
        # debugging) but never in chat input — admins use paste mode for
        # those.
        re.compile(
            r"(?i)\b(grant|give|add|need|assign|make|set)\b\W+"
            r"(?:\w+\W+){0,10}?"
            r"\b(\*|admin|administrator(access)?|administrative|root|"
            r"superuser|all\s+permissions)\b"
        ),
    ),
]

# High-signal structural patterns — match on the SHAPE of the input,
# regardless of decoded content. A long base64 or binary blob in chat
# input is itself adversarial in a permissions-request context: there
# is no legitimate reason a user would type 200 chars of base64 into
# "what AWS access do you need?".
_OBFUSCATION_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "obfuscation-base64-blob",
        # ≥40 base64 chars in a row = ~30+ bytes payload. Random English
        # text never produces sustained runs that look like base64
        # because base64 chars are A-Za-z0-9+/= with strict structure.
        re.compile(r"[A-Za-z0-9+/]{40,}={0,2}"),
    ),
    (
        "obfuscation-binary-blob",
        # ≥48 chars of `01 01 01 …` runs (6 ASCII chars worth).
        re.compile(r"(?:[01]{8}\s+){5,}[01]{8}"),
    ),
    (
        "obfuscation-hex-blob",
        # ≥40 hex chars in a row.
        re.compile(r"\b[0-9a-fA-F]{40,}\b"),
    ),
    (
        "obfuscation-circled-letters",
        # ≥6 circled/squared/regional Unicode letters in a row.
        # `re` doesn't support `\p{}`, so we list the ranges explicitly.
        re.compile(
            r"[Ⓐ-ⓩ㉈-㉏㉑-㉟㊱-㊿"
            r"\U0001F130-\U0001F149\U0001F150-\U0001F169\U0001F170-\U0001F189]{6,}"
        ),
    ),
    (
        "obfuscation-pig-latin",
        # ≥4 consecutive words all ending in 'ay' or 'way'. Pig latin's
        # signature is unmistakable — no normal English chat input
        # naturally produces this. Catches the encoding directly even
        # when full reversal is ambiguous.
        re.compile(r"(?i)(?:\b\w+(?:way|ay)\b\W+){3,}\b\w+(?:way|ay)\b"),
    ),
]


# Medium-signal: looser patterns that may flag legitimate phrasing.
_MEDIUM_SIGNAL_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    (
        "delimiter-injection",
        re.compile(r"\"\"\"|---\s*end\s*of\s*(prompt|instructions)|<\|im_(start|end)\|>"),
    ),
    (
        "json-prompt-impersonation",
        re.compile(
            r"(?is)\{\s*\"(role|system_prompt|instructions)\"\s*:\s*\""
        ),
    ),
    (
        "reverse-psychology",
        re.compile(
            r"(?i)(do\s+not\s+tell|don't\s+tell|don't\s+say|not\s+supposed\s+to)\s+"
            r"(the\s+)?(approver|admin|user|human|anyone)"
        ),
    ),
]


@dataclass(frozen=True)
class InjectionVerdict:
    detected: bool
    confidence: str  # "high" | "medium" | "none"
    reasons: list[str]
    snippets: list[str]
    """Up to 80 chars of the matching text per rule, for the audit log.

    Capped to keep audit entries small and never echo the user's full
    message back into logs (which then get shipped to Datadog, etc.)."""


# ---- Decoders / normalizers ----
#
# Each `_decode_*` returns either a string (a candidate decoded view of
# the input that should also be scanned) or "" (no plausible decoding).
# They are intentionally permissive: false positives at this layer are
# fine — the regex rules are what ultimately classify the result.


# Reverse leetspeak character map. Some leet substitutions are
# ambiguous (1 → i OR l). We pick the more common-in-injection-text
# mapping for each digit. The detection pipeline runs the rules
# against multiple variants so getting one ambiguity wrong rarely
# matters: if "ignore" is leet'd as "1gn0r3", reversing 1→i gives
# "ignore"; if "all" is leet'd as "411", reversing 1→l gives "all".
_LEET_REVERSE_MAP: dict[str, str] = {
    "0": "o",
    "1": "i",
    "3": "e",
    "4": "a",
    "5": "s",
    "6": "g",
    "7": "t",
    "8": "b",
    "9": "g",
    "@": "a",
    "$": "s",
    "!": "i",
    "+": "t",
}


def _decode_leetspeak(text: str) -> str:
    return "".join(_LEET_REVERSE_MAP.get(c, c) for c in text)


def _decode_leetspeak_l_variant(text: str) -> str:
    """Same as `_decode_leetspeak` but maps `1` → `l` instead of `i`.

    Some letters have multiple plausible leet substitutions ("1" stands
    in for both 'i' and 'l'). Single-output reversal can only pick one,
    losing words that used the other. Emitting both variants lets the
    regex pass match against whichever happens to round-trip back to
    English.
    """
    out = []
    for c in text:
        if c == "1":
            out.append("l")
        else:
            out.append(_LEET_REVERSE_MAP.get(c, c))
    return "".join(out)


# Targeted homoglyph fold: NFKC catches circled/squared/fullwidth, but
# leaves Cyrillic look-alikes (а, е, о, с, etc.) alone. Manual map.
_HOMOGLYPH_MAP: dict[str, str] = {
    # Cyrillic look-alikes for Latin letters
    "а": "a", "А": "A", "е": "e", "Е": "E", "о": "o", "О": "O",
    "с": "c", "С": "C", "р": "p", "Р": "P", "у": "y", "У": "Y",
    "х": "x", "Х": "X", "і": "i", "І": "I", "ј": "j", "Ј": "J",
    "ѕ": "s", "Ѕ": "S",
    # Greek look-alikes
    "α": "a", "ε": "e", "ο": "o", "Ι": "I", "Α": "A", "Ε": "E",
    "Ο": "O", "Β": "B", "Η": "H", "Κ": "K", "Μ": "M", "Ν": "N",
    "Ρ": "P", "Τ": "T", "Χ": "X", "Υ": "Y", "Ζ": "Z",
}


def _decode_homoglyphs(text: str) -> str:
    """Apply NFKC + custom Cyrillic/Greek fold."""
    nfkc = unicodedata.normalize("NFKC", text)
    return "".join(_HOMOGLYPH_MAP.get(c, c) for c in nfkc)


_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def _decode_base64(text: str) -> str:
    """Decode every base64-looking substring; concat the results.

    Non-decodable substrings are skipped silently. Output is filtered
    to printable ASCII so binary garbage doesn't trip later rules
    randomly."""
    out: list[str] = []
    for m in _BASE64_RE.finditer(text):
        candidate = m.group(0)
        # base64 length must be a multiple of 4 with padding.
        pad = (4 - len(candidate) % 4) % 4
        try:
            decoded = base64.b64decode(candidate + "=" * pad, validate=False)
        except Exception:
            continue
        try:
            decoded_text = decoded.decode("utf-8", errors="ignore")
        except Exception:
            continue
        # Keep only if the decode produced text that looks like text
        # (printable ascii + whitespace). Otherwise it was probably
        # incidental base64-shaped data (e.g. AWS account IDs, ARNs).
        if decoded_text and sum(
            1 for c in decoded_text if c.isprintable() or c in "\n\r\t "
        ) / max(len(decoded_text), 1) > 0.85:
            out.append(decoded_text)
    return " ".join(out)


_BINARY_RE = re.compile(r"(?:[01]{8}\s*){4,}")


def _decode_binary(text: str) -> str:
    """Decode runs of 8-bit ASCII binary back to text."""
    out: list[str] = []
    for m in _BINARY_RE.finditer(text):
        bits = re.sub(r"\s+", "", m.group(0))
        if len(bits) % 8 != 0:
            bits = bits[: len(bits) - (len(bits) % 8)]
        try:
            chars = [
                chr(int(bits[i : i + 8], 2))
                for i in range(0, len(bits), 8)
            ]
        except ValueError:
            continue
        decoded = "".join(c for c in chars if c.isprintable() or c == " ")
        if decoded:
            out.append(decoded)
    return " ".join(out)


_HEX_RE = re.compile(r"\b[0-9a-fA-F]{16,}\b")


def _decode_hex(text: str) -> str:
    out: list[str] = []
    for m in _HEX_RE.finditer(text):
        h = m.group(0)
        if len(h) % 2 != 0:
            h = h[:-1]
        try:
            decoded = bytes.fromhex(h).decode("utf-8", errors="ignore")
        except Exception:
            continue
        if decoded and sum(
            1 for c in decoded if c.isprintable() or c in "\n\r\t "
        ) / max(len(decoded), 1) > 0.85:
            out.append(decoded)
    return " ".join(out)


def _decode_rot13(text: str) -> str:
    try:
        return codecs.decode(text, "rot_13")
    except Exception:
        return ""


def _decode_reversed(text: str) -> str:
    return text[::-1]


_PIG_LATIN_WORD = re.compile(r"\b([a-z]+?)(way|ay)\b", re.IGNORECASE)
_VOWELS = set("aeiouAEIOU")


def _decode_pig_latin(text: str) -> str:
    """Heuristic pig-latin reversal.

    Pig latin construction:
      - vowel-start: 'ignore' → 'ignoreway' (suffix 'way')
      - consonant-cluster: 'previous' → 'eviouspray' — move leading
        consonant cluster to end + 'ay'. Trailing consonants in the
        encoded body ARE the original leading cluster.

    Reversal:
      - 'way' → drop suffix.
      - 'ay'  → take trailing consonant run from body, prepend to rest.
        Single-trailing-consonant case ('snake' → 'akesn'+'ay') needs
        the consonant run to be the entire trailing run, not just one
        letter.
    """

    def _flip(match: re.Match) -> str:
        body, suffix = match.group(1), match.group(2).lower()
        if suffix == "way":
            return body
        if not body:
            return body
        # Find the run of trailing consonants — these are *candidates*
        # for the originally-shifted leading cluster, but we don't know
        # how long the cluster was: 'eviouspr' has trailing 'spr', and
        # the original cluster could have been any prefix of those
        # consonants. Emit all rotations so the regex pass sees them
        # all.
        i = len(body)
        while i > 0 and body[i - 1].lower() not in _VOWELS:
            i -= 1
        if i == len(body) or i == 0:
            return body
        trailing = body[i:]
        head = body[:i]
        rotations: list[str] = []
        # Try each possible split of `trailing` as the leading cluster.
        # Skip the unrotated body — it isn't English and just adds
        # noise to the regex pass.
        for k in range(1, len(trailing) + 1):
            cluster = trailing[-k:]
            tail = trailing[:-k]
            rotations.append(cluster + head + tail)
        return " ".join(rotations)

    return _PIG_LATIN_WORD.sub(_flip, text)


def _normalize_for_detection(text: str) -> dict[str, str]:
    """Return a dict of `variant_name → decoded_text` to scan against.

    The raw text is always one of the variants. Decoders that produce
    empty / unchanged output are dropped to keep the regex pass fast."""
    variants: dict[str, str] = {"raw": text}

    homoglyphs = _decode_homoglyphs(text)
    if homoglyphs != text:
        variants["homoglyphs"] = homoglyphs

    leet = _decode_leetspeak(homoglyphs.lower())
    if leet != homoglyphs.lower():
        variants["leetspeak"] = leet

    leet_l = _decode_leetspeak_l_variant(homoglyphs.lower())
    if leet_l != homoglyphs.lower() and leet_l != leet:
        variants["leetspeak_l"] = leet_l

    b64 = _decode_base64(text)
    if b64:
        variants["base64"] = b64

    bins = _decode_binary(text)
    if bins:
        variants["binary"] = bins

    hexv = _decode_hex(text)
    if hexv:
        variants["hex"] = hexv

    rot13 = _decode_rot13(text)
    if rot13 and rot13 != text:
        variants["rot13"] = rot13

    rev = _decode_reversed(text)
    if rev != text:
        variants["reversed"] = rev

    pig = _decode_pig_latin(text)
    if pig != text:
        variants["pig_latin"] = pig

    return variants


_MAX_DETECT_INPUT_BYTES = 64 * 1024


def detect(text: str) -> InjectionVerdict:
    """Scan `text` for prompt-injection patterns. Returns a verdict.

    Runs the pattern set against the raw input AND against a battery
    of decoded views (leetspeak, base64, binary, hex, ROT13, reversed,
    pig latin, homoglyph-folded). Also fires on structural patterns
    indicating the input is itself an obfuscation envelope.

    No-op (returns confidence='none') for empty input or text under 4
    chars — too short to express meaningful injection.

    Length cap: any input over 64 KiB is truncated before regex
    evaluation. This is a ReDoS guard — even though our patterns are
    written to avoid catastrophic backtracking, the body-size middleware
    is the primary defense and this cap is the secondary one.
    Truncation is safe for detection: if there's an attack within the
    first 64 KiB it still fires; if the whole 64 KiB is benign and
    only the suffix is malicious, the body-size middleware would have
    already refused the request.
    """
    if not isinstance(text, str) or len(text.strip()) < 4:
        return InjectionVerdict(
            detected=False, confidence="none", reasons=[], snippets=[]
        )
    if len(text) > _MAX_DETECT_INPUT_BYTES:
        text = text[:_MAX_DETECT_INPUT_BYTES]

    high_hits: list[tuple[str, str]] = []
    medium_hits: list[tuple[str, str]] = []

    # Structural / obfuscation-envelope rules apply to the raw input —
    # decoding them first would defeat the point of the rule.
    for name, pattern in _OBFUSCATION_PATTERNS:
        m = pattern.search(text)
        if m:
            high_hits.append((name, m.group(0)[:80]))

    variants = _normalize_for_detection(text)
    for variant_name, candidate in variants.items():
        if not candidate:
            continue
        for name, pattern in _HIGH_SIGNAL_PATTERNS:
            m = pattern.search(candidate)
            if m:
                tag = name if variant_name == "raw" else f"{name}:{variant_name}"
                high_hits.append((tag, m.group(0)[:80]))
        for name, pattern in _MEDIUM_SIGNAL_PATTERNS:
            m = pattern.search(candidate)
            if m:
                tag = name if variant_name == "raw" else f"{name}:{variant_name}"
                medium_hits.append((tag, m.group(0)[:80]))

    if high_hits:
        confidence = "high"
        reasons = [n for n, _ in high_hits]
        snippets = [s for _, s in high_hits]
    elif len(medium_hits) >= 2:
        confidence = "high"
        reasons = [n for n, _ in medium_hits]
        snippets = [s for _, s in medium_hits]
    elif medium_hits:
        confidence = "medium"
        reasons = [n for n, _ in medium_hits]
        snippets = [s for _, s in medium_hits]
    else:
        return InjectionVerdict(
            detected=False, confidence="none", reasons=[], snippets=[]
        )

    # Dedupe reasons while preserving order — multiple variants will
    # often hit the same rule and the audit log is more useful with
    # one entry per rule.
    seen: set[str] = set()
    unique_reasons: list[str] = []
    unique_snippets: list[str] = []
    for r, s in zip(reasons, snippets):
        if r in seen:
            continue
        seen.add(r)
        unique_reasons.append(r)
        unique_snippets.append(s)

    return InjectionVerdict(
        detected=True,
        confidence=confidence,
        reasons=unique_reasons,
        snippets=unique_snippets,
    )
