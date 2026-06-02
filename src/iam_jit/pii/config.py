# ADOPT-7 / #721 — declarative custom-PII-entity config.
"""Parse + validate the declarative custom-entities config.

The config is a list of entity declarations. Each declaration maps
directly onto a Presidio recognizer; there is NO interpretation step
(no LLM, no NL synthesis — per [[no-nl-synthesis]]).

Config shape (YAML)::

    schema_version: 1
    entities:
      - name: EMP_BADGE                 # required; the entity label
        description: "employee badge ID"  # optional; surfaced to operator
        patterns:                       # regex patterns -> PatternRecognizer
          - "EMP-\\d{5}"
        deny_list:                      # literal terms -> deny-list recognizer
          - "Project Bluefin"
          - "Codename Redshift"
        context:                        # nearby words that boost confidence
          - badge
          - employee
        score: 0.8                      # base confidence 0.0–1.0 for patterns

At least one of ``patterns`` or ``deny_list`` is required per entity.
``score`` defaults to 0.6 and applies to ``patterns`` matches (deny-list
matches are exact-string and scored 1.0 by Presidio). ``context`` is
optional and, when supplied, boosts a nearby match's score.

JSON is also accepted (same keys). The file extension picks the parser;
``.json`` -> JSON, anything else -> YAML.
"""

from __future__ import annotations

import dataclasses
import json
import pathlib
import re
from typing import Any

# A reasonable default confidence for pattern matches when the operator
# doesn't pin one. Mid-range: high enough to fire, low enough that a
# context-word boost still has room to push it toward certainty.
DEFAULT_SCORE = 0.6

# Cap on declared entities / patterns. A config is operator-authored and
# small; these bounds just stop a pathological file from building tens of
# thousands of recognizers (each is a compiled regex run over every body).
MAX_ENTITIES = 200
MAX_PATTERNS_PER_ENTITY = 50
MAX_DENY_LIST_PER_ENTITY = 5000

# Presidio entity labels are upper-snake by convention (PERSON,
# CREDIT_CARD, ...). We require the same so custom entities sit cleanly
# alongside the built-ins and so a label can't collide with a regex
# metacharacter when it lands in a redaction placeholder.
_ENTITY_NAME_RE = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")


class PiiConfigError(ValueError):
    """Raised on a malformed / invalid custom-PII config. Carries an
    operator-readable message; the CLI prints it and exits non-zero."""


@dataclasses.dataclass(frozen=True)
class CustomEntity:
    """One declared custom PII entity. Maps 1:1 onto Presidio
    recognizer constructor args (see ``recognizers.build_recognizers``).
    """

    name: str
    """Entity label, e.g. ``EMP_BADGE``. Upper-snake."""

    patterns: tuple[str, ...] = ()
    """Regex patterns. Each becomes a Presidio ``Pattern`` inside a
    ``PatternRecognizer`` for this entity."""

    deny_list: tuple[str, ...] = ()
    """Literal terms. Become a deny-list ``PatternRecognizer`` for this
    entity (exact, case-insensitive matches scored 1.0)."""

    context: tuple[str, ...] = ()
    """Words that, when present near a match, raise the match's
    confidence. Best-effort proximity boost — see recognizers.py."""

    score: float = DEFAULT_SCORE
    """Base confidence (0.0–1.0) assigned to ``patterns`` matches."""

    description: str = ""
    """Optional human-readable note surfaced in CLI output."""


@dataclasses.dataclass(frozen=True)
class CustomPiiConfig:
    """A parsed, validated custom-PII config."""

    schema_version: int
    entities: tuple[CustomEntity, ...]

    @property
    def entity_names(self) -> tuple[str, ...]:
        return tuple(e.name for e in self.entities)


def _as_str_tuple(value: Any, *, field: str, entity: str, cap: int) -> tuple[str, ...]:
    """Coerce a config value into a tuple of non-empty strings, or raise."""
    if value is None:
        return ()
    if isinstance(value, str):
        # A bare string is a common authoring slip for a one-element
        # list; accept it rather than silently treating each char as
        # an item.
        items = [value]
    elif isinstance(value, (list, tuple)):
        items = list(value)
    else:
        raise PiiConfigError(
            f"entity {entity!r}: field {field!r} must be a list of "
            f"strings (got {type(value).__name__})"
        )
    out: list[str] = []
    for item in items:
        if not isinstance(item, str):
            raise PiiConfigError(
                f"entity {entity!r}: every {field!r} item must be a "
                f"string (got {type(item).__name__})"
            )
        s = item.strip()
        if not s:
            raise PiiConfigError(
                f"entity {entity!r}: {field!r} contains an empty string"
            )
        out.append(s)
    if len(out) > cap:
        raise PiiConfigError(
            f"entity {entity!r}: {field!r} has {len(out)} items; "
            f"max {cap}"
        )
    return tuple(out)


def _parse_entity(raw: Any, *, index: int) -> CustomEntity:
    if not isinstance(raw, dict):
        raise PiiConfigError(
            f"entities[{index}] must be a mapping (got "
            f"{type(raw).__name__})"
        )
    name = raw.get("name")
    if not isinstance(name, str) or not name.strip():
        raise PiiConfigError(
            f"entities[{index}]: 'name' is required and must be a "
            "non-empty string"
        )
    name = name.strip()
    if not _ENTITY_NAME_RE.match(name):
        raise PiiConfigError(
            f"entity {name!r}: name must be UPPER_SNAKE_CASE "
            r"(matching ^[A-Z][A-Z0-9_]{0,63}$), e.g. EMP_BADGE"
        )

    patterns = _as_str_tuple(
        raw.get("patterns"), field="patterns", entity=name,
        cap=MAX_PATTERNS_PER_ENTITY,
    )
    deny_list = _as_str_tuple(
        raw.get("deny_list"), field="deny_list", entity=name,
        cap=MAX_DENY_LIST_PER_ENTITY,
    )
    context = _as_str_tuple(
        raw.get("context"), field="context", entity=name,
        cap=MAX_PATTERNS_PER_ENTITY,
    )

    if not patterns and not deny_list:
        raise PiiConfigError(
            f"entity {name!r}: declare at least one of 'patterns' or "
            "'deny_list' (an entity with neither detects nothing)"
        )

    # Compile every regex now so a bad pattern fails LOUDLY at config
    # load — never silently at scan time. (We discard the compiled
    # object; recognizers.py recompiles via Presidio's Pattern.)
    for pat in patterns:
        try:
            re.compile(pat)
        except re.error as e:
            raise PiiConfigError(
                f"entity {name!r}: invalid regex {pat!r}: {e}"
            ) from e

    score_raw = raw.get("score", DEFAULT_SCORE)
    try:
        score = float(score_raw)
    except (TypeError, ValueError) as e:
        raise PiiConfigError(
            f"entity {name!r}: 'score' must be a number 0.0–1.0 "
            f"(got {score_raw!r})"
        ) from e
    if not (0.0 <= score <= 1.0):
        raise PiiConfigError(
            f"entity {name!r}: 'score' must be between 0.0 and 1.0 "
            f"(got {score})"
        )

    description = raw.get("description", "")
    if description is None:
        description = ""
    if not isinstance(description, str):
        raise PiiConfigError(
            f"entity {name!r}: 'description' must be a string"
        )

    return CustomEntity(
        name=name,
        patterns=patterns,
        deny_list=deny_list,
        context=context,
        score=score,
        description=description.strip(),
    )


def parse_config(data: Any) -> CustomPiiConfig:
    """Parse + validate an already-loaded config mapping.

    Raises :class:`PiiConfigError` on any problem. Validation is strict
    + fail-loud: a malformed entity raises rather than being skipped, so
    an operator can never believe a detector is active when it silently
    wasn't built.
    """
    if not isinstance(data, dict):
        raise PiiConfigError(
            f"config root must be a mapping (got {type(data).__name__})"
        )

    schema_version = data.get("schema_version", 1)
    if not isinstance(schema_version, int) or schema_version != 1:
        raise PiiConfigError(
            f"unsupported schema_version {schema_version!r}; this build "
            "supports schema_version: 1"
        )

    raw_entities = data.get("entities")
    if not isinstance(raw_entities, list) or not raw_entities:
        raise PiiConfigError(
            "config must declare a non-empty 'entities' list"
        )
    if len(raw_entities) > MAX_ENTITIES:
        raise PiiConfigError(
            f"config declares {len(raw_entities)} entities; max "
            f"{MAX_ENTITIES}"
        )

    entities = tuple(
        _parse_entity(raw, index=i) for i, raw in enumerate(raw_entities)
    )

    seen: set[str] = set()
    for e in entities:
        if e.name in seen:
            raise PiiConfigError(
                f"duplicate entity name {e.name!r}; names must be unique"
            )
        seen.add(e.name)

    return CustomPiiConfig(schema_version=schema_version, entities=entities)


def load_config(path: str | pathlib.Path) -> CustomPiiConfig:
    """Load + parse a custom-PII config file.

    ``.json`` is parsed as JSON; everything else as YAML. Raises
    :class:`PiiConfigError` on a missing file, parse error, or invalid
    content.
    """
    p = pathlib.Path(path)
    try:
        text = p.read_text(encoding="utf-8")
    except OSError as e:
        raise PiiConfigError(f"could not read config {p}: {e}") from e

    if p.suffix.lower() == ".json":
        try:
            data = json.loads(text)
        except json.JSONDecodeError as e:
            raise PiiConfigError(f"invalid JSON in {p}: {e}") from e
    else:
        from ruamel.yaml import YAML
        from ruamel.yaml.error import YAMLError

        yaml = YAML(typ="safe")
        try:
            data = yaml.load(text)
        except YAMLError as e:
            raise PiiConfigError(f"invalid YAML in {p}: {e}") from e

    return parse_config(data)
