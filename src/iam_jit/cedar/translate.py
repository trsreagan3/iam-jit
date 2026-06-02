# ADOPT-5 / #719 — the IAM <-> Cedar translator core.
"""Faithful, HONEST IAM <-> Cedar translation.

See :mod:`iam_jit.cedar` for positioning + the honesty contract. This
module implements the translation itself. The guiding rule, restated:

    A wrong translation is a security risk. Where IAM and Cedar are not
    1:1, emit a visible marker + a structured note. NEVER silently drop
    a construct or emit a subtly-wrong policy.

Translation map (IAM -> Cedar), faithful subset:

    IAM                              Cedar
    ---------------------------      --------------------------------
    Effect: "Allow"                  permit ( ... );
    Effect: "Deny"                   forbid ( ... );
    Action: "s3:GetObject"           action == Action::"s3:GetObject"
    Action: ["a","b"]                action in [Action::"a", Action::"b"]
    Action: "*"                      action  (unconstrained)
    Resource: "<arn>"                resource == IamResource::"<arn>"
    Resource: ["x","y"]              resource in [IamResource::"x", ...]
    Resource: "*"                    resource  (unconstrained)
    Principal (resource policy)      principal == / in IamPrincipal::"..."
    Condition: StringEquals (one)    when { context["<key>"] == "<val>" }
    Condition: StringEquals (list)   when { ["a","b"].contains(context["<key>"]) }
    Condition: Bool true/false       when { context["<key>"] == true }

Explicitly UNTRANSLATABLE (loud marker + note, never silent):

    * NotAction / NotResource / NotPrincipal — Cedar has no negated
      element form; faking it with `unless` would change matching
      semantics (IAM negated-element matching is not the same as a
      Cedar condition). Emitted as `// UNTRANSLATABLE` + note.
    * Wildcards INSIDE an action/resource value other than a bare "*"
      (e.g. "s3:Get*", "arn:aws:s3:::bucket/*") — Cedar entity refs are
      exact strings; Cedar has no glob over entity uids. We preserve the
      literal so nothing is silently broadened, and flag it.
    * Condition operators outside the faithful subset (StringLike,
      DateGreaterThan, IpAddress, ArnLike, Null, ...) — emitted as a
      commented `// UNTRANSLATABLE condition` + note; the rest of the
      statement still translates so the operator can finish by hand.

Cedar -> IAM is best-effort and inverts the faithful subset. Cedar
constructs with no IAM equivalent (entity attribute references like
`resource.owner == principal`, `is` type tests, set/`like` operators)
are surfaced as notes and the affected scope is left as `"*"` ONLY when
that is the conservative reading; otherwise the statement is flagged.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from typing import Any


class TranslationError(ValueError):
    """Raised on malformed input that cannot be parsed at all.

    A parse failure is distinct from an *untranslatable construct*: a
    malformed IAM document or unparseable Cedar text is a hard error
    (the caller gave us garbage). An untranslatable-but-well-formed
    construct is NOT an error — it produces a visible marker + a note so
    the human can finish it. We fail loud on both, but only raise on the
    former."""


@dataclass(frozen=True)
class TranslationNote:
    """One structured translation note.

    `severity`:
        "untranslatable" — the construct has NO faithful equivalent; the
            output contains a visible marker and MUST be reviewed before
            use. Presence of any such note sets `is_lossy`.
        "lossy" — translated, but with a caveat that could matter (e.g.
            an embedded wildcard preserved literally). Sets `is_lossy`.
        "info" — purely informational; does NOT set `is_lossy`.
    """

    severity: str
    construct: str
    message: str
    location: str = ""

    def as_dict(self) -> dict[str, str]:
        return {
            "severity": self.severity,
            "construct": self.construct,
            "message": self.message,
            "location": self.location,
        }


@dataclass
class TranslationResult:
    """Result of a one-way translation.

    `output` is the translated text (Cedar) or JSON-string (IAM),
    depending on direction. `policy` is the parsed IAM dict when the
    direction is cedar->iam (None otherwise). `notes` carries every
    translation note; `is_lossy` is True if any note is severity
    "untranslatable" or "lossy"."""

    direction: str  # "iam->cedar" | "cedar->iam"
    output: str
    notes: list[TranslationNote] = field(default_factory=list)
    policy: dict[str, Any] | None = None

    @property
    def is_lossy(self) -> bool:
        return any(n.severity in ("untranslatable", "lossy") for n in self.notes)

    @property
    def has_untranslatable(self) -> bool:
        return any(n.severity == "untranslatable" for n in self.notes)

    def as_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "direction": self.direction,
            "output": self.output,
            "is_lossy": self.is_lossy,
            "has_untranslatable": self.has_untranslatable,
            "notes": [n.as_dict() for n in self.notes],
        }
        if self.policy is not None:
            d["policy"] = self.policy
        return d


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _as_list(v: Any) -> list[Any]:
    """IAM allows a scalar OR a list anywhere a list is allowed."""
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def _has_embedded_wildcard(s: str) -> bool:
    """True if `s` contains a `*`/`?` glob that is NOT a bare full-`*`.

    A bare "*" maps to an unconstrained Cedar element. Any other glob
    (``s3:Get*``, ``arn:...:bucket/*``) has no faithful Cedar entity-uid
    equivalent — Cedar entity refs are exact strings."""
    return s != "*" and ("*" in s or "?" in s)


# Cedar string-literal escaping: Cedar uses the same escape set as JSON
# strings for the common cases (\\ \" \n \t \r). We escape conservatively.
def _cedar_str(s: str) -> str:
    out = s.replace("\\", "\\\\").replace('"', '\\"')
    out = out.replace("\n", "\\n").replace("\t", "\\t").replace("\r", "\\r")
    return f'"{out}"'


# ===========================================================================
# IAM  ->  Cedar
# ===========================================================================


def iam_to_cedar(policy_json: dict[str, Any] | str) -> TranslationResult:
    """Translate an AWS IAM policy document to Cedar policy text.

    Accepts either a parsed dict or a JSON string. Returns a
    :class:`TranslationResult`; inspect ``.notes`` / ``.is_lossy`` to see
    where the translation was not 1:1. Raises :class:`TranslationError`
    only when the input cannot be parsed as an IAM policy at all.
    """
    if isinstance(policy_json, str):
        try:
            policy = json.loads(policy_json)
        except json.JSONDecodeError as e:
            raise TranslationError(f"input is not valid JSON: {e}") from e
    elif isinstance(policy_json, dict):
        policy = policy_json
    else:
        raise TranslationError(
            "IAM policy must be a JSON object or JSON string, got "
            f"{type(policy_json).__name__}"
        )

    if not isinstance(policy, dict):
        raise TranslationError("IAM policy must be a JSON object")

    statements = policy.get("Statement")
    # AWS grammar: Statement may be a single object or a list.
    if isinstance(statements, dict):
        statements = [statements]
    if statements is None:
        raise TranslationError(
            "IAM policy has no `Statement` key (not a valid IAM policy)"
        )
    if not isinstance(statements, list):
        raise TranslationError(
            "`Statement` must be an object or a list of objects"
        )

    notes: list[TranslationNote] = []
    blocks: list[str] = []

    header = (
        "// Translated from AWS IAM by iam-jit (interop layer).\n"
        "// iam-jit is NOT Cedar; this is a portability convenience.\n"
        "// Review any `// UNTRANSLATABLE` / `// NOTE` markers before use\n"
        "// — IAM and Cedar are not 1:1 (see translation notes).\n"
    )

    for idx, stmt in enumerate(statements):
        loc = f"Statement[{idx}]"
        if not isinstance(stmt, dict):
            raise TranslationError(
                f"{loc} is not an object (got {type(stmt).__name__})"
            )
        block, stmt_notes = _statement_to_cedar(stmt, idx)
        notes.extend(stmt_notes)
        blocks.append(block)

    cedar_text = header + "\n" + "\n\n".join(blocks) + "\n"
    return TranslationResult(
        direction="iam->cedar",
        output=cedar_text,
        notes=notes,
    )


def _statement_to_cedar(
    stmt: dict[str, Any], idx: int
) -> tuple[str, list[TranslationNote]]:
    notes: list[TranslationNote] = []
    loc = f"Statement[{idx}]"
    sid = stmt.get("Sid")

    effect = stmt.get("Effect")
    if effect not in ("Allow", "Deny"):
        raise TranslationError(
            f"{loc} has invalid Effect {effect!r} (must be 'Allow' or 'Deny')"
        )
    keyword = "permit" if effect == "Allow" else "forbid"

    # --- principal ---------------------------------------------------
    principal_clause, p_notes = _principal_to_cedar(stmt, loc)
    notes.extend(p_notes)

    # --- action ------------------------------------------------------
    action_clause, a_notes = _action_to_cedar(stmt, loc)
    notes.extend(a_notes)

    # --- resource ----------------------------------------------------
    resource_clause, r_notes = _resource_to_cedar(stmt, loc)
    notes.extend(r_notes)

    # --- condition ---------------------------------------------------
    when_clauses, c_notes = _condition_to_cedar(stmt.get("Condition"), loc)
    notes.extend(c_notes)

    head_parts = [principal_clause, action_clause, resource_clause]
    head = ",\n    ".join(head_parts)

    lines = []
    if sid is not None:
        lines.append(f"// Sid: {sid}")
    lines.append(f"{keyword} (\n    {head}\n)")
    for wc in when_clauses:
        lines.append(wc)
    block = "\n".join(lines) + ";"
    return block, notes


def _principal_to_cedar(
    stmt: dict[str, Any], loc: str
) -> tuple[str, list[TranslationNote]]:
    notes: list[TranslationNote] = []
    if "NotPrincipal" in stmt:
        notes.append(
            TranslationNote(
                "untranslatable",
                "NotPrincipal",
                "IAM `NotPrincipal` (negated principal matching) has no "
                "faithful Cedar equivalent. Cedar's principal scope is "
                "positive (`==` / `in`); a `forbid` with `unless` does NOT "
                "reproduce IAM NotPrincipal semantics. Left unconstrained "
                "with a marker — REVIEW before use.",
                loc,
            )
        )
        return "principal  // UNTRANSLATABLE: NotPrincipal — review", notes

    principal = stmt.get("Principal")
    if principal is None:
        # Identity-based policy: principal is implicit (the role the
        # policy is attached to). Cedar needs an explicit scope; `principal`
        # unconstrained is the faithful reading (the policy applies to
        # whoever holds it).
        notes.append(
            TranslationNote(
                "info",
                "Principal",
                "No `Principal` (identity-based policy). The principal is "
                "implicit in IAM (whoever the policy is attached to). "
                "Emitted as unconstrained `principal` in Cedar.",
                loc,
            )
        )
        return "principal", notes

    # Resource-based policy principal. `"*"` => any principal.
    if principal == "*":
        return "principal", notes

    # Typed forms: {"AWS": "...", "Service": "...", "Federated": "..."}
    if isinstance(principal, dict):
        flat: list[str] = []
        for ptype, pval in principal.items():
            for v in _as_list(pval):
                flat.append(str(v))
        if any(v == "*" for v in flat):
            return "principal", notes
        if not flat:
            return "principal", notes
        embedded = [v for v in flat if _has_embedded_wildcard(v)]
        if embedded:
            notes.append(
                TranslationNote(
                    "lossy",
                    "Principal",
                    "Principal value(s) contain embedded wildcards "
                    f"({embedded}); Cedar entity uids are exact strings. "
                    "Preserved literally (NOT expanded) so nothing is "
                    "silently broadened — review.",
                    loc,
                )
            )
        return _entity_scope("principal", "IamPrincipal", flat), notes

    if isinstance(principal, str):
        if _has_embedded_wildcard(principal):
            notes.append(
                TranslationNote(
                    "lossy",
                    "Principal",
                    f"Principal `{principal}` contains an embedded wildcard; "
                    "Cedar entity uids are exact. Preserved literally.",
                    loc,
                )
            )
        return _entity_scope("principal", "IamPrincipal", [principal]), notes

    raise TranslationError(f"{loc} has an unrecognized Principal shape")


def _action_to_cedar(
    stmt: dict[str, Any], loc: str
) -> tuple[str, list[TranslationNote]]:
    notes: list[TranslationNote] = []
    if "NotAction" in stmt:
        notes.append(
            TranslationNote(
                "untranslatable",
                "NotAction",
                "IAM `NotAction` (all actions EXCEPT these) has no faithful "
                "Cedar equivalent. Cedar action scope is a positive `==` / "
                "`in [...]`; there is no negated-action element. Translating "
                "it as a positive list would INVERT the meaning. Left "
                "unconstrained with a marker — REVIEW before use.",
                loc,
            )
        )
        return "action  // UNTRANSLATABLE: NotAction — review", notes

    action = stmt.get("Action")
    if action is None:
        raise TranslationError(f"{loc} has neither Action nor NotAction")

    actions = [str(a) for a in _as_list(action)]
    if any(a == "*" for a in actions):
        if len(actions) > 1:
            notes.append(
                TranslationNote(
                    "info",
                    "Action",
                    "Action list contains `*` alongside specific actions; "
                    "`*` subsumes them. Emitted as unconstrained `action`.",
                    loc,
                )
            )
        return "action", notes

    embedded = [a for a in actions if _has_embedded_wildcard(a)]
    if embedded:
        notes.append(
            TranslationNote(
                "lossy",
                "Action",
                f"Action(s) {embedded} use service-glob wildcards (e.g. "
                "`s3:Get*`). Cedar `Action::` uids are exact — there is no "
                "glob over action uids. Preserved literally as exact uids "
                "(NOT expanded to the matching action set). REVIEW: the "
                "Cedar policy will NOT match the intended action family.",
                loc,
            )
        )

    return _entity_scope("action", "Action", actions), notes


def _resource_to_cedar(
    stmt: dict[str, Any], loc: str
) -> tuple[str, list[TranslationNote]]:
    notes: list[TranslationNote] = []
    if "NotResource" in stmt:
        notes.append(
            TranslationNote(
                "untranslatable",
                "NotResource",
                "IAM `NotResource` (all resources EXCEPT these) has no "
                "faithful Cedar equivalent (no negated-resource element). "
                "Left unconstrained with a marker — REVIEW before use.",
                loc,
            )
        )
        return "resource  // UNTRANSLATABLE: NotResource — review", notes

    resource = stmt.get("Resource")
    if resource is None:
        # Resource-based policies (e.g. an S3 bucket policy) may omit
        # Resource because the resource is implied. Treat as unconstrained
        # but note it.
        notes.append(
            TranslationNote(
                "info",
                "Resource",
                "No `Resource` (resource-based policy — resource is "
                "implicit). Emitted as unconstrained `resource`.",
                loc,
            )
        )
        return "resource", notes

    resources = [str(r) for r in _as_list(resource)]
    if any(r == "*" for r in resources):
        if len(resources) > 1:
            notes.append(
                TranslationNote(
                    "info",
                    "Resource",
                    "Resource list contains `*` alongside specific ARNs; "
                    "`*` subsumes them. Emitted as unconstrained `resource`.",
                    loc,
                )
            )
        return "resource", notes

    embedded = [r for r in resources if _has_embedded_wildcard(r)]
    if embedded:
        notes.append(
            TranslationNote(
                "lossy",
                "Resource",
                f"Resource ARN(s) {embedded} contain wildcards (e.g. "
                "`arn:aws:s3:::bucket/*`). Cedar `IamResource::` uids are "
                "exact strings — Cedar has no glob over resource uids. "
                "Preserved literally (NOT expanded). REVIEW: the Cedar "
                "policy matches only the literal uid, not the ARN family.",
                loc,
            )
        )

    return _entity_scope("resource", "IamResource", resources), notes


def _entity_scope(element: str, etype: str, values: list[str]) -> str:
    """Build a Cedar scope clause for principal/action/resource.

    One value  -> `element == Type::"v"`
    Many       -> `element in [Type::"a", Type::"b"]`
    """
    if len(values) == 1:
        return f'{element} == {etype}::{_cedar_str(values[0])}'
    refs = ", ".join(f"{etype}::{_cedar_str(v)}" for v in values)
    return f"{element} in [{refs}]"


# Faithful Condition operators -> a Cedar `when` comparison builder.
# Anything not in this map is emitted as a commented UNTRANSLATABLE
# condition with a structured note (never silently dropped).
def _condition_to_cedar(
    condition: Any, loc: str
) -> tuple[list[str], list[TranslationNote]]:
    notes: list[TranslationNote] = []
    if condition is None:
        return [], notes
    if not isinstance(condition, dict):
        raise TranslationError(f"{loc} has a non-object Condition")

    when_exprs: list[str] = []
    untranslatable_ops: list[str] = []

    for op, kv in condition.items():
        if not isinstance(kv, dict):
            raise TranslationError(
                f"{loc} Condition.{op} is not an object"
            )
        if op == "StringEquals":
            for key, val in kv.items():
                vals = _as_list(val)
                ctx = f"context[{_cedar_str(str(key))}]"
                if len(vals) == 1:
                    when_exprs.append(
                        f"{ctx} == {_cedar_str(str(vals[0]))}"
                    )
                else:
                    # IAM gives a LIST of values for a single key OR-style
                    # set membership (the key matches ANY value). Emit Cedar
                    # SET MEMBERSHIP — `["a","b"].contains(context["k"])` —
                    # which preserves the OR semantics. Joining the values
                    # with `&&` equalities would be unsatisfiable (a single
                    # value can't equal two distinct strings), silently
                    # turning a Deny/forbid into a no-op.
                    set_lit = ", ".join(
                        _cedar_str(str(v)) for v in vals
                    )
                    when_exprs.append(f"[{set_lit}].contains({ctx})")
        elif op == "Bool":
            for key, val in kv.items():
                for v in _as_list(val):
                    bv = str(v).lower() in ("true", "1")
                    when_exprs.append(
                        f'context[{_cedar_str(str(key))}] == {str(bv).lower()}'
                    )
        else:
            untranslatable_ops.append(op)

    when_clauses: list[str] = []
    if when_exprs:
        body = " &&\n        ".join(when_exprs)
        when_clauses.append(f"when {{\n        {body}\n    }}")

    for op in untranslatable_ops:
        notes.append(
            TranslationNote(
                "untranslatable",
                f"Condition.{op}",
                f"IAM condition operator `{op}` is outside the faithful "
                "translation subset (only StringEquals and Bool map 1:1). "
                "Operators like StringLike/DateGreaterThan/IpAddress/ArnLike/"
                "Null use IAM-specific matching (globs, ARN structure, CIDR, "
                "key-presence) with no exact Cedar equivalent. Emitted as a "
                "marker — translate by hand against Cedar `context`.",
                loc,
            )
        )
        when_clauses.append(
            f"// UNTRANSLATABLE: Condition.{op} — translate by hand "
            f"(no faithful Cedar equivalent)"
        )

    return when_clauses, notes


# ===========================================================================
# Cedar  ->  IAM   (best-effort; inverts the faithful subset)
# ===========================================================================

# We parse a deliberately RESTRICTED Cedar subset — exactly the shape
# `iam_to_cedar` emits, plus common hand-written variants. Anything
# outside that subset is surfaced as a note (and, where its meaning
# can't be safely guessed, the affected scope/statement is flagged
# rather than silently approximated). We do NOT ship a full Cedar
# grammar; that would be a false promise of fidelity.

_COMMENT_RE = re.compile(r"//[^\n]*")
_ENTITY_RE = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)::"((?:[^"\\]|\\.)*)"')


def _strip_comments(text: str) -> str:
    return _COMMENT_RE.sub("", text)


def _unescape_cedar_str(s: str) -> str:
    return (
        s.replace('\\"', '"')
        .replace("\\n", "\n")
        .replace("\\t", "\t")
        .replace("\\r", "\r")
        .replace("\\\\", "\\")
    )


def cedar_to_iam(cedar_text: str) -> TranslationResult:
    """Translate Cedar policy text to a best-effort AWS IAM policy.

    Inverts the faithful subset produced by :func:`iam_to_cedar`. Cedar
    constructs with no IAM equivalent (entity attribute references, `is`
    type tests, set/`like` operators) are surfaced as notes and the
    affected statement is flagged rather than silently approximated.

    Raises :class:`TranslationError` only when the text cannot be parsed
    as Cedar policies at all.
    """
    if not isinstance(cedar_text, str):
        raise TranslationError("Cedar input must be a string")

    # Detect untranslatable markers the forward direction may have left.
    marker_notes: list[TranslationNote] = []
    for m in re.finditer(r"//\s*(UNTRANSLATABLE|NOTE):[^\n]*", cedar_text):
        marker_notes.append(
            TranslationNote(
                "untranslatable" if "UNTRANSLATABLE" in m.group(0) else "info",
                "marker",
                "Input carries a translation marker from a prior "
                f"translation: {m.group(0).strip()}",
            )
        )

    body = _strip_comments(cedar_text).strip()
    if not body:
        raise TranslationError(
            "no Cedar policy statements found (input was empty or "
            "comments-only)"
        )

    # Split into statements on the policy terminator `;` at top level.
    # The faithful subset has no nested `;`, so a simple split is safe
    # for that subset; reject anything with unbalanced braces.
    raw_stmts = [s.strip() for s in body.split(";") if s.strip()]
    if not raw_stmts:
        raise TranslationError("no Cedar policy statements found")

    notes: list[TranslationNote] = list(marker_notes)
    iam_statements: list[dict[str, Any]] = []

    for i, raw in enumerate(raw_stmts):
        loc = f"policy[{i}]"
        stmt, stmt_notes = _cedar_stmt_to_iam(raw, loc)
        notes.extend(stmt_notes)
        if stmt is not None:
            iam_statements.append(stmt)

    if not iam_statements:
        raise TranslationError(
            "no translatable Cedar `permit`/`forbid` statements found"
        )

    policy = {"Version": "2012-10-17", "Statement": iam_statements}
    return TranslationResult(
        direction="cedar->iam",
        output=json.dumps(policy, indent=2),
        notes=notes,
        policy=policy,
    )


def _cedar_stmt_to_iam(
    raw: str, loc: str
) -> tuple[dict[str, Any] | None, list[TranslationNote]]:
    notes: list[TranslationNote] = []

    m = re.match(r"^(permit|forbid)\b", raw)
    if not m:
        # Cedar allows annotations (@id("...")) before the effect.
        m2 = re.match(r"^(?:@[A-Za-z_][\w]*\([^)]*\)\s*)+(permit|forbid)\b", raw)
        if m2:
            effect_kw = m2.group(1)
            raw = raw[raw.index(effect_kw):]
        else:
            raise TranslationError(
                f"{loc} does not start with `permit` or `forbid` "
                f"(got: {raw[:40]!r})"
            )
    effect_kw = re.match(r"^(permit|forbid)\b", raw).group(1)
    effect = "Allow" if effect_kw == "permit" else "Deny"

    # Scope is the parenthesised head: permit ( <scope> ) [when {...}].
    head_match = re.search(r"\(", raw)
    if not head_match:
        raise TranslationError(f"{loc} has no `( ... )` scope head")
    # Find matching close paren for the scope.
    depth = 0
    start = head_match.start()
    end = -1
    for j in range(start, len(raw)):
        if raw[j] == "(":
            depth += 1
        elif raw[j] == ")":
            depth -= 1
            if depth == 0:
                end = j
                break
    if end < 0:
        raise TranslationError(f"{loc} has an unbalanced scope `(`")
    scope = raw[start + 1 : end]
    tail = raw[end + 1 :].strip()  # when/unless clauses

    stmt: dict[str, Any] = {"Effect": effect}

    # Parse the three comma-separated scope clauses. Cedar's grammar puts
    # principal, action, resource in that order; each may be:
    #   principal                      (unconstrained)
    #   principal == Type::"uid"
    #   principal in [Type::"a", ...]
    clauses = _split_top_level(scope, ",")
    for clause in clauses:
        clause = clause.strip()
        if not clause:
            continue
        c_notes = _parse_scope_clause(clause, stmt, loc)
        notes.extend(c_notes)

    # Defaults: an unconstrained element in Cedar == "any" => IAM "*".
    stmt.setdefault("Action", "*")
    stmt.setdefault("Resource", "*")

    # --- when / unless ----------------------------------------------
    if tail:
        t_notes = _parse_cedar_tail(tail, stmt, loc)
        notes.extend(t_notes)

    return stmt, notes


def _split_top_level(s: str, sep: str) -> list[str]:
    """Split `s` on `sep` ignoring separators inside [] or "" ."""
    out: list[str] = []
    buf: list[str] = []
    depth = 0
    in_str = False
    esc = False
    for ch in s:
        if in_str:
            buf.append(ch)
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
            continue
        if ch == '"':
            in_str = True
            buf.append(ch)
        elif ch in "[(":
            depth += 1
            buf.append(ch)
        elif ch in "])":
            depth -= 1
            buf.append(ch)
        elif ch == sep and depth == 0:
            out.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    if buf:
        out.append("".join(buf))
    return out


def _parse_scope_clause(
    clause: str, stmt: dict[str, Any], loc: str
) -> list[TranslationNote]:
    notes: list[TranslationNote] = []
    head = re.match(r"^(principal|action|resource)\b", clause)
    if not head:
        raise TranslationError(
            f"{loc} scope clause does not start with principal/action/"
            f"resource: {clause[:40]!r}"
        )
    element = head.group(1)
    rest = clause[head.end():].strip()

    if not rest:
        # Unconstrained. principal => no Principal key (identity policy
        # default); action/resource handled by setdefault("*") later.
        if element == "principal":
            notes.append(
                TranslationNote(
                    "info",
                    "principal",
                    "Unconstrained Cedar `principal` — emitted with no "
                    "IAM `Principal` (identity-based reading).",
                    loc,
                )
            )
        return notes

    if rest.startswith("=="):
        ref = rest[2:].strip()
        em = _ENTITY_RE.match(ref)
        if not em:
            # `principal == ?principal` (slot) or an attribute expr.
            notes.append(
                TranslationNote(
                    "untranslatable",
                    element,
                    f"Cedar `{element} == {ref[:40]}` is not a concrete "
                    "entity uid (template slot or expression). No faithful "
                    "IAM equivalent — flagged; element left as `*`.",
                    loc,
                )
            )
            _assign_iam_scope(element, "*", stmt)
            return notes
        uid = _unescape_cedar_str(em.group(2))
        _assign_iam_scope(element, uid, stmt)
    elif rest.startswith("in"):
        after = rest[2:].strip()
        if after.startswith("["):
            inner = after[1: after.rindex("]")] if "]" in after else after[1:]
            uids = [
                _unescape_cedar_str(em.group(2))
                for em in _ENTITY_RE.finditer(inner)
            ]
            if not uids:
                notes.append(
                    TranslationNote(
                        "untranslatable",
                        element,
                        f"Cedar `{element} in [...]` had no concrete entity "
                        "uids (slots/exprs). Flagged; element left as `*`.",
                        loc,
                    )
                )
                _assign_iam_scope(element, "*", stmt)
            else:
                _assign_iam_scope(element, uids, stmt)
        else:
            em = _ENTITY_RE.match(after)
            if em:
                # `principal in Group::"x"` — hierarchy membership; IAM has
                # no group-of-resources concept here. Best-effort: treat as
                # the single uid but flag.
                uid = _unescape_cedar_str(em.group(2))
                notes.append(
                    TranslationNote(
                        "lossy",
                        element,
                        f"Cedar `{element} in {em.group(1)}::\"{uid}\"` is a "
                        "hierarchy-membership test (the element is a MEMBER "
                        "of this entity). IAM has no equivalent grouping; "
                        "emitted the uid literally — REVIEW.",
                        loc,
                    )
                )
                _assign_iam_scope(element, uid, stmt)
            else:
                notes.append(
                    TranslationNote(
                        "untranslatable",
                        element,
                        f"Cedar `{element} in {after[:40]}` is not a "
                        "concrete entity reference. Flagged; left as `*`.",
                        loc,
                    )
                )
                _assign_iam_scope(element, "*", stmt)
    elif rest.startswith("is"):
        notes.append(
            TranslationNote(
                "untranslatable",
                element,
                f"Cedar `{element} is <Type>` (entity-type test) has no IAM "
                "equivalent. Flagged; element left as `*` — REVIEW.",
                loc,
            )
        )
        _assign_iam_scope(element, "*", stmt)
    else:
        raise TranslationError(
            f"{loc} unrecognized {element} operator in {clause[:50]!r}"
        )
    return notes


def _assign_iam_scope(
    element: str, value: str | list[str], stmt: dict[str, Any]
) -> None:
    """Map a Cedar element to its IAM key.

    principal -> Principal (resource-based) ; action -> Action ;
    resource -> Resource. A `"*"` value for principal means "any
    principal" => Principal: "*".
    """
    if element == "principal":
        if value == "*":
            stmt["Principal"] = "*"
        else:
            stmt["Principal"] = {"AWS": value}
    elif element == "action":
        stmt["Action"] = value
    elif element == "resource":
        stmt["Resource"] = value


def _parse_cedar_tail(
    tail: str, stmt: dict[str, Any], loc: str
) -> list[TranslationNote]:
    """Parse trailing `when { ... }` / `unless { ... }` clauses.

    Only the faithful inverse is reconstructed (`context["k"] == "v"`
    -> StringEquals ; `context["k"] == true` -> Bool). Everything else
    is surfaced as a note; `unless` is always flagged (IAM has no
    negated-condition form that round-trips)."""
    notes: list[TranslationNote] = []
    conditions: dict[str, dict[str, Any]] = {}

    for kw, brace_body in _iter_clauses(tail):
        if kw == "unless":
            notes.append(
                TranslationNote(
                    "untranslatable",
                    "unless",
                    "Cedar `unless { ... }` (negated condition) has no "
                    "faithful IAM equivalent — IAM conditions are positive "
                    "match constraints. Flagged; the negated condition was "
                    "NOT translated. REVIEW before use.",
                    loc,
                )
            )
            continue
        # when { ... } : parse `context["k"] == <literal>` exprs.
        exprs = _split_top_level(brace_body, "&")
        # `&&` splitting: collapse empties from the double-&.
        for e in exprs:
            e = e.strip().strip("&").strip()
            if not e:
                continue
            # Set-membership form emitted by the forward direction for a
            # multi-value StringEquals: `["a","b"].contains(context["k"])`.
            # Parse it back to the full IAM value LIST (never last-wins drop).
            setm = re.match(
                r'\[\s*(.*?)\s*\]\s*\.\s*contains\(\s*'
                r'context\[\s*"((?:[^"\\]|\\.)*)"\s*\]\s*\)$',
                e,
            )
            if setm:
                key = _unescape_cedar_str(setm.group(2))
                str_lits = re.findall(
                    r'"((?:[^"\\]|\\.)*)"', setm.group(1)
                )
                if str_lits:
                    values = [_unescape_cedar_str(s) for s in str_lits]
                    se = conditions.setdefault("StringEquals", {})
                    se[key] = (
                        values[0] if len(values) == 1 else values
                    )
                    continue
                notes.append(
                    TranslationNote(
                        "untranslatable",
                        "when",
                        f"Cedar set-membership `{e[:50]}` for key `{key}` "
                        "has no string-literal members — no faithful IAM "
                        "StringEquals mapping. NOT translated.",
                        loc,
                    )
                )
                continue
            cm = re.match(
                r'context\[\s*"((?:[^"\\]|\\.)*)"\s*\]\s*==\s*(.+)$', e
            )
            if not cm:
                notes.append(
                    TranslationNote(
                        "untranslatable",
                        "when",
                        f"Cedar `when` sub-expression `{e[:50]}` is outside "
                        "the faithful subset (only `context[\"k\"] == "
                        "<string|bool>` maps to IAM StringEquals/Bool). "
                        "Entity-attribute refs (resource.owner == "
                        "principal), set/`like` ops, arithmetic — no IAM "
                        "equivalent. NOT translated; REVIEW.",
                        loc,
                    )
                )
                continue
            key = _unescape_cedar_str(cm.group(1))
            rhs = cm.group(2).strip()
            sm = re.match(r'^"((?:[^"\\]|\\.)*)"$', rhs)
            if sm:
                # Accumulate repeated same-key equalities into a value list
                # rather than last-wins-dropping the earlier value(s).
                se = conditions.setdefault("StringEquals", {})
                val = _unescape_cedar_str(sm.group(1))
                if key in se:
                    existing = se[key]
                    if not isinstance(existing, list):
                        existing = [existing]
                    if val not in existing:
                        existing.append(val)
                    se[key] = existing
                else:
                    se[key] = val
            elif rhs in ("true", "false"):
                conditions.setdefault("Bool", {})[key] = rhs
            else:
                notes.append(
                    TranslationNote(
                        "untranslatable",
                        "when",
                        f"Cedar condition RHS `{rhs[:40]}` for key `{key}` "
                        "is not a string or boolean literal — no faithful "
                        "IAM StringEquals/Bool mapping. NOT translated.",
                        loc,
                    )
                )

    if conditions:
        stmt["Condition"] = conditions
    return notes


def _iter_clauses(tail: str):
    """Yield (keyword, brace_body) for each when/unless clause in `tail`."""
    i = 0
    n = len(tail)
    while i < n:
        m = re.compile(r"(when|unless)\s*\{").search(tail, i)
        if not m:
            break
        kw = m.group(1)
        # Find matching close brace.
        depth = 0
        body_start = m.end()  # just after `{`
        j = m.end() - 1  # at the `{`
        while j < n:
            if tail[j] == "{":
                depth += 1
            elif tail[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        if j >= n:
            raise TranslationError("unbalanced `{` in when/unless clause")
        yield kw, tail[body_start:j]
        i = j + 1
