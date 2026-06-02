"""
silent_degradation_linter.lint
==============================

AST + grep-based linter that detects silent-degradation patterns.

Rules shipped in v1:
  SD-1  bare ``except: pass`` / ``except Exception: pass`` (no log, no re-raise)
  SD-2  function parameter declared but never referenced in body
  SD-4  ``return <positive>`` inside an ``except`` block

SD-3 / SD-5 deferred (follow-up tasks #623 / #624).

Suppression:
  inline  ``# noqa: SD-1 <human reason>`` on the offending line
  file    ``.silent_degradation_ignore`` in repo root — paths / globs with optional reason
"""

from __future__ import annotations

import ast
import fnmatch
import hashlib
import json
import re
import tokenize
import io
from collections import Counter
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Sequence


# Number of source lines of context captured on each side of the matched
# line to build the stable content signature.  Small enough to stay specific
# to the finding, large enough to disambiguate otherwise-identical matched
# lines that live in genuinely different surrounding code.
_CONTEXT_RADIUS = 2

# Baseline schema version.  v1 = line-keyed (legacy); v2 = content-keyed.
BASELINE_SCHEMA = 2


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

def _normalize_code(text: str) -> str:
    """Collapse all runs of whitespace to a single space and strip.

    Makes the signature insensitive to indentation / reflow / trailing
    whitespace so a re-indented or re-wrapped (but textually identical)
    finding maps to the same signature.
    """
    return re.sub(r"\s+", " ", text).strip()


# Sentinel scope for findings that have no enclosing function/class (i.e. live
# at module level).  Stable string so module-level findings still hash
# deterministically; they're rare and the path+context still distinguishes most.
_MODULE_SCOPE = "<module>"


@dataclass
class Finding:
    rule: str          # e.g. "SD-1"
    path: str          # relative or absolute path
    line: int          # 1-based line of the matched node (informational only)
    col: int
    message: str
    snippet: str = ""  # matched source line text (stripped) — informational
    context: str = ""  # normalized context window — part of the content key
    scope: str = _MODULE_SCOPE  # enclosing def/class qualified name — part of key

    def signature(self) -> str:
        """Content/context signature for this finding.

        Stable across line-number shifts (the raw line number is NOT part of
        the signature), yet specific to the *code* that produced the finding:
        the rule, the file path, the qualified name of the nearest enclosing
        function/class (so the SAME boilerplate in DIFFERENT functions is
        DISTINCT), the human message (which encodes the load-bearing identity
        such as the SD-2 parameter name), and a whitespace-normalized window of
        surrounding source.

        A finding that merely moves down the file (within the same enclosing
        scope) keeps the same signature.  A genuinely-new pattern in
        new/changed code — including byte-identical boilerplate in a *different*
        function — produces a new signature.  The enclosing scope is what
        defeats slot-freeing: deleting one occurrence of a high-count baselined
        signature and adding a new identical swallow in another function no
        longer collides, because the two live in different scopes.
        """
        material = "\x1f".join((
            self.rule,
            self.path,
            self.scope,
            _normalize_code(self.message),
            self.context,
        ))
        digest = hashlib.sha256(material.encode("utf-8")).hexdigest()[:16]
        return f"{self.rule}:{self.path}:{digest}"

    # Backwards-compatible alias.  Historically ``key()`` returned the
    # line-keyed identity; it now returns the content signature so any
    # remaining callers transparently get the stable key.
    def key(self) -> str:
        return self.signature()

    def as_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Helpers: noqa comment parsing
# ---------------------------------------------------------------------------

_NOQA_RE = re.compile(r"#\s*noqa:\s*(SD-\d+)", re.IGNORECASE)


def _has_noqa(line_text: str, rule: str) -> bool:
    """Return True if the source line suppresses *rule* via noqa comment."""
    m = _NOQA_RE.search(line_text)
    if m and m.group(1).upper() == rule.upper():
        return True
    return False


def _source_lines(source: str) -> list[str]:
    return source.splitlines()


def _build_context(lines: list[str], lineno: int, radius: int = _CONTEXT_RADIUS) -> str:
    """Return a whitespace-normalized window of code around *lineno* (1-based).

    The window spans ``[lineno - radius, lineno + radius]`` clamped to the
    file.  Each line is whitespace-normalized and the lines are joined with a
    newline so the signature reflects the *code shape* around the finding,
    not its absolute position.  Blank/normalized-empty lines are dropped so
    that inserting blank lines above a finding (the canonical line-shift case)
    does not perturb the signature.
    """
    start = max(0, lineno - 1 - radius)
    end = min(len(lines), lineno + radius)
    window = [_normalize_code(lines[i]) for i in range(start, end)]
    window = [w for w in window if w]
    return "\n".join(window)


# ---------------------------------------------------------------------------
# Helpers: enclosing-scope (qualified def/class name) resolution
# ---------------------------------------------------------------------------

_SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)


def _build_scope_map(tree: ast.AST, total_lines: int) -> dict[int, str]:
    """Map every 1-based source line to the qualified name of its nearest
    enclosing function/class.

    Lines not inside any def/class map to ``_MODULE_SCOPE``.  Qualified names
    nest with ``.`` (e.g. ``MyClass.my_method``).  When scopes nest, the
    INNERMOST (longest end-line, smallest span) wins — we resolve this by
    assigning each line the qualified name of the deepest scope whose body
    spans it, processing outer-to-inner so inner assignments overwrite outer.

    A finding's scope is therefore the name of the function/class it physically
    lives inside, which makes byte-identical boilerplate in two different
    functions hash to two different signatures.
    """
    line_to_scope: dict[int, str] = {}

    def walk(node: ast.AST, prefix: str) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, _SCOPE_NODES):
                qual = f"{prefix}.{child.name}" if prefix else child.name
                start = getattr(child, "lineno", None)
                end = getattr(child, "end_lineno", None)
                if start is not None:
                    if end is None:
                        end = start
                    # Assign this scope to every line it spans; because we
                    # recurse AFTER assigning, the inner (deeper) scope's
                    # assignment overwrites the outer one for shared lines.
                    for ln in range(start, min(end, total_lines) + 1):
                        line_to_scope[ln] = qual
                    walk(child, qual)
            else:
                walk(child, prefix)

    walk(tree, "")
    return line_to_scope


def _scope_for_line(scope_map: dict[int, str], lineno: int) -> str:
    return scope_map.get(lineno, _MODULE_SCOPE)


# ---------------------------------------------------------------------------
# Helpers: locate comment tokens (for SD-2 noqa on the def line)
# ---------------------------------------------------------------------------

def _collect_noqa_lines(source: str, rule: str) -> set[int]:
    """Return set of 1-based line numbers suppressing *rule*."""
    suppressed: set[int] = set()
    lines = _source_lines(source)
    for lineno_0, line in enumerate(lines):
        if _has_noqa(line, rule):
            suppressed.add(lineno_0 + 1)
    return suppressed


# ---------------------------------------------------------------------------
# Rule SD-1: bare except: pass
# ---------------------------------------------------------------------------

_POSITIVE_CONSTANTS: frozenset = frozenset({True, None, "ok", "OK", "success",
                                             "done", "created", "accepted"})


class SD1Visitor(ast.NodeVisitor):
    """Detect except handlers whose entire body is a single ``pass``."""

    def __init__(self, lines: list[str]) -> None:
        self.lines = lines
        self.findings: list[tuple[int, int, str]] = []  # line, col, msg

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        body = node.body
        # Body is purely [Pass] — no log, no raise, nothing
        if len(body) == 1 and isinstance(body[0], ast.Pass):
            exc_type = _exc_type_str(node)
            msg = f"SD-1: bare except-pass swallows {exc_type} silently"
            self.findings.append((node.lineno, node.col_offset, msg))
        self.generic_visit(node)


def _exc_type_str(handler: ast.ExceptHandler) -> str:
    if handler.type is None:
        return "all exceptions"
    return ast.unparse(handler.type)


# ---------------------------------------------------------------------------
# Rule SD-2: ignored function parameters
# ---------------------------------------------------------------------------

class SD2Visitor(ast.NodeVisitor):
    """
    Detect named parameters declared in a function signature that are never
    referenced anywhere in the function body.

    Opt-outs:
      - ``_`` prefix → skip (conventional "unused" marker)
      - ``**kw``-style  → skip (kwargs catch-all)
      - ``*args``-style → skip
      - ``# noqa: SD-2`` on the ``def`` line
    """

    def __init__(self, lines: list[str]) -> None:
        self.lines = lines
        self.findings: list[tuple[int, int, str]] = []

    def _all_names_in_body(self, body: list[ast.stmt]) -> set[str]:
        names: set[str] = set()
        for stmt in body:
            for node in ast.walk(stmt):
                if isinstance(node, ast.Name):
                    names.add(node.id)
                elif isinstance(node, ast.Attribute):
                    # capture ``self.x`` → only bare name side matters for params
                    if isinstance(node.value, ast.Name):
                        names.add(node.value.id)
        return names

    @staticmethod
    def _is_stub_body(body: list[ast.stmt]) -> bool:
        """Return True if the function body is a stub (``...``, ``pass``, docstring only, or raise NotImplementedError)."""
        if not body:
            return True
        # Single ellipsis: def f(...): ...
        if len(body) == 1:
            stmt = body[0]
            if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant):
                return stmt.value.value is ...
            if isinstance(stmt, ast.Pass):
                return True
            # raise NotImplementedError(...)
            if isinstance(stmt, ast.Raise):
                exc = stmt.exc
                if exc is None:
                    return True
                if isinstance(exc, ast.Call) and isinstance(exc.func, ast.Name):
                    return exc.func.id in ("NotImplementedError", "AbstractMethodError")
                if isinstance(exc, ast.Name):
                    return exc.id in ("NotImplementedError",)
        # Docstring + ellipsis / pass
        if len(body) == 2:
            first = body[0]
            second = body[1]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
                if isinstance(second, ast.Expr) and isinstance(second.value, ast.Constant) and second.value.value is ...:
                    return True
                if isinstance(second, ast.Pass):
                    return True
        return False

    @staticmethod
    def _has_abstractmethod(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        for dec in node.decorator_list:
            if isinstance(dec, ast.Name) and dec.id in ("abstractmethod", "overload"):
                return True
            if isinstance(dec, ast.Attribute) and dec.attr in ("abstractmethod", "overload"):
                return True
        return False

    def _check_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        def_line = self.lines[node.lineno - 1] if node.lineno <= len(self.lines) else ""
        if _has_noqa(def_line, "SD-2"):
            self.generic_visit(node)
            return

        # Skip stub / abstract / protocol methods — they intentionally don't use params
        if self._is_stub_body(node.body):
            self.generic_visit(node)
            return
        if self._has_abstractmethod(node):
            self.generic_visit(node)
            return

        args = node.args
        # Collect all explicit positional / keyword-only params (not *args / **kwargs)
        param_nodes: list[ast.arg] = (
            args.args
            + args.posonlyargs
            + args.kwonlyargs
        )

        used = self._all_names_in_body(node.body)

        for arg in param_nodes:
            name = arg.arg
            if name == "self" or name == "cls":
                continue
            if name.startswith("_"):
                continue  # conventional unused marker
            if name not in used:
                msg = (
                    f"SD-2: parameter '{name}' declared in "
                    f"'{node.name}' but never used in body"
                )
                self.findings.append((arg.lineno, arg.col_offset, msg))

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_function(node)
        self.generic_visit(node)


# ---------------------------------------------------------------------------
# Rule SD-4: return <positive> inside except block
# ---------------------------------------------------------------------------

_POSITIVE_DICT_STATUS = frozenset({"ok", "OK", "success", "done",
                                    "created", "accepted", "200"})


def _is_positive_value(node: ast.expr | None) -> bool:
    """
    Return True if the AST expression looks like a success/positive return:
      - True
      - None  (implicit success in many APIs)
      - a string constant in _POSITIVE_CONSTANTS
      - a dict with key 'status' mapped to a positive string
      - a dict with key 'ok' / 'success' mapped to True
    """
    if node is None:
        return True  # bare return (returns None)
    if isinstance(node, ast.Constant):
        return node.value in _POSITIVE_CONSTANTS
    if isinstance(node, ast.Dict):
        for k, v in zip(node.keys, node.values):
            if isinstance(k, ast.Constant):
                if k.value == "status" and isinstance(v, ast.Constant):
                    return str(v.value).lower() in {s.lower() for s in _POSITIVE_DICT_STATUS}
                if k.value in {"ok", "success"} and isinstance(v, ast.Constant) and v.value is True:
                    return True
    return False


class SD4Visitor(ast.NodeVisitor):
    """Detect positive-return inside an except handler body."""

    def __init__(self, lines: list[str]) -> None:
        self.lines = lines
        self.findings: list[tuple[int, int, str]] = []

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        # Walk the handler body looking for Return nodes
        for child in ast.walk(ast.Module(body=node.body, type_ignores=[])):
            if isinstance(child, ast.Return):
                ret_line = self.lines[child.lineno - 1] if child.lineno <= len(self.lines) else ""
                if _has_noqa(ret_line, "SD-4"):
                    continue
                if _is_positive_value(child.value):
                    val_repr = ast.unparse(child.value) if child.value else "None"
                    exc_type = _exc_type_str(node)
                    msg = (
                        f"SD-4: positive return ({val_repr}) inside except "
                        f"handler for {exc_type} — caller cannot distinguish "
                        f"failure from success"
                    )
                    self.findings.append((child.lineno, child.col_offset, msg))
        self.generic_visit(node)


# ---------------------------------------------------------------------------
# Ignore-file loading
# ---------------------------------------------------------------------------

def _load_ignore_patterns(repo_root: Path) -> list[str]:
    ignore_file = repo_root / ".silent_degradation_ignore"
    if not ignore_file.exists():
        return []
    patterns: list[str] = []
    for raw in ignore_file.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        # strip inline reason after whitespace
        pattern = line.split()[0]
        patterns.append(pattern)
    return patterns


def _is_ignored(path: Path, patterns: list[str], repo_root: Path) -> bool:
    rel = str(path.relative_to(repo_root)) if path.is_absolute() else str(path)
    for pat in patterns:
        if fnmatch.fnmatch(rel, pat):
            return True
        if fnmatch.fnmatch(path.name, pat):
            return True
    return False


# ---------------------------------------------------------------------------
# Per-file scan
# ---------------------------------------------------------------------------

def scan_file(
    path: Path,
    repo_root: Path,
    ignore_patterns: list[str],
    rules: Sequence[str] = ("SD-1", "SD-2", "SD-4"),
) -> list[Finding]:
    if _is_ignored(path, ignore_patterns, repo_root):
        return []

    try:
        source = path.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(source, filename=str(path))
    except SyntaxError:
        return []

    lines = _source_lines(source)
    rel_path = str(path.relative_to(repo_root)) if path.is_absolute() else str(path)
    scope_map = _build_scope_map(tree, len(lines))

    findings: list[Finding] = []

    if "SD-1" in rules:
        v = SD1Visitor(lines)
        v.visit(tree)
        for lineno, col, msg in v.findings:
            line_text = lines[lineno - 1].strip() if lineno <= len(lines) else ""
            if _has_noqa(lines[lineno - 1] if lineno <= len(lines) else "", "SD-1"):
                continue
            ctx = _build_context(lines, lineno)
            scope = _scope_for_line(scope_map, lineno)
            findings.append(Finding("SD-1", rel_path, lineno, col, msg, line_text, ctx, scope))

    if "SD-2" in rules:
        v2 = SD2Visitor(lines)
        v2.visit(tree)
        for lineno, col, msg in v2.findings:
            line_text = lines[lineno - 1].strip() if lineno <= len(lines) else ""
            if _has_noqa(lines[lineno - 1] if lineno <= len(lines) else "", "SD-2"):
                continue
            ctx = _build_context(lines, lineno)
            scope = _scope_for_line(scope_map, lineno)
            findings.append(Finding("SD-2", rel_path, lineno, col, msg, line_text, ctx, scope))

    if "SD-4" in rules:
        v4 = SD4Visitor(lines)
        v4.visit(tree)
        for lineno, col, msg in v4.findings:
            # noqa already checked inside SD4Visitor per-return-line
            line_text = lines[lineno - 1].strip() if lineno <= len(lines) else ""
            ctx = _build_context(lines, lineno)
            scope = _scope_for_line(scope_map, lineno)
            findings.append(Finding("SD-4", rel_path, lineno, col, msg, line_text, ctx, scope))

    return findings


# ---------------------------------------------------------------------------
# Directory scan
# ---------------------------------------------------------------------------

DEFAULT_SCAN_PATHS = ("src/iam_jit", "tests")


def scan_paths(
    paths: Sequence[str | Path],
    repo_root: Path,
    rules: Sequence[str] = ("SD-1", "SD-2", "SD-4"),
) -> list[Finding]:
    ignore_patterns = _load_ignore_patterns(repo_root)
    all_findings: list[Finding] = []

    for scan_path in paths:
        p = Path(scan_path)
        if not p.is_absolute():
            p = repo_root / p
        if p.is_file() and p.suffix == ".py":
            all_findings.extend(scan_file(p, repo_root, ignore_patterns, rules))
        elif p.is_dir():
            for py_file in sorted(p.rglob("*.py")):
                all_findings.extend(scan_file(py_file, repo_root, ignore_patterns, rules))

    return all_findings


# ---------------------------------------------------------------------------
# Baseline support
# ---------------------------------------------------------------------------

# Sentinel meaning "the baseline file did not exist". Distinct from an empty
# baseline (a real baseline that pins zero findings) so a missing file does not
# silently turn every finding into "new".
_MISSING_BASELINE = object()


def _is_legacy_baseline(data: dict) -> bool:
    """A v1 (line-keyed) baseline stores ``findings`` as a flat list of
    ``RULE:path:LINE`` strings and has no ``schema`` field (or schema < 2)."""
    if int(data.get("schema", 1)) >= 2:
        return False
    findings = data.get("findings")
    return isinstance(findings, list)


def load_baseline(baseline_path: Path) -> Counter | object:
    """Return a multiset (``Counter``) of content signatures from a baseline.

    Returns the ``_MISSING_BASELINE`` sentinel if the file does not exist.

    Supports both schemas:
      * v2 (content-keyed): ``{"schema": 2, "findings": {signature: count}}``
      * v1 (legacy line-keyed): ``{"findings": ["RULE:path:LINE", ...]}`` —
        loaded as a best-effort fallback so an un-migrated tree still runs,
        but note that v1 keys will NOT match v2 signatures.  The expected
        path is to migrate via ``--baseline-update``.
    """
    if not baseline_path.exists():
        return _MISSING_BASELINE
    data = json.loads(baseline_path.read_text())

    if _is_legacy_baseline(data):
        # Legacy line-keyed baseline: keep the raw keys as a degenerate
        # multiset. These will not match the new content signatures, which is
        # intentional — a v1 baseline must be regenerated with the v2 schema.
        return Counter(data.get("findings", []))

    findings = data.get("findings", {})
    counter: Counter = Counter()
    for sig, count in findings.items():
        counter[sig] = int(count)
    return counter


def baseline_counts(findings: list[Finding]) -> Counter:
    """Multiset of content signatures for *findings*."""
    return Counter(f.signature() for f in findings)


def save_baseline(baseline_path: Path, findings: list[Finding]) -> None:
    """Write the content-keyed (v2) baseline.

    The baseline pins a *multiset* of content signatures: each signature maps
    to the number of times that exact finding occurs in the tree.  Recording
    the count is what lets the ratchet detect "a NEW identical finding was
    added" (count goes up) while tolerating line-number shifts (count stays
    the same, signature unchanged).
    """
    counts = baseline_counts(findings)
    # Sorted for stable diffs.
    ordered = {sig: counts[sig] for sig in sorted(counts)}
    baseline_path.write_text(
        json.dumps(
            {"schema": BASELINE_SCHEMA, "findings": ordered, "count": sum(counts.values())},
            indent=2,
        )
        + "\n"
    )


def new_findings(findings: list[Finding], baseline: Counter | object) -> list[Finding]:
    """Return the findings that exceed what the baseline pins.

    Multiset semantics: for each content signature, the baseline allows up to
    ``baseline[sig]`` occurrences.  If the current tree has more occurrences of
    that signature than the baseline pins, the surplus occurrences are
    reported as NEW.  This is the property that:

      * a line-shifted existing finding is NOT new (same signature, count
        unchanged);
      * a genuinely-new pattern in new/changed code IS new (signature absent
        from the baseline, surplus = its full count);
      * adding a SECOND copy of an already-baselined finding IS new (count
        exceeds the pinned count);
      * removing one of two identical findings is tolerated (count drops; the
        ratchet only fails on *new* debt, never on debt reduction).

    A ``_MISSING_BASELINE`` sentinel (no baseline file) means "nothing is
    pinned" → every finding is new.
    """
    if baseline is _MISSING_BASELINE:
        return list(findings)

    allowed = Counter(baseline)  # copy we can decrement
    surplus: list[Finding] = []
    # Process deterministically (by line) so which occurrence is reported as
    # "new" is stable across runs.
    for f in sorted(findings, key=lambda x: (x.path, x.line, x.col)):
        sig = f.signature()
        if allowed.get(sig, 0) > 0:
            allowed[sig] -= 1  # consume one pinned slot
        else:
            surplus.append(f)
    return surplus


# ---------------------------------------------------------------------------
# Formatters
# ---------------------------------------------------------------------------

def _format_pretty(findings: list[Finding]) -> str:
    if not findings:
        return "silent-degradation-linter: no findings.\n"
    lines = ["silent-degradation-linter findings:\n"]
    by_rule: dict[str, list[Finding]] = {}
    for f in findings:
        by_rule.setdefault(f.rule, []).append(f)
    for rule in sorted(by_rule):
        lines.append(f"  [{rule}]")
        for f in by_rule[rule]:
            lines.append(f"    {f.path}:{f.line}:{f.col}  {f.message}")
            if f.snippet:
                lines.append(f"      | {f.snippet}")
    lines.append(f"\n{len(findings)} finding(s) total.")
    return "\n".join(lines) + "\n"


def _format_json(findings: list[Finding]) -> str:
    return json.dumps([f.as_dict() for f in findings], indent=2) + "\n"


def _format_github(findings: list[Finding]) -> str:
    """GitHub Actions annotation format."""
    lines = []
    for f in findings:
        # ::error file=path,line=N,col=N::message
        lines.append(
            f"::error file={f.path},line={f.line},col={f.col}::{f.rule}: {f.message}"
        )
    return "\n".join(lines) + ("\n" if lines else "")


def format_findings(findings: list[Finding], fmt: str = "pretty") -> str:
    if fmt == "json":
        return _format_json(findings)
    if fmt == "github":
        return _format_github(findings)
    return _format_pretty(findings)
