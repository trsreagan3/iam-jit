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
import json
import re
import tokenize
import io
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Sequence


# ---------------------------------------------------------------------------
# Data types
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    rule: str          # e.g. "SD-1"
    path: str          # relative or absolute path
    line: int
    col: int
    message: str
    snippet: str = ""  # source line text (stripped)

    def key(self) -> str:
        """Stable key for baseline matching."""
        return f"{self.rule}:{self.path}:{self.line}"

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

    findings: list[Finding] = []

    if "SD-1" in rules:
        v = SD1Visitor(lines)
        v.visit(tree)
        for lineno, col, msg in v.findings:
            line_text = lines[lineno - 1].strip() if lineno <= len(lines) else ""
            if _has_noqa(lines[lineno - 1] if lineno <= len(lines) else "", "SD-1"):
                continue
            findings.append(Finding("SD-1", rel_path, lineno, col, msg, line_text))

    if "SD-2" in rules:
        v2 = SD2Visitor(lines)
        v2.visit(tree)
        for lineno, col, msg in v2.findings:
            line_text = lines[lineno - 1].strip() if lineno <= len(lines) else ""
            if _has_noqa(lines[lineno - 1] if lineno <= len(lines) else "", "SD-2"):
                continue
            findings.append(Finding("SD-2", rel_path, lineno, col, msg, line_text))

    if "SD-4" in rules:
        v4 = SD4Visitor(lines)
        v4.visit(tree)
        for lineno, col, msg in v4.findings:
            # noqa already checked inside SD4Visitor per-return-line
            line_text = lines[lineno - 1].strip() if lineno <= len(lines) else ""
            findings.append(Finding("SD-4", rel_path, lineno, col, msg, line_text))

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

def load_baseline(baseline_path: Path) -> set[str]:
    """Return set of finding keys from a baseline JSON file."""
    if not baseline_path.exists():
        return set()
    data = json.loads(baseline_path.read_text())
    return set(data.get("findings", []))


def save_baseline(baseline_path: Path, findings: list[Finding]) -> None:
    keys = sorted(f.key() for f in findings)
    baseline_path.write_text(
        json.dumps({"findings": keys, "count": len(keys)}, indent=2) + "\n"
    )


def new_findings(findings: list[Finding], baseline: set[str]) -> list[Finding]:
    """Return only findings whose key is not in baseline."""
    return [f for f in findings if f.key() not in baseline]


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
