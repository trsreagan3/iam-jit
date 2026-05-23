"""#397 — loader / source-discovery tests."""

from __future__ import annotations

import pathlib

import pytest

from iam_jit.ambient_config import (
    ConfigLoadError,
    discover_declaration_source,
    load_declaration,
    load_declaration_from_path,
)


def _write(path: pathlib.Path, body: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body)


# ---------------------------------------------------------------------------
# Auto-discovery precedence
# ---------------------------------------------------------------------------


def test_discover_finds_standalone_yaml(tmp_path: pathlib.Path) -> None:
    _write(tmp_path / ".iam-jit.yaml", "iam-jit:\n  enabled: true\n")
    found = discover_declaration_source(cwd=tmp_path)
    assert found is not None
    assert found.kind == "standalone"
    assert found.path.name == ".iam-jit.yaml"


def test_discover_finds_codeblock_in_claude_md(
    tmp_path: pathlib.Path,
) -> None:
    _write(
        tmp_path / "CLAUDE.md",
        "# Notes\n\n```iam-jit-config\niam-jit:\n  enabled: true\n```\n",
    )
    found = discover_declaration_source(cwd=tmp_path)
    assert found is not None
    assert found.kind == "context"
    assert found.path.name == "CLAUDE.md"


def test_discover_standalone_beats_codeblock(
    tmp_path: pathlib.Path,
) -> None:
    _write(tmp_path / ".iam-jit.yaml", "iam-jit:\n  enabled: false\n")
    _write(
        tmp_path / "CLAUDE.md",
        "```iam-jit-config\niam-jit:\n  enabled: true\n```\n",
    )
    found = discover_declaration_source(cwd=tmp_path)
    assert found is not None
    assert found.path.name == ".iam-jit.yaml"


def test_discover_returns_none_when_nothing(tmp_path: pathlib.Path) -> None:
    assert discover_declaration_source(cwd=tmp_path) is None


def test_discover_ignores_context_file_without_codeblock(
    tmp_path: pathlib.Path,
) -> None:
    _write(tmp_path / "CLAUDE.md", "# Just notes, no iam-jit declaration\n")
    assert discover_declaration_source(cwd=tmp_path) is None


# ---------------------------------------------------------------------------
# Path loading
# ---------------------------------------------------------------------------


def test_load_from_standalone_yaml(tmp_path: pathlib.Path) -> None:
    p = tmp_path / ".iam-jit.yaml"
    _write(
        p,
        """iam-jit:
  enabled: true
  bouncers:
    ibounce:
      enabled: true
      mode: discovery
""",
    )
    decl = load_declaration_from_path(p)
    assert decl["iam-jit"]["enabled"] is True
    assert decl["iam-jit"]["bouncers"]["ibounce"]["mode"] == "discovery"


def test_load_from_context_md(tmp_path: pathlib.Path) -> None:
    p = tmp_path / "CLAUDE.md"
    _write(
        p,
        """# Project rules

```iam-jit-config
iam-jit:
  enabled: true
  posture: ambient
```
""",
    )
    decl = load_declaration_from_path(p)
    assert decl["iam-jit"]["posture"] == "ambient"


def test_load_from_missing_path(tmp_path: pathlib.Path) -> None:
    with pytest.raises(ConfigLoadError) as exc:
        load_declaration_from_path(tmp_path / "absent.yaml")
    assert exc.value.code == "file_not_found"


def test_load_from_context_no_codeblock(tmp_path: pathlib.Path) -> None:
    p = tmp_path / "CLAUDE.md"
    _write(p, "no codeblock here")
    with pytest.raises(ConfigLoadError) as exc:
        load_declaration_from_path(p)
    assert exc.value.code == "no_codeblock"


# ---------------------------------------------------------------------------
# load_declaration polymorphism
# ---------------------------------------------------------------------------


def test_load_declaration_dict_input() -> None:
    decl, src = load_declaration({"iam-jit": {"enabled": True}})
    assert decl["iam-jit"]["enabled"] is True
    assert src == "<inline>"


def test_load_declaration_string_yaml_text() -> None:
    body = "iam-jit:\n  enabled: true\n"
    decl, src = load_declaration(body)
    assert decl["iam-jit"]["enabled"] is True
    assert src == "<inline-text>"


def test_load_declaration_string_path(tmp_path: pathlib.Path) -> None:
    p = tmp_path / ".iam-jit.yaml"
    _write(p, "iam-jit:\n  enabled: false\n")
    decl, src = load_declaration(str(p))
    assert decl["iam-jit"]["enabled"] is False
    assert src == str(p)


def test_load_declaration_autodiscover(tmp_path: pathlib.Path) -> None:
    _write(
        tmp_path / ".iam-jit.yaml", "iam-jit:\n  enabled: true\n"
    )
    decl, src = load_declaration(None, cwd=tmp_path)
    assert decl["iam-jit"]["enabled"] is True
    assert ".iam-jit.yaml" in src


def test_load_declaration_autodiscover_no_source(
    tmp_path: pathlib.Path,
) -> None:
    with pytest.raises(ConfigLoadError) as exc:
        load_declaration(None, cwd=tmp_path)
    assert exc.value.code == "no_declaration_found"
