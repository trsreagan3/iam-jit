"""Schema corpus — baked-in tool-name → schema mapping.

Per [[ibounce-honest-positioning]] every entry CITES its source so
operators can audit the corpus. We do NOT invent tool names; unknown
tools fire as `hallucinated-tool-name` rather than being silently
accepted.

Three shape namespaces:

  - `mcp`       — Model Context Protocol standard methods
                  (https://modelcontextprotocol.io/specification)
  - `openai`    — OpenAI Assistants + Chat Completions built-in tools
                  (https://platform.openai.com/docs/assistants/tools)
  - `anthropic` — Anthropic Messages API tool-use built-in tools
                  (https://docs.anthropic.com/en/docs/build-with-claude/tool-use)

The baked-in set is INTENTIONALLY SMALL — these are the tools that the
provider itself documents as built-in / standard. Operators bring their
own tool catalog via `schema_corpus_path` for custom tools.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class ToolSchema:
    """One known-tool schema entry.

    `required` / `optional` are field NAMES — we validate presence /
    absence rather than full JSON-schema type semantics (which would
    expand the false-positive surface for v1.0). A future pass may
    upgrade to full JSON-schema validation.
    """

    name: str
    shape: str  # "mcp" | "openai" | "anthropic"
    required: tuple[str, ...] = ()
    optional: tuple[str, ...] = ()
    source: str = ""  # provenance URL or doc cite
    note: str = ""    # short description


# ---------------------------------------------------------------------
# Baked-in MCP standard methods. Drawn from the MCP specification's
# server-method list. CITED in `source` per [[ibounce-honest-positioning]].
# ---------------------------------------------------------------------

MCP_TOOLS: tuple[ToolSchema, ...] = (
    ToolSchema(
        name="tools/list",
        shape="mcp",
        required=(),
        optional=("cursor",),
        source="modelcontextprotocol.io/specification (tools/list)",
        note="List tools available on the MCP server",
    ),
    ToolSchema(
        name="tools/call",
        shape="mcp",
        required=("name",),
        optional=("arguments",),
        source="modelcontextprotocol.io/specification (tools/call)",
        note="Invoke a named tool",
    ),
    ToolSchema(
        name="resources/list",
        shape="mcp",
        required=(),
        optional=("cursor",),
        source="modelcontextprotocol.io/specification (resources/list)",
        note="List resources",
    ),
    ToolSchema(
        name="resources/read",
        shape="mcp",
        required=("uri",),
        optional=(),
        source="modelcontextprotocol.io/specification (resources/read)",
        note="Read a resource by URI",
    ),
    ToolSchema(
        name="prompts/list",
        shape="mcp",
        required=(),
        optional=("cursor",),
        source="modelcontextprotocol.io/specification (prompts/list)",
        note="List prompts",
    ),
    ToolSchema(
        name="prompts/get",
        shape="mcp",
        required=("name",),
        optional=("arguments",),
        source="modelcontextprotocol.io/specification (prompts/get)",
        note="Get a prompt by name",
    ),
    ToolSchema(
        name="initialize",
        shape="mcp",
        required=("protocolVersion", "capabilities"),
        optional=("clientInfo",),
        source="modelcontextprotocol.io/specification (initialize)",
        note="MCP session initialize",
    ),
    ToolSchema(
        name="ping",
        shape="mcp",
        required=(),
        optional=(),
        source="modelcontextprotocol.io/specification (ping)",
        note="Liveness check",
    ),
)

# ---------------------------------------------------------------------
# OpenAI built-in tools (Assistants API + Chat Completions tool_calls).
# Drawn from platform.openai.com/docs/assistants/tools.
# ---------------------------------------------------------------------

OPENAI_TOOLS: tuple[ToolSchema, ...] = (
    ToolSchema(
        name="code_interpreter",
        shape="openai",
        required=(),
        optional=(),
        source="platform.openai.com/docs/assistants/tools/code-interpreter",
        note="OpenAI code-interpreter built-in tool",
    ),
    ToolSchema(
        name="file_search",
        shape="openai",
        required=(),
        optional=("queries", "max_num_results"),
        source="platform.openai.com/docs/assistants/tools/file-search",
        note="OpenAI file-search built-in tool",
    ),
    ToolSchema(
        name="web_search",
        shape="openai",
        required=("query",),
        optional=("search_context_size",),
        source="platform.openai.com/docs/guides/tools-web-search",
        note="OpenAI web-search built-in tool",
    ),
    ToolSchema(
        name="image_generation",
        shape="openai",
        required=("prompt",),
        optional=("size", "quality"),
        source="platform.openai.com/docs/guides/tools-image-generation",
        note="OpenAI image-generation tool",
    ),
)

# ---------------------------------------------------------------------
# Anthropic built-in tools (Messages API tool-use).
# Drawn from docs.anthropic.com/en/docs/build-with-claude/tool-use.
# ---------------------------------------------------------------------

ANTHROPIC_TOOLS: tuple[ToolSchema, ...] = (
    ToolSchema(
        name="computer",
        shape="anthropic",
        required=("action",),
        optional=("coordinate", "text", "duration"),
        source="docs.anthropic.com/en/docs/build-with-claude/computer-use",
        note="Anthropic computer-use tool",
    ),
    ToolSchema(
        name="text_editor",
        shape="anthropic",
        required=("command", "path"),
        optional=("file_text", "insert_line", "new_str", "old_str", "view_range"),
        source="docs.anthropic.com/en/docs/build-with-claude/tool-use/text-editor-tool",
        note="Anthropic text-editor tool",
    ),
    ToolSchema(
        name="bash",
        shape="anthropic",
        required=("command",),
        optional=("restart",),
        source="docs.anthropic.com/en/docs/build-with-claude/tool-use/bash-tool",
        note="Anthropic bash tool",
    ),
    ToolSchema(
        name="web_search",
        shape="anthropic",
        required=("query",),
        optional=("max_uses",),
        source="docs.anthropic.com/en/docs/build-with-claude/tool-use/web-search-tool",
        note="Anthropic web-search tool",
    ),
)


@dataclass(frozen=True)
class SchemaCorpus:
    """A lookup table of (shape, name) -> ToolSchema.

    Frozen so callers can cache. Use `lookup(shape, name)` to query;
    missing tools return None (the caller treats that as
    `hallucinated-tool-name`).
    """

    tools: tuple[ToolSchema, ...] = field(default_factory=tuple)

    def lookup(self, shape: str, name: str) -> ToolSchema | None:
        for t in self.tools:
            if t.shape == shape and t.name == name:
                return t
        return None

    def has_shape(self, shape: str) -> bool:
        return any(t.shape == shape for t in self.tools)

    def names_for_shape(self, shape: str) -> tuple[str, ...]:
        return tuple(t.name for t in self.tools if t.shape == shape)


_DEFAULT_TOOLS: tuple[ToolSchema, ...] = (
    MCP_TOOLS + OPENAI_TOOLS + ANTHROPIC_TOOLS
)


def default_corpus() -> SchemaCorpus:
    """Return the baked-in corpus (MCP + OpenAI + Anthropic standard)."""
    return SchemaCorpus(tools=_DEFAULT_TOOLS)


def load_corpus(path: str | None) -> SchemaCorpus:
    """Load + merge a corpus from disk on top of the baked-in defaults.

    Operator entries WIN on collision (same shape + name).

    File format (YAML or JSON):
        tools:
          - name: my_custom_tool
            shape: mcp                # or openai | anthropic
            required: [field_a]
            optional: [field_b]
            source: my-org-tool-catalog
            note: short description

    Returns the baked-in corpus alone when `path` is empty / None /
    missing. Malformed files emit a `ValueError` so the bouncer's
    profile-load step can surface it (we don't silently fall back).
    """
    if not path:
        return default_corpus()
    p = Path(path)
    if not p.exists():
        return default_corpus()
    raw_text = p.read_text(encoding="utf-8")
    raw: Any
    if p.suffix in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore[import-untyped]
        except ImportError as e:
            raise ValueError(
                f"tool_call_validator: corpus path {path} is YAML but "
                f"PyYAML is not installed"
            ) from e
        raw = yaml.safe_load(raw_text)
    else:
        raw = json.loads(raw_text)
    if not isinstance(raw, dict):
        raise ValueError(
            f"tool_call_validator: corpus file {path} must be a mapping"
        )
    operator_entries = raw.get("tools") or []
    if not isinstance(operator_entries, list):
        raise ValueError(
            f"tool_call_validator: corpus file {path} 'tools' must be a list"
        )

    operator_tools: list[ToolSchema] = []
    for entry in operator_entries:
        if not isinstance(entry, dict):
            continue
        name = str(entry.get("name") or "").strip()
        shape = str(entry.get("shape") or "").strip()
        if not name or not shape:
            continue
        required = entry.get("required") or ()
        optional = entry.get("optional") or ()
        if not isinstance(required, (list, tuple)):
            required = ()
        if not isinstance(optional, (list, tuple)):
            optional = ()
        operator_tools.append(
            ToolSchema(
                name=name,
                shape=shape,
                required=tuple(str(r) for r in required),
                optional=tuple(str(o) for o in optional),
                source=str(entry.get("source") or "operator-supplied"),
                note=str(entry.get("note") or ""),
            )
        )

    # Operator entries WIN on collision: drop baked-in matches.
    op_keys: set[tuple[str, str]] = {(t.shape, t.name) for t in operator_tools}
    merged = [t for t in _DEFAULT_TOOLS if (t.shape, t.name) not in op_keys]
    merged.extend(operator_tools)
    return SchemaCorpus(tools=tuple(merged))
