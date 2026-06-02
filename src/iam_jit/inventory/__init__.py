# ADOPT-3 / #717 — MCP/A2A attack-surface inventory.
"""Enumerate the agent's MCP/A2A attack surface.

This is the operator-facing answer to "here is everything my agent can
reach / be reached through": the MCP servers (and, where discoverable,
their tools) the agent has configured, the bouncers wired in + their
ports/endpoints, and any A2A / agent endpoints discoverable from the
environment.

The module REUSES existing discovery rather than reinventing it:

  * ``iam_jit.posture.bouncers.detect_all_bouncers`` — the running /
    port / env-wiring / misconfig truth for ibounce / kbounce /
    dbounce / gbounce. The inventory's "bouncer surface" section is a
    risk-tagged projection of that block.
  * The ``mcp install-*`` config-path ladder (mirrored from
    ``cli_init._detect_harness`` + ``cli_uninstall._check_mcp_entries``)
    — the canonical on-disk locations of Claude Code / Cursor / Claude
    Desktop MCP configs.
  * ``iam_jit.posture.sanitize.sanitize_posture`` — the same
    credential-scrubbing pass, so no token VALUE ever lands in the
    inventory output.

Honesty contract per [[ibounce-honest-positioning]]:
  * Report only what is actually discoverable on disk / over loopback.
  * Tools are NOT enumerable from a static MCP config (servers declare
    a launch command, not their tool list) — so we mark a server's
    tools ``"unknown — not enumerable from static config"`` UNLESS the
    server is iam-jit's own, whose tool list we read directly from the
    in-process ``TOOLS`` registry.
  * Token values are never emitted: we report a server's name + whether
    it carries an auth secret (``authed: true/false``), never the
    secret itself.

Read-only. Never mutates any config, never starts/stops a process.
"""

from __future__ import annotations

from .collect import (
    INVENTORY_SCHEMA_VERSION,
    capture_inventory,
    render_inventory_table,
)

__all__ = [
    "INVENTORY_SCHEMA_VERSION",
    "capture_inventory",
    "render_inventory_table",
]
