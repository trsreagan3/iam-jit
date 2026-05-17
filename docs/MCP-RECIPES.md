# MCP recipes for non-Claude-Code clients

The Bounce suite ships MCP servers — `ibounce mcp serve` (AWS gate)
and `kbounce mcp serve` (Kubernetes gate) — that speak standard MCP
over stdio JSON-RPC 2.0. The `install-claude-code`,
`install-cursor`, and `install-codex` subcommands handle the most-
common clients automatically (atomic merge into the client's MCP
config, preserves every other server entry). **This doc is for
everything else.**

If you're on Claude Code, Cursor, or Codex (JSON variant), prefer
the `install-*` shortcut — it's exactly what this doc would walk
you through, with the merge handled for you. See
[`IBOUNCE.md`](IBOUNCE.md) for the canonical install path and
[`SECURITY-POSTURE.md`](SECURITY-POSTURE.md) for what the MCP
server does over the wire.

The canonical snippet:

```json
{
  "mcpServers": {
    "ibounce": {
      "command": "ibounce",
      "args": ["mcp", "serve"],
      "env": {}
    },
    "kbounce": {
      "command": "kbounce",
      "args": ["mcp", "serve"],
      "env": {}
    }
  }
}
```

If your client supports `mcpServers`-style JSON config — most do —
that snippet is what you want; substitute your client's config
path below.

---

## Cursor

Cursor reads its MCP config from `~/.cursor/mcp.json` (user-level,
applies to every workspace) or `<project>/.cursor/mcp.json`
(workspace-level, applies only inside that project root).

Recommended path: use the shipped command.

```bash
ibounce mcp install-cursor      # writes ~/.cursor/mcp.json
kbounce mcp install-cursor      # idem for kbounce
```

Both perform an atomic merge: any existing `mcpServers` entries are
preserved, and the install fails closed (no partial write) if the
existing file is not valid JSON. Pass `--path
<project>/.cursor/mcp.json` to target the workspace level instead.

Hand-edit form, if you'd rather not run the installer — drop the
canonical snippet above into `~/.cursor/mcp.json`. Merge with any
existing `mcpServers` object; do not overwrite the file.

**Verify:** restart Cursor; open Settings → MCP; both `ibounce`
and `kbounce` should appear as connected servers. Then ask the
agent to call a low-impact tool — for example,
`ibounce_list_rules` (lists the rule set; pure read) or
`kbounce_list_rules`.

---

## Devin

Devin's MCP config surface has evolved across releases; consult
Devin's current docs for the canonical config-file location. The
snippet shape is identical to Cursor — the standard `mcpServers`
JSON above.

If Devin's documented location is a JSON file, you can typically
point `ibounce mcp install-cursor --path <devin-config>` at it; the
installer is path-agnostic and performs the same atomic merge.

**Verify:** restart the Devin session; ask the agent to list its
available MCP tools. The `ibounce_*` and `kbounce_*` tools should
appear (use `ibounce mcp list-tools` or `kbounce mcp list-tools`
locally to see the canonical tool set the agent should see).

---

## Codex (OpenAI Codex CLI)

Codex MCP stores its config in TOML at `~/.codex/config.toml`,
**not** JSON. The Bounce installers will not edit TOML in place by
default (third-party TOML editing risks corrupting unrelated keys
the operator cares about), so `install-codex` prints a
copy-pasteable snippet plus the target path.

```bash
ibounce mcp install-codex       # prints TOML snippet + target path
kbounce mcp install-codex       # same shape for kbounce
```

Paste the printed snippet into your `~/.codex/config.toml`. The
expected shape (Codex uses `[mcp_servers.<name>]`, plural with
underscore):

```toml
[mcp_servers.ibounce]
command = "ibounce"
args = ["mcp", "serve"]

[mcp_servers.kbounce]
command = "kbounce"
args = ["mcp", "serve"]
```

If you keep a separate JSON-shaped MCP config (e.g. some operators
maintain a `~/.codex/mcp.json`), the JSON install path works:
`ibounce mcp install-codex --path ~/.codex/mcp.json --force`. That
performs the same atomic JSON merge as `install-cursor` /
`install-claude-code`.

**Verify:** restart Codex; the MCP server list in your Codex
client should include `ibounce` and `kbounce`.

---

## Custom JSON-RPC stdio clients

The Bounce MCP server speaks plain JSON-RPC 2.0 over stdin / stdout
— there is no transport-specific protocol beyond what the
[Model Context Protocol spec](https://spec.modelcontextprotocol.io)
defines.

To wire it into a custom client:

1. Spawn `ibounce mcp serve` (or `kbounce mcp serve`) as a
   subprocess; capture its stdin and stdout.
2. Write a framed `initialize` JSON-RPC request on stdin. Read the
   response on stdout.
3. Issue subsequent calls — `tools/list`, `tools/call`,
   `resources/list`, etc. — per the MCP spec.
4. The server exits cleanly when its stdin is closed.

For the full tool surface the server exposes, run `ibounce mcp
list-tools --json` or `kbounce mcp list-tools --json` locally; the
output is the same JSON-Schema description a client receives in
response to `tools/list`. The ibounce tool catalog is also
documented in the MCP section of [`IBOUNCE.md`](IBOUNCE.md).

---

## dbounce (future)

`dbounce` ships with the same pattern when its v1.0 lands.
Expected shape:

```json
{
  "mcpServers": {
    "dbounce": {
      "command": "dbounce",
      "args": ["mcp", "serve"],
      "env": {}
    }
  }
}
```

`dbounce mcp install-*` subcommands will mirror the
ibounce / kbounce installer surface.

---

## Verification recipe (no client required)

You can confirm the MCP server is healthy without any client. The
canonical smoke test:

```bash
# Send an MCP initialize handshake on stdin; expect a JSON-RPC
# response on stdout that includes serverInfo.
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05","capabilities":{},"clientInfo":{"name":"smoke","version":"0.0.1"}}}' \
  | ibounce mcp serve \
  | head -1
```

If the server is wired correctly you'll see a single JSON object
containing `"result"` and the server's `serverInfo`. The same shape
works against `kbounce mcp serve`.

For a fuller pass, `ibounce mcp list-tools` (and the kbounce
equivalent) prints the exact tool surface an agent would see —
that's the right command to confirm "what can my agent actually
do through this server."

---

## When to prefer `install-*` over hand-editing

For Claude Code, Cursor, and Codex (JSON variant), the
`install-{claude-code,cursor,codex}` subcommands are the
recommended path — they perform an atomic merge that preserves
every existing `mcpServers` entry and the rest of the config file.
A hand-edit can clobber unrelated entries; the installer cannot.

This doc is for:

- MCP clients **not** covered by the install-* commands (e.g.
  Devin, custom JSON-RPC stdio clients)
- Operators who want to hand-craft the config (e.g. as part of a
  dotfiles-managed setup) and need the snippet shape
- The Codex TOML path, where the installer deliberately prints
  rather than edits in place

For an end-to-end picture of what each MCP tool does and why the
suite ships an MCP surface at all, see
[`IBOUNCE.md`](IBOUNCE.md). For the security properties of the
`mcp serve` subprocess (what it does and does not send over the
network), see [`SECURITY-POSTURE.md`](SECURITY-POSTURE.md).

---

Last reviewed: 2026-05-17.
