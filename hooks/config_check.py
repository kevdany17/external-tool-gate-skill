#!/usr/bin/env python3
"""PreToolUse hook: flags hand-edits to Claude Code config files so the
agent doesn't quietly register a new external MCP server, plugin, or hook
without having run the external-tool-security-gate skill first.

Unlike gate_check.py this does not hard-deny — Edit/Write on settings.json
has plenty of legitimate reasons unrelated to adding an external tool. It
asks instead, surfacing a reminder inside the normal permission prompt, so a
human still has to actively approve registering a new outside source.

Reads the standard Claude Code hook JSON on stdin:
  {"tool_name": "Edit"|"Write", "tool_input": {"file_path": "...", ...}, ...}
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

CONFIG_FILENAMES = {
    "settings.json",
    "settings.local.json",
    ".mcp.json",
    "mcp.json",
}


def changed_text(tool_input: dict) -> str:
    # Write: full new content. Edit: just the new fragment (old_string/
    # new_string) — still enough to catch the common case of someone
    # pasting a new mcpServers/hooks block in.
    return (
        tool_input.get("content")
        or tool_input.get("new_string")
        or ""
    )


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, OSError):
        return 0

    if payload.get("tool_name") not in ("Edit", "Write"):
        return 0

    tool_input = payload.get("tool_input") or {}
    file_path = tool_input.get("file_path", "")
    if not file_path or Path(file_path).name not in CONFIG_FILENAMES:
        return 0

    text = changed_text(tool_input)
    looks_relevant = (
        "mcpServers" in text
        or '"hooks"' in text
        or "mcp" in Path(file_path).name.lower()
    )
    if not looks_relevant:
        return 0

    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "ask",
            "permissionDecisionReason": (
                "external-tool-security-gate: this edits a Claude Code config file "
                "that can register a new MCP server, plugin, or hook. If this adds "
                "one from an outside source, run the external-tool-security-gate "
                "skill first and get an ALLOWED verdict before approving this edit."
            ),
        }
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
