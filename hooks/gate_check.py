#!/usr/bin/env python3
"""PreToolUse hook: blocks package/tool install-or-update commands run via
Bash until the external-tool-security-gate skill has recorded an approval
for that exact command.

This hook cannot itself judge whether something is safe — it only enforces
that the SKILL.md procedure actually ran and reached an ALLOWED verdict
before the install executes. Scoring, the heuristic scan, and (for the
80-96% gray zone) asking the user are the skill's job; this hook is the
backstop so the agent can't just run the install anyway because it forgot,
got lazy, or decided to skip the gate under time pressure.

Reads the standard Claude Code hook JSON on stdin:
  {"tool_name": "Bash", "tool_input": {"command": "..."}, ...}
Emits structured deny JSON on stdout when blocking; emits nothing and exits
0 to let the tool call proceed untouched.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "lib"))
from gate_store import is_approved  # noqa: E402

# Commands that ADD or UPDATE something from an outside source — a Claude
# Code tool (skill/plugin/MCP server) or a project dependency. Heuristic,
# not exhaustive, same philosophy as scripts/heuristic_scan.py: a match is
# a reason to gate, not a legal definition of "this is an install".
INSTALL_PATTERNS = [
    r"\bnpm\s+(install|i|add)\s+\S",
    r"\bnpm\s+update\s+\S",
    r"\bnpx\s+skills\s+add\b",
    r"\bpnpm\s+add\s+\S",
    r"\bpnpm\s+update\s+\S",
    r"\byarn\s+add\s+\S",
    r"\byarn\s+upgrade\s+\S",
    r"\bpip3?\s+install\s+\S",
    r"\buv\s+(add|pip\s+install)\s+\S",
    r"\bpoetry\s+add\s+\S",
    r"\bcargo\s+add\s+\S",
    r"\bcargo\s+update\s+-p\s+\S",
    r"\bcomposer\s+require\s+\S",
    r"\bgem\s+install\s+\S",
    r"\bgem\s+update\s+\S",
    r"\bgo\s+(get|install)\s+\S",
    r"\bbrew\s+(install|upgrade|tap)\s+\S",
    r"\bclaude\s+plugin\s+(install|marketplace\s+add)\b",
    r"\bclaude\s+mcp\s+add\b",
]

# Clearly-local, no-new-external-code operations — never gated, regardless
# of the patterns above (checked first).
SAFE_PATTERNS = [
    r"^\s*npm\s+(install|ci)\s*$",
    r"^\s*(npm|pnpm|yarn)\s+install\s*$",
    r"\bpip3?\s+install\s+-e\s+\.\s*$",
]

RECORD_HINT = (
    'python3 "<plugin-root>/skills/external-tool-security-gate/scripts/'
    'record_approval.py" "<the exact command>" --score <N>'
)


def matches_any(patterns: list[str], text: str) -> bool:
    return any(re.search(p, text) for p in patterns)


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except (json.JSONDecodeError, OSError):
        return 0

    if payload.get("tool_name") != "Bash":
        return 0

    command = (payload.get("tool_input") or {}).get("command", "")
    if not command:
        return 0

    if matches_any(SAFE_PATTERNS, command):
        return 0
    if not matches_any(INSTALL_PATTERNS, command):
        return 0

    approval = is_approved(command)
    if approval is not None:
        return 0  # gate already ran for this exact command recently; let it through

    reason = (
        "external-tool-security-gate: this command installs or updates something "
        "from an outside source. Run the external-tool-security-gate skill's full "
        "procedure first (identify artifact, run scripts/heuristic_scan.py over "
        "the downloaded/cached artifact if one exists on disk, static review, "
        "score it). If the verdict is ALLOWED (score >=96%, or the user "
        "explicitly approved the 80-96% gray zone after being asked), record "
        f"that before retrying this exact command: {RECORD_HINT}. If the score "
        "is below 80%, do not run this command at all — tell the user it is "
        "blocked and why, and do not retry with a tweaked command to dodge this "
        "check."
    )
    print(json.dumps({
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": "deny",
            "permissionDecisionReason": reason,
        }
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
