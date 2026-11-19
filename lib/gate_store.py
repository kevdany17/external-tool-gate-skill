"""Shared approval-store logic for the external-tool-security-gate hook.

The PreToolUse hook (hooks/gate_check.py) blocks install/update-shaped
commands unless a matching approval record exists here. The only writer is
skills/external-tool-security-gate/scripts/record_approval.py, which the
agent is instructed (SKILL.md step 7) to run only after it has actually
completed the gate procedure and reached an ALLOWED verdict — this module
never grants anything by itself, it's just the shared hash/read/write/prune
code both ends call.

Store lives under the OS temp dir, not the repo: it's a short-lived,
per-machine cache of "this exact command was gated a moment ago", not a
durable record, and it should never land in version control.
"""
from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from pathlib import Path

STORE_PATH = Path(tempfile.gettempdir()) / "claude-security-gate" / "approvals.json"
DEFAULT_TTL_HOURS = 4


def normalize_command(command: str) -> str:
    return " ".join(command.split()).strip()


def command_hash(command: str) -> str:
    return hashlib.sha256(normalize_command(command).encode("utf-8")).hexdigest()


def _load() -> list[dict]:
    if not STORE_PATH.exists():
        return []
    try:
        data = json.loads(STORE_PATH.read_text())
    except (json.JSONDecodeError, OSError):
        return []
    if not isinstance(data, list):
        return []
    now = time.time()
    return [e for e in data if isinstance(e, dict) and e.get("expires_at", 0) > now]


def _save(entries: list[dict]) -> None:
    STORE_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = STORE_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(entries, indent=2))
    tmp.replace(STORE_PATH)
    try:
        os.chmod(STORE_PATH, 0o600)
    except OSError:
        pass


def is_approved(command: str) -> dict | None:
    """Return the approval entry for this exact command, or None."""
    h = command_hash(command)
    for entry in _load():
        if entry.get("hash") == h and entry.get("decision") == "allow":
            return entry
    return None


class ScoreTooLowError(ValueError):
    """Raised when something tries to record an approval below the 80% floor."""


def record_approval(
    command: str,
    *,
    score: float,
    decision: str = "allow",
    ttl_hours: float = DEFAULT_TTL_HOURS,
    note: str = "",
) -> dict:
    if decision == "allow" and score < 80:
        raise ScoreTooLowError(
            f"refusing to record an 'allow' approval at {score}% — the 80% floor "
            "is enforced here, not just in the CLI, so nothing that imports this "
            "module can record a below-floor approval by calling the function "
            "directly."
        )
    entries = _load()
    h = command_hash(command)
    entries = [e for e in entries if e.get("hash") != h]
    entry = {
        "hash": h,
        "command": normalize_command(command),
        "decision": decision,
        "score": score,
        "note": note,
        "recorded_at": time.time(),
        "expires_at": time.time() + ttl_hours * 3600,
    }
    entries.append(entry)
    _save(entries)
    return entry
