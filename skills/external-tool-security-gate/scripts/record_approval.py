#!/usr/bin/env python3
"""Record that the external-tool-security-gate procedure ran for an exact
command and reached an ALLOWED verdict — so the PreToolUse hook
(hooks/gate_check.py) lets that specific command through next time it is
attempted.

Only call this AFTER actually completing SKILL.md's procedure and landing
on one of:
  - score >= 96% (proceeds automatically), or
  - score 80-96% and the user was explicitly asked and said yes.

Never call this to pre-clear a command you haven't scored yet, and never
call it for a < 80% or user-declined verdict — the point of the hook is
that it cannot be talked out of blocking by anything other than a real,
already-reached ALLOWED decision.

Usage:
    python3 record_approval.py "<the exact command that will be run>" \\
        --score 97 [--ttl-hours 4] [--note "npm trust score 97%, see report"]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[3] / "lib"))
from gate_store import DEFAULT_TTL_HOURS, ScoreTooLowError, record_approval  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", help="the exact shell command the gate approved")
    parser.add_argument("--score", type=float, required=True, help="the gate's 0-100 score")
    parser.add_argument("--ttl-hours", type=float, default=DEFAULT_TTL_HOURS,
                         help=f"how long the approval stays valid (default: {DEFAULT_TTL_HOURS}h)")
    parser.add_argument("--note", default="", help="short free-text context for the record")
    args = parser.parse_args()

    try:
        entry = record_approval(args.command, score=args.score, ttl_hours=args.ttl_hours, note=args.note)
    except ScoreTooLowError as e:
        print(f"refusing to record: {e}", file=sys.stderr)
        return 1
    print(f"recorded: score={entry['score']}%  expires_in={args.ttl_hours}h  "
          f"command={entry['command']!r}")
    if 80 <= args.score < 96:
        print("note: this is a gray-zone (80-96%) approval — it must only be recorded "
              "after the user was explicitly asked and agreed to proceed.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
