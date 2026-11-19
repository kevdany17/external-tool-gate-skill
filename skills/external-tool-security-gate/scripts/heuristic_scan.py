#!/usr/bin/env python3
"""Heuristic static scanner for external-tool-security-gate.

Scans a file or directory tree (a downloaded skill, plugin, MCP server, or
package) for text patterns commonly associated with credential/data
exfiltration, remote code execution, obfuscation, destructive operations,
and prompt-injection framing.

This is a REGEX HEURISTIC, not a verdict. It never executes the candidate
code (reads bytes only) and it will both miss real issues (anything
sufficiently obfuscated) and flag benign code (a test fixture that happens
to read an env var). Every hit still requires a human/model read of the
surrounding context before it affects the score — see SKILL.md step 4.

Usage:
    python3 heuristic_scan.py <path> [--json] [--max-bytes N]

Exit code is always 0 (this is a reporting tool, not a pass/fail gate by
itself) unless the path is invalid.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

# Directories never worth descending into for this kind of review.
SKIP_DIRS = {".git", "__pycache__", ".mypy_cache", ".pytest_cache"}

# Extensions treated as text; anything else is read but skipped if it
# doesn't decode as UTF-8 (binary blobs are a separate, unscored signal).
TEXT_LIKE_SUFFIXES = {
    "", ".py", ".js", ".ts", ".jsx", ".tsx", ".mjs", ".cjs", ".sh", ".bash",
    ".zsh", ".rb", ".php", ".go", ".rs", ".java", ".md", ".mdx", ".json",
    ".yaml", ".yml", ".toml", ".cfg", ".ini", ".txt", ".ps1", ".bat",
}

MAX_FILE_BYTES_DEFAULT = 2_000_000  # skip absurdly large files, note it


@dataclass
class Finding:
    category: str
    severity: str  # "high" | "medium" | "low"
    file: str
    line: int
    snippet: str
    rule: str


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped_binary: int = 0
    files_skipped_large: int = 0


# Each rule: (category, severity, description, compiled regex)
# Severity guidance mirrors SKILL.md step 6:
#   high   -> treat like a real finding, heavy weight against score
#   medium -> note it, weigh moderately, context decides
#   low    -> common in legitimate code, light weight, context decides
RULES: list[tuple[str, str, str, re.Pattern]] = [
    # --- Credential / secret access ---------------------------------
    ("credential_access", "high", "reads SSH private key material",
     re.compile(r"BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY")),
    ("credential_access", "medium", "reads a dotfile credential store",
     re.compile(r"""['"](~|\$HOME|\.)/?\.(ssh/|aws/credentials|npmrc|netrc|git-credentials|docker/config\.json)""")),
    ("credential_access", "low", "reads process environment generically",
     re.compile(r"\b(os\.environ|process\.env|Deno\.env|System\.getenv)\b")),
    ("credential_access", "medium", "reads a named secret-shaped env var",
     re.compile(r"\b(os\.environ|process\.env)\s*(\.get\(|\[)\s*['\"]?(\w*_)?(API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE_KEY|ACCESS_KEY|CREDENTIAL)\w*", re.IGNORECASE)),
    ("credential_access", "medium", "reads macOS/Windows credential stores",
     re.compile(r"\b(security find-generic-password|Get-Credential|keytar|keychain)\b")),

    # --- Network exfiltration ----------------------------------------
    ("network_exfil", "low", "outbound HTTP call (context-dependent)",
     re.compile(r"\b(requests\.(get|post|put)|urllib\.request\.urlopen|http\.client\.|fetch\(|axios\.(get|post)|XMLHttpRequest|curl\s+-|wget\s+)")),
    ("network_exfil", "high", "raw socket connection (possible C2/backdoor)",
     re.compile(r"\b(socket\.socket\(|net\.connect\(|new Socket\(|/dev/tcp/)")),
    ("network_exfil", "high", "reverse-shell-shaped command",
     re.compile(r"\bnc\s+-e\b|\bbash\s+-i\s+>&\s*/dev/tcp/|/bin/sh\s+-i\b")),
    ("network_exfil", "medium", "pipes a remote download straight into a shell",
     re.compile(r"\b(curl|wget)\b[^\n]{0,120}\|\s*(bash|sh|zsh|python3?)\b")),
    ("network_exfil", "medium", "downloads+executes via scripting runtime",
     re.compile(r"(IEX|Invoke-Expression)\s*\(|New-Object\s+Net\.WebClient|powershell[^\n]{0,40}-enc(odedcommand)?\b", re.IGNORECASE)),

    # --- Dynamic code execution ----------------------------------------
    ("code_exec", "medium", "dynamic eval/exec of a string",
     re.compile(r"\b(eval|exec)\s*\(")),
    ("code_exec", "medium", "JS dynamic function construction",
     re.compile(r"\bnew Function\s*\(")),
    ("code_exec", "medium", "shell-equals-true subprocess call",
     re.compile(r"\bsubprocess\.(run|call|Popen|check_output)\([^)]*shell\s*=\s*True")),
    ("code_exec", "low", "generic shell-out from code",
     re.compile(r"\bos\.system\(|os\.popen\(|child_process\.(exec|execSync|spawn)\(")),

    # --- Obfuscation ----------------------------------------------------
    ("obfuscation", "medium", "base64/atob decode feeding exec/eval",
     re.compile(r"(base64\.b64decode|atob)\([^)]*\)[^\n]{0,80}\b(eval|exec)\s*\(", re.IGNORECASE)),
    ("obfuscation", "low", "long hex/unicode escape run (possible packed payload)",
     re.compile(r"(\\x[0-9a-fA-F]{2}){20,}|(\\u[0-9a-fA-F]{4}){20,}")),

    # --- Destructive / persistence --------------------------------------
    ("destructive", "high", "recursive force-delete of a root-ish path",
     re.compile(r"\brm\s+-rf\s+(/|~|\$HOME|--no-preserve-root)\b")),
    ("destructive", "medium", "recursive delete from code",
     re.compile(r"\bshutil\.rmtree\(|fs\.rmSync\([^)]*recursive")),
    ("destructive", "medium", "installs a persistence mechanism",
     re.compile(r"\bcrontab\s+-e\b|\blaunchctl\s+load\b|\bNew-ItemProperty\b.*\bRun\b|reg\s+add\b.*\\Run\b", re.IGNORECASE)),

    # --- Prompt-injection / model-directed framing (skills, agent defs) --
    ("prompt_injection", "high", "tells the model to ignore/override prior instructions",
     re.compile(r"\b(ignore|disregard)\s+(all\s+)?(previous|prior|above)\s+instructions\b", re.IGNORECASE)),
    ("prompt_injection", "medium", "tells the model to hide actions from the user",
     re.compile(r"\bdo not (tell|inform|mention to)\s+the user\b|\bwithout (telling|asking)\s+the user\b", re.IGNORECASE)),
    ("prompt_injection", "medium", "claims elevated/developer/unrestricted mode",
     re.compile(r"\b(developer mode|DAN mode|unrestricted mode|no (safety|ethical) (guidelines|restrictions))\b", re.IGNORECASE)),
    ("prompt_injection", "low", "zero-width / invisible unicode (possible hidden instructions)",
     re.compile(r"[​‌‍⁠﻿]")),
]


def iter_files(root: Path):
    if root.is_file():
        yield root
        return
    for p in root.rglob("*"):
        if p.is_dir():
            continue
        if any(part in SKIP_DIRS for part in p.parts):
            continue
        yield p


def scan_file(path: Path, max_bytes: int, result: ScanResult) -> None:
    try:
        size = path.stat().st_size
    except OSError:
        return
    if size > max_bytes:
        result.files_skipped_large += 1
        return
    if path.suffix not in TEXT_LIKE_SUFFIXES and path.suffix != "":
        # Unknown/binary-ish extension: still worth a peek for embedded
        # secrets but don't try to line-number it as text.
        return
    try:
        text = path.read_text(encoding="utf-8", errors="strict")
    except (UnicodeDecodeError, OSError):
        result.files_skipped_binary += 1
        return

    result.files_scanned += 1
    lines = text.splitlines()
    for lineno, line in enumerate(lines, start=1):
        for category, severity, rule_desc, pattern in RULES:
            if pattern.search(line):
                snippet = line.strip()
                if len(snippet) > 160:
                    snippet = snippet[:157] + "..."
                result.findings.append(
                    Finding(
                        category=category,
                        severity=severity,
                        file=str(path),
                        line=lineno,
                        snippet=snippet,
                        rule=rule_desc,
                    )
                )


def run(path: Path, max_bytes: int) -> ScanResult:
    result = ScanResult()
    for f in iter_files(path):
        scan_file(f, max_bytes, result)
    return result


SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


def print_report(result: ScanResult) -> None:
    print(f"files scanned: {result.files_scanned}  "
          f"skipped (binary): {result.files_skipped_binary}  "
          f"skipped (too large): {result.files_skipped_large}")
    if not result.findings:
        print("no heuristic hits. this is NOT a pass — it means this scanner found nothing;"
              " manual read per SKILL.md step 4 is still required.")
        return

    findings = sorted(result.findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.category, f.file, f.line))
    counts = {"high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f.severity] += 1

    print(f"findings: {counts['high']} high, {counts['medium']} medium, {counts['low']} low\n")
    for f in findings:
        print(f"[{f.severity.upper():6}] {f.category:18} {f.file}:{f.line}")
        print(f"         rule: {f.rule}")
        print(f"         code: {f.snippet}")
    print(
        "\nEvery HIGH hit above must be read in context and either explained in the report\n"
        "or treated as a heavy negative per the scoring rubric (step 6). A hit is a reason\n"
        "to go read that line, not a verdict by itself — false positives happen."
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("path", type=Path, help="file or directory to scan")
    parser.add_argument("--json", action="store_true", help="emit JSON instead of text")
    parser.add_argument("--max-bytes", type=int, default=MAX_FILE_BYTES_DEFAULT,
                         help="skip individual files larger than this (default: %(default)s)")
    args = parser.parse_args()

    if not args.path.exists():
        print(f"error: path not found: {args.path}", file=sys.stderr)
        return 2

    result = run(args.path, args.max_bytes)

    if args.json:
        payload = {
            "files_scanned": result.files_scanned,
            "files_skipped_binary": result.files_skipped_binary,
            "files_skipped_large": result.files_skipped_large,
            "findings": [f.__dict__ for f in result.findings],
        }
        print(json.dumps(payload, indent=2))
    else:
        print_report(result)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
