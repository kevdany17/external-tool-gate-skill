# external-tool-security-gate

Claude Code skill: a security gate that runs **before** installing any external tool into the agent's own capabilities — a skill, subagent, plugin, MCP server, or package (npm/pip/uv/pnpm/yarn/cargo/composer/gem/go get) — from a source that isn't first-party Anthropic or your own repo.

It computes a 0–100% safety confidence score from source reputation, actual scanner findings (never just a badge color), a static content/code review, and a bundled Python heuristic scan for exfiltration/malicious-code patterns. Decision is tiered:

- **≥ 96%** — install proceeds, residual risk still reported.
- **80–96%** — "gray zone": install is paused, the user is shown the full verdict and asked explicitly whether to proceed anyway.
- **< 80%** — hard block, no override.

In every tier, the user is told the score and the final decision, never a silent outcome.

## Why

A scanner badge is a summary, not a verification. This gate was written after a session saw a "Med Risk" badge on a skill, didn't read what the finding actually said, and installed anyway. The finding turned out benign — but that was luck. This skill forces the actual finding, and the actual code, to be read every time, regardless of what the badge says.

## What it covers

- `npx skills add` / any skill or plugin marketplace install
- `claude plugin install` / `claude mcp add` / hand-edited `settings.json` or MCP config
- New subagent types from outside this session's built-ins
- `npm install`, `pip install`, `uv add`, `cargo add`, etc. for any unvetted package
- Repointing an existing tool at a new, previously-unvetted source (fork, new marketplace)

First-party Anthropic packages/skills/MCP servers and your own repos are out of scope.

## Enforcement, not just a procedure to remember

This plugin ships hooks (`hooks/hooks.json`), active once installed:

- A `PreToolUse` hook on `Bash` (`hooks/gate_check.py`) **denies** any install/update-shaped command (npm/pip/uv/pnpm/yarn/cargo/composer/gem/go, `claude plugin install`, `claude mcp add`, `npx skills add`, …) unless this skill already ran for that exact command and recorded an ALLOWED verdict via `scripts/record_approval.py` — which itself refuses to record anything scoring under 80%, even if called directly.
- A `PreToolUse` hook on `Edit`/`Write` (`hooks/config_check.py`) flags hand-edits to `settings.json`/`.mcp.json` that look like they register a new MCP server, asking for explicit approval.

So the gate isn't something the agent has to remember to invoke — the install itself is blocked until it does.

## Install

### Via marketplace (Claude Code plugin system)

```
claude plugin marketplace add kevdany17/external-tool-gate-skill
claude plugin install external-tool-security-gate@kevdany17
```

### Local (testing / development)

```bash
git clone git@github.com:kevdany17/external-tool-gate-skill.git
claude --plugin-dir ./external-tool-gate-skill
```

### Manual (add to your `~/.claude/settings.json`)

```json
{
  "plugins": {
    "external-tool-security-gate": {
      "source": "/path/to/external-tool-gate-skill"
    }
  }
}
```

After installing, the hooks are active automatically — no further configuration needed.

### Requirements

- Python 3.8+ (stdlib only — no `pip install` needed)
- `jq` available on `PATH` is NOT required; this plugin uses Python everywhere

## How it works

See [`skills/external-tool-security-gate/SKILL.md`](skills/external-tool-security-gate/SKILL.md) for the full procedure: artifact identification, signal collection, scanner-finding review, the bundled heuristic scan ([`scripts/heuristic_scan.py`](skills/external-tool-security-gate/scripts/heuristic_scan.py)), static content/code review per artifact category, the scoring rubric, the tiered decision logic, and the report format.

## License

Apache-2.0 — see [LICENSE](LICENSE).
