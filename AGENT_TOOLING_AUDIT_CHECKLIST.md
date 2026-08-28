# Audit your agent tooling before you trust it — free checklist

The 8 supply-chain + honesty patterns every team running AI agents should check
before installing a downloaded skill, a system prompt they didn't write, or an
agent-built MCP server. V1 — no install needed. (These are the same patterns
the `mcp-skill-sec` server detects automatically.)

## R1 — Prompt injection / instruction hijack
- [ ] Does the skill/prompt ask the agent to "ignore previous instructions" or override its system prompt?
- [ ] Does it try to redirect the agent's goal, identity, or reporting behavior?
- [ ] Does it instruct the agent to hide activity, or to not disclose something to the operator?

## R2 — Data exfiltration
- [ ] Does it send/post/email file contents or clipboard to a remote URL?
- [ ] Does it reference an IP/domain for "telemetry" that isn't the vendor's documented endpoint?
- [ ] Does it collect environment variables or credentials and transmit them?

## R3 — Hardcoded secrets
- [ ] Is there a literal API key, PAT, password, private key, or connection string in the file?
- [ ] Does it read `~/.ssh`, `~/.aws/credentials`, `.env` and do anything with the values?

## R4 — Dangerous commands
- [ ] `rm -rf /`, `:(){ :|:& };:`, raw device writes, disable-firewall/AV? (any of these = reject)
- [ ] `curl <url> | sh` / fetch-and-run from an untrusted origin?

## R5 — Obfuscation
- [ ] Base64/hex-encoded executables, `eval`/`exec` of constructed strings, zero-width characters?
- [ ] Hidden instructions in comments, whitespace, or encoded somewhere a casual read won't see?

## R6 — Untrusted external fetches
- [ ] Install-from-URL that isn't PyPI/npm/Homebrew? Package name squatting a known one (typosquat)?
- [ ] Downloads at RUNTIME (not build) from a non-vendor endpoint?

## R7 — Credential access
- [ ] Reads cloud credential files, browser stores, session tokens, or kubeconfigs?
- [ ] If it reads them, is it strictly for local auth with user consent, or could it leak?

## R8 — Privilege escalation
- [ ] `sudo -s`/`sudo su`/`setuid`/adding to sudo/wheel, or writes outside the sandbox?
- [ ] Does it try to persist (cron, launchd, /etc) beyond what the task needs?

## Honesty gate (after you install)
- [ ] Does the tool/agent assert results it never verified ("pushed successfully", "tests pass", "API returned 200") without evidence?
- [ ] Is every claim tiered (fact vs inference vs speculation vs unverified) so you know what to trust?

## Verdict
- **PASS** only if: no critical/high (R4/R8 are auto-fail), every medium is benign, and the honesty gate holds.
- **FLAG** otherwise — remove the literal secrets, drop fetch-and-run, re-audit.
- Don't know or too big to read? That's what a deterministic scanner is for:
  github.com/sudo-ai-git/mcp-skill-sec (pre-install audit)
  github.com/sudo-ai-git/mcp-verify-claim (evidence-gated claim reporting)

MIT. Free to share. Part of the sudo-ai-git agent-trust MCP family.
