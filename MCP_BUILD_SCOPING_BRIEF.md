# What a custom agent→data build looks like (30-second read)

You've told an agent to "go check the system / move a change / answer from our
own data." It can't — because there's no safe connector between the agent and
the thing it needs to reach. That gap is a **custom MCP server build**. Here is
exactly what that is, what it costs, and what you get.

## What you get in a build

1. **A single MCP server** that exposes the operations you actually use with
   your agent — query, check, and (guarded) mutate. Deterministic, no-LLM inside,
   no network calls beyond your own systems.
2. **Auth + audit built in.** The server only does what the operator's permission
   allows, and every mutation is written to an audit log a reviewer can read.
3. **Evidence-gated output.** The agent is forced to report *what it actually
   ran and saw* (exit code, real read-back, real status), not a guess. "It
   passed" becomes "ran `x`, exit 0, output: ...".
4. **Delivery in your tree.** Source in your repo, self-hostable, deployable
   anywhere MCP runs (Claude Code, Cursor, Copilot, Codex CLI, any MCP client).

## What it typically costs (honest ranges)

| Scope | What it covers | Range |
|---|---|---|
| **Single connector** | One data source or operation surface, auth, audit, evidence gate | $8K–$15K |
| **Multi-surface** | 2–4 sources or a set of guarded operations, role model, audit trail | $20K–$40K |
| **Enterprise / HIPAA-grade** | Hardened auth, highest security bar, compliance review, SLA | $40K–$60K+ |

Cost scales with the *security and auth surface*, not the number of tools. A
read-only connector on an internal API is the low end; a server that can
mutate production state under tight permissions is the high end.

## Why the "deterministic, no-LLM" part matters

The server is a pure protocol layer. It does not reason, does not guess, does
not phone home. That means: the same input always gives the same result, it
can run air-gapped, and a security reviewer can audit it line by line. The
agent stays the weak point — which is exactly why the evidence gate exists.

## Proof we can ship these

Two servers are public and pass the official 8-point MCP supply-chain
security scan (deterministic, no-LLM, MIT):
- github.com/sudo-ai-git/mcp-skill-sec    (pre-install skill/security audit)
- github.com/sudo-ai-git/mcp-verify-claim (evidence-gated claim reporting)

## The ask

A 30-minute scoping call, no commitment. We map one of your real agent→data
pain points to a concrete fixed-price build and you leave with a written scope
even if you don't build with us. Reply here and we'll set it up.

—
MCP Build Service · mcp-builds@agentmail.to · part of the sudo-ai-git
agent-trust MCP family.
