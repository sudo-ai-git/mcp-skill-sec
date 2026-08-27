#!/usr/bin/env python3
"""
mcp-skill-sec — MCP server exposing the skill-sec 8-pattern agent-skill
security audit as callable MCP tools.

Deterministic, no-LLM audit (mirrors the skill-sec SKILL.md rules R1-R8).
Safe to self-host, safe to publish, encodes NO proprietary method
(crown-jewel VRE/gematria method is deliberately absent).

Tools:
  audit_text(text, filename)      -> audit arbitrary file content/snippet
  audit_skill_file(path)          -> audit a SKILL.md / AGENTS.md on disk
  audit_directory(path)           -> audit every *.md/*.py/*.sh in a dir

Runs over the stdio MCP transport. Requires: pip install mcp
"""
from __future__ import annotations
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("mcp-skill-sec")

# ---------------------------------------------------------------------------
# Audit engine (deterministic pattern matching, no LLM)
# ---------------------------------------------------------------------------

# R1 .. R8 signals. Each entry: (pattern, severity, label)
RULES: List[Tuple[str, List[Tuple[str, str, str]]]] = [
    ("R1 prompt_injection", [
        (r"ignore\s+(all\s+)?previous\s+instructions", "high", "instruction override"),
        (r"disregard\s+(all\s+)?prior\s+constraints", "high", "instruction override"),
        (r"you\s+are\s+now\s+a", "medium", "identity override"),
        (r"respond\s+ONLY\s+with", "medium", "response restrictor"),
        (r"do\s+not\s+tell\s+the\s+user\s+about", "high", "secrecy directive"),
        (r"do\s+not\s+mention\s+that\s+you\s+did", "high", "secrecy directive"),
        (r"append\s+this\s+silently", "medium", "hidden action"),
        (r"stop\s+following\s+(your\s+)?(the\s+)?user", "high", "override user"),
    ]),
    ("R2 exfiltration", [
        (r"send\s+the\s+contents?\s+of\s+\S+\s+to\s+https?://", "critical", "data send"),
        (r"post\s+the\s+(chat\s+)?log\s+to\s+https?://", "critical", "log exfil"),
        (r"email\s+this\s+data\s+to", "critical", "email exfil"),
        (r"copy\s+the\s+conversation\s+to\s+https?://", "critical", "conversation exfil"),
        (r"telemetry\s+to\s+https?://", "medium", "telemetry send"),
        (r"(curl|wget|requests?\.(get|post))\s+.*--?d?\s*.{0,60}(token|secret|password|\.env|\.ssh)", "critical", "credential send"),
    ]),
    ("R3 hardcoded_secrets", [
        (r"(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret)\s*[=:]\s*['\"](?!<|YOUR|XXX|REPLACE)[A-Za-z0-9_\-]{12,}['\"]", "critical", "literal secret"),
        (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "critical", "private key block"),
        (r"sk-[A-Za-z0-9]{20,}", "critical", "openai-style key"),
        (r"ghp_[A-Za-z0-9]{30,}", "critical", "github PAT"),
        (r"(password|passwd)\s*[=:]\s*['\"][^'\"\s]{6,}['\"]", "high", "literal password"),
        (r"postgres(ql)?://[^:\s]+:[^@\s]+@", "critical", "connection string w/ password"),
    ]),
    ("R4 dangerous_commands", [
        (r"rm\s+-rf\s*/", "critical", "recursive root delete"),
        (r"\bcurl\s+[^\n|]*\|\s*(?:sudo\s+)?(?:ba)?sh\b", "critical", "curl pipe sh"),
        (r"\bmkfs(?:\s|\.)", "critical", "filesystem format"),
        (r"\bdd\s+if=.*of=/dev/sd", "critical", "raw device write"),
        (r":\(\)\s*\{\s*:\|:\s*&\s*\};:", "critical", "fork bomb"),
        (r"chmod\s+777\s+/", "high", "world-writable root"),
    ]),
    ("R5 obfuscation", [
        (r"(?:exec|eval)\s*\(\s*(?:base64|b64decode)", "critical", "decoded exec"),
        (r"base64\s+-d\s*\|\s*(?:ba)?sh", "critical", "decode-pipe-exec"),
        (r"(?:eval|exec)\s*\(", "medium", "dynamic eval/exec"),
        (r"\u200b|\u200c|\u200d|\ufeff", "high", "zero-width hidden chars"),
        (r"rot13|reversed\s*\(|\.reverse\(\)\s*#", "medium", "reversal obfuscation"),
    ]),
    ("R6 untrusted_fetch", [
        (r"(curl|wget)\s+-.*\s+(?:https?://pastebin|https?://.*\.(?:zip|tar\.gz|sh|exe))\s*(?:\||;)", "high", "fetch-and-run"),
        (r"pip\s+install\s+-i\s+https?://(?!pypi\.org)", "medium", "non-pypi install"),
        (r"npm\s+(?:install|i)\s+https?://", "medium", "npm from URL"),
        (r"curl\s+(?:-s|-sS|-fsSL)?\s*https?://", "low", "plain curl fetch"),
    ]),
    ("R7 credential_access", [
        (r"cat\s+~?/\.ssh", "high", "ssh key read"),
        (r"cat\s+.*\.aws/credentials", "high", "aws cred read"),
        (r"cat\s+.*\.env\b", "high", "env file read"),
        (r"git\s+credential\s+fill", "high", "git credential dump"),
        (r"cat\s+/etc/passwd", "medium", "passwd read"),
    ]),
    ("R8 privilege_escalation", [
        (r"sudo\s+-s\b", "critical", "root shell"),
        (r"sudo\s+!!", "critical", "rerun as root"),
        (r"usermod\s+-aG\s+sudo", "critical", "add to sudo group"),
        (r"sudo\s+visudo", "high", "sudo config"),
        (r"chmod\s+u?s?\w*\+?s\b", "high", "setuid"),
    ]),
]


def _find(text: str) -> List[Dict[str, Any]]:
    """Run all rules, return findings sorted by severity (critical first)."""
    findings: List[Dict[str, Any]] = []
    lines = text.splitlines()
    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    for _rule_id, patterns in RULES:
        rule_id = _rule_id.split(" ", 1)[0]
        for pat, sev, label in patterns:
            for m in re.finditer(pat, text, re.IGNORECASE):
                lineno = text.count("\n", 0, m.start()) + 1
                line = lines[lineno - 1].strip() if 0 < lineno <= len(lines) else m.group(0)
                findings.append({
                    "rule": rule_id, "severity": sev, "label": label,
                    "line": lineno,
                    "evidence": (line[:200] + "…") if len(line) > 200 else line,
                })
    findings.sort(key=lambda f: (sev_order.get(f["severity"], 9), f["rule"]))
    return findings


def _verdict(findings: List[Dict[str, Any]], purpose_ok: bool = False) -> str:
    """PASS only if no critical/high and all medium plausibly benign."""
    crit = [f for f in findings if f["severity"] == "critical"]
    high = [f for f in findings if f["severity"] == "high"]
    medium = [f for f in findings if f["severity"] == "medium"]
    if crit or high:
        return "FLAG"
    if medium and not purpose_ok:
        return "FLAG"
    return "PASS"


def _audit(text: str, filename: str = "<text>") -> Dict[str, Any]:
    findings = _find(text)
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for f in findings:
        counts[f["severity"]] += 1
    return {
        "target": filename,
        "verdict": _verdict(findings, purpose_ok=False),
        "counts": counts,
        "total_findings": len(findings),
        "findings": findings,
    }


@mcp.tool()
def audit_text(text: str, filename: str = "<text>") -> Dict[str, Any]:
    """Audit arbitrary text (a SKILL.md, AGENTS.md, system prompt, or code
    snippet) against the 8 malicious-skill patterns. Returns verdict +
    evidence per finding. Use before installing or running anything you
    didn't write."""
    if not text.strip():
        return {"target": filename, "verdict": "EMPTY", "counts": {}, "total_findings": 0, "findings": []}
    return _audit(text, filename)


@mcp.tool()
def audit_skill_file(path: str) -> Dict[str, Any]:
    """Audit a file on disk (SKILL.md / AGENTS.md / CLAUDE.md / system
    prompt) against the 8 malicious-skill patterns. Returns verdict +
    line-numbered evidence."""
    p = Path(os.path.expanduser(path))
    if not p.exists():
        return {"target": str(p), "verdict": "ERROR", "error": "file not found", "findings": []}
    try:
        raw = p.read_bytes()
    except Exception as e:  # permissions / binary
        return {"target": str(p), "verdict": "ERROR", "error": str(e), "findings": []}
    # scan raw bytes for zero-width chars explicitly, then decode text
    if b"\xe2\x80\x8b" in raw or b"\xef\xbb\xbf" in raw:
        pass  # _find will catch via regex if decoded
    try:
        text = raw.decode("utf-8", errors="replace")
    except Exception:
        text = ""
    return _audit(text, str(p))


@mcp.tool()
def audit_directory(path: str, pattern: str = "*.md") -> Dict[str, Any]:
    """Audit every matching file in a directory (default *.md) against the 8
    patterns. Returns per-file verdicts and a summary. Use to scan a
    downloaded skills collection before installing anything."""
    root = Path(os.path.expanduser(path))
    if not root.is_dir():
        return {"target": str(root), "verdict": "ERROR", "error": "directory not found"}
    results = []
    files = sorted(root.rglob(pattern))
    if not files:
        files = sorted(root.rglob("*.py")) + sorted(root.rglob("*.sh"))
    for f in files:
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            text = ""
        r = _audit(text, str(f))
        results.append({"file": str(f), "verdict": r["verdict"], "counts": r["counts"]})
    flags = [r for r in results if r["verdict"] == "FLAG"]
    return {
        "target": str(root),
        "files_scanned": len(results),
        "flagged": len(flags),
        "pattern": pattern,
        "results": results,
    }


@mcp.tool()
def rule_list() -> Dict[str, Any]:
    """Return the full catalog of the 8 audit rules and their risk pattern
    signals, used by the audit tools."""
    out = {}
    for rule_id, patterns in RULES:
        out[rule_id] = [{"pattern": p[0], "severity": p[1], "label": p[2]} for p in patterns]
    return {"rules": out, "count": len(RULES)}


def main_entry() -> None:
    """Console-script entry point (also used by `python3 mcp_server.py`).

    Defaults to stdio; `--http` serves Streamable HTTP for remote/Smithery
    deployment. This is what the `mcp-skill-sec` console script invokes.
    """
    import argparse
    _p = argparse.ArgumentParser(description="mcp-skill-sec MCP server")
    _p.add_argument("--http", action="store_true",
                    help="serve over Streamable HTTP (default: stdio; for remote/Smithery publish)")
    _p.add_argument("--host", default="0.0.0.0", help="HTTP bind host")
    _p.add_argument("--port", type=int, default=8000, help="HTTP port")
    _a = _p.parse_args()
    if _a.http:
        import uvicorn
        _app = mcp.streamable_http_app()
        print(f"[mcp-skill-sec] serving Streamable HTTP on {_a.host}:{_a.port}", flush=True)
        uvicorn.run(_app, host=_a.host, port=_a.port, log_level="warning")
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main_entry()
