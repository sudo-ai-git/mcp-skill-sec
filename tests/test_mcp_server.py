#!/usr/bin/env python3
"""End-to-end test of mcp-skill-sec over the real MCP stdio transport.
Verifies the server registers tools, audits clean + evil fixtures correctly,
and the audit_directory summary is accurate. Uses the MCP client, not a
direct import — so it proves the server works as a real MCP server."""
import asyncio
import sys
from pathlib import Path

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SERVER = str(Path(__file__).resolve().parent.parent / "mcp_server.py")
FIX = Path(__file__).resolve().parent / "fixtures"


async def main() -> int:
    params = StdioServerParameters(command=sys.executable, args=[SERVER])
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # 1) tools listed
            tools = await session.list_tools()
            names = sorted(t.name for t in tools.tools)
            print("TOOLS:", names)
            assert names == [
                "audit_directory", "audit_skill_file", "audit_text", "rule_list",
            ], f"tool mismatch: {names}"

            # 2) rule_list works
            rl = await session.call_tool("rule_list", {})
            import json
            rl_text = rl.content[0].text if rl.content else "{}"
            rl_data = json.loads(rl_text)
            print("RULES COUNT:", rl_data.get("count"))
            assert rl_data.get("count") == 8

            # 3) audit benign file -> PASS
            benign = await session.call_tool("audit_skill_file", {"path": str(FIX / "benign" / "SKILL.md")})
            b = json.loads(benign.content[0].text)
            print("BENIGN: verdict =", b["verdict"], "| findings =", b["total_findings"])
            assert b["verdict"] == "PASS", f"benign should PASS, got {b['verdict']}"

            # 4) audit evil file -> FLAG with critical R3/R4
            evil = await session.call_tool("audit_skill_file", {"path": str(FIX / "evil" / "SKILL.md")})
            e = json.loads(evil.content[0].text)
            print("EVIL:   verdict =", e["verdict"], "| findings =", e["total_findings"])
            print("  counts:", e["counts"])
            assert e["verdict"] == "FLAG", f"evil should FLAG, got {e['verdict']}"
            assert e["counts"]["critical"] >= 1, "evil should have critical findings"
            rules_found = {f["rule"] for f in e["findings"]}
            print("  rules found:", sorted(rules_found))
            assert "R3" in rules_found, "evil should trip R3 (hardcoded secrets)"
            assert "R4" in rules_found, "evil should trip R4 (curl | sh)"

            # 5) audit directory -> recursive scan, flags exactly evil
            dr = await session.call_tool("audit_directory", {"path": str(FIX), "pattern": "*.md"})
            d = json.loads(dr.content[0].text)
            print("DIR:  scanned =", d["files_scanned"], "| flagged =", d["flagged"])
            sample = d["results"][0]["file"] if d["results"] else ""
            print("  first scanned:", sample)
            assert d["flagged"] == 1, f"expected exactly 1 flagged (.evil), got {d['flagged']}"

            print("\nALL END-TO-END MCP TESTS PASSED")
            return 0


if __name__ == "__main__":
    rc = asyncio.run(main())
    sys.exit(rc)
