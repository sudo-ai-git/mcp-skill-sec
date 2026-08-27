#!/usr/bin/env bash
# COMPLETE the Official MCP Registry publish — one command once you have a PyPI token.
#
# USAGE:
#   1. Create a PyPI API token:
#      https://pypi.org/manage/account/  ->  "Add API token"
#      Scope: "Entire account" (or project mcp-skill-sec)
#      Copy the token (prefix pypi-...)
#
#   2. Run:  ./publish_to_registry.sh  <your-pypi-token>
#
# It will: build -> upload sdist+wheel to PyPI -> publish server.json to the
# Official MCP Registry -> verify the live listing.
#
# Requires: python3, pip (twine, build, mcp), the mcp-publisher binary.
set -euo pipefail

TOKEN="${1:?Usage: $0 <pypi-api-token>}"
ROOT="$(cd "$(dirname "$0")" && pwd)"
PUBLISHER="${MCP_PUBLISHER:-/tmp/mcp-publisher}"
export TWINE_USERNAME="__token__"
export TWINE_PASSWORD="$TOKEN"

echo "==> 1/4 Building package..."
cd "$ROOT"
rm -rf dist build *.egg-info
python3 -m build

echo "==> 2/4 Uploading sdist+wheel to PyPI..."
python3 -m twine upload dist/*

echo "==> 3/4 Publishing to Official MCP Registry..."
"$PUBLISHER" validate server.json
"$PUBLISHER" publish server.json

echo "==> 4/4 Done. Verify at: https://registry.modelcontextprotocol.io/servers/io.github.sudo-ai-git/mcp-skill-sec"
echo "       and https://pypi.org/project/mcp-skill-sec/"
