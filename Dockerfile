# mcp-skill-sec — container image for hosted/Smithery/Glama deployment
# Glama's build-test "starts your server to verify it works" probes the bound
# port (EXPOSE 8000), so the container MUST serve over HTTP. `--http` binds
# Streamable HTTP on 8000 (host/port from env, defaults 0.0.0.0:8000).
# The stdio transport stays available for local/Smithery use via the console
# script (mcp-skill-sec) / pyproject [project.scripts] — unaffected by CMD.
FROM python:3.11-slim
WORKDIR /app
COPY mcp_server.py /app/mcp_server.py
RUN pip install --no-cache-dir "mcp>=1.0,<2"
EXPOSE 8000
ENV HOST=0.0.0.0
ENV PORT=8000
# exec-form CMD does not expand ${HOST}/${PORT} (no shell), so pass the default
# values literally. Glama build-test / remote deploy binds 0.0.0.0:8000.
CMD ["python3", "/app/mcp_server.py", "--http", "--host", "0.0.0.0", "--port", "8000"]
