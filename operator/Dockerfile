FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY drivers ./drivers
COPY app ./app

ENV MCP_PLATFORM_DB=/data/mcp_platform.db
ENV MCP_PLATFORM_CONFIG_ROOT=/data/configs
ENV MCP_RUNTIME_NETWORK=ai-net
ENV MCP_RUNTIME_PUBLIC_PORT_BASE=19000

CMD ["python", "-m", "app.worker"]
