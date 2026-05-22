FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app

ENV MCP_PLATFORM_DB=/data/mcp_platform.db
ENV MCP_PLATFORM_CONFIG_ROOT=/data/configs

EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
