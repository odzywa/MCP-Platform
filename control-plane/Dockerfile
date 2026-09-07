FROM python:3.12-slim

RUN useradd -u 1000 -m app
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app ./app

# Numeryczny UID: kubelet potrafi zweryfikować runAsNonRoot tylko dla liczby.
# 1000 = właściciel katalogu ./data w docker-compose.
USER 1000:1000

ENV MCP_PLATFORM_DB=/data/mcp_platform.db
ENV MCP_PLATFORM_CONFIG_ROOT=/data/configs

EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
