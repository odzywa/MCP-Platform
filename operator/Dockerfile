FROM registry.access.redhat.com/ubi9/python-312-minimal

USER 0

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --root-user-action=ignore -r requirements.txt
COPY drivers ./drivers
COPY app ./app

ENV MCP_PLATFORM_DB=/data/mcp_platform.db
ENV MCP_PLATFORM_CONFIG_ROOT=/data/configs
ENV MCP_RUNTIME_NETWORK=ai-net
ENV MCP_RUNTIME_PUBLIC_PORT_BASE=19000

# CELOWO root: operator zarządza kontenerami przez /var/run/docker.sock,
# które należy do root:docker. Obraz bazowy UBI domyślnie działa jako 1001 —
# bez tej linii operator straciłby dostęp do gniazda i nie wdrożyłby niczego.
USER 0

CMD ["python", "-m", "app.worker"]
