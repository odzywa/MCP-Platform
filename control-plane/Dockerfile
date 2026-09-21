FROM registry.access.redhat.com/ubi9/python-312-minimal

# Obraz bazowy działa jako 1001 — instalacja wymaga roota.
USER 0

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir --root-user-action=ignore -r requirements.txt
COPY app ./app

# OpenShift uruchamia kontener z losowym UID w grupie 0, więc grupa musi mieć
# te same prawa co właściciel. fix-permissions to narzędzie UBI do tego celu.
RUN fix-permissions /app

# Numeryczny UID: kubelet potrafi zweryfikować runAsNonRoot tylko dla liczby.
# 1000 = właściciel katalogu ./data w docker-compose. Grupa 0 = konwencja OpenShift.
USER 1000:0

ENV MCP_PLATFORM_DB=/data/mcp_platform.db
ENV MCP_PLATFORM_CONFIG_ROOT=/data/configs

EXPOSE 8080
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8080"]
