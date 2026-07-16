#!/usr/bin/env bash
# deploy.sh — MCP Platform → OpenShift
# Użycie: ./deploy.sh
# Przed uruchomieniem: wypełnij config.env i zaloguj się do klastra (oc login)

set -euo pipefail
cd "$(dirname "$0")"

source config.env

# Użyj lokalnego oc jeśli nie ma w PATH
if ! command -v oc &>/dev/null && [ -f "./oc" ]; then
  export PATH="$PWD:$PATH"
fi

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  MCP Platform → OpenShift Deploy                ║"
echo "╚══════════════════════════════════════════════════╝"
echo "  Registry    : $REGISTRY"
echo "  Apps domain : $APPS_DOMAIN"
echo "  Namespace   : $NAMESPACE"
echo "  StorageClass: $STORAGE_CLASS"
echo ""

PARENT_DIR="$(cd .. && pwd)"

# ── 1. Buduj obrazy ────────────────────────────────────────────────────────────
echo "[1/5] Budowanie obrazów..."

# Operator k8s (z tego projektu)
docker build -t mcp-platform-operator-k8s:latest ./operator/

# Control plane i runtime images (z głównego projektu)
(cd "$PARENT_DIR" && docker compose build mcp-platform 2>/dev/null) || \
  echo "  UWAGA: control-plane build failed — użyj istniejącego obrazu"
(cd "$PARENT_DIR" && docker compose --profile build-only build 2>/dev/null) || \
  echo "  UWAGA: runtime images build failed — użyj istniejących obrazów"

# ── 2. Push obrazów do rejestru ───────────────────────────────────────────────
echo "[2/5] Push obrazów do rejestru..."

# Logowanie do rejestru OpenShift przez podman (--tls-verify=false omija problemy z CA)
if [[ "$REGISTRY" == *"openshift-image-registry"* ]]; then
  REGISTRY_HOST=$(echo "$REGISTRY" | cut -d'/' -f1)
  TOKEN=$(oc whoami -t 2>/dev/null || true)
  if [ -n "$TOKEN" ]; then
    podman login --tls-verify=false -u "$(oc whoami)" -p "$TOKEN" "$REGISTRY_HOST" 2>/dev/null || \
      echo "  UWAGA: podman login failed — próbuję bez logowania"
  fi
fi

push() {
  local src="$1" dst="$REGISTRY/$2"
  echo "  $src → $dst"
  # Skopiuj z docker daemon do podman, potem wypchnij
  podman pull --tls-verify=false "docker-daemon:${src}" 2>/dev/null || true
  podman tag "$src" "$dst" 2>/dev/null || true
  podman push --tls-verify=false "$dst"
}

push "mcp-platform-control-plane:latest"  "mcp-platform-control-plane:latest"
push "mcp-platform-operator-k8s:latest"   "mcp-platform-operator-k8s:latest"
push "mcp-runtime-http-gateway:latest"    "mcp-runtime-http-gateway:latest"
push "mcp-runtime-shell:latest"           "mcp-runtime-shell:latest"
push "mcp-runtime-openapi:latest"         "mcp-runtime-openapi:latest"

# ── 3. Podstaw wartości w manifestach ─────────────────────────────────────────
echo "[3/5] Przygotowywanie manifestów..."

WORK_DIR="$(mktemp -d)"
cp k8s/*.yaml "$WORK_DIR/"

# Podmień placeholdery
for f in "$WORK_DIR"/*.yaml; do
  sed -i \
    -e "s|__REGISTRY__|$REGISTRY|g" \
    -e "s|__PULL_REGISTRY__|$PULL_REGISTRY|g" \
    -e "s|__APPS_DOMAIN__|$APPS_DOMAIN|g" \
    -e "s|__NAMESPACE__|$NAMESPACE|g" \
    -e "s|__STORAGE_CLASS__|$STORAGE_CLASS|g" \
    "$f"
done

# ── 4. Aplikuj manifesty ──────────────────────────────────────────────────────
echo "[4/5] Aplikowanie manifestów..."

oc apply -f "$WORK_DIR/01-namespace-storage.yaml"
oc apply -f "$WORK_DIR/02-rbac.yaml"
oc apply -f "$WORK_DIR/03-control-plane.yaml"
oc apply -f "$WORK_DIR/04-operator.yaml"
oc apply -f "$WORK_DIR/05-networkpolicy.yaml"

rm -rf "$WORK_DIR"

# ── 5. Wymusz rollout (nowy obraz pod tym samym tagiem) i czekaj ─────────────
echo "[5/5] Czekam na gotowość control-plane..."
oc rollout restart deployment/mcp-platform -n "$NAMESPACE"
oc rollout restart deployment/mcp-platform-operator -n "$NAMESPACE"
oc rollout status deployment/mcp-platform -n "$NAMESPACE" --timeout=120s

ROUTE=$(oc get route mcp-platform -n "$NAMESPACE" --template='https://{{ .spec.host }}' 2>/dev/null || echo "")
PLATFORM_URL="${ROUTE:-https://mcp-platform-${NAMESPACE}.${APPS_DOMAIN}}"

# ── 6. Auto-konfiguracja OpenShift MCP (opcjonalna) ──────────────────────────
OC_MCP_TOKEN="${OC_MCP_TOKEN:-}"
OC_MCP_SERVER="${OC_MCP_SERVER:-}"

if [ -n "$OC_MCP_TOKEN" ] && [ -n "$OC_MCP_SERVER" ]; then
  echo "[6/6] Konfigurowanie OpenShift MCP (openshift-monitor)..."

  # Czekaj aż platforma odpowie (max 60s)
  echo "  Czekam na API platformy..."
  for i in $(seq 1 12); do
    if curl -sk "$PLATFORM_URL/health" | grep -q "ok"; then
      break
    fi
    sleep 5
  done

  # Zaloguj się i pobierz cookie sesji
  COOKIE_JAR="$(mktemp)"
  HTTP_STATUS=$(curl -sk -o /dev/null -w "%{http_code}" \
    -c "$COOKIE_JAR" \
    -X POST "$PLATFORM_URL/login" \
    -d "username=admin&password=admin" \
    -L --max-redirs 3)

  if [ "$HTTP_STATUS" != "200" ] && [ "$HTTP_STATUS" != "303" ]; then
    echo "  ⚠ Logowanie nieudane (HTTP $HTTP_STATUS) — pomiń auto-konfigurację."
    echo "    Dodaj OC_TOKEN i OC_SERVER ręcznie w UI → openshift-monitor → Secrets."
    rm -f "$COOKIE_JAR"
  else
    # Dodaj credentials
    curl -sk -b "$COOKIE_JAR" -X POST "$PLATFORM_URL/api/runtimes/openshift-monitor/credentials" \
      -d "kind=env&name=OC_TOKEN&env_name=OC_TOKEN&value=${OC_MCP_TOKEN}" > /dev/null
    curl -sk -b "$COOKIE_JAR" -X POST "$PLATFORM_URL/api/runtimes/openshift-monitor/credentials" \
      -d "kind=env&name=OC_SERVER&env_name=OC_SERVER&value=${OC_MCP_SERVER}" > /dev/null

    # Wdróż
    curl -sk -b "$COOKIE_JAR" -X POST "$PLATFORM_URL/api/runtimes/openshift-monitor/deploy" > /dev/null

    rm -f "$COOKIE_JAR"
    echo "  ✅ openshift-monitor wdrożony!"
    echo "  Endpoint MCP pojawi się za ~30s w UI → Runtimes → openshift-monitor"
  fi
else
  echo "[6/6] Pominięto auto-konfigurację OCP MCP (OC_MCP_TOKEN/OC_MCP_SERVER puste w config.env)"
fi

echo ""
echo "╔══════════════════════════════════════════════════╗"
echo "║  Deploy zakończony!                             ║"
echo "╚══════════════════════════════════════════════════╝"
echo ""
echo "UI control plane:"
echo "  $PLATFORM_URL"
echo ""
echo "Status podów:"
oc get pods -n "$NAMESPACE"
echo ""
echo "Pierwsze logowanie: admin / admin  ← zmień od razu!"
echo ""
echo "Następne kroki:"
echo "  1. Zaloguj się do UI"
echo "  2. Runtimes → openshift-monitor → dodaj OC_TOKEN + OC_SERVER → Deploy"
echo "     (lub wypełnij OC_MCP_TOKEN/OC_MCP_SERVER w config.env i przejedź deploy.sh ponownie)"
echo "  3. Skopiuj endpoint MCP z UI i wklej do klienta AI (Claude Desktop / OpenCode)"
echo "     Klucz: X-API-Key  Wartość: <token z UI → Auth → Generate token>"
