#!/usr/bin/env bash
# deploy.sh — MCP Platform → OpenShift
# Użycie: ./deploy.sh
# Przed uruchomieniem: wypełnij config.env i zaloguj się do klastra (oc login)

set -euo pipefail
cd "$(dirname "$0")"

source config.env

for _var in REGISTRY PULL_REGISTRY APPS_DOMAIN NAMESPACE; do
  if [ -z "${!_var:-}" ]; then
    echo "BŁĄD: $_var nie jest ustawione w config.env" >&2
    exit 1
  fi
done

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

# ── 0. Silnik kontenerowy ─────────────────────────────────────────────────────
# Skrypt działa na podmanie albo na dockerze — nie wymaga obu naraz.
# Wymuszenie: CONTAINER_ENGINE=docker ./deploy.sh
ENGINE="${CONTAINER_ENGINE:-}"
if [ -z "$ENGINE" ]; then
  if command -v podman &>/dev/null;  then ENGINE=podman
  elif command -v docker &>/dev/null; then ENGINE=docker
  else
    echo "BŁĄD: nie znaleziono ani podmana, ani dockera" >&2
    exit 1
  fi
fi
command -v "$ENGINE" &>/dev/null || { echo "BŁĄD: $ENGINE niedostępny" >&2; exit 1; }

# Do rejestru OpenShift pchamy podmanem, bo --tls-verify=false rozwiązuje
# problemy z samopodpisanym CA bez grzebania w konfiguracji demona.
# Gdy jest tylko docker, pchamy dockerem — wymaga wtedy wpisu w
# /etc/docker/daemon.json: {"insecure-registries": ["<REGISTRY_HOST>"]}
if command -v podman &>/dev/null; then PUSH_ENGINE=podman; else PUSH_ENGINE=docker; fi

# Obrazy zbudowane dockerem, a pchane podmanem, trzeba przenieść między
# magazynami przez transport docker-daemon:. Przy jednym silniku to zbędne.
NEED_TRANSFER=false
[ "$ENGINE" = docker ] && [ "$PUSH_ENGINE" = podman ] && NEED_TRANSFER=true

echo "  Silnik      : $ENGINE (push: $PUSH_ENGINE$([ "$NEED_TRANSFER" = true ] && echo ", przez docker-daemon:"))"
echo ""

# ── 1. Buduj obrazy ────────────────────────────────────────────────────────────
echo "[1/6] Budowanie obrazów..."

# Budujemy wprost, bez compose — deploy potrzebuje dokładnie tych pięciu obrazów,
# a `compose` nie jest dostępne w każdej instalacji podmana.
# Format: <nazwa obrazu>|<katalog kontekstu>
IMAGES="
mcp-platform-operator-k8s|./operator
mcp-platform-control-plane|$PARENT_DIR/control-plane
mcp-runtime-http-gateway|$PARENT_DIR/runtime-http-gateway
mcp-runtime-shell|$PARENT_DIR/runtime-shell
mcp-runtime-openapi|$PARENT_DIR/runtime-openapi
"

while IFS='|' read -r img ctx; do
  [ -z "$img" ] && continue
  echo "  budowanie $img:latest  (kontekst: $ctx)"
  # Błąd builda nie przerywa deployu — może istnieć obraz zbudowany wcześniej.
  # Komunikat musi być widoczny, więc bez 2>/dev/null.
  "$ENGINE" build -t "$img:latest" "$ctx" || \
    echo "  UWAGA: build $img nieudany — spróbuję użyć istniejącego obrazu"
done <<< "$IMAGES"

# ...ale pchać można tylko to, co faktycznie istnieje.
require_image() {
  "$ENGINE" image inspect "$1" >/dev/null 2>&1 || {
    echo "BŁĄD: brak obrazu $1 w magazynie $ENGINE — zbuduj go przed deployem" >&2
    exit 1
  }
}
while IFS='|' read -r img _; do
  [ -z "$img" ] && continue
  require_image "$img:latest"
done <<< "$IMAGES"

# ── 2. Push obrazów do rejestru ───────────────────────────────────────────────
echo "[2/6] Push obrazów do rejestru..."

# Logowanie do rejestru OpenShift. --tls-verify=false (podman) omija problemy
# z samopodpisanym CA; docker nie ma odpowiednika i wymaga insecure-registries.
TLS_FLAG=""
[ "$PUSH_ENGINE" = podman ] && TLS_FLAG="--tls-verify=false"

REGISTRY_HOST="${REGISTRY%%/*}"

# Poświadczenia w kolejności: jawne z config.env → sesja oc → brak.
# Hasło zawsze przez --password-stdin: przy -p token byłby widoczny
# w `ps` dla każdego użytkownika maszyny.
if [ -n "${REGISTRY_USER:-}" ]; then
  echo "  logowanie do $REGISTRY_HOST jako $REGISTRY_USER (z config.env)"
  # shellcheck disable=SC2086
  printf '%s' "${REGISTRY_PASSWORD:-}" | \
    "$PUSH_ENGINE" login $TLS_FLAG -u "$REGISTRY_USER" --password-stdin "$REGISTRY_HOST" || {
      echo "BŁĄD: logowanie do $REGISTRY_HOST nieudane — sprawdź REGISTRY_USER/REGISTRY_PASSWORD" >&2
      exit 1
    }
else
  # Wbudowany rejestr OpenShift uwierzytelnia się SAMYM TOKENEM — nazwa
  # użytkownika jest ignorowana przez rejestr, ale musi być niepusta.
  #
  # Celowo NIE używamy `oc whoami` do jej ustalenia: to polecenie odpytuje
  # API serwera i zwraca pustą wartość, gdy API jest nieosiągalne lub sesja
  # wygasła — podczas gdy `oc whoami -t` czyta token z kubeconfig i zwraca go
  # zawsze. Kombinacja "pusty użytkownik + poprawny token" kończy się myląco
  # brzmiącym błędem: invalid username/password.
  OC_TOKEN=$(oc whoami -t 2>/dev/null || true)
  if [ -n "$OC_TOKEN" ]; then
    # Dowolna niepusta nazwa; rejestr OpenShift patrzy wyłącznie na token.
    OC_USER=unused
    echo "  logowanie do $REGISTRY_HOST tokenem sesji oc (użytkownik: $OC_USER)"
    # shellcheck disable=SC2086
    printf '%s' "$OC_TOKEN" | \
      "$PUSH_ENGINE" login $TLS_FLAG -u "$OC_USER" --password-stdin "$REGISTRY_HOST" || \
      echo "  UWAGA: logowanie nieudane — push najpewniej padnie za chwilę"
  else
    echo "  UWAGA: brak sesji oc i brak REGISTRY_USER — push bez uwierzytelnienia"
  fi
fi

push() {
  local src="$1" dst="$REGISTRY/$2"
  echo "  $src → $dst"
  # Każdy krok musi się udać — inaczej wypchnęlibyśmy stary obraz pod tym samym tagiem.
  if [ "$NEED_TRANSFER" = true ]; then
    # Obraz siedzi w demonie dockera, a pchamy podmanem — przenieś między magazynami.
    # shellcheck disable=SC2086
    "$PUSH_ENGINE" pull $TLS_FLAG "docker-daemon:${src}"
  fi
  "$PUSH_ENGINE" tag "$src" "$dst"
  # shellcheck disable=SC2086
  "$PUSH_ENGINE" push $TLS_FLAG "$dst"
}

push "mcp-platform-control-plane:latest"  "mcp-platform-control-plane:latest"
push "mcp-platform-operator-k8s:latest"   "mcp-platform-operator-k8s:latest"
push "mcp-runtime-http-gateway:latest"    "mcp-runtime-http-gateway:latest"
push "mcp-runtime-shell:latest"           "mcp-runtime-shell:latest"
push "mcp-runtime-openapi:latest"         "mcp-runtime-openapi:latest"

# ── 3. Podstaw wartości w manifestach ─────────────────────────────────────────
echo "[3/6] Przygotowywanie manifestów..."

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
echo "[4/6] Aplikowanie manifestów..."

oc apply -f "$WORK_DIR/01-namespace-storage.yaml"
oc apply -f "$WORK_DIR/02-rbac.yaml"

# Presety Tool Package z ../templates/ — obraz control-plane ich nie zawiera
oc create configmap mcp-platform-templates -n "$NAMESPACE" \
  --from-file="$PARENT_DIR/templates/openshift-mcp/" \
  --dry-run=client -o yaml | oc apply -f -

# 04 przed 03: dostarcza ConfigMapę mcp-operator-env, którą pod control-plane
# wciąga przez envFrom w kontenerze operatora
oc apply -f "$WORK_DIR/04-operator.yaml"
oc apply -f "$WORK_DIR/03-control-plane.yaml"
oc apply -f "$WORK_DIR/05-networkpolicy.yaml"

# Migracja ze starego układu: operator miał własny Deployment, teraz jest
# drugim kontenerem w podzie mcp-platform. Usuń osierocony Deployment.
oc delete deployment mcp-platform-operator -n "$NAMESPACE" --ignore-not-found

rm -rf "$WORK_DIR"

# ── 5. Wymusz rollout (nowy obraz pod tym samym tagiem) i czekaj ─────────────
echo "[5/6] Czekam na gotowość control-plane..."
oc rollout restart deployment/mcp-platform -n "$NAMESPACE"
oc rollout status deployment/mcp-platform -n "$NAMESPACE" --timeout=180s

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
