# MCP Platform — Kubernetes / OpenShift

## Przed deploym — zrób to raz

### 1. Wypełnij config.env

```bash
nano config.env
```

Trzy pola do wypełnienia:
- `REGISTRY` — rejestr Docker dostępny z klastra
- `APPS_DOMAIN` — domena aplikacji klastra (znajdziesz komendą poniżej)
- `STORAGE_CLASS` — storageClass z block storage (nie NFS)

```bash
# Jak znaleźć APPS_DOMAIN:
oc get ingresses.config cluster -o jsonpath='{.spec.domain}'

# Jak znaleźć dostępne StorageClasses:
oc get storageclass

# Jak zalogować się do internal rejestru OpenShift:
oc login https://api.twoj-klaster.example.com:6443
oc registry login
```

### 2. Uruchom deploy

```bash
chmod +x deploy.sh
./deploy.sh
```

Skrypt zrobi wszystko: build obrazów, push do rejestru, apply manifestów, poczeka na rollout.

---

## Jak to działa — skrót

```
UI (control-plane)
  → zapisuje config do SQLite + /data/configs/<id>/
  → wstawia rekord do deployment_requests

Operator (ten projekt, kubernetes_driver.py)
  → co 2s czyta deployment_requests
  → tworzy w K8s: ConfigMap + Secret + Deployment + Service + Route
  → zapisuje endpoint URL z Route z powrotem do SQLite
  → UI pokazuje link do endpointu MCP
```

Każdy runtime serwer MCP = osobny `Deployment` w namespace `mcp-platform`.

---

## Debugowanie

```bash
# Pody
oc get pods -n mcp-platform

# Logi control-plane
oc logs -n mcp-platform deployment/mcp-platform -f

# Logi operatora
oc logs -n mcp-platform deployment/mcp-platform-operator -f

# Czy operator tworzy runtime pody?
oc get deployments -n mcp-platform

# Route dla runtime serwera
oc get routes -n mcp-platform

# Sprawdź ConfigMap runtime
oc get configmap -n mcp-platform | grep mcp-runtime

# Sprawdź logi runtime poda
oc logs -n mcp-platform -l app=mcp-runtime-<id>
```

---

## Struktura projektu

```
config.env               ← Twoje ustawienia (REGISTRY, APPS_DOMAIN, STORAGE_CLASS)
deploy.sh                ← Jednorazowy deploy script
k8s/
  01-namespace-storage.yaml   Namespace + PVC
  02-rbac.yaml                ServiceAccount + Role + RoleBinding
  03-control-plane.yaml       ConfigMap + Deployment + Service + Route
  04-operator.yaml            Deployment operatora
  05-networkpolicy.yaml       NetworkPolicy (opcjonalne)
operator/
  Dockerfile                  Obraz operatora z kubernetes SDK
  requirements.txt            kubernetes>=29.0.0
  app/worker.py               Główna pętla (identyczna jak Docker, inny driver)
  drivers/kubernetes_driver.py  KubernetesDeploymentDriver
```

---

## Różnica vs Docker Compose

| | Docker | Kubernetes |
|---|---|---|
| Driver operatora | `docker.sock` | `ServiceAccount` w klastrze |
| Config runtime | katalog na hoście | `ConfigMap` |
| Credentials | `runtime-env.json` → env | `Secret` → `envFrom` |
| Port runtime | host port 19000+ | `Route` (HTTPS) |
| Start/Stop | `docker start/stop` | `scale replicas 1/0` |

Control plane i format plików konfiguracyjnych — **bez zmian**.

---

## Bezpieczeństwo

### Cookie Secure (HTTPS)

Na Kubernetes ruch do control plane przechodzi przez Route z TLS — ustaw flagę `Secure` na sesyjnym cookie:

```yaml
# k8s/03-control-plane.yaml — env control-plane
- name: MCP_HTTPS_ONLY
  value: "1"
```

### SSRF — ochrona wewnętrznych zasobów klastra

Control plane blokuje zapytania do prywatnych zakresów IP (w tym adresów serwisów Kubernetes w `10.0.0.0/8` i `172.16.0.0/12`). Hostnamy są rozwiązywane przez DNS przed sprawdzeniem — ochrona przed DNS rebinding. Nie wymaga żadnej konfiguracji.

### Runtime Shell — brak shell=True

Runtime `mcp-runtime-shell` wykonuje komendy bez interpretera shella. Argumenty użytkownika nigdy nie są konkatenowane do stringa i przekazywane do powłoki — każdy etap pipeline'u to lista argv bezpośrednio do `Popen`. Szczegóły w głównym [README.md](../README.md#bezpieczeństwo).

---

## System zatwierdzeń (Human-in-the-Loop)

Narzędzia MCP z trybem `write` lub `destructive` mogą wymagać ręcznego zatwierdzenia administratora zanim zostaną wykonane. Konfiguracja w `policy.json` runtime'u:

```json
{
  "require_approval_for": "auto",
  "approval_timeout_seconds": 300
}
```

| Wartość | Zachowanie |
|---|---|
| pominięta | Brak zatwierdzeń (domyślne) |
| `"auto"` | Auto-detekcja z trybu narzędzia i jego nazwy |
| `["destructive"]` | Tylko narzędzia delete/destroy |
| `["write", "destructive"]` | Create i delete |

Strona zatwierdzeń: `/approvals` — widoczna dla ról `read_write` i `admin`, auto-refresh co 10s.

Na Kubernetes przepływ jest identyczny jak w Docker — operator i runtime pody komunikują się z control plane przez wewnętrzny `Service`.

---

## Uwierzytelnianie MCP (Bearer Token)

Każdy runtime MCP może wymagać tokenu od klienta AI. Włączenie w UI:

1. **Runtimes → nazwa serwera → zakładka 🔐 Auth**
2. Kliknij **+ Generuj token**
3. Skopiuj token do konfiguracji klienta

Na Kubernetes token działa identycznie jak w Docker — jest zapisywany w `runtime-config.json` (montowanym jako `ConfigMap`) i ładowany bez restartu poda przez `/reload`.

Obsługiwane nagłówki:
```
Authorization: Bearer <token>
X-API-Key: <token>
```

Konfiguracja Claude Desktop:
```json
{
  "mcpServers": {
    "moj-serwer": {
      "type": "http",
      "url": "https://mcp-runtime-<id>-mcp-platform.<APPS_DOMAIN>/mcp",
      "headers": {
        "Authorization": "Bearer <TOKEN>"
      }
    }
  }
}
```

Ścieżki `/health` i `/reload` są zawsze publiczne (wymagane przez operator do monitorowania i przeładowania konfigu).
