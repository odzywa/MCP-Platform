# Jak stworzyć działający MCP server od zera

Kompletna instrukcja krok po kroku — od pomysłu na tools, przez Package Generator, po działający endpoint MCP gotowy dla Continue, OpenWebUI i innych klientów.

---

## Zależności platformy — pakiety i frameworki

### mcp-platform (control plane)

| Pakiet | Wersja | Cel |
|--------|--------|-----|
| `fastapi` | ≥0.110 | Framework HTTP, routing, strony HTML |
| `uvicorn[standard]` | ≥0.29 | ASGI server |
| `httpx` | ≥0.27 | Async HTTP client (health-check runtimeów) |
| `python-multipart` | ≥0.0.9 | Obsługa formularzy HTML (`multipart/form-data`) |
| `jinja2` | ≥3.1 | Szablony HTML (używane wewnętrznie przez FastAPI) |
| `pydantic` | v2 | Walidacja requestów (wbudowane w FastAPI) |
| `sqlite3` | stdlib | Baza danych platformy (WAL mode) |

**Licencje:** MIT / Apache 2.0 — dopuszczone do użytku komercyjnego.

---

### mcp-runtime-shell

| Pakiet | Wersja | Cel |
|--------|--------|-----|
| `fastapi` | ≥0.110 | HTTP API dla runtimeu |
| `uvicorn[standard]` | ≥0.29 | ASGI server |
| `jsonschema` | ≥4.21 | Walidacja argumentów toolów wg `input_schema` |
| `subprocess` (stdlib) | — | Wykonywanie komend shell |
| `shlex` (stdlib) | — | Bezpieczne parsowanie komend (brak shell injection) |

**System:** Ubuntu 24.04 base image z `curl`, `jq`, `oc`, `kubectl`, `psql` (opcjonalnie przez Image Builder).

---

### mcp-runtime-http-gateway

| Pakiet | Wersja | Cel |
|--------|--------|-----|
| `fastapi` | ≥0.110 | HTTP API dla runtimeu |
| `uvicorn[standard]` | ≥0.29 | ASGI server |
| `httpx` | ≥0.27 | Async HTTP client do wywołań narzędzi |
| `jinja2` | ≥3.1 | Renderowanie URL/body templates (`${variable}`) |

---

### operator

| Pakiet | Wersja | Cel |
|--------|--------|-----|
| `docker` (SDK) | ≥7.0 | Zarządzanie kontenerami (create/start/stop/rm) |
| `requests` | ≥2.31 | HTTP do control plane (callback) |

---

### RAGHybrid (osobna usługa)

| Pakiet/Framework | Wersja | Cel |
|-----------------|--------|-----|
| `fastapi` | ≥0.110 | REST API endpointy |
| `uvicorn[standard]` | ≥0.29 | ASGI server |
| `sentence-transformers` | ≥2.7 | Embeddingi lokalne (model `all-MiniLM-L6-v2` i inne) |
| `pgvector` / `psycopg2` | ≥0.3 / ≥2.9 | PostgreSQL z wektorem (similarity search) |
| `neo4j` (driver) | ≥5.19 | Graf wiedzy (Cypher queries, entity relationships) |
| `rank-bm25` | ≥0.2.2 | BM25 lexical search |
| `httpx` | ≥0.27 | Async HTTP |
| `pydantic` | v2 | Modele requestów/response |
| `numpy` | ≥1.26 | Obliczenia wektorowe |

**Licencje:** MIT / Apache 2.0 / BSD — dopuszczone do użytku komercyjnego.  
Modele Sentence Transformers: Apache 2.0 (MiniLM, BGE, paraphrase-multilingual).

---

### OpenWebUI (zewnętrzna integracja)

| Komponent | Rola |
|-----------|------|
| Filter pipeline `raghybrid_auto_context` | Automatycznie dołącza kontekst RAG do promptu gdy tool jest aktywny |
| Python Tool `hybridrag_search` | Tool importowany bezpośrednio z endpointu `/api/runtimes/{id}/openwebui-tool.py` |
| Tool Server (OpenAPI) | Endpoint `/openwebui/openapi.json` — serwer narzędzi dodawany przez panel Admin → Tool Servers |

---

## Koncepcja platformy w jednym zdaniu

```
Tool Package → MCP Server (definicja) → Deploy → Runtime Container → Endpoint MCP
```

Nie piszesz kodu. Konfigurujesz tools wizualnie, platforma generuje gotowy serwer MCP.

---

## Rodzaje tools które możesz zbudować

| Typ | Co robi | Kiedy użyć |
|-----|---------|------------|
| **http_request** | Wywołuje REST API przez httpx | GitLab API, RAGHybrid, dowolne REST API |
| **shell/curl** | Wykonuje komendy w kontenerze | curl, jq, oc, kubectl, dowolne CLI |
| **shell/oc** | Komendy OpenShift read-only | oc get/describe/logs |
| **shell/ssh** | (planowane) | SSH do serwerów |

---

## ŚCIEŻKA A — HTTP Request Tool (najprostsza)

Nie potrzebujesz custom obrazu. Używasz gotowego `mcp-runtime-http-gateway:latest`.

### Przykład: Tool wywołujący dowolne REST API

---

### Krok 1 — Otwórz Package Generator

```
http://mcp.dom:18100/tool-packages
→ kliknij zielony przycisk  + Generuj paczkę
```

Lub bezpośrednio:
```
http://mcp.dom:18100/tool-packages/generate
```

---

### Krok 2 — Wypełnij metadane paczki

| Pole | Przykład | Uwagi |
|------|---------|-------|
| Nazwa paczki | `GitLab Search` | Pojawi się w kreatorze |
| Kategoria | `http` | Dla porządku |
| Risk | `low` | HTTP read-only = low |
| Opis | `Search GitLab issues and MRs` | Opcjonalny |

---

### Krok 3 — Runtime Class

| Pole | Wartość dla HTTP tools |
|------|----------------------|
| Runtime image | `mcp-runtime-http-gateway:latest` |
| Runtime class name | `http-gateway` (wpisz lub zostaw auto) |
| Execution types | ✅ tylko `http_request` |
| Security profile | `restricted` |

---

### Krok 4 — Policy

Dla HTTP read-only API:
- ✅ require_read_only
- ✅ block_write_tools
- ✅ block_destructive_tools
- Allowed binaries: *zostaw puste* (nie dotyczy HTTP)
- Timeout: `30`
- Max payload: `262144`
- Max response: `5242880`

---

### Krok 5 — Dodaj tool (http_request)

Kliknij **+ Dodaj tool**, ustaw:

| Pole | Wartość |
|------|---------|
| Nazwa | `gitlab_search` |
| Typ | `http_request` |
| Risk | `low` |
| Mode | `read-only` |
| Enabled | ✅ |
| Opis | `Search GitLab issues` |

**Sekcja HTTP config pojawi się automatycznie:**

| Pole | Wartość |
|------|---------|
| Method | `POST` |
| URL | `https://gitlab.example.com/api/v4/search` |
| Body template JSON | `{"scope": "issues", "search": "${query}"}` |
| Timeout | `30` |

**+ Dodaj pole** (input schema):

| Nazwa | Typ | Opis | Required |
|-------|-----|------|----------|
| `query` | string | Search query | ✅ |

**Podgląd JSON aktualizuje się na bieżąco.**

---

### Krok 6 — Zainstaluj paczkę

Kliknij **Zainstaluj paczkę** — platforma instaluje i przekierowuje do Tool Packages.

---

### Krok 7 — Utwórz MCP Server

```
Create (górne menu)
→ Krok 1: Wpisz nazwę np. "GitLab Assistant", wybierz paczkę "GitLab Search"
→ Krok 2: Adapters (http_request zaznacza się automatycznie)
→ Krok 3: Tools (ładują się z paczki automatycznie)
→ Krok 4: Policy (low risk)
→ Krok 5: Create MCP Server
```

---

### Krok 8 — (jeśli API wymaga tokena) Dodaj credential

Na stronie runtime → sekcja **Runtime Credentials**:

| Pole | Wartość |
|------|---------|
| Kind | `env` |
| Name | `GITLAB_TOKEN` |
| Value | `glpat-xxxxxxxxxxxx` |

Kliknij **Add Credential**.

Wróć do tool config i ustaw URL/header z `${GITLAB_TOKEN}` jeśli potrzebujesz.

---

### Krok 9 — Deploy

Na stronie runtime → kliknij **Deploy**.

Po ~2 sekundach status zmienia się na `running` (auto-refresh).
Endpoint pojawia się w sekcji Lifecycle.

---

### Krok 10 — Test Tool (w UI)

Na stronie runtime → sekcja **Test Tool**:

```
Tool: gitlab_search
Arguments: {"query": "authentication bug"}
→ Run Tool
```

Wynik pojawia się od razu na stronie.

---

### Krok 11 — Podepnij do Continue

```json
{
  "mcpServers": {
    "gitlab": {
      "url": "http://mcp.dom:PORT/mcp",
      "transport": "streamable-http"
    }
  }
}
```

Port widzisz na stronie runtime w polu Endpoint.

---

---

## ŚCIEŻKA B — Shell Tool z curl/jq

Obraz `mcp-runtime-shell:latest` ma już zainstalowane: `curl`, `jq`, `oc`, `kubectl`.

### Przykład: Tool robiący HTTP GET przez curl

---

### Krok 1 — Package Generator

```
Tool Packages → + Generuj paczkę
```

---

### Krok 2 — Metadane

| Pole | Wartość |
|------|---------|
| Nazwa | `Curl HTTP Toolkit` |
| Kategoria | `http` |
| Risk | `low` |

---

### Krok 3 — Runtime Class

| Pole | Wartość |
|------|---------|
| Runtime image | `mcp-runtime-shell:latest` |
| Runtime class name | `shell-readonly` |
| Execution types | ✅ tylko `shell` |
| Security profile | `restricted` |

---

### Krok 4 — Policy

| Pole | Wartość |
|------|---------|
| require_read_only | ✅ |
| block_write_tools | ✅ |
| block_destructive_tools | ✅ |
| **Allowed binaries** | `curl jq` |
| Timeout | `30` |

> **Ważne:** `allowed_binaries` blokuje wszystko poza wpisanymi binarkami.
> Dla curl toolkit: `curl jq`
> Dla OpenShift: `oc jq`
> Dla Kubernetes: `kubectl jq`

---

### Krok 5 — Dodaj tool (shell)

Kliknij **+ Dodaj tool**, ustaw:

| Pole | Wartość |
|------|---------|
| Nazwa | `http_get` |
| Typ | `shell` |
| Risk | `low` |
| Mode | `read-only` |

**Sekcja Shell config:**

```
Komenda: curl -s -L --max-time 20 ${url}
Timeout: 25
```

Jak pisać komendy:
- Każde słowo oddzielone spacją to osobny element tablicy komendy
- Argumenty dynamiczne: `${nazwa_parametru}`
- Przykłady:
  - `curl -s ${url}` → proste GET
  - `curl -s -H Accept: application/json ${url}` → z headerem
  - `oc get pods -n ${namespace} -o json` → OC command

**+ Dodaj pole:**

| Nazwa | Typ | Required |
|-------|-----|----------|
| `url` | string | ✅ |

---

### Krok 6—11 — identyczne jak w Ścieżce A

Instaluj → Create → Deploy → Test Tool → Connect.

---

---

## ŚCIEŻKA C — Custom obraz (np. z oc/kubectl)

Gdy potrzebujesz binarek których nie ma w bazowych obrazach.

### Krok 1 — Runtime Image Builder

```
Tool Packages → sekcja "Runtime Image Builder"
```

| Pole | Przykład |
|------|---------|
| Image tag | `mcp-runtime-oc:latest` |
| Base image | `mcp-runtime-shell:latest` |
| Runtime class name | `openshift-readonly` |
| Allowed execution types | `shell` |
| APT packages | `curl ca-certificates` |
| Pip packages | *(puste)* |
| Extra Dockerfile | patrz niżej |

**Extra Dockerfile (jeśli `oc` nie jest w base):**
```dockerfile
RUN curl -L https://mirror.openshift.com/pub/openshift-v4/clients/ocp/stable/openshift-client-linux.tar.gz \
    -o /tmp/oc.tar.gz \
    && tar -xzf /tmp/oc.tar.gz -C /usr/local/bin oc \
    && rm /tmp/oc.tar.gz
```

> **Uwaga:** `mcp-runtime-shell:latest` ma już `oc` i `kubectl`.
> Image Builder potrzebujesz tylko dla niestandardowych narzędzi.

Kliknij **Build Runtime Image** → operator buduje w tle.
Status widoczny w tabeli "Recent Image Builds" (odśwież po ~2-5 minutach).

### Krok 2 — Reszta jak Ścieżka B

Po zbudowaniu obrazu, nowa Runtime Class pojawia się w dropdownach automatycznie.

---

---

## Schemat: skąd platforma wie co uruchomić

```
Tool Package JSON
  │
  ├─ runtime_class.runtime_image  → który Docker image uruchomić
  ├─ runtime_class.name           → nazwa klasy (pojawia się w kreatorze)
  ├─ policy                       → co wolno robić w runtime
  └─ tools[]
       ├─ execution_type          → "http_request" lub "shell"
       ├─ config.command          → [dla shell] tablica komendy z ${vars}
       ├─ config.url + body       → [dla http] URL i body template
       └─ input_schema            → JSON Schema argumentów toola

→ Control plane generuje: runtime-config.json, tools.json, policy.json
→ Operator tworzy kontener z obrazem i montuje /config/
→ Runtime container ładuje config i wystawia /mcp endpoint
```

---

---

## Format komendy shell — cheat sheet

```
Wpisujesz w generatorze:       Staje się tablicą:
─────────────────────────────────────────────────────
curl -s ${url}              →  ["curl", "-s", "${url}"]
oc get pods -n ${ns}        →  ["oc", "get", "pods", "-n", "${ns}"]
curl -H Accept: app/json    →  ["curl", "-H", "Accept: app/json", ...]
```

**Jak działają zmienne `${variable}`:**

```
Tool config:   ["curl", "-s", "${url}"]
User calls:    {"url": "https://example.com/api"}
Runtime exec:  subprocess.run(["curl", "-s", "https://example.com/api"])
```

Parametr jest podstawiany jeden do jednego w odpowiednie miejsce tablicy.
Nie ma shell injection — subprocess.run nie używa shell=True.

---

---

## Gotowe paczki w katalogu

Kliknij **Tool Packages** → są zainstalowane:

| Paczka | Co robi | Runtime |
|--------|---------|---------|
| `curl-http-toolkit` | GET, POST, status check przez curl | shell |
| `raghybrid-assistant` | RAGHybrid context/search/sources/health | http-gateway |
| `openshift-readonly` | oc get/logs/events/describe | shell |

Żeby użyć: kliknij **Create MCP** przy paczce → wpisz nazwę → Deploy.

---

---

## Integracja z OpenWebUI

### Tool Server (zalecane — wiele narzędzi naraz)

Każdy runtime wystawia endpoint `GET /openwebui/openapi.json` z pełnym OpenAPI spec.

Adres do wpisania w OpenWebUI → Admin → Tool Servers:
```
http://mcp.dom:PORT/openwebui
```

> **Uwaga:** wpisz `/openwebui`, nie `/openwebui/openapi.json` — OpenWebUI sam doda `/openapi.json`.

OpenWebUI wysyła wywołania narzędzi na `POST /openwebui/tools/{tool_name}`.

### Python Tool (import przez link)

Na stronie runtime → sekcja **Połączenia** → link **OpenWebUI Python Tool**.
Skopiuj link i w OpenWebUI → Tools → Import from URL.
Link ma format: `http://mcp.dom:18100/api/runtimes/{id}/openwebui-tool.py`

### Logowanie wywołań (Wywołania tab)

Każde wywołanie toola jest logowane z:
- czas, nazwa narzędzia, status (OK/ERR), czas wykonania
- **IP źródłowe** — z nagłówka `X-Forwarded-For` / `X-Real-IP` lub bezpośrednio
- **Nazwa modelu** — z nagłówka `X-Model` / `X-OpenWebUI-Model` / `X-AI-Model`

Logi dostępne w Runtime detail → zakładka **Wywołania** oraz globalnie w `/audit` → **Wywołania AI**.

---

---

## Gdzie patrzeć gdy coś nie działa

### Runtime nie startuje (status: failed)
```
Runtime detail → Lifecycle → "Last error"
Runtime detail → Runtime Logs (na dole strony)
Runtime detail → Logs (przycisk) → odświeży logi z kontenera
```

### Tool zwraca błąd policy
```
Sprawdź: Runtime detail → Policy
- allowed_binaries musi zawierać nazwę binarki (np. "curl")
- require_read_only=true wymaga mode="read-only" na toolach
Po zmianie policy: kliknij Reload Config (nie trzeba redeploy)
```

### Tool zwraca błąd "binary not allowed"
```
Runtime detail → Policy → Allowed binaries
Dodaj brakującą binarkę (np. "curl jq oc")
→ Reload Config
```

### Nie widać toola w tools/list
```
Sprawdź czy tool jest Enabled (Runtime detail → Tools → Edit)
Po włączeniu: Reload Config
```

### Test Tool zwraca pusty wynik
```
Sprawdź status runtime → musi być "running"
Sprawdź endpoint URL w Lifecycle section
```

### Tool Server w OpenWebUI zwraca 404
```
Sprawdź czy URL wpisany bez /openapi.json: http://mcp.dom:PORT/openwebui
OpenWebUI sam woła /openwebui/openapi.json i /openwebui/tools/{name}
```

---

---

## Najczęstsze wzorce

### Pattern 1: REST API z tokenem

```
http_request tool:
  URL: https://api.example.com/v1/search
  Method: POST
  Body: {"query": "${query}", "limit": 10}

Credential (env):
  Name: API_TOKEN
  Value: secret123

URL z headerem: dodaj do config jako osobny tool z
  curl -H "Authorization: Bearer ${API_TOKEN}" https://...
  (API_TOKEN jest w środowisku kontenera)
```

### Pattern 2: Multi-tool package

Jedna paczka może mieć wiele tools. Wszystkie idą do jednego runtime container.

```
package: "GitLab Assistant"
tools:
  - gitlab_search    → POST /api/v4/search
  - gitlab_issues    → GET /api/v4/projects/${id}/issues
  - gitlab_mr        → GET /api/v4/projects/${id}/merge_requests
  - gitlab_pipelines → GET /api/v4/projects/${id}/pipelines
```

### Pattern 3: Export istniejącego runtime jako paczka

```
Runtime detail → Lifecycle → "⬇ Export jako Package JSON"
→ pobiera curl-http-toolkit-package.json
→ możesz zmodyfikować i zaimportować jako nową paczkę
→ lub commitować do repo jako template
```

### Pattern 4: Klonuj runtime dla innego środowiska

```
Runtime detail → "Klonuj Runtime" → wpisz "GitLab Assistant PROD"
→ masz kopię z tymi samymi tools i policy
→ zmień credentials na produkcyjne
→ Deploy
```

---

---

---

---

## Przykłady gotowych scenariuszy

Trzy kompletne przepisy. Każdy możesz wyklikać w UI bez pisania kodu.

---

### SCENARIUSZ 1 — PostgreSQL read-only (SELECT)

**Cel:** model może zapytać bazę SQL, dostaje wyniki tabelaryczne.

**Obraz:** `mcp-runtime-mcp-runtime-shell-latest-postgresqlcl:latest` (ma psql)
— jeśli go nie ma, zbuduj przez Image Builder z base `mcp-runtime-shell:latest` + APT package `postgresql-client`

#### Krok 1 — Utwórz read-only użytkownika w bazie (jednorazowo w psql)

```sql
CREATE USER mcp_reader WITH PASSWORD 'silne_haslo';
GRANT CONNECT ON DATABASE nazwa_bazy TO mcp_reader;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO mcp_reader;
-- opcjonalnie dla przyszłych tabel:
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT ON TABLES TO mcp_reader;
```

#### Krok 2 — Package Generator

```
Tool Packages → + Generuj paczkę
```

| Pole | Wartość |
|------|---------|
| Nazwa | `PostgreSQL Read-Only` |
| Runtime image | `mcp-runtime-mcp-runtime-shell-latest-postgresqlcl:latest` |
| Execution types | ✅ `shell` |
| Risk | `medium` |
| Security profile | `restricted` |

**Policy:**
```json
{
  "allowed_binaries": ["psql"],
  "blocked_patterns": ["DROP", "DELETE", "INSERT", "UPDATE", "TRUNCATE", "ALTER", "CREATE", "GRANT", "REVOKE"],
  "require_read_only": true,
  "timeout_seconds": 30
}
```

#### Krok 3 — Dodaj tools

**Tool 1: `sql_query`** — dowolny SELECT

| Pole | Wartość |
|------|---------|
| Nazwa | `sql_query` |
| Typ | `shell` |
| Opis | `Wykonaj zapytanie SELECT na bazie PostgreSQL` |
| Komenda | `psql -h ${PGHOST} -U ${PGUSER} -d ${PGDATABASE} -c ${query}` |

Input schema:
| Parametr | Typ | Opis | Required |
|----------|-----|------|----------|
| `query` | string | Zapytanie SQL (tylko SELECT) | ✅ |

**Tool 2: `list_tables`** — lista tabel (bez parametrów)

| Pole | Wartość |
|------|---------|
| Komenda | `psql -h ${PGHOST} -U ${PGUSER} -d ${PGDATABASE} -c \dt` |

**Tool 3: `describe_table`** — struktura tabeli

| Pole | Wartość |
|------|---------|
| Komenda | `psql -h ${PGHOST} -U ${PGUSER} -d ${PGDATABASE} -c \d ${table_name}` |

Input schema: `table_name` (string, required)

#### Krok 4 — Credentials (na stronie runtime po Deploy)

| Kind | Name | Value |
|------|------|-------|
| `env` | `PGHOST` | `192.168.1.10` |
| `env` | `PGPORT` | `5432` |
| `env` | `PGUSER` | `mcp_reader` |
| `env` | `PGPASSWORD` | `silne_haslo` |
| `env` | `PGDATABASE` | `nazwa_bazy` |

> Zmienne środowiskowe `PG*` są automatycznie rozpoznawane przez `psql` — nie musisz ich podawać w komendzie explicite. Wystarczy `psql -c "${query}"`.

#### Krok 5 — Deploy i test

```
Test Tool → sql_query
Arguments: {"query": "SELECT table_name FROM information_schema.tables WHERE table_schema='public' LIMIT 10;"}
```

---

---

### SCENARIUSZ 2 — Linux server (SSH read-only)

**Cel:** model może odpytać zdalny serwer Linux — logi, procesy, dyski, usługi.

**Obraz:** `mcp-runtime-shell:latest` (ma ssh/sshpass)
— lub generic-runtime z SSH execution type jeśli potrzebujesz pełnego SSH adapter

#### Krok 1 — Przygotuj SSH key na serwerze (jednorazowo)

```bash
# Na maszynie MCP Platform:
ssh-keygen -t ed25519 -f /tmp/mcp_key -N ""
cat /tmp/mcp_key.pub

# Na serwerze docelowym:
echo "ssh-ed25519 AAAA... mcp-readonly" >> ~/.ssh/authorized_keys
```

#### Krok 2 — Package Generator

| Pole | Wartość |
|------|---------|
| Nazwa | `Linux Server Read-Only` |
| Runtime image | `mcp-runtime-shell:latest` |
| Execution types | ✅ `shell` |
| Risk | `medium` |
| Security profile | `restricted` |

**Policy:**
```json
{
  "allowed_binaries": ["ssh"],
  "blocked_patterns": ["rm ", "kill ", "shutdown", "reboot", "mkfs", "dd ", "> /", "chmod 777"],
  "require_read_only": true,
  "timeout_seconds": 20
}
```

#### Krok 3 — Dodaj tools

**Tool 1: `run_command`** — dowolna komenda read-only

| Pole | Wartość |
|------|---------|
| Nazwa | `run_command` |
| Komenda | `ssh -i /config/secrets/mcp_key -o StrictHostKeyChecking=no ${user}@${host} ${command}` |

Input schema:
| Parametr | Typ | Required |
|----------|-----|----------|
| `host` | string | ✅ |
| `user` | string | ✅ |
| `command` | string | ✅ |

**Tool 2: `get_logs`** — ostatnie linie journald

Komenda: `ssh -i /config/secrets/mcp_key -o StrictHostKeyChecking=no ${user}@${host} journalctl -u ${service} -n ${lines} --no-pager`

Input schema: `host`, `user`, `service`, `lines` (integer, default 50)

**Tool 3: `disk_usage`** — użycie dysków

Komenda: `ssh -i /config/secrets/mcp_key -o StrictHostKeyChecking=no ${user}@${host} df -h`

Input schema: `host`, `user`

**Tool 4: `process_list`** — lista procesów

Komenda: `ssh -i /config/secrets/mcp_key -o StrictHostKeyChecking=no ${user}@${host} ps aux --sort=-%cpu | head -20`

Input schema: `host`, `user`

#### Krok 4 — Credentials (plik z kluczem SSH)

| Kind | Name | Mount path |
|------|------|------------|
| `file` | `mcp_key` | `/config/secrets/mcp_key` |

W polu Value wklej zawartość `/tmp/mcp_key` (klucz prywatny).

```bash
cat /tmp/mcp_key   # skopiuj całą zawartość łącznie z -----BEGIN...-----
```

#### Krok 5 — Deploy i test

```
Test Tool → get_logs
Arguments: {"host": "192.168.1.50", "user": "admin", "service": "nginx", "lines": 20}
```

---

---

### SCENARIUSZ 3 — MikroTik (REST API)

**Cel:** model może odpytać router MikroTik — interfejsy, routing, DHCP, firewall, logi.

**Wymaganie:** RouterOS 7.1+ z włączonym REST API (`/ip service set www-ssl enabled=yes` lub www)

**Obraz:** `mcp-runtime-http-gateway:latest` (czyste HTTP, nie potrzebujesz shell)

#### Krok 1 — Włącz REST API na MikroTiku

```routeros
/ip service set www enabled=yes port=80
-- lub HTTPS:
/ip service set www-ssl enabled=yes port=443
/certificate add name=self-signed common-name=mikrotik days-valid=3650 key-size=2048
/certificate sign self-signed
/ip service set www-ssl certificate=self-signed
```

Utwórz read-only użytkownika:
```routeros
/user group add name=mcp-readonly policy=read,api,!write,!password,!policy,!reboot
/user add name=mcp group=mcp-readonly password=silne_haslo
```

#### Krok 2 — Package Generator

| Pole | Wartość |
|------|---------|
| Nazwa | `MikroTik Read-Only` |
| Runtime image | `mcp-runtime-http-gateway:latest` |
| Execution types | ✅ `http_request` |
| Risk | `medium` |
| Security profile | `restricted` |

**Policy:**
```json
{
  "require_read_only": true,
  "block_write_tools": true,
  "block_destructive_tools": true,
  "timeout_seconds": 15
}
```

#### Krok 3 — Dodaj tools

REST API MikroTika: `GET http://router/rest/ścieżka` z Basic Auth.
Wszystkie endpointy GET są read-only.

**Tool 1: `get_interfaces`** — stan interfejsów

| Pole | Wartość |
|------|---------|
| Nazwa | `get_interfaces` |
| Typ | `http_request` |
| Method | `GET` |
| URL | `http://${MIKROTIK_HOST}/rest/interface` |
| Auth header | wstrzyknięty przez credential (patrz niżej) |

**Tool 2: `get_dhcp_leases`** — przydzielone adresy DHCP

| Pole | Wartość |
|------|---------|
| URL | `http://${MIKROTIK_HOST}/rest/ip/dhcp-server/lease` |

**Tool 3: `get_routes`** — tabela routingu

| Pole | Wartość |
|------|---------|
| URL | `http://${MIKROTIK_HOST}/rest/ip/route` |

**Tool 4: `get_firewall`** — reguły firewall

| Pole | Wartość |
|------|---------|
| URL | `http://${MIKROTIK_HOST}/rest/ip/firewall/filter` |

**Tool 5: `get_logs`** — logi systemowe

| Pole | Wartość |
|------|---------|
| URL | `http://${MIKROTIK_HOST}/rest/log` |

**Tool 6: `get_resource`** — CPU, RAM, uptime

| Pole | Wartość |
|------|---------|
| URL | `http://${MIKROTIK_HOST}/rest/system/resource` |

> REST API MikroTika zwraca JSON automatycznie — nie potrzebujesz dodatkowego parsowania.

#### Krok 4 — Credentials

| Kind | Name | Value |
|------|------|-------|
| `env` | `MIKROTIK_HOST` | `192.168.88.1` |
| `env` | `MIKROTIK_USER` | `mcp` |
| `env` | `MIKROTIK_PASS` | `silne_haslo` |

> **Uwaga:** Basic Auth dla MikroTik REST API. W URL możesz użyć formatu:
> `http://${MIKROTIK_USER}:${MIKROTIK_PASS}@${MIKROTIK_HOST}/rest/interface`

#### Krok 5 — Deploy i test

```
Test Tool → get_resource
Arguments: {}  (brak parametrów — URL jest kompletny z credentials)
```

Oczekiwany wynik:
```json
[{"uptime":"15d2h","version":"7.14","cpu-load":"3","free-memory":"38MB",...}]
```

---

#### MikroTik przez SSH (alternatywa dla starszego RouterOS)

Jeśli masz RouterOS < 7.1 bez REST API, użyj SSH jak w Scenariuszu 2:

```
ssh -i /config/secrets/mcp_key admin@192.168.88.1 /ip address print
ssh -i /config/secrets/mcp_key admin@192.168.88.1 /interface print
ssh -i /config/secrets/mcp_key admin@192.168.88.1 /log print
```

Komendy MikroTik SSH zaczynają się od `/` — np. `/ip route print`, `/interface wireless print`.

---

---

## Podsumowanie: co klikasz w UI

```
1. Tool Packages → + Generuj paczkę
   └─ wypełnij formularz → JSON generuje się na żywo → Zainstaluj

2. Create → wybierz paczkę → Next×4 → Create MCP Server

3. Runtime detail → (opcjonalnie) Credentials → Add

4. Runtime detail → Deploy → czekaj ~2s → status: running

5. Runtime detail → Test Tool → wpisz argumenty → Run Tool

6. Skopiuj endpoint URL → wklej do Continue/OpenWebUI
```

Nie piszesz ani jednej linii kodu.
