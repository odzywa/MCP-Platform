# MCP Platform

A self-hosted platform for creating, deploying and managing **MCP (Model Context Protocol) servers** — without writing code.

Connect AI assistants (Continue, OpenWebUI, Claude Desktop) to your infrastructure: databases, APIs, Kubernetes clusters, Linux servers — all through a visual web UI.

---

## What it does

- **Visual tool builder** — create MCP tools from a web form, not code
- **Instant deploy** — one click deploys a containerized MCP server
- **Multiple runtime types** — shell commands, HTTP APIs, custom images
- **Policy engine** — allowlist binaries, block dangerous commands, enforce read-only mode
- **OpenWebUI integration** — Tool Server (OpenAPI), Python tool import, filter pipeline
- **Continue integration** — `streamable-http` transport, auto-generated config snippets
- **Audit log** — every tool invocation logged with caller IP and model name

---

## Quick Start

**Requirements:** Docker 24+, Docker Compose v2, Linux

```bash
git clone https://github.com/YOUR_USERNAME/mcp-platform.git
cd mcp-platform
chmod +x install.sh
./install.sh
```

Open **http://localhost:18100** — login: `admin` / `admin`

---

## Manual Setup

```bash
# 1. Copy and edit configuration
cp .env.example .env
# Edit MCP_HOST_DATA_PATH to the absolute path of the data/ folder

# 2. Build runtime images
docker compose --profile build-only build

# 3. Start the platform
docker compose up -d

# 4. Open the UI
open http://localhost:18100
```

---

## Architecture

```
┌─────────────────────────────────────────────────┐
│                   MCP Platform UI                │
│            (FastAPI · SQLite · port 18100)        │
└────────────────────┬────────────────────────────┘
                     │ manages
         ┌───────────▼──────────┐
         │   Operator (worker)   │
         │   Docker SDK          │
         └───────────┬──────────┘
                     │ creates/stops
     ┌───────────────┼───────────────────┐
     ▼               ▼                   ▼
┌─────────┐   ┌─────────────┐   ┌──────────────┐
│ Shell   │   │ HTTP Gateway│   │ Custom Image │
│ Runtime │   │ Runtime     │   │ Runtime      │
│ /mcp    │   │ /mcp        │   │ /mcp         │
└─────────┘   └─────────────┘   └──────────────┘
     ▲               ▲
     │ calls         │ calls
┌────┴───────────────┴──────┐
│  AI Client                │
│  Continue / OpenWebUI     │
└───────────────────────────┘
```

| Component | Description |
|-----------|-------------|
| `control-plane` | Web UI + REST API — manages runtimes, tools, policies |
| `operator` | Background worker — creates/stops Docker containers |
| `runtime-shell` | Shell runtime — executes CLI commands (curl, psql, oc, ping...) |
| `runtime-http-gateway` | HTTP runtime — calls external REST APIs |

---

## Creating your first MCP server

### Option A — Use an example package

1. Go to **Tool Packages** → **Import Package JSON**
2. Upload a file from `examples/` (e.g. `curl-http-toolkit.json`)
3. Click **Create MCP** → name it → **Deploy**
4. Copy the endpoint URL → paste into Continue or OpenWebUI

### Option B — Build from scratch

1. **Tool Packages** → **+ Generate Package**
2. Fill in name, choose runtime type (Shell or HTTP)
3. Add tools with commands/URLs and input parameters
4. Install → Create MCP Server → Deploy

See `docs/jak-stworzyc-mcp-server.md` for full step-by-step guide.

---

## Connect to Continue

```json
{
  "mcpServers": {
    "my-server": {
      "url": "http://localhost:PORT/mcp",
      "transport": "streamable-http"
    }
  }
}
```

## Connect to OpenWebUI

**Tool Server** (multiple tools at once):
- Admin → Tool Servers → Add → URL: `http://HOST:PORT/openwebui`

**Python Tool** (import from link):
- Runtime detail → copy the Python Tool link → OpenWebUI → Tools → Import from URL

---

## Example Packages

| File | Description |
|------|-------------|
| `examples/curl-http-toolkit.json` | HTTP GET, POST, status check via curl |
| `examples/psql-readonly.json` | PostgreSQL SELECT queries |
| `examples/openshift-readonly.json` | oc get / describe / logs |

---

## Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `MCP_PLATFORM_PORT` | `18100` | UI port |
| `MCP_HOST_DATA_PATH` | *(required)* | Absolute path to `data/` on host |
| `MCP_RUNTIME_PUBLIC_BASE_URL` | `http://localhost` | Base URL for runtime endpoints |
| `MCP_RUNTIME_PUBLIC_PORT_BASE` | `19000` | Starting port for runtime containers |

---

## License

Copyright (c) 2026 — All Rights Reserved.  
See [LICENSE](LICENSE) for terms. Non-commercial use only.
