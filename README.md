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

## Prerequisites

| Requirement | Version | Install |
|-------------|---------|---------|
| **Docker Engine** | 24.0+ | [docs.docker.com/engine/install](https://docs.docker.com/engine/install/) |
| **Docker Compose** | v2.20+ (plugin) | included with Docker Desktop / `apt install docker-compose-plugin` |
| **OS** | Linux (Ubuntu 22.04+ recommended) | — |
| **RAM** | 2 GB minimum, 4 GB recommended | — |
| **Disk** | 4 GB free (images + data) | — |
| **Ports** | 18100 + range 19000–19999 open | firewall / UFW |

> **Note:** Docker Desktop on macOS/Windows works for development but runtime containers may not be reachable by AI clients outside the VM. Linux is recommended for production.

### Install Docker (Ubuntu)

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker
docker --version        # Docker version 24.x.x
docker compose version  # Docker Compose version v2.x.x
```

> **Important:** Your user must be in the `docker` group, otherwise `install.sh` and all `docker` commands will fail with permission errors.
>
> ```bash
> # Add current user to docker group
> sudo usermod -aG docker $USER
>
> # Apply without logout (current session only)
> newgrp docker
>
> # Verify
> docker ps   # should work without sudo
> ```
>
> If you log out and back in, group membership is applied automatically.

---

## Installation

```bash
# 1. Install Docker (if not already installed)
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
newgrp docker

# 2. Clone the repository
git clone https://github.com/YOUR_USERNAME/mcp-platform.git
cd mcp-platform

# 3. Run the installer
chmod +x install.sh
./install.sh
```

Open **http://YOUR_SERVER_IP:18100** — login: `admin` / `admin`

### Updating to a newer version

```bash
git pull
docker compose up -d --build mcp-platform mcp-platform-operator
```

> **Note:** `--force-recreate` alone does **not** rebuild images from updated source code.  
> Always use `--build` after `git pull`.

### Rebuilding images manually (after local code changes)

```bash
# Rebuild control plane only
docker compose up -d --build mcp-platform

# Rebuild operator only
docker compose up -d --build mcp-platform-operator

# Rebuild runtime images (shell / http-gateway)
docker compose --profile build-only build
# Then redeploy running runtimes via the UI: Runtime → Deploy

# Rebuild everything at once
docker compose build && docker compose up -d
```

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

## OpenWebUI Integration

MCP Platform has native integration with [OpenWebUI](https://github.com/open-webui/open-webui).  
Each deployed MCP server automatically exposes three integration endpoints:

### Option 1 — Tool Server (recommended, multiple tools at once)

Each runtime serves a full OpenAPI spec at `/openwebui/openapi.json`.  
OpenWebUI discovers all tools automatically.

1. OpenWebUI → **Admin Panel → Tools → Tool Servers → Add**
2. Enter URL: `http://YOUR_IP:PORT/openwebui`
3. Save — all tools from the MCP server appear instantly

> OpenWebUI automatically appends `/openapi.json` — enter the base URL only.

### Option 2 — Python Tool (import from link)

Each runtime generates a ready-to-import Python tool file.

1. Open the runtime detail page → **Podłącz** tab → copy the **Python Tool** link
2. OpenWebUI → **Workspace → Tools → Import from URL** → paste the link
3. The tool appears in your workspace with full function signatures

### Option 3 — RAGHybrid filter pipeline

If you run RAGHybrid alongside MCP Platform, use the auto-context filter:
- Automatically injects RAG context into prompts when the tool is active
- Configurable `top_k`, retrieval mode, and source filtering

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
