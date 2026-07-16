# MCP Platform — Kubernetes / OpenShift

## Before First Deploy

### 1. Fill in config.env

```bash
nano config.env
```

Three fields to fill in:
- `REGISTRY` — Docker registry accessible from the cluster
- `APPS_DOMAIN` — cluster application domain
- `STORAGE_CLASS` — block storage StorageClass (not NFS)

```bash
# Find APPS_DOMAIN:
oc get ingresses.config cluster -o jsonpath='{.spec.domain}'

# List available StorageClasses:
oc get storageclass

# Log in to OpenShift internal registry:
oc login https://api.your-cluster.example.com:6443
oc registry login
```

### 2. Run deploy

```bash
chmod +x deploy.sh
./deploy.sh
```

The script handles everything: image builds, push to registry, apply manifests, wait for rollout.

---

## How It Works

```
UI (control-plane)
  → saves config to SQLite + /data/configs/<id>/
  → inserts record into deployment_requests

Operator (this project, kubernetes_driver.py)
  → reads deployment_requests every 2s
  → creates in K8s: ConfigMap + Secret + Deployment + Service + Route
  → writes endpoint URL from Route back to SQLite
  → UI shows link to MCP endpoint
```

Each MCP runtime server = a separate `Deployment` in the `mcp-platform` namespace.

---

## Debugging

```bash
# Pods
oc get pods -n mcp-platform

# Control-plane logs
oc logs -n mcp-platform deployment/mcp-platform -f

# Operator logs
oc logs -n mcp-platform deployment/mcp-platform-operator -f

# Check if operator creates runtime pods
oc get deployments -n mcp-platform

# Route for runtime server
oc get routes -n mcp-platform

# Check runtime ConfigMap
oc get configmap -n mcp-platform | grep mcp-runtime

# Runtime pod logs
oc logs -n mcp-platform -l app=mcp-runtime-<id>
```

---

## Project Structure

```
config.env               ← Your settings (REGISTRY, APPS_DOMAIN, STORAGE_CLASS)
deploy.sh                ← One-shot deploy script
k8s/
  01-namespace-storage.yaml   Namespace + PVC
  02-rbac.yaml                ServiceAccount + Role + RoleBinding
  03-control-plane.yaml       ConfigMap + Deployment + Service + Route
  04-operator.yaml            Operator Deployment
  05-networkpolicy.yaml       NetworkPolicy (optional)
operator/
  Dockerfile                  Operator image with Kubernetes SDK
  requirements.txt            kubernetes>=29.0.0
  app/worker.py               Main reconciler loop
  drivers/kubernetes_driver.py  KubernetesDeploymentDriver
```

---

## Differences vs Docker Compose

| | Docker | Kubernetes |
|---|---|---|
| Operator driver | `docker.sock` | `ServiceAccount` in cluster |
| Runtime config | host directory | `ConfigMap` |
| Credentials | `runtime-env.json` → env | `Secret` → `envFrom` |
| Runtime port | host port 19000+ | `Route` (HTTPS) |
| Start/Stop | `docker start/stop` | `scale replicas 1/0` |

Control plane and config file format — **unchanged**.

---

## Security

### Cookie Secure (HTTPS)

On Kubernetes traffic to the control plane goes through a Route with TLS — set the `Secure` flag on the session cookie:

```yaml
# k8s/03-control-plane.yaml — control-plane env
- name: MCP_HTTPS_ONLY
  value: "1"
```

### SSRF — Internal Cluster Resource Protection

The control plane blocks requests to private IP ranges (including Kubernetes service addresses in `10.0.0.0/8` and `172.16.0.0/12`). Hostnames are resolved via DNS before the check — protection against DNS rebinding. No configuration required.

### Runtime Shell — No shell=True

The `mcp-runtime-shell` runtime executes commands without a shell interpreter. User arguments are never concatenated into a string and passed to a shell — each pipeline stage is an argv list passed directly to `Popen`. See the main [README.md](../README.md) for details.

---

## Human-in-the-Loop Approval System

MCP tools with `write` or `destructive` mode can require explicit user confirmation before execution. The approval happens **directly in the AI chat** — no separate web UI needed.

### How It Works

```
AI calls a tool (e.g. oc_delete)
  → runtime checks policy
  → approval required → returns approval_required message to AI
  → AI asks the user in chat: "Do you want to delete pod X? Say 'yes' to confirm."
  → User says "yes"
  → AI calls the same tool again with __confirm="yes"
  → runtime skips approval check, executes the command
```

The `__confirm` parameter is defined in every tool's input schema, so the AI client can pass it without schema validation errors.

### Policy Configuration (policy.json)

```json
{
  "require_approval_for": "auto",
  "require_approval_for_prefixes": [
    "oc delete",
    "oc apply",
    "oc patch",
    "kubectl delete"
  ],
  "approval_timeout_seconds": 120
}
```

| `require_approval_for` value | Behaviour |
|---|---|
| omitted / `""` | No approvals (default) |
| `"auto"` | Auto-detect: mode=write/destructive OR tool name contains action keyword |
| `["destructive"]` | Only mode=destructive tools (delete/destroy) |
| `["write", "destructive"]` | Both write and destructive tools |

**Auto-detection keywords** (matched against tool name): `delete`, `remove`, `destroy`, `drop`, `purge`, `wipe`, `truncate`, `erase`, `clean`, `create`, `apply`, `deploy`, `install`, `patch`, `scale`, `expose`, `rollout`, `add`, `set`, `update`, `replace`, `restart`.

### Prefix-Based Approval

`require_approval_for_prefixes` triggers approval for specific commands regardless of tool mode:

```json
"require_approval_for_prefixes": ["oc delete", "oc apply", "kubectl delete"]
```

> **Important:** Do NOT add prefixes to `blocked_command_prefixes` if you want approval to handle them. The approval gate takes precedence over the prefix blocklist when the user confirms (`__confirm="yes"`).

### Configuring via UI

Runtime → Policy → **Approvals (Human-in-the-Loop)** section:
- **Require approval for**: dropdown — Off / Auto / Destructive only / Write+Destructive
- **Prefixes requiring approval**: one per line
- **Approval timeout**: seconds before auto-rejection

Click **💾 Save shell policy** — the policy is saved and the runtime reloads automatically.

### Applying Fixes to an Existing Deployment

If you deployed before the approval system was added, run this on the control-plane pod to update tool schemas:

```bash
oc exec -n mcp-platform deployment/mcp-platform -- python3 -c "
import sqlite3, json
conn = sqlite3.connect('/data/mcp_platform.db', timeout=10)
confirm = {'type': 'string', 'description': 'Pass yes to confirm execution after user approval'}
rows = conn.execute('SELECT id, input_schema_json FROM tools').fetchall()
for row in rows:
    s = json.loads(row['input_schema_json'])
    if '__confirm' not in s.get('properties', {}):
        s.setdefault('properties', {})['__confirm'] = confirm
        conn.execute('UPDATE tools SET input_schema_json=? WHERE id=?', (json.dumps(s), row['id']))
conn.commit()
print('OK')
"
```

Then **Reload** the runtime in the UI.

---

## MCP Authentication (Bearer Token)

Each MCP runtime can require a Bearer token from the AI client. Optional and per-runtime — servers without a token remain open.

### Enable

1. Runtime details → **🔐 Auth** tab
2. Click **+ Generate token**
3. Copy the token to your AI client config

### Supported Headers

```http
Authorization: Bearer <token>
X-API-Key: <token>
```

### Client Configuration

**Claude Desktop** (`~/.claude.json`):
```json
{
  "mcpServers": {
    "my-server": {
      "type": "http",
      "url": "https://mcp-runtime-<id>-mcp-platform.<APPS_DOMAIN>/mcp",
      "headers": {
        "Authorization": "Bearer <TOKEN>"
      }
    }
  }
}
```

**Continue / VS Code**:
```json
{
  "mcp.servers": [{
    "name": "my-server",
    "transport": "streamable-http",
    "url": "https://mcp-runtime-<id>-mcp-platform.<APPS_DOMAIN>/mcp",
    "headers": {
      "Authorization": "Bearer <TOKEN>"
    }
  }]
}
```

The `/health` and `/reload` paths are always public (required by the operator for monitoring and config reload).

On Kubernetes the token works identically to Docker — it is stored in `runtime-config.json` (mounted as a `ConfigMap`) and loaded without pod restart via `/reload`.

---

## OpenShift Monitor Runtime

The platform ships with a pre-configured `openshift-monitor` runtime — a full set of OpenShift tools for cluster management. On first startup, the control plane seeds it automatically with correct command definitions.

### Required Runtime Credentials

Add these in UI → Runtime → Credentials:

| Name | Value |
|---|---|
| `OC_TOKEN` | Service account token: `oc create token <sa> -n <ns>` |
| `OC_SERVER` | API server URL: `https://api.cluster.dom:6443` |

### Included Tools

| Tool | Mode | Description |
|---|---|---|
| `oc_get` | read-only | `oc get <args>` |
| `oc_describe` | read-only | `oc describe <args>` |
| `oc_logs` | read-only | `oc logs <args>` |
| `oc_events` | read-only | Events for a namespace |
| `oc_status` | read-only | Cluster status |
| `oc_top` | read-only | Pod resource usage |
| `oc_projects` | read-only | List projects/namespaces |
| `oc_apply` | write | `oc apply <args>` |
| `oc_apply_yaml` | write | Apply inline YAML via stdin pipe |
| `oc_create` | write | `oc create <args>` |
| `oc_create_yaml` | write | Create resource from inline YAML |
| `oc_patch` | write | `oc patch <args>` |
| `oc_rollout` | write | `oc rollout <args>` |
| `oc_scale` | write | `oc scale <args>` |
| `oc_new_app` | write | `oc new-app <args>` |
| `oc_expose` | write | `oc expose <args>` |
| `oc_set` | write | `oc set <args>` |
| `oc_adm` | write | `oc adm <args>` |
| `oc_exec` | write | `oc exec <args>` |
| `oc_delete` | destructive | `oc delete <args>` — requires approval |

### YAML Apply Pipeline

`oc_apply_yaml` and `oc_create_yaml` use stdin piping (not temp files) because `shell=False` does not support `>` redirects:

```
printf %s <yaml_content> | oc apply -f -
```

This is handled natively by the runtime's pipeline engine — `|` in the command template creates a Popen chain with `stdout=PIPE`.

### Default Policy

The runtime ships with approval enabled by default:

```json
{
  "allowed_binaries": ["oc", "kubectl", "jq", "printf", "rm", "cat", "bash", "sh"],
  "require_approval_for": "auto",
  "require_approval_for_prefixes": ["oc delete", "oc apply", "oc patch", "kubectl delete"],
  "approval_timeout_seconds": 120
}
```
