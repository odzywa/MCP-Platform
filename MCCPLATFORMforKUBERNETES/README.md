# MCP Platform — Kubernetes / OpenShift

## Before First Deploy

### 0. Create the deploy account (once, by a cluster admin)

`deploy.sh` does **not** create this account — it assumes you are already logged in as it.

Cluster-admin rights are needed **only for this one step**. Everything the installer
does afterwards happens inside the `mcp-platform` namespace.

```bash
# As a cluster admin — creates the namespace, the mcp-deployer ServiceAccount
# and the roles it needs:
oc apply -f k8s/00-deployer-account.yaml

# Issue a token for the account (24h; adjust as needed):
oc create token mcp-deployer -n mcp-platform --duration=24h
```

Then log in as that account on the machine that will run `deploy.sh`:

```bash
oc login --token=<TOKEN-FROM-ABOVE> --server=https://api.your-cluster.example.com:6443
oc whoami          # expect: system:serviceaccount:mcp-platform:mcp-deployer
```

The account is scoped to the `mcp-platform` namespace. The only cluster-wide grant is
`get/patch/update` on the single namespace object named `mcp-platform` — `oc apply`
sends a PATCH to it even when nothing changes, and without this the deploy fails with
`namespaces is forbidden`.

Its Role is deliberately a **superset** of the `mcp-operator` Role created later.
Kubernetes forbids granting permissions you do not hold yourself, so a narrower deploy
account would fail at `02-rbac.yaml` with `attempt to grant extra privileges`.

If a long-lived token is preferred over a 24h one (CI pipelines, unattended installs):

```bash
oc apply -n mcp-platform -f - <<'YAML'
apiVersion: v1
kind: Secret
metadata:
  name: mcp-deployer-token
  namespace: mcp-platform
  annotations:
    kubernetes.io/service-account.name: mcp-deployer
type: kubernetes.io/service-account-token
YAML

oc get secret mcp-deployer-token -n mcp-platform -o jsonpath='{.data.token}' | base64 -d
```

Note that this token does not expire — store it like any other credential and delete the
Secret when it is no longer needed.

> Changing `NAMESPACE` in `config.env`? Update it in `k8s/00-deployer-account.yaml`
> as well — the namespace is hardcoded there in 9 YAML fields.

### 1. Fill in config.env

`config.env` is gitignored, so start from the template:

```bash
cp config.env.example config.env
nano config.env
```

Required — `deploy.sh` aborts if any is empty:
- `REGISTRY` — registry to **push** to, reachable from the machine running the script
- `PULL_REGISTRY` — registry the **cluster pulls from**; on OpenShift this is the
  internal registry service and differs from `REGISTRY`
- `APPS_DOMAIN` — cluster application domain, used to build Route hostnames
- `NAMESPACE` — project for the platform and all runtimes (created if absent)

Optional:
- `STORAGE_CLASS` — block storage class for the SQLite PVC; empty = cluster default.
  **Must not be NFS** — SQLite WAL needs file locking that NFS does not provide.
- `OC_MCP_TOKEN` / `OC_MCP_SERVER` — fill both to have `deploy.sh` also deploy the
  `openshift-monitor` MCP server automatically. Leave empty to skip and add it later
  from the UI.

```bash
# Find APPS_DOMAIN:
oc get ingresses.config cluster -o jsonpath='{.spec.domain}'

# List available StorageClasses:
oc get storageclass

# Log in to OpenShift internal registry:
oc login https://api.your-cluster.example.com:6443
oc registry login
```

### 2. Container engine

`deploy.sh` works with **podman or docker** — it does not need both. It auto-detects
what is installed, preferring podman when available:

```bash
./deploy.sh                          # auto-detect
CONTAINER_ENGINE=docker ./deploy.sh  # force docker
```

Images are built directly with `podman build` / `docker build` — `compose` is not
required, since the deploy needs exactly five known images.

Pushing to the OpenShift internal registry uses podman when present, because
`--tls-verify=false` handles a self-signed registry CA without touching daemon
config. **With docker only**, add the registry to `/etc/docker/daemon.json` first:

```json
{ "insecure-registries": ["default-route-openshift-image-registry.apps.your-cluster.example.com"] }
```

then restart the docker daemon. This is not needed for an external registry with a
trusted certificate (Quay, Harbor, Nexus).

If you build with docker but push with podman — the case when both are installed and
you force `CONTAINER_ENGINE=docker` — the script moves images between the two stores
via the `docker-daemon:` transport automatically.

### 3. Run deploy

`deploy.sh` is idempotent — the same script installs and upgrades. Running it again
on an existing deployment rebuilds the images, pushes them under the same tags and
rolls every component, including the MCP runtimes.

What an upgrade covers:

| | handled by |
|---|---|
| Control plane + operator | `oc rollout restart deployment/mcp-platform` (step 5) — both run in one pod |
| Database schema | `init_db()` on startup — `CREATE TABLE IF NOT EXISTS` plus guarded `ALTER TABLE`, idempotent |
| Seeded tool definitions | `seed_example_runtimes()` (`control-plane/app/catalog/seed.py`) patches `config_json` / `input_schema` of existing `openshift-monitor` runtime on every start (`"on_existing": "sync_tools"`) |
| **MCP runtimes** | `oc rollout restart` on every Deployment labelled `app.kubernetes.io/managed-by=mcp-platform` (step 7) |

Step 7 matters more than it looks. Runtime Deployments are created by the operator,
not by these manifests, so nothing in steps 1–6 touches them. They do carry
`imagePullPolicy: Always`, but pushing a new image under an existing tag does not by
itself restart anything — without step 7 the platform upgrades while every MCP server
keeps serving the old code.

> **Limit worth knowing.** Step 7 restarts pods, which picks up new *images*. It does
> not regenerate the per-runtime config artifacts (`tools.json`, `policy.json`, …)
> held in each runtime's ConfigMap. If a release changes the *format* of those files,
> hit **Redeploy** on the affected runtime in the UI — that re-renders the config and
> rolls the pod.



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
oc logs -n mcp-platform deployment/mcp-platform -c control-plane -f

# Operator logs (operator to drugi kontener w podzie mcp-platform)
oc logs -n mcp-platform deployment/mcp-platform -c operator -f

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
| Image builds | `docker build` in the operator | OpenShift `BuildConfig` with the same generated Dockerfile (see *Image Builder*) |

Control plane and config file format — **unchanged**.

---

## Image Builder (custom runtime images)

The **Budowanie obrazów** tab works the same way as on Docker Compose: a custom image is a
base runtime image plus extra tools (system packages, pip packages, optional Dockerfile fragment).
The control plane generates the Dockerfile; the operator builds it.

On OpenShift the operator:

1. creates or updates a `BuildConfig` named after the image, with the generated Dockerfile inline
   (`source.type: Dockerfile`, Docker strategy);
2. sets the base image through `dockerStrategy.from` — an `ImageStreamTag` when the base lives in the
   namespace (platform images, previously built images), otherwise a `DockerImage` reference;
3. writes the result to an `ImageStream` in the namespace (created when missing), i.e. the same
   internal registry path that runtime Deployments pull from;
4. starts the build and **waits for it to finish** — the build shows `gotowy` only after the Build
   reaches `Complete`; on `Failed` / `Error` / `Cancelled` the OpenShift reason and log snippet are
   shown in the error column.

Notes:

- Image names must be valid Kubernetes names (lowercase letters, digits, `-`, `.`).
- While a build runs the operator does not process other actions (same as the Docker operator).
  Timeout: `MCP_IMAGE_BUILD_TIMEOUT_SECONDS` (default `1800`).
- The build pod needs network access to the package repositories used by the base image
  (UBI repos for platform images, PyPI for pip packages).
- Docker-strategy builds must be allowed for the operator's ServiceAccount. This is the OpenShift
  default (`system:build-strategy-docker` is bound to authenticated users); if your cluster
  restricts it, grant it: `oc adm policy add-cluster-role-to-user system:build-strategy-docker -z mcp-operator -n <namespace>`.
- Runtimes using a built image whose name does not start with one of
  `MCP_RUNTIME_LOCAL_IMAGE_PREFIXES` are still resolved to the internal registry when an
  ImageStream of that name exists in the namespace.
- Vanilla Kubernetes has no built-in build mechanism: the build fails with a message asking to
  build and push the image manually.
- Deleting an image in the UI removes the build record and its runtime class; the ImageStream and
  BuildConfig stay in the cluster (`oc delete bc,is <name>`).

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

MCP tools with `write` or `destructive` mode can require approval by a human before execution. The decision is always made by a **person** — the model has no parameter or other way to approve an operation itself and has to wait for the decision.

### How It Works

Two paths, chosen automatically:

```
1. The AI client supports a confirmation dialog (MCP elicitation)
   AI calls a tool (e.g. oc_delete)
     → the runtime asks the client for confirmation, with the exact command
     → the chat window shows a Yes/No dialog (the model does not see it)
     → the tool call WAITS for the answer of the user
     → Yes: the command runs · No / no answer: it does not

2. Other clients (e.g. OpenWebUI over REST)
   AI calls a tool
     → the runtime returns a link to the chat: <platform URL>/approve/<id>
     → the user opens it, logs in to the platform, approves or rejects
     → AI calls the same tool again (the call waits a moment for the decision)
     → once approved the command runs — one approval = one execution
```

An approval given through the link covers exactly that command (tool + arguments), requires a
logged-in `read_write` or `admin` user and a form POST — opening the link or using the service API
token (`X-API-Key`) approves nothing. Decisions are written to the audit log.

The link uses `MCP_PLATFORM_PUBLIC_URL` (ConfigMap `mcp-platform-env`), by default the OpenShift
Route host `https://mcp-platform-<namespace>.<apps domain>`; set it if your Route uses a custom host.
The elicitation path keeps the HTTP response open as an SSE stream with keep-alive comments every
10 s, so the idle timeout of the router does not cut it.

### Policy Configuration (policy.json)

```json
{
  "require_approval_for": "auto",
  "require_approval_for_prefixes": [
    "oc delete",
    "oc apply",
    "oc patch",
    "kubectl delete"
  ]
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

> **Important:** A prefix listed in `blocked_command_prefixes` is always blocked — even after approval. Put commands that should be possible after a human approves only into `require_approval_for_prefixes`.

### Configuring via UI

Runtime → Policy → **Approvals (Human-in-the-Loop)** section:
- **Require approval for**: dropdown — Off / Auto / Destructive only / Write+Destructive
- **Prefixes requiring approval**: one per line
- **Approval timeout**: how long the confirmation dialog waits and how long a link approval stays usable (seconds)

Click **💾 Save shell policy** — the policy is saved and the runtime reloads automatically.

### Upgrading from the `__confirm` version

Earlier versions let the model confirm an operation itself by passing `__confirm="yes"`. That
parameter is now ignored and hidden from tool schemas; no data migration is needed. Rebuild the
`mcp-runtime-shell` image and redeploy shell runtimes to get the new behaviour.

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

The platform ships with a pre-configured `openshift-monitor` runtime — a full set of OpenShift tools for cluster management. On first startup, the control plane seeds it automatically in `draft` status. You only need to add credentials and click Deploy.

> **Two layers of naming — the usual source of confusion.**
> In `config.env` the fields are `OC_MCP_TOKEN` / `OC_MCP_SERVER`. Inside the
> platform they become Runtime Credentials named `OC_TOKEN` / `OC_SERVER`,
> because that is what the `oc` tool templates reference:
> `["oc", "--token=${OC_TOKEN}", "--server=${OC_SERVER}", ...]`.
> `deploy.sh` performs that translation for you. When adding credentials by hand
> in the UI they **must** be named `OC_TOKEN` and `OC_SERVER` — the `OC_MCP_*`
> names work only inside `config.env`.

### Option A — Auto-deploy via config.env (recommended)

Fill in two optional fields in `config.env` **before** running `deploy.sh`:

```bash
# Create a dedicated Service Account with cluster-admin
oc create sa mcp-admin -n mcp-platform
oc adm policy add-cluster-role-to-user cluster-admin -z mcp-admin -n mcp-platform

# Generate a long-lived token (8760h = 1 year)
OC_MCP_TOKEN=$(oc create token mcp-admin -n mcp-platform --duration=8760h)
OC_MCP_SERVER=$(oc whoami --show-server)

# Paste into config.env:
echo "OC_MCP_TOKEN=$OC_MCP_TOKEN" >> config.env
echo "OC_MCP_SERVER=$OC_MCP_SERVER" >> config.env
```

Then run `./deploy.sh` — step 6 prints the HTTP status of every call it makes, so
a failure shows up instead of being reported as success. It will:
1. Wait for the platform API to be ready
2. Log in with default admin credentials
3. Set `OC_TOKEN` and `OC_SERVER` as Runtime Credentials on `openshift-monitor`
4. Trigger deployment

The runtime will be live at its MCP endpoint within ~30 seconds.

> **Note:** `config.env` is in `.gitignore` — credentials are never committed to git.

### Option B — Manual setup via UI

Add these in UI → Runtimes → openshift-monitor → Secrets:

| Name | Value |
|---|---|
| `OC_TOKEN` | Service account token: `oc create token <sa> -n <ns>` |
| `OC_SERVER` | API server URL: `https://api.cluster.dom:6443` |

Then click **▶ Deploy**.

### Connect an AI client

After the runtime is running, generate an MCP auth token in UI → openshift-monitor → Auth → Generate token, then configure your client:

```
# OpenCode (request headers):
X-API-Key: <token>

# Claude Desktop / Cline (headers in mcpServers config):
Authorization: Bearer <token>
```

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
  "require_approval_for_prefixes": ["oc delete", "oc apply", "oc patch", "kubectl delete"]
}
```
