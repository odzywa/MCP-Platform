import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.error import URLError
from urllib.request import Request as _UrlRequest
from urllib.request import urlopen

import docker
from docker.errors import NotFound


NETWORK = os.getenv("MCP_RUNTIME_NETWORK", "ai-net")
PUBLIC_PORT_BASE = int(os.getenv("MCP_RUNTIME_PUBLIC_PORT_BASE", "19000"))
PUBLIC_BASE_URL = os.getenv("MCP_RUNTIME_PUBLIC_BASE_URL", "http://localhost").rstrip("/")
CONFIG_CONTAINER_ROOT = os.getenv("MCP_PLATFORM_CONFIG_ROOT", "/data/configs")
CONFIG_HOST_ROOT = os.getenv("MCP_PLATFORM_CONFIG_HOST_ROOT", CONFIG_CONTAINER_ROOT)
CALLBACK_URL = os.getenv("MCP_PLATFORM_CALLBACK_URL", "http://mcp-platform:8080")


@dataclass(frozen=True)
class DeploySpec:
    server_id: str
    name: str
    runtime_class: str
    runtime_image: str
    config_mount: str
    env: dict[str, str] = field(default_factory=dict)
    labels: dict[str, str] = field(default_factory=dict)
    security_context: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class InstanceStatus:
    server_id: str
    state: str
    endpoint_url: str | None = None
    container_name: str | None = None
    last_error: str | None = None


def container_name(server_id: str) -> str:
    return f"mcp-runtime-{server_id}"


def host_config_path(config_path: str) -> str:
    if config_path.startswith(CONFIG_CONTAINER_ROOT):
        return CONFIG_HOST_ROOT + config_path[len(CONFIG_CONTAINER_ROOT):]
    return config_path


class DockerDeploymentDriver:
    """Docker-backed deployment driver implementing full MCP runtime lifecycle."""

    name = "docker"

    def __init__(self, client: docker.DockerClient) -> None:
        self._client = client

    def _assign_port(self, server_id: str) -> int:
        preferred = PUBLIC_PORT_BASE + sum(ord(ch) for ch in server_id) % 800
        used_ports: set[int] = set()
        try:
            for container in self._client.containers.list(filters={"name": "mcp-runtime-"}):
                for port_bindings in (container.ports or {}).values():
                    for binding in port_bindings or []:
                        if binding and binding.get("HostPort"):
                            try:
                                used_ports.add(int(binding["HostPort"]))
                            except (ValueError, TypeError):
                                pass
        except Exception:
            pass
        port = preferred
        while port in used_ports and port < PUBLIC_PORT_BASE + 900:
            port += 1
        if port >= PUBLIC_PORT_BASE + 900:
            raise RuntimeError(
                f"No available port in range {PUBLIC_PORT_BASE}-{PUBLIC_PORT_BASE + 900}"
            )
        return port

    def _endpoint(self, port: int) -> str:
        return f"{PUBLIC_BASE_URL}:{port}/mcp"

    def apply(self, spec: DeploySpec) -> InstanceStatus:
        name = container_name(spec.server_id)
        docker_config_path = host_config_path(spec.config_mount)

        runtime_env_path = Path(spec.config_mount) / "runtime-env.json"
        runtime_env: dict[str, str] = {
            "MCP_PLATFORM_CALLBACK_URL": CALLBACK_URL,
            "MCP_RUNTIME_ID": spec.server_id,
            **spec.env,
        }
        if runtime_env_path.exists():
            try:
                loaded = json.loads(runtime_env_path.read_text(encoding="utf-8")).get("env") or {}
                runtime_env.update(loaded)
            except (OSError, json.JSONDecodeError) as exc:
                raise RuntimeError(f"invalid runtime-env.json: {exc}") from exc

        for old in self._client.containers.list(all=True, filters={"name": f"^{name}$"}):
            old.remove(force=True)

        port = self._assign_port(spec.server_id)
        sc: dict[str, Any] = {
            "read_only": True,
            "tmpfs": {"/tmp": "rw,noexec,nosuid,size=64m"},
            "mem_limit": "512m",
            "nano_cpus": 1_000_000_000,
            "cap_drop": ["ALL"],
            "security_opt": ["no-new-privileges:true"],
            "user": "1000:1000",
            **spec.security_context,
        }

        container = self._client.containers.run(
            spec.runtime_image,
            name=name,
            detach=True,
            network=NETWORK,
            ports={"8080/tcp": port},
            volumes={docker_config_path: {"bind": "/config", "mode": "ro"}},
            environment=runtime_env,
            labels={
                "mcp.platform.runtime_id": spec.server_id,
                "mcp.platform.runtime_class": spec.runtime_class,
                **spec.labels,
            },
            read_only=sc["read_only"],
            tmpfs=sc["tmpfs"],
            mem_limit=sc["mem_limit"],
            nano_cpus=sc["nano_cpus"],
            cap_drop=sc["cap_drop"],
            security_opt=sc["security_opt"],
            user=sc["user"],
            restart_policy={"Name": "unless-stopped"},
        )
        return InstanceStatus(
            server_id=spec.server_id,
            state="running",
            endpoint_url=self._endpoint(port),
            container_name=container.name,
        )

    def delete(self, server_id: str) -> InstanceStatus:
        name = container_name(server_id)
        try:
            c = self._client.containers.get(name)
            c.remove(force=True)
        except NotFound:
            pass
        return InstanceStatus(server_id=server_id, state="deleted", container_name=None)

    def start(self, server_id: str) -> InstanceStatus:
        name = container_name(server_id)
        c = self._client.containers.get(name)
        c.start()
        port = PUBLIC_PORT_BASE + sum(ord(ch) for ch in server_id) % 800
        return InstanceStatus(
            server_id=server_id,
            state="running",
            endpoint_url=self._endpoint(port),
            container_name=name,
        )

    def stop(self, server_id: str) -> InstanceStatus:
        name = container_name(server_id)
        c = self._client.containers.get(name)
        c.stop(timeout=10)
        return InstanceStatus(server_id=server_id, state="stopped", container_name=name)

    def restart(self, server_id: str) -> InstanceStatus:
        name = container_name(server_id)
        c = self._client.containers.get(name)
        c.restart(timeout=10)
        port = PUBLIC_PORT_BASE + sum(ord(ch) for ch in server_id) % 800
        return InstanceStatus(
            server_id=server_id,
            state="running",
            endpoint_url=self._endpoint(port),
            container_name=name,
        )

    def status(self, server_id: str) -> InstanceStatus:
        name = container_name(server_id)
        try:
            c = self._client.containers.get(name)
            c.reload()
            docker_status = c.attrs.get("State", {}).get("Status", c.status)
            state = "running" if docker_status == "running" else docker_status
            last_error = None
            if docker_status == "running":
                health_url = f"http://{name}:8080/health"
                try:
                    with urlopen(health_url, timeout=3) as response:
                        if response.status != 200:
                            state = "unhealthy"
                            last_error = f"health check returned HTTP {response.status}"
                except (URLError, TimeoutError, OSError) as exc:
                    state = "unhealthy"
                    last_error = str(exc)
            return InstanceStatus(
                server_id=server_id,
                state=state,
                container_name=name,
                last_error=last_error,
            )
        except NotFound:
            return InstanceStatus(server_id=server_id, state="missing")

    def sync_statuses(self) -> list[InstanceStatus]:
        """One-shot scan of all mcp-runtime containers for bulk reconciliation."""
        statuses: list[InstanceStatus] = []
        try:
            for c in self._client.containers.list(all=True, filters={"name": "mcp-runtime-"}):
                c.reload()
                docker_status = c.attrs.get("State", {}).get("Status", c.status)
                state = "running" if docker_status == "running" else docker_status
                server_id = (c.labels or {}).get("mcp.platform.runtime_id", "")
                if server_id:
                    statuses.append(
                        InstanceStatus(server_id=server_id, state=state, container_name=c.name)
                    )
        except Exception:
            pass
        return statuses

    def container_logs(self, server_id: str, tail: int = 80) -> list[str]:
        name = container_name(server_id)
        c = self._client.containers.get(name)
        raw = c.logs(tail=tail).decode("utf-8", errors="replace")
        return [line for line in raw.splitlines()[-40:] if line.strip()]

    def reload_config(self, server_id: str) -> dict:
        """POST /reload to runtime container — reloads tools.json and policy.json without restart."""
        name = container_name(server_id)
        s = self.status(server_id)
        if s.state != "running":
            raise RuntimeError(f"runtime not running (state: {s.state})")
        reload_url = f"http://{name}:8080/reload"
        req = _UrlRequest(reload_url, data=b"{}", method="POST")
        req.add_header("Content-Type", "application/json")
        try:
            with urlopen(req, timeout=10) as resp:
                return json.loads(resp.read()) if resp.status == 200 else {"ok": True}
        except Exception as exc:
            raise RuntimeError(f"reload failed: {exc}") from exc

    def build_image(self, context_path: Path, tag: str) -> None:
        self._client.images.build(path=str(context_path), tag=tag, rm=True, pull=False)
