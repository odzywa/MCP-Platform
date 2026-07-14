"""
KubernetesDeploymentDriver — zastępuje DockerDeploymentDriver na K8s/OpenShift.

Każdy MCP runtime server = Deployment + Service + ConfigMap + Secret + Route.
Operator używa ServiceAccount zamiast docker.sock.

Wymagania: pip install kubernetes>=29.0.0
"""
from __future__ import annotations

import json
import os
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from kubernetes import client as k8s, config as k8s_config
from kubernetes.client.rest import ApiException


# ── Config z env ───────────────────────────────────────────────────────────────

NAMESPACE = os.getenv("MCP_RUNTIME_NAMESPACE", "mcp-platform")
CONFIG_ROOT = Path(os.getenv("MCP_PLATFORM_CONFIG_ROOT", "/data/configs"))
CALLBACK_URL = os.getenv("MCP_PLATFORM_CALLBACK_URL", "http://mcp-platform:8080")
# Prefix dodawany do nazw obrazów bez rejestru (np. mcp-runtime-shell:latest → <prefix>/mcp-runtime-shell:latest)
IMAGE_REGISTRY_PREFIX = os.getenv("MCP_RUNTIME_IMAGE_REGISTRY_PREFIX", "")

CPU_REQUEST = os.getenv("MCP_RUNTIME_CPU_REQUEST", "50m")
CPU_LIMIT   = os.getenv("MCP_RUNTIME_CPU_LIMIT",   "1000m")
MEM_REQUEST = os.getenv("MCP_RUNTIME_MEM_REQUEST", "64Mi")
MEM_LIMIT   = os.getenv("MCP_RUNTIME_MEM_LIMIT",   "512Mi")

MANAGED_BY_LABEL  = "app.kubernetes.io/managed-by"
MANAGED_BY_VALUE  = "mcp-platform"
RUNTIME_ID_LABEL  = "mcp-platform/runtime-id"


# ── Shared dataclasses (identyczne jak w docker_driver) ────────────────────────

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
    container_name: str | None = None  # tutaj = nazwa Deployment
    last_error: str | None = None


# ── Nazewnictwo zasobów ────────────────────────────────────────────────────────

def _dep(sid: str) -> str:    return f"mcp-runtime-{sid}"
def _cm(sid: str) -> str:     return f"mcp-runtime-{sid}-config"
def _sec(sid: str) -> str:    return f"mcp-runtime-{sid}-env"
def _svc(sid: str) -> str:    return f"mcp-runtime-{sid}"
def _route(sid: str) -> str:  return f"mcp-runtime-{sid}"

def _labels(sid: str) -> dict[str, str]:
    return {
        MANAGED_BY_LABEL:  MANAGED_BY_VALUE,
        RUNTIME_ID_LABEL:  sid,
        "app":             _dep(sid),
    }


# ── Ładowanie plików konfiguracyjnych ─────────────────────────────────────────

# Pliki niepoufne → ConfigMap
_CONFIG_FILES = [
    "runtime-config.json",
    "tools.json",
    "policy.json",
    "adapter-config.json",
    "targets.json",
    "secrets.json",
]

def _load_config_files(config_dir: Path) -> dict[str, str]:
    data: dict[str, str] = {}
    for fname in _CONFIG_FILES:
        fp = config_dir / fname
        if fp.exists():
            data[fname] = fp.read_text()
    return data


def _load_env_vars(config_dir: Path) -> dict[str, str]:
    """runtime-env.json → env vars → Secret."""
    fp = config_dir / "runtime-env.json"
    if not fp.exists():
        return {}
    try:
        return dict(json.loads(fp.read_text()).get("env", {}))
    except Exception:
        return {}


# ── Builder objektów K8s ──────────────────────────────────────────────────────

def _make_configmap(sid: str, config_dir: Path) -> k8s.V1ConfigMap:
    return k8s.V1ConfigMap(
        metadata=k8s.V1ObjectMeta(name=_cm(sid), namespace=NAMESPACE, labels=_labels(sid)),
        data=_load_config_files(config_dir),
    )


def _make_secret(sid: str, env_vars: dict[str, str]) -> k8s.V1Secret:
    return k8s.V1Secret(
        metadata=k8s.V1ObjectMeta(name=_sec(sid), namespace=NAMESPACE, labels=_labels(sid)),
        string_data=env_vars or {"_empty": "true"},
        type="Opaque",
    )


def _make_deployment(spec: DeploySpec) -> k8s.V1Deployment:
    sid = spec.server_id
    labels = _labels(sid)

    env = [
        k8s.V1EnvVar(name="RUNTIME_CONFIG_DIR",           value="/config"),
        k8s.V1EnvVar(name="MCP_RUNTIME_ID",               value=sid),
        k8s.V1EnvVar(name="MCP_PLATFORM_CALLBACK_URL",    value=CALLBACK_URL),
    ]
    # Dodatkowe env z spec (np. BACKEND_BASE_URL dla openapi runtime)
    for k, v in (spec.env or {}).items():
        env.append(k8s.V1EnvVar(name=k, value=v))

    env_from = [
        k8s.V1EnvFromSource(
            secret_ref=k8s.V1SecretEnvSource(name=_sec(sid), optional=True)
        )
    ]

    return k8s.V1Deployment(
        metadata=k8s.V1ObjectMeta(name=_dep(sid), namespace=NAMESPACE, labels=labels),
        spec=k8s.V1DeploymentSpec(
            replicas=1,
            strategy=k8s.V1DeploymentStrategy(type="Recreate"),
            selector=k8s.V1LabelSelector(match_labels={"app": _dep(sid)}),
            template=k8s.V1PodTemplateSpec(
                metadata=k8s.V1ObjectMeta(labels=labels),
                spec=k8s.V1PodSpec(
                    automount_service_account_token=False,
                    security_context=k8s.V1PodSecurityContext(
                        run_as_non_root=True,
                    ),
                    containers=[k8s.V1Container(
                        name="runtime",
                        image=_qualify_image(spec.runtime_image),
                        image_pull_policy="IfNotPresent",
                        ports=[k8s.V1ContainerPort(container_port=8080, name="mcp")],
                        env=env,
                        env_from=env_from,
                        security_context=k8s.V1SecurityContext(
                            read_only_root_filesystem=True,
                            allow_privilege_escalation=False,
                            run_as_non_root=True,
                            capabilities=k8s.V1Capabilities(drop=["ALL"]),
                        ),
                        resources=k8s.V1ResourceRequirements(
                            requests={"cpu": CPU_REQUEST, "memory": MEM_REQUEST},
                            limits={"cpu": CPU_LIMIT,    "memory": MEM_LIMIT},
                        ),
                        volume_mounts=[
                            k8s.V1VolumeMount(name="config", mount_path="/config", read_only=True),
                            k8s.V1VolumeMount(name="tmp",    mount_path="/tmp"),
                        ],
                        readiness_probe=k8s.V1Probe(
                            http_get=k8s.V1HTTPGetAction(path="/health", port=8080),
                            initial_delay_seconds=5,
                            period_seconds=10,
                        ),
                        liveness_probe=k8s.V1Probe(
                            http_get=k8s.V1HTTPGetAction(path="/health", port=8080),
                            initial_delay_seconds=15,
                            period_seconds=30,
                            failure_threshold=3,
                        ),
                    )],
                    volumes=[
                        k8s.V1Volume(
                            name="config",
                            config_map=k8s.V1ConfigMapVolumeSource(name=_cm(sid)),
                        ),
                        k8s.V1Volume(
                            name="tmp",
                            empty_dir=k8s.V1EmptyDirVolumeSource(medium="Memory", size_limit="64Mi"),
                        ),
                    ],
                ),
            ),
        ),
    )


def _make_service(sid: str) -> k8s.V1Service:
    return k8s.V1Service(
        metadata=k8s.V1ObjectMeta(name=_svc(sid), namespace=NAMESPACE, labels=_labels(sid)),
        spec=k8s.V1ServiceSpec(
            selector={"app": _dep(sid)},
            ports=[k8s.V1ServicePort(name="mcp", port=8080, target_port=8080)],
            type="ClusterIP",
        ),
    )


def _make_route(sid: str) -> dict:
    """OpenShift Route jako raw dict (custom objects API)."""
    return {
        "apiVersion": "route.openshift.io/v1",
        "kind": "Route",
        "metadata": {
            "name": _route(sid),
            "namespace": NAMESPACE,
            "labels": _labels(sid),
        },
        "spec": {
            "to": {"kind": "Service", "name": _svc(sid), "weight": 100},
            "port": {"targetPort": "mcp"},
            "tls": {
                "termination": "edge",
                "insecureEdgeTerminationPolicy": "Redirect",
            },
        },
    }


def _qualify_image(image: str) -> str:
    """Dodaj prefix rejestru jeśli obraz nie ma adresu rejestru."""
    if not IMAGE_REGISTRY_PREFIX:
        return image
    # Jeśli obraz już ma rejestr (zawiera '/' z domeną lub adresem svc) — zostaw
    if "/" in image and ("." in image.split("/")[0] or ":" in image.split("/")[0]):
        return image
    return f"{IMAGE_REGISTRY_PREFIX}/{image}"


# ── Driver ─────────────────────────────────────────────────────────────────────

class KubernetesDeploymentDriver:
    """
    Kubernetes/OpenShift driver — zastępuje DockerDeploymentDriver.
    Używa ServiceAccount (in-cluster config) zamiast docker.sock.
    """

    name = "kubernetes"

    def __init__(self) -> None:
        try:
            k8s_config.load_incluster_config()
        except k8s_config.ConfigException:
            k8s_config.load_kube_config()

        self._apps   = k8s.AppsV1Api()
        self._core   = k8s.CoreV1Api()
        self._custom = k8s.CustomObjectsApi()
        self._openshift = self._check_openshift()

    def _check_openshift(self) -> bool:
        try:
            for g in k8s.ApisApi().get_api_versions().groups:
                if g.name == "route.openshift.io":
                    return True
        except Exception:
            pass
        return False

    # ── Apply / create or update ───────────────────────────────────────────────

    def _upsert_cm(self, sid: str, config_dir: Path) -> None:
        obj = _make_configmap(sid, config_dir)
        try:
            self._core.read_namespaced_config_map(_cm(sid), NAMESPACE)
            self._core.replace_namespaced_config_map(_cm(sid), NAMESPACE, obj)
        except ApiException as e:
            if e.status == 404:
                self._core.create_namespaced_config_map(NAMESPACE, obj)
            else:
                raise

    def _upsert_secret(self, sid: str, env_vars: dict[str, str]) -> None:
        obj = _make_secret(sid, env_vars)
        try:
            self._core.read_namespaced_secret(_sec(sid), NAMESPACE)
            self._core.replace_namespaced_secret(_sec(sid), NAMESPACE, obj)
        except ApiException as e:
            if e.status == 404:
                self._core.create_namespaced_secret(NAMESPACE, obj)
            else:
                raise

    def _upsert_deployment(self, spec: DeploySpec) -> None:
        obj = _make_deployment(spec)
        try:
            self._apps.read_namespaced_deployment(_dep(spec.server_id), NAMESPACE)
            self._apps.replace_namespaced_deployment(_dep(spec.server_id), NAMESPACE, obj)
        except ApiException as e:
            if e.status == 404:
                self._apps.create_namespaced_deployment(NAMESPACE, obj)
            else:
                raise

    def _upsert_service(self, sid: str) -> None:
        obj = _make_service(sid)
        try:
            self._core.read_namespaced_service(_svc(sid), NAMESPACE)
            self._core.patch_namespaced_service(_svc(sid), NAMESPACE, obj)
        except ApiException as e:
            if e.status == 404:
                self._core.create_namespaced_service(NAMESPACE, obj)
            else:
                raise

    def _upsert_route(self, sid: str) -> str | None:
        if not self._openshift:
            return None
        body = _make_route(sid)
        route_name = _route(sid)
        try:
            existing = self._custom.get_namespaced_custom_object(
                "route.openshift.io", "v1", NAMESPACE, "routes", route_name,
            )
            body["metadata"]["resourceVersion"] = existing["metadata"]["resourceVersion"]
            result = self._custom.replace_namespaced_custom_object(
                "route.openshift.io", "v1", NAMESPACE, "routes", route_name, body,
            )
        except ApiException as e:
            if e.status == 404:
                result = self._custom.create_namespaced_custom_object(
                    "route.openshift.io", "v1", NAMESPACE, "routes", body,
                )
            else:
                raise
        host = (result.get("spec") or {}).get("host") or ""
        return f"https://{host}/mcp" if host else None

    def _safe_delete(self, fn, name: str, **kw) -> None:
        try:
            fn(name=name, **kw)
        except ApiException as e:
            if e.status != 404:
                raise

    def _route_url(self, sid: str) -> str | None:
        if not self._openshift:
            return None
        try:
            r = self._custom.get_namespaced_custom_object(
                "route.openshift.io", "v1", NAMESPACE, "routes", _route(sid),
            )
            host = (r.get("spec") or {}).get("host") or ""
            if host:
                tls = (r.get("spec") or {}).get("tls")
                scheme = "https" if tls else "http"
                return f"{scheme}://{host}/mcp"
        except ApiException:
            pass
        return None

    def _internal_url(self, sid: str) -> str:
        return f"http://{_svc(sid)}.{NAMESPACE}.svc:8080/mcp"

    # ── Publiczny interfejs (identyczny jak DockerDeploymentDriver) ────────────

    def apply(self, spec: DeploySpec) -> InstanceStatus:
        config_dir = Path(spec.config_mount)
        self._upsert_cm(spec.server_id, config_dir)
        self._upsert_secret(spec.server_id, _load_env_vars(config_dir))
        self._upsert_deployment(spec)
        self._upsert_service(spec.server_id)
        route_url = self._upsert_route(spec.server_id)
        endpoint = route_url or self._internal_url(spec.server_id)
        return InstanceStatus(
            server_id=spec.server_id,
            state="running",
            endpoint_url=endpoint,
            container_name=_dep(spec.server_id),
        )

    def delete(self, server_id: str) -> InstanceStatus:
        self._safe_delete(self._apps.delete_namespaced_deployment, _dep(server_id), namespace=NAMESPACE)
        self._safe_delete(self._core.delete_namespaced_service,    _svc(server_id), namespace=NAMESPACE)
        self._safe_delete(self._core.delete_namespaced_config_map, _cm(server_id),  namespace=NAMESPACE)
        self._safe_delete(self._core.delete_namespaced_secret,     _sec(server_id), namespace=NAMESPACE)
        if self._openshift:
            try:
                self._custom.delete_namespaced_custom_object(
                    "route.openshift.io", "v1", NAMESPACE, "routes", _route(server_id),
                )
            except ApiException as e:
                if e.status != 404:
                    raise
        return InstanceStatus(server_id=server_id, state="deleted", container_name=_dep(server_id))

    def stop(self, server_id: str) -> InstanceStatus:
        try:
            self._apps.patch_namespaced_deployment_scale(
                _dep(server_id), NAMESPACE, {"spec": {"replicas": 0}},
            )
            return InstanceStatus(server_id=server_id, state="stopped", container_name=_dep(server_id))
        except ApiException as e:
            if e.status == 404:
                return InstanceStatus(server_id=server_id, state="missing", container_name=_dep(server_id))
            raise

    def start(self, server_id: str) -> InstanceStatus:
        try:
            self._apps.patch_namespaced_deployment_scale(
                _dep(server_id), NAMESPACE, {"spec": {"replicas": 1}},
            )
            url = self._route_url(server_id) or self._internal_url(server_id)
            return InstanceStatus(server_id=server_id, state="running",
                                  endpoint_url=url, container_name=_dep(server_id))
        except ApiException as e:
            if e.status == 404:
                return InstanceStatus(server_id=server_id, state="missing", container_name=_dep(server_id))
            raise

    def restart(self, server_id: str) -> InstanceStatus:
        patch = {"spec": {"template": {"metadata": {"annotations": {
            "kubectl.kubernetes.io/restartedAt": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }}}}}
        try:
            self._apps.patch_namespaced_deployment(_dep(server_id), NAMESPACE, patch)
            url = self._route_url(server_id) or self._internal_url(server_id)
            return InstanceStatus(server_id=server_id, state="running",
                                  endpoint_url=url, container_name=_dep(server_id))
        except ApiException as e:
            if e.status == 404:
                return InstanceStatus(server_id=server_id, state="missing", container_name=_dep(server_id))
            raise

    def status(self, server_id: str) -> InstanceStatus:
        try:
            dep = self._apps.read_namespaced_deployment(_dep(server_id), NAMESPACE)
        except ApiException as e:
            if e.status == 404:
                return InstanceStatus(server_id=server_id, state="missing",
                                      container_name=_dep(server_id))
            raise

        desired = dep.spec.replicas or 0
        ready   = dep.status.ready_replicas or 0

        if desired == 0:
            state = "stopped"
        elif ready == 0:
            state = "starting"
        else:
            state = "running"

        url = self._route_url(server_id) or self._internal_url(server_id)

        if state == "running":
            health_url = url.replace("/mcp", "/health")
            try:
                urllib.request.urlopen(health_url, timeout=3)
            except Exception as exc:
                return InstanceStatus(server_id=server_id, state="unhealthy",
                                      endpoint_url=url, container_name=_dep(server_id),
                                      last_error=str(exc))

        return InstanceStatus(server_id=server_id, state=state,
                              endpoint_url=url, container_name=_dep(server_id))

    def sync_statuses(self) -> list[InstanceStatus]:
        try:
            deps = self._apps.list_namespaced_deployment(
                NAMESPACE, label_selector=f"{MANAGED_BY_LABEL}={MANAGED_BY_VALUE}",
            )
        except ApiException:
            return []

        result: list[InstanceStatus] = []
        for dep in deps.items:
            sid = (dep.metadata.labels or {}).get(RUNTIME_ID_LABEL, "")
            if not sid:
                continue
            desired = dep.spec.replicas or 0
            ready   = dep.status.ready_replicas or 0
            state   = "stopped" if desired == 0 else ("running" if ready > 0 else "starting")
            url     = self._route_url(sid) or self._internal_url(sid)
            result.append(InstanceStatus(server_id=sid, state=state,
                                         endpoint_url=url, container_name=dep.metadata.name))
        return result

    def build_image(self, context_path: Path, tag: str) -> None:
        """Triggeruje OpenShift BuildConfig. Na vanilla K8s — push obraz ręcznie."""
        if not self._openshift:
            raise NotImplementedError(
                f"build_image nie działa na vanilla K8s. "
                f"Push obraz {tag} ręcznie do rejestru."
            )
        # Nazwa BuildConfig = część tagu bez registry i :tag
        bc_name = tag.split("/")[-1].split(":")[0]
        build_request = {
            "apiVersion": "build.openshift.io/v1",
            "kind": "BuildRequest",
            "metadata": {"name": bc_name},
        }
        self._custom.create_namespaced_custom_object(
            "build.openshift.io", "v1", NAMESPACE,
            f"buildconfigs/{bc_name}/instantiate", build_request,
        )

    def container_logs(self, server_id: str, tail: int = 100) -> list[str]:
        try:
            pods = self._core.list_namespaced_pod(
                NAMESPACE, label_selector=f"app={_dep(server_id)}",
            )
            if not pods.items:
                return []
            pod = pods.items[0]
            logs = self._core.read_namespaced_pod_log(
                pod.metadata.name, NAMESPACE, container="runtime", tail_lines=tail,
            )
            return [l for l in logs.splitlines() if l]
        except ApiException:
            return []
