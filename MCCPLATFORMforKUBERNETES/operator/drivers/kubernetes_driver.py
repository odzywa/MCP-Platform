"""
KubernetesDeploymentDriver — zastępuje DockerDeploymentDriver na K8s/OpenShift.

Każdy MCP runtime server = Deployment + Service + ConfigMap + Secret + Route.
Operator używa ServiceAccount zamiast docker.sock.

Wymagania: pip install kubernetes>=29.0.0
"""
from __future__ import annotations

import hashlib
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
# Prefix dodawany do nazw obrazów platformy bez rejestru (np. mcp-runtime-shell:latest → <prefix>/mcp-runtime-shell:latest)
IMAGE_REGISTRY_PREFIX = os.getenv("MCP_RUNTIME_IMAGE_REGISTRY_PREFIX", "")

CPU_REQUEST = os.getenv("MCP_RUNTIME_CPU_REQUEST", "50m")
CPU_LIMIT   = os.getenv("MCP_RUNTIME_CPU_LIMIT",   "1000m")
MEM_REQUEST = os.getenv("MCP_RUNTIME_MEM_REQUEST", "64Mi")
MEM_LIMIT   = os.getenv("MCP_RUNTIME_MEM_LIMIT",   "512Mi")

MANAGED_BY_LABEL  = "app.kubernetes.io/managed-by"
MANAGED_BY_VALUE  = "mcp-platform"
RUNTIME_ID_LABEL  = "mcp-platform/runtime-id"
CONFIG_HASH_ANNOTATION = "mcp-platform/config-hash"
# Label ma limit 63 znaków, więc długie runtime_id jest w nim przycięte.
# Pełne id trzymamy w adnotacji (bez limitu) i to ją czyta sync_statuses.
RUNTIME_ID_ANNOTATION = "mcp-platform/runtime-id-full"

# Obrazy budowane przez platformę — tylko one dostają prefix rejestru.
# Rozszerzalne, bo Runtime Image Builder pozwala nadać obrazowi dowolną nazwę.
PLATFORM_IMAGE_PREFIXES = tuple(
    p.strip() for p in os.getenv(
        "MCP_RUNTIME_LOCAL_IMAGE_PREFIXES",
        "mcp-runtime-,mcp-generic-,mcp-platform-,mcp-",
    ).split(",") if p.strip()
)

# Jak długo cache'ujemy negatywny wynik detekcji OpenShift (sekundy).
_OPENSHIFT_RECHECK_SECONDS = 300


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

# Nazwy Service i wygenerowany host Route muszą się zmieścić w 63 znakach
# (label DNS), a runtime_id nie ma limitu długości po stronie control-plane.
_MAX_NAME = 63
# Najdłuższy sufiks doklejany do nazwy bazowej ("-config" = 7 znaków).
_MAX_SUFFIX = len("-config")


def _rt_name(sid: str) -> str:
    """Bazowa nazwa zasobów runtime, przycięta do limitu K8s z hashem na końcu."""
    base = f"mcp-runtime-{sid}"
    limit = _MAX_NAME - _MAX_SUFFIX
    if len(base) <= limit:
        return base
    digest = hashlib.sha1(sid.encode()).hexdigest()[:6]
    return base[: limit - 7].rstrip("-.") + "-" + digest


def _label_value(value: str) -> str:
    """Wartość labela: max 63 znaki, musi kończyć się alfanumerycznie."""
    if len(value) <= _MAX_NAME:
        return value
    digest = hashlib.sha1(value.encode()).hexdigest()[:6]
    return value[: _MAX_NAME - 7].rstrip("-._") + "-" + digest


def _dep(sid: str) -> str:       return _rt_name(sid)
def _cm(sid: str) -> str:        return f"{_rt_name(sid)}-config"
def _sec(sid: str) -> str:       return f"{_rt_name(sid)}-env"
def _secfiles(sid: str) -> str:  return f"{_rt_name(sid)}-files"
def _secconf(sid: str) -> str:   return f"{_rt_name(sid)}-rtconf"
def _svc(sid: str) -> str:       return _rt_name(sid)
def _route(sid: str) -> str:     return _rt_name(sid)

def _labels(sid: str) -> dict[str, str]:
    return {
        MANAGED_BY_LABEL:  MANAGED_BY_VALUE,
        RUNTIME_ID_LABEL:  _label_value(sid),
        "app":             _dep(sid),
    }


# ── Ładowanie plików konfiguracyjnych ─────────────────────────────────────────

# Pliki niepoufne → ConfigMap
_CONFIG_FILES = [
    "tools.json",
    "policy.json",
    "adapter-config.json",
    "targets.json",
    "secrets.json",
]

# runtime-config.json zawiera mcp_auth_token — nie może trafić do ConfigMapy,
# którą widzi każdy z `get configmaps` i która nie jest szyfrowana at-rest.
# Ląduje w Secrecie i jest scalana z ConfigMapą w projected volume pod /config.
_SECRET_CONFIG_FILES = [
    "runtime-config.json",
]


def _read_files(config_dir: Path, names: list[str]) -> dict[str, str]:
    data: dict[str, str] = {}
    for fname in names:
        fp = config_dir / fname
        if fp.exists():
            data[fname] = fp.read_text()
    return data


def _load_config_files(config_dir: Path) -> dict[str, str]:
    return _read_files(config_dir, _CONFIG_FILES)


def _load_secret_config_files(config_dir: Path) -> dict[str, str]:
    return _read_files(config_dir, _SECRET_CONFIG_FILES)


def _load_env_vars(config_dir: Path) -> dict[str, str]:
    """runtime-env.json → env vars → Secret."""
    fp = config_dir / "runtime-env.json"
    if not fp.exists():
        return {}
    try:
        return dict(json.loads(fp.read_text()).get("env", {}))
    except Exception:
        return {}


def _load_secret_files(config_dir: Path) -> dict[str, str]:
    """<config>/secrets/* → osobny Secret montowany pod /config/secrets."""
    secrets_dir = config_dir / "secrets"
    if not secrets_dir.is_dir():
        return {}
    data: dict[str, str] = {}
    for fp in sorted(secrets_dir.iterdir()):
        if fp.is_file():
            try:
                data[fp.name] = fp.read_text()
            except (OSError, UnicodeDecodeError):
                continue
    return data


def _config_hash(config_dir: Path) -> str:
    """
    Odcisk całej konfiguracji runtime'u. Trafia do adnotacji pod template,
    dzięki czemu zmiana tools.json/policy.json/credentiali wymusza nowy
    ReplicaSet — runtime czyta pliki tylko przy starcie.
    """
    digest = hashlib.sha256()
    for name, content in sorted(_load_config_files(config_dir).items()):
        digest.update(name.encode())
        digest.update(content.encode())
    for name, content in sorted(_load_secret_config_files(config_dir).items()):
        digest.update(name.encode())
        digest.update(content.encode())
    for name, content in sorted(_load_env_vars(config_dir).items()):
        digest.update(name.encode())
        digest.update(str(content).encode())
    for name, content in sorted(_load_secret_files(config_dir).items()):
        digest.update(name.encode())
        digest.update(content.encode())
    return digest.hexdigest()[:16]


# ── Builder objektów K8s ──────────────────────────────────────────────────────

def _make_configmap(sid: str, config_dir: Path) -> k8s.V1ConfigMap:
    return k8s.V1ConfigMap(
        metadata=k8s.V1ObjectMeta(name=_cm(sid), namespace=NAMESPACE, labels=_labels(sid)),
        data=_load_config_files(config_dir),
    )


def _make_secret(sid: str, env_vars: dict[str, str]) -> k8s.V1Secret:
    return k8s.V1Secret(
        metadata=k8s.V1ObjectMeta(name=_sec(sid), namespace=NAMESPACE, labels=_labels(sid)),
        string_data=env_vars or {},
        type="Opaque",
    )


def _make_secret_config(sid: str, files: dict[str, str]) -> k8s.V1Secret:
    return k8s.V1Secret(
        metadata=k8s.V1ObjectMeta(name=_secconf(sid), namespace=NAMESPACE, labels=_labels(sid)),
        string_data=files or {},
        type="Opaque",
    )


def _make_secret_files(sid: str, files: dict[str, str]) -> k8s.V1Secret:
    return k8s.V1Secret(
        metadata=k8s.V1ObjectMeta(name=_secfiles(sid), namespace=NAMESPACE, labels=_labels(sid)),
        string_data=files or {},
        type="Opaque",
    )


def _annotations(sid: str, config_hash: str = "") -> dict[str, str]:
    ann = {RUNTIME_ID_ANNOTATION: sid}
    if config_hash:
        ann[CONFIG_HASH_ANNOTATION] = config_hash
    return ann


def _make_deployment(spec: DeploySpec, config_hash: str = "") -> k8s.V1Deployment:
    sid = spec.server_id
    labels = _labels(sid)

    env_values: dict[str, str] = {
        "RUNTIME_CONFIG_DIR":        "/config",
        # readOnlyRootFilesystem + losowy UID (OpenShift SCC) = brak zapisywalnego $HOME.
        # oc/kubectl i inne narzędzia muszą mieć gdzie trzymać cache.
        "HOME":                      "/tmp",
        "KUBECACHEDIR":              "/tmp/.kube/cache",
        "MCP_RUNTIME_ID":            sid,
        "MCP_PLATFORM_CALLBACK_URL": CALLBACK_URL,
    }
    # Dodatkowe env z spec (np. BACKEND_BASE_URL dla openapi runtime) — nadpisują domyślne
    env_values.update(spec.env or {})
    env = [k8s.V1EnvVar(name=k, value=v) for k, v in env_values.items()]

    env_from = [
        k8s.V1EnvFromSource(
            secret_ref=k8s.V1SecretEnvSource(name=_sec(sid), optional=True)
        )
    ]

    return k8s.V1Deployment(
        metadata=k8s.V1ObjectMeta(name=_dep(sid), namespace=NAMESPACE, labels=labels,
                                  annotations=_annotations(sid)),
        spec=k8s.V1DeploymentSpec(
            replicas=1,
            strategy=k8s.V1DeploymentStrategy(type="Recreate"),
            selector=k8s.V1LabelSelector(match_labels={"app": _dep(sid)}),
            template=k8s.V1PodTemplateSpec(
                metadata=k8s.V1ObjectMeta(
                    labels=labels,
                    annotations=_annotations(sid, config_hash),
                ),
                spec=k8s.V1PodSpec(
                    automount_service_account_token=False,
                    security_context=k8s.V1PodSecurityContext(
                        run_as_non_root=True,
                        seccomp_profile=k8s.V1SeccompProfile(type="RuntimeDefault"),
                    ),
                    containers=[k8s.V1Container(
                        name="runtime",
                        image=_qualify_image(spec.runtime_image),
                        image_pull_policy="Always",
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
                            k8s.V1VolumeMount(name="secret-files", mount_path="/config/secrets", read_only=True),
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
                            # Projected: runtime widzi jeden katalog /config, ale poufne
                            # runtime-config.json leży w Secrecie, nie w ConfigMapie.
                            projected=k8s.V1ProjectedVolumeSource(
                                default_mode=0o444,
                                sources=[
                                    k8s.V1VolumeProjection(
                                        config_map=k8s.V1ConfigMapProjection(name=_cm(sid)),
                                    ),
                                    k8s.V1VolumeProjection(
                                        secret=k8s.V1SecretProjection(name=_secconf(sid)),
                                    ),
                                ],
                            ),
                        ),
                        k8s.V1Volume(
                            name="secret-files",
                            # 0444: pliki Secreta należą do root:root, a kontener dostaje
                            # losowy UID (OpenShift) — 0400/0440 byłyby nieczytelne.
                            secret=k8s.V1SecretVolumeSource(
                                secret_name=_secfiles(sid), default_mode=0o444, optional=True,
                            ),
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
    """
    Dodaj prefix rejestru wyłącznie do obrazów budowanych przez platformę.
    Obrazy publiczne (nginx:latest, python:3.12-slim) i te z jawną ścieżką
    rejestru zostają nietknięte — inaczej dostalibyśmy ImagePullBackOff.
    """
    if not IMAGE_REGISTRY_PREFIX:
        return image
    if "/" in image:  # ma już rejestr lub ścieżkę — nie ruszamy
        return image
    if not image.startswith(PLATFORM_IMAGE_PREFIXES):
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
        self._openshift = False
        # -inf, nie 0.0: time.monotonic() liczy od startu systemu, więc 0.0
        # oznaczałoby "sprawdzone przed chwilą" przez pierwsze 5 min po bootcie.
        self._openshift_checked_at = float("-inf")

    def _check_openshift(self) -> bool:
        try:
            for g in k8s.ApisApi().get_api_versions().groups:
                if g.name == "route.openshift.io":
                    return True
        except Exception:
            pass
        return False

    def _is_openshift(self) -> bool:
        """
        Detekcja z odświeżaniem — pojedyncze nieudane discovery przy starcie
        nie może na stałe zdegradować drivera do trybu vanilla K8s (brak Route).
        """
        if self._openshift:
            return True
        now = time.monotonic()
        if now - self._openshift_checked_at >= _OPENSHIFT_RECHECK_SECONDS:
            self._openshift_checked_at = now
            self._openshift = self._check_openshift()
        return self._openshift

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

    def _upsert_secret_config(self, sid: str, files: dict[str, str]) -> None:
        obj = _make_secret_config(sid, files)
        try:
            self._core.read_namespaced_secret(_secconf(sid), NAMESPACE)
            self._core.replace_namespaced_secret(_secconf(sid), NAMESPACE, obj)
        except ApiException as e:
            if e.status == 404:
                self._core.create_namespaced_secret(NAMESPACE, obj)
            else:
                raise

    def _upsert_secret_files(self, sid: str, files: dict[str, str]) -> None:
        obj = _make_secret_files(sid, files)
        try:
            self._core.read_namespaced_secret(_secfiles(sid), NAMESPACE)
            self._core.replace_namespaced_secret(_secfiles(sid), NAMESPACE, obj)
        except ApiException as e:
            if e.status == 404:
                self._core.create_namespaced_secret(NAMESPACE, obj)
            else:
                raise

    def _upsert_deployment(self, spec: DeploySpec, config_hash: str = "",
                           preserve_replicas: bool = False) -> None:
        obj = _make_deployment(spec, config_hash)
        try:
            existing = self._apps.read_namespaced_deployment(_dep(spec.server_id), NAMESPACE)
            if preserve_replicas:
                # Szablon ma na stałe replicas=1; bez tego reload wystartowałby
                # runtime zatrzymany wcześniej przez użytkownika.
                obj.spec.replicas = existing.spec.replicas or 0
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
        if not self._is_openshift():
            return None
        body = _make_route(sid)
        route_name = _route(sid)
        try:
            existing = self._custom.get_namespaced_custom_object(
                "route.openshift.io", "v1", NAMESPACE, "routes", route_name,
            )
            body["metadata"]["resourceVersion"] = existing["metadata"]["resourceVersion"]
            # Zachowaj host przypisany przez router — replace bez hosta wygenerowałby nowy URL.
            host = (existing.get("spec") or {}).get("host")
            if host:
                body["spec"]["host"] = host
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
        if not self._is_openshift():
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

    def _replicas(self, sid: str) -> int | None:
        try:
            dep = self._apps.read_namespaced_deployment(_dep(sid), NAMESPACE)
        except ApiException as e:
            if e.status == 404:
                return None
            raise
        return dep.spec.replicas or 0

    # ── Publiczny interfejs (identyczny jak DockerDeploymentDriver) ────────────

    def apply(self, spec: DeploySpec, preserve_replicas: bool = False) -> InstanceStatus:
        config_dir = Path(spec.config_mount)
        self._upsert_cm(spec.server_id, config_dir)
        self._upsert_secret(spec.server_id, _load_env_vars(config_dir))
        self._upsert_secret_config(spec.server_id, _load_secret_config_files(config_dir))
        self._upsert_secret_files(spec.server_id, _load_secret_files(config_dir))
        self._upsert_deployment(spec, _config_hash(config_dir), preserve_replicas)
        self._upsert_service(spec.server_id)
        route_url = self._upsert_route(spec.server_id)
        endpoint = route_url or self._internal_url(spec.server_id)
        replicas = self._replicas(spec.server_id) or 0
        return InstanceStatus(
            server_id=spec.server_id,
            state="starting" if replicas > 0 else "stopped",
            endpoint_url=endpoint,
            container_name=_dep(spec.server_id),
        )

    def delete(self, server_id: str) -> InstanceStatus:
        self._safe_delete(self._apps.delete_namespaced_deployment, _dep(server_id), namespace=NAMESPACE)
        self._safe_delete(self._core.delete_namespaced_service,    _svc(server_id), namespace=NAMESPACE)
        self._safe_delete(self._core.delete_namespaced_config_map, _cm(server_id),  namespace=NAMESPACE)
        self._safe_delete(self._core.delete_namespaced_secret,     _sec(server_id), namespace=NAMESPACE)
        self._safe_delete(self._core.delete_namespaced_secret,     _secfiles(server_id), namespace=NAMESPACE)
        self._safe_delete(self._core.delete_namespaced_secret,     _secconf(server_id),  namespace=NAMESPACE)
        if self._is_openshift():
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
            return InstanceStatus(server_id=server_id, state="starting",
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
            replicas = self._replicas(server_id)
            if replicas is None:
                return InstanceStatus(server_id=server_id, state="missing", container_name=_dep(server_id))
            self._apps.patch_namespaced_deployment(_dep(server_id), NAMESPACE, patch)
            url = self._route_url(server_id) or self._internal_url(server_id)
            # Rollout restart nie skaluje w górę — zatrzymany runtime pozostaje zatrzymany.
            state = "starting" if replicas > 0 else "stopped"
            return InstanceStatus(server_id=server_id, state=state,
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
            # Zawsze przez Service: Route to zewnętrzny host z certyfikatem routera,
            # którego operator wewnątrz klastra nie zweryfikuje.
            health_url = self._internal_url(server_id).replace("/mcp", "/health")
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
            # Adnotacja trzyma pełne id; label bywa przycięty do 63 znaków.
            sid = (dep.metadata.annotations or {}).get(RUNTIME_ID_ANNOTATION) \
                or (dep.metadata.labels or {}).get(RUNTIME_ID_LABEL, "")
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
        if not self._is_openshift():
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
        # CustomObjectsApi nie obsługuje subresourców (plural z '/' zostaje
        # zakodowany jako %2F → 404), więc wołamy surową ścieżkę API.
        self._custom.api_client.call_api(
            f"/apis/build.openshift.io/v1/namespaces/{NAMESPACE}"
            f"/buildconfigs/{bc_name}/instantiate",
            "POST",
            body=build_request,
            header_params={"Accept": "application/json", "Content-Type": "application/json"},
            auth_settings=["BearerToken"],
            response_type="object",
            _return_http_data_only=True,
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
