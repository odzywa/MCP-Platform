from typing import Any

from mcp_platform_core.models import RuntimeDeploymentSpec


def default_runtime_security_context() -> dict[str, Any]:
    return {
        "run_as_non_root": True,
        "read_only_root_filesystem": True,
        "no_new_privileges": True,
        "drop_capabilities": ["ALL"],
        "allow_docker_socket": False,
        "allow_host_network": False,
        "seccomp_profile": "RuntimeDefault",
    }


def build_container_runtime_plan(spec: RuntimeDeploymentSpec) -> dict[str, Any]:
    """Return backend-neutral container intent for Docker/Podman/Kubernetes drivers.

    This is a deployment plan, not an executable shell command. Concrete drivers
    translate it to Docker Engine, rootless Podman, Compose, Kubernetes, or
    OpenShift API calls.
    """

    security_context = {
        **default_runtime_security_context(),
        **spec.security_context,
    }

    return {
        "name": spec.name,
        "image": spec.runtime_image,
        "replicas": spec.replicas,
        "endpoint": spec.endpoint,
        "env": spec.env,
        "labels": {
            "mcp.platform/server-id": spec.server_id,
            "mcp.platform/runtime-class": spec.runtime_class,
            **spec.labels,
        },
        "mounts": [
            {
                "type": "config",
                "source": spec.config_mount,
                "target": "/config",
                "read_only": True,
            }
        ],
        "secrets_mount": spec.secrets_mount,
        "resources": spec.resources,
        "security_context": security_context,
    }
