"""Choices offered by the image builder: base images and tools that can be added on top."""
from typing import Any

# Platform runtime images — a custom image is one of these plus extra tools,
# so the result still contains the MCP runtime and can be deployed as a server.
PLATFORM_BASE_IMAGES: list[dict[str, Any]] = [
    {
        "image": "mcp-runtime-shell:latest",
        "label": "mcp-runtime-shell — komendy shell (zalecany)",
        "contains": "oc, kubectl, curl, jq, ssh, ping, tar, gzip",
        "runtime_class": "shell-readonly / shell-readwrite",
        "execution_types": ["shell"],
        "family": "rhel",
    },
    {
        "image": "mcp-runtime-http-gateway:latest",
        "label": "mcp-runtime-http-gateway — wywołania HTTP/REST",
        "contains": "klient HTTP (httpx)",
        "runtime_class": "http-gateway",
        "execution_types": ["http_request"],
        "family": "rhel",
    },
    {
        "image": "mcp-runtime-openapi:latest",
        "label": "mcp-runtime-openapi — auto-MCP ze specyfikacji OpenAPI",
        "contains": "FastMCP.from_openapi",
        "runtime_class": "openapi",
        "execution_types": ["http_request"],
        "family": "rhel",
    },
]

# All platform images are built on this one (see runtime-*/Dockerfile).
PLATFORM_IMAGE_BASE = "registry.access.redhat.com/ubi9/python-312-minimal"

# System package names differ between distributions; "rhel" covers the UBI9-based platform images.
SYSTEM_TOOL_PRESETS: list[dict[str, Any]] = [
    {"label": "git", "packages": {"rhel": "git", "debian": "git", "alpine": "git"}},
    {"label": "psql (PostgreSQL)", "packages": {"rhel": "postgresql", "debian": "postgresql-client", "alpine": "postgresql-client"}},
    {"label": "dig / nslookup", "packages": {"rhel": "bind-utils", "debian": "dnsutils", "alpine": "bind-tools"}},
    {"label": "nc (netcat)", "packages": {"rhel": "nmap-ncat", "debian": "netcat-openbsd", "alpine": "netcat-openbsd"}},
    {"label": "wget", "packages": {"rhel": "wget", "debian": "wget", "alpine": "wget"}},
    {"label": "unzip", "packages": {"rhel": "unzip", "debian": "unzip", "alpine": "unzip"}},
    {"label": "rsync", "packages": {"rhel": "rsync", "debian": "rsync", "alpine": "rsync"}},
    {"label": "openssl", "packages": {"rhel": "openssl", "debian": "openssl", "alpine": "openssl"}},
    {"label": "ps / top", "packages": {"rhel": "procps-ng", "debian": "procps", "alpine": "procps"}},
]

PIP_TOOL_PRESETS: list[dict[str, str]] = [
    {"label": "AWS CLI", "package": "awscli"},
    {"label": "Ansible", "package": "ansible-core"},
    {"label": "Kubernetes (klient Python)", "package": "kubernetes"},
    {"label": "boto3", "package": "boto3"},
    {"label": "httpx", "package": "httpx"},
    {"label": "PyYAML", "package": "pyyaml"},
]


def guess_family(image: str) -> str:
    """Package-manager family guessed from an image reference (only used to pick preset package names)."""
    name = image.lower()
    if "alpine" in name:
        return "alpine"
    if any(word in name for word in ("debian", "ubuntu", "-slim", "bookworm", "bullseye")):
        return "debian"
    return "rhel"
