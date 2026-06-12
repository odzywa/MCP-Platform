"""Dockerfile generation helpers for custom runtime image builds."""


def build_runtime_dockerfile(base_image: str, apt_packages: list[str], pip_packages: list[str], extra_dockerfile: str) -> str:
    lines = [
        f"FROM {base_image}",
        "USER root",
        "ENV PYTHONDONTWRITEBYTECODE=1",
    ]
    if apt_packages:
        packages = " ".join(apt_packages)
        lines.append(
            "RUN apt-get update "
            f"&& apt-get install -y --no-install-recommends {packages} "
            "&& rm -rf /var/lib/apt/lists/*"
        )
    if pip_packages:
        lines.append(f"RUN pip install --no-cache-dir {' '.join(pip_packages)}")
    extra = extra_dockerfile.strip()
    if extra:
        lines.append("")
        lines.append("# Admin-provided Dockerfile fragment")
        lines.extend(extra.splitlines())
    return "\n".join(lines).rstrip() + "\n"
