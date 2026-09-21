"""Dockerfile generation helpers for custom runtime image builds."""


def _system_packages_step(packages: str) -> str:
    """
    Instalacja pakietów systemowych niezależna od dystrybucji obrazu bazowego.

    Obrazy platformy stoją na UBI9 (microdnf), ale użytkownik może wybrać bazę
    debianową, alpine albo dowolną inną. Menedżer pakietów rozpoznajemy dopiero
    w trakcie budowania, bo z samej nazwy obrazu nie da się go ustalić.

    Nazwy pakietów bywają różne między dystrybucjami (np. iputils-ping na
    Debianie vs iputils na RHEL) — tego nie tłumaczymy, podaje je użytkownik.
    """
    return (
        "RUN set -e; "
        "if command -v microdnf >/dev/null 2>&1; then "
        f"microdnf install -y --nodocs --setopt=install_weak_deps=0 {packages} && microdnf clean all; "
        "elif command -v dnf >/dev/null 2>&1; then "
        f"dnf install -y --setopt=install_weak_deps=False {packages} && dnf clean all; "
        "elif command -v apt-get >/dev/null 2>&1; then "
        f"apt-get update && apt-get install -y --no-install-recommends {packages} "
        "&& rm -rf /var/lib/apt/lists/*; "
        "elif command -v apk >/dev/null 2>&1; then "
        f"apk add --no-cache {packages}; "
        "else echo 'nie rozpoznano menedżera pakietów w obrazie bazowym' >&2; exit 1; fi"
    )


def build_runtime_dockerfile(base_image: str, apt_packages: list[str], pip_packages: list[str], extra_dockerfile: str) -> str:
    # apt_packages to historyczna nazwa pola — są to pakiety systemowe,
    # instalowane menedżerem właściwym dla obrazu bazowego.
    lines = [
        f"FROM {base_image}",
        "USER root",
        "ENV PYTHONDONTWRITEBYTECODE=1",
    ]
    if apt_packages:
        lines.append(_system_packages_step(" ".join(apt_packages)))
    if pip_packages:
        lines.append(f"RUN pip install --no-cache-dir {' '.join(pip_packages)}")
    extra = extra_dockerfile.strip()
    if extra:
        lines.append("")
        lines.append("# Admin-provided Dockerfile fragment")
        lines.extend(extra.splitlines())
    # Wracamy do użytkownika nieuprzywilejowanego — wyżej przełączyliśmy na root
    # na czas instalacji. Bez tego obraz działa jako root i pod runAsNonRoot
    # nie wystartuje na Kubernetesie. Szanujemy USER ustawiony we fragmencie.
    if not any(l.strip().upper().startswith("USER ") for l in extra.splitlines()):
        lines.append("USER 1000:0")
    return "\n".join(lines).rstrip() + "\n"
