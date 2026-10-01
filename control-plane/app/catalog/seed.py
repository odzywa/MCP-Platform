"""Startup seeding: execution adapters, runtime classes, built-in Tool Packages and example runtimes."""
import json
from typing import Any

from .. import queries as sql
from .. import store
from ..adapters_config import adapter_contracts
from . import builtin_tool_packages, example_runtimes


def seed_all() -> None:
    seed_platform_catalog()
    seed_example_runtimes()


def seed_platform_catalog() -> None:
    now = store.now_iso()
    changed = False
    adapters = [
        {
            "name": "http_request",
            "description": "Execute schema-validated HTTP requests from the generic HTTP gateway runtime.",
            "adapter_type": "http",
            "runtime_image": "mcp-runtime-http-gateway:latest",
            "enabled": 1,
            "implemented": 1,
            "risk_level": "low",
            "mode": "read-only",
            "schema": {
                "type": "object",
                "required": ["url"],
                "properties": {
                    "url": {"type": "string"},
                    "method": {"type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"]},
                    "body": {"type": "object"},
                    "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": 300},
                },
            },
        },
        {
            "name": "shell",
            "description": "Adapter shell — wykonuje dozwolone komendy w izolowanych kontenerach runtime.",
            "adapter_type": "shell",
            "runtime_image": "mcp-runtime-shell:latest",
            "enabled": 1,
            "implemented": 1,
            "risk_level": "high",
            "mode": "read-only",
            "schema": {"type": "object"},
        },
        {
            "name": "ssh",
            "description": "Adapter SSH — wykonuje komendy na zdalnych serwerach infrastruktury.",
            "adapter_type": "ssh",
            "runtime_image": "mcp-generic-runtime:latest",
            "enabled": 1,
            "implemented": 1,
            "risk_level": "high",
            "mode": "read-only",
            "schema": adapter_contracts()["ssh"]["config_schema"],
        },
        {
            "name": "python",
            "description": "Planowany adapter Python — izolowany sandbox do skryptów Python.",
            "adapter_type": "python",
            "runtime_image": "mcp-runtime-python:latest",
            "enabled": 0,
            "implemented": 0,
            "risk_level": "medium",
            "mode": "read-only",
            "schema": {"type": "object"},
        },
        {
            "name": "openshift",
            "description": "Planowany adapter OpenShift/Kubernetes — tylko odczyt zasobów klastra.",
            "adapter_type": "openshift",
            "runtime_image": "mcp-runtime-openshift:latest",
            "enabled": 0,
            "implemented": 0,
            "risk_level": "medium",
            "mode": "read-only",
            "schema": {"type": "object"},
        },
        {
            "name": "workflow",
            "description": "Planowany adapter workflow — łączenie wielu toolów w sekwencje.",
            "adapter_type": "workflow",
            "runtime_image": "mcp-runtime-workflow:latest",
            "enabled": 0,
            "implemented": 0,
            "risk_level": "medium",
            "mode": "read-only",
            "schema": {"type": "object"},
        },
    ]
    for adapter in adapters:
        contract_json = json.dumps(adapter_contracts().get(adapter["name"], {"name": adapter["name"], "config_schema": adapter["schema"]}))
        if not store.one(sql.SELECT_ADAPTER_NAME_BY_NAME, (adapter["name"],)):
            changed = True
            store.execute(
                sql.INSERT_EXECUTION_ADAPTER,
                (
                    adapter["name"],
                    adapter["description"],
                    adapter["adapter_type"],
                    adapter["runtime_image"],
                    json.dumps(adapter["schema"]),
                    contract_json,
                    adapter["enabled"],
                    adapter["implemented"],
                    adapter["risk_level"],
                    adapter["mode"],
                    now,
                    now,
                ),
            )
        else:
            store.execute(
                """
                UPDATE execution_adapters
                SET description = ?, adapter_type = ?, adapter_contract_json = ?, config_schema_json = ?, runtime_image = ?,
                    enabled = ?, implemented = ?, risk_level = ?, mode = ?, updated_at = ?
                WHERE name = ?
                """,
                (
                    adapter["description"],
                    adapter["adapter_type"],
                    contract_json,
                    json.dumps(adapter["schema"]),
                    adapter["runtime_image"],
                    adapter["enabled"],
                    adapter["implemented"],
                    adapter["risk_level"],
                    adapter["mode"],
                    now,
                    adapter["name"],
                ),
            )
    for _rc_name, _rc_desc, _rc_image, _rc_types in [
        ("shell-readonly",  "Shell runtime for CLI tools (curl, psql, oc, ping...)",   "mcp-runtime-shell:latest",        ["shell"]),
        ("shell-readwrite", "Shell runtime — write mode allowed",                       "mcp-runtime-shell:latest",        ["shell"]),
        ("openapi",         "Auto-MCP from OpenAPI spec via FastMCP.from_openapi()",    "mcp-runtime-openapi:latest",      ["http_request"]),
    ]:
        if not store.one(sql.SELECT_RUNTIME_CLASS_NAME_BY_NAME, (_rc_name,)):
            changed = True
            store.execute(
                "INSERT INTO runtime_classes(name, description, runtime_image, allowed_execution_types_json, enabled, risk_level, security_profile, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (_rc_name, _rc_desc, _rc_image, json.dumps(_rc_types), 1, "low", "restricted", now, now),
            )
        else:
            store.execute(
                "UPDATE runtime_classes SET runtime_image=?, allowed_execution_types_json=?, enabled=1, updated_at=? WHERE name=?",
                (_rc_image, json.dumps(_rc_types), now, _rc_name),
            )
    if not store.one(sql.SELECT_RUNTIME_CLASS_NAME_BY_NAME, ("http-gateway",)):
        changed = True
        store.execute(
            sql.INSERT_RUNTIME_CLASS,
            (
                "http-gateway",
                "Generic HTTP MCP runtime. Supports config-driven HTTP tools.",
                "mcp-runtime-http-gateway:latest",
                json.dumps(["http_request"]),
                1,
                "low",
                "restricted",
                now,
                now,
            ),
        )
    if not store.one(sql.SELECT_RUNTIME_CLASS_NAME_BY_NAME, ("generic-runtime",)):
        changed = True
        store.execute(
            sql.INSERT_RUNTIME_CLASS,
            (
                "generic-runtime",
                "Generic adapter-driven MCP runtime. Loads adapter-config, targets, tools and policy.",
                "mcp-generic-runtime:latest",
                json.dumps(["http_request", "ssh"]),
                1,
                "medium",
                "restricted",
                now,
                now,
            ),
        )
    else:
        store.execute(
            """
            UPDATE runtime_classes
            SET runtime_image = ?, allowed_execution_types_json = ?, enabled = ?, risk_level = ?, security_profile = ?, updated_at = ?
            WHERE name = ?
            """,
            (
                "mcp-generic-runtime:latest",
                json.dumps(["http_request", "ssh"]),
                1,
                "medium",
                "restricted",
                now,
                "generic-runtime",
            ),
        )
    if changed:
        store.audit("system", "seed_catalog", "platform", "runtime-adapters", {})
    seed_builtin_tool_packages()


def seed_builtin_tool_packages() -> None:
    now = store.now_iso()
    for package in builtin_tool_packages():
        store.execute(
            """
            INSERT INTO tool_packages(id, name, description, category, risk_level, source, enabled, package_json, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
              name = excluded.name,
              description = excluded.description,
              category = excluded.category,
              risk_level = excluded.risk_level,
              package_json = excluded.package_json,
              updated_at = excluded.updated_at
            """,
            (
                package["id"],
                package["name"],
                package["description"],
                package["category"],
                package["risk_level"],
                "builtin",
                1,
                json.dumps(package),
                now,
                now,
            ),
        )
        upsert_package_dependencies(package)


def upsert_package_dependencies(package: dict[str, Any]) -> None:
    now = store.now_iso()
    runtime_class = package.get("runtime_class") or {}
    if runtime_class.get("name"):
        store.execute(
            sql.UPSERT_RUNTIME_CLASS,
            (
                runtime_class["name"],
                runtime_class.get("description") or package.get("description", ""),
                runtime_class.get("runtime_image") or "mcp-runtime-http-gateway:latest",
                json.dumps(runtime_class.get("allowed_execution_types") or ["http_request"]),
                1,
                runtime_class.get("risk_level") or package.get("risk_level", "low"),
                runtime_class.get("security_profile") or "restricted",
                now,
                now,
            ),
        )
    for adapter in package.get("adapters") or []:
        store.execute(
            """
            INSERT INTO execution_adapters(name, description, adapter_type, runtime_image, config_schema_json,
                                           adapter_contract_json, enabled, implemented, risk_level, mode, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
              description = excluded.description,
              adapter_type = excluded.adapter_type,
              runtime_image = excluded.runtime_image,
              config_schema_json = excluded.config_schema_json,
              adapter_contract_json = excluded.adapter_contract_json,
              enabled = excluded.enabled,
              implemented = excluded.implemented,
              risk_level = excluded.risk_level,
              mode = excluded.mode,
              updated_at = excluded.updated_at
            """,
            (
                adapter["name"],
                adapter.get("description", ""),
                adapter.get("adapter_type", adapter["name"]),
                adapter.get("runtime_image", runtime_class.get("runtime_image", "")),
                json.dumps(adapter.get("schema") or {}),
                json.dumps(adapter.get("contract") or adapter_contracts().get(adapter["name"], {"name": adapter["name"], "config_schema": adapter.get("schema") or {}})),
                1 if adapter.get("enabled") else 0,
                1 if adapter.get("implemented") else 0,
                adapter.get("risk_level", package.get("risk_level", "low")),
                adapter.get("mode", "read-only"),
                now,
                now,
            ),
        )


def seed_example_runtimes() -> None:
    """Create the example runtimes from catalog/runtimes/ unless they already exist.

    on_existing = "skip"       — leave an existing runtime untouched,
    on_existing = "sync_tools" — refresh config/input schema of its tools from the catalog.
    """
    for runtime in example_runtimes():
        runtime_id = runtime["id"]
        now = store.now_iso()
        if store.one(sql.SELECT_RUNTIME_ID_EXISTS, (runtime_id,)):
            if runtime.get("on_existing") == "sync_tools":
                for tool in runtime["tools"]:
                    store.execute(
                        """UPDATE tools SET config_json=?, input_schema_json=?, updated_at=?
                           WHERE runtime_id=? AND name=?""",
                        (
                            json.dumps(tool.get("config") or {}),
                            json.dumps(tool.get("input_schema") or {"type": "object"}),
                            now,
                            runtime_id,
                            tool["name"],
                        ),
                    )
            continue
        store.execute(
            sql.INSERT_RUNTIME,
            (
                runtime_id,
                runtime["name"],
                runtime["description"],
                runtime["runtime_class"],
                runtime["template"],
                runtime["status"],
                runtime["risk_level"],
                runtime["image"],
                now,
                now,
            ),
        )
        for tool in runtime["tools"]:
            store.execute(
                sql.INSERT_TOOL,
                (
                    runtime_id,
                    tool["name"],
                    tool.get("description", ""),
                    tool.get("execution_type", "shell"),
                    json.dumps(tool.get("config") or {}),
                    json.dumps(tool.get("input_schema") or {"type": "object"}),
                    json.dumps(tool.get("output_schema", {"type": "object"})),
                    1 if tool.get("enabled", True) else 0,
                    tool.get("risk_level", "low"),
                    tool.get("mode", "read-only"),
                    tool.get("category", "other"),
                    now,
                    now,
                ),
            )
        store.execute(sql.INSERT_POLICY, (runtime_id, json.dumps(runtime["policy"]), now))
        store.audit("system", "seed_runtime", "runtime", runtime_id, {"template": runtime["template"]})
