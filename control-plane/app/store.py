import json
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


DB_PATH = os.getenv("MCP_PLATFORM_DB", "/data/mcp_platform.db")
CONFIG_ROOT = Path(os.getenv("MCP_PLATFORM_CONFIG_ROOT", "/data/configs"))


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


@contextmanager
def db():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def init_db() -> None:
    CONFIG_ROOT.mkdir(parents=True, exist_ok=True)
    with db() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS runtimes (
              id TEXT PRIMARY KEY,
              name TEXT NOT NULL,
              description TEXT NOT NULL DEFAULT '',
              runtime_class TEXT NOT NULL,
              template TEXT NOT NULL DEFAULT '',
              status TEXT NOT NULL DEFAULT 'draft',
              risk_level TEXT NOT NULL DEFAULT 'low',
              endpoint_url TEXT,
              container_name TEXT,
              image TEXT NOT NULL DEFAULT 'mcp-runtime-http-gateway:latest',
              config_path TEXT,
              last_error TEXT,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tools (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              runtime_id TEXT NOT NULL,
              name TEXT NOT NULL,
              description TEXT NOT NULL DEFAULT '',
              execution_type TEXT NOT NULL,
              config_json TEXT NOT NULL,
              input_schema_json TEXT NOT NULL DEFAULT '{}',
              output_schema_json TEXT NOT NULL DEFAULT '{}',
              enabled INTEGER NOT NULL DEFAULT 0,
              risk_level TEXT NOT NULL DEFAULT 'low',
              mode TEXT NOT NULL DEFAULT 'read-only',
              category TEXT NOT NULL DEFAULT 'other',
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS policies (
              runtime_id TEXT PRIMARY KEY,
              policy_json TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS deployment_requests (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              runtime_id TEXT NOT NULL,
              action TEXT NOT NULL,
              status TEXT NOT NULL DEFAULT 'pending',
              error TEXT,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audit_log (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              actor TEXT NOT NULL,
              action TEXT NOT NULL,
              target_type TEXT NOT NULL,
              target_id TEXT NOT NULL,
              details_json TEXT NOT NULL DEFAULT '{}',
              created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS runtime_logs (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              runtime_id TEXT NOT NULL,
              level TEXT NOT NULL DEFAULT 'info',
              message TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS runtime_classes (
              name TEXT PRIMARY KEY,
              description TEXT NOT NULL DEFAULT '',
              runtime_image TEXT NOT NULL,
              allowed_execution_types_json TEXT NOT NULL DEFAULT '[]',
              enabled INTEGER NOT NULL DEFAULT 1,
              risk_level TEXT NOT NULL DEFAULT 'low',
              security_profile TEXT NOT NULL DEFAULT 'restricted',
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS execution_adapters (
              name TEXT PRIMARY KEY,
              description TEXT NOT NULL DEFAULT '',
              adapter_type TEXT NOT NULL,
              runtime_image TEXT NOT NULL DEFAULT '',
              config_schema_json TEXT NOT NULL DEFAULT '{}',
              adapter_contract_json TEXT NOT NULL DEFAULT '{}',
              enabled INTEGER NOT NULL DEFAULT 0,
              implemented INTEGER NOT NULL DEFAULT 0,
              risk_level TEXT NOT NULL DEFAULT 'low',
              mode TEXT NOT NULL DEFAULT 'read-only',
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS runtime_adapters (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              runtime_id TEXT NOT NULL,
              adapter_name TEXT NOT NULL,
              config_json TEXT NOT NULL DEFAULT '{}',
              policy_json TEXT NOT NULL DEFAULT '{}',
              enabled INTEGER NOT NULL DEFAULT 1,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL,
              UNIQUE(runtime_id, adapter_name)
            );
            CREATE TABLE IF NOT EXISTS targets (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              runtime_id TEXT NOT NULL,
              adapter_name TEXT NOT NULL,
              name TEXT NOT NULL,
              target_json TEXT NOT NULL DEFAULT '{}',
              secret_refs_json TEXT NOT NULL DEFAULT '{}',
              tags_json TEXT NOT NULL DEFAULT '[]',
              enabled INTEGER NOT NULL DEFAULT 1,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS secrets (
              id TEXT PRIMARY KEY,
              workspace_id TEXT NOT NULL DEFAULT 'default',
              name TEXT NOT NULL,
              secret_type TEXT NOT NULL,
              provider TEXT NOT NULL DEFAULT 'local-ref',
              secret_ref TEXT NOT NULL,
              masked_preview TEXT NOT NULL DEFAULT '***',
              metadata_json TEXT NOT NULL DEFAULT '{}',
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tool_packages (
              id TEXT PRIMARY KEY,
              name TEXT NOT NULL,
              description TEXT NOT NULL DEFAULT '',
              category TEXT NOT NULL DEFAULT 'other',
              risk_level TEXT NOT NULL DEFAULT 'low',
              source TEXT NOT NULL DEFAULT 'builtin',
              enabled INTEGER NOT NULL DEFAULT 1,
              package_json TEXT NOT NULL,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS runtime_image_builds (
              id TEXT PRIMARY KEY,
              image TEXT NOT NULL,
              base_image TEXT NOT NULL,
              runtime_class TEXT NOT NULL DEFAULT '',
              context_path TEXT NOT NULL,
              dockerfile TEXT NOT NULL,
              status TEXT NOT NULL DEFAULT 'pending',
              error TEXT,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS external_mcp_servers (
              id TEXT PRIMARY KEY,
              name TEXT NOT NULL,
              description TEXT NOT NULL DEFAULT '',
              endpoint_url TEXT NOT NULL,
              auth_type TEXT NOT NULL DEFAULT 'none',
              auth_token TEXT NOT NULL DEFAULT '',
              status TEXT NOT NULL DEFAULT 'unknown',
              last_checked_at TEXT,
              last_error TEXT,
              tools_json TEXT NOT NULL DEFAULT '[]',
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS runtime_credentials (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              runtime_id TEXT NOT NULL,
              kind TEXT NOT NULL DEFAULT 'env',
              name TEXT NOT NULL,
              value TEXT NOT NULL,
              env_name TEXT NOT NULL DEFAULT '',
              mount_path TEXT NOT NULL DEFAULT '',
              enabled INTEGER NOT NULL DEFAULT 1,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS users (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              username TEXT UNIQUE NOT NULL,
              password_hash TEXT NOT NULL,
              role TEXT NOT NULL DEFAULT 'read_only',
              active INTEGER NOT NULL DEFAULT 1,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
              token TEXT PRIMARY KEY,
              user_id INTEGER NOT NULL,
              username TEXT NOT NULL,
              role TEXT NOT NULL,
              expires_at TEXT NOT NULL,
              created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS registration_requests (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              username TEXT UNIQUE NOT NULL,
              password_hash TEXT NOT NULL,
              status TEXT NOT NULL DEFAULT 'pending',
              requested_role TEXT NOT NULL DEFAULT 'read_write',
              admin_note TEXT,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS tool_calls (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              runtime_id TEXT NOT NULL,
              tool_name TEXT NOT NULL,
              arguments_json TEXT NOT NULL DEFAULT '{}',
              result_ok INTEGER NOT NULL DEFAULT 0,
              result_json TEXT NOT NULL DEFAULT '{}',
              duration_ms INTEGER NOT NULL DEFAULT 0,
              caller TEXT NOT NULL DEFAULT '',
              caller_ip TEXT NOT NULL DEFAULT '',
              model TEXT NOT NULL DEFAULT '',
              created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS webhooks (
              id INTEGER PRIMARY KEY AUTOINCREMENT,
              name TEXT NOT NULL,
              url TEXT NOT NULL,
              events_json TEXT NOT NULL DEFAULT '["runtime_failed","health_failed","tool_error"]',
              runtime_id TEXT NOT NULL DEFAULT '',
              enabled INTEGER NOT NULL DEFAULT 1,
              last_fired_at TEXT,
              last_status INTEGER,
              created_at TEXT NOT NULL,
              updated_at TEXT NOT NULL
            );
            """
        )
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(tool_packages)").fetchall()}
        if "enabled" not in columns:
            conn.execute("ALTER TABLE tool_packages ADD COLUMN enabled INTEGER NOT NULL DEFAULT 1")
        adapter_columns = {row["name"] for row in conn.execute("PRAGMA table_info(execution_adapters)").fetchall()}
        if "adapter_contract_json" not in adapter_columns:
            conn.execute("ALTER TABLE execution_adapters ADD COLUMN adapter_contract_json TEXT NOT NULL DEFAULT '{}'")
        tc_columns = {row["name"] for row in conn.execute("PRAGMA table_info(tool_calls)").fetchall()}
        if "caller_ip" not in tc_columns:
            conn.execute("ALTER TABLE tool_calls ADD COLUMN caller_ip TEXT NOT NULL DEFAULT ''")
        if "model" not in tc_columns:
            conn.execute("ALTER TABLE tool_calls ADD COLUMN model TEXT NOT NULL DEFAULT ''")


def rows(query: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    with db() as conn:
        return [dict(row) for row in conn.execute(query, params).fetchall()]


def one(query: str, params: tuple[Any, ...] = ()) -> dict[str, Any] | None:
    result = rows(query, params)
    return result[0] if result else None


def execute(query: str, params: tuple[Any, ...] = ()) -> None:
    with db() as conn:
        conn.execute(query, params)


def audit(actor: str, action: str, target_type: str, target_id: str, details: dict[str, Any] | None = None) -> None:
    execute(
        "INSERT INTO audit_log(actor, action, target_type, target_id, details_json, created_at) VALUES (?, ?, ?, ?, ?, ?)",
        (actor, action, target_type, target_id, json.dumps(details or {}), now_iso()),
    )


def log(runtime_id: str, message: str, level: str = "info") -> None:
    execute(
        "INSERT INTO runtime_logs(runtime_id, level, message, created_at) VALUES (?, ?, ?, ?)",
        (runtime_id, level, message, now_iso()),
    )
