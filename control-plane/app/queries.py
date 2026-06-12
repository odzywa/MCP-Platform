"""Named SQL query constants for queries that are reused across multiple call sites in main.py.

Centralizing these means a schema/column change only needs to be edited here once,
instead of hunting down every copy-pasted variant of the same statement.
"""

# ── runtimes ─────────────────────────────────────────────────────────────────
SELECT_RUNTIME_ID_EXISTS = "SELECT id FROM runtimes WHERE id = ?"
SELECT_RUNTIME_BY_ID = "SELECT * FROM runtimes WHERE id = ?"
SELECT_RUNTIMES_ACTIVE = "SELECT * FROM runtimes WHERE status != 'deleted' ORDER BY created_at DESC"

INSERT_RUNTIME = """
        INSERT INTO runtimes(id, name, description, runtime_class, template, status, risk_level, image, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """

# ── tools ────────────────────────────────────────────────────────────────────
SELECT_TOOL_BY_ID_AND_RUNTIME = "SELECT * FROM tools WHERE id = ? AND runtime_id = ?"

INSERT_TOOL = """
        INSERT INTO tools(runtime_id, name, description, execution_type, config_json, input_schema_json, output_schema_json,
                          enabled, risk_level, mode, category, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """

# ── policies ─────────────────────────────────────────────────────────────────
SELECT_POLICY_JSON_BY_RUNTIME = "SELECT policy_json FROM policies WHERE runtime_id = ?"
INSERT_POLICY = "INSERT INTO policies(runtime_id, policy_json, updated_at) VALUES (?, ?, ?)"
UPSERT_POLICY_COMPACT = "INSERT INTO policies(runtime_id, policy_json, updated_at) VALUES(?,?,?) ON CONFLICT(runtime_id) DO UPDATE SET policy_json=excluded.policy_json, updated_at=excluded.updated_at"
UPSERT_POLICY = """
        INSERT INTO policies(runtime_id, policy_json, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(runtime_id) DO UPDATE SET policy_json = excluded.policy_json, updated_at = excluded.updated_at
        """

# ── runtime_classes ──────────────────────────────────────────────────────────
SELECT_RUNTIME_CLASS_NAME_BY_NAME = "SELECT name FROM runtime_classes WHERE name = ?"
SELECT_RUNTIME_CLASS_BY_NAME = "SELECT * FROM runtime_classes WHERE name = ?"
SELECT_RUNTIME_CLASS_ENABLED_BY_NAME = "SELECT * FROM runtime_classes WHERE name = ? AND enabled = 1"
SELECT_RUNTIME_CLASSES_ALL = "SELECT * FROM runtime_classes ORDER BY name"

INSERT_RUNTIME_CLASS = """
            INSERT INTO runtime_classes(name, description, runtime_image, allowed_execution_types_json,
                                        enabled, risk_level, security_profile, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """

UPSERT_RUNTIME_CLASS = """
            INSERT INTO runtime_classes(name, description, runtime_image, allowed_execution_types_json,
                                        enabled, risk_level, security_profile, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(name) DO UPDATE SET
              description = excluded.description,
              runtime_image = excluded.runtime_image,
              allowed_execution_types_json = excluded.allowed_execution_types_json,
              enabled = excluded.enabled,
              risk_level = excluded.risk_level,
              security_profile = excluded.security_profile,
              updated_at = excluded.updated_at
            """

# ── execution_adapters ───────────────────────────────────────────────────────
SELECT_ADAPTER_NAME_BY_NAME = "SELECT name FROM execution_adapters WHERE name = ?"
SELECT_ADAPTER_BY_NAME = "SELECT * FROM execution_adapters WHERE name = ?"
SELECT_ADAPTER_ENABLED_IMPLEMENTED = "SELECT * FROM execution_adapters WHERE name = ? AND enabled = 1 AND implemented = 1"
SELECT_ADAPTERS_ALL = "SELECT * FROM execution_adapters ORDER BY name"

INSERT_EXECUTION_ADAPTER = """
        INSERT INTO execution_adapters(name, description, adapter_type, runtime_image, config_schema_json,
                                       adapter_contract_json, enabled, implemented, risk_level, mode, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """

# ── targets ──────────────────────────────────────────────────────────────────
INSERT_TARGET = """
        INSERT INTO targets(runtime_id, adapter_name, name, target_json, secret_refs_json, tags_json, enabled, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """

# ── tool_packages ────────────────────────────────────────────────────────────
SELECT_TOOL_PACKAGE_BY_ID = "SELECT * FROM tool_packages WHERE id = ?"
SELECT_TOOL_PACKAGE_ID_BY_ID = "SELECT id FROM tool_packages WHERE id = ?"

# ── sessions ─────────────────────────────────────────────────────────────────
DELETE_SESSIONS_BY_USER = "DELETE FROM sessions WHERE user_id=?"

# ── webhooks ─────────────────────────────────────────────────────────────────
UPDATE_WEBHOOK_FIRED = "UPDATE webhooks SET last_fired_at=?,last_status=?,updated_at=? WHERE id=?"
