"""Static execution-adapter contracts (config/secret/target/tool/policy schemas)."""
from typing import Any


def adapter_contracts() -> dict[str, dict[str, Any]]:
    return {
        "http_request": {
            "name": "http_request",
            "display_name": "HTTP Adapter",
            "category": "api",
            "config_schema": {
                "type": "object",
                "properties": {
                    "base_url": {"type": "string", "title": "Base URL"},
                    "auth_type": {"type": "string", "title": "Auth type", "enum": ["none", "bearer", "basic", "api_key"], "default": "none"},
                    "timeout_seconds": {"type": "integer", "title": "Timeout seconds", "default": 30, "minimum": 1, "maximum": 300},
                    "retry_count": {"type": "integer", "title": "Retries", "default": 1, "minimum": 0, "maximum": 10},
                },
            },
            "secret_schema": {
                "type": "object",
                "properties": {
                    "bearer_token": {"type": "string", "title": "Bearer token secret ref"},
                    "basic_password": {"type": "string", "title": "Basic password secret ref"},
                    "api_key": {"type": "string", "title": "API key secret ref"},
                },
            },
            "target_schema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "title": "Target name"},
                    "base_url": {"type": "string", "title": "Base URL"},
                    "environment": {"type": "string", "title": "Environment"},
                },
                "required": ["name", "base_url"],
            },
            "tool_schema": {
                "type": "object",
                "properties": {
                    "method": {"type": "string", "enum": ["GET", "POST", "PUT", "PATCH", "DELETE"], "default": "GET"},
                    "path": {"type": "string", "title": "Path"},
                    "body_template": {"type": "string", "title": "Body template"},
                },
                "required": ["method", "path"],
            },
            "policy_schema": {
                "type": "object",
                "properties": {
                    "allowed_methods": {"type": "array", "items": {"type": "string"}, "default": ["GET", "POST"]},
                    "allowed_hosts": {"type": "array", "items": {"type": "string"}},
                    "max_response_bytes": {"type": "integer", "default": 5242880},
                },
            },
            "capabilities": ["http.request", "http.read", "http.write"],
        },
        "shell": {
            "name": "shell",
            "display_name": "Process/Shell Adapter",
            "category": "system",
            "config_schema": {
                "type": "object",
                "properties": {
                    "working_dir": {"type": "string", "title": "Working directory", "default": "/tmp"},
                    "timeout_seconds": {"type": "integer", "title": "Timeout seconds", "default": 20, "minimum": 1, "maximum": 300},
                },
            },
            "secret_schema": {"type": "object", "properties": {}},
            "target_schema": {"type": "object", "properties": {"name": {"type": "string", "title": "Target name"}}},
            "tool_schema": {
                "type": "object",
                "properties": {
                    "command": {"type": "array", "title": "Command argv", "items": {"type": "string"}},
                },
                "required": ["command"],
            },
            "policy_schema": {
                "type": "object",
                "properties": {
                    "allowed_binaries": {"type": "array", "items": {"type": "string"}},
                    "blocked_commands": {"type": "array", "items": {"type": "string"}},
                    "max_response_bytes": {"type": "integer", "default": 1048576},
                },
            },
            "capabilities": ["process.execute", "process.readonly"],
        },
        "ssh": {
            "name": "ssh",
            "display_name": "SSH Adapter",
            "category": "infrastructure",
            "config_schema": {
                "type": "object",
                "properties": {
                    "default_port": {"type": "integer", "title": "Default SSH port", "default": 22, "minimum": 1, "maximum": 65535},
                    "connect_timeout_seconds": {"type": "integer", "title": "Connect timeout", "default": 10, "minimum": 1, "maximum": 120},
                    "command_timeout_seconds": {"type": "integer", "title": "Command timeout", "default": 20, "minimum": 1, "maximum": 300},
                    "strict_host_key_checking": {"type": "boolean", "title": "Strict host key checking", "default": True},
                },
            },
            "secret_schema": {
                "type": "object",
                "properties": {
                    "password": {"type": "string", "title": "Password secret ref"},
                    "private_key": {"type": "string", "title": "Private key secret ref"},
                    "passphrase": {"type": "string", "title": "Key passphrase secret ref"},
                },
            },
            "target_schema": {
                "type": "object",
                "properties": {
                    "name": {"type": "string", "title": "Target name"},
                    "host": {"type": "string", "title": "Host/IP"},
                    "port": {"type": "integer", "title": "SSH port", "default": 22, "minimum": 1, "maximum": 65535},
                    "username": {"type": "string", "title": "Username"},
                    "auth_method": {"type": "string", "title": "Auth method", "enum": ["password", "private_key"], "default": "private_key"},
                    "environment": {"type": "string", "title": "Environment"},
                },
                "required": ["name", "host", "username"],
            },
            "tool_schema": {
                "type": "object",
                "properties": {
                    "target_selector": {"type": "string", "title": "Target selector"},
                    "command_template": {"type": "string", "title": "Command template"},
                    "output_parser": {"type": "string", "title": "Output parser", "enum": ["text", "json", "lines"], "default": "text"},
                },
                "required": ["command_template"],
            },
            "policy_schema": {
                "type": "object",
                "properties": {
                    "allowed_command_prefixes": {"type": "array", "items": {"type": "string"}},
                    "blocked_command_patterns": {"type": "array", "items": {"type": "string"}},
                    "allow_targets_from_inventory_only": {"type": "boolean", "default": True},
                    "max_output_bytes": {"type": "integer", "default": 1048576},
                    "concurrent_sessions": {"type": "integer", "default": 2, "minimum": 1, "maximum": 50},
                },
            },
            "capabilities": ["ssh.command.execute", "ssh.command.readonly", "ssh.command.privileged"],
        },
    }
