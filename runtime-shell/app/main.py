import json
import os
import shlex
import subprocess
import time
import threading
import urllib.request
from pathlib import Path
from string import Template
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from jsonschema import validate


CONFIG_DIR = Path(os.getenv("RUNTIME_CONFIG_DIR", "/config"))
CALLBACK_URL = os.getenv("MCP_PLATFORM_CALLBACK_URL", "")
RUNTIME_ID = os.getenv("MCP_RUNTIME_ID", "")
app = FastAPI(title="Generic MCP Runtime Shell", version="0.1.0")


def _fire_tool_call_log(tool_name: str, arguments: dict, result: dict, duration_ms: int,
                        caller_ip: str = "", model: str = "") -> None:
    if not CALLBACK_URL or not RUNTIME_ID:
        return
    payload = json.dumps({
        "runtime_id": RUNTIME_ID,
        "tool_name": tool_name,
        "arguments": arguments,
        "ok": result.get("ok", False),
        "result": {k: v for k, v in result.items() if k != "output"},
        "duration_ms": duration_ms,
        "caller": "",
        "caller_ip": caller_ip,
        "model": model,
    }).encode()
    def _post() -> None:
        try:
            req = urllib.request.Request(
                f"{CALLBACK_URL}/api/tool-call",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=3)
        except Exception:
            pass
    threading.Thread(target=_post, daemon=True).start()

runtime_config: dict[str, Any] = {}
policy: dict[str, Any] = {}
tools: dict[str, dict[str, Any]] = {}


def load_config() -> None:
    global runtime_config, policy, tools
    runtime_config = json.loads((CONFIG_DIR / "runtime-config.json").read_text(encoding="utf-8"))
    policy = json.loads((CONFIG_DIR / "policy.json").read_text(encoding="utf-8"))
    tools_data = json.loads((CONFIG_DIR / "tools.json").read_text(encoding="utf-8"))
    tools = {tool["name"]: tool for tool in tools_data.get("tools", [])}


@app.on_event("startup")
def startup() -> None:
    load_config()


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "server_id": runtime_config.get("server_id"),
        "name": runtime_config.get("name"),
        "tools": len(tools),
        "runtime": "shell",
    }


@app.post("/reload")
def reload() -> dict[str, Any]:
    load_config()
    return {
        "ok": True,
        "tools": len(tools),
        "server_id": runtime_config.get("server_id"),
    }


@app.get("/tools")
def list_tools() -> dict[str, Any]:
    return {
        "tools": [
            {
                "name": tool["name"],
                "description": tool.get("description", ""),
                "inputSchema": tool.get("input_schema") or {},
            }
            for tool in tools.values()
        ]
    }


def openapi_tool_spec() -> dict[str, Any]:
    visible_tools = [t for t in tools.values() if t.get("openwebui_enabled") is not False]
    return {
        "openapi": "3.0.3",
        "info": {
            "title": runtime_config.get("name", "MCP Runtime"),
            "version": "0.1.0",
            "description": "Config-driven MCP shell runtime tools.",
        },
        "servers": [{"url": "/"}],
        "paths": {
            f"/tools/{tool['name']}": {
                "post": {
                    "operationId": tool["name"],
                    "summary": tool.get("description") or tool["name"],
                    "description": tool.get("description") or "",
                    "requestBody": {
                        "required": True,
                        "content": {"application/json": {"schema": tool.get("input_schema") or {"type": "object"}}},
                    },
                    "responses": {
                        "200": {
                            "description": "Tool execution result.",
                            "content": {"application/json": {"schema": tool.get("output_schema") or {"type": "object"}}},
                        }
                    },
                }
            }
            for tool in visible_tools
        },
    }


@app.get("/openwebui")
def openwebui_base() -> dict[str, Any]:
    return openapi_tool_spec()


@app.get("/openwebui/openapi.json")
def openwebui_openapi() -> dict[str, Any]:
    return openapi_tool_spec()


@app.post("/openwebui/tools/{tool_name}")
async def rest_tool_openwebui(tool_name: str, request: Request) -> JSONResponse:
    """Alias for OpenWebUI tool server — resolves calls to /openwebui/tools/{name}."""
    payload = await request.json()
    return JSONResponse(await execute_tool(tool_name, payload))


def render_arg(value: Any, arguments: dict[str, Any]) -> str:
    return Template(str(value)).safe_substitute({key: str(val) for key, val in arguments.items()})


def policy_check(command: list[str]) -> None:
    if not command:
        raise ValueError("empty command")
    allowed_binaries = set(policy.get("allowed_binaries") or [])
    blocked = set(policy.get("blocked_commands") or [])
    binary = Path(command[0]).name
    command_text = shlex.join(command)
    allowed_prefixes = [str(item).strip() for item in policy.get("allowed_command_prefixes") or [] if str(item).strip()]
    blocked_prefixes = [str(item).strip() for item in policy.get("blocked_command_prefixes") or [] if str(item).strip()]
    if allowed_binaries and binary not in allowed_binaries:
        raise ValueError(f"binary not allowed: {binary}")
    if allowed_prefixes and not any(command_text == prefix or command_text.startswith(prefix + " ") for prefix in allowed_prefixes):
        raise ValueError(f"command prefix not allowed: {command_text}")
    for prefix in blocked_prefixes:
        if command_text == prefix or command_text.startswith(prefix + " "):
            raise ValueError(f"blocked command prefix: {prefix}")
    for arg in command:
        token = Path(str(arg)).name
        if token in blocked or str(arg) in blocked:
            raise ValueError(f"blocked command token: {arg}")


def _policy_check(tool: dict[str, Any], arguments: dict[str, Any]) -> str | None:
    tool_security = tool.get("security") or {}
    tool_mode = tool_security.get("mode") or tool.get("mode", "read-only")
    if policy.get("require_read_only") and tool_mode != "read-only":
        return "policy: only read-only tools are permitted"
    if policy.get("block_write_tools") and tool_mode == "write":
        return "policy: write tools are blocked"
    if policy.get("block_destructive_tools") and tool_mode == "destructive":
        return "policy: destructive tools are blocked"
    max_payload = int(policy.get("max_payload_bytes") or 1_048_576)
    if len(json.dumps(arguments or {}).encode()) > max_payload:
        return f"policy: request payload exceeds limit of {max_payload} bytes"
    return None


async def execute_tool(tool_name: str, arguments: dict[str, Any],
                       caller_ip: str = "", model: str = "") -> dict[str, Any]:
    _t0 = time.monotonic()
    tool = tools.get(tool_name)
    if not tool:
        return {"ok": False, "error": f"unknown tool: {tool_name}"}
    policy_error = _policy_check(tool, arguments or {})
    if policy_error:
        return {"ok": False, "error": policy_error, "policy_blocked": True}
    if tool.get("execution_type") != "shell":
        return {"ok": False, "error": f"unsupported execution type: {tool.get('execution_type')}"}
    validate(arguments, tool.get("input_schema") or {})
    execution = tool.get("execution") or {}
    command_template = execution.get("command") or []
    # Build command — ${*varname} expands value with shlex.split (multi-arg passthrough)
    command: list[str] = []
    for part in command_template:
        s = str(part)
        if s.startswith("${*") and s.endswith("}"):
            var_name = s[3:-1]
            raw = str(arguments.get(var_name, ""))
            try:
                command.extend(shlex.split(raw))
            except ValueError:
                command.append(raw)
        else:
            command.append(render_arg(s, arguments))
    try:
        policy_check(command)
    except ValueError as exc:
        return {"ok": False, "tool": tool_name, "error": str(exc)}
    timeout = int(execution.get("timeout_seconds") or policy.get("timeout_seconds") or 20)
    max_response_bytes = int(execution.get("max_response_bytes") or policy.get("max_response_bytes") or 1_048_576)
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        result = {
            "ok": False, "tool": tool_name, "error": f"command timed out after {timeout}s",
            "command": [command[0], *command[1:]],
        }
        _fire_tool_call_log(tool_name, arguments, result, int((time.monotonic() - _t0) * 1000),
                            caller_ip=caller_ip, model=model)
        return result
    stdout = completed.stdout[:max_response_bytes]
    stderr = completed.stderr[:max_response_bytes]
    output: dict[str, Any]
    try:
        output = json.loads(stdout) if stdout.strip() else {}
    except json.JSONDecodeError:
        output = {"text": stdout}
    result = {
        "ok": completed.returncode == 0,
        "status_code": completed.returncode,
        "tool": tool_name,
        "command": [command[0], *["***" if "token" in part.lower() else part for part in command[1:]]],
        "output": output,
        "stderr": stderr,
    }
    _fire_tool_call_log(tool_name, arguments, result, int((time.monotonic() - _t0) * 1000),
                        caller_ip=caller_ip, model=model)
    return result


def _caller_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for") or request.headers.get("x-real-ip")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else ""


def _model_from_request(request: Request) -> str:
    return (
        request.headers.get("x-model")
        or request.headers.get("x-openwebui-model")
        or request.headers.get("x-ai-model")
        or ""
    )


@app.post("/tools/{tool_name}")
async def rest_tool(tool_name: str, request: Request) -> JSONResponse:
    payload = await request.json()
    result = await execute_tool(tool_name, payload,
                                caller_ip=_caller_ip(request),
                                model=_model_from_request(request))
    return JSONResponse(result)


@app.post("/openwebui/tools/{tool_name}")
async def rest_tool_openwebui(tool_name: str, request: Request) -> JSONResponse:
    payload = await request.json()
    result = await execute_tool(tool_name, payload,
                                caller_ip=_caller_ip(request),
                                model=_model_from_request(request))
    return JSONResponse(result)


@app.post("/mcp/tools/{tool_name}")
async def rest_tool_mcp_alias(tool_name: str, request: Request) -> JSONResponse:
    payload = await request.json()
    result = await execute_tool(tool_name, payload,
                                caller_ip=_caller_ip(request),
                                model=_model_from_request(request))
    return JSONResponse(result)


@app.get("/mcp")
def mcp_info() -> dict[str, Any]:
    return {
        "name": runtime_config.get("name", "mcp-runtime"),
        "transport": "streamable-http",
        "endpoint": "/mcp",
        "tools": list(tools),
    }


def jsonrpc_result(message_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message_id, "result": result}


def jsonrpc_error(message_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message_id, "error": {"code": code, "message": message}}


@app.post("/mcp")
async def mcp(request: Request):
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse(jsonrpc_error(None, -32700, "Parse error"), status_code=400)
    messages = payload if isinstance(payload, list) else [payload]
    responses = []
    for message in messages:
        method = message.get("method")
        message_id = message.get("id")
        params = message.get("params") or {}
        if method == "initialize":
            responses.append(
                jsonrpc_result(
                    message_id,
                    {
                        "protocolVersion": "2024-11-05",
                        "capabilities": {"tools": {}},
                        "serverInfo": {"name": runtime_config.get("name", "mcp-runtime"), "version": "0.1.0"},
                    },
                )
            )
        elif method == "tools/list":
            responses.append(
                jsonrpc_result(
                    message_id,
                    {
                        "tools": [
                            {
                                "name": tool["name"],
                                "description": tool.get("description", ""),
                                "inputSchema": tool.get("input_schema") or {},
                            }
                            for tool in tools.values()
                        ]
                    },
                )
            )
        elif method == "tools/call":
            result = await execute_tool(params.get("name"), params.get("arguments") or {})
            responses.append(jsonrpc_result(message_id, {"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}]}))
        elif method == "notifications/initialized":
            continue
        else:
            responses.append(jsonrpc_error(message_id, -32601, f"Method not found: {method}"))
    if not responses:
        return Response(status_code=202)
    return JSONResponse(responses if isinstance(payload, list) else responses[0])
