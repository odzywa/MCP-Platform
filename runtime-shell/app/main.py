import asyncio
import json
import os
import re as _re
import secrets
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
from pydantic import BaseModel, create_model, field_validator


CONFIG_DIR = Path(os.getenv("RUNTIME_CONFIG_DIR", "/config"))
CALLBACK_URL = os.getenv("MCP_PLATFORM_CALLBACK_URL", "")
RUNTIME_ID = os.getenv("MCP_RUNTIME_ID", "")
app = FastAPI(title="Generic MCP Runtime Shell", version="0.1.0")


@app.middleware("http")
async def _mcp_auth(request: Request, call_next: Any) -> Response:
    if request.url.path in ("/health", "/reload"):
        return await call_next(request)
    token: str = runtime_config.get("auth_token", "")
    if not token:
        return await call_next(request)
    auth = request.headers.get("Authorization", "")
    api_key = request.headers.get("X-API-Key", "")
    bearer_ok = auth.startswith("Bearer ") and secrets.compare_digest(auth[7:], token)
    key_ok = bool(api_key) and secrets.compare_digest(api_key, token)
    if bearer_ok or key_ok:
        return await call_next(request)
    return JSONResponse({"error": "Unauthorized"}, status_code=401,
                        headers={"WWW-Authenticate": "Bearer"})

# Shell metacharacters that act as pipeline/redirect operators.
# These are recognised ONLY in tool-definition templates, never in user input.
_PIPELINE_SEP = "|"
_REDIRECT_OPS = {">", ">>", "<", "<<", "<<<", "2>", "2>&1"}
_SHELL_OPS = {_PIPELINE_SEP} | _REDIRECT_OPS

# Env vars that are shell-internal and must not be forwarded to subprocesses.
_SHELL_INTERNAL_VARS = frozenset({
    "PS1", "PS2", "PS3", "PS4", "_", "BASH_VERSION", "BASH_VERSINFO",
    "SHELLOPTS", "BASHOPTS", "BASH_CMDS", "BASH_ALIASES", "DIRSTACK",
    "FUNCNAME", "GROUPS", "HISTFILE", "HISTSIZE", "HISTFILESIZE",
    "PPID", "RANDOM", "SECONDS", "SHLVL", "LINENO", "OLDPWD",
})

MAX_OUTPUT_BYTES = 10 * 1024 * 1024  # hard cap independent of tool config


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


_pydantic_cache: dict[str, type[BaseModel]] = {}

def _build_pydantic_model(tool_name: str, schema: dict, policy_blocked: list[str]) -> type[BaseModel] | None:
    props = schema.get("properties") or {}
    if not props:
        return None
    cache_key = json.dumps({"t": tool_name, "s": schema, "b": policy_blocked}, sort_keys=True)
    if cache_key in _pydantic_cache:
        return _pydantic_cache[cache_key]

    fields: dict[str, Any] = {}
    validators: dict[str, Any] = {}
    required = set(schema.get("required") or [])

    for pname, pdef in props.items():
        py_type = {"integer": int, "number": float, "boolean": bool}.get(pdef.get("type", "string"), str)
        if pname in required:
            fields[pname] = (py_type, ...)
        else:
            default = "" if py_type is str else (0 if py_type in (int, float) else False)
            fields[pname] = (py_type, default)

        rules = pdef.get("validation") or {}
        allowed = rules.get("allowed_values") or []
        blocked = list(rules.get("blocked_words") or []) + policy_blocked
        pattern = rules.get("pattern") or ""
        max_len = rules.get("max_length") or 0

        if allowed or blocked or pattern or max_len:
            _a, _b, _p, _m, _fn = allowed, blocked, pattern, max_len, pname
            def _make_check(a=_a, b=_b, p=_p, m=_m, fn=_fn):
                def _check(cls, v):
                    s = str(v)
                    if a and s not in a:
                        raise ValueError(f"{fn}: '{s}' niedozwolone. Dozwolone: {a}")
                    if b:
                        upper = s.upper()
                        for word in b:
                            if word.upper() in upper:
                                raise ValueError(f"{fn}: zabronione słowo '{word}'")
                    if p and not _re.match(p, s):
                        raise ValueError(f"{fn}: nie pasuje do wzorca '{p}'")
                    if m and len(s) > m:
                        raise ValueError(f"{fn}: max {m} znaków, podano {len(s)}")
                    return v
                return _check
            validators[f"check_{pname}"] = field_validator(pname, mode="before")(_make_check())

    model = create_model(f"Tool_{tool_name}", **fields, __validators__=validators)
    _pydantic_cache[cache_key] = model
    return model


def validate_with_pydantic(tool_name: str, arguments: dict, schema: dict, tool_policy: dict) -> str | None:
    policy_blocked = [str(w) for w in (tool_policy.get("blocked_commands") or [])]
    model = _build_pydantic_model(tool_name, schema, policy_blocked)
    if not model:
        return None
    try:
        model(**arguments)
        return None
    except Exception as exc:
        return str(exc)


def _policy_check_stage(argv: list[str]) -> None:
    """Validate one pipeline stage. Raises ValueError on violation."""
    if not argv:
        raise ValueError("empty command stage")

    binary_path = argv[0]

    # Reject path separators in binary name unless it's an explicitly allowed absolute path.
    # This blocks things like "../../bin/sh" or "subdir/script.sh".
    if "/" in binary_path or "\\" in binary_path:
        allowed_paths = set(policy.get("allowed_absolute_paths") or [])
        if binary_path not in allowed_paths:
            raise ValueError(f"path separators not allowed in binary: {binary_path!r}")

    binary = Path(binary_path).name
    allowed_binaries = set(policy.get("allowed_binaries") or [])
    blocked = set(policy.get("blocked_commands") or [])

    if allowed_binaries and binary not in allowed_binaries:
        raise ValueError(f"binary not allowed: {binary!r}")
    if binary in blocked:
        raise ValueError(f"blocked binary: {binary!r}")

    # Check prefix allowlist/blocklist against this stage's full argv string.
    stage_text = shlex.join(argv)
    allowed_prefixes = [str(p).strip() for p in (policy.get("allowed_command_prefixes") or []) if str(p).strip()]
    blocked_prefixes = [str(p).strip() for p in (policy.get("blocked_command_prefixes") or []) if str(p).strip()]
    if allowed_prefixes and not any(
        stage_text == pfx or stage_text.startswith(pfx + " ") for pfx in allowed_prefixes
    ):
        raise ValueError(f"command prefix not allowed: {stage_text}")
    for pfx in blocked_prefixes:
        if stage_text == pfx or stage_text.startswith(pfx + " "):
            raise ValueError(f"blocked command prefix: {stage_text}")

    # Check blocked tokens in arguments (not the binary itself).
    for arg in argv[1:]:
        if str(arg) in blocked:
            raise ValueError(f"blocked token in arguments: {arg!r}")


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


def _parse_pipeline_template(command_template: list[str]) -> list[list[str]]:
    """
    Split a flat command template into pipeline stages on literal '|' tokens.
    The '|' must appear as its own token in the template — it cannot come from
    user-supplied variable substitution.
    """
    stages: list[list[str]] = []
    current: list[str] = []
    for token in command_template:
        if str(token) == _PIPELINE_SEP:
            stages.append(current)
            current = []
        else:
            current.append(str(token))
    stages.append(current)
    return [s for s in stages if s]  # drop empty stages


def _build_stage_argv(stage_template: list[str], arguments: dict[str, Any]) -> list[str]:
    """
    Build argv for one pipeline stage.

    Rules:
    - ${var}  → exactly ONE element in argv (the raw value, no splitting)
    - ${*var} → shlex.split() the value → extend argv with resulting tokens
               (the tokens are added as separate arguments, never joined back
                into a string that would be re-interpreted by a shell)
    - Anything else → Template safe_substitute → single element

    Shell metacharacters arriving through ${*var} or ${var} are INERT because
    the resulting argv is always passed to Popen/run with shell disabled.
    """
    merged_env: dict[str, str] = {k: v for k, v in os.environ.items()}
    merged_env.update({k: str(v) for k, v in arguments.items()})

    argv: list[str] = []
    for part in stage_template:
        s = str(part)
        if s.startswith("${*") and s.endswith("}"):
            # Multi-arg passthrough — tokenise, then extend (never join back)
            var_name = s[3:-1]
            raw = str(arguments.get(var_name, ""))
            try:
                tokens = shlex.split(raw)
            except ValueError:
                tokens = [raw]
            argv.extend(tokens)
        elif s.startswith("${") and s.endswith("}"):
            # Single-value substitution — one argv element regardless of spaces
            var_name = s[2:-1]
            value = merged_env.get(var_name, "")
            argv.append(value)
        else:
            # Literal template with ${...} placeholders — safe_substitute, one element
            argv.append(Template(s).safe_substitute(merged_env))
    return argv


def _minimal_env() -> dict[str, str]:
    """
    Return a minimal execution environment — full os.environ minus shell internals.
    We keep everything except known shell-internal vars so that runtime credentials
    (OC_TOKEN, etc.) injected into the container remain available to subprocesses,
    but bash/zsh state variables are stripped.
    """
    return {k: v for k, v in os.environ.items() if k not in _SHELL_INTERNAL_VARS}


# Keywords in tool names that signal a potentially destructive or mutating action.
# Used only when require_approval_for is set to "auto".
_AUTO_APPROVAL_KEYWORDS = frozenset({
    # deletes
    "delete", "remove", "destroy", "drop", "purge", "wipe", "truncate", "erase", "clean",
    # creates / mutations
    "create", "apply", "deploy", "install", "patch", "scale", "expose",
    "rollout", "new", "add", "set", "update", "replace", "restart",
})


def _needs_approval(tool: dict[str, Any]) -> bool:
    """
    Return True when this tool call requires human approval.

    Policy field ``require_approval_for`` controls the behaviour:
      - not set / empty list → no approval required (default, backwards-compatible)
      - "auto" or ["auto"]   → auto-detect: approve if mode is write/destructive
                               OR if the tool name contains a known action keyword
      - ["write","destructive"] → explicit list of modes that need approval
    """
    require_for = policy.get("require_approval_for")
    if not require_for:
        return False

    tool_mode = (tool.get("security") or {}).get("mode") or tool.get("mode", "read-only")
    tool_name = (tool.get("name") or "").lower()

    # "auto" keyword — zero-config mode detection
    if require_for == "auto" or (isinstance(require_for, list) and "auto" in require_for):
        if tool_mode in ("write", "destructive"):
            return True
        return any(kw in tool_name for kw in _AUTO_APPROVAL_KEYWORDS)

    # Explicit list of modes
    modes = require_for if isinstance(require_for, list) else [require_for]
    return tool_mode in modes


async def _request_approval(
    tool_name: str,
    arguments: dict[str, Any],
    tool_mode: str,
    caller_ip: str,
    model: str,
) -> dict[str, Any]:
    """
    Submit an approval request to the control plane and poll until a decision
    is made or the configured timeout expires.

    Returns {"approved": bool, "reason": str | None}.
    """
    if not CALLBACK_URL:
        return {"approved": False, "reason": "no callback URL — approval cannot be requested"}

    req_id = secrets.token_urlsafe(16)
    payload = json.dumps({
        "id": req_id,
        "runtime_id": RUNTIME_ID,
        "tool_name": tool_name,
        "arguments": arguments,
        "mode": tool_mode,
        "caller_ip": caller_ip,
        "model": model,
    }).encode()

    try:
        req = urllib.request.Request(
            f"{CALLBACK_URL}/api/approval-request",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        urllib.request.urlopen(req, timeout=5)
    except Exception as exc:
        return {"approved": False, "reason": f"approval request failed: {exc}"}

    timeout_s = int(policy.get("approval_timeout_seconds") or 300)
    deadline = time.monotonic() + timeout_s
    poll_url = f"{CALLBACK_URL}/api/approval-status/{req_id}"

    while time.monotonic() < deadline:
        await asyncio.sleep(2)
        try:
            resp = urllib.request.urlopen(poll_url, timeout=5)
            data = json.loads(resp.read())
            status = data.get("status")
            if status == "approved":
                return {"approved": True, "reason": None}
            if status in ("rejected", "timeout"):
                return {"approved": False, "reason": data.get("reject_reason") or status}
        except Exception:
            pass

    return {"approved": False, "reason": f"approval timeout after {timeout_s}s"}


def _run_pipeline(
    stages: list[list[str]],
    timeout: int,
    max_bytes: int,
) -> tuple[str, str, int]:
    """
    Execute a pipeline of argv lists — subprocess shell flag is always disabled.

    Single stage  → subprocess.run(shell=False)
    Multi-stage   → chain of Popen objects with stdout=PIPE → stdin
                    stdout of each intermediate stage is closed in the parent
                    immediately after the next stage is started to avoid
                    file-descriptor leaks and deadlocks.
    """
    env = _minimal_env()
    cwd = "/tmp"

    if len(stages) == 1:
        completed = subprocess.run(
            stages[0],
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            env=env,
            cwd=cwd,
        )
        return (
            completed.stdout[:max_bytes],
            completed.stderr[:max_bytes],
            completed.returncode,
        )

    # Multi-stage pipeline via Popen.
    procs: list[subprocess.Popen] = []
    prev_stdout = None
    for i, argv in enumerate(stages):
        is_last = i == len(stages) - 1
        proc = subprocess.Popen(
            argv,
            shell=False,
            stdin=prev_stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE if is_last else subprocess.DEVNULL,
            text=True,
            env=env,
            cwd=cwd,
        )
        # Close the write-end of the previous pipe in the parent so the
        # next stage's stdin EOF propagates correctly when the child closes it.
        if prev_stdout is not None:
            prev_stdout.close()
        prev_stdout = proc.stdout
        procs.append(proc)

    # Collect output from the last stage.
    stdout_data = ""
    stderr_data = ""
    returncode = -1
    try:
        stdout_data, stderr_data = procs[-1].communicate(timeout=timeout)
        returncode = procs[-1].returncode
    except subprocess.TimeoutExpired:
        for proc in procs:
            proc.kill()
        for proc in procs:
            proc.wait()
        raise
    finally:
        # Ensure all intermediate processes are reaped.
        for proc in procs[:-1]:
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()

    return stdout_data[:max_bytes], stderr_data[:max_bytes], returncode


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

    # Normalize arguments — convert lists to strings (some models send arrays)
    for k, v in list(arguments.items()):
        if isinstance(v, list):
            arguments[k] = " ".join(str(x) for x in v)

    validate(arguments, tool.get("input_schema") or {})
    pydantic_error = validate_with_pydantic(tool_name, arguments, tool.get("input_schema") or {}, policy)
    if pydantic_error:
        return {"ok": False, "error": pydantic_error, "validation_blocked": True}

    execution = tool.get("execution") or {}
    command_template: list[str] = execution.get("command") or []

    # ── Parse pipeline stages from the TEMPLATE (before user input touches it).
    # '|' in the template creates pipeline stages; '|' in user input is inert.
    pipeline_templates = _parse_pipeline_template(command_template)
    if not pipeline_templates:
        return {"ok": False, "error": "empty command template"}

    # ── Build argv for each stage (token-level substitution, no string joining).
    try:
        stages: list[list[str]] = [
            _build_stage_argv(tmpl, arguments) for tmpl in pipeline_templates
        ]
    except Exception as exc:
        return {"ok": False, "error": f"command build error: {exc}"}

    # ── Check allowlist for argv[0] of EVERY stage independently.
    for stage_argv in stages:
        try:
            _policy_check_stage(stage_argv)
        except ValueError as exc:
            return {"ok": False, "tool": tool_name, "error": str(exc)}

    timeout = int(execution.get("timeout_seconds") or policy.get("timeout_seconds") or 20)
    max_response_bytes = min(
        int(execution.get("max_response_bytes") or policy.get("max_response_bytes") or 1_048_576),
        MAX_OUTPUT_BYTES,
    )

    # ── Human-in-the-Loop approval for write/destructive tools.
    if _needs_approval(tool):
        tool_mode = (tool.get("security") or {}).get("mode") or tool.get("mode", "write")
        decision = await _request_approval(tool_name, arguments, tool_mode, caller_ip, model)
        if not decision["approved"]:
            result = {
                "ok": False, "tool": tool_name,
                "error": f"Tool call requires approval — {decision.get('reason') or 'rejected'}",
                "approval_required": True,
            }
            _fire_tool_call_log(tool_name, arguments, result,
                                int((time.monotonic() - _t0) * 1000),
                                caller_ip=caller_ip, model=model)
            return result

    # ── Execute — always shell=False; pipelines via explicit Popen chain.
    try:
        stdout, stderr, returncode = _run_pipeline(stages, timeout, max_response_bytes)
    except subprocess.TimeoutExpired:
        result = {
            "ok": False, "tool": tool_name,
            "error": f"command timed out after {timeout}s",
            "command": stages[0][:1],
        }
        _fire_tool_call_log(tool_name, arguments, result,
                            int((time.monotonic() - _t0) * 1000),
                            caller_ip=caller_ip, model=model)
        return result

    output: dict[str, Any]
    try:
        output = json.loads(stdout) if stdout.strip() else {}
    except json.JSONDecodeError:
        output = {"text": stdout}

    # Redact tokens from the logged command representation.
    def _redact(argv: list[str]) -> list[str]:
        return [argv[0]] + [
            "***" if "token" in a.lower() else a for a in argv[1:]
        ]

    result = {
        "ok": returncode == 0,
        "status_code": returncode,
        "tool": tool_name,
        "command": _redact(stages[0]),
        "pipeline_stages": len(stages),
        "output": output,
        "stderr": stderr,
    }
    _fire_tool_call_log(tool_name, arguments, result,
                        int((time.monotonic() - _t0) * 1000),
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
            result = await execute_tool(params.get("name"), params.get("arguments") or {},
                                        caller_ip=_caller_ip(request),
                                        model=_model_from_request(request))
            responses.append(jsonrpc_result(message_id, {"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}]}))
        elif method == "notifications/initialized":
            continue
        else:
            responses.append(jsonrpc_error(message_id, -32601, f"Method not found: {method}"))
    if not responses:
        return Response(status_code=202)
    return JSONResponse(responses if isinstance(payload, list) else responses[0])
