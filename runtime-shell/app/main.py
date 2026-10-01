import asyncio
import hashlib
import json
import os
import re as _re
import secrets
import shlex
import subprocess
import time
import threading
import urllib.error
import urllib.request
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from string import Template
from typing import Any

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
from jsonschema import validate, ValidationError as JsonSchemaValidationError
from pydantic import BaseModel, create_model, field_validator


CONFIG_DIR = Path(os.getenv("RUNTIME_CONFIG_DIR", "/config"))
CALLBACK_URL = os.getenv("MCP_PLATFORM_CALLBACK_URL", "")
RUNTIME_ID = os.getenv("MCP_RUNTIME_ID", "")
app = FastAPI(title="Generic MCP Runtime Shell", version="0.1.0")


@app.middleware("http")
async def _mcp_auth(request: Request, call_next: Any) -> Response:
    # /reload przeładowuje konfigurację — wymaga tokenu tak samo jak toole.
    # Publiczne zostaje samo /health (sondy K8s nie wysyłają nagłówków).
    if request.url.path == "/health":
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

# ── MCP sessions and elicitation (approval dialog shown by the client) ─────────
# Elicitation exists since this protocol revision; older clients keep the old handshake.
_ELICITATION_PROTOCOL = "2025-06-18"
_LEGACY_PROTOCOL = "2024-11-05"
# session id -> client capabilities; in-memory, so after a restart clients fall back to approval links.
_sessions: "OrderedDict[str, dict[str, Any]]" = OrderedDict()
_MAX_SESSIONS = 2000
# elicitation request id -> future resolved by the client's JSON-RPC response
_pending_elicitations: dict[str, "asyncio.Future[str]"] = {}
_SSE_KEEPALIVE_SECONDS = 10


def _public_schema(tool: dict[str, Any]) -> dict[str, Any]:
    """Input schema as shown to clients — without the legacy __confirm property (it approves nothing)."""
    schema = tool.get("input_schema") or {}
    props = schema.get("properties")
    if not isinstance(props, dict) or "__confirm" not in props:
        return schema
    return {**schema, "properties": {k: v for k, v in props.items() if k != "__confirm"}}


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
                "inputSchema": _public_schema(tool),
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
                        "content": {"application/json": {"schema": _public_schema(tool) or {"type": "object"}}},
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

    # Check prefix allowlist/blocklist.
    # Use both the full shlex.join string AND a "subcommand key" (binary + first
    # non-flag arg) so that global flags inserted before the subcommand
    # (e.g. "oc --token=X --server=Y create ...") still match prefix "oc create".
    stage_text = shlex.join(argv)
    sub = _stage_sub(argv)
    allowed_prefixes = [str(p).strip() for p in (policy.get("allowed_command_prefixes") or []) if str(p).strip()]
    blocked_prefixes = [str(p).strip() for p in (policy.get("blocked_command_prefixes") or []) if str(p).strip()]
    if allowed_prefixes and not any(
        _pfx_match(stage_text, pfx) or _pfx_match(sub, pfx) for pfx in allowed_prefixes
    ):
        raise ValueError(f"command prefix not allowed: {stage_text}")
    # Blocklista jest kontrolą admina — potwierdzenie od wywołującego jej nie znosi.
    for pfx in blocked_prefixes:
        if _pfx_match(stage_text, pfx) or _pfx_match(sub, pfx):
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
    # Kolejność jest krytyczna: os.environ NADPISUJE argumenty, nie odwrotnie.
    # Schematy toolów nie ustawiają additionalProperties:false, więc wywołujący
    # może dorzucić dowolny klucz. Przy odwrotnej kolejności argument o nazwie
    # OC_SERVER podmieniłby adres w szablonie ["oc", "--token=${OC_TOKEN}",
    # "--server=${OC_SERVER}", ...] i wysłał prawdziwy token pod obcy adres.
    merged_env: dict[str, str] = {k: str(v) for k, v in arguments.items()}
    merged_env.update(os.environ)

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


def _pfx_match(text: str, pfx: str) -> bool:
    return text == pfx or text.startswith(pfx + " ")


def _stage_sub(stage_argv: list[str]) -> str:
    """Return 'binary subcommand' skipping leading flags, for prefix matching."""
    parts = [stage_argv[0]]
    for a in stage_argv[1:]:
        if not a.startswith("-"):
            parts.append(a)
            break
    return " ".join(parts)


def _stages_need_approval(stages: list[list[str]]) -> bool:
    """Return True if any pipeline stage matches require_approval_for_prefixes."""
    approval_prefixes = [
        str(p).strip()
        for p in (policy.get("require_approval_for_prefixes") or [])
        if str(p).strip()
    ]
    if not approval_prefixes:
        return False
    for stage_argv in stages:
        if not stage_argv:
            continue
        stage_text = shlex.join(stage_argv)
        sub = _stage_sub(stage_argv)
        if any(_pfx_match(stage_text, p) or _pfx_match(sub, p) for p in approval_prefixes):
            return True
    return False


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


def _approval_timeout() -> int:
    """How long an approval dialog waits and how long an approved link stays usable (seconds)."""
    try:
        return max(30, int(policy.get("approval_timeout_seconds") or 300))
    except (TypeError, ValueError):
        return 300


def _approval_key(tool_name: str, arguments: dict[str, Any]) -> str:
    """
    Deterministyczny identyfikator zgody: to samo narzędzie + te same argumenty
    dają ten sam klucz, więc ponowne wywołanie odnajduje decyzję człowieka
    bez przekazywania czegokolwiek przez model.
    """
    payload = json.dumps(
        {"r": RUNTIME_ID, "t": tool_name, "a": arguments}, sort_keys=True, default=str
    )
    return hashlib.sha256(payload.encode()).hexdigest()[:32]


def _approval_fresh(decided_at: str | None, max_age_s: int) -> bool:
    """Zgoda starsza niż okno ważności nie upoważnia do wykonania."""
    if not decided_at:
        return False
    try:
        ts = datetime.fromisoformat(decided_at.replace("Z", "+00:00"))
    except ValueError:
        return False
    if ts.tzinfo is None:
        ts = ts.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - ts).total_seconds() <= max_age_s


def _control_plane(method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any] | None:
    """Blocking call to the control plane; None on 404, raises on other errors."""
    req = urllib.request.Request(
        f"{CALLBACK_URL}{path}",
        data=json.dumps(body).encode() if body is not None else None,
        headers={"Content-Type": "application/json"},
        method=method,
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise


def _not_executed(tool_name: str, message: str, **extra: Any) -> dict[str, Any]:
    return {"ok": False, "tool": tool_name, "approval_required": True, "message": message, **extra}


async def _link_approval(tool_name: str, arguments: dict[str, Any], cmd_preview: str,
                         tool_mode: str, caller_ip: str, model: str) -> dict[str, Any] | None:
    """
    Zgoda przez link do control-plane (dla klientów bez okna potwierdzenia).
    Zwraca None gdy człowiek zatwierdził dokładnie tę komendę, inaczej wynik
    "nie wykonano" z linkiem. Jedna zgoda = jedno wykonanie.
    """
    if not CALLBACK_URL or not RUNTIME_ID:
        return _not_executed(
            tool_name,
            f"\u26d4 This operation requires human approval, but this server has no way to ask for it "
            f"(no control plane configured). It was NOT executed.\n\nCommand: {cmd_preview}",
            approval_denied=True,
        )
    req_id = _approval_key(tool_name, {**arguments, "_command": cmd_preview})
    max_age = _approval_timeout()
    try:
        data = await asyncio.to_thread(_control_plane, "GET", f"/api/approval-status/{req_id}")
        # Prośba już czeka: model wywołał ponownie — daj człowiekowi chwilę na decyzję,
        # zamiast odsyłać model od razu (ograniczone, żeby nie przekroczyć timeoutu proxy).
        if data and data.get("status") == "pending":
            deadline = time.monotonic() + min(20, int(policy.get("approval_wait_seconds") or 20))
            while time.monotonic() < deadline:
                await asyncio.sleep(2)
                data = await asyncio.to_thread(_control_plane, "GET", f"/api/approval-status/{req_id}")
                if not data or data.get("status") != "pending":
                    break
        status = (data or {}).get("status")
        if status == "approved" and _approval_fresh(data.get("decided_at"), max_age):
            used = await asyncio.to_thread(_control_plane, "POST", f"/api/approval-consume/{req_id}", {})
            if used and used.get("ok"):
                return None
            status = "used"  # ktoś inny zużył tę zgodę — potrzebna nowa
        if status == "rejected" and _approval_fresh(data.get("decided_at"), max_age):
            reason = data.get("reject_reason") or "rejected"
            return _not_executed(
                tool_name,
                f"\u26d4 A human rejected this operation. It was NOT executed.\n\n"
                f"Command: {cmd_preview}\nReason: {reason}\n\nDo not retry.",
                approval_denied=True, error=f"operation not approved: {reason}",
            )
        if status == "pending":
            url = data.get("url")
        else:
            created = await asyncio.to_thread(_control_plane, "POST", "/api/approval-request", {
                "id": req_id, "runtime_id": RUNTIME_ID, "tool_name": tool_name,
                "arguments": {**arguments, "_command": cmd_preview},
                "mode": tool_mode, "caller_ip": caller_ip, "model": model,
            })
            url = (created or {}).get("url")
            if not url:
                raise RuntimeError("control plane did not accept the approval request")
    except Exception as exc:
        return _not_executed(
            tool_name,
            f"\u26d4 This operation requires human approval, but the approval service could not be reached "
            f"({exc}). It was NOT executed.\n\nCommand: {cmd_preview}",
        )
    return _not_executed(
        tool_name,
        f"\u23f8 This operation is waiting for approval by a human and has NOT been executed.\n\n"
        f"Command: {cmd_preview}\n\n"
        f"Approval link — show it to the user exactly as written:\n{url}\n\n"
        f"You cannot approve this yourself and there is no parameter that confirms it. "
        f"Ask the user to open the link and decide. After they say it is approved, call this same "
        f"tool again with exactly the same parameters.",
        approval_url=url,
    )


async def _require_approval(tool_name: str, arguments: dict[str, Any], cmd_preview: str, tool_mode: str,
                            caller_ip: str, model: str, elicit: Any) -> dict[str, Any] | None:
    """Returns None when a human approved the operation, otherwise the "not executed" result."""
    if elicit is not None:
        # Klient MCP sam pyta użytkownika (okno Tak/Nie) — wywołanie czeka na odpowiedź,
        # a model nie bierze w tym udziału.
        answer = await elicit(
            f"Approve this operation?\n\nTool: {tool_name} ({tool_mode})\nCommand: {cmd_preview}"
        )
        if answer == "accept":
            return None
        if answer in ("decline", "cancel"):
            return _not_executed(
                tool_name,
                f"\u26d4 The user declined this operation. It was NOT executed.\n\nCommand: {cmd_preview}\n\nDo not retry.",
                approval_denied=True, error="operation not approved by the user",
            )
        if answer == "timeout":
            return _not_executed(
                tool_name,
                f"\u26d4 The user did not answer the approval dialog within {_approval_timeout()} s. "
                f"It was NOT executed.\n\nCommand: {cmd_preview}",
                approval_denied=True, error="approval timed out",
            )
        # any other outcome (client error) → fall back to the approval link
    return await _link_approval(tool_name, arguments, cmd_preview, tool_mode, caller_ip, model)


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
                       caller_ip: str = "", model: str = "",
                       elicit: Any = None) -> dict[str, Any]:
    """
    elicit — async callable(message) -> "accept" | "decline" | "cancel" | "timeout",
    available when the MCP client can show a confirmation dialog itself.
    """
    _t0 = time.monotonic()
    tool = tools.get(tool_name)
    if not tool:
        return {"ok": False, "error": f"unknown tool: {tool_name}"}
    # Legacy parameter: the model used to confirm operations itself. It is ignored now —
    # only a human can approve (client dialog or approval link).
    arguments.pop("__confirm", None)
    policy_error = _policy_check(tool, arguments or {})
    if policy_error:
        return {"ok": False, "error": policy_error, "policy_blocked": True}
    if tool.get("execution_type") != "shell":
        return {"ok": False, "error": f"unsupported execution type: {tool.get('execution_type')}"}

    # Normalize arguments — convert lists to strings (some models send arrays)
    for k, v in list(arguments.items()):
        if isinstance(v, list):
            arguments[k] = " ".join(str(x) for x in v)

    try:
        validate(arguments, tool.get("input_schema") or {})
    except JsonSchemaValidationError as exc:
        return {"ok": False, "error": f"validation error: {exc.message}", "validation_blocked": True}
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

    timeout = int(execution.get("timeout_seconds") or policy.get("timeout_seconds") or 20)
    max_response_bytes = min(
        int(execution.get("max_response_bytes") or policy.get("max_response_bytes") or 1_048_576),
        MAX_OUTPUT_BYTES,
    )

    # ── Human-in-the-Loop approval — decyzję podejmuje człowiek, nigdy model.
    if _needs_approval(tool) or _stages_need_approval(stages):
        cmd_preview = " | ".join(shlex.join(s) for s in stages)
        tool_mode = (tool.get("security") or {}).get("mode") or tool.get("mode", "read-only")
        blocked = await _require_approval(tool_name, arguments, cmd_preview, tool_mode, caller_ip, model, elicit)
        if blocked is not None:
            _fire_tool_call_log(tool_name, arguments, blocked,
                                int((time.monotonic() - _t0) * 1000),
                                caller_ip=caller_ip, model=model)
            return blocked

    # ── Hard policy check for every pipeline stage.
    for stage_argv in stages:
        try:
            _policy_check_stage(stage_argv)
        except ValueError as exc:
            return {"ok": False, "tool": tool_name, "error": str(exc)}

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


def _tool_result_message(message_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return jsonrpc_result(message_id, {"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}]})


def _sse(message: dict[str, Any]) -> str:
    return f"event: message\ndata: {json.dumps(message, ensure_ascii=False)}\n\n"


def _initialize(message_id: Any, params: dict[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
    """Handshake. Clients that can show an approval dialog (elicitation) get a session."""
    requested = str(params.get("protocolVersion") or "")
    can_elicit = "elicitation" in (params.get("capabilities") or {}) and requested >= _ELICITATION_PROTOCOL
    headers: dict[str, str] = {}
    if can_elicit:
        session_id = secrets.token_urlsafe(24)
        _sessions[session_id] = {"elicitation": True}
        while len(_sessions) > _MAX_SESSIONS:
            _sessions.popitem(last=False)
        headers["Mcp-Session-Id"] = session_id
    result = jsonrpc_result(
        message_id,
        {
            # Bez elicitation zostaje dotychczasowy handshake — nic się nie zmienia dla starszych klientów.
            "protocolVersion": _ELICITATION_PROTOCOL if can_elicit else _LEGACY_PROTOCOL,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": runtime_config.get("name", "mcp-runtime"), "version": "0.1.0"},
        },
    )
    return result, headers


async def _call_tool_with_dialog(message_id: Any, params: dict[str, Any], request: Request) -> Response:
    """
    tools/call dla klienta z elicitation. Jeśli operacja wymaga zgody, odpowiedź
    staje się strumieniem SSE: serwer wysyła żądanie elicitation/create, klient
    pokazuje użytkownikowi okno, a wynik narzędzia przychodzi tym samym strumieniem
    dopiero po decyzji. Bez potrzeby zgody — zwykła odpowiedź JSON jak dotąd.
    """
    outbox: asyncio.Queue = asyncio.Queue()

    async def elicit(prompt: str) -> str:
        request_id = f"approval-{secrets.token_hex(8)}"
        answer: asyncio.Future = asyncio.get_running_loop().create_future()
        _pending_elicitations[request_id] = answer
        await outbox.put({
            "jsonrpc": "2.0", "id": request_id, "method": "elicitation/create",
            "params": {"message": prompt, "requestedSchema": {"type": "object", "properties": {}}},
        })
        try:
            return await asyncio.wait_for(answer, timeout=_approval_timeout())
        except asyncio.TimeoutError:
            return "timeout"
        finally:
            _pending_elicitations.pop(request_id, None)

    call = asyncio.create_task(execute_tool(
        params.get("name"), params.get("arguments") or {},
        caller_ip=_caller_ip(request), model=_model_from_request(request), elicit=elicit,
    ))

    def final_message() -> dict[str, Any]:
        try:
            return _tool_result_message(message_id, call.result())
        except Exception as exc:
            return jsonrpc_error(message_id, -32603, f"Internal error: {exc}")

    first = asyncio.create_task(outbox.get())
    await asyncio.wait({call, first}, return_when=asyncio.FIRST_COMPLETED)
    if not first.done():  # tool finished without asking anything
        first.cancel()
        return JSONResponse(final_message())

    async def stream():
        yield _sse(first.result())
        while not call.done():
            pending = asyncio.create_task(outbox.get())
            await asyncio.wait({call, pending}, timeout=_SSE_KEEPALIVE_SECONDS, return_when=asyncio.FIRST_COMPLETED)
            if pending.done():
                yield _sse(pending.result())
                continue
            pending.cancel()
            if not call.done():
                yield ": waiting for the user's decision\n\n"  # keeps proxies from closing an idle stream
        yield _sse(final_message())

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.post("/mcp")
async def mcp(request: Request):
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse(jsonrpc_error(None, -32700, "Parse error"), status_code=400)
    messages = payload if isinstance(payload, list) else [payload]
    session = _sessions.get(request.headers.get("mcp-session-id", ""))
    can_stream = "text/event-stream" in request.headers.get("accept", "") and not isinstance(payload, list)
    responses = []
    extra_headers: dict[str, str] = {}
    for message in messages:
        method = message.get("method")
        message_id = message.get("id")
        params = message.get("params") or {}
        if method is None and message_id in _pending_elicitations:
            # Odpowiedź klienta na elicitation/create — decyzja użytkownika z okna potwierdzenia.
            action = str((message.get("result") or {}).get("action") or "cancel")
            answer = _pending_elicitations[message_id]
            if not answer.done():
                answer.set_result(action if action in ("accept", "decline", "cancel") else "cancel")
            continue
        if method is None:
            continue  # response to a request we no longer wait for
        if method == "initialize":
            result, extra_headers = _initialize(message_id, params)
            responses.append(result)
        elif method == "tools/list":
            responses.append(
                jsonrpc_result(
                    message_id,
                    {
                        "tools": [
                            {
                                "name": tool["name"],
                                "description": tool.get("description", ""),
                                "inputSchema": _public_schema(tool),
                            }
                            for tool in tools.values()
                        ]
                    },
                )
            )
        elif method == "tools/call":
            if session and session.get("elicitation") and can_stream:
                return await _call_tool_with_dialog(message_id, params, request)
            result = await execute_tool(params.get("name"), params.get("arguments") or {},
                                        caller_ip=_caller_ip(request),
                                        model=_model_from_request(request))
            responses.append(_tool_result_message(message_id, result))
        elif method in ("notifications/initialized", "notifications/cancelled"):
            continue
        else:
            responses.append(jsonrpc_error(message_id, -32601, f"Method not found: {method}"))
    if not responses:
        return Response(status_code=202)
    return JSONResponse(responses if isinstance(payload, list) else responses[0], headers=extra_headers)
