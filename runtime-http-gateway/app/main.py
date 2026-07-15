import json
import os
import asyncio
import secrets
import threading
import time
import urllib.request
import uuid
from pathlib import Path
from string import Template
from typing import Any

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse
from jsonschema import validate


CONFIG_DIR = Path(os.getenv("RUNTIME_CONFIG_DIR", "/config"))
CALLBACK_URL = os.getenv("MCP_PLATFORM_CALLBACK_URL", "")
RUNTIME_ID = os.getenv("MCP_RUNTIME_ID", "")
app = FastAPI(title="Generic MCP Runtime HTTP Gateway", version="0.1.0")


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
sse_sessions: dict[str, asyncio.Queue[dict[str, Any]]] = {}


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
    paths = {}
    for tool in tools.values():
        execution = tool.get("execution") or {}
        if tool.get("openwebui_enabled") is False or execution.get("openwebui_enabled") is False:
            continue
        name = tool["name"]
        paths[f"/tools/{name}"] = {
            "post": {
                "operationId": name,
                "summary": tool.get("description") or name,
                "description": tool.get("description") or "",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": tool.get("input_schema") or {"type": "object"},
                        }
                    },
                },
                "responses": {
                    "200": {
                        "description": "Tool execution result.",
                        "content": {
                            "application/json": {
                                "schema": tool.get("output_schema") or {"type": "object"},
                            }
                        },
                    }
                },
            }
        }
    return {
        "openapi": "3.0.3",
        "info": {
            "title": runtime_config.get("name", "MCP Runtime"),
            "version": "0.1.0",
            "description": "Config-driven MCP runtime tools.",
        },
        "servers": [{"url": "/"}],
        "paths": paths,
    }


def input_defaults(schema: dict[str, Any]) -> dict[str, Any]:
    defaults = {}
    for name, spec in (schema.get("properties") or {}).items():
        if isinstance(spec, dict) and "default" in spec:
            defaults[name] = spec["default"]
    return defaults


def substitute_template(value: Any, values: dict[str, Any]) -> Any:
    if isinstance(value, str):
        exact = value.strip()
        if exact.startswith("${") and exact.endswith("}") and exact.count("${") == 1:
            key = exact[2:-1]
            if key in values:
                return values[key]
        return Template(value).safe_substitute({key: str(val) for key, val in values.items()})
    if isinstance(value, dict):
        return {key: substitute_template(val, values) for key, val in value.items()}
    if isinstance(value, list):
        return [substitute_template(item, values) for item in value]
    return value


def compact_text(value: Any, limit: int = 1400) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return text[: limit - 20].rstrip() + "\n[truncated]"


def format_context_text(output: dict[str, Any], tool: dict[str, Any]) -> dict[str, Any]:
    formatter = tool.get("response_formatter") or (tool.get("execution") or {}).get("response_formatter") or {}
    max_items = int(formatter.get("max_items") or 8)
    content_limit = int(formatter.get("content_chars") or 1400)
    include_debug = bool(formatter.get("include_debug", False))
    query = output.get("query", "")
    instruction = output.get("instruction", "")
    results = output.get("results") or []
    debug = output.get("debug") or {}

    lines = [
        "RAGHybrid retrieval context",
        f"Query: {query}",
    ]

    # --- observability header (fusion-aware) ---
    retrieval_meta: list[str] = []
    chunks_found = debug.get("results_before_gate") or debug.get("fused_candidates") or debug.get("vector_results")
    if chunks_found is not None:
        retrieval_meta.append(f"chunks_found={chunks_found}")
    gate_accepted = debug.get("results_after_gate")
    if gate_accepted is not None:
        retrieval_meta.append(f"gate_accepted={gate_accepted}")
    top_score = debug.get("top_score")
    if top_score is not None:
        retrieval_meta.append(f"top_score={round(float(top_score), 3)}")
    lex = debug.get("lexical_overlap")
    if lex is not None:
        retrieval_meta.append(f"lexical={round(float(lex), 2)}")
    # Fusion-specific fields
    fusion_active = debug.get("fusion_active") or debug.get("fused_candidates")
    if fusion_active:
        v = debug.get("vector_results", 0)
        g = debug.get("graph_results", 0)
        e = debug.get("graph_evidence_results", 0)
        retrieval_meta.append(f"paths=v{v}+g{g}+e{e}")
    if retrieval_meta:
        lines.append(f"[retrieval: {' | '.join(retrieval_meta)}]")

    if not results:
        gate_reason = debug.get("gate_reason") or debug.get("relevance_reason") or debug.get("reason")
        lines.append("")
        if gate_reason:
            lines.append(f"[gate blocked: {gate_reason}]")
        if instruction:
            lines.extend(["", compact_text(instruction, 900)])
        return {
            "content": "\n".join(lines).strip(),
            "sources": [],
            "query": query,
            "result_count": 0,
            "gate_reason": gate_reason,
            "rag_used": False,
        }

    if instruction:
        lines.extend(["", "Use this guidance:", compact_text(instruction, 900)])
    lines.extend(["", "Sources:"])
    sources = []
    any_truncated = False

    for index, item in enumerate(results[:max_items], start=1):
        source = item.get("source") or (item.get("metadata") or {}).get("source") or "unknown"
        rank = item.get("rank", index)
        kind = item.get("type") or "context"
        raw_content = item.get("content") or item.get("text") or item
        text = compact_text(raw_content, content_limit)
        if len(str(raw_content)) > content_limit:
            any_truncated = True

        # Build per-item score annotation (fusion-aware)
        fused = item.get("fused_score")
        vs = item.get("vector_score")
        gs = item.get("graph_score")
        rerank_r = item.get("rerank_reason") or ""
        retrieval_srcs = item.get("retrieval_sources") or []

        if fused is not None:
            score_parts = [f"fused={round(float(fused), 3)}"]
            if vs is not None:
                score_parts.append(f"vec={round(float(vs), 3)}")
            if gs is not None:
                score_parts.append(f"graph={round(float(gs), 3)}")
            if retrieval_srcs:
                score_parts.append(f"via={'|'.join(retrieval_srcs)}")
            score_str = " " + " ".join(score_parts)
        else:
            score = item.get("score")
            score_str = f" score={round(float(score), 3)}" if score is not None else ""

        traversal = item.get("traversal_path")
        if traversal and kind == "graph":
            lines.extend(["", f"[{rank}] {source} ({kind}){score_str}", text])
        else:
            lines.extend(["", f"[{rank}] {source} ({kind}){score_str}", text])

        is_truncated = bool((item.get("metadata") or {}).get("truncated") or len(str(raw_content)) > content_limit)
        sources.append({
            "rank": rank,
            "source": source,
            "type": kind,
            "fused_score": fused,
            "vector_score": vs,
            "graph_score": gs,
            "score": fused or item.get("score"),
            "retrieval_sources": retrieval_srcs,
            "rerank_reason": rerank_r,
            "traversal_path": item.get("traversal_path"),
            "truncated": is_truncated,
            "metadata": item.get("metadata") or {},
        })

    if include_debug and debug:
        lines.extend(["", "--- retrieval debug ---", json.dumps(debug, ensure_ascii=False)])

    return {
        "content": "\n".join(lines).strip(),
        "sources": sources,
        "query": query,
        "result_count": len(results),
        "context_truncated": any_truncated,
        "rag_used": True,
        "gate_reason": debug.get("gate_reason"),
        "fusion_active": bool(fusion_active),
    }


def format_sources_text(output: dict[str, Any], tool: dict[str, Any]) -> dict[str, Any]:
    formatter = tool.get("response_formatter") or (tool.get("execution") or {}).get("response_formatter") or {}
    max_items = int(formatter.get("max_items") or 16)
    results = output.get("results") or []
    grouped: dict[str, dict[str, Any]] = {}
    for item in results:
        source = item.get("source") or item.get("metadata", {}).get("source") or "unknown"
        entry = grouped.setdefault(
            source,
            {
                "source": source,
                "types": set(),
                "count": 0,
                "best_score": item.get("score"),
                "metadata": item.get("metadata") or {},
            },
        )
        entry["count"] += 1
        entry["types"].add(item.get("type") or "context")
        score = item.get("score")
        if score is not None and (entry["best_score"] is None or score > entry["best_score"]):
            entry["best_score"] = score
    sources = []
    lines = [f"RAGHybrid sources for: {output.get('query', '')}", ""]
    for index, entry in enumerate(list(grouped.values())[:max_items], start=1):
        item = {
            "source": entry["source"],
            "types": sorted(entry["types"]),
            "count": entry["count"],
            "best_score": entry["best_score"],
            "metadata": entry["metadata"],
        }
        sources.append(item)
        lines.append(f"[{index}] {item['source']} | chunks: {item['count']} | types: {', '.join(item['types'])}")
    return {
        "content": "\n".join(lines).strip(),
        "sources": sources,
        "query": output.get("query", ""),
        "result_count": len(results),
    }


def format_health_text(output: Any) -> dict[str, Any]:
    if not isinstance(output, dict):
        return {"content": compact_text(output), "raw": output}
    status = output.get("status") or output.get("ok") or "unknown"
    lines = [f"RAGHybrid health: {status}"]
    for key, value in output.items():
        if key == "status":
            continue
        lines.append(f"- {key}: {compact_text(value, 500)}")
    return {"content": "\n".join(lines), "raw": output}


@app.get("/openwebui")
def openwebui_base() -> dict[str, Any]:
    return openapi_tool_spec()


@app.get("/openwebui/openapi.json")
def openwebui_openapi() -> dict[str, Any]:
    return openapi_tool_spec()


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
    """Alias for OpenWebUI tool server — resolves paths relative to /openwebui base."""
    payload = await request.json()
    result = await execute_tool(tool_name, payload,
                                caller_ip=_caller_ip(request),
                                model=_model_from_request(request))
    return JSONResponse(result)


@app.post("/mcp/tools/{tool_name}")
async def rest_tool_mcp_alias(tool_name: str, request: Request) -> JSONResponse:
    """Alias for OpenWebUI tool server registered with /mcp base URL."""
    payload = await request.json()
    result = await execute_tool(tool_name, payload,
                                caller_ip=_caller_ip(request),
                                model=_model_from_request(request))
    return JSONResponse(result)


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


async def execute_tool(tool_name: str, arguments: dict[str, Any], response_profile: str = "rest",
                       caller_ip: str = "", model: str = "") -> dict[str, Any]:
    _t0 = time.monotonic()
    tool = tools.get(tool_name)
    if not tool:
        return {"error": f"unknown tool: {tool_name}"}
    policy_error = _policy_check(tool, arguments or {})
    if policy_error:
        return {"error": policy_error, "policy_blocked": True}
    if tool.get("execution_type") != "http_request":
        return {"error": f"unsupported execution type: {tool.get('execution_type')}"}
    arguments = {**input_defaults(tool.get("input_schema") or {}), **(arguments or {})}
    validate(arguments, tool.get("input_schema") or {})
    execution = tool.get("execution") or {}
    method = str(execution.get("method", "POST")).upper()
    template_values = {**runtime_config, **arguments}
    header_values = {**os.environ, **template_values}
    url = Template(str(execution["url"])).safe_substitute(template_values)
    body_template = execution.get("body", arguments)
    if isinstance(body_template, dict):
        body = substitute_template(body_template, template_values)
    elif isinstance(body_template, str):
        body = json.loads(Template(body_template).safe_substitute(template_values))
    else:
        body = arguments
    headers_template = execution.get("headers") or {}
    headers = {str(k): str(v) for k, v in substitute_template(headers_template, header_values).items()}
    timeout = int(execution.get("timeout_seconds") or policy.get("timeout_seconds") or 30)
    max_response_bytes = int(execution.get("max_response_bytes") or policy.get("max_response_bytes") or 5_242_880)
    async with httpx.AsyncClient(timeout=timeout) as client:
        response = await client.request(method, url, json=body if method in {"POST", "PUT", "PATCH"} else None,
                                         headers=headers or None)
        content = response.content[:max_response_bytes]
        try:
            output = json.loads(content.decode("utf-8")) if content else {}
        except json.JSONDecodeError:
            output = {"text": content.decode("utf-8", errors="replace")}
    response_mode = "json"
    if response_profile == "mcp":
        response_mode = str(execution.get("mcp_response_mode") or tool.get("mcp_response_mode") or "json")
    formatted = output
    if response_mode == "context_text" and isinstance(output, dict):
        formatted = format_context_text(output, tool)
    elif response_mode == "sources_text" and isinstance(output, dict):
        formatted = format_sources_text(output, tool)
    elif response_mode == "health_text":
        formatted = format_health_text(output)
    result = {
        "ok": 200 <= response.status_code < 300,
        "status_code": response.status_code,
        "tool": tool_name,
        "output": formatted,
    }
    _fire_tool_call_log(tool_name, arguments, result, int((time.monotonic() - _t0) * 1000),
                        caller_ip=caller_ip, model=model)
    return result


@app.get("/mcp")
async def mcp_info(request: Request):
    accept = request.headers.get("accept", "")
    if "text/event-stream" in accept:
        return create_sse_response(request)
    return {
        "name": runtime_config.get("name", "mcp-runtime"),
        "transport": "streamable-http",
        "endpoint": "/mcp",
        "sse_endpoint": "/sse",
        "tools": list(tools),
    }


def jsonrpc_result(message_id: Any, result: Any) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message_id, "result": result}


def jsonrpc_error(message_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": message_id, "error": {"code": code, "message": message}}


def mcp_tool_content(result: dict[str, Any]) -> dict[str, Any]:
    if result.get("error"):
        return {"content": [{"type": "text", "text": str(result["error"])}], "isError": True}

    output = result.get("output")
    if isinstance(output, dict) and isinstance(output.get("content"), str):
        text = output["content"]
        structured = {
            key: value
            for key, value in output.items()
            if key not in {"content", "raw"}
        }
    else:
        text = json.dumps(output, ensure_ascii=False)
        structured = output if isinstance(output, dict) else {}

    response: dict[str, Any] = {"content": [{"type": "text", "text": text}]}
    if structured:
        response["structuredContent"] = structured
    if not result.get("ok", False):
        response["isError"] = True
    return response


async def handle_mcp_payload(payload: Any, request: Request | None = None) -> tuple[list[dict[str, Any]], bool]:
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
            name = params.get("name")
            arguments = params.get("arguments") or {}
            result = await execute_tool(name, arguments, response_profile="mcp",
                                        caller_ip=_caller_ip(request) if request else "",
                                        model=_model_from_request(request) if request else "")
            responses.append(jsonrpc_result(message_id, mcp_tool_content(result)))
        elif method == "notifications/initialized":
            continue
        else:
            responses.append(jsonrpc_error(message_id, -32601, f"Method not found: {method}"))
    return responses, isinstance(payload, list)


@app.post("/mcp")
async def mcp(request: Request):
    try:
        payload = await request.json()
    except Exception:
        return JSONResponse(jsonrpc_error(None, -32700, "Parse error"), status_code=400)

    responses, is_batch = await handle_mcp_payload(payload, request)
    if not responses:
        return Response(status_code=202)
    return JSONResponse(responses if is_batch else responses[0])


def sse_event(data: Any, event: str | None = None) -> str:
    lines = []
    if event:
        lines.append(f"event: {event}")
    if not isinstance(data, str):
        data = json.dumps(data, ensure_ascii=False)
    for line in data.splitlines() or [""]:
        lines.append(f"data: {line}")
    return "\n".join(lines) + "\n\n"


def create_sse_response(request: Request) -> StreamingResponse:
    session_id = str(uuid.uuid4())
    queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue()
    sse_sessions[session_id] = queue
    endpoint = f"/messages?session_id={session_id}"

    async def event_stream():
        try:
            yield sse_event(endpoint, event="endpoint")
            while True:
                if await request.is_disconnected():
                    break
                try:
                    message = await asyncio.wait_for(queue.get(), timeout=15)
                    yield sse_event(message, event="message")
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
        finally:
            sse_sessions.pop(session_id, None)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


@app.get("/sse")
async def sse(request: Request):
    return create_sse_response(request)


@app.post("/messages/{session_id}")
async def sse_message(session_id: str, request: Request):
    queue = sse_sessions.get(session_id)
    if queue is None:
        return JSONResponse({"error": "unknown SSE session"}, status_code=404)

    try:
        payload = await request.json()
    except Exception:
        await queue.put(jsonrpc_error(None, -32700, "Parse error"))
        return Response(status_code=202)

    responses, _ = await handle_mcp_payload(payload, request)
    for response in responses:
        await queue.put(response)
    return Response(status_code=202)


@app.post("/messages")
async def sse_message_query(request: Request):
    session_id = request.query_params.get("session_id") or request.query_params.get("sessionId")
    if not session_id:
        return JSONResponse({"error": "missing session_id"}, status_code=400)
    return await sse_message(session_id, request)
