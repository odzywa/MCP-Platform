# Continue + RAGHybrid MCP

This guide describes the intended Continue setup for the `RAGHybrid Assistant` runtime.

## Continue config

Use the SSE endpoint exposed by MCP Platform:

```yaml
name: RAGHybrid MCP Platform
version: 0.0.1
schema: v1
mcpServers:
  - name: RAGHybrid
    type: sse
    url: http://mcp.dom:19041/sse
```

After changing runtime tools, reload Continue or restart VS Code. Continue can cache the MCP tool list.

## Tool contract

Continue should see four MCP tools:

```text
hybridrag_context
hybridrag_search
hybridrag_sources
hybridrag_health
```

Use them this way:

- `hybridrag_context` is the default coding tool. Use it before answering questions about this platform, architecture, local conventions, runtime behavior, or implementation history.
- `hybridrag_sources` is for checking which documents or chunks support an answer.
- `hybridrag_health` is for quick diagnosis when retrieval seems broken.
- `hybridrag_search` returns raw JSON. Prefer it only for debugging or when full metadata is needed.

OpenWebUI intentionally sees only `/tools/hybridrag_search` in `/openwebui/openapi.json`. Do not expose the Continue-only tools to OpenWebUI unless its integration expects MCP-style text responses.

## Recommended model behavior

For smaller coding models such as `coder30b`, use explicit instructions in Continue:

```text
When working in this repository, use the RAGHybrid MCP tools when you need project context.
Prefer hybridrag_context for normal coding questions.
Use hybridrag_sources when you need to verify source documents.
Use hybridrag_search only when raw JSON or debugging metadata is needed.
Do not invent platform behavior if RAGHybrid context is missing; say what is unknown and ask for more context.
```

This matters because smaller/local models often do not infer tool intent from names alone. Clear tool descriptions plus the instruction above make tool use much more reliable.

## Quick verification

List MCP tools:

```bash
curl -sS -X POST http://127.0.0.1:19041/mcp \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}'
```

Call the Continue-oriented context tool:

```bash
curl -sS -X POST http://127.0.0.1:19041/mcp \
  -H 'Content-Type: application/json' \
  --data '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"hybridrag_context","arguments":{"query":"co to jest MCP Platform?","top_k":3}}}'
```

Check the OpenWebUI surface:

```bash
curl -sS http://127.0.0.1:19041/openwebui/openapi.json
```

Expected result:

- MCP `tools/list` returns four `hybridrag_*` tools.
- `hybridrag_context` returns plain text in MCP `content`.
- OpenWebUI OpenAPI exposes only `/tools/hybridrag_search`.

