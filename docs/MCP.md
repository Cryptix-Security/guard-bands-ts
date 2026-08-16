# MCP Integration

The `@guardbands/core/mcp` entry point protects complete MCP `tools/call`
arguments and results without changing application JSON schemas:

- the client writes a detached input envelope to
  `_meta["com.guardbands/guard-band"]`;
- the server wrapper verifies that envelope before invoking the tool;
- the server signs the complete `CallToolResult` and optionally wraps every
  text block in a visible Guard Band; and
- the client verifies the complete result and every visible text band before
  returning it to the host.

The signed context binds the audience, tool name, call id, direction,
application context, and a SHA-256 digest of the original arguments. A result
from one call therefore cannot be transplanted into another.

## Server handler

Wrap the callback passed to the official MCP 2.x server SDK:

```ts
import { McpServer } from "@modelcontextprotocol/server";
import { z } from "zod";

import { GuardBandCrypto } from "@guardbands/core";
import { MCPToolPolicy, guardToolHandler } from "@guardbands/core/mcp";

const crypto = new GuardBandCrypto(Buffer.from(process.env.GUARD_BAND_KEY!, "base64"));
const server = new McpServer({ name: "example", version: "1.0.0" });

server.registerTool(
  "summarize",
  { inputSchema: z.object({ text: z.string() }) },
  guardToolHandler(
    "summarize",
    async ({ text }) => ({ content: [{ type: "text", text: `Summary: ${text}` }] }),
    {
      crypto,
      audience: "example-host",
      policy: new MCPToolPolicy({ guardInputs: true, guardOutputs: true }),
      contextResolver: (_name, _arguments, context) => ({
        session_id: context.sessionId ?? "local",
      }),
      issuer: "example-server",
    },
  ),
);
```

The context resolver must derive security-relevant values from authenticated
server state, not from tool arguments supplied by the model.

## Client

```ts
import { Client } from "@modelcontextprotocol/client";

import { GuardBandCrypto } from "@guardbands/core";
import { GuardBandMCPClient, MCPToolPolicy } from "@guardbands/core/mcp";

const rawClient = new Client({ name: "host", version: "1.0.0" });
const guarded = new GuardBandMCPClient(rawClient, crypto, {
  audience: "example-host",
  policies: {
    summarize: new MCPToolPolicy({ guardInputs: true, guardOutputs: true }),
  },
  issuer: "example-client",
});

const result = await guarded.callTool(
  "summarize",
  { text: "untrusted document" },
  { guardContext: { session_id: "session-123" } },
);
```

## Lifecycle boundary

The adapter signs a complete `CallToolResult`. Streamable HTTP framing does not
change that boundary, and progress notifications report status rather than
partial result content. Multi-round-trip `input_required` results are returned
without output signing; the retried call's eventual complete result is signed.

Do not apply a mandatory guarded-output policy to a tool that returns only a
Task handle. Sign and verify the later application-level payload after task
resolution, or wait for a standardized task-result integration. Incremental
chunk signing is not implemented.
