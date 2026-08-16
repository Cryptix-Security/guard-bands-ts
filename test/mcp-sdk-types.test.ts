import { McpServer } from "@modelcontextprotocol/server";
import { describe, expect, it } from "vitest";
import { z } from "zod";

import { GuardBandCrypto } from "../src/index.js";
import { guardToolHandler, MCPToolPolicy } from "../src/mcp.js";

describe("official MCP SDK type integration", () => {
  it("registers a guarded handler without adapters or casts", () => {
    const server = new McpServer({ name: "type-test", version: "1.0.0" });
    const crypto = new GuardBandCrypto(Buffer.from("type-test-secret"));

    const registration = server.registerTool(
      "echo",
      { inputSchema: z.object({ text: z.string() }) },
      guardToolHandler("echo", async ({ text }) => ({ content: [{ type: "text", text }] }), {
        crypto,
        audience: "type-test",
        policy: new MCPToolPolicy({ guardInputs: true, guardOutputs: true }),
        contextResolver: () => ({ tenant: "a" }),
      }),
    );

    expect(registration).toBeDefined();
  });
});
