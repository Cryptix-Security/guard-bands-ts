import type {
  CallToolRequestOptions,
  CallToolRequestParams,
  CallToolResult,
} from "@modelcontextprotocol/client";
import type {
  CallToolResult as ServerCallToolResult,
  ServerContext,
} from "@modelcontextprotocol/server";
import { describe, expect, it } from "vitest";
import type { JsonObject } from "../src/index.js";
import { GuardBandCrypto } from "../src/index.js";
import {
  GuardBandMCPClient,
  GuardBandMCPError,
  guardToolHandler,
  MCP_GUARD_BAND_ID,
  MCPToolPolicy,
  mcpResultPayload,
} from "../src/mcp.js";

const key = Buffer.from("shared MCP test secret");
const crypto = new GuardBandCrypto(key);
const policy = new MCPToolPolicy({ guardInputs: true, guardOutputs: true });

type ToolArguments = { text: string };

function serverContext(meta: CallToolRequestParams["_meta"]): ServerContext {
  return { mcpReq: { _meta: meta } } as unknown as ServerContext;
}

class LoopbackClient {
  tamperInput = false;
  tamperOutput = false;

  readonly handler = guardToolHandler<ToolArguments>(
    "echo",
    async (arguments_) => ({
      content: [{ type: "text", text: arguments_.text }],
      structuredContent: { echo: arguments_.text },
    }),
    {
      crypto,
      audience: "test-suite",
      policy,
      contextResolver: () => ({ tenant: "a" }),
      issuer: "test-server",
    },
  );

  async callTool(
    params: CallToolRequestParams,
    _options?: CallToolRequestOptions,
  ): Promise<CallToolResult> {
    const arguments_ = { ...(params.arguments as ToolArguments) };
    if (this.tamperInput) arguments_.text = "tampered input";
    const result = await this.handler(arguments_, serverContext(params._meta));
    if (!Array.isArray((result as { content?: unknown }).content)) {
      throw new Error("Unexpected input-required result");
    }
    const finalResult = result as ServerCallToolResult;
    if (this.tamperOutput && finalResult.content[0]?.type === "text") {
      finalResult.content[0] = { ...finalResult.content[0], text: "tampered output" };
    }
    return finalResult as unknown as CallToolResult;
  }
}

function guardedClient(loopback: LoopbackClient): GuardBandMCPClient {
  return new GuardBandMCPClient(loopback, crypto, {
    audience: "test-suite",
    policies: { echo: policy },
    issuer: "test-client",
  });
}

describe("MCP tools/call integration", () => {
  it("signs arguments and verifies complete results and visible text", async () => {
    const result = await guardedClient(new LoopbackClient()).callTool(
      "echo",
      { text: "untrusted document" },
      { guardContext: { tenant: "a" } },
    );

    expect(result.structuredContent).toEqual({ echo: "untrusted document" });
    expect(result.content[0]?.type).toBe("text");
    if (result.content[0]?.type === "text") {
      expect(result.content[0].text).toContain("⟪INERT:START:v:2:");
      expect(result.content[0].text).toContain("untrusted document");
    }
    expect(result._meta).toHaveProperty(MCP_GUARD_BAND_ID);
  });

  it("rejects argument tampering between client and server", async () => {
    const loopback = new LoopbackClient();
    loopback.tamperInput = true;
    await expect(
      guardedClient(loopback).callTool(
        "echo",
        { text: "original" },
        { guardContext: { tenant: "a" } },
      ),
    ).rejects.toThrow(/input verification failed/);
  });

  it("rejects result tampering between server and client", async () => {
    const loopback = new LoopbackClient();
    loopback.tamperOutput = true;
    await expect(
      guardedClient(loopback).callTool(
        "echo",
        { text: "original" },
        { guardContext: { tenant: "a" } },
      ),
    ).rejects.toThrow(/output verification failed/);
  });

  it("rejects caller-supplied reserved metadata", async () => {
    await expect(
      guardedClient(new LoopbackClient()).callTool(
        "echo",
        { text: "x" },
        {
          guardContext: { tenant: "a" },
          meta: { [MCP_GUARD_BAND_ID]: {} },
        },
      ),
    ).rejects.toThrow(GuardBandMCPError);
  });

  it("normalizes result payloads exactly like the Python integration", () => {
    const payload = mcpResultPayload({ content: [{ type: "text", text: "x" }] });
    expect(payload).toEqual({
      content: [{ type: "text", text: "x", annotations: null, _meta: null }],
      is_error: false,
      structured_content: null,
    });
  });

  it("requires application context to agree on both sides", async () => {
    await expect(
      guardedClient(new LoopbackClient()).callTool(
        "echo",
        { text: "x" },
        { guardContext: { tenant: "b" } },
      ),
    ).rejects.toThrow(/input verification failed/);
  });

  it("passes disabled policies through unchanged", async () => {
    const calls: JsonObject[] = [];
    const rawClient = {
      async callTool(params: CallToolRequestParams): Promise<CallToolResult> {
        calls.push(params.arguments as JsonObject);
        return { content: [{ type: "text", text: "raw" }] };
      },
    };
    const client = new GuardBandMCPClient(rawClient, crypto, {
      audience: "test-suite",
      policies: {},
    });
    const result = await client.callTool("public", { value: 1 });

    expect(calls).toEqual([{ value: 1 }]);
    expect(result.content).toEqual([{ type: "text", text: "raw" }]);
  });
});
