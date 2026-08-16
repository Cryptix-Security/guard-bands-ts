import { createHash, randomBytes } from "node:crypto";

import type {
  CallToolRequestOptions,
  CallToolRequestParams,
  CallToolResult,
} from "@modelcontextprotocol/client";
import type {
  InputRequiredResult,
  CallToolResult as ServerCallToolResult,
  ServerContext,
} from "@modelcontextprotocol/server";

import { canonicalJson } from "./canonical.js";
import type { GuardBandCrypto } from "./crypto.js";
import type { DetachedEnvelope, JsonObject, JsonValue } from "./types.js";

export const MCP_GUARD_BAND_ID = "com.guardbands/guard-band";
export const MCP_GUARD_BAND_VERSION = 1;
export const DEFAULT_MAX_MCP_PAYLOAD_BYTES = 1_000_000;

const CALL_ID_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;

type MaybePromise<T> = Promise<T> | T;
type MCPMeta = Record<string, unknown>;

interface ToolResultShape {
  content: readonly unknown[];
  isError?: boolean | undefined;
  structuredContent?: unknown;
  _meta?: MCPMeta | undefined;
}

export interface MCPToolPolicyOptions {
  guardInputs?: boolean;
  guardOutputs?: boolean;
  wrapTextOutputs?: boolean;
  ttlSeconds?: number;
}

export class MCPToolPolicy {
  readonly guardInputs: boolean;
  readonly guardOutputs: boolean;
  readonly wrapTextOutputs: boolean;
  readonly ttlSeconds?: number;

  constructor(options: MCPToolPolicyOptions = {}) {
    this.guardInputs = options.guardInputs ?? false;
    this.guardOutputs = options.guardOutputs ?? false;
    this.wrapTextOutputs = this.guardOutputs && (options.wrapTextOutputs ?? true);
    if (options.ttlSeconds !== undefined) {
      if (!Number.isSafeInteger(options.ttlSeconds) || options.ttlSeconds < 0) {
        throw new RangeError("ttlSeconds must be a non-negative safe integer");
      }
      this.ttlSeconds = options.ttlSeconds;
    }
  }

  get enabled(): boolean {
    return this.guardInputs || this.guardOutputs;
  }
}

export class GuardBandMCPError extends Error {}

export interface MCPClientLike {
  callTool(
    params: CallToolRequestParams,
    options?: CallToolRequestOptions,
  ): Promise<CallToolResult>;
}

export interface GuardBandMCPClientOptions {
  audience: string;
  policies: Readonly<Record<string, MCPToolPolicy>>;
  signingKeyId?: string;
  issuer?: string;
  authorizer?: (
    name: string,
    arguments_: JsonObject,
    applicationContext: JsonObject,
  ) => MaybePromise<void>;
  maxPayloadBytes?: number;
}

export interface GuardedCallOptions {
  guardContext?: JsonObject;
  meta?: MCPMeta;
  requestOptions?: CallToolRequestOptions;
}

export interface GuardedToolHandlerOptions<TArgs extends Record<string, unknown>> {
  crypto: GuardBandCrypto;
  audience: string;
  policy: MCPToolPolicy;
  contextResolver?: (name: string, arguments_: TArgs, context: ServerContext) => JsonObject;
  signingKeyId?: string;
  issuer?: string;
  maxPayloadBytes?: number;
}

function policyFor(
  policies: Readonly<Record<string, MCPToolPolicy>>,
  toolName: string,
): MCPToolPolicy {
  return policies[toolName] ?? policies["*"] ?? new MCPToolPolicy();
}

function requirePositivePayloadLimit(value: number): number {
  if (!Number.isSafeInteger(value) || value <= 0) {
    throw new RangeError("maxPayloadBytes must be a positive safe integer");
  }
  return value;
}

function asJsonObject(value: unknown, label: string): JsonObject {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new GuardBandMCPError(`${label} must be a JSON object`);
  }
  canonicalJson(value as JsonObject);
  return value as JsonObject;
}

function inputDigest(arguments_: JsonObject): string {
  return createHash("sha256").update(canonicalJson(arguments_), "utf8").digest("hex");
}

function mcpContext(options: {
  audience: string;
  direction: "input" | "output" | "output-text";
  toolName: string;
  callId: string;
  applicationContext: JsonObject;
  arguments_: JsonObject;
  contentIndex?: number;
}): JsonObject {
  const context: JsonObject = {
    application: options.applicationContext,
    audience: options.audience,
    call_id: options.callId,
    direction: options.direction,
    input_sha256: inputDigest(options.arguments_),
    integration: "mcp",
    method: "tools/call",
    tool: options.toolName,
  };
  if (options.contentIndex !== undefined) context.content_index = options.contentIndex;
  return context;
}

function payloadSize(value: JsonValue): number {
  return Buffer.byteLength(canonicalJson(value), "utf8");
}

function jsonValue(value: unknown, label: string): JsonValue {
  try {
    canonicalJson(value as JsonValue);
    return value as JsonValue;
  } catch (error) {
    throw new GuardBandMCPError(
      `${label} is not RFC 8785 JSON: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

function normalizeAnnotations(value: unknown): JsonValue {
  if (value === undefined || value === null) return null;
  const annotation = asJsonObject(value, "MCP annotations");
  return {
    audience: annotation.audience ?? null,
    priority: annotation.priority ?? null,
    lastModified: annotation.lastModified ?? null,
  };
}

function normalizeIcon(value: unknown): JsonObject {
  const icon = asJsonObject(value, "MCP icon");
  return {
    src: jsonValue(icon.src, "MCP icon src"),
    mimeType: icon.mimeType ?? null,
    sizes: icon.sizes ?? null,
    theme: icon.theme ?? null,
  };
}

function normalizeContentBlock(value: unknown): JsonObject {
  const block = asJsonObject(value, "MCP content block");
  const type = block.type;
  if (typeof type !== "string") throw new GuardBandMCPError("MCP content block type is required");
  if (type === "text") {
    return {
      type,
      text: jsonValue(block.text, "MCP text content"),
      annotations: normalizeAnnotations(block.annotations),
      _meta: block._meta ?? null,
    };
  }
  if (type === "image" || type === "audio") {
    return {
      type,
      data: jsonValue(block.data, "MCP binary content"),
      mimeType: jsonValue(block.mimeType, "MCP media type"),
      annotations: normalizeAnnotations(block.annotations),
      _meta: block._meta ?? null,
    };
  }
  if (type === "resource_link") {
    const icons = block.icons;
    return {
      name: jsonValue(block.name, "MCP resource name"),
      title: block.title ?? null,
      uri: jsonValue(block.uri, "MCP resource URI"),
      description: block.description ?? null,
      mimeType: block.mimeType ?? null,
      size: block.size ?? null,
      icons: icons === undefined || icons === null ? null : (icons as unknown[]).map(normalizeIcon),
      annotations: normalizeAnnotations(block.annotations),
      _meta: block._meta ?? null,
      type,
    };
  }
  if (type === "resource") {
    const resource = asJsonObject(block.resource, "MCP embedded resource");
    const normalizedResource: JsonObject = {
      uri: jsonValue(resource.uri, "MCP embedded resource URI"),
      mimeType: resource.mimeType ?? null,
      _meta: resource._meta ?? null,
    };
    if (Object.hasOwn(resource, "text"))
      normalizedResource.text = jsonValue(resource.text, "MCP resource text");
    if (Object.hasOwn(resource, "blob"))
      normalizedResource.blob = jsonValue(resource.blob, "MCP resource blob");
    return {
      type,
      resource: normalizedResource,
      annotations: normalizeAnnotations(block.annotations),
      _meta: block._meta ?? null,
    };
  }
  if (type === "tool_use") {
    return {
      type,
      name: jsonValue(block.name, "MCP nested tool name"),
      id: jsonValue(block.id, "MCP nested tool id"),
      input: jsonValue(block.input, "MCP nested tool input"),
      _meta: block._meta ?? null,
    };
  }
  if (type === "tool_result") {
    const content = block.content ?? [];
    if (!Array.isArray(content))
      throw new GuardBandMCPError("MCP nested tool content must be an array");
    return {
      type,
      toolUseId: jsonValue(block.toolUseId, "MCP nested tool-use id"),
      content: content.map(normalizeContentBlock),
      structuredContent: block.structuredContent ?? null,
      isError: block.isError ?? null,
      _meta: block._meta ?? null,
    };
  }
  throw new GuardBandMCPError(`Unsupported MCP content block type: ${type}`);
}

export function mcpResultPayload(result: ToolResultShape): JsonObject {
  return {
    content: result.content.map(normalizeContentBlock),
    is_error: result.isError ?? false,
    structured_content:
      result.structuredContent === undefined
        ? null
        : jsonValue(result.structuredContent, "MCP structured content"),
  };
}

function isFinalToolResult(
  result: ServerCallToolResult | InputRequiredResult,
): result is ServerCallToolResult {
  return Array.isArray((result as { content?: unknown }).content);
}

function guardMeta(meta: MCPMeta | undefined): MCPMeta | undefined {
  const value = meta?.[MCP_GUARD_BAND_ID];
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as MCPMeta)
    : undefined;
}

function callId(meta: MCPMeta | undefined): string | undefined {
  const guard = guardMeta(meta);
  if (guard?.version !== MCP_GUARD_BAND_VERSION) return undefined;
  const value = guard.call_id;
  return typeof value === "string" && CALL_ID_PATTERN.test(value) ? value : undefined;
}

function signOptions(keyId: string | undefined, issuer: string, ttlSeconds: number | undefined) {
  return {
    ...(keyId === undefined ? {} : { keyId }),
    issuer,
    ...(ttlSeconds === undefined ? {} : { ttlSeconds }),
  };
}

function wrapTextBlocks(
  result: ServerCallToolResult,
  crypto: GuardBandCrypto,
  policy: MCPToolPolicy,
  options: {
    audience: string;
    toolName: string;
    callId: string;
    applicationContext: JsonObject;
    arguments_: JsonObject;
    signingKeyId?: string;
    issuer: string;
  },
): ServerCallToolResult {
  const content = result.content.map((block, index) => {
    if (block.type !== "text") return block;
    if (block.text.includes("⟪INERT:START") || block.text.includes("⟪INERT:END")) {
      throw new GuardBandMCPError("Tool output contains reserved Guard Band markers");
    }
    const text = crypto.wrapContent(
      block.text,
      mcpContext({
        audience: options.audience,
        direction: "output-text",
        toolName: options.toolName,
        callId: options.callId,
        applicationContext: options.applicationContext,
        arguments_: options.arguments_,
        contentIndex: index,
      }),
      signOptions(options.signingKeyId, options.issuer, policy.ttlSeconds),
    );
    return { ...block, text };
  });
  return { ...result, content };
}

export function guardToolHandler<TArgs extends Record<string, unknown>>(
  name: string,
  handler: (
    arguments_: TArgs,
    context: ServerContext,
  ) => MaybePromise<ServerCallToolResult | InputRequiredResult>,
  options: GuardedToolHandlerOptions<TArgs>,
): (
  arguments_: TArgs,
  context: ServerContext,
) => Promise<ServerCallToolResult | InputRequiredResult> {
  if (options.audience.length === 0) throw new RangeError("audience is required");
  const maxPayloadBytes = requirePositivePayloadLimit(
    options.maxPayloadBytes ?? DEFAULT_MAX_MCP_PAYLOAD_BYTES,
  );
  const issuer = options.issuer ?? "mcp-server";

  return async (arguments_, context) => {
    if (!options.policy.enabled) return handler(arguments_, context);
    const jsonArguments = asJsonObject(arguments_, "MCP tool arguments");
    if (payloadSize(jsonArguments) > maxPayloadBytes) {
      throw new GuardBandMCPError("Guarded MCP payload is too large");
    }
    const requestMeta = context.mcpReq._meta as MCPMeta | undefined;
    const logicalCallId = callId(requestMeta);
    if (logicalCallId === undefined) {
      throw new GuardBandMCPError("Valid Guard Band call metadata is required");
    }
    const applicationContext =
      options.contextResolver?.(name, arguments_, context) ?? ({} satisfies JsonObject);
    canonicalJson(applicationContext);

    if (options.policy.guardInputs) {
      const envelope = guardMeta(requestMeta)?.input;
      const verification = options.crypto.verifyValue(
        jsonArguments,
        envelope,
        mcpContext({
          audience: options.audience,
          direction: "input",
          toolName: name,
          callId: logicalCallId,
          applicationContext,
          arguments_: jsonArguments,
        }),
      );
      if (!verification.valid) throw new GuardBandMCPError("Guard Band input verification failed");
    }

    const handlerResult = await handler(arguments_, context);
    if (!options.policy.guardOutputs || !isFinalToolResult(handlerResult)) return handlerResult;
    let result = handlerResult;
    if (payloadSize(mcpResultPayload(result)) > maxPayloadBytes) {
      throw new GuardBandMCPError("Guarded MCP result is too large");
    }
    if (options.policy.wrapTextOutputs) {
      result = wrapTextBlocks(result, options.crypto, options.policy, {
        audience: options.audience,
        toolName: name,
        callId: logicalCallId,
        applicationContext,
        arguments_: jsonArguments,
        ...(options.signingKeyId === undefined ? {} : { signingKeyId: options.signingKeyId }),
        issuer,
      });
    }
    const payload = mcpResultPayload(result);
    if (payloadSize(payload) > maxPayloadBytes) {
      throw new GuardBandMCPError("Guarded MCP result is too large");
    }
    const envelope = options.crypto.signValue(
      payload,
      mcpContext({
        audience: options.audience,
        direction: "output",
        toolName: name,
        callId: logicalCallId,
        applicationContext,
        arguments_: jsonArguments,
      }),
      signOptions(options.signingKeyId, issuer, options.policy.ttlSeconds),
    );
    const meta: MCPMeta = { ...(result._meta ?? {}) };
    meta[MCP_GUARD_BAND_ID] = {
      version: MCP_GUARD_BAND_VERSION,
      call_id: logicalCallId,
      output: envelope,
    };
    return { ...result, _meta: meta };
  };
}

export class GuardBandMCPClient {
  readonly #client: MCPClientLike;
  readonly #crypto: GuardBandCrypto;
  readonly #options: GuardBandMCPClientOptions;
  readonly #maxPayloadBytes: number;

  constructor(client: MCPClientLike, crypto: GuardBandCrypto, options: GuardBandMCPClientOptions) {
    if (options.audience.length === 0) throw new RangeError("audience is required");
    this.#client = client;
    this.#crypto = crypto;
    this.#options = options;
    this.#maxPayloadBytes = requirePositivePayloadLimit(
      options.maxPayloadBytes ?? DEFAULT_MAX_MCP_PAYLOAD_BYTES,
    );
  }

  async callTool(
    name: string,
    arguments_: JsonObject = {},
    options: GuardedCallOptions = {},
  ): Promise<CallToolResult> {
    const policy = policyFor(this.#options.policies, name);
    if (!policy.enabled) {
      const params: CallToolRequestParams = {
        name,
        arguments: arguments_,
        ...(options.meta === undefined ? {} : { _meta: options.meta }),
      };
      return this.#client.callTool(params, options.requestOptions);
    }
    canonicalJson(arguments_);
    const applicationContext = options.guardContext ?? {};
    canonicalJson(applicationContext);
    if (payloadSize(arguments_) > this.#maxPayloadBytes) {
      throw new GuardBandMCPError("Guarded MCP payload is too large");
    }
    await this.#options.authorizer?.(name, arguments_, applicationContext);
    const meta: MCPMeta = { ...(options.meta ?? {}) };
    if (Object.hasOwn(meta, MCP_GUARD_BAND_ID)) {
      throw new GuardBandMCPError(`${MCP_GUARD_BAND_ID} metadata is reserved`);
    }
    const logicalCallId = randomBytes(16).toString("base64url");
    const guard: MCPMeta = { version: MCP_GUARD_BAND_VERSION, call_id: logicalCallId };
    if (policy.guardInputs) {
      guard.input = this.#crypto.signValue(
        arguments_,
        mcpContext({
          audience: this.#options.audience,
          direction: "input",
          toolName: name,
          callId: logicalCallId,
          applicationContext,
          arguments_,
        }),
        signOptions(
          this.#options.signingKeyId,
          this.#options.issuer ?? "mcp-client",
          policy.ttlSeconds,
        ),
      );
    }
    meta[MCP_GUARD_BAND_ID] = guard;
    const result = await this.#client.callTool(
      { name, arguments: arguments_, _meta: meta },
      options.requestOptions,
    );
    if (policy.guardOutputs) {
      this.#verifyResult(result, policy, name, logicalCallId, applicationContext, arguments_);
    }
    return result;
  }

  #verifyResult(
    result: CallToolResult,
    policy: MCPToolPolicy,
    toolName: string,
    logicalCallId: string,
    applicationContext: JsonObject,
    arguments_: JsonObject,
  ): void {
    const payload = mcpResultPayload(result);
    if (payloadSize(payload) > this.#maxPayloadBytes) {
      throw new GuardBandMCPError("Guarded MCP result is too large");
    }
    const guard = guardMeta(result._meta as MCPMeta | undefined);
    if (
      guard === undefined ||
      guard.version !== MCP_GUARD_BAND_VERSION ||
      guard.call_id !== logicalCallId
    ) {
      throw new GuardBandMCPError("Valid Guard Band result metadata is required");
    }
    const verification = this.#crypto.verifyValue(
      payload,
      guard.output as DetachedEnvelope,
      mcpContext({
        audience: this.#options.audience,
        direction: "output",
        toolName,
        callId: logicalCallId,
        applicationContext,
        arguments_,
      }),
    );
    if (!verification.valid) throw new GuardBandMCPError("Guard Band output verification failed");
    if (!policy.wrapTextOutputs) return;
    result.content.forEach((block, index) => {
      if (block.type !== "text") return;
      const textVerification = this.#crypto.extractAndVerify(
        block.text,
        mcpContext({
          audience: this.#options.audience,
          direction: "output-text",
          toolName,
          callId: logicalCallId,
          applicationContext,
          arguments_,
          contentIndex: index,
        }),
      );
      if (!textVerification.valid) {
        throw new GuardBandMCPError("Guard Band text output verification failed");
      }
    });
  }
}

export function guardBandsClientCapability(): Record<string, JsonValue> {
  return { [MCP_GUARD_BAND_ID]: { envelopeVersion: MCP_GUARD_BAND_VERSION } };
}
