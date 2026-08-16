import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";
import type { DetachedEnvelope, GuardBandKey, JsonObject, JsonValue } from "../src/index.js";
import {
  canonicalJson,
  extractGuardBandBlocks,
  GuardBandCrypto,
  loadEd25519PrivateKey,
  loadEd25519PublicKey,
  StaticKeyResolver,
} from "../src/index.js";
import { mcpResultPayload } from "../src/mcp.js";

interface CanonicalVector {
  id: string;
  input_json: string;
  canonical_json: string;
}

interface SignatureVector {
  id: string;
  mode: "detached-json" | "inline";
  version: "1" | "2";
  key_id: string;
  issuer: string;
  nonce: string;
  issued_at: number;
  expires_at: number;
  content?: string;
  value?: JsonValue;
  context: JsonObject;
  artifact: DetachedEnvelope | string;
}

interface NegativeVector {
  id: string;
  mode: "detached-json" | "inline";
  key_id: string;
  context: JsonObject;
  value?: JsonValue;
  artifact: DetachedEnvelope | string;
  valid: false;
}

interface MCPVector {
  id: string;
  audience: string;
  tool: string;
  call_id: string;
  arguments: JsonObject;
  application_context: JsonObject;
  input_envelope: DetachedEnvelope;
  result_payload: {
    content: JsonObject[];
    is_error: boolean;
    structured_content: JsonValue;
  };
  output_envelope: DetachedEnvelope;
}

interface ConformanceVectors {
  test_keys: {
    "test-hmac-01": { secret_hex: string };
    "test-ed25519-01": { private_seed_hex: string; public_key_base64url: string };
  };
  canonicalization: CanonicalVector[];
  signatures: SignatureVector[];
  mcp: MCPVector[];
  negative_cases: NegativeVector[];
}

class FixedNonceCrypto extends GuardBandCrypto {
  override generateNonce(): string {
    return "AAAAAAAAAAAAAAAA";
  }
}

const vectors = JSON.parse(
  readFileSync(new URL("../conformance/vectors.json", import.meta.url), "utf8"),
) as ConformanceVectors;
const hmacKey = Buffer.from(vectors.test_keys["test-hmac-01"].secret_hex, "hex");
const privateSeed = Buffer.from(
  vectors.test_keys["test-ed25519-01"].private_seed_hex,
  "hex",
).toString("base64url");
const privateKey = loadEd25519PrivateKey(privateSeed);
const publicKey = loadEd25519PublicKey(vectors.test_keys["test-ed25519-01"].public_key_base64url);

function verificationCrypto(): GuardBandCrypto {
  return new GuardBandCrypto({
    keyResolver: new StaticKeyResolver(
      { "test-hmac-01": hmacKey, "test-ed25519-01": publicKey },
      "test-hmac-01",
    ),
  });
}

function signingKey(vector: SignatureVector): GuardBandKey {
  return vector.key_id === "test-hmac-01" ? hmacKey : privateKey;
}

function mcpContext(
  vector: MCPVector,
  direction: "input" | "output" | "output-text",
  contentIndex?: number,
): JsonObject {
  const context: JsonObject = {
    application: vector.application_context,
    audience: vector.audience,
    call_id: vector.call_id,
    direction,
    input_sha256: createHash("sha256")
      .update(canonicalJson(vector.arguments), "utf8")
      .digest("hex"),
    integration: "mcp",
    method: "tools/call",
    tool: vector.tool,
  };
  if (contentIndex !== undefined) context.content_index = contentIndex;
  return context;
}

describe("RFC 8785 canonicalization", () => {
  for (const vector of vectors.canonicalization) {
    it(vector.id, () => {
      expect(canonicalJson(JSON.parse(vector.input_json) as JsonValue)).toBe(vector.canonical_json);
    });
  }

  it.each([Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY])(
    "rejects out-of-domain number %s",
    (value) => {
      expect(() => canonicalJson(value)).toThrow();
    },
  );

  it("rejects lone Unicode surrogates", () => {
    expect(() => canonicalJson("\ud800")).toThrow(/surrogate/);
  });
});

describe("cross-language signature vectors", () => {
  for (const vector of vectors.signatures) {
    it(`verifies ${vector.id}`, () => {
      const crypto = verificationCrypto();
      const result =
        vector.mode === "inline"
          ? crypto.extractAndVerify(vector.artifact as string, vector.context, vector.issued_at)
          : crypto.verifyValue(
              vector.value as JsonValue,
              vector.artifact,
              vector.context,
              vector.issued_at,
            );
      expect(result.valid).toBe(true);
    });

    if (vector.version === "2") {
      it(`reproduces ${vector.id}`, () => {
        const key = signingKey(vector);
        const crypto = new FixedNonceCrypto({
          keyResolver: new StaticKeyResolver({ [vector.key_id]: key }, vector.key_id),
        });
        const options = {
          issuer: vector.issuer,
          ttlSeconds: vector.expires_at - vector.issued_at,
          now: vector.issued_at,
        };
        const artifact =
          vector.mode === "inline"
            ? crypto.wrapContent(vector.content ?? "", vector.context, options)
            : crypto.signValue(vector.value as JsonValue, vector.context, options);
        expect(artifact).toEqual(vector.artifact);
      });
    }
  }

  for (const vector of vectors.negative_cases) {
    it(`rejects ${vector.id}`, () => {
      const crypto = verificationCrypto();
      const result =
        vector.mode === "inline"
          ? crypto.extractAndVerify(vector.artifact as string, vector.context, 1_700_000_000)
          : crypto.verifyValue(
              vector.value as JsonValue,
              vector.artifact,
              vector.context,
              1_700_000_000,
            );
      expect(result.valid).toBe(vector.valid);
    });
  }
});

describe("marker hardening", () => {
  it("rejects reserved markers before signing", () => {
    const crypto = new GuardBandCrypto(hmacKey);
    expect(() => crypto.wrapContent("bad ⟪INERT:END marker", {})).toThrow(/reserved/);
  });

  it("extracts only complete syntactically valid bands", () => {
    const crypto = new FixedNonceCrypto(hmacKey);
    const wrapped = crypto.wrapContent("safe", {}, { now: 1_700_000_000 });
    expect(extractGuardBandBlocks(`prefix ${wrapped} suffix`)).toEqual([wrapped]);
  });

  it("refuses to create an unverifiable timestamp range", () => {
    const crypto = new GuardBandCrypto(hmacKey);
    expect(() =>
      crypto.wrapContent("safe", {}, { now: Number.MAX_SAFE_INTEGER, ttlSeconds: 1 }),
    ).toThrow(/expiry/);
  });
});

describe("cross-language MCP exchange", () => {
  it("verifies signed arguments, normalized result, and visible text", () => {
    const vector = vectors.mcp[0];
    if (vector === undefined) throw new Error("Missing MCP vector");
    const crypto = verificationCrypto();

    expect(
      crypto.verifyValue(
        vector.arguments,
        vector.input_envelope,
        mcpContext(vector, "input"),
        1_700_000_000,
      ).valid,
    ).toBe(true);
    expect(
      crypto.verifyValue(
        vector.result_payload,
        vector.output_envelope,
        mcpContext(vector, "output"),
        1_700_000_000,
      ).valid,
    ).toBe(true);
    const firstBlock = vector.result_payload.content[0];
    expect(firstBlock).toBeDefined();
    expect(
      crypto.extractAndVerify(
        firstBlock?.text as string,
        mcpContext(vector, "output-text", 0),
        1_700_000_000,
      ).valid,
    ).toBe(true);
    expect(
      mcpResultPayload({
        content: vector.result_payload.content,
        isError: vector.result_payload.is_error,
        structuredContent: vector.result_payload.structured_content,
      }),
    ).toEqual(vector.result_payload);
  });
});
