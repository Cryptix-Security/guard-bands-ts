import {
  createHmac,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  KeyObject,
  randomBytes,
  sign as signEd25519,
  timingSafeEqual,
  verify as verifyEd25519,
} from "node:crypto";
import { TextDecoder } from "node:util";

import { canonicalJson, canonicalJsonForVersion } from "./canonical.js";
import type {
  DetachedEnvelope,
  GuardBandAlgorithm,
  GuardBandCryptoOptions,
  GuardBandKey,
  InlineVerificationResult,
  JsonObject,
  JsonValue,
  KeyResolver,
  ProtocolVersion,
  SignOptions,
  ValueVerificationResult,
  WrappedMetadata,
} from "./types.js";

export const CURRENT_PROTOCOL_VERSION = "2" as const;
export const SUPPORTED_PROTOCOL_VERSIONS = ["1", "2"] as const;
export const LEGACY_MAC_ALG = "GBv1-HMAC-SHA256" as const;
export const LEGACY_ED25519_ALG = "GBv1-Ed25519" as const;
export const MAC_ALG = "GBv2-HMAC-SHA256" as const;
export const ED25519_ALG = "GBv2-Ed25519" as const;

const DEFAULT_TTL_SECONDS = 900;
const DEFAULT_ISSUER = "anonymous";
const STRUCTURED_VALUE_KIND = "json";
const START_PREFIX = "⟪INERT:START:";
const END_PREFIX = "⟪INERT:END:";
const RESERVED_START_MARKER = "⟪INERT:START";
const RESERVED_END_MARKER = "⟪INERT:END";
const KEY_ID_PATTERN = /^[A-Za-z0-9_.-]{1,64}$/;
const NONCE_PATTERN = /^[A-Za-z0-9_-]{16,128}$/;
const ISSUER_PATTERN = /^[A-Za-z0-9_-]{1,344}$/;
const INT_PATTERN = /^[0-9]{1,19}$/;
const BASE64_PATTERN = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;

const ALGORITHMS: Record<
  ProtocolVersion,
  { hmac: GuardBandAlgorithm; ed25519: GuardBandAlgorithm }
> = {
  "1": { hmac: LEGACY_MAC_ALG, ed25519: LEGACY_ED25519_ALG },
  "2": { hmac: MAC_ALG, ed25519: ED25519_ALG },
};

interface ParsedBand {
  content: string;
  version: ProtocolVersion;
  nonce: string;
  issuedAt: number;
  expiresAt: number;
  keyId: string;
  issuer: string;
  signature: string;
}

function isProtocolVersion(value: unknown): value is ProtocolVersion {
  return value === "1" || value === "2";
}

function asBuffer(value: Uint8Array): Buffer {
  return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
}

function isEd25519Key(key: GuardBandKey): key is KeyObject {
  return key instanceof KeyObject;
}

function assertEd25519Key(key: KeyObject): void {
  if (key.asymmetricKeyType !== "ed25519") {
    throw new TypeError(`Unsupported asymmetric key type: ${String(key.asymmetricKeyType)}`);
  }
}

export function keyAlgorithm(
  key: GuardBandKey,
  version: ProtocolVersion = CURRENT_PROTOCOL_VERSION,
): GuardBandAlgorithm {
  if (isEd25519Key(key)) {
    assertEd25519Key(key);
    return ALGORITHMS[version].ed25519;
  }
  if (key instanceof Uint8Array) return ALGORITHMS[version].hmac;
  throw new TypeError("Unsupported key type");
}

function encodeIssuer(issuer: string): string {
  return Buffer.from(issuer, "utf8").toString("base64url");
}

function decodeIssuer(encoded: string): string | undefined {
  try {
    return new TextDecoder("utf-8", { fatal: true }).decode(Buffer.from(encoded, "base64url"));
  } catch {
    return undefined;
  }
}

function decodeBase64(value: string, expectedLength?: number): Buffer | undefined {
  if (!BASE64_PATTERN.test(value)) return undefined;
  const decoded = Buffer.from(value, "base64");
  if (expectedLength !== undefined && decoded.length !== expectedLength) return undefined;
  return decoded;
}

function normalizeOptions(options: SignOptions = {}): Required<Omit<SignOptions, "keyId">> & {
  keyId?: string;
} {
  const issuer = options.issuer || DEFAULT_ISSUER;
  if (Buffer.byteLength(issuer, "utf8") > 256)
    throw new RangeError("Issuer must be at most 256 bytes");
  const ttlSeconds = options.ttlSeconds ?? DEFAULT_TTL_SECONDS;
  if (!Number.isSafeInteger(ttlSeconds) || ttlSeconds < 0) {
    throw new RangeError("ttlSeconds must be a non-negative safe integer");
  }
  const now = Math.trunc(options.now ?? Date.now() / 1000);
  if (!Number.isSafeInteger(now) || now < 0)
    throw new RangeError("now must be a non-negative safe integer");
  return options.keyId === undefined
    ? { issuer, ttlSeconds, now }
    : { issuer, ttlSeconds, now, keyId: options.keyId };
}

export function canonicalMacPayload(
  content: string,
  context: JsonObject,
  nonce: string,
  metadata: {
    version: ProtocolVersion;
    keyId: string;
    issuer: string;
    issuedAt: number;
    expiresAt: number;
    algorithm: GuardBandAlgorithm;
    kind?: "json" | "text";
  },
): Uint8Array {
  const payload: JsonObject = {
    alg: metadata.algorithm,
    content,
    context,
    exp: metadata.expiresAt,
    iat: metadata.issuedAt,
    iss: metadata.issuer,
    kid: metadata.keyId,
    nonce,
    v: metadata.version,
  };
  if (metadata.kind !== undefined && metadata.kind !== "text") payload.kind = metadata.kind;
  return Buffer.from(canonicalJsonForVersion(payload, metadata.version), "utf8");
}

export class StaticKeyResolver implements KeyResolver {
  readonly signingKeyId: string;
  readonly #keys: ReadonlyMap<string, GuardBandKey>;

  constructor(keys: Readonly<Record<string, GuardBandKey>>, signingKeyId = "key001") {
    const entries = Object.entries(keys);
    if (entries.length === 0) throw new RangeError("At least one signing key is required");
    if (!Object.hasOwn(keys, signingKeyId))
      throw new RangeError("Signing key id must exist in key map");
    for (const [keyId, key] of entries) {
      if (!KEY_ID_PATTERN.test(keyId)) throw new RangeError(`Invalid key id: ${keyId}`);
      keyAlgorithm(key);
    }
    this.#keys = new Map(entries);
    this.signingKeyId = signingKeyId;
  }

  getSigningKey(keyId?: string): [string, GuardBandKey] {
    const selected = keyId ?? this.signingKeyId;
    if (!KEY_ID_PATTERN.test(selected)) throw new RangeError("Invalid signing key id format");
    const key = this.#keys.get(selected);
    if (key === undefined) throw new RangeError(`Unknown signing key id: ${selected}`);
    if (isEd25519Key(key) && key.type === "public") {
      throw new RangeError(`Key id ${selected} is verification-only and cannot sign`);
    }
    return [selected, key];
  }

  getVerificationKey(keyId: string): GuardBandKey | undefined {
    return this.#keys.get(keyId);
  }
}

export function generateEd25519KeyPair(): { privateKey: string; publicKey: string } {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const privateDer = privateKey.export({ format: "der", type: "pkcs8" });
  const publicDer = publicKey.export({ format: "der", type: "spki" });
  return {
    privateKey: privateDer.subarray(-32).toString("base64url"),
    publicKey: publicDer.subarray(-32).toString("base64url"),
  };
}

export function loadEd25519PrivateKey(encoded: string): KeyObject {
  const seed = Buffer.from(encoded.trim(), "base64url");
  if (seed.length !== 32) throw new RangeError("Ed25519 private key must be 32 bytes");
  const prefix = Buffer.from("302e020100300506032b657004220420", "hex");
  return createPrivateKey({ key: Buffer.concat([prefix, seed]), format: "der", type: "pkcs8" });
}

export function loadEd25519PublicKey(encoded: string): KeyObject {
  const raw = Buffer.from(encoded.trim(), "base64url");
  if (raw.length !== 32) throw new RangeError("Ed25519 public key must be 32 bytes");
  const prefix = Buffer.from("302a300506032b6570032100", "hex");
  return createPublicKey({ key: Buffer.concat([prefix, raw]), format: "der", type: "spki" });
}

function parseParameters(
  raw: string,
  expected: ReadonlySet<string>,
): { values?: Record<string, string>; error?: string } {
  const parts = raw.split(":");
  if (parts.length % 2 !== 0) return { error: "Malformed marker parameters" };
  const values: Record<string, string> = {};
  for (let index = 0; index < parts.length; index += 2) {
    const key = parts[index] ?? "";
    const value = parts[index + 1] ?? "";
    if (key.length === 0 || value.length === 0) return { error: "Malformed marker parameters" };
    if (Object.hasOwn(values, key)) return { error: `Duplicate marker parameter: ${key}` };
    if (!expected.has(key)) return { error: `Unsupported marker parameter: ${key}` };
    values[key] = value;
  }
  for (const key of [...expected].sort()) {
    if (!Object.hasOwn(values, key)) return { error: `Missing marker parameter: ${key}` };
  }
  return { values };
}

function parseBand(
  wrapped: string,
  validateSignature = false,
): { parsed?: ParsedBand; error?: string } {
  if (!wrapped.startsWith(START_PREFIX)) return { error: "Missing start marker" };
  const startClose = wrapped.indexOf("⟫\n", START_PREFIX.length);
  if (startClose < 0) return { error: "Malformed guard band block" };
  const contentStart = startClose + 2;
  const endIndex = wrapped.lastIndexOf(`\n${END_PREFIX}`);
  if (endIndex < contentStart) return { error: "Missing end marker" };
  const endClose = wrapped.indexOf("⟫", endIndex + END_PREFIX.length + 1);
  if (endClose !== wrapped.length - 1) return { error: "Malformed guard band block" };

  const content = wrapped.slice(contentStart, endIndex);
  if (content.includes(RESERVED_START_MARKER) || content.includes(RESERVED_END_MARKER)) {
    return { error: "Nested guard band markers are not allowed" };
  }
  const start = parseParameters(
    wrapped.slice(START_PREFIX.length, startClose),
    new Set(["v", "r", "iat", "exp"]),
  );
  if (start.error !== undefined) return { error: start.error };
  const end = parseParameters(
    wrapped.slice(endIndex + 1 + END_PREFIX.length, endClose),
    new Set(["mac", "kid", "iss"]),
  );
  if (end.error !== undefined) return { error: end.error };
  const startValues = start.values ?? {};
  const endValues = end.values ?? {};

  const version = startValues.v;
  if (!isProtocolVersion(version))
    return { error: `Unsupported guard band version: ${String(version)}` };
  const nonce = startValues.r ?? "";
  if (!NONCE_PATTERN.test(nonce)) return { error: "Invalid nonce format" };
  const issuedRaw = startValues.iat ?? "";
  const expiresRaw = startValues.exp ?? "";
  if (!INT_PATTERN.test(issuedRaw) || !INT_PATTERN.test(expiresRaw)) {
    return { error: "Invalid timestamp format" };
  }
  const issuedAt = Number(issuedRaw);
  const expiresAt = Number(expiresRaw);
  if (!Number.isSafeInteger(issuedAt) || !Number.isSafeInteger(expiresAt)) {
    return { error: "Invalid timestamp format" };
  }
  if (expiresAt < issuedAt) return { error: "Invalid timestamp range" };
  const keyId = endValues.kid ?? "";
  if (!KEY_ID_PATTERN.test(keyId)) return { error: "Invalid key id format" };
  const encodedIssuer = endValues.iss ?? "";
  if (!ISSUER_PATTERN.test(encodedIssuer)) return { error: "Invalid issuer format" };
  const issuer = decodeIssuer(encodedIssuer);
  if (issuer === undefined) return { error: "Invalid issuer encoding" };
  const signature = endValues.mac ?? "";
  if (validateSignature) {
    const decoded = decodeBase64(signature);
    if (decoded === undefined) return { error: "Invalid MAC encoding" };
    if (decoded.length !== 32 && decoded.length !== 64) return { error: "Invalid MAC length" };
  }
  return { parsed: { content, version, nonce, issuedAt, expiresAt, keyId, issuer, signature } };
}

export function extractGuardBandBlocks(text: string): string[] {
  const blocks: string[] = [];
  let searchFrom = 0;
  for (;;) {
    const startIndex = text.indexOf(START_PREFIX, searchFrom);
    if (startIndex < 0) return blocks;
    const startClose = text.indexOf("⟫\n", startIndex + START_PREFIX.length);
    if (startClose < 0) {
      searchFrom = startIndex + START_PREFIX.length;
      continue;
    }
    const nestedHeader = text.indexOf(START_PREFIX, startIndex + START_PREFIX.length);
    if (nestedHeader >= 0 && nestedHeader < startClose) {
      searchFrom = nestedHeader;
      continue;
    }
    const endIndex = text.indexOf(`\n${END_PREFIX}`, startClose + 2);
    if (endIndex < 0) {
      searchFrom = startIndex + START_PREFIX.length;
      continue;
    }
    const endClose = text.indexOf("⟫", endIndex + END_PREFIX.length + 1);
    if (endClose < 0) {
      searchFrom = startIndex + START_PREFIX.length;
      continue;
    }
    const nestedContent = text.indexOf(START_PREFIX, startClose + 2);
    if (nestedContent >= 0 && nestedContent < endIndex) {
      searchFrom = nestedContent;
      continue;
    }
    const candidate = text.slice(startIndex, endClose + 1);
    if (parseBand(candidate, true).error === undefined) {
      blocks.push(candidate);
      searchFrom = endClose + 1;
    } else {
      searchFrom = startIndex + START_PREFIX.length;
    }
  }
}

export class GuardBandCrypto {
  readonly keyResolver: KeyResolver;
  readonly signingVersion: ProtocolVersion;

  constructor(secretKeyOrOptions: Uint8Array | GuardBandCryptoOptions) {
    const options: GuardBandCryptoOptions =
      secretKeyOrOptions instanceof Uint8Array
        ? { secretKey: secretKeyOrOptions }
        : secretKeyOrOptions;
    this.signingVersion = options.signingVersion ?? CURRENT_PROTOCOL_VERSION;
    if (!isProtocolVersion(this.signingVersion)) {
      throw new RangeError(`Unsupported signing version: ${String(this.signingVersion)}`);
    }
    if (options.keyResolver !== undefined) {
      this.keyResolver = options.keyResolver;
    } else if (options.secretKey !== undefined) {
      const defaultKeyId = options.defaultKeyId ?? "key001";
      this.keyResolver = new StaticKeyResolver({ [defaultKeyId]: options.secretKey }, defaultKeyId);
    } else {
      throw new RangeError("secretKey or keyResolver is required");
    }
  }

  generateNonce(): string {
    return randomBytes(16).toString("base64url");
  }

  generateSignature(
    content: string,
    context: JsonObject,
    nonce: string,
    key: GuardBandKey,
    metadata: {
      version: ProtocolVersion;
      keyId: string;
      issuer: string;
      issuedAt: number;
      expiresAt: number;
      kind?: "json" | "text";
    },
  ): string {
    const algorithm = keyAlgorithm(key, metadata.version);
    const payload = canonicalMacPayload(content, context, nonce, { ...metadata, algorithm });
    if (isEd25519Key(key)) {
      assertEd25519Key(key);
      if (key.type === "public")
        throw new RangeError("Ed25519 public key is verification-only and cannot sign");
      return signEd25519(null, payload, key).toString("base64");
    }
    return createHmac("sha256", asBuffer(key)).update(payload).digest("base64");
  }

  verifySignature(
    content: string,
    context: JsonObject,
    nonce: string,
    signature: string,
    key: GuardBandKey,
    metadata: {
      version: ProtocolVersion;
      keyId: string;
      issuer: string;
      issuedAt: number;
      expiresAt: number;
      kind?: "json" | "text";
    },
  ): boolean {
    const rawSignature = decodeBase64(signature, isEd25519Key(key) ? 64 : 32);
    if (rawSignature === undefined) return false;
    const algorithm = keyAlgorithm(key, metadata.version);
    const payload = canonicalMacPayload(content, context, nonce, { ...metadata, algorithm });
    if (isEd25519Key(key)) {
      assertEd25519Key(key);
      return verifyEd25519(
        null,
        payload,
        key.type === "private" ? createPublicKey(key) : key,
        rawSignature,
      );
    }
    const expected = createHmac("sha256", asBuffer(key)).update(payload).digest();
    return timingSafeEqual(expected, rawSignature);
  }

  wrapWithMetadata(
    content: string,
    context: JsonObject,
    options: SignOptions = {},
  ): WrappedMetadata {
    if (content.includes(RESERVED_START_MARKER) || content.includes(RESERVED_END_MARKER)) {
      throw new RangeError("Content contains reserved Guard Band markers");
    }
    const normalized = normalizeOptions(options);
    const nonce = this.generateNonce();
    const [keyId, key] = this.keyResolver.getSigningKey(normalized.keyId);
    const expiresAt = normalized.now + normalized.ttlSeconds;
    if (!Number.isSafeInteger(expiresAt)) {
      throw new RangeError("Guard Band expiry exceeds the safe integer domain");
    }
    const signature = this.generateSignature(content, context, nonce, key, {
      version: this.signingVersion,
      keyId,
      issuer: normalized.issuer,
      issuedAt: normalized.now,
      expiresAt,
    });
    const wrapped =
      `⟪INERT:START:v:${this.signingVersion}:r:${nonce}:iat:${normalized.now}:exp:${expiresAt}⟫\n` +
      `${content}\n` +
      `⟪INERT:END:mac:${signature}:kid:${keyId}:iss:${encodeIssuer(normalized.issuer)}⟫`;
    return {
      wrapped,
      nonce,
      key_id: keyId,
      issuer: normalized.issuer,
      issued_at: normalized.now,
      expires_at: expiresAt,
    };
  }

  wrapContent(content: string, context: JsonObject, options: SignOptions = {}): string {
    return this.wrapWithMetadata(content, context, options).wrapped;
  }

  signValue(value: JsonValue, context: JsonObject, options: SignOptions = {}): DetachedEnvelope {
    const valueJson = canonicalJsonForVersion(value, this.signingVersion);
    const normalized = normalizeOptions(options);
    const nonce = this.generateNonce();
    const [keyId, key] = this.keyResolver.getSigningKey(normalized.keyId);
    const expiresAt = normalized.now + normalized.ttlSeconds;
    if (!Number.isSafeInteger(expiresAt)) {
      throw new RangeError("Guard Band expiry exceeds the safe integer domain");
    }
    const signature = this.generateSignature(valueJson, context, nonce, key, {
      version: this.signingVersion,
      keyId,
      issuer: normalized.issuer,
      issuedAt: normalized.now,
      expiresAt,
      kind: STRUCTURED_VALUE_KIND,
    });
    return {
      version: this.signingVersion,
      nonce,
      issued_at: normalized.now,
      expires_at: expiresAt,
      key_id: keyId,
      issuer: normalized.issuer,
      algorithm: keyAlgorithm(key, this.signingVersion),
      signature,
    };
  }

  verifyValue<T extends JsonValue>(
    value: T,
    envelope: unknown,
    context: JsonObject,
    now = Date.now() / 1000,
  ): ValueVerificationResult<T> {
    try {
      if (typeof envelope !== "object" || envelope === null || Array.isArray(envelope)) {
        return { valid: false, error: "Invalid detached envelope fields" };
      }
      const record = envelope as Record<string, unknown>;
      const expectedFields = [
        "version",
        "nonce",
        "issued_at",
        "expires_at",
        "key_id",
        "issuer",
        "algorithm",
        "signature",
      ];
      if (
        Object.keys(record).length !== expectedFields.length ||
        expectedFields.some((key) => !Object.hasOwn(record, key))
      ) {
        return { valid: false, error: "Invalid detached envelope fields" };
      }
      const version = record.version;
      if (!isProtocolVersion(version)) {
        return { valid: false, error: `Unsupported guard band version: ${String(version)}` };
      }
      const nonce = record.nonce;
      if (typeof nonce !== "string" || !NONCE_PATTERN.test(nonce))
        return { valid: false, error: "Invalid nonce format" };
      const issuedAt = record.issued_at;
      const expiresAt = record.expires_at;
      if (!Number.isSafeInteger(issuedAt) || !Number.isSafeInteger(expiresAt)) {
        return { valid: false, error: "Invalid timestamp format" };
      }
      if ((issuedAt as number) < 0 || (expiresAt as number) < (issuedAt as number)) {
        return { valid: false, error: "Invalid timestamp range" };
      }
      const keyId = record.key_id;
      if (typeof keyId !== "string" || !KEY_ID_PATTERN.test(keyId))
        return { valid: false, error: "Invalid key id format" };
      const issuer = record.issuer;
      if (typeof issuer !== "string" || Buffer.byteLength(issuer, "utf8") > 256) {
        return { valid: false, error: "Invalid issuer format" };
      }
      const signature = record.signature;
      if (typeof signature !== "string") return { valid: false, error: "Invalid signature format" };
      const verificationKey = this.keyResolver.getVerificationKey(keyId);
      if (verificationKey === undefined) return { valid: false, error: `Unknown key id: ${keyId}` };
      const expectedAlgorithm = keyAlgorithm(verificationKey, version);
      if (record.algorithm !== expectedAlgorithm)
        return { valid: false, error: "Signature algorithm mismatch" };
      if (decodeBase64(signature, isEd25519Key(verificationKey) ? 64 : 32) === undefined) {
        return { valid: false, error: "Invalid signature encoding or length" };
      }
      const valueJson = canonicalJsonForVersion(value, version);
      if (
        !this.verifySignature(valueJson, context, nonce, signature, verificationKey, {
          version,
          keyId,
          issuer,
          issuedAt: issuedAt as number,
          expiresAt: expiresAt as number,
          kind: STRUCTURED_VALUE_KIND,
        })
      ) {
        return { valid: false, error: "Signature verification failed" };
      }
      const currentTime = Math.trunc(now);
      if (currentTime > (expiresAt as number)) {
        return { valid: false, error: "Guard band expired", nonce, key_id: keyId };
      }
      return {
        valid: true,
        value,
        nonce,
        key_id: keyId,
        version,
        issuer,
        issued_at: issuedAt as number,
        expires_at: expiresAt as number,
        algorithm: expectedAlgorithm,
      };
    } catch (error) {
      return {
        valid: false,
        error: `Value verification error: ${error instanceof Error ? error.message : String(error)}`,
      };
    }
  }

  extractAndVerify(
    wrapped: string,
    context: JsonObject,
    now = Date.now() / 1000,
  ): InlineVerificationResult {
    try {
      if (!wrapped.includes(RESERVED_START_MARKER))
        return { valid: false, error: "Missing start marker" };
      if (!wrapped.includes(RESERVED_END_MARKER))
        return { valid: false, error: "Missing end marker" };
      const result = parseBand(wrapped);
      if (result.error !== undefined) return { valid: false, error: result.error };
      const parsed = result.parsed;
      if (parsed === undefined) return { valid: false, error: "Malformed guard band block" };
      const key = this.keyResolver.getVerificationKey(parsed.keyId);
      if (key === undefined) return { valid: false, error: `Unknown key id: ${parsed.keyId}` };
      const expectedLength = isEd25519Key(key) ? 64 : 32;
      if (decodeBase64(parsed.signature, expectedLength) === undefined) {
        return { valid: false, error: "Invalid MAC encoding or length" };
      }
      if (
        !this.verifySignature(parsed.content, context, parsed.nonce, parsed.signature, key, {
          version: parsed.version,
          keyId: parsed.keyId,
          issuer: parsed.issuer,
          issuedAt: parsed.issuedAt,
          expiresAt: parsed.expiresAt,
        })
      ) {
        return { valid: false, error: "MAC verification failed" };
      }
      const currentTime = Math.trunc(now);
      if (currentTime > parsed.expiresAt) {
        return {
          valid: false,
          error: "Guard band expired",
          nonce: parsed.nonce,
          key_id: parsed.keyId,
        };
      }
      return {
        valid: true,
        content: parsed.content,
        nonce: parsed.nonce,
        key_id: parsed.keyId,
        version: parsed.version,
        issuer: parsed.issuer,
        issued_at: parsed.issuedAt,
        expires_at: parsed.expiresAt,
      };
    } catch (error) {
      return {
        valid: false,
        error: `Parse error: ${error instanceof Error ? error.message : String(error)}`,
      };
    }
  }
}

export { canonicalJson };
