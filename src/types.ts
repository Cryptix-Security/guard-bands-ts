import type { KeyObject } from "node:crypto";

export type JsonPrimitive = boolean | null | number | string;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };

export type ProtocolVersion = "1" | "2";
export type GuardBandAlgorithm =
  | "GBv1-HMAC-SHA256"
  | "GBv1-Ed25519"
  | "GBv2-HMAC-SHA256"
  | "GBv2-Ed25519";
export type GuardBandKey = Uint8Array | KeyObject;

export interface KeyResolver {
  getSigningKey(keyId?: string): [string, GuardBandKey];
  getVerificationKey(keyId: string): GuardBandKey | undefined;
}

export interface GuardBandCryptoOptions {
  secretKey?: Uint8Array;
  keyResolver?: KeyResolver;
  defaultKeyId?: string;
  signingVersion?: ProtocolVersion;
}

export interface SignOptions {
  keyId?: string;
  issuer?: string;
  ttlSeconds?: number;
  now?: number;
}

export interface DetachedEnvelope {
  version: ProtocolVersion;
  nonce: string;
  issued_at: number;
  expires_at: number;
  key_id: string;
  issuer: string;
  algorithm: GuardBandAlgorithm;
  signature: string;
}

export interface WrappedMetadata {
  wrapped: string;
  nonce: string;
  key_id: string;
  issuer: string;
  issued_at: number;
  expires_at: number;
}

export interface ValidInlineResult {
  valid: true;
  content: string;
  nonce: string;
  key_id: string;
  version: ProtocolVersion;
  issuer: string;
  issued_at: number;
  expires_at: number;
}

export interface ValidValueResult<T extends JsonValue> {
  valid: true;
  value: T;
  nonce: string;
  key_id: string;
  version: ProtocolVersion;
  issuer: string;
  issued_at: number;
  expires_at: number;
  algorithm: GuardBandAlgorithm;
}

export interface InvalidResult {
  valid: false;
  error: string;
  nonce?: string;
  key_id?: string;
}

export type InlineVerificationResult = InvalidResult | ValidInlineResult;
export type ValueVerificationResult<T extends JsonValue> = InvalidResult | ValidValueResult<T>;
