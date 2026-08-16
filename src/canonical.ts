import type { JsonValue, ProtocolVersion } from "./types.js";

function assertValidUnicode(value: string): void {
  for (let index = 0; index < value.length; index += 1) {
    const code = value.charCodeAt(index);
    if (code >= 0xd800 && code <= 0xdbff) {
      if (index + 1 >= value.length) {
        throw new TypeError("String contains a lone Unicode surrogate");
      }
      const next = value.charCodeAt(index + 1);
      if (next < 0xdc00 || next > 0xdfff) {
        throw new TypeError("String contains a lone Unicode surrogate");
      }
      index += 1;
    } else if (code >= 0xdc00 && code <= 0xdfff) {
      throw new TypeError("String contains a lone Unicode surrogate");
    }
  }
}

function assertPlainObject(value: object): asserts value is Record<string, unknown> {
  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError("Only plain JSON objects are supported");
  }
  const enumerableSymbols = Object.getOwnPropertySymbols(value).filter((symbol) =>
    Object.prototype.propertyIsEnumerable.call(value, symbol),
  );
  if (enumerableSymbols.length > 0) {
    throw new TypeError("JSON object keys must be strings");
  }
}

function serializeNumber(value: number): string {
  if (!Number.isFinite(value)) {
    throw new TypeError(`${String(value)} is not representable in JCS`);
  }
  return JSON.stringify(value);
}

function serializeJcs(value: unknown, ancestors: Set<object>): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") return serializeNumber(value);
  if (typeof value === "string") {
    assertValidUnicode(value);
    return JSON.stringify(value);
  }
  if (typeof value !== "object") {
    throw new TypeError(`Unsupported JSON value: ${typeof value}`);
  }
  if (ancestors.has(value)) throw new TypeError("Circular JSON value");
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return `[${value.map((entry) => serializeJcs(entry, ancestors)).join(",")}]`;
    }
    assertPlainObject(value);
    const entries = Object.keys(value)
      .sort()
      .map((key) => {
        assertValidUnicode(key);
        return `${JSON.stringify(key)}:${serializeJcs(value[key], ancestors)}`;
      });
    return `{${entries.join(",")}}`;
  } finally {
    ancestors.delete(value);
  }
}

function compareCodePoints(left: string, right: string): number {
  const leftPoints = Array.from(left, (character) => character.codePointAt(0) ?? 0);
  const rightPoints = Array.from(right, (character) => character.codePointAt(0) ?? 0);
  const length = Math.min(leftPoints.length, rightPoints.length);
  for (let index = 0; index < length; index += 1) {
    const difference = (leftPoints[index] ?? 0) - (rightPoints[index] ?? 0);
    if (difference !== 0) return difference;
  }
  return leftPoints.length - rightPoints.length;
}

function serializeV1Subset(value: unknown, ancestors: Set<object>): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new TypeError("Protocol v1 verification supports only safe integer numbers");
    }
    return String(value);
  }
  if (typeof value === "string") {
    assertValidUnicode(value);
    return JSON.stringify(value);
  }
  if (typeof value !== "object") throw new TypeError(`Unsupported JSON value: ${typeof value}`);
  if (ancestors.has(value)) throw new TypeError("Circular JSON value");
  ancestors.add(value);
  try {
    if (Array.isArray(value)) {
      return `[${value.map((entry) => serializeV1Subset(entry, ancestors)).join(",")}]`;
    }
    assertPlainObject(value);
    const entries = Object.keys(value)
      .sort(compareCodePoints)
      .map((key) => {
        assertValidUnicode(key);
        return `${JSON.stringify(key)}:${serializeV1Subset(value[key], ancestors)}`;
      });
    return `{${entries.join(",")}}`;
  } finally {
    ancestors.delete(value);
  }
}

export function canonicalJson(value: JsonValue): string {
  return serializeJcs(value, new Set());
}

export function canonicalJsonForVersion(value: JsonValue, version: ProtocolVersion): string {
  return version === "1" ? serializeV1Subset(value, new Set()) : canonicalJson(value);
}
