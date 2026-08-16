# Guard Bands for TypeScript

[![CI](https://github.com/Cryptix-Security/guard-bands-ts/actions/workflows/ci.yml/badge.svg)](https://github.com/Cryptix-Security/guard-bands-ts/actions/workflows/ci.yml)
[![CodeQL](https://github.com/Cryptix-Security/guard-bands-ts/actions/workflows/codeql.yml/badge.svg)](https://github.com/Cryptix-Security/guard-bands-ts/actions/workflows/codeql.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)

TypeScript implementation of the
[Guard Bands](https://github.com/Cryptix-Security/guard-bands) cryptographic
boundary protocol and its MCP `tools/call` integration.

Guard Bands authenticates untrusted content, provenance, lifetime, and the
application context in which that content may be used. Verification establishes
a data boundary; it does not grant authority or replace normal authorization.

> Early development: `@guardbands/core` is not yet published to npm.

## Install from source

```bash
pnpm add github:Cryptix-Security/guard-bands-ts#v0.1.0
```

Node.js 20 or later is required.

## Core usage

```ts
import { GuardBandCrypto } from "@guardbands/core";

const crypto = new GuardBandCrypto(Buffer.from(process.env.GUARD_BAND_KEY!, "base64"));
const context = {
  tenant_id: "tenant-a",
  request_id: "req-001",
  policy_path: "support.summarize",
};

const wrapped = crypto.wrapContent("Untrusted document text", context, {
  issuer: "document-ingress",
});
const result = crypto.extractAndVerify(wrapped, context);

if (!result.valid) throw new Error(result.error);
console.log(result.content);
```

The package also supports detached JSON envelopes through `signValue` and
`verifyValue`, HMAC-SHA256 for a shared trust domain, and Ed25519 private/public
keys for signing and verification role separation.

## Interoperability

New signatures use protocol v2 and RFC 8785 JSON Canonicalization Scheme (JCS).
The test suite reproduces the Python implementation's HMAC, Ed25519, inline,
and detached artifacts byte-for-byte using the vendored
[`conformance/vectors.json`](conformance/vectors.json).

Protocol v1 verification is available only for its portable subset. V1 used
Python-specific JSON number serialization, so new cross-language signatures
must use v2.

## MCP

`@guardbands/core/mcp` provides a guarded MCP client and a wrapper for official
MCP 2.x server tool handlers. It verifies tool inputs before execution, signs
complete results, and preserves visible Guard Bands around text shown to a
model. See [`docs/MCP.md`](docs/MCP.md).

## Development

```bash
pnpm install
pnpm check
pnpm build
```

The CI matrix runs on Node.js 20, 22, and 24. This repository is pre-1.0, and a
stable release is blocked on the joint Python/TypeScript
[independent review gate](https://github.com/Cryptix-Security/guard-bands/blob/main/docs/EXTERNAL_REVIEW.md).
Review progress is tracked in
[Cryptix-Security/guard-bands#31](https://github.com/Cryptix-Security/guard-bands/issues/31).
