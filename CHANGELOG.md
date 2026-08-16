# Changelog

## Unreleased

- Added a Node.js/TypeScript implementation of Guard Bands protocol v2 with
  RFC 8785/JCS canonicalization, HMAC-SHA256, Ed25519, inline text bands,
  detached JSON envelopes, and legacy v1 verification for the portable subset.
- Added MCP 2.x client and server-handler wrappers for authenticated
  `tools/call` inputs, complete results, and visible text-output boundaries.
- Vendored the language-neutral Python conformance vectors and required exact
  byte-for-byte reproduction in the test suite.
