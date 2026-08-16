# Security Policy

Guard Bands is an experimental security library. Please report suspected
vulnerabilities privately before opening a public issue.

## Reporting a Vulnerability

Email: mtoren@cryptix.com

Please include the affected commit, a description and reproduction, expected
impact, and a suggested mitigation if known.

## Scope

In scope:

- wrapping or verification bypasses;
- canonicalization or Python interoperability flaws;
- malformed, ambiguous, or nested marker acceptance;
- key, version, algorithm, context, timestamp, or envelope confusion; and
- MCP input, output, call-binding, or normalization bypasses.

Out of scope:

- model hallucination without a Guard Bands boundary issue;
- malicious but correctly signed content;
- denial of service requiring unrealistic local access; and
- third-party service issues unless this repository's integration meaningfully
  contributes.

## Review status

The Python repository owns the joint pre-`1.0.0` independent review brief and
tracking issue for both implementations:

- [review brief](https://github.com/Cryptix-Security/guard-bands/blob/main/docs/EXTERNAL_REVIEW.md)
- [review tracking issue](https://github.com/Cryptix-Security/guard-bands/issues/31)

Only the default branch is actively maintained while this package is pre-1.0.
