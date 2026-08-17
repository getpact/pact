# Verifier conformance corpus

`@getpact/verifier-sdk` (Node) and `getpact-verifier` (Python) independently
re-implement the same SD-JWT + KB-JWT checks. Running both test suites proves
each one is self-consistent; it does not prove they agree with each other. A
divergence here is a security bug: the same presentation would be allowed by one
integration and denied by the other.

`verifier-cases.json` is the shared contract. Both suites replay every case and
assert the same verdict:

- `packages/verifier-sdk-node/src/__tests__/conformance.test.ts`
- `packages/verifier-sdk-python/tests/test_conformance.py`

## Regenerating

```
pnpm --filter @getpact/crypto build
node scripts/gen-verifier-fixtures.mjs
```

Tokens are minted with `@getpact/crypto`, the same code the issuer signs with, so
the corpus pins the real wire format rather than a hand-rolled approximation.

Generation is deterministic: fixed Ed25519 seeds, fixed disclosure salts, and a
fixed reference clock (`nowSeconds`) that both suites inject in place of the wall
clock. Regenerating without editing a case produces a byte-identical file, and CI
regenerates and diffs to catch silent drift in the SD-JWT encoder.

## What is covered

Two allow cases (issuer `scope_claim` with no resource constraint; disclosed
`scope` with a wildcard resource match), and one deny case per `DenyReason` that
a caller can actually trigger: `expired`, `aud_mismatch`, `kb_missing`,
`kb_binding_invalid`, `kb_signature_invalid`, `kb_iat_invalid` (both edges of the
freshness window), `signature_invalid`, `invalid_format`, `tool_mismatch`,
`scope_mismatch`, `resource_required`, `kb_replay_detected`, `jwks_fetch_failed`.

## Known API asymmetries

These are differences in the option surface, not in verdicts. The corpus works
around them; anyone porting code between the two SDKs should know about them.

- `now` units differ. The Node `now()` returns milliseconds (it substitutes for
  `Date.now`); the Python `now()` returns seconds (it substitutes for
  `time.time`).
- Python `VerifyOpts` accepts an optional `issuer`, and rejects a token whose
  `iss` does not match it. Node has no equivalent option and never inspects
  `iss`. Default behaviour matches because the Python option defaults to `None`.

## Not covered

Type-coercion edges where the two languages genuinely disagree, rather than where
one is wrong. `_match_pattern` compares a scope value against a requested value
with `==` in Python and `===` in TypeScript once neither side is a string, array,
or object, so a scope of `true` matched against a requested `1` is accepted by
Python and rejected by Node. No token the issuer mints carries such a scope, so
the corpus does not encode the disagreement as expected behaviour.
