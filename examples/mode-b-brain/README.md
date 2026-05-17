# mode-b-brain

Drop `verifyPactToken` into your existing brain via one Hono handler. This shows it.

The god-mode demo simulates the issuer, MCP, and brain in one process. This
example does the part most teams actually need to ship: a downstream brain that
trusts nothing except a Pact SD-JWT in the request, calls
`@getpact/verifier-sdk`, and lets the verifier enforce audience, tool name,
holder binding, freshness, and replay before any data leaves the process.

## What is here

- `src/index.ts` builds a Hono app with one route, `POST /brain/query`. It
  pulls the bearer token off `Authorization`, optionally splices a sidecar
  KB-JWT from `X-Pact-KB-JWT` onto the trailing slot, calls
  `verifyPactToken`, and on allow filters an in-memory document set by the
  per-user document allowlist disclosed in the token (`policy.docs`, with
  fallback to `scope.docs` for tokens that fold the allowlist into the scope
  claim and pair it with a matching resource on the brain side).
- `src/server.ts` exports `runServer({ port, jwksUri, ... })` which boots the
  app on Node's `http` server. Used both as a CLI (`tsx src/server.ts`) and by
  the test suite.
- `__tests__/mode-b.test.ts` mints a local SD-JWT with the same primitives the
  god-mode demo uses (Ed25519 + SD-JWT compact form + KB-JWT), spins the
  server on an ephemeral port, and asserts the allow/deny matrix end to end
  over real HTTP. JWKS resolution is satisfied by stubbing `globalThis.fetch`
  for the `PACT_JWKS_URI` only.

## Verify path

```
client ---bearer SD-JWT---> brain.fetch
                                |
                                v
                      verifyPactToken(token, {
                        jwksUri, audience: "pact-brain",
                        toolName: "brain.query",
                        replayCache
                      })
                                |
       reject  <----- denied -----+----- allow -----> filter docs
                                                    by scopeClaim.docs
```

## Run the server

```
PACT_JWKS_URI=https://issuer.example.com/.well-known/jwks.json \
  pnpm --filter @getpact/mode-b-brain start
```

The default audience is `pact-brain`, the default tool name is `brain.query`,
the default port is `8899`, and the default document set is three rows of
fake content. Override with environment variables and the `runServer` options.

## Run the tests

```
pnpm --filter @getpact/mode-b-brain test
```

The tests cover six rows in the matrix:

- allow with a `policy.docs` array of two ids returns exactly those rows
- allow with an empty `policy.docs` array returns zero rows
- deny `aud_mismatch` when the token audience is not `pact-brain`
- deny `tool_mismatch` when the token was minted for a different tool
- deny `kb_replay_detected` on the second presentation of the same KB-JWT
- 401 with no bearer, 403 with a junk bearer

## Replace what

To wire this into a real brain, replace the in-memory `documents` slice in
`buildBrainApp` and the post-verify filter in `/brain/query` with your own
storage call. Everything above that line is the contract the verifier SDK
enforces.
