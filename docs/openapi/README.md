# OpenAPI

`pact.v1.yaml` is the current HTTP contract source of truth. It is intentionally
checked in as a static contract until route-level runtime schemas are introduced.

Rules:

- Update this file in the same change as public HTTP route changes.
- Run `pnpm check:openapi` before merging API changes.
- Do not generate SDKs from inline Hono `c.req.json<T>()` types; those are not
  runtime validation.
- The first generated SDK should cover issuer, verifier, admin, and audit APIs.
  Gateway success responses remain opaque upstream responses.

Next migration step: introduce shared runtime schemas, wire them into Hono
handlers, then generate this OpenAPI file from those schemas.
