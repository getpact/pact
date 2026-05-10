# @getpact/core

Shared primitives used across the Pact codebase: branded types (`WorkspaceId`, `UserId`, `Email`), email canonicalization, RFC 4122 UUID validation (`isUuid`), and the `PactError` hierarchy (`AuthError`, `AuthzError`, `NotFoundError`, `ValidationError`, `ConflictError`).

```ts
import { canonicalizeEmail, isUuid, AuthError } from "@getpact/core";

if (!isUuid(input)) throw new AuthError("malformed workspace id");
const email = canonicalizeEmail("Alice@Example.com");
```

No runtime dependencies.
