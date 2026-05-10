# @getpact/policy

Policy schema and evaluator. Policies are versioned per workspace (only one active version at a time, enforced by a unique partial index on `replaced_at IS NULL`). Evaluation takes a token's claims, an action, a resource, and the active policy body; rules match by subject (role, group, or user) and effect (allow or deny). Default deny.

```ts
import { tryParsePolicy, evaluate } from "@getpact/policy";

const policy = tryParsePolicy(rowFromDb);
const verdict = evaluate({ token: { sub, email, groups, roles }, action, resource, policy });
if (!verdict.allow) console.log("denied:", verdict.reasons);
```

Policy bodies are validated against the `Policy` schema before being persisted by the admin API.
