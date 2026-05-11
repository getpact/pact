import * as fc from "fast-check";
import { describe, expect, it } from "vitest";
import { evaluate, type Policy, type TokenClaims } from "../index.js";

const tokenArbitrary: fc.Arbitrary<TokenClaims> = fc.record({
  sub: fc.string({ minLength: 1, maxLength: 24 }),
  email: fc.emailAddress(),
  groups: fc.array(fc.string({ minLength: 1, maxLength: 16 }), { maxLength: 5 }),
  roles: fc.array(fc.string({ minLength: 1, maxLength: 16 }), { maxLength: 5 }),
});

describe("policy evaluation properties", () => {
  it("defaults to deny when no rules match", () => {
    fc.assert(
      fc.property(
        tokenArbitrary,
        fc.string({ minLength: 1 }),
        fc.string({ minLength: 1 }),
        (token, action, resource) => {
          const result = evaluate({ token, action, resource, policy: { rules: [] } });
          expect(result.allow).toBe(false);
          expect(result.reasons).toContain("default deny");
        },
      ),
    );
  });

  it("deny on a matching subject always wins over an allow on the same subject", () => {
    fc.assert(
      fc.property(
        tokenArbitrary,
        fc.string({ minLength: 1 }),
        fc.string({ minLength: 1 }),
        (token, action, resource) => {
          fc.pre(token.roles.length > 0);
          const subject = { kind: "role" as const, value: token.roles[0] as string };
          const policy: Policy = {
            rules: [
              { subject, effect: "allow" },
              { subject, effect: "deny" },
            ],
          };
          const result = evaluate({ token, action, resource, policy });
          expect(result.allow).toBe(false);
        },
      ),
    );
  });

  it("wildcard allow for a matching subject grants any action and resource", () => {
    fc.assert(
      fc.property(
        tokenArbitrary,
        fc.string({ minLength: 1 }),
        fc.string({ minLength: 1 }),
        (token, action, resource) => {
          fc.pre(token.roles.length > 0);
          const subject = { kind: "role" as const, value: token.roles[0] as string };
          const policy: Policy = { rules: [{ subject, effect: "allow" }] };
          const result = evaluate({ token, action, resource, policy });
          expect(result.allow).toBe(true);
        },
      ),
    );
  });

  it("rule with action prefix x:* allows only actions starting with x:", () => {
    fc.assert(
      fc.property(tokenArbitrary, fc.string({ minLength: 1, maxLength: 8 }), (token, prefix) => {
        fc.pre(token.roles.length > 0 && !prefix.includes(":"));
        const subject = { kind: "role" as const, value: token.roles[0] as string };
        const matching = `${prefix}:foo`;
        const notMatching = `other:${prefix}`;
        const policy: Policy = {
          rules: [{ subject, effect: "allow", action: `${prefix}:*` }],
        };
        expect(evaluate({ token, action: matching, resource: "any", policy }).allow).toBe(true);
        expect(evaluate({ token, action: notMatching, resource: "any", policy }).allow).toBe(false);
      }),
    );
  });

  it("rule with subject not matching the token never grants access", () => {
    fc.assert(
      fc.property(
        tokenArbitrary,
        fc.string({ minLength: 1, maxLength: 12 }),
        (token, foreignRole) => {
          fc.pre(!token.roles.includes(foreignRole));
          const policy: Policy = {
            rules: [{ subject: { kind: "role", value: foreignRole }, effect: "allow" }],
          };
          const result = evaluate({ token, action: "anything", resource: "anywhere", policy });
          expect(result.allow).toBe(false);
        },
      ),
    );
  });
});
