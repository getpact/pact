import { describe, expect, it } from "vitest";
import { evaluate, type Policy, parsePolicy, type TokenClaims, tryParsePolicy } from "../index.js";

const tokenFor = (overrides: Partial<TokenClaims> = {}): TokenClaims => ({
  sub: "user-123",
  email: "alice@acme.test",
  groups: ["eng"],
  roles: ["member"],
  ...overrides,
});

describe("policy evaluate", () => {
  it("default denies when no rules match", () => {
    const result = evaluate({
      token: tokenFor(),
      action: "read",
      resource: "doc:secret",
      policy: { rules: [] },
    });
    expect(result.allow).toBe(false);
    expect(result.reasons).toEqual(["default deny"]);
  });

  it("allows when group rule matches", () => {
    const policy: Policy = {
      rules: [{ subject: { kind: "group", value: "eng" }, effect: "allow", action: "read" }],
    };
    const result = evaluate({ token: tokenFor(), action: "read", resource: "doc:x", policy });
    expect(result.allow).toBe(true);
  });

  it("denies when group rule does not include user's groups", () => {
    const policy: Policy = {
      rules: [{ subject: { kind: "group", value: "finance" }, effect: "allow", action: "read" }],
    };
    const result = evaluate({ token: tokenFor(), action: "read", resource: "doc:x", policy });
    expect(result.allow).toBe(false);
  });

  it("explicit deny overrides explicit allow", () => {
    const policy: Policy = {
      rules: [
        { subject: { kind: "group", value: "eng" }, effect: "allow", action: "read" },
        { subject: { kind: "user", value: "alice@acme.test" }, effect: "deny", action: "read" },
      ],
    };
    const result = evaluate({ token: tokenFor(), action: "read", resource: "doc:x", policy });
    expect(result.allow).toBe(false);
    expect(result.reasons[0]).toContain("deny by user");
  });

  it("matches role-based rule", () => {
    const policy: Policy = {
      rules: [{ subject: { kind: "role", value: "admin" }, effect: "allow" }],
    };
    const result = evaluate({
      token: tokenFor({ roles: ["admin"] }),
      action: "any",
      resource: "any",
      policy,
    });
    expect(result.allow).toBe(true);
  });

  it("supports wildcard prefix on resource", () => {
    const policy: Policy = {
      rules: [{ subject: { kind: "group", value: "eng" }, effect: "allow", resource: "slack:*" }],
    };
    const ok = evaluate({
      token: tokenFor(),
      action: "read",
      resource: "slack:channel:eng",
      policy,
    });
    expect(ok.allow).toBe(true);

    const notOk = evaluate({
      token: tokenFor(),
      action: "read",
      resource: "drive:file:abc",
      policy,
    });
    expect(notOk.allow).toBe(false);
  });

  it("user rule by email and by sub both match", () => {
    const policy: Policy = {
      rules: [{ subject: { kind: "user", value: "user-123" }, effect: "allow" }],
    };
    const result = evaluate({
      token: tokenFor({ email: "x@y.test" }),
      action: "any",
      resource: "any",
      policy,
    });
    expect(result.allow).toBe(true);
  });

  it("multiple allows still pass", () => {
    const policy: Policy = {
      rules: [
        { subject: { kind: "group", value: "eng" }, effect: "allow", action: "read" },
        { subject: { kind: "role", value: "member" }, effect: "allow", action: "read" },
      ],
    };
    const result = evaluate({ token: tokenFor(), action: "read", resource: "doc:x", policy });
    expect(result.allow).toBe(true);
    expect(result.reasons.length).toBe(2);
  });

  it("parsePolicy accepts a valid policy and rejects garbage", () => {
    const valid = parsePolicy({
      rules: [{ subject: { kind: "role", value: "admin" }, effect: "allow" }],
    });
    expect(valid.rules.length).toBe(1);
    expect(() => parsePolicy({ rules: [{ effect: "allow" }] })).toThrow();
    expect(tryParsePolicy({ rules: "nope" })).toBeNull();
    expect(tryParsePolicy(null)).toBeNull();
  });

  it("undefined action and resource on rule means wildcard", () => {
    const policy: Policy = {
      rules: [{ subject: { kind: "role", value: "member" }, effect: "allow" }],
    };
    const result = evaluate({
      token: tokenFor(),
      action: "any.action",
      resource: "any:resource",
      policy,
    });
    expect(result.allow).toBe(true);
  });
});
