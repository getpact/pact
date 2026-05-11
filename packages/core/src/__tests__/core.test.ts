import { describe, expect, it } from "vitest";
import {
  assertAllowedUpstreamHost,
  assertSafeUpstreamUrl,
  isPrivateHost,
  isStrongSharedSecret,
  timingSafeEqualString,
  tokenModeForAudience,
} from "../index.js";

describe("token audience modes", () => {
  it("maps gateway tokens to Mode B and service tokens to Mode A", () => {
    expect(tokenModeForAudience("pact-gateway")).toBe("B");
    expect(tokenModeForAudience("pact-mcp")).toBe("A");
    expect(tokenModeForAudience("pact-admin")).toBe("A");
    expect(tokenModeForAudience("pact-audit")).toBe("A");
    expect(tokenModeForAudience("unknown")).toBeNull();
  });
});

describe("timing safe string comparison", () => {
  it("compares equal strings and rejects mismatches", () => {
    expect(timingSafeEqualString("Bearer service-secret", "Bearer service-secret")).toBe(true);
    expect(timingSafeEqualString("Bearer service-secret", "Bearer wrong-secret")).toBe(false);
    expect(timingSafeEqualString("Bearer service-secret", "Bearer service-secret-extra")).toBe(
      false,
    );
  });

  it("rejects oversized strings", () => {
    const oversized = "a".repeat(4097);
    expect(timingSafeEqualString(oversized, oversized)).toBe(false);
  });
});

describe("shared secret strength", () => {
  it("accepts long non-placeholder secrets", () => {
    expect(isStrongSharedSecret("0123456789abcdef0123456789abcdef")).toBe(true);
  });

  it("rejects weak, placeholder, or whitespace secrets", () => {
    expect(isStrongSharedSecret(undefined)).toBe(false);
    expect(isStrongSharedSecret("short")).toBe(false);
    expect(isStrongSharedSecret("replace-with-real-service-token-value")).toBe(false);
    expect(isStrongSharedSecret("0123456789abcdef 0123456789abcdef")).toBe(false);
  });
});

describe("upstream URL validation", () => {
  it("allows public HTTPS upstream URLs", () => {
    expect(assertSafeUpstreamUrl("https://api.example.com/base").toString()).toBe(
      "https://api.example.com/base",
    );
  });

  it("rejects private hosts and IP literals", () => {
    expect(isPrivateHost("localhost")).toBe(true);
    expect(isPrivateHost("127.0.0.1")).toBe(true);
    expect(isPrivateHost("10.0.0.1")).toBe(true);
    expect(isPrivateHost("172.16.0.1")).toBe(true);
    expect(isPrivateHost("192.168.1.1")).toBe(true);
    expect(isPrivateHost("8.8.8.8")).toBe(true);
    expect(isPrivateHost("service.local")).toBe(true);
    expect(isPrivateHost("[::1]")).toBe(true);
  });

  it("rejects unsafe upstream URLs", () => {
    expect(() => assertSafeUpstreamUrl("http://api.example.com")).toThrow(
      "upstream must use https",
    );
    expect(() => assertSafeUpstreamUrl("https://user:pass@api.example.com")).toThrow(
      "upstream credentials forbidden",
    );
    expect(() => assertSafeUpstreamUrl("https://127.0.0.1")).toThrow("upstream host not allowed");
  });

  it("enforces upstream host allowlists", () => {
    const url = assertSafeUpstreamUrl("https://api.example.com/base");
    expect(() => assertAllowedUpstreamHost(url, "api.example.com")).not.toThrow();
    expect(() => assertAllowedUpstreamHost(url, "*.example.com")).not.toThrow();
    expect(() => assertAllowedUpstreamHost(url, "other.example.com")).toThrow(
      "upstream host not allowed by allowlist",
    );
    expect(() => assertAllowedUpstreamHost(url, undefined, { required: true })).toThrow(
      "upstream host allowlist required",
    );
  });
});
