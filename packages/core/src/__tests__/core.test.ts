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

  it("rejects low-entropy secrets even when long enough", () => {
    expect(isStrongSharedSecret("A".repeat(40))).toBe(false);
    expect(isStrongSharedSecret("abababababababababababababababab")).toBe(false);
  });
});

describe("upstream URL validation", () => {
  it("allows public HTTPS upstream URLs", () => {
    expect(assertSafeUpstreamUrl("https://api.example.com/base").toString()).toBe(
      "https://api.example.com/base",
    );
  });

  const privateHosts: Array<[string, string]> = [
    ["localhost label", "localhost"],
    ["canonical loopback", "127.0.0.1"],
    ["mid-loopback range", "127.5.6.7"],
    ["unspecified ipv4", "0.0.0.0"],
    ["private class A", "10.0.0.1"],
    ["private class B mid", "172.20.5.5"],
    ["private class C", "192.168.1.1"],
    ["link-local", "169.254.10.20"],
    ["cloud metadata", "169.254.169.254"],
    ["mdns suffix", "service.local"],
    ["internal suffix", "host.internal"],
    ["loopback v6 bracketed", "[::1]"],
    ["loopback v6 bare", "::1"],
    ["unique local v6", "[fc00::1]"],
    ["link-local v6", "[fe80::1]"],
    ["decimal integer loopback", "2130706433"],
    ["hex dotted loopback", "0x7f.0.0.1"],
    ["single hex loopback", "0x7f000001"],
    ["octal dotted loopback", "0177.0.0.1"],
    ["single octal loopback", "017700000001"],
    ["3-octet compressed loopback", "127.1"],
    ["2-octet compressed private", "10.1"],
    ["ipv4-mapped v6 hex", "::ffff:7f00:0001"],
    ["ipv4-mapped v6 dotted", "::ffff:127.0.0.1"],
    ["ipv4-mapped v6 bracketed", "[::ffff:169.254.169.254]"],
    ["6to4 wrapping loopback", "2002:7f00:1::"],
    ["overflow integer", "4294967296"],
  ];

  for (const [label, host] of privateHosts) {
    it(`flags ${label} (${host}) as private`, () => {
      expect(isPrivateHost(host)).toBe(true);
    });
  }

  const publicHosts: Array<[string, string]> = [
    ["public dns", "8.8.8.8"],
    ["cloudflare dns", "1.1.1.1"],
    ["dotted public", "203.0.113.42"],
    ["public ipv6", "[2606:4700:4700::1111]"],
    ["public hostname", "api.example.com"],
    ["nested subdomain", "v1.api.example.com"],
  ];

  for (const [label, host] of publicHosts) {
    it(`permits ${label} (${host})`, () => {
      expect(isPrivateHost(host)).toBe(false);
    });
  }

  it("rejects unsafe upstream URLs", () => {
    expect(() => assertSafeUpstreamUrl("http://api.example.com")).toThrow(
      "upstream must use https",
    );
    expect(() => assertSafeUpstreamUrl("https://user:pass@api.example.com")).toThrow(
      "upstream credentials forbidden",
    );
    expect(() => assertSafeUpstreamUrl("https://127.0.0.1")).toThrow("upstream host not allowed");
    expect(() => assertSafeUpstreamUrl("https://2130706433")).toThrow("upstream host not allowed");
    expect(() => assertSafeUpstreamUrl("https://0x7f000001")).toThrow("upstream host not allowed");
    expect(() => assertSafeUpstreamUrl("https://[::ffff:127.0.0.1]")).toThrow(
      "upstream host not allowed",
    );
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
