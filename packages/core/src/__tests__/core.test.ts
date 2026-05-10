import { describe, expect, it } from "vitest";
import { assertAllowedUpstreamHost, assertSafeUpstreamUrl, isPrivateHost } from "../index.js";

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
