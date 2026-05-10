import { describe, expect, it } from "vitest";
import app, { buildGatewayTarget, gatewayAuthorization } from "../index.js";

const env = { ENVIRONMENT: "test" };

describe("gateway", () => {
  it("returns health", async () => {
    const res = await app.request("/health", undefined, env);
    expect(res.status).toBe(200);
  });

  it("rejects gateway requests without bearer auth", async () => {
    const res = await app.request("/acme/gateway/notion/v1/pages", undefined, env);
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: "unauthorized", message: "missing bearer token" });
  });

  it("sets security headers", async () => {
    const res = await app.request("/health", undefined, env);
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expect(res.headers.get("x-frame-options")).toBe("DENY");
    expect(res.headers.get("content-security-policy")).toContain("default-src 'none'");
  });

  it("builds gateway authorization from method, brain, and path", () => {
    expect(gatewayAuthorization("POST", "notion", "v1/pages")).toEqual({
      action: "gateway.post",
      resource: "gateway:notion:/v1/pages",
    });
  });

  it("builds safe HTTPS upstream targets", () => {
    expect(
      buildGatewayTarget("https://api.example.com/root", "v1/pages", "?limit=1").toString(),
    ).toBe("https://api.example.com/root/v1/pages?limit=1");
  });

  it("rejects private or non-HTTPS upstream targets", () => {
    expect(() => buildGatewayTarget("http://api.example.com", "v1/pages", "")).toThrow(
      "gateway upstream must use HTTPS",
    );
    expect(() => buildGatewayTarget("https://127.0.0.1:8080", "v1/pages", "")).toThrow(
      "gateway upstream host is not allowed",
    );
    expect(() => buildGatewayTarget("https://8.8.8.8", "v1/pages", "")).toThrow(
      "gateway upstream host is not allowed",
    );
    expect(() => buildGatewayTarget("https://service.local", "v1/pages", "")).toThrow(
      "gateway upstream host is not allowed",
    );
  });
});
