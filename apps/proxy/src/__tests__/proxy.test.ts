import { describe, expect, it } from "vitest";
import app from "../index.js";

const env = { ENVIRONMENT: "test" };

describe("proxy", () => {
  it("returns 501 on the brain proxy route", async () => {
    const res = await app.request("/acme/proxy/notion/v1/pages", undefined, env);
    expect(res.status).toBe(501);
  });

  it("sets security headers", async () => {
    const res = await app.request("/acme/proxy/notion/v1/pages", undefined, env);
    expect(res.headers.get("x-content-type-options")).toBe("nosniff");
    expect(res.headers.get("x-frame-options")).toBe("DENY");
    expect(res.headers.get("content-security-policy")).toContain("default-src 'none'");
  });
});
