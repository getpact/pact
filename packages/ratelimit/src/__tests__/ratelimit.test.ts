import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { memoryRateLimiter, rateLimit } from "../index.js";

describe("memoryRateLimiter", () => {
  it("allows up to limit and rejects subsequent calls", async () => {
    const rl = memoryRateLimiter();
    const a = await rl.hit("ip", 2, 60);
    const b = await rl.hit("ip", 2, 60);
    const c = await rl.hit("ip", 2, 60);
    expect(a.allowed).toBe(true);
    expect(b.allowed).toBe(true);
    expect(c.allowed).toBe(false);
    expect(c.remaining).toBe(0);
  });

  it("isolates separate keys", async () => {
    const rl = memoryRateLimiter();
    const a = await rl.hit("alice", 1, 60);
    const b = await rl.hit("bob", 1, 60);
    expect(a.allowed).toBe(true);
    expect(b.allowed).toBe(true);
  });

  it("rejects invalid options", async () => {
    const rl = memoryRateLimiter();
    await expect(rl.hit("ip", 0, 60)).rejects.toThrow();
    await expect(rl.hit("ip", 1, 0)).rejects.toThrow();
  });
});

describe("rateLimit middleware", () => {
  it("returns 429 once over limit", async () => {
    const rl = memoryRateLimiter();
    const app = new Hono();
    app.use(
      "/x",
      rateLimit({
        limiter: rl,
        limit: 1,
        windowSeconds: 60,
        keyFn: () => "test",
      }),
    );
    app.get("/x", (c) => c.text("ok"));
    const first = await app.request("/x");
    const second = await app.request("/x");
    expect(first.status).toBe(200);
    expect(second.status).toBe(429);
    expect(second.headers.get("retry-after")).not.toBeNull();
    expect(first.headers.get("x-ratelimit-remaining")).toBe("0");
  });
});
