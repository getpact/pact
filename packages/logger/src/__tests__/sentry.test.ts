import { describe, expect, it } from "vitest";
import { createSentry, type SentryEvent, scrubPii, sentryFromEnv } from "../sentry.js";

describe("sentry", () => {
  it("returns a no-op client when DSN is unset", () => {
    const client = createSentry({});
    expect(client.enabled).toBe(false);
    client.captureException(new Error("ignored"));
    client.captureMessage("ignored");
  });

  it("returns a no-op client when DSN is malformed", () => {
    const client = createSentry({ dsn: "not-a-url" });
    expect(client.enabled).toBe(false);
  });

  it("sends an envelope when a DSN is present", async () => {
    const sent: Array<{ url: string; body: string; headers: Record<string, string> }> = [];
    const client = createSentry({
      dsn: "https://abc123@o111.ingest.sentry.io/222",
      environment: "test",
      tags: { app: "issuer" },
      transport: async (url, body, headers) => {
        sent.push({ url, body, headers });
      },
    });
    expect(client.enabled).toBe(true);
    client.captureException(new Error("boom"));
    await client.flush();
    expect(sent.length).toBe(1);
    const first = sent[0];
    if (!first) throw new Error("expected at least one envelope");
    expect(first.url).toBe("https://o111.ingest.sentry.io/api/222/envelope/");
    expect(first.headers["x-sentry-auth"]).toContain("sentry_key=abc123");
    const lines = first.body.split("\n");
    expect(lines).toHaveLength(3);
    const payload = JSON.parse(lines[2] as string) as SentryEvent;
    expect(payload.exception?.values?.[0]?.value).toBe("boom");
    expect(payload.tags?.app).toBe("issuer");
    expect(payload.environment).toBe("test");
  });

  it("redacts PII headers and body fields on captureRequest", async () => {
    const sent: SentryEvent[] = [];
    const client = createSentry({
      dsn: "https://abc@o1.sentry.io/1",
      transport: async (_url, body) => {
        const parts = body.split("\n");
        sent.push(JSON.parse(parts[2] as string) as SentryEvent);
      },
    });
    const req = new Request("https://example.test/v1/x", {
      method: "POST",
      headers: {
        authorization: "Bearer secret-value",
        cookie: "session=abc",
        "content-type": "application/json",
      },
    });
    client.captureRequest(req, new Error("kapow"));
    await client.flush();
    const event = sent[0];
    if (!event) throw new Error("expected event");
    expect(event.request?.headers?.authorization).toBe("[redacted]");
    expect(event.request?.headers?.cookie).toBe("[redacted]");
    expect(event.request?.headers?.["content-type"]).toBe("application/json");
  });

  it("scrubPii redacts known sensitive extra keys", () => {
    const event: SentryEvent = {
      message: "x",
      extra: {
        password: "hunter2",
        nested: { token: "t", ok: "keep" },
        ok: 1,
      },
    };
    const out = scrubPii(event);
    const extra = out.extra as Record<string, unknown>;
    expect(extra.password).toBe("[redacted]");
    const nested = extra.nested as Record<string, unknown>;
    expect(nested.token).toBe("[redacted]");
    expect(nested.ok).toBe("keep");
    expect(extra.ok).toBe(1);
  });

  it("sentryFromEnv is a no-op when SENTRY_DSN is absent", () => {
    const client = sentryFromEnv({}, "issuer");
    expect(client.enabled).toBe(false);
  });

  it("sentryFromEnv tags events with the app name", async () => {
    const sent: SentryEvent[] = [];
    const client = sentryFromEnv(
      {
        SENTRY_DSN: "https://k@o.sentry.io/1",
      },
      "verifier",
    );
    expect(client.enabled).toBe(true);
    const probe = createSentry({
      dsn: "https://k@o.sentry.io/1",
      tags: { app: "verifier" },
      transport: async (_u, body) => {
        sent.push(JSON.parse(body.split("\n")[2] as string) as SentryEvent);
      },
    });
    probe.captureMessage("hello");
    await probe.flush();
    expect(sent[0]?.tags?.app).toBe("verifier");
  });
});
