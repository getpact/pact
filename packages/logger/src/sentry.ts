export type SentryLevel = "fatal" | "error" | "warning" | "info" | "debug";

export type SentryEvent = {
  message?: string;
  level?: SentryLevel;
  exception?: { values: Array<{ type: string; value: string; stacktrace?: unknown }> };
  request?: {
    url?: string;
    method?: string;
    headers?: Record<string, string>;
    data?: unknown;
  };
  tags?: Record<string, string>;
  extra?: Record<string, unknown>;
  environment?: string;
  release?: string;
  timestamp?: number;
  platform?: "javascript";
};

export type SentryOptions = {
  dsn?: string;
  environment?: string;
  release?: string;
  tags?: Record<string, string>;
  transport?: (url: string, body: string, headers: Record<string, string>) => Promise<void>;
  beforeSend?: (event: SentryEvent) => SentryEvent | null;
};

export type SentryClient = {
  captureException: (err: unknown, extra?: Record<string, unknown>) => void;
  captureMessage: (msg: string, level?: SentryLevel, extra?: Record<string, unknown>) => void;
  captureRequest: (req: Request, err: unknown) => void;
  flush: () => Promise<void>;
  enabled: boolean;
};

const PII_KEYS = new Set([
  "authorization",
  "cookie",
  "set-cookie",
  "password",
  "token",
  "secret",
  "key",
  "x-api-key",
  "x-pact-dev-issue-secret",
  "x-pact-web-service-token",
]);

const REDACT = "[redacted]";

const scrubRecord = (input: Record<string, unknown>): Record<string, unknown> => {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(input)) {
    const lower = k.toLowerCase();
    if (PII_KEYS.has(lower) || lower.includes("password") || lower.includes("secret")) {
      out[k] = REDACT;
      continue;
    }
    out[k] = scrubValue(v);
  }
  return out;
};

const scrubValue = (v: unknown): unknown => {
  if (v === null || v === undefined) return v;
  if (Array.isArray(v)) return v.map(scrubValue);
  if (typeof v === "object") return scrubRecord(v as Record<string, unknown>);
  return v;
};

export const scrubPii = (event: SentryEvent): SentryEvent => {
  const out: SentryEvent = { ...event };
  if (event.request) {
    const req: SentryEvent["request"] = { ...event.request };
    if (req.headers) {
      const hdr: Record<string, string> = {};
      for (const [k, v] of Object.entries(req.headers)) {
        hdr[k] = PII_KEYS.has(k.toLowerCase()) ? REDACT : v;
      }
      req.headers = hdr;
    }
    if (req.data && typeof req.data === "object") {
      req.data = scrubRecord(req.data as Record<string, unknown>);
    }
    out.request = req;
  }
  if (event.extra) out.extra = scrubRecord(event.extra);
  return out;
};

type DsnParts = { url: string; publicKey: string; projectId: string };

const parseDsn = (dsn: string): DsnParts | null => {
  try {
    const parsed = new URL(dsn);
    const publicKey = parsed.username;
    const projectId = parsed.pathname.replace(/^\/+/, "");
    if (!publicKey || !projectId) return null;
    const host = parsed.host;
    const protocol = parsed.protocol;
    const url = `${protocol}//${host}/api/${projectId}/envelope/`;
    return { url, publicKey, projectId };
  } catch {
    return null;
  }
};

const defaultTransport = async (
  url: string,
  body: string,
  headers: Record<string, string>,
): Promise<void> => {
  await fetch(url, { method: "POST", headers, body });
};

const eventToEnvelope = (event: SentryEvent): string => {
  const eventId = crypto.randomUUID().replace(/-/g, "");
  const sentAt = new Date().toISOString();
  const header = JSON.stringify({ event_id: eventId, sent_at: sentAt });
  const itemHeader = JSON.stringify({ type: "event" });
  const payload = JSON.stringify({ ...event, event_id: eventId, platform: "javascript" });
  return `${header}\n${itemHeader}\n${payload}`;
};

const errorEvent = (err: unknown, extra?: Record<string, unknown>): SentryEvent => {
  if (err instanceof Error) {
    return {
      level: "error",
      exception: {
        values: [{ type: err.name, value: err.message, stacktrace: { frames: [] } }],
      },
      ...(extra ? { extra } : {}),
      timestamp: Date.now() / 1000,
    };
  }
  return {
    level: "error",
    message: String(err),
    ...(extra ? { extra } : {}),
    timestamp: Date.now() / 1000,
  };
};

const noopClient: SentryClient = {
  captureException: () => undefined,
  captureMessage: () => undefined,
  captureRequest: () => undefined,
  flush: async () => undefined,
  enabled: false,
};

export const createSentry = (opts: SentryOptions = {}): SentryClient => {
  if (!opts.dsn) return noopClient;
  const parts = parseDsn(opts.dsn);
  if (!parts) return noopClient;

  const transport = opts.transport ?? defaultTransport;
  const beforeSend = opts.beforeSend ?? scrubPii;
  const baseTags = opts.tags ?? {};
  const inflight = new Set<Promise<void>>();

  const send = (event: SentryEvent): void => {
    const enriched: SentryEvent = {
      ...event,
      tags: { ...baseTags, ...(event.tags ?? {}) },
      ...(opts.environment ? { environment: opts.environment } : {}),
      ...(opts.release ? { release: opts.release } : {}),
      platform: "javascript",
    };
    const scrubbed = beforeSend(scrubPii(enriched));
    if (!scrubbed) return;
    const body = eventToEnvelope(scrubbed);
    const auth = [
      "Sentry sentry_version=7",
      `sentry_client=pact-logger/0.0.0`,
      `sentry_key=${parts.publicKey}`,
    ].join(", ");
    const promise = transport(parts.url, body, {
      "content-type": "application/x-sentry-envelope",
      "x-sentry-auth": auth,
    }).catch(() => undefined);
    inflight.add(promise);
    promise.finally(() => inflight.delete(promise));
  };

  return {
    enabled: true,
    captureException: (err, extra) => send(errorEvent(err, extra)),
    captureMessage: (msg, level, extra) =>
      send({
        message: msg,
        level: level ?? "info",
        ...(extra ? { extra } : {}),
        timestamp: Date.now() / 1000,
      }),
    captureRequest: (req, err) => {
      const headers: Record<string, string> = {};
      req.headers.forEach((value, key) => {
        headers[key] = value;
      });
      const url = req.url;
      const event = errorEvent(err);
      event.request = { url, method: req.method, headers };
      send(event);
    },
    flush: async () => {
      await Promise.all([...inflight]);
    },
  };
};

export type SentryEnv = {
  SENTRY_DSN?: string;
  SENTRY_ENVIRONMENT?: string;
  SENTRY_RELEASE?: string;
};

export const sentryFromEnv = (env: SentryEnv, app: string): SentryClient =>
  createSentry({
    ...(env.SENTRY_DSN ? { dsn: env.SENTRY_DSN } : {}),
    ...(env.SENTRY_ENVIRONMENT ? { environment: env.SENTRY_ENVIRONMENT } : {}),
    ...(env.SENTRY_RELEASE ? { release: env.SENTRY_RELEASE } : {}),
    tags: { app },
  });
