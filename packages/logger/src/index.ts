export type LogLevel = "debug" | "info" | "warn" | "error";

export type LogFields = Record<string, unknown>;

export type Logger = {
  debug: (msg: string, fields?: LogFields) => void;
  info: (msg: string, fields?: LogFields) => void;
  warn: (msg: string, fields?: LogFields) => void;
  error: (msg: string, fields?: LogFields) => void;
  child: (fields: LogFields) => Logger;
};

export type LoggerOptions = {
  level?: LogLevel;
  base?: LogFields;
  sink?: (line: string) => void;
};

const LEVEL_ORDER: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40,
};

const safeStringify = (value: unknown): string => {
  const seen = new WeakSet<object>();
  return JSON.stringify(value, (_k, v) => {
    if (typeof v === "bigint") return v.toString();
    if (v instanceof Error) {
      return { name: v.name, message: v.message, stack: v.stack };
    }
    if (typeof v === "object" && v !== null) {
      if (seen.has(v)) return "[circular]";
      seen.add(v);
    }
    return v;
  });
};

const envLogLevel = (): LogLevel | undefined => {
  const raw = typeof process !== "undefined" && process.env ? process.env.LOG_LEVEL : undefined;
  if (raw === "debug" || raw === "info" || raw === "warn" || raw === "error") return raw;
  return undefined;
};

export const createLogger = (opts: LoggerOptions = {}): Logger => {
  const minLevel = LEVEL_ORDER[opts.level ?? envLogLevel() ?? "info"];
  const base = opts.base ?? {};
  const sink = opts.sink ?? ((line: string) => process.stdout.write(`${line}\n`));

  const log = (level: LogLevel, msg: string, fields: LogFields = {}): void => {
    if (LEVEL_ORDER[level] < minLevel) return;
    const record = {
      ts: new Date().toISOString(),
      level,
      msg,
      ...base,
      ...fields,
    };
    sink(safeStringify(record));
  };

  const make = (extra: LogFields): Logger => ({
    debug: (msg, fields) => log("debug", msg, { ...extra, ...fields }),
    info: (msg, fields) => log("info", msg, { ...extra, ...fields }),
    warn: (msg, fields) => log("warn", msg, { ...extra, ...fields }),
    error: (msg, fields) => log("error", msg, { ...extra, ...fields }),
    child: (fields) => make({ ...extra, ...fields }),
  });

  return make({});
};

import type { Context, Next } from "hono";

export const requestLogger =
  (logger: Logger, app: string) =>
  async (c: Context, next: Next): Promise<void> => {
    const requestId = c.req.header("x-request-id") ?? newRequestId();
    const start = Date.now();
    const reqLog = logger.child({ app, requestId, method: c.req.method, path: c.req.path });
    c.set("logger", reqLog);
    c.set("requestId", requestId);
    c.header("x-request-id", requestId);
    try {
      await next();
      reqLog.info("request", {
        status: c.res.status,
        durationMs: Date.now() - start,
      });
    } catch (err) {
      reqLog.error("request failed", {
        err,
        durationMs: Date.now() - start,
      });
      throw err;
    }
  };

export const newRequestId = (): string => {
  if (typeof crypto !== "undefined" && typeof crypto.randomUUID === "function") {
    return crypto.randomUUID();
  }
  return Math.random().toString(36).slice(2, 14);
};

export {
  type AnalyticsEngineDataPoint,
  type AnalyticsEngineDataset,
  createMetrics,
  METRIC_NAMES,
  type MetricsClient,
  type MetricsEnv,
  type MetricsOptions,
  type MetricsSink,
  type MetricTags,
  metricsFromEnv,
} from "./metrics.js";
export {
  createSentry,
  type SentryClient,
  type SentryEnv,
  type SentryEvent,
  type SentryLevel,
  type SentryOptions,
  scrubPii,
  sentryFromEnv,
} from "./sentry.js";
