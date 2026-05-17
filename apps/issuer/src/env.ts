import { fromBase64 } from "@getpact/crypto";
import type { AnalyticsEngineDataset } from "@getpact/logger";

export type Env = {
  DATABASE_URL: string;
  MEK: string;
  GOOGLE_OAUTH_CLIENT_ID: string;
  GOOGLE_OAUTH_CLIENT_SECRET: string;
  GOOGLE_TOKEN_ENDPOINT?: string;
  GOOGLE_JWKS_URI?: string;
  GOOGLE_ISSUER?: string;
  ISSUER_BASE_URL: string;
  ENVIRONMENT?: string;
  ENABLE_DEV_ISSUE?: string;
  DEV_ISSUE_SECRET?: string;
  WEB_ISSUER_SERVICE_TOKEN?: string;
  WEB_OAUTH_REDIRECT_URI?: string;
  MCP_BASE_URL?: string;
  TOKEN_TTL_SECONDS?: string;
  SENTRY_DSN?: string;
  SENTRY_ENVIRONMENT?: string;
  SENTRY_RELEASE?: string;
  METRICS?: AnalyticsEngineDataset;
};

export const decodeMek = (env: Env): Uint8Array => fromBase64(env.MEK);

export const tokenTtlSeconds = (env: Env): number => {
  const raw = env.TOKEN_TTL_SECONDS;
  if (!raw) return 900;
  const parsed = Number.parseInt(raw, 10);
  if (Number.isNaN(parsed) || parsed < 60 || parsed > 3600) return 900;
  return parsed;
};

export const isDevIssueEnabled = (env: Env): boolean => {
  return env.ENABLE_DEV_ISSUE === "true" && env.ENVIRONMENT !== "production";
};
