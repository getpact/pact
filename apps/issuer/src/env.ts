import { fromBase64 } from "@getpact/crypto";

export type Env = {
  DATABASE_URL: string;
  MEK: string;
  GOOGLE_OAUTH_CLIENT_ID: string;
  GOOGLE_OAUTH_CLIENT_SECRET: string;
  ISSUER_BASE_URL: string;
  ENVIRONMENT?: string;
  ENABLE_DEV_ISSUE?: string;
  TOKEN_TTL_SECONDS?: string;
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
  const flag = env.ENABLE_DEV_ISSUE === "true";
  const local = env.ENVIRONMENT === "dev" || env.ENVIRONMENT === "test";
  return flag || local;
};
