import { exportAesKey, generateAesKey, toBase64 } from "@getpact/crypto";

export type TestEnv = {
  DATABASE_URL: string;
  MEK: string;
  GOOGLE_OAUTH_CLIENT_ID: string;
  GOOGLE_OAUTH_CLIENT_SECRET: string;
  ISSUER_BASE_URL: string;
  ENVIRONMENT: string;
  ENABLE_DEV_ISSUE: string;
  PACT_ALLOW_UNAUTHED_WORKSPACE_CREATE: string;
  ADMIN_AUDIENCE: string;
  AUDIT_AUDIENCE: string;
  MCP_AUDIENCE: string;
};

const LOCAL_HOSTS = new Set(["localhost", "127.0.0.1", "0.0.0.0", "::1"]);

const isLocalHost = (host: string): boolean => {
  if (LOCAL_HOSTS.has(host)) return true;
  if (host.endsWith(".local")) return true;
  return false;
};

const assertLocalDatabase = (databaseUrl: string): void => {
  if (process.env.NODE_ENV === "production") {
    throw new Error("refusing to enable workspace bypass in NODE_ENV=production");
  }
  let url: URL;
  try {
    url = new URL(databaseUrl);
  } catch {
    throw new Error("refusing to enable workspace bypass against unparsable database url");
  }
  const host = url.hostname;
  if (isLocalHost(host)) return;
  if (host === "") {
    const sockHost = url.searchParams.get("host");
    if (sockHost?.startsWith("/")) return;
  }
  throw new Error(
    `refusing to enable workspace bypass against non-test database (host=${host || "<empty>"})`,
  );
};

export const buildTestEnv = async (databaseUrl: string): Promise<TestEnv> => {
  assertLocalDatabase(databaseUrl);
  const mek = await generateAesKey();
  return {
    DATABASE_URL: databaseUrl,
    MEK: toBase64(await exportAesKey(mek)),
    GOOGLE_OAUTH_CLIENT_ID: "test",
    GOOGLE_OAUTH_CLIENT_SECRET: "test",
    ISSUER_BASE_URL: "https://issuer.test/acme",
    ENVIRONMENT: "test",
    ENABLE_DEV_ISSUE: "true",
    PACT_ALLOW_UNAUTHED_WORKSPACE_CREATE: "true",
    ADMIN_AUDIENCE: "pact-admin",
    AUDIT_AUDIENCE: "pact-audit",
    MCP_AUDIENCE: "pact-mcp",
  };
};

export type IssuerApp = {
  request: (
    path: string,
    init?: RequestInit,
    env?: Record<string, unknown>,
  ) => Promise<Response> | Response;
};

export type CreatedWorkspace = {
  workspaceId: string;
  adminUserId: string;
  jwtKeyId?: string;
  auditKeyId?: string;
  provenanceKeyId?: string;
  adapterDriveKeyId?: string;
};

export type CreateWorkspaceInput = {
  slug: string;
  name?: string;
  adminEmail: string;
};

export const createTestWorkspace = async (
  issuer: IssuerApp,
  env: TestEnv,
  input: CreateWorkspaceInput,
): Promise<CreatedWorkspace> => {
  const clientIp = `127.0.0.${Math.floor(Math.random() * 200) + 1}`;
  const res = await Promise.resolve(
    issuer.request(
      "/v1/workspaces",
      {
        method: "POST",
        headers: { "content-type": "application/json", "x-forwarded-for": clientIp },
        body: JSON.stringify({
          slug: input.slug,
          name: input.name ?? input.slug,
          adminEmail: input.adminEmail,
        }),
      },
      env,
    ),
  );
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`workspace create failed (${res.status}): ${text}`);
  }
  return (await res.json()) as CreatedWorkspace;
};

export type IssueTestTokenInput = {
  workspaceId: string;
  email: string;
  audience: string;
};

export type IssuedTestToken = {
  token: string;
  jti: string;
  exp: number;
  userId: string;
  refreshToken: string;
  refreshExpiresAt: string;
};

export const issueTestToken = async (
  issuer: IssuerApp,
  env: TestEnv,
  input: IssueTestTokenInput,
): Promise<IssuedTestToken> => {
  const clientIp = `127.0.1.${Math.floor(Math.random() * 200) + 1}`;
  const res = await Promise.resolve(
    issuer.request(
      "/v1/dev/issue",
      {
        method: "POST",
        headers: { "content-type": "application/json", "x-forwarded-for": clientIp },
        body: JSON.stringify(input),
      },
      env,
    ),
  );
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`token issue failed (${res.status}): ${text}`);
  }
  return (await res.json()) as IssuedTestToken;
};

export const uniqueSlug = (prefix: string): string =>
  `${prefix}-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`;
