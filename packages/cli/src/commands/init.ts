import { createWorkspace, devIssue } from "../api.js";
import { loadConfig, saveConfig } from "../config.js";
import {
  buildGoogleAuthorizeUrl,
  captureLoopbackCallback,
  exchangeGoogleCodePublic,
  generatePkce,
  newState,
  openBrowser,
} from "../oauth.js";

export type InitIo = {
  out: (s: string) => void;
  err: (s: string) => void;
};

export type InitOptions = {
  endpoint: string;
  slug: string;
  name?: string;
  adminEmail: string;
  adminName?: string;
  audience: string;
  clientId?: string;
  skipOauth: boolean;
  oauthTimeoutMs?: number;
  fetchIdToken?: (input: { redirectUri: string }) => Promise<string>;
};

export type InitResult = {
  workspaceId: string;
  adminUserId: string;
  email: string;
  mcpUrl: string;
};

const defaultIo: InitIo = {
  out: (s) => process.stdout.write(s),
  err: (s) => process.stderr.write(s),
};

const parseFlag = (argv: readonly string[], name: string): string | undefined => {
  const prefix = `--${name}=`;
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i] ?? "";
    if (a === `--${name}`) return argv[i + 1];
    if (a.startsWith(prefix)) return a.slice(prefix.length);
  }
  return undefined;
};

const hasFlag = (argv: readonly string[], name: string): boolean =>
  argv.some((a) => a === `--${name}` || a.startsWith(`--${name}=`));

const buildMcpUrl = (endpoint: string, workspaceId: string): string => {
  const base = endpoint.replace(/\/+$/, "");
  return `${base}/${workspaceId}/mcp`;
};

const runOauthIdToken = async (opts: {
  clientId: string;
  timeoutMs: number;
  io: InitIo;
}): Promise<string> => {
  const { codeVerifier, codeChallenge } = await generatePkce();
  const state = newState();
  const cb = await captureLoopbackCallback(opts.timeoutMs);

  const cleanup = (signal: NodeJS.SignalsListener) => process.off("SIGINT", signal);
  const sigint = () => {
    opts.io.err("oauth cancelled\n");
    process.exit(130);
  };
  process.on("SIGINT", sigint);

  try {
    const authorizeUrl = buildGoogleAuthorizeUrl({
      clientId: opts.clientId,
      redirectUri: cb.redirectUri,
      codeChallenge,
      state,
      prompt: "select_account",
    });
    opts.io.out("opening browser for Google sign-in...\n");
    opts.io.out(`if it does not open, visit:\n  ${authorizeUrl}\n`);
    openBrowser(authorizeUrl);

    const captured = await cb.awaitCallback();
    if (captured.state !== state) {
      throw new Error("oauth state mismatch");
    }
    const { idToken } = await exchangeGoogleCodePublic({
      clientId: opts.clientId,
      code: captured.code,
      codeVerifier,
      redirectUri: cb.redirectUri,
    });
    return idToken;
  } finally {
    cleanup(sigint);
  }
};

export const runInit = async (opts: InitOptions, io: InitIo = defaultIo): Promise<InitResult> => {
  let googleIdToken: string | undefined;
  if (opts.skipOauth) {
    io.err(
      "warning: --skip-oauth set, no google_id_token sent; issuer must allow unauthed workspace create.\n",
    );
  } else {
    if (opts.fetchIdToken) {
      googleIdToken = await opts.fetchIdToken({ redirectUri: "" });
    } else {
      if (!opts.clientId) {
        throw new Error(
          "missing google client id: set PACT_GOOGLE_CLIENT_ID (or PACT_GOOGLE_CLIENT) or pass --client-id",
        );
      }
      googleIdToken = await runOauthIdToken({
        clientId: opts.clientId,
        timeoutMs: opts.oauthTimeoutMs ?? 300_000,
        io,
      });
    }
  }

  const created = await createWorkspace(opts.endpoint, {
    slug: opts.slug,
    name: opts.name ?? opts.slug,
    adminEmail: opts.adminEmail,
    ...(opts.adminName ? { adminName: opts.adminName } : {}),
    ...(googleIdToken ? { googleIdToken } : {}),
  });

  const issued = await devIssue(opts.endpoint, {
    workspaceId: created.workspaceId,
    email: opts.adminEmail,
    audience: opts.audience,
  });

  const previous = (await loadConfig()) ?? { endpoint: opts.endpoint };
  await saveConfig({
    ...previous,
    endpoint: opts.endpoint,
    workspaceId: created.workspaceId,
    workspaceSlug: opts.slug,
    email: opts.adminEmail,
    accessToken: issued.token,
    accessExpiresAt: issued.exp,
    refreshToken: issued.refreshToken,
    refreshExpiresAt: issued.refreshExpiresAt,
  });

  const mcpUrl = buildMcpUrl(opts.endpoint, created.workspaceId);
  io.out(`workspace ${opts.slug} created (${created.workspaceId})\n`);
  io.out(`signed in as ${opts.adminEmail}\n`);
  io.out(`mcp url: ${mcpUrl}\n`);
  return {
    workspaceId: created.workspaceId,
    adminUserId: created.adminUserId,
    email: opts.adminEmail,
    mcpUrl,
  };
};

export type CliInitDeps = {
  env?: NodeJS.ProcessEnv;
  io?: InitIo;
};

export const runInitFromArgv = async (
  argv: readonly string[],
  deps: CliInitDeps = {},
): Promise<InitResult> => {
  const env = deps.env ?? process.env;
  const io = deps.io ?? defaultIo;
  const endpoint = parseFlag(argv, "endpoint") ?? env.PACT_ENDPOINT ?? "http://localhost:8787";
  const slug = parseFlag(argv, "workspace") ?? env.PACT_SLUG;
  const adminEmail = parseFlag(argv, "email") ?? env.PACT_ADMIN_EMAIL;
  const name = parseFlag(argv, "name") ?? env.PACT_NAME ?? slug;
  const adminName = parseFlag(argv, "admin-name") ?? env.PACT_ADMIN_NAME;
  const audience = env.PACT_AUDIENCE ?? "pact-mcp";
  const clientId =
    parseFlag(argv, "client-id") ?? env.PACT_GOOGLE_CLIENT_ID ?? env.PACT_GOOGLE_CLIENT;
  const skipOauth = hasFlag(argv, "skip-oauth");

  if (!slug) throw new Error("missing workspace slug: pass --workspace or set PACT_SLUG");
  if (!adminEmail) throw new Error("missing admin email: pass --email or set PACT_ADMIN_EMAIL");

  return runInit(
    {
      endpoint,
      slug,
      ...(name ? { name } : {}),
      adminEmail,
      ...(adminName ? { adminName } : {}),
      audience,
      ...(clientId ? { clientId } : {}),
      skipOauth,
    },
    io,
  );
};
