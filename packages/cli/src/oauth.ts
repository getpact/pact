import { spawn } from "node:child_process";
import { createHash, randomBytes as nodeRandomBytes } from "node:crypto";
import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";

const base64url = (bytes: Buffer | Uint8Array): string => Buffer.from(bytes).toString("base64url");

export type PkcePair = {
  codeVerifier: string;
  codeChallenge: string;
};

export const generatePkce = async (): Promise<PkcePair> => {
  const codeVerifier = base64url(nodeRandomBytes(32));
  const hash = createHash("sha256").update(codeVerifier).digest();
  const codeChallenge = base64url(hash);
  return { codeVerifier, codeChallenge };
};

const opener = (): string => {
  switch (process.platform) {
    case "darwin":
      return "open";
    case "win32":
      return "start";
    default:
      return "xdg-open";
  }
};

export const openBrowser = (url: string): void => {
  try {
    spawn(opener(), [url], { detached: true, stdio: "ignore" }).unref();
  } catch {
    // user opens manually
  }
};

export type CapturedCallback = {
  code: string;
  state: string;
};

export const captureLoopbackCallback = async (
  timeoutMs = 120_000,
): Promise<{
  port: number;
  redirectUri: string;
  awaitCallback: () => Promise<CapturedCallback>;
}> => {
  let resolve: (v: CapturedCallback) => void;
  let reject: (e: Error) => void;
  const promise = new Promise<CapturedCallback>((res, rej) => {
    resolve = res;
    reject = rej;
  });

  const server = createServer((req: IncomingMessage, res: ServerResponse) => {
    const url = new URL(req.url ?? "/", "http://localhost");
    if (url.pathname !== "/callback") {
      res.writeHead(404);
      res.end();
      return;
    }
    const code = url.searchParams.get("code");
    const state = url.searchParams.get("state") ?? "";
    if (!code) {
      res.writeHead(400, { "content-type": "text/plain" });
      res.end("missing code");
      return;
    }
    res.writeHead(200, { "content-type": "text/html" });
    res.end("<html><body><h2>pact login complete</h2><p>You can close this tab.</p></body></html>");
    resolve({ code, state });
  });

  await new Promise<void>((r) => server.listen(0, "127.0.0.1", () => r()));
  const port = (server.address() as AddressInfo).port;
  const redirectUri = `http://127.0.0.1:${port}/callback`;

  const timer = setTimeout(() => reject(new Error("login timed out")), timeoutMs);

  const awaitCallback = async () => {
    try {
      const result = await promise;
      return result;
    } finally {
      clearTimeout(timer);
      server.close();
    }
  };

  return { port, redirectUri, awaitCallback };
};

export const buildGoogleAuthorizeUrl = (params: {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  state: string;
  scopes?: string[];
  prompt?: "consent" | "select_account" | "none";
}): string => {
  const url = new URL("https://accounts.google.com/o/oauth2/v2/auth");
  url.searchParams.set("client_id", params.clientId);
  url.searchParams.set("redirect_uri", params.redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("scope", (params.scopes ?? ["openid", "email", "profile"]).join(" "));
  url.searchParams.set("state", params.state);
  url.searchParams.set("code_challenge", params.codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");
  if (params.prompt) url.searchParams.set("prompt", params.prompt);
  return url.toString();
};

export const newState = (): string => base64url(nodeRandomBytes(16));
