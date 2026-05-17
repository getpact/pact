// Mode B reference brain.
//
// Drop verifyPactToken into your existing brain via one Hono handler. This file is the
// canonical "I am a downstream brain, here is the only authn/authz I do"
// example. The MCP-side issuer has already minted an SD-JWT; the brain just
// checks that the bearer matches our audience, the requested tool, and the
// scope claim before it returns anything.

import {
  type JwksCache,
  type ReplayCache,
  type VerifyDenied,
  type VerifyResult,
  verifyPactToken,
} from "@getpact/verifier-sdk";
import { Hono } from "hono";

const dec = new TextDecoder();

const fromBase64Url = (s: string): Uint8Array => {
  const pad = s.length % 4;
  const padded = pad === 0 ? s : s + "=".repeat(4 - pad);
  const b64 = padded.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i += 1) out[i] = bin.charCodeAt(i);
  return out;
};

// Pulls the named disclosure value from an already-verified SD-JWT. The crypto
// is gated by `verifyPactToken`; this helper just decodes the trailing tilde
// segments and looks up a top-level disclosure by name. Treats parse errors as
// "not present" so a malformed disclosure cannot widen access.
const readDisclosure = <T>(sdJwt: string, name: string): T | undefined => {
  const parts = sdJwt.split("~");
  if (parts.length < 2) return undefined;
  const last = parts[parts.length - 1];
  const end =
    last === "" || (last && last.split(".").length === 3) ? parts.length - 1 : parts.length;
  for (let i = 1; i < end; i += 1) {
    const tok = parts[i];
    if (!tok || tok.length === 0) continue;
    let arr: unknown;
    try {
      arr = JSON.parse(dec.decode(fromBase64Url(tok)));
    } catch {
      continue;
    }
    if (!Array.isArray(arr) || arr.length !== 3) continue;
    if (arr[1] === name) return arr[2] as T;
  }
  return undefined;
};

export type BrainEnv = {
  jwksUri: string;
  audience: string;
  toolName: string;
  jwksCache?: JwksCache;
  replayCache?: ReplayCache;
  documents: BrainDocument[];
  now?: () => number;
};

export type BrainDocument = {
  id: string;
  title: string;
  snippet: string;
};

export type BrainQueryBody = {
  q: string;
};

const inMemoryReplayCache = (): ReplayCache => {
  const seen = new Set<string>();
  return {
    has: async (k) => seen.has(k),
    add: async (k) => {
      seen.add(k);
    },
  };
};

const asStringArray = (value: unknown): string[] | null => {
  if (!Array.isArray(value)) return null;
  const out: string[] = [];
  for (const v of value) {
    if (typeof v !== "string") return null;
    out.push(v);
  }
  return out;
};

// Pulls the per-user document allowlist out of the verified token. v0.1 issues
// a `policy` disclosure shaped as `{ docs: string[] }`. We also accept
// `scope.docs` for tokens that fold the allowlist into the scope claim and
// pass a matching resource on the brain side.
const extractAllowedDocs = (
  scopeClaim: Record<string, unknown>,
  presented: string,
): string[] | null => {
  const policy = readDisclosure<unknown>(presented, "policy");
  if (policy && typeof policy === "object" && !Array.isArray(policy)) {
    const docs = asStringArray((policy as Record<string, unknown>).docs);
    if (docs !== null) return docs;
  }
  const fromScope = asStringArray(scopeClaim.docs);
  if (fromScope !== null) return fromScope;
  return null;
};

const deniedBody = (reason: VerifyDenied["reason"], detail?: string): Record<string, unknown> => ({
  allow: false,
  reason,
  ...(detail !== undefined ? { detail } : {}),
});

export const buildBrainApp = (env: BrainEnv) => {
  const replayCache = env.replayCache ?? inMemoryReplayCache();
  const app = new Hono();

  app.post("/brain/query", async (c) => {
    const auth = c.req.header("Authorization") ?? "";
    if (!auth.toLowerCase().startsWith("bearer ")) {
      return c.json(deniedBody("invalid_format", "missing bearer token"), 401);
    }
    const sdJwtFromAuth = auth.slice("bearer ".length).trim();
    if (sdJwtFromAuth.length === 0) {
      return c.json(deniedBody("invalid_format", "empty bearer token"), 401);
    }

    // Many MCP clients ship the KB-JWT in a sidecar header instead of glueing
    // it onto the trailing slot of the compact SD-JWT. Accept either form.
    const sidecarKb = c.req.header("X-Pact-KB-JWT");
    const presented = (() => {
      if (!sidecarKb || sidecarKb.length === 0) return sdJwtFromAuth;
      if (sdJwtFromAuth.endsWith("~")) return `${sdJwtFromAuth}${sidecarKb}`;
      return sdJwtFromAuth;
    })();

    let body: BrainQueryBody;
    try {
      body = (await c.req.json()) as BrainQueryBody;
    } catch {
      return c.json({ allow: false, reason: "bad_request", detail: "invalid json" }, 400);
    }
    if (!body || typeof body.q !== "string") {
      return c.json({ allow: false, reason: "bad_request", detail: "missing q" }, 400);
    }

    const verifyOpts = {
      jwksUri: env.jwksUri,
      audience: env.audience,
      toolName: env.toolName,
      replayCache,
      ...(env.jwksCache ? { jwksCache: env.jwksCache } : {}),
      ...(env.now ? { now: env.now } : {}),
    };
    const result = await verifyPactToken(presented, verifyOpts);
    if (!result.ok) {
      const denied = result as VerifyDenied;
      const status = denied.reason === "kb_replay_detected" ? 410 : 403;
      return c.json(deniedBody(denied.reason, denied.detail), status);
    }

    const ok = result as VerifyResult;
    const allowedDocs = extractAllowedDocs(ok.scopeClaim, presented);
    const hits = env.documents.filter((doc) =>
      allowedDocs === null ? false : allowedDocs.includes(doc.id),
    );
    const filtered = hits.map((doc) => ({
      id: doc.id,
      title: doc.title,
      snippet: `${body.q} :: ${doc.snippet}`,
    }));
    return c.json({
      allow: true,
      agent_id: ok.agentId ?? null,
      workspace_id: ok.workspaceId,
      audience: ok.audience,
      jti: ok.jti,
      hits: filtered,
    });
  });

  app.get("/healthz", (c) => c.json({ ok: true }));

  return app;
};

export type BrainApp = ReturnType<typeof buildBrainApp>;
