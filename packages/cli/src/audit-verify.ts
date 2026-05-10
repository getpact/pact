import { computeGenesisHash } from "@getpact/audit/genesis";
import { type AuditJwks, type StoredEvent, verifyChain } from "@getpact/audit/verifier";
import { fromBase64, importPublicSpki } from "@getpact/crypto";
import { refresh } from "./api.js";
import { type CliConfig, saveConfig } from "./config.js";

type EventsResponse = {
  events: Array<StoredEvent & { id: string }>;
  nextCursor: string | null;
};

type KeysResponse = {
  keys: Array<{ id: string; publicKeySpki: string }>;
};

type WorkspaceResponse = {
  id: string;
  slug: string;
  createdAt: string;
};

type ChainResponse = {
  head: { lastHash: string; lastEventId: string | null; updatedAt?: string } | null;
};

const requireConfig = (cfg: CliConfig | null): CliConfig & { workspaceId: string } => {
  if (!cfg) throw new Error("not signed in. run pact init or pact login first.");
  if (!cfg.workspaceId) throw new Error("config missing workspaceId");
  return { ...cfg, workspaceId: cfg.workspaceId };
};

const issuerBase = (cfg: CliConfig): string =>
  cfg.endpoint ?? process.env.PACT_ENDPOINT ?? "http://localhost:8787";

const auditBase = (cfg: CliConfig): string =>
  process.env.PACT_AUDIT_ENDPOINT ?? process.env.PACT_ENDPOINT ?? cfg.endpoint;

const auditAudience = (): string => process.env.PACT_AUDIT_AUDIENCE ?? "pact-audit";

const getAuditToken = async (cfg: CliConfig & { workspaceId: string }): Promise<string> => {
  if (!cfg.refreshToken) {
    throw new Error("config missing refreshToken; run pact login again.");
  }
  let issued: Awaited<ReturnType<typeof refresh>>;
  try {
    issued = await refresh(issuerBase(cfg), {
      workspaceId: cfg.workspaceId,
      refreshToken: cfg.refreshToken,
      audience: auditAudience(),
    });
  } catch {
    throw new Error("could not mint audit token; run pact login with PACT_AUDIENCE=pact-audit");
  }
  await saveConfig({
    ...cfg,
    refreshToken: issued.refreshToken,
    refreshExpiresAt: issued.refreshExpiresAt,
  });
  return issued.token;
};

const get = async <T>(url: string, token: string): Promise<T> => {
  const res = await fetch(url, {
    method: "GET",
    headers: { authorization: `Bearer ${token}` },
  });
  if (!res.ok) throw new Error(`GET ${url} failed: ${res.status}`);
  return (await res.json()) as T;
};

export type VerifyReport =
  | { ok: true; eventsChecked: number; head: string }
  | { ok: false; brokenAt: { index: number; reason: string } };

export const runAuditVerify = async (cfg: CliConfig | null): Promise<VerifyReport> => {
  const config = requireConfig(cfg);
  const workspaceId = config.workspaceId;
  const token = await getAuditToken(config);
  const base = auditBase(config).replace(/\/+$/, "");

  const ws = await get<WorkspaceResponse>(
    `${base}/v1/workspaces/${workspaceId}/audit/workspace`,
    token,
  );
  const chain = await get<ChainResponse>(`${base}/v1/workspaces/${workspaceId}/audit/chain`, token);
  const keysRes = await get<KeysResponse>(`${base}/v1/workspaces/${workspaceId}/audit/keys`, token);
  const jwks: AuditJwks = {};
  for (const k of keysRes.keys) {
    jwks[k.id] = await importPublicSpki(fromBase64(k.publicKeySpki));
  }

  const all: StoredEvent[] = [];
  let cursor: string | null = null;
  for (;;) {
    const url = new URL(`${base}/v1/workspaces/${workspaceId}/audit/events`);
    url.searchParams.set("order", "asc");
    url.searchParams.set("limit", "200");
    if (cursor) url.searchParams.set("cursor", cursor);
    const page = await get<EventsResponse>(url.toString(), token);
    for (const e of page.events) {
      all.push({
        workspaceId: e.workspaceId,
        ts: typeof e.ts === "string" ? e.ts : new Date(e.ts).toISOString(),
        actorKind: e.actorKind,
        actorId: e.actorId,
        action: e.action,
        target: e.target,
        decision: e.decision,
        supporting: e.supporting,
        signingKeyId: e.signingKeyId,
        prevHash: e.prevHash,
        thisHash: e.thisHash,
        signature: e.signature,
      });
    }
    if (!page.nextCursor) break;
    cursor = page.nextCursor;
  }

  const genesis = await computeGenesisHash(workspaceId, new Date(ws.createdAt));
  const result = await verifyChain(all, jwks, genesis);
  if (result.ok) {
    const head = all[all.length - 1]?.thisHash ?? genesis;
    if (chain.head && chain.head.lastHash !== head) {
      return { ok: false, brokenAt: { index: all.length, reason: "chain head mismatch" } };
    }
    if (!chain.head && all.length > 0) {
      return { ok: false, brokenAt: { index: all.length - 1, reason: "missing chain head" } };
    }
    return { ok: true, eventsChecked: all.length, head };
  }
  return result;
};
