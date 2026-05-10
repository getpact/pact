import { computeGenesisHash } from "@getpact/audit/genesis";
import { type AuditJwks, type StoredEvent, verifyChain } from "@getpact/audit/verifier";
import { fromBase64, importPublicSpki } from "@getpact/crypto";
import type { CliConfig } from "./config.js";

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

const requireToken = (cfg: CliConfig | null): { token: string; workspaceId: string } => {
  if (!cfg?.accessToken) throw new Error("not signed in. run pact init or pact login first.");
  if (!cfg.workspaceId) throw new Error("config missing workspaceId");
  return { token: cfg.accessToken, workspaceId: cfg.workspaceId };
};

const auditBase = (): string =>
  process.env.PACT_AUDIT_ENDPOINT ?? process.env.PACT_ENDPOINT ?? "http://localhost:8787";

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
  const { token, workspaceId } = requireToken(cfg);
  const base = auditBase().replace(/\/+$/, "");

  const ws = await get<WorkspaceResponse>(
    `${base}/v1/workspaces/${workspaceId}/audit/workspace`,
    token,
  );
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
    return { ok: true, eventsChecked: all.length, head };
  }
  return result;
};
