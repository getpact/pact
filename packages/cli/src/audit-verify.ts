import { createHmac, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import { computeGenesisHash } from "@getpact/audit/genesis";
import { type AuditJwks, type StoredEvent, verifyChain } from "@getpact/audit/verifier";
import { type Ed25519PublicJwk, importPublicJwkEd25519 } from "@getpact/crypto";
import { refresh } from "./api.js";
import { type CliConfig, saveConfig } from "./config.js";

type EventsResponse = {
  events: Array<StoredEvent & { id: string }>;
  nextCursor: string | null;
};

type JwksResponse = {
  keys: Ed25519PublicJwk[];
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
const expectedAuditHead = (): string | undefined => process.env.PACT_AUDIT_EXPECTED_HEAD;
const checkpointFile = (): string | undefined => process.env.PACT_AUDIT_CHECKPOINT_FILE;
const checkpointSecret = (): string | undefined => process.env.PACT_AUDIT_CHECKPOINT_SECRET;

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

export type AuditCheckpoint = {
  version: 1;
  workspaceId: string;
  head: string;
  eventsChecked: number;
  createdAt: string;
  signature: string;
};

const checkpointPayload = (checkpoint: Omit<AuditCheckpoint, "signature">): string =>
  JSON.stringify(checkpoint);

const signCheckpoint = (checkpoint: Omit<AuditCheckpoint, "signature">): AuditCheckpoint => {
  const secret = checkpointSecret();
  if (!secret) throw new Error("missing PACT_AUDIT_CHECKPOINT_SECRET");
  const signature = createHmac("sha256", secret)
    .update(checkpointPayload(checkpoint))
    .digest("base64url");
  return { ...checkpoint, signature: `hmac-sha256:${signature}` };
};

const loadCheckpoint = (): AuditCheckpoint | null => {
  const file = checkpointFile();
  if (!file) return null;
  const parsed = JSON.parse(readFileSync(file, "utf8")) as Partial<AuditCheckpoint>;
  if (
    parsed.version !== 1 ||
    typeof parsed.workspaceId !== "string" ||
    typeof parsed.head !== "string" ||
    typeof parsed.eventsChecked !== "number" ||
    typeof parsed.createdAt !== "string" ||
    typeof parsed.signature !== "string"
  ) {
    throw new Error("invalid audit checkpoint");
  }
  return parsed as AuditCheckpoint;
};

const verifyCheckpointSignature = (checkpoint: AuditCheckpoint): boolean => {
  const expected = signCheckpoint({
    version: checkpoint.version,
    workspaceId: checkpoint.workspaceId,
    head: checkpoint.head,
    eventsChecked: checkpoint.eventsChecked,
    createdAt: checkpoint.createdAt,
  }).signature;
  const actualBytes = new TextEncoder().encode(checkpoint.signature);
  const expectedBytes = new TextEncoder().encode(expected);
  return actualBytes.length === expectedBytes.length && timingSafeEqual(actualBytes, expectedBytes);
};

export const runAuditVerify = async (
  cfg: CliConfig | null,
  opts: { externalCheckpoint?: boolean } = {},
): Promise<VerifyReport> => {
  const checkExternalCheckpoint = opts.externalCheckpoint ?? true;
  const config = requireConfig(cfg);
  const workspaceId = config.workspaceId;
  const token = await getAuditToken(config);
  const base = auditBase(config).replace(/\/+$/, "");

  const ws = await get<WorkspaceResponse>(
    `${base}/v1/workspaces/${workspaceId}/audit/workspace`,
    token,
  );

  // Fetch audit verifying keys from the issuer's public JWKS, not audit-api.
  // This keeps the chain trustworthy if audit-api is compromised: a tampered
  // audit-api cannot mint new signing keys, only the issuer can.
  const issuerUrl = issuerBase(config).replace(/\/+$/, "");
  const jwksRes = await fetch(
    `${issuerUrl}/v1/workspaces/${workspaceId}/.well-known/audit-jwks.json`,
  );
  if (!jwksRes.ok) throw new Error(`audit jwks fetch failed: ${jwksRes.status}`);
  const jwksBody = (await jwksRes.json()) as JwksResponse;
  const jwks: AuditJwks = {};
  for (const jwk of jwksBody.keys) {
    if (!jwk.kid) continue;
    jwks[jwk.kid] = await importPublicJwkEd25519(jwk);
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
        ts: e.ts,
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

  const chain = await get<ChainResponse>(`${base}/v1/workspaces/${workspaceId}/audit/chain`, token);
  const genesis = await computeGenesisHash(workspaceId, new Date(ws.createdAt));
  const result = await verifyChain(all, jwks, genesis);
  if (result.ok) {
    const head = all[all.length - 1]?.thisHash ?? genesis;
    const expectedHead = expectedAuditHead();
    if (expectedHead && expectedHead !== head) {
      return { ok: false, brokenAt: { index: all.length, reason: "expected head mismatch" } };
    }
    if (checkExternalCheckpoint) {
      const checkpoint = loadCheckpoint();
      if (checkpoint) {
        if (checkpoint.workspaceId !== workspaceId) {
          return {
            ok: false,
            brokenAt: { index: all.length, reason: "checkpoint workspace mismatch" },
          };
        }
        if (!verifyCheckpointSignature(checkpoint)) {
          return {
            ok: false,
            brokenAt: { index: all.length, reason: "checkpoint signature mismatch" },
          };
        }
        if (checkpoint.head !== head) {
          return { ok: false, brokenAt: { index: all.length, reason: "checkpoint head mismatch" } };
        }
      }
    }
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

export const runAuditCheckpoint = async (cfg: CliConfig | null): Promise<AuditCheckpoint> => {
  const config = requireConfig(cfg);
  const report = await runAuditVerify(config, { externalCheckpoint: false });
  if (!report.ok) {
    throw new Error(
      `audit chain broken at index ${report.brokenAt.index}: ${report.brokenAt.reason}`,
    );
  }
  return signCheckpoint({
    version: 1,
    workspaceId: config.workspaceId,
    head: report.head,
    eventsChecked: report.eventsChecked,
    createdAt: new Date().toISOString(),
  });
};
