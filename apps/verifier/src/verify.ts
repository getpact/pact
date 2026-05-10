import { writeEvent } from "@getpact/audit";
import { verifyJwt } from "@getpact/crypto";
import { createClient, withWorkspace } from "@getpact/db";
import { policies, revokedJtis, workspaces } from "@getpact/db/schema";
import { listVerifyingKeys, loadActiveSigningKey } from "@getpact/keystore";
import { evaluate, type TokenClaims, tryParsePolicy } from "@getpact/policy";
import { and, desc, eq, isNull } from "drizzle-orm";
import { decodeJwt, decodeProtectedHeader } from "jose";
import { cacheKey, type RevocationCache } from "./cache.js";

const REVOCATION_CACHE_TTL = 60;

export type VerifyInput = {
  token: string;
  action: string;
  resource: string;
  audience: string;
};

export type VerifyOutput = {
  allow: boolean;
  reasons: string[];
  sub?: string;
};

const result = (allow: boolean, reasons: string[], sub: string | undefined): VerifyOutput =>
  sub ? { allow, reasons, sub } : { allow, reasons };

const tryAudit = async (
  databaseUrl: string,
  rawMek: Uint8Array,
  workspaceId: string,
  decision: "allow" | "deny",
  reasons: string[],
  actorId: string | undefined,
  input: VerifyInput,
): Promise<void> => {
  try {
    const db = createClient(databaseUrl);
    const [ws] = await db
      .select({ id: workspaces.id, createdAt: workspaces.createdAt })
      .from(workspaces)
      .where(eq(workspaces.id, workspaceId))
      .limit(1);
    if (!ws) return;

    await withWorkspace(db, workspaceId, async (tx) => {
      const auditKey = await loadActiveSigningKey(tx, workspaceId, "audit", rawMek);
      await writeEvent(tx, {
        workspaceId,
        workspaceCreatedAt: ws.createdAt,
        signingKeyId: auditKey.id,
        signingKey: auditKey.privateKey,
        event: {
          actorKind: "user",
          ...(actorId ? { actorId } : {}),
          action: `verify.${input.action}`,
          target: { resource: input.resource, audience: input.audience },
          decision,
          supporting: { reasons },
        },
      });
    });
  } catch {
    // best-effort: never fail the verify call because audit failed
  }
};

export type VerifyDeps = {
  databaseUrl: string;
  rawMek: Uint8Array;
  issuer: string;
  cache?: RevocationCache;
};

export const verifyAction = async (deps: VerifyDeps, input: VerifyInput): Promise<VerifyOutput> => {
  const { databaseUrl, rawMek, cache } = deps;
  let claims: ReturnType<typeof decodeJwt>;
  try {
    claims = decodeJwt(input.token);
  } catch {
    return result(false, ["malformed token"], undefined);
  }
  const workspaceId = claims.org as string | undefined;
  const jti = claims.jti as string | undefined;
  const sub = claims.sub;
  if (!workspaceId || !jti) {
    return result(false, ["malformed token"], sub);
  }

  const db = createClient(databaseUrl);

  let kid: string | undefined;
  try {
    kid = decodeProtectedHeader(input.token).kid;
  } catch {
    return result(false, ["malformed token header"], sub);
  }
  if (!kid) {
    return result(false, ["missing kid"], sub);
  }

  const keys = await withWorkspace(db, workspaceId, (tx) =>
    listVerifyingKeys(tx, workspaceId, "jwt"),
  );
  const matched = keys.find((k) => k.id === kid);
  if (!matched) {
    await tryAudit(databaseUrl, rawMek, workspaceId, "deny", ["unknown kid"], sub, input);
    return result(false, ["unknown kid"], sub);
  }
  try {
    await verifyJwt(input.token, {
      publicKey: matched.publicKey,
      issuer: deps.issuer,
      audience: input.audience,
    });
  } catch {
    await tryAudit(databaseUrl, rawMek, workspaceId, "deny", ["signature invalid"], sub, input);
    return result(false, ["signature invalid"], sub);
  }

  const ck = cacheKey(workspaceId, jti);
  let revokedFlag: boolean | null = null;
  if (cache) {
    revokedFlag = await cache.get(ck);
  }
  if (revokedFlag === null) {
    const revokedRows = await withWorkspace(db, workspaceId, (tx) =>
      tx
        .select({ jti: revokedJtis.jti })
        .from(revokedJtis)
        .where(and(eq(revokedJtis.workspaceId, workspaceId), eq(revokedJtis.jti, jti)))
        .limit(1),
    );
    revokedFlag = revokedRows.length > 0;
    if (cache) {
      await cache.set(ck, revokedFlag, REVOCATION_CACHE_TTL);
    }
  }
  if (revokedFlag === true) {
    await tryAudit(databaseUrl, rawMek, workspaceId, "deny", ["token revoked"], sub, input);
    return result(false, ["token revoked"], sub);
  }

  const policyRow = await withWorkspace(db, workspaceId, (tx) =>
    tx
      .select({ body: policies.body })
      .from(policies)
      .where(and(eq(policies.workspaceId, workspaceId), isNull(policies.replacedAt)))
      .orderBy(desc(policies.version))
      .limit(1),
  );

  if (policyRow.length === 0) {
    await tryAudit(databaseUrl, rawMek, workspaceId, "deny", ["no active policy"], sub, input);
    return result(false, ["no active policy"], sub);
  }

  const tokenClaims: TokenClaims = {
    sub: claims.sub ?? "",
    email: (claims.email as string | undefined) ?? "",
    groups: (claims.groups as string[] | undefined) ?? [],
    roles: (claims.scopes as string[] | undefined) ?? [],
  };

  const policy = tryParsePolicy(policyRow[0]?.body);
  if (!policy) {
    await tryAudit(databaseUrl, rawMek, workspaceId, "deny", ["invalid policy"], sub, input);
    return result(false, ["invalid policy"], sub);
  }
  const evalResult = evaluate({
    token: tokenClaims,
    action: input.action,
    resource: input.resource,
    policy,
  });

  await tryAudit(
    databaseUrl,
    rawMek,
    workspaceId,
    evalResult.allow ? "allow" : "deny",
    evalResult.reasons,
    sub,
    input,
  );
  return result(evalResult.allow, evalResult.reasons, sub);
};
