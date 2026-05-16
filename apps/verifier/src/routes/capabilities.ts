import { writeEvent } from "@getpact/audit";
import { isStrongSharedSecret, isUuid, timingSafeEqualString } from "@getpact/core";
import {
  type Ed25519PublicJwk,
  fromBase64,
  fromBase64Url,
  sdjwt,
  sha256,
  toHex,
} from "@getpact/crypto";
import { createClient, type Tx, withWorkspace } from "@getpact/db";
import { workspaces } from "@getpact/db/schema";
import { listVerifyingKeys, loadActiveSigningKey } from "@getpact/keystore";
import { eq, sql } from "drizzle-orm";
import type { Context, Hono } from "hono";
import type { ContentfulStatusCode } from "hono/utils/http-status";
import { cacheKey, type RevocationCache } from "../cache.js";

export type CapabilitiesEnv = {
  DATABASE_URL: string;
  MEK: string;
  ENVIRONMENT?: string;
  VERIFIER_SERVICE_TOKEN?: string;
  REVOCATION_CACHE?: {
    get: (k: string) => Promise<string | null>;
    put: (k: string, v: string, o?: { expirationTtl?: number }) => Promise<void>;
  };
};

export type RedeemBody = {
  sd_jwt: string;
  tool_name: string;
  resource: Record<string, unknown>;
};

export type RedeemAllow = {
  allow: true;
  scope_claim: Record<string, unknown>;
  agent_id: string;
  on_behalf_of: string | null;
  audience: string;
  delegation_depth: number;
};

export type RedeemDeny = {
  allow: false;
  reasons: string[];
};

const REVOCATION_CACHE_TTL = 60;

const denyResult = (reasons: string[]): RedeemDeny => ({ allow: false, reasons });

const denyStatus = (reason: string): number => {
  if (reason === "token_revoked" || reason === "token_expired" || reason === "kb_replay_detected")
    return 410;
  if (reason === "max_redeems_exceeded") return 409;
  if (reason === "scope_mismatch" || reason === "tool_mismatch" || reason === "resource_required")
    return 422;
  return 403;
};

const isUniqueViolation = (err: unknown): boolean => {
  if (!err || typeof err !== "object") return false;
  const code = (err as { code?: unknown }).code;
  if (code === "23505") return true;
  const cause = (err as { cause?: unknown }).cause;
  if (cause && typeof cause === "object" && (cause as { code?: unknown }).code === "23505") {
    return true;
  }
  return false;
};

const KB_IAT_SKEW_SECONDS = 300;

const isKbIatAcceptable = (kbIat: unknown): kbIat is number => {
  if (typeof kbIat !== "number" || !Number.isFinite(kbIat) || !Number.isInteger(kbIat)) {
    return false;
  }
  if (kbIat <= 0) return false;
  const now = Math.floor(Date.now() / 1000);
  if (kbIat > now + KB_IAT_SKEW_SECONDS) return false;
  return true;
};

const sdJwtWithoutKb = (compact: string): string => {
  const parts = compact.split("~");
  if (parts.length < 2) return compact;
  const last = parts[parts.length - 1];
  if (last === "" || last === undefined) return compact;
  return `${parts.slice(0, -1).join("~")}~`;
};

const inMemoryCacheFromBinding = (
  binding: CapabilitiesEnv["REVOCATION_CACHE"],
): RevocationCache | undefined => {
  if (!binding) return undefined;
  return {
    get: async (k) => {
      const v = await binding.get(k);
      if (v === null) return null;
      return v === "revoked";
    },
    set: async (k, revoked, ttl) => {
      await binding.put(k, revoked ? "revoked" : "ok", { expirationTtl: ttl });
    },
  };
};

const isPlainObject = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

const matchPattern = (scopeValue: unknown, requested: unknown): boolean => {
  if (typeof scopeValue === "string" && typeof requested === "string") {
    if (scopeValue === requested) return true;
    if (scopeValue.endsWith("*")) {
      const prefix = scopeValue.slice(0, -1);
      return requested.startsWith(prefix);
    }
    if (scopeValue === "*") return true;
    return false;
  }
  if (Array.isArray(scopeValue)) {
    return scopeValue.some((v) => matchPattern(v, requested));
  }
  if (isPlainObject(scopeValue) && isPlainObject(requested)) {
    return matchScope(scopeValue, requested);
  }
  return scopeValue === requested;
};

const matchScope = (scope: Record<string, unknown>, resource: Record<string, unknown>): boolean => {
  for (const [k, v] of Object.entries(scope)) {
    if (k === "tool_name") continue;
    if (!(k in resource)) return false;
    if (!matchPattern(v, resource[k])) return false;
  }
  return true;
};

const exportEd25519PublicJwk = async (
  key: CryptoKey,
  kid: string,
): Promise<Ed25519PublicJwk & { kid: string }> => {
  const jwk = (await crypto.subtle.exportKey("jwk", key)) as JsonWebKey;
  return { kty: "OKP", crv: "Ed25519", x: jwk.x as string, kid };
};

type IssuerPayload = {
  org?: unknown;
  jti?: unknown;
  aud?: unknown;
  exp?: unknown;
  iat?: unknown;
};

const parseIssuerPayload = (compact: string): IssuerPayload | null => {
  try {
    const jws = compact.split("~")[0];
    if (!jws) return null;
    const seg = jws.split(".")[1];
    if (!seg) return null;
    const json = new TextDecoder().decode(fromBase64Url(seg));
    return JSON.parse(json) as IssuerPayload;
  } catch {
    return null;
  }
};

const writeCapabilityAudit = async (
  tx: Tx,
  workspaceId: string,
  workspaceCreatedAt: Date,
  rawMek: Uint8Array,
  action: "agent.capability.redeemed" | "agent.capability.denied",
  agentId: string | undefined,
  target: Record<string, unknown>,
  supporting: Record<string, unknown>,
): Promise<void> => {
  const auditKey = await loadActiveSigningKey(tx, workspaceId, "audit", rawMek);
  await writeEvent(tx, {
    workspaceId,
    workspaceCreatedAt,
    signingKeyId: auditKey.id,
    signingKey: auditKey.privateKey,
    event: {
      actorKind: "agent",
      ...(agentId ? { actorId: agentId } : {}),
      action,
      target,
      decision: action === "agent.capability.redeemed" ? "allow" : "deny",
      supporting,
    },
  });
};

const auditDenyOutsideTx = async (
  databaseUrl: string,
  rawMek: Uint8Array,
  workspaceId: string,
  jti: string,
  reasons: string[],
  toolName: string,
  resource: Record<string, unknown>,
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
      await writeCapabilityAudit(
        tx,
        workspaceId,
        ws.createdAt,
        rawMek,
        "agent.capability.denied",
        undefined,
        { jti, tool_name: toolName, resource },
        { reasons },
      );
    });
  } catch {
    // audit failure here must not change the redeem response
  }
};

const enforceServiceToken = (c: Context): Response | null => {
  const env = c.env as CapabilitiesEnv;
  const serviceToken = env.VERIFIER_SERVICE_TOKEN?.trim();
  if (!serviceToken && env.ENVIRONMENT === "production") {
    return c.json({ error: "misconfigured", message: "verifier service token is required" }, 503);
  }
  if (serviceToken && env.ENVIRONMENT === "production" && !isStrongSharedSecret(serviceToken)) {
    return c.json({ error: "misconfigured", message: "verifier service token is too weak" }, 503);
  }
  if (serviceToken) {
    const expected = `Bearer ${serviceToken}`;
    const received = c.req.header("Authorization") ?? "";
    if (!timingSafeEqualString(received, expected)) {
      return c.json({ error: "unauthorized", message: "invalid service token" }, 401);
    }
  }
  return null;
};

// biome-ignore lint/suspicious/noExplicitAny: route registration is generic over the app instance
export const registerCapabilityRoutes = (app: Hono<any>): void => {
  app.post("/v1/capabilities/:jti/redeem", async (c) => {
    const authFail = enforceServiceToken(c);
    if (authFail) return authFail;

    const pathJti = c.req.param("jti");
    if (!pathJti || !isUuid(pathJti)) {
      return c.json({ error: "bad_request", message: "invalid jti" }, 400);
    }

    let body: RedeemBody;
    try {
      body = await c.req.json<RedeemBody>();
    } catch {
      return c.json({ error: "bad_request", message: "invalid json body" }, 400);
    }
    if (
      !body ||
      typeof body.sd_jwt !== "string" ||
      typeof body.tool_name !== "string" ||
      !isPlainObject(body.resource)
    ) {
      return c.json({ error: "bad_request", message: "missing required fields" }, 400);
    }

    const issuerPayload = parseIssuerPayload(body.sd_jwt);
    if (!issuerPayload) {
      return c.json(denyResult(["malformed_sd_jwt"]), 403);
    }
    const workspaceId = typeof issuerPayload.org === "string" ? issuerPayload.org : null;
    const payloadJti = typeof issuerPayload.jti === "string" ? issuerPayload.jti : null;
    const audience = typeof issuerPayload.aud === "string" ? issuerPayload.aud : null;
    if (!workspaceId || !isUuid(workspaceId) || !payloadJti || !audience) {
      return c.json(denyResult(["malformed_sd_jwt"]), 403);
    }
    if (payloadJti !== pathJti) {
      return c.json(denyResult(["jti_mismatch"]), 400);
    }
    if (
      typeof issuerPayload.exp === "number" &&
      Math.floor(Date.now() / 1000) > issuerPayload.exp
    ) {
      // Even though we have a DB row for status, fail fast on exp.
    }

    const env = c.env as CapabilitiesEnv;
    const rawMek = fromBase64(env.MEK);
    const db = createClient(env.DATABASE_URL);

    const keys = await withWorkspace(db, workspaceId, (tx) =>
      listVerifyingKeys(tx, workspaceId, "jwt"),
    );
    const issuerJwks = {
      keys: await Promise.all(keys.map((k) => exportEd25519PublicJwk(k.publicKey, k.id))),
    };

    let kbClaims: Record<string, unknown> | undefined;
    try {
      const verified = await sdjwt.verifySdJwt({
        compactSdJwt: body.sd_jwt,
        issuerJwks,
        expectedAudience: audience,
        requireKbBinding: true,
      });
      kbClaims = verified.kbClaims;
    } catch (err) {
      const code =
        err && typeof err === "object" && "code" in err && typeof err.code === "string"
          ? err.code
          : "verify_failed";
      const reason = mapSdJwtReason(code);
      await auditDenyOutsideTx(
        env.DATABASE_URL,
        rawMek,
        workspaceId,
        payloadJti,
        [reason],
        body.tool_name,
        body.resource,
      );
      return c.json(denyResult([reason]), 403);
    }

    const kbIatRaw = kbClaims?.iat;
    if (!isKbIatAcceptable(kbIatRaw)) {
      await auditDenyOutsideTx(
        env.DATABASE_URL,
        rawMek,
        workspaceId,
        payloadJti,
        ["kb_iat_invalid"],
        body.tool_name,
        body.resource,
      );
      return c.json(denyResult(["kb_iat_invalid"]), 403);
    }
    const kbIat = kbIatRaw;
    const sdHashDigest = await sha256(new TextEncoder().encode(sdJwtWithoutKb(body.sd_jwt)));
    const sdHashParam = sql`decode(${toHex(sdHashDigest)}, 'hex')`;

    const cache = inMemoryCacheFromBinding(env.REVOCATION_CACHE);
    const ck = cacheKey(workspaceId, payloadJti);
    let cachedRevoked: boolean | null = null;
    if (cache) cachedRevoked = await cache.get(ck);
    if (cachedRevoked === true) {
      await auditDenyOutsideTx(
        env.DATABASE_URL,
        rawMek,
        workspaceId,
        payloadJti,
        ["token_revoked"],
        body.tool_name,
        body.resource,
      );
      return c.json(denyResult(["token_revoked"]), 410);
    }

    const [ws] = await db
      .select({ id: workspaces.id, createdAt: workspaces.createdAt })
      .from(workspaces)
      .where(eq(workspaces.id, workspaceId))
      .limit(1);
    if (!ws) {
      return c.json(denyResult(["unknown_workspace"]), 403);
    }

    type TxResult =
      | {
          ok: true;
          response: RedeemAllow;
        }
      | {
          ok: false;
          status: number;
          reasons: string[];
        };

    const txOutcome = await withWorkspace(db, workspaceId, async (tx): Promise<TxResult> => {
      const revRows = (await tx.execute(
        sql`SELECT 1 FROM revoked_jtis WHERE workspace_id = ${workspaceId} AND jti = ${payloadJti} LIMIT 1`,
      )) as unknown as Array<{ "?column?": number }>;
      if (revRows.length > 0) {
        await writeCapabilityAudit(
          tx,
          workspaceId,
          ws.createdAt,
          rawMek,
          "agent.capability.denied",
          undefined,
          { jti: payloadJti, tool_name: body.tool_name, resource: body.resource },
          { reasons: ["token_revoked"] },
        );
        return { ok: false, status: 410, reasons: ["token_revoked"] };
      }

      let replayDetected = false;
      try {
        await tx.transaction(async (sp) => {
          await sp.execute(
            sql`INSERT INTO kbjwt_replay_log (workspace_id, jti, kb_iat, sd_hash)
                VALUES (${workspaceId}, ${payloadJti}, ${kbIat}, ${sdHashParam})`,
          );
        });
      } catch (insertErr) {
        if (!isUniqueViolation(insertErr)) throw insertErr;
        replayDetected = true;
      }
      if (replayDetected) {
        await writeCapabilityAudit(
          tx,
          workspaceId,
          ws.createdAt,
          rawMek,
          "agent.capability.denied",
          undefined,
          { jti: payloadJti, tool_name: body.tool_name, resource: body.resource },
          { reasons: ["kb_replay_detected"] },
        );
        return { ok: false, status: 410, reasons: ["kb_replay_detected"] };
      }

      const invRows = (await tx.execute(
        sql`SELECT id,
                   COALESCE(agent_id, agent_id_snapshot) AS agent_id,
                   COALESCE(on_behalf_of_user_id, on_behalf_of_user_id_snapshot)
                     AS on_behalf_of_user_id,
                   tool_name, scope_claim,
                   audience, redeem_status, redeem_count, max_redeems, expires_at
            FROM agent_invocations
            WHERE workspace_id = ${workspaceId} AND jti = ${payloadJti}
            FOR UPDATE`,
      )) as unknown as Array<{
        id: string;
        agent_id: string;
        on_behalf_of_user_id: string | null;
        tool_name: string;
        scope_claim: Record<string, unknown>;
        audience: string;
        redeem_status: string;
        redeem_count: number;
        max_redeems: number;
        expires_at: Date | string;
      }>;
      const inv = invRows[0];
      if (!inv) {
        await writeCapabilityAudit(
          tx,
          workspaceId,
          ws.createdAt,
          rawMek,
          "agent.capability.denied",
          undefined,
          { jti: payloadJti, tool_name: body.tool_name, resource: body.resource },
          { reasons: ["unknown_invocation"] },
        );
        return { ok: false, status: 403, reasons: ["unknown_invocation"] };
      }

      if (inv.redeem_status !== "issued") {
        const reason =
          inv.redeem_status === "redeemed"
            ? "already_redeemed"
            : inv.redeem_status === "expired"
              ? "token_expired"
              : inv.redeem_status === "revoked"
                ? "token_revoked"
                : "not_redeemable";
        await writeCapabilityAudit(
          tx,
          workspaceId,
          ws.createdAt,
          rawMek,
          "agent.capability.denied",
          inv.agent_id,
          { jti: payloadJti, tool_name: body.tool_name, resource: body.resource },
          { reasons: [reason] },
        );
        return { ok: false, status: denyStatus(reason), reasons: [reason] };
      }

      const expiresAt = inv.expires_at instanceof Date ? inv.expires_at : new Date(inv.expires_at);
      if (Date.now() > expiresAt.getTime()) {
        await tx.execute(
          sql`UPDATE agent_invocations SET redeem_status = 'expired', deny_reason = 'expired'
              WHERE workspace_id = ${workspaceId} AND jti = ${payloadJti}`,
        );
        await writeCapabilityAudit(
          tx,
          workspaceId,
          ws.createdAt,
          rawMek,
          "agent.capability.denied",
          inv.agent_id,
          { jti: payloadJti, tool_name: body.tool_name, resource: body.resource },
          { reasons: ["token_expired"] },
        );
        return { ok: false, status: 410, reasons: ["token_expired"] };
      }

      if (inv.tool_name !== body.tool_name) {
        await writeCapabilityAudit(
          tx,
          workspaceId,
          ws.createdAt,
          rawMek,
          "agent.capability.denied",
          inv.agent_id,
          { jti: payloadJti, tool_name: body.tool_name, resource: body.resource },
          { reasons: ["tool_mismatch"] },
        );
        return { ok: false, status: 422, reasons: ["tool_mismatch"] };
      }

      if (inv.audience !== audience) {
        await writeCapabilityAudit(
          tx,
          workspaceId,
          ws.createdAt,
          rawMek,
          "agent.capability.denied",
          inv.agent_id,
          { jti: payloadJti, tool_name: body.tool_name, resource: body.resource },
          { reasons: ["audience_mismatch"] },
        );
        return { ok: false, status: 403, reasons: ["audience_mismatch"] };
      }

      if (!matchScope(inv.scope_claim, body.resource)) {
        await writeCapabilityAudit(
          tx,
          workspaceId,
          ws.createdAt,
          rawMek,
          "agent.capability.denied",
          inv.agent_id,
          { jti: payloadJti, tool_name: body.tool_name, resource: body.resource },
          { reasons: ["scope_mismatch"] },
        );
        return { ok: false, status: 422, reasons: ["scope_mismatch"] };
      }

      if (inv.redeem_count >= inv.max_redeems) {
        await writeCapabilityAudit(
          tx,
          workspaceId,
          ws.createdAt,
          rawMek,
          "agent.capability.denied",
          inv.agent_id,
          { jti: payloadJti, tool_name: body.tool_name, resource: body.resource },
          { reasons: ["max_redeems_exceeded"] },
        );
        return { ok: false, status: 409, reasons: ["max_redeems_exceeded"] };
      }

      const newCount = inv.redeem_count + 1;
      const nextStatus = newCount >= inv.max_redeems ? "redeemed" : "issued";
      await tx.execute(
        sql`UPDATE agent_invocations
            SET redeem_count = ${newCount},
                redeem_status = ${nextStatus},
                last_redeemed_at = NOW()
            WHERE workspace_id = ${workspaceId} AND jti = ${payloadJti}`,
      );
      if (nextStatus === "redeemed") {
        await tx.execute(
          sql`INSERT INTO revoked_jtis (workspace_id, jti, reason)
              VALUES (${workspaceId}, ${payloadJti}, 'redeemed')
              ON CONFLICT (workspace_id, jti) DO NOTHING`,
        );
      }

      const depthRows = (await tx.execute(
        sql`SELECT depth FROM delegation_chains
            WHERE workspace_id = ${workspaceId} AND child_jti = ${payloadJti}
            LIMIT 1`,
      )) as unknown as Array<{ depth: number }>;
      const delegationDepth = depthRows[0]?.depth ?? 0;

      await writeCapabilityAudit(
        tx,
        workspaceId,
        ws.createdAt,
        rawMek,
        "agent.capability.redeemed",
        inv.agent_id,
        {
          jti: payloadJti,
          tool_name: body.tool_name,
          resource: body.resource,
          audience,
        },
        {
          scope_claim: inv.scope_claim,
          agent_id: inv.agent_id,
          on_behalf_of: inv.on_behalf_of_user_id,
          delegation_depth: delegationDepth,
        },
      );

      return {
        ok: true,
        response: {
          allow: true,
          scope_claim: inv.scope_claim,
          agent_id: inv.agent_id,
          on_behalf_of: inv.on_behalf_of_user_id,
          audience,
          delegation_depth: delegationDepth,
        },
      };
    });

    if (txOutcome.ok) {
      return c.json(txOutcome.response, 200);
    }
    if (cache && txOutcome.reasons.includes("token_revoked")) {
      await cache.set(ck, true, REVOCATION_CACHE_TTL);
    }
    return c.json(denyResult(txOutcome.reasons), txOutcome.status as ContentfulStatusCode);
  });
};

const mapSdJwtReason = (code: string): string => {
  switch (code) {
    case "kb_required":
      return "kb_jwt_missing";
    case "kb_sig_invalid":
    case "kb_without_cnf":
    case "kb_wrong_typ":
    case "kb_sd_hash_mismatch":
      return "cnf_binding_invalid";
    case "kb_wrong_audience":
      return "audience_mismatch";
    case "kb_wrong_nonce":
      return "nonce_mismatch";
    case "issuer_sig_invalid":
      return "issuer_sig_invalid";
    case "unknown_kid":
    case "missing_kid":
      return "issuer_key_unknown";
    case "disclosure_hash_mismatch":
    case "bad_disclosure":
    case "disclosure_duplicate":
    case "missing_sd":
      return "disclosure_invalid";
    default:
      return "denied";
  }
};
