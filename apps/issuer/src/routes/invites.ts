import { writeEvent } from "@getpact/audit";
import { canonicalizeEmail, isUuid } from "@getpact/core";
import { type Ed25519PublicJwk, fromBase64Url, sdjwt } from "@getpact/crypto";
import { createClient, type Tx, withWorkspace } from "@getpact/db";
import { invites, workspaces } from "@getpact/db/schema";
import { listVerifyingKeys, loadActiveSigningKey } from "@getpact/keystore";
import { eq, sql } from "drizzle-orm";
import type { Hono } from "hono";
import { createRemoteJWKSet, exportJWK, jwtVerify } from "jose";
import { decodeMek, type Env } from "../env.js";

type WorkspaceRow = typeof workspaces.$inferSelect;

const INVITE_AUDIENCE = "pact-invite";
const GOOGLE_JWKS_URI = "https://www.googleapis.com/oauth2/v3/certs";
const GOOGLE_ISSUER = "https://accounts.google.com";
const ACCEPT_AUDIENCE_DEFAULT = "pact-mcp";

const isRecord = (v: unknown): v is Record<string, unknown> =>
  typeof v === "object" && v !== null && !Array.isArray(v);

type ParsedAccept = {
  inviteToken: string;
  googleIdToken: string;
  cnfJwk: sdjwt.CnfJwk;
  audience: string;
};

const parseAccept = (body: unknown): ParsedAccept | string => {
  if (!isRecord(body)) return "body must be an object";
  if (typeof body.invite_token !== "string" || body.invite_token.length === 0) {
    return "invite_token is required";
  }
  if (typeof body.google_id_token !== "string" || body.google_id_token.length === 0) {
    return "google_id_token is required";
  }
  if (!isRecord(body.cnf_jwk)) {
    return "cnf_jwk is required and must be an object";
  }
  const j = body.cnf_jwk;
  if (j.kty !== "OKP" || j.crv !== "Ed25519" || typeof j.x !== "string") {
    return "cnf_jwk must be an Ed25519 OKP jwk";
  }
  const audience =
    typeof body.audience === "string" && body.audience.length > 0
      ? body.audience
      : ACCEPT_AUDIENCE_DEFAULT;
  return {
    inviteToken: body.invite_token,
    googleIdToken: body.google_id_token,
    cnfJwk: { kty: "OKP", crv: "Ed25519", x: j.x },
    audience,
  };
};

const exportEd25519PublicJwk = async (
  key: CryptoKey,
  kid: string,
): Promise<Ed25519PublicJwk & { kid: string; alg: string }> => {
  const jwk = (await exportJWK(key)) as { x?: string };
  return { kty: "OKP", crv: "Ed25519", x: jwk.x as string, kid, alg: "EdDSA" };
};

type InvitePayload = {
  iss: string;
  sub: string;
  aud: string;
  org: string;
  jti: string;
  email: string;
  group_ids: string[];
  scope: Record<string, unknown>;
  iat: number;
  exp: number;
};

const td = new TextDecoder();
const parseUnverifiedJws = (token: string): { header: unknown; payload: unknown } | null => {
  const parts = token.split(".");
  if (parts.length !== 3) return null;
  try {
    const header = JSON.parse(td.decode(fromBase64Url(parts[0] ?? "")));
    const payload = JSON.parse(td.decode(fromBase64Url(parts[1] ?? "")));
    return { header, payload };
  } catch {
    return null;
  }
};

const isInvitePayload = (v: unknown): v is InvitePayload => {
  if (!isRecord(v)) return false;
  return (
    typeof v.org === "string" &&
    typeof v.jti === "string" &&
    typeof v.email === "string" &&
    typeof v.iat === "number" &&
    typeof v.exp === "number"
  );
};

const verifyInviteToken = async (
  tx: Tx,
  workspaceId: string,
  issuerUrl: string,
  inviteToken: string,
): Promise<InvitePayload | { error: string }> => {
  const decoded = parseUnverifiedJws(inviteToken);
  if (!decoded || !isRecord(decoded.header)) {
    return { error: "invite_token_malformed" };
  }
  const kid = typeof decoded.header.kid === "string" ? decoded.header.kid : undefined;
  if (!kid) return { error: "invite_token_missing_kid" };

  const keys = await listVerifyingKeys(tx, workspaceId, "jwt");
  const localJwks = {
    keys: await Promise.all(keys.map((k) => exportEd25519PublicJwk(k.publicKey, k.id))),
  };
  const found = localJwks.keys.find((k) => k.kid === kid);
  if (!found) return { error: "invite_token_unknown_kid" };

  try {
    const cryptoKey = await crypto.subtle.importKey("jwk", found, { name: "Ed25519" }, true, [
      "verify",
    ]);
    const { payload } = await jwtVerify(inviteToken, cryptoKey, {
      issuer: issuerUrl,
      audience: INVITE_AUDIENCE,
      algorithms: ["EdDSA"],
    });
    if (!isInvitePayload(payload)) return { error: "invite_token_payload_invalid" };
    if (payload.org !== workspaceId) return { error: "invite_token_workspace_mismatch" };
    return payload;
  } catch {
    return { error: "invite_token_signature_invalid" };
  }
};

const writeInviteAcceptAudit = async (
  tx: Tx,
  input: {
    workspaceId: string;
    ws: WorkspaceRow;
    rawMek: Uint8Array;
    actorUserId: string | null;
    action: string;
    target: unknown;
    decision: "allow" | "deny";
    supporting?: unknown;
  },
): Promise<void> => {
  const auditKey = await loadActiveSigningKey(tx, input.workspaceId, "audit", input.rawMek);
  await writeEvent(tx, {
    workspaceId: input.workspaceId,
    workspaceCreatedAt: input.ws.createdAt,
    signingKeyId: auditKey.id,
    signingKey: auditKey.privateKey,
    event: {
      actorKind: "user",
      ...(input.actorUserId ? { actorId: input.actorUserId } : {}),
      action: input.action,
      target: input.target,
      decision: input.decision,
      supporting: input.supporting ?? null,
    },
  });
};

const denyOutsideTx = async (
  env: Env,
  workspaceId: string,
  action: string,
  target: unknown,
  supporting: Record<string, unknown>,
): Promise<void> => {
  try {
    const db = createClient(env.DATABASE_URL);
    const rawMek = decodeMek(env);
    const [ws] = await db.select().from(workspaces).where(eq(workspaces.id, workspaceId)).limit(1);
    if (!ws) return;
    await withWorkspace(db, workspaceId, (tx) =>
      writeInviteAcceptAudit(tx, {
        workspaceId,
        ws,
        rawMek,
        actorUserId: null,
        action,
        target,
        decision: "deny",
        supporting,
      }),
    );
  } catch {
    // audit failure must not change the response
  }
};

export const registerInviteAcceptRoutes = <T extends { Bindings: Env }>(app: Hono<T>): void => {
  app.post("/v1/workspaces/:workspaceId/invites/accept", async (c) => {
    const workspaceId = c.req.param("workspaceId");
    if (!workspaceId || !isUuid(workspaceId)) {
      return c.json({ error: "invalid_request", message: "workspace id must be a uuid" }, 400);
    }

    let raw: unknown;
    try {
      raw = await c.req.json();
    } catch {
      return c.json({ error: "invalid_body", message: "invalid json body" }, 400);
    }
    const parsed = parseAccept(raw);
    if (typeof parsed === "string") {
      return c.json({ error: "invalid_body", message: parsed }, 400);
    }

    const db = createClient(c.env.DATABASE_URL);
    const rawMek = decodeMek(c.env);

    const [ws] = await db.select().from(workspaces).where(eq(workspaces.id, workspaceId)).limit(1);
    if (!ws) {
      return c.json({ error: "not_found", message: "workspace not found" }, 404);
    }

    const verified = await withWorkspace(db, workspaceId, (tx) =>
      verifyInviteToken(tx, workspaceId, c.env.ISSUER_BASE_URL, parsed.inviteToken),
    );
    if ("error" in verified) {
      await denyOutsideTx(
        c.env as Env,
        workspaceId,
        "invite.accept.denied",
        { reason: verified.error },
        {
          audience: parsed.audience,
        },
      );
      return c.json({ error: "unauthorized", message: verified.error }, 401);
    }

    const invitePayload = verified;
    if (invitePayload.exp * 1000 <= Date.now()) {
      await denyOutsideTx(
        c.env as Env,
        workspaceId,
        "invite.accept.denied",
        { jti: invitePayload.jti, email: invitePayload.email },
        { reason: "invite_expired" },
      );
      return c.json({ error: "forbidden", message: "invite_expired" }, 403);
    }

    const googleJwks = createRemoteJWKSet(new URL(GOOGLE_JWKS_URI));
    let googlePayload: Awaited<ReturnType<typeof jwtVerify>>["payload"];
    try {
      ({ payload: googlePayload } = await jwtVerify(parsed.googleIdToken, googleJwks, {
        issuer: GOOGLE_ISSUER,
        audience: c.env.GOOGLE_OAUTH_CLIENT_ID,
        algorithms: ["RS256"],
      }));
    } catch {
      await denyOutsideTx(
        c.env as Env,
        workspaceId,
        "invite.accept.denied",
        { jti: invitePayload.jti, email: invitePayload.email },
        { reason: "google_id_token_invalid" },
      );
      return c.json({ error: "unauthorized", message: "google_id_token_invalid" }, 401);
    }

    const googleEmail =
      typeof googlePayload.email === "string" ? canonicalizeEmail(googlePayload.email) : null;
    const googleSub = typeof googlePayload.sub === "string" ? googlePayload.sub : null;
    const emailVerified = googlePayload.email_verified === true;
    if (!googleEmail || !googleSub || !emailVerified) {
      await denyOutsideTx(
        c.env as Env,
        workspaceId,
        "invite.accept.denied",
        { jti: invitePayload.jti, email: invitePayload.email },
        { reason: "google_email_not_verified" },
      );
      return c.json({ error: "forbidden", message: "google_email_not_verified" }, 403);
    }
    if (googleEmail !== canonicalizeEmail(invitePayload.email)) {
      await denyOutsideTx(
        c.env as Env,
        workspaceId,
        "invite.accept.denied",
        { jti: invitePayload.jti, email: invitePayload.email },
        { reason: "email_binding_mismatch", google_email: googleEmail },
      );
      return c.json({ error: "forbidden", message: "email_binding_mismatch" }, 403);
    }

    type AcceptResult =
      | {
          kind: "ok";
          capability: string;
          expiresAt: number;
          userId: string;
        }
      | { kind: "already_consumed" }
      | { kind: "error"; status: number; code: string; message: string };

    try {
      const result = await withWorkspace(db, workspaceId, async (tx): Promise<AcceptResult> => {
        const claim = (await tx.execute(
          sql`UPDATE invites
              SET consumed_at = NOW(),
                  consumed_user_id_snapshot = NULL,
                  status = 'consumed'
              WHERE workspace_id = ${workspaceId}
                AND jti = ${invitePayload.jti}::uuid
                AND consumed_at IS NULL
              RETURNING id, group_ids`,
        )) as Array<{ id: string; group_ids: string[] }>;
        if (claim.length === 0) {
          return { kind: "already_consumed" };
        }
        const claimed = claim[0];
        if (!claimed) {
          return {
            kind: "error",
            status: 500,
            code: "internal_error",
            message: "invite claim returned no row",
          };
        }

        const upserted = (await tx.execute(
          sql`INSERT INTO users (workspace_id, email, google_sub)
              VALUES (${workspaceId}, ${googleEmail}, ${googleSub})
              ON CONFLICT (workspace_id, email)
              DO UPDATE SET google_sub = COALESCE(users.google_sub, EXCLUDED.google_sub)
              RETURNING id`,
        )) as Array<{ id: string }>;
        const userId = upserted[0]?.id;
        if (!userId) {
          return {
            kind: "error",
            status: 500,
            code: "internal_error",
            message: "user upsert returned no row",
          };
        }

        await tx
          .update(invites)
          .set({ consumedUserId: userId, consumedUserIdSnapshot: userId })
          .where(eq(invites.id, claimed.id));

        if (claimed.group_ids.length > 0) {
          for (const gid of claimed.group_ids) {
            await tx.execute(
              sql`INSERT INTO group_members (workspace_id, group_id, user_id)
                  VALUES (${workspaceId}, ${gid}::uuid, ${userId}::uuid)
                  ON CONFLICT (group_id, user_id)
                  DO UPDATE SET revoked_at = NULL, added_at = now()`,
            );
          }
        }

        const jwtKey = await loadActiveSigningKey(tx, workspaceId, "jwt", rawMek);
        const newJti = crypto.randomUUID();
        const iat = Math.floor(Date.now() / 1000);
        const exp = iat + invitePayload.exp - invitePayload.iat;

        const issuerClaims: Record<string, unknown> = {
          iss: c.env.ISSUER_BASE_URL,
          sub: userId,
          aud: parsed.audience,
          iat,
          exp,
          jti: newJti,
          org: workspaceId,
          email: googleEmail,
          mode: "invite",
          invite_jti: invitePayload.jti,
        };
        const compactSdJwt = await sdjwt.issueSdJwt({
          issuerPrivateKey: jwtKey.privateKey,
          issuerKid: jwtKey.id,
          issuerClaims,
          disclosures: [
            { name: "policy", value: { scope: invitePayload.scope } },
            { name: "payload", value: { user_id: userId, email: googleEmail } },
          ],
          cnfJkt: parsed.cnfJwk,
        });

        await writeInviteAcceptAudit(tx, {
          workspaceId,
          ws,
          rawMek,
          actorUserId: userId,
          action: "invite.consumed",
          target: {
            invite_id: claimed.id,
            jti: invitePayload.jti,
            email: googleEmail,
            user_id: userId,
            group_ids: claimed.group_ids,
          },
          decision: "allow",
          supporting: {
            new_jti: newJti,
            audience: parsed.audience,
            ttl_seconds: invitePayload.exp - invitePayload.iat,
          },
        });

        return { kind: "ok", capability: compactSdJwt, expiresAt: exp, userId };
      });

      if (result.kind === "already_consumed") {
        await denyOutsideTx(
          c.env as Env,
          workspaceId,
          "invite.accept.denied",
          { jti: invitePayload.jti, email: invitePayload.email },
          { reason: "invite_already_consumed" },
        );
        return c.json({ error: "gone", message: "invite_already_consumed" }, 410);
      }
      if (result.kind === "error") {
        return c.json({ error: result.code, message: result.message }, result.status as 500);
      }
      // Encourage caller to reach the right MCP endpoint.
      const mcpUrl = c.env.MCP_BASE_URL ?? "https://mcp.getpact.dev";
      return c.json(
        {
          capability: result.capability,
          mcp_url: mcpUrl,
          expires_at: result.expiresAt,
          user_id: result.userId,
        },
        201,
      );
    } catch (e) {
      const message = e instanceof Error ? e.message : "accept failed";
      return c.json({ error: "internal_error", message }, 500);
    }
  });
};

export const __testables = { exportEd25519PublicJwk, parseUnverifiedJws, isInvitePayload };
