import {
  type Ed25519PublicJwk,
  fromBase64,
  generateEd25519Keypair,
  sdjwt,
  toBase64,
} from "@getpact/crypto";
import { createClient, type DbClient, withWorkspace } from "@getpact/db";
import {
  agentInvocations,
  agents,
  auditEvents,
  revokedJtis,
  users,
  workspaces,
} from "@getpact/db/schema";
import { createSigningKey } from "@getpact/keystore";
import { buildTestEnv, uniqueSlug } from "@getpact/test-helpers";
import { and, eq, sql } from "drizzle-orm";
import { afterEach, describe, expect, it } from "vitest";
import app from "../index.js";

const url = process.env.DATABASE_URL;
const run = url ? describe : describe.skip;

type Setup = {
  workspaceId: string;
  agentId: string;
  jti: string;
  audience: string;
  sdJwt: string;
  env: { DATABASE_URL: string; MEK: string };
};

const exportEd25519Jwk = async (
  key: CryptoKey,
  kid: string,
): Promise<Ed25519PublicJwk & { kid: string }> => {
  const jwk = (await crypto.subtle.exportKey("jwk", key)) as JsonWebKey;
  return { kty: "OKP", crv: "Ed25519", x: jwk.x as string, kid };
};

run("capabilities redeem", () => {
  const cleanup: string[] = [];
  const db: DbClient = createClient(url as string);

  afterEach(async () => {
    while (cleanup.length > 0) {
      const id = cleanup.pop();
      if (!id) continue;
      try {
        await db.delete(workspaces).where(eq(workspaces.id, id));
      } catch {
        // ignore
      }
    }
  });

  const buildCapability = async (overrides?: {
    maxRedeems?: number;
    scopeClaim?: Record<string, unknown>;
    toolName?: string;
    audience?: string;
    expiresInMs?: number;
    skipKbJwt?: boolean;
    wrongHolder?: boolean;
    insertRevoked?: boolean;
  }): Promise<Setup> => {
    const env = await buildTestEnv(url as string);
    const rawMek = fromBase64(env.MEK);
    const slug = uniqueSlug("cap");

    const [ws] = await db
      .insert(workspaces)
      .values({ slug, name: slug })
      .returning({ id: workspaces.id });
    if (!ws) throw new Error("workspace insert failed");
    cleanup.push(ws.id);

    const [admin] = await withWorkspace(db, ws.id, (tx) =>
      tx
        .insert(users)
        .values({ workspaceId: ws.id, email: `${slug}-admin@example.com` })
        .returning({ id: users.id }),
    );
    if (!admin) throw new Error("admin user insert failed");

    const jwtKey = await withWorkspace(db, ws.id, (tx) =>
      createSigningKey(tx, { workspaceId: ws.id, kind: "jwt", rawMek }),
    );
    await withWorkspace(db, ws.id, (tx) =>
      createSigningKey(tx, { workspaceId: ws.id, kind: "audit", rawMek }),
    );

    // Replace the stored public key with a freshly generated one whose private
    // half is available in the test, so we can sign SD-JWTs that verify under
    // the issuer JWKS the verifier loads from workspace_signing_keys.
    const issuerPair = await generateEd25519Keypair();
    const issuerSpki = new Uint8Array(await crypto.subtle.exportKey("spki", issuerPair.publicKey));
    await db.execute(
      sql`UPDATE workspace_signing_keys
          SET public_key_spki = ${toBase64(issuerSpki)}
          WHERE id = ${jwtKey.id}`,
    );

    const agentPair = await generateEd25519Keypair();
    const agentPubJwk = await exportEd25519Jwk(agentPair.publicKey, "agent");
    const thumbprint = await sdjwt.jwkThumbprint(agentPubJwk);

    const [agentRow] = await withWorkspace(db, ws.id, (tx) =>
      tx
        .insert(agents)
        .values({
          workspaceId: ws.id,
          slug: `${slug}-agent`,
          displayName: "Test Agent",
          kind: "service",
          ownerUserId: admin.id,
          pubkeyJwk: agentPubJwk,
          pubkeyThumbprint: thumbprint,
        })
        .returning({ id: agents.id }),
    );
    if (!agentRow) throw new Error("agent insert failed");

    const audience = overrides?.audience ?? "pact-mcp";
    const toolName = overrides?.toolName ?? "search.documents";
    const scopeClaim = overrides?.scopeClaim ?? { resource: "drive:doc-1" };
    const expiresInMs = overrides?.expiresInMs ?? 60_000;
    const jti = crypto.randomUUID();

    await withWorkspace(db, ws.id, (tx) =>
      tx.insert(agentInvocations).values({
        workspaceId: ws.id,
        jti,
        agentId: agentRow.id,
        onBehalfOfUserId: admin.id,
        toolName,
        scopeClaim,
        audience,
        cnfThumbprint: thumbprint,
        redeemStatus: "issued",
        maxRedeems: overrides?.maxRedeems ?? 1,
        expiresAt: new Date(Date.now() + expiresInMs),
      }),
    );

    if (overrides?.insertRevoked) {
      await withWorkspace(db, ws.id, (tx) =>
        tx.insert(revokedJtis).values({ workspaceId: ws.id, jti, reason: "test" }),
      );
    }

    const issuerClaims: Record<string, unknown> = {
      iss: `https://issuer.test/${slug}`,
      org: ws.id,
      jti,
      aud: audience,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor((Date.now() + expiresInMs) / 1000),
    };

    const sd = await sdjwt.issueSdJwt({
      issuerPrivateKey: issuerPair.privateKey,
      issuerKid: jwtKey.id,
      issuerClaims,
      disclosures: [
        { name: "scope", value: { tool_name: toolName, ...scopeClaim } },
        { name: "agent_id", value: agentRow.id },
      ],
      cnfJkt: agentPubJwk,
    });

    let sdJwt = sd;
    if (!overrides?.skipKbJwt) {
      const holderPriv = overrides?.wrongHolder
        ? (await generateEd25519Keypair()).privateKey
        : agentPair.privateKey;
      sdJwt = await sdjwt.signKbJwt({
        holderPrivateKey: holderPriv,
        sdJwt: sd,
        audience,
        nonce: crypto.randomUUID(),
      });
    }

    return {
      workspaceId: ws.id,
      agentId: agentRow.id,
      jti,
      audience,
      sdJwt,
      env: { DATABASE_URL: env.DATABASE_URL, MEK: env.MEK },
    };
  };

  it("redeems a valid capability and records audit", async () => {
    const s = await buildCapability();
    const res = await app.request(
      `/v1/capabilities/${s.jti}/redeem`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          sd_jwt: s.sdJwt,
          tool_name: "search.documents",
          resource: { resource: "drive:doc-1" },
        }),
      },
      s.env,
    );
    expect(res.status).toBe(200);
    const body = (await res.json()) as {
      allow: boolean;
      scope_claim: Record<string, unknown>;
      agent_id: string;
      delegation_depth: number;
    };
    expect(body.allow).toBe(true);
    expect(body.agent_id).toBe(s.agentId);
    expect(body.delegation_depth).toBe(0);

    const inv = await withWorkspace(db, s.workspaceId, (tx) =>
      tx
        .select()
        .from(agentInvocations)
        .where(
          and(eq(agentInvocations.workspaceId, s.workspaceId), eq(agentInvocations.jti, s.jti)),
        ),
    );
    expect(inv[0]?.redeemCount).toBe(1);
    expect(inv[0]?.redeemStatus).toBe("redeemed");

    const events = await withWorkspace(db, s.workspaceId, (tx) =>
      tx
        .select()
        .from(auditEvents)
        .where(
          and(
            eq(auditEvents.workspaceId, s.workspaceId),
            eq(auditEvents.action, "agent.capability.redeemed"),
          ),
        ),
    );
    expect(events.length).toBe(1);
    expect(events[0]?.decision).toBe("allow");
  });

  it("rejects replay after redeem count is exhausted", async () => {
    const s = await buildCapability({ maxRedeems: 1 });
    const r1 = await app.request(
      `/v1/capabilities/${s.jti}/redeem`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          sd_jwt: s.sdJwt,
          tool_name: "search.documents",
          resource: { resource: "drive:doc-1" },
        }),
      },
      s.env,
    );
    expect(r1.status).toBe(200);

    const r2 = await app.request(
      `/v1/capabilities/${s.jti}/redeem`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          sd_jwt: s.sdJwt,
          tool_name: "search.documents",
          resource: { resource: "drive:doc-1" },
        }),
      },
      s.env,
    );
    expect(r2.status).toBe(410);
    const body = (await r2.json()) as { allow: boolean; reasons: string[] };
    expect(body.allow).toBe(false);
    expect(body.reasons).toContain("token_revoked");
  });

  it("denies when kb-jwt is missing", async () => {
    const s = await buildCapability({ skipKbJwt: true });
    const res = await app.request(
      `/v1/capabilities/${s.jti}/redeem`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          sd_jwt: s.sdJwt,
          tool_name: "search.documents",
          resource: { resource: "drive:doc-1" },
        }),
      },
      s.env,
    );
    expect(res.status).toBe(403);
    const body = (await res.json()) as { allow: boolean; reasons: string[] };
    expect(body.allow).toBe(false);
    expect(body.reasons).toContain("kb_jwt_missing");
  });

  it("denies when kb-jwt is signed by a key that does not match cnf", async () => {
    const s = await buildCapability({ wrongHolder: true });
    const res = await app.request(
      `/v1/capabilities/${s.jti}/redeem`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          sd_jwt: s.sdJwt,
          tool_name: "search.documents",
          resource: { resource: "drive:doc-1" },
        }),
      },
      s.env,
    );
    expect(res.status).toBe(403);
    const body = (await res.json()) as { allow: boolean; reasons: string[] };
    expect(body.reasons).toContain("cnf_binding_invalid");
  });

  it("denies when the invocation has expired", async () => {
    const s = await buildCapability({ expiresInMs: 1_000 });
    await db.execute(
      sql`UPDATE agent_invocations SET expires_at = NOW() - INTERVAL '5 seconds'
          WHERE workspace_id = ${s.workspaceId} AND jti = ${s.jti}`,
    );
    const res = await app.request(
      `/v1/capabilities/${s.jti}/redeem`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          sd_jwt: s.sdJwt,
          tool_name: "search.documents",
          resource: { resource: "drive:doc-1" },
        }),
      },
      s.env,
    );
    expect(res.status).toBe(410);
    const body = (await res.json()) as { allow: boolean; reasons: string[] };
    expect(body.reasons).toContain("token_expired");
  });

  it("denies a jti listed in revoked_jtis", async () => {
    const s = await buildCapability({ insertRevoked: true });
    const res = await app.request(
      `/v1/capabilities/${s.jti}/redeem`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          sd_jwt: s.sdJwt,
          tool_name: "search.documents",
          resource: { resource: "drive:doc-1" },
        }),
      },
      s.env,
    );
    expect(res.status).toBe(410);
    const body = (await res.json()) as { allow: boolean; reasons: string[] };
    expect(body.reasons).toContain("token_revoked");
  });

  it("denies when requested resource falls outside the scope claim", async () => {
    const s = await buildCapability({ scopeClaim: { resource: "drive:doc-1" } });
    const res = await app.request(
      `/v1/capabilities/${s.jti}/redeem`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          sd_jwt: s.sdJwt,
          tool_name: "search.documents",
          resource: { resource: "drive:doc-2" },
        }),
      },
      s.env,
    );
    expect(res.status).toBe(422);
    const body = (await res.json()) as { allow: boolean; reasons: string[] };
    expect(body.reasons).toContain("scope_mismatch");
  });
});
