import {
  type Ed25519PublicJwk,
  fromBase64,
  generateEd25519Keypair,
  sdjwt,
  toBase64,
} from "@getpact/crypto";
import { createClient, type DbClient, withWorkspace } from "@getpact/db";
import { agentInvocations, agents, auditEvents, users, workspaces } from "@getpact/db/schema";
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
  baseSdJwt: string;
  agentPair: CryptoKeyPair;
  env: { DATABASE_URL: string; MEK: string };
};

const exportEd25519Jwk = async (
  key: CryptoKey,
  kid: string,
): Promise<Ed25519PublicJwk & { kid: string }> => {
  const jwk = (await crypto.subtle.exportKey("jwk", key)) as JsonWebKey;
  return { kty: "OKP", crv: "Ed25519", x: jwk.x as string, kid };
};

const postRedeem = async (
  s: Setup,
  sdJwt: string,
): Promise<{ status: number; body: { allow: boolean; reasons?: string[] } }> => {
  const res = await app.request(
    `/v1/capabilities/${s.jti}/redeem`,
    {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        sd_jwt: sdJwt,
        tool_name: "search.documents",
        resource: { resource: "drive:doc-1" },
      }),
    },
    s.env,
  );
  const body = (await res.json()) as { allow: boolean; reasons?: string[] };
  return { status: res.status, body };
};

run("capabilities kb-jwt replay defense", () => {
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

  const buildCapability = async (overrides?: { maxRedeems?: number }): Promise<Setup> => {
    const env = await buildTestEnv(url as string);
    const rawMek = fromBase64(env.MEK);
    const slug = uniqueSlug("rep");

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

    const audience = "pact-mcp";
    const toolName = "search.documents";
    const scopeClaim = { resource: "drive:doc-1" };
    const expiresInMs = 60_000;
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

    const issuerClaims: Record<string, unknown> = {
      iss: `https://issuer.test/${slug}`,
      org: ws.id,
      jti,
      aud: audience,
      iat: Math.floor(Date.now() / 1000),
      exp: Math.floor((Date.now() + expiresInMs) / 1000),
    };

    const baseSdJwt = await sdjwt.issueSdJwt({
      issuerPrivateKey: issuerPair.privateKey,
      issuerKid: jwtKey.id,
      issuerClaims,
      disclosures: [
        { name: "scope", value: { tool_name: toolName, ...scopeClaim } },
        { name: "agent_id", value: agentRow.id },
      ],
      cnfJkt: agentPubJwk,
    });

    return {
      workspaceId: ws.id,
      agentId: agentRow.id,
      jti,
      audience,
      baseSdJwt,
      agentPair,
      env: { DATABASE_URL: env.DATABASE_URL, MEK: env.MEK },
    };
  };

  it("rejects an exact bundle replay with kb_replay_detected", async () => {
    const s = await buildCapability({ maxRedeems: 5 });
    const presented = await sdjwt.signKbJwt({
      holderPrivateKey: s.agentPair.privateKey,
      sdJwt: s.baseSdJwt,
      audience: s.audience,
      nonce: crypto.randomUUID(),
    });

    const first = await postRedeem(s, presented);
    expect(first.status).toBe(200);
    expect(first.body.allow).toBe(true);

    const second = await postRedeem(s, presented);
    expect(second.status).toBe(410);
    expect(second.body.allow).toBe(false);
    expect(second.body.reasons).toContain("kb_replay_detected");

    const events = await withWorkspace(db, s.workspaceId, (tx) =>
      tx
        .select()
        .from(auditEvents)
        .where(
          and(
            eq(auditEvents.workspaceId, s.workspaceId),
            eq(auditEvents.action, "agent.capability.denied"),
          ),
        ),
    );
    const denyReasons = events
      .map((e) => (e.supporting as { reasons?: unknown } | null)?.reasons)
      .filter((r): r is string[] => Array.isArray(r));
    expect(denyReasons.some((r) => r.includes("kb_replay_detected"))).toBe(true);
  });

  it("accepts two distinct KB-JWTs over the same SD-JWT when max_redeems allows", async () => {
    const s = await buildCapability({ maxRedeems: 2 });

    const firstKb = await sdjwt.signKbJwt({
      holderPrivateKey: s.agentPair.privateKey,
      sdJwt: s.baseSdJwt,
      audience: s.audience,
      nonce: "nonce-one",
    });
    const r1 = await postRedeem(s, firstKb);
    expect(r1.status).toBe(200);

    // Wait long enough for the next signKbJwt to use a different iat second.
    await new Promise((resolve) => setTimeout(resolve, 1100));

    const secondKb = await sdjwt.signKbJwt({
      holderPrivateKey: s.agentPair.privateKey,
      sdJwt: s.baseSdJwt,
      audience: s.audience,
      nonce: "nonce-two",
    });
    expect(secondKb).not.toBe(firstKb);
    const r2 = await postRedeem(s, secondKb);
    expect(r2.status).toBe(200);
    expect(r2.body.allow).toBe(true);
  });

  it("scopes replay entries by workspace via row level security", async () => {
    const a = await buildCapability({ maxRedeems: 1 });
    const b = await buildCapability({ maxRedeems: 1 });

    const presentedA = await sdjwt.signKbJwt({
      holderPrivateKey: a.agentPair.privateKey,
      sdJwt: a.baseSdJwt,
      audience: a.audience,
      nonce: crypto.randomUUID(),
    });

    // Pre-seed the wrong workspace with a bogus replay entry that uses the
    // same jti and an arbitrary sd_hash. RLS must keep it out of workspace A.
    const bogusHashHex = "ab".repeat(32);
    await withWorkspace(db, b.workspaceId, (tx) =>
      tx.execute(
        sql`INSERT INTO kbjwt_replay_log (workspace_id, jti, kb_iat, sd_hash)
            VALUES (${b.workspaceId}, ${a.jti}, ${1}, decode(${bogusHashHex}, 'hex'))`,
      ),
    );

    const res = await postRedeem(a, presentedA);
    expect(res.status).toBe(200);
    expect(res.body.allow).toBe(true);
  });
});
