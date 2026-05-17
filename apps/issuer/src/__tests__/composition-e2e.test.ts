import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import type { AddressInfo } from "node:net";
import { computeGenesisHash, type StoredEvent, verifyChain } from "@getpact/audit";
import { type Ed25519PublicJwk, generateEd25519Keypair, sdjwt } from "@getpact/crypto";
import { createClient, withWorkspace } from "@getpact/db";
import {
  agentInvocations,
  auditEvents,
  groupMembers,
  groups,
  users,
  workspaces,
} from "@getpact/db/schema";
import { listVerifyingKeys } from "@getpact/keystore";
import {
  buildTestEnv,
  createTestWorkspace,
  issueTestToken,
  uniqueSlug,
} from "@getpact/test-helpers";
import { and, asc, eq, sql } from "drizzle-orm";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import adminApi from "../../../../apps/admin-api/src/index.js";
import mcpServer from "../../../../apps/mcp-server/src/index.js";
import verifier from "../../../../apps/verifier/src/index.js";
import issuer from "../index.js";

const url = process.env.DATABASE_URL;
const run = url ? describe : describe.skip;

const exportEd25519Jwk = async (key: CryptoKey): Promise<Ed25519PublicJwk> => {
  const jwk = (await crypto.subtle.exportKey("jwk", key)) as JsonWebKey;
  return { kty: "OKP", crv: "Ed25519", x: jwk.x as string };
};

const callJson = async (
  app: {
    request: (
      path: string,
      init: RequestInit,
      env: Record<string, unknown>,
    ) => Promise<Response> | Response;
  },
  path: string,
  init: RequestInit,
  env: Record<string, unknown>,
): Promise<{ status: number; body: unknown }> => {
  const res = await Promise.resolve(app.request(path, init, env));
  const text = await res.text();
  const body = text.length > 0 ? JSON.parse(text) : null;
  return { status: res.status, body };
};

const authHeaders = (token: string): HeadersInit => ({
  "content-type": "application/json",
  Authorization: `Bearer ${token}`,
});

run("composition end-to-end demo loop", () => {
  const adminDb = createClient(url as string);
  const cleanup: string[] = [];
  let verifierServer: ReturnType<typeof createServer>;
  let verifierUrl: string;
  let verifierProxyEnv: Record<string, unknown> = {};

  beforeAll(async () => {
    verifierServer = createServer((req: IncomingMessage, res: ServerResponse) => {
      let payload = "";
      req.on("data", (chunk) => {
        payload += chunk;
      });
      req.on("end", async () => {
        try {
          const method = req.method ?? "POST";
          const headers = new Headers({ "content-type": "application/json" });
          if (req.headers.authorization) {
            headers.set("authorization", req.headers.authorization);
          }
          const init: RequestInit = { method, headers };
          if (method !== "GET" && method !== "HEAD") init.body = payload;
          const upstream = await verifier.request(req.url ?? "/", init, verifierProxyEnv);
          const out = await upstream.text();
          res.writeHead(upstream.status, {
            "content-type": upstream.headers.get("content-type") ?? "application/json",
          });
          res.end(out);
        } catch (e) {
          const message = e instanceof Error ? e.message : "verifier proxy error";
          res.writeHead(500, { "content-type": "application/json" });
          res.end(JSON.stringify({ error: message }));
        }
      });
    });
    await new Promise<void>((resolve) => verifierServer.listen(0, "127.0.0.1", () => resolve()));
    const addr = verifierServer.address() as AddressInfo;
    verifierUrl = `http://127.0.0.1:${addr.port}`;
  });

  afterAll(
    () =>
      new Promise<void>((resolve, reject) =>
        verifierServer.close((err) => (err ? reject(err) : resolve())),
      ),
  );

  afterEach(async () => {
    while (cleanup.length > 0) {
      const id = cleanup.pop();
      if (!id) continue;
      try {
        await adminDb.delete(workspaces).where(eq(workspaces.id, id));
      } catch {
        // ignore
      }
    }
  });

  it("walks oauth, group setup, mint, kb-jwt, redeem, replay, tool call, and audit chain", async () => {
    const startedAt = Date.now();

    // Step 1: create workspace via issuer
    const env = await buildTestEnv(url as string);
    const workspaceSlug = uniqueSlug("e2e");
    const created = await createTestWorkspace(issuer, env, {
      slug: workspaceSlug,
      adminEmail: "alice@example.com",
    });
    cleanup.push(created.workspaceId);
    const wsId = created.workspaceId;

    // Step 2: dev/issue an admin token for alice. This stands in for the
    // oauth exchange path; the dev route mints the same JWT shape.
    const adminTokenRes = await issueTestToken(issuer, env, {
      workspaceId: wsId,
      email: "alice@example.com",
      audience: env.ADMIN_AUDIENCE,
    });
    const adminToken = adminTokenRes.token;

    const adminEnv = {
      DATABASE_URL: env.DATABASE_URL,
      MEK: env.MEK,
      ISSUER_BASE_URL: env.ISSUER_BASE_URL,
      ADMIN_AUDIENCE: env.ADMIN_AUDIENCE,
    };

    // Step 3: create the "eng" group via admin-api
    const groupRes = await callJson(
      adminApi,
      `/v1/workspaces/${wsId}/groups`,
      {
        method: "POST",
        headers: authHeaders(adminToken),
        body: JSON.stringify({ name: "eng" }),
      },
      adminEnv,
    );
    expect(groupRes.status).toBe(201);
    const engGroupId = (groupRes.body as { group: { id: string } }).group.id;

    // Step 4: create alice's collaborator "alice2" via admin-api so we have
    // a user we can ladder a capability for. The workspace admin (alice) is
    // already in the workspace; we add a second user to keep mint subject
    // distinct from the caller, matching the demo loop.
    const userRes = await callJson(
      adminApi,
      `/v1/workspaces/${wsId}/users`,
      {
        method: "POST",
        headers: authHeaders(adminToken),
        body: JSON.stringify({ email: "alice2@example.com", name: "Alice 2" }),
      },
      adminEnv,
    );
    expect(userRes.status).toBe(201);
    const alice2Id = (userRes.body as { user: { id: string } }).user.id;

    // Step 5: add alice2 to "eng"
    const memberRes = await callJson(
      adminApi,
      `/v1/workspaces/${wsId}/groups/${engGroupId}/members`,
      {
        method: "POST",
        headers: authHeaders(adminToken),
        body: JSON.stringify({ user_id: alice2Id }),
      },
      adminEnv,
    );
    expect(memberRes.status).toBe(201);

    // Step 6: create the agent and its grants via the admin-api routes. The
    // holder keypair is generated locally so the test retains the private
    // key needed to sign kb-jwts; only the public JWK is sent to the server.
    const agentPair = await generateEd25519Keypair();
    const agentPubJwk = await exportEd25519Jwk(agentPair.publicKey);
    const agentRes = await callJson(
      adminApi,
      `/v1/workspaces/${wsId}/agents`,
      {
        method: "POST",
        headers: authHeaders(adminToken),
        body: JSON.stringify({
          name: `agent-${Date.now().toString(36)}`,
          owner_user_id: created.adminUserId,
          pubkey_jwk: agentPubJwk,
        }),
      },
      adminEnv,
    );
    expect(agentRes.status).toBe(201);
    const agentId = (agentRes.body as { agent: { id: string } }).agent.id;

    const grantRes = await callJson(
      adminApi,
      `/v1/workspaces/${wsId}/agents/${agentId}/grants`,
      {
        method: "POST",
        headers: authHeaders(adminToken),
        body: JSON.stringify({
          tool_name: "pact.brain.search",
          audience: "pact-mcp",
          scope: { group_in: ["eng"] },
          on_behalf_of_user_id: alice2Id,
        }),
      },
      adminEnv,
    );
    expect(grantRes.status).toBe(201);
    const grantId = (grantRes.body as { grant: { id: string } }).grant.id;
    expect(grantId).toBeTruthy();

    const whoamiGrantRes = await callJson(
      adminApi,
      `/v1/workspaces/${wsId}/agents/${agentId}/grants`,
      {
        method: "POST",
        headers: authHeaders(adminToken),
        body: JSON.stringify({
          tool_name: "pact.whoami",
          audience: "pact-mcp",
          scope: {},
          on_behalf_of_user_id: alice2Id,
        }),
      },
      adminEnv,
    );
    expect(whoamiGrantRes.status).toBe(201);

    // Step 7: mint the capability SD-JWT via the issuer. The holder is the
    // agent keypair generated above; its public JWK is the cnf.
    const holderPair = agentPair;
    const holderPubJwk = agentPubJwk;
    const mintRes = await callJson(
      issuer,
      `/v1/agents/${agentId}/capabilities`,
      {
        method: "POST",
        headers: authHeaders(adminToken),
        body: JSON.stringify({
          on_behalf_of: "alice2@example.com",
          tool_name: "pact.brain.search",
          scope: { group_in: ["eng"] },
          audience: "pact-mcp",
          ttl_seconds: 300,
          // max_redeems=2 lets the first call succeed without flipping the
          // invocation into the redeemed/revoked state. The second call then
          // hits the kb-jwt replay log first and returns kb_replay_detected
          // instead of token_revoked, which is the more diagnostic signal.
          max_redeems: 2,
          cnf_jwk: holderPubJwk,
        }),
      },
      env as unknown as Record<string, unknown>,
    );
    expect(mintRes.status).toBe(201);
    const minted = mintRes.body as { jti: string; sd_jwt: string; exp: number };
    expect(minted.sd_jwt.endsWith("~")).toBe(true);

    // Step 8: holder signs the kb-jwt locally
    const sdJwtWithKb = await sdjwt.signKbJwt({
      holderPrivateKey: holderPair.privateKey,
      sdJwt: minted.sd_jwt,
      audience: "pact-mcp",
      nonce: crypto.randomUUID(),
    });

    // Step 9: redeem at the verifier capability endpoint directly. This is
    // the unit-style assertion that the verifier's redeem handler returns
    // the expected shape and audits the decision; the mcp-server SD-JWT
    // path is exercised separately in step 11b below.
    const verifierEnv = {
      DATABASE_URL: env.DATABASE_URL,
      MEK: env.MEK,
      ISSUER_BASE_URL: env.ISSUER_BASE_URL,
    };
    const redeemRes = await callJson(
      verifier,
      `/v1/capabilities/${minted.jti}/redeem`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          sd_jwt: sdJwtWithKb,
          tool_name: "pact.brain.search",
          resource: { tool_name: "pact.brain.search" },
        }),
      },
      verifierEnv,
    );
    expect(redeemRes.status).toBe(200);
    const redeemBody = redeemRes.body as {
      allow: boolean;
      scope_claim: Record<string, unknown>;
      agent_id: string;
      audience: string;
    };
    expect(redeemBody.allow).toBe(true);
    expect(redeemBody.agent_id).toBe(agentId);
    expect(redeemBody.audience).toBe("pact-mcp");

    // Step 10: replay the same sd-jwt+kb-jwt and assert kb_replay_detected
    const replayRes = await callJson(
      verifier,
      `/v1/capabilities/${minted.jti}/redeem`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          sd_jwt: sdJwtWithKb,
          tool_name: "pact.brain.search",
          resource: { tool_name: "pact.brain.search" },
        }),
      },
      verifierEnv,
    );
    expect(replayRes.status).toBe(410);
    const replayBody = replayRes.body as { allow: boolean; reasons: string[] };
    expect(replayBody.allow).toBe(false);
    expect(replayBody.reasons).toContain("kb_replay_detected");

    // Step 11: the working production demo path is bearer JWT -> mcp tools
    // call -> verifier /v1/verify -> tool result. Install an allow-admin
    // policy and exercise that flow end to end so we prove the canonical
    // mcp+verifier wiring functions over real http.
    const policyRes = await callJson(
      adminApi,
      `/v1/workspaces/${wsId}/policies`,
      {
        method: "POST",
        headers: authHeaders(adminToken),
        body: JSON.stringify({
          body: { rules: [{ subject: { kind: "role", value: "admin" }, effect: "allow" }] },
        }),
      },
      adminEnv,
    );
    expect(policyRes.status).toBe(201);

    const mcpTokenRes = await issueTestToken(issuer, env, {
      workspaceId: wsId,
      email: "alice@example.com",
      audience: env.MCP_AUDIENCE,
    });
    verifierProxyEnv = {
      DATABASE_URL: env.DATABASE_URL,
      MEK: env.MEK,
      ISSUER_BASE_URL: env.ISSUER_BASE_URL,
    };
    const mcpEnv = {
      DATABASE_URL: env.DATABASE_URL,
      ISSUER_BASE_URL: env.ISSUER_BASE_URL,
      VERIFIER_URL: verifierUrl,
      MCP_AUDIENCE: env.MCP_AUDIENCE,
    };
    const mcpCallRes = await callJson(
      mcpServer,
      `/${workspaceSlug}/mcp`,
      {
        method: "POST",
        headers: authHeaders(mcpTokenRes.token),
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 1,
          method: "tools/call",
          params: { name: "pact.whoami", arguments: {} },
        }),
      },
      mcpEnv,
    );
    expect(mcpCallRes.status).toBe(200);
    const mcpBody = mcpCallRes.body as {
      result?: { content: Array<{ text: string }> };
      error?: { code: number; message: string };
    };
    expect(mcpBody.error).toBeUndefined();
    expect(mcpBody.result?.content[0]?.text).toContain("alice@example.com");

    // Step 11b: mint a fresh capability and exercise the SD-JWT bearer path
    // through the mcp-server front door. The first tools/call must redeem
    // (not /v1/verify) and the second must trip replay defense with
    // kb_replay_detected. This closes the composition gap noted earlier.
    const mintBRes = await callJson(
      issuer,
      `/v1/agents/${agentId}/capabilities`,
      {
        method: "POST",
        headers: authHeaders(adminToken),
        body: JSON.stringify({
          on_behalf_of: "alice2@example.com",
          tool_name: "pact.whoami",
          scope: {},
          audience: "pact-mcp",
          ttl_seconds: 300,
          max_redeems: 2,
          cnf_jwk: holderPubJwk,
        }),
      },
      env as unknown as Record<string, unknown>,
    );
    expect(mintBRes.status).toBe(201);
    const mintedB = mintBRes.body as { jti: string; sd_jwt: string };
    const sdJwtForMcp = await sdjwt.signKbJwt({
      holderPrivateKey: holderPair.privateKey,
      sdJwt: mintedB.sd_jwt,
      audience: "pact-mcp",
      nonce: crypto.randomUUID(),
    });

    const sdJwtCallRes = await callJson(
      mcpServer,
      `/${workspaceSlug}/mcp`,
      {
        method: "POST",
        headers: authHeaders(sdJwtForMcp),
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 2,
          method: "tools/call",
          params: { name: "pact.whoami", arguments: {} },
        }),
      },
      mcpEnv,
    );
    expect(sdJwtCallRes.status).toBe(200);
    const sdJwtBody = sdJwtCallRes.body as {
      result?: { content: Array<{ text: string }> };
      error?: { code: number; message: string };
    };
    expect(sdJwtBody.error).toBeUndefined();
    expect(sdJwtBody.result?.content[0]?.text).toContain("alice2@example.com");

    const replayMcpRes = await callJson(
      mcpServer,
      `/${workspaceSlug}/mcp`,
      {
        method: "POST",
        headers: authHeaders(sdJwtForMcp),
        body: JSON.stringify({
          jsonrpc: "2.0",
          id: 3,
          method: "tools/call",
          params: { name: "pact.whoami", arguments: {} },
        }),
      },
      mcpEnv,
    );
    expect(replayMcpRes.status).toBe(200);
    const replayMcpBody = replayMcpRes.body as {
      error?: { code: number; data?: { reasons: string[]; status?: number } };
    };
    expect(replayMcpBody.error?.code).toBe(-32001);
    expect(replayMcpBody.error?.data?.reasons).toContain("kb_replay_detected");
    expect(replayMcpBody.error?.data?.status).toBe(410);

    // Step 12: verify the audit chain contains every step. We use direct
    // queries; admin-api's audit list route is paginated and would only
    // duplicate this check.
    const events = await withWorkspace(adminDb, wsId, (tx) =>
      tx
        .select({ action: auditEvents.action, decision: auditEvents.decision })
        .from(auditEvents)
        .where(eq(auditEvents.workspaceId, wsId))
        .orderBy(asc(auditEvents.auditSeq)),
    );
    const actions = events.map((e) => e.action);
    for (const required of [
      "group.created",
      "admin.user.created",
      "group.member.added",
      "admin.policy.created",
      "agent.capability.minted",
      "agent.capability.redeemed",
      "agent.capability.denied",
      "verify.tool:pact.whoami",
    ]) {
      expect(actions).toContain(required);
    }
    const mintEvent = events.find((e) => e.action === "agent.capability.minted");
    expect(mintEvent?.decision).toBe("allow");
    const redeemEvent = events.find((e) => e.action === "agent.capability.redeemed");
    expect(redeemEvent?.decision).toBe("allow");
    const denyEvent = events.find((e) => e.action === "agent.capability.denied");
    expect(denyEvent?.decision).toBe("deny");

    // Confirm the invocation row reflects redeem then revoke
    const invRows = await withWorkspace(adminDb, wsId, (tx) =>
      tx
        .select()
        .from(agentInvocations)
        .where(and(eq(agentInvocations.workspaceId, wsId), eq(agentInvocations.jti, minted.jti))),
    );
    // First redeem succeeded, second was rejected before counting up; the
    // replay defense fires before redeem_count is incremented again.
    expect(invRows[0]?.redeemStatus).toBe("issued");
    expect(invRows[0]?.redeemCount).toBe(1);

    // Confirm the group has alice2
    const memberRows = await withWorkspace(adminDb, wsId, (tx) =>
      tx
        .select({ userId: groupMembers.userId })
        .from(groupMembers)
        .where(and(eq(groupMembers.workspaceId, wsId), eq(groupMembers.groupId, engGroupId))),
    );
    expect(memberRows.map((r) => r.userId)).toContain(alice2Id);

    // Confirm the user list is what we expect
    const userRows = await withWorkspace(adminDb, wsId, (tx) =>
      tx.select({ email: users.email }).from(users).where(eq(users.workspaceId, wsId)),
    );
    const emails = userRows.map((r) => r.email);
    expect(emails).toEqual(expect.arrayContaining(["alice@example.com", "alice2@example.com"]));

    // Confirm the group was actually written
    const groupRows = await withWorkspace(adminDb, wsId, (tx) =>
      tx
        .select({ id: groups.id, name: groups.name })
        .from(groups)
        .where(eq(groups.workspaceId, wsId)),
    );
    expect(groupRows.find((g) => g.name === "eng")).toBeTruthy();

    // Step 13: verify the audit chain signature end to end with the audit
    // public keys loaded from the workspace keystore.
    const verifyingKeys = await withWorkspace(adminDb, wsId, (tx) =>
      listVerifyingKeys(tx, wsId, "audit"),
    );
    const jwks: Record<string, CryptoKey> = {};
    for (const key of verifyingKeys) {
      jwks[key.id] = key.publicKey;
    }
    const fullEvents = (await adminDb.execute(
      sql`SELECT workspace_id, ts, actor_kind, actor_id, action, target, decision, supporting,
                 signing_key_id, prev_hash, this_hash, signature
          FROM audit_events
          WHERE workspace_id = ${wsId}
          ORDER BY audit_seq ASC`,
    )) as Array<{
      workspace_id: string;
      ts: string | Date;
      actor_kind: string;
      actor_id: string | null;
      action: string;
      target: unknown;
      decision: string;
      supporting: unknown;
      signing_key_id: string;
      prev_hash: string;
      this_hash: string;
      signature: string;
    }>;

    const stored: StoredEvent[] = fullEvents.map((r) => ({
      workspaceId: r.workspace_id,
      ts: new Date(r.ts).toISOString(),
      actorKind: r.actor_kind,
      actorId: r.actor_id,
      action: r.action,
      target: r.target,
      decision: r.decision,
      supporting: r.supporting,
      signingKeyId: r.signing_key_id,
      prevHash: r.prev_hash,
      thisHash: r.this_hash,
      signature: r.signature,
    }));

    const [wsRow] = await adminDb
      .select({ createdAt: workspaces.createdAt })
      .from(workspaces)
      .where(eq(workspaces.id, wsId))
      .limit(1);
    if (!wsRow) throw new Error("workspace row missing");
    const genesis = await computeGenesisHash(wsId, wsRow.createdAt);

    const chainResult = await verifyChain(stored, jwks, genesis);
    if (!chainResult.ok) {
      throw new Error(
        `audit chain broke at index ${chainResult.brokenAt.index}: ${chainResult.brokenAt.reason}`,
      );
    }
    expect(chainResult.ok).toBe(true);

    const elapsed = Date.now() - startedAt;
    expect(elapsed).toBeLessThan(60_000);
  });
});
