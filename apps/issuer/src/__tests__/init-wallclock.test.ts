import { verifyJwt } from "@getpact/crypto";
import { createClient, withWorkspace } from "@getpact/db";
import { workspaces } from "@getpact/db/schema";
import { listVerifyingKeys } from "@getpact/keystore";
import { buildTestEnv, createTestWorkspace, uniqueSlug } from "@getpact/test-helpers";
import { eq } from "drizzle-orm";
import { afterEach, describe, expect, it } from "vitest";
import adminApi from "../../../../apps/admin-api/src/index.js";
import issuer from "../index.js";

const url = process.env.DATABASE_URL;
const run = url ? describe : describe.skip;

type IssuerEnv = Awaited<ReturnType<typeof buildTestEnv>>;

const authHeaders = (token: string): HeadersInit => ({
  "content-type": "application/json",
  Authorization: `Bearer ${token}`,
});

const adminRuntime = (env: IssuerEnv): Record<string, unknown> => ({
  DATABASE_URL: env.DATABASE_URL,
  MEK: env.MEK,
  ISSUER_BASE_URL: env.ISSUER_BASE_URL,
  ADMIN_AUDIENCE: env.ADMIN_AUDIENCE,
});

const timed = async <T>(fn: () => Promise<T>): Promise<{ value: T; ms: number }> => {
  const start = Date.now();
  const value = await fn();
  return { value, ms: Date.now() - start };
};

run("pact init wall-clock", () => {
  const adminDb = createClient(url as string);
  const cleanup: string[] = [];

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

  it("provisions a working endpoint within the G1 budget", async () => {
    const base = await buildTestEnv(url as string);
    // POST /v1/workspaces requires a google_id_token unless this flag is on.
    // Set it locally so the timing test does not depend on test-helpers also
    // wiring it through buildTestEnv.
    const env = { ...base, PACT_ALLOW_UNAUTHED_WORKSPACE_CREATE: "true" } as typeof base;
    const slug = uniqueSlug("init-wc");

    const totalStart = Date.now();

    // Phase 1: workspace create. Matches POST /v1/workspaces from `pact init`.
    const ws = await timed(() =>
      createTestWorkspace(issuer, env, { slug, adminEmail: "alice@example.com" }),
    );
    cleanup.push(ws.value.workspaceId);
    const wsId = ws.value.workspaceId;

    // Phase 2: admin bearer issuance. Matches POST /v1/dev/issue. This is the
    // credential `pact init` writes to ~/.pact/credentials.
    const adminIssue = await timed(() =>
      issuer.request(
        "/v1/dev/issue",
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            workspaceId: wsId,
            email: "alice@example.com",
            audience: env.ADMIN_AUDIENCE,
          }),
        },
        env,
      ),
    );
    expect(adminIssue.value.status).toBe(200);
    const adminToken = ((await adminIssue.value.json()) as { token: string }).token;

    // Phase 3: first user upsert via admin-api. Matches the post-init step where
    // the operator adds a teammate before pointing an MCP client at the
    // endpoint.
    const userUpsert = await timed(() =>
      adminApi.request(
        `/v1/workspaces/${wsId}/users`,
        {
          method: "POST",
          headers: authHeaders(adminToken),
          body: JSON.stringify({ email: "bob@example.com", name: "Bob" }),
        },
        adminRuntime(env),
      ),
    );
    expect(userUpsert.value.status).toBe(201);

    // Phase 4: MCP-audience bearer mint. This is the token an MCP client uses
    // after `pact init` to hit the workspace MCP URL.
    const mcpIssue = await timed(() =>
      issuer.request(
        "/v1/dev/issue",
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            workspaceId: wsId,
            email: "alice@example.com",
            audience: env.MCP_AUDIENCE,
          }),
        },
        env,
      ),
    );
    expect(mcpIssue.value.status).toBe(200);
    const mcpBody = (await mcpIssue.value.json()) as { token: string; exp: number };

    // Phase 5: JWKS fetch. The published verifying key gates every downstream
    // verifyPactToken roundtrip; this is the first hop a Verifier SDK consumer
    // makes against a fresh workspace.
    const jwksFetch = await timed(() =>
      issuer.request(`/v1/workspaces/${wsId}/.well-known/jwks.json`, undefined, env),
    );
    expect(jwksFetch.value.status).toBe(200);
    const jwksBody = (await jwksFetch.value.json()) as {
      keys: Array<{ kid: string }>;
    };
    expect(jwksBody.keys.length).toBe(1);

    // Phase 6: verify the minted MCP token against the published JWKS. The
    // public key load goes through the workspace keystore so we get a real
    // CryptoKey, matching what a verifier deployment does on first use.
    const verify = await timed(async () => {
      const verifying = await withWorkspace(adminDb, wsId, (tx) =>
        listVerifyingKeys(tx, wsId, "jwt"),
      );
      const publicKey = verifying[0]?.publicKey;
      if (!publicKey) throw new Error("missing workspace verifying key");
      return verifyJwt(mcpBody.token, {
        publicKey,
        issuer: env.ISSUER_BASE_URL,
        audience: env.MCP_AUDIENCE,
      });
    });
    expect(verify.value.payload.email).toBe("alice@example.com");

    const totalMs = Date.now() - totalStart;

    const phases = [
      { phase: "workspace_create", ms: ws.ms },
      { phase: "admin_token_issue", ms: adminIssue.ms },
      { phase: "first_user_upsert", ms: userUpsert.ms },
      { phase: "mcp_token_issue", ms: mcpIssue.ms },
      { phase: "jwks_fetch", ms: jwksFetch.ms },
      { phase: "verify_roundtrip", ms: verify.ms },
    ];
    const slowest = phases.reduce(
      (acc, p) => (p.ms > acc.ms ? p : acc),
      phases[0] as {
        phase: string;
        ms: number;
      },
    );

    const report = {
      kind: "pact_init_wallclock",
      slug,
      workspaceId: wsId,
      totalMs,
      phases,
      slowest,
      budgetMs: 5_000,
      prdG1BudgetMs: 600_000,
    };
    process.stdout.write(`${JSON.stringify(report)}\n`);

    // In-process Hono dispatch removes the network. Allow 5x headroom over a
    // realistic local-stack call so a regression here flags long before the
    // 10-minute PRD G1 ceiling matters.
    expect(totalMs).toBeLessThan(5_000);
    // PRD G1 acceptance check, kept explicit so the test fails loudly if the
    // floor ever regresses by orders of magnitude.
    expect(totalMs).toBeLessThan(600_000);
  });
});
