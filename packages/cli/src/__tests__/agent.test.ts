import { mkdtempSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  buildCreateAgentBody,
  buildMintBody,
  formatAgentsTable,
  generateKeypairRecord,
  parseFlags,
  runAgent,
} from "../commands/agent.js";

const makeIo = () => {
  const out: string[] = [];
  const err: string[] = [];
  return {
    out,
    err,
    io: {
      out: (s: string) => out.push(s),
      err: (s: string) => err.push(s),
    },
  };
};

const baseEnv = {
  PACT_API_BASE: "https://issuer.test",
  PACT_ADMIN_TOKEN: "admin-token",
  PACT_WORKSPACE_ID: "ws-1",
} as NodeJS.ProcessEnv;

describe("parseFlags", () => {
  it("parses values, positionals, booleans, and --no-X negation", () => {
    const p = parseFlags([
      "abc",
      "--agent",
      "a-1",
      "--reason",
      "leaked",
      "--cascade",
      "--no-strict",
      "tail",
    ]);
    expect(p.positional).toEqual(["abc", "tail"]);
    expect(p.flags.get("agent")).toBe("a-1");
    expect(p.flags.get("reason")).toBe("leaked");
    expect(p.booleans.has("cascade")).toBe(true);
    expect(p.negated.has("strict")).toBe(true);
  });
});

describe("buildMintBody", () => {
  it("emits snake_case keys and skips cnf_jwk when absent", () => {
    const body = buildMintBody({
      agent: "agent-1",
      onBehalfOf: "alice@example.com",
      tool: "pact.drive.search",
      scope: { folder_id: ["X"] },
      audience: "drive-mcp",
      ttlSeconds: 600,
      maxRedeems: 2,
    });
    expect(body).toEqual({
      on_behalf_of: "alice@example.com",
      tool_name: "pact.drive.search",
      scope: { folder_id: ["X"] },
      audience: "drive-mcp",
      ttl_seconds: 600,
      max_redeems: 2,
    });
    expect("cnf_jwk" in body).toBe(false);
  });

  it("includes cnf_jwk when provided", () => {
    const body = buildMintBody({
      agent: "agent-1",
      onBehalfOf: "alice@example.com",
      tool: "t",
      scope: {},
      audience: "aud",
      ttlSeconds: 300,
      maxRedeems: 1,
      cnfJwk: { kty: "OKP", crv: "Ed25519", x: "abc" },
    });
    expect(body.cnf_jwk).toEqual({ kty: "OKP", crv: "Ed25519", x: "abc" });
  });
});

describe("formatAgentsTable", () => {
  it("renders header, separator, and rows", () => {
    const out = formatAgentsTable([
      { id: "a-1", name: "agent one", status: "active", created_at: "2026-01-01" },
      { id: "a-2", slug: "two", status: "suspended" },
    ]);
    expect(out).toContain("ID");
    expect(out).toContain("STATUS");
    expect(out).toContain("a-1");
    expect(out).toContain("agent one");
    expect(out).toContain("a-2");
    expect(out).toContain("suspended");
  });

  it("prints a friendly message when there are no rows", () => {
    expect(formatAgentsTable([])).toBe("no agents\n");
  });
});

describe("runAgent mint", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("calls POST /v1/agents/:id/capabilities and prints the JWT on the last line", async () => {
    const fetchMock = vi.fn(async (input: string | URL, init?: RequestInit) => {
      expect(String(input)).toBe("https://issuer.test/v1/agents/agent-1/capabilities");
      expect(init?.method).toBe("POST");
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      expect(body.on_behalf_of).toBe("alice@example.com");
      expect(body.tool_name).toBe("pact.drive.search");
      expect(body.scope).toEqual({ folder_id: ["X"] });
      expect(body.audience).toBe("drive-mcp");
      expect(body.ttl_seconds).toBe(300);
      expect(body.max_redeems).toBe(1);
      const headers = init?.headers as Record<string, string>;
      expect(headers.authorization).toBe("Bearer admin-token");
      return Response.json(
        {
          jti: "00000000-0000-4000-8000-000000000001",
          sd_jwt: "eyJhbGciOiJFZERTQSJ9.PAYLOAD.SIG~policy~payload~audience~",
          exp: 1_700_000_000,
          cnf_thumbprint: "",
        },
        { status: 201 },
      );
    });
    vi.stubGlobal("fetch", fetchMock);
    const { io, out } = makeIo();
    const res = await runAgent(
      [
        "mint",
        "--agent",
        "agent-1",
        "--on-behalf-of",
        "alice@example.com",
        "--tool",
        "pact.drive.search",
        "--scope",
        '{"folder_id":["X"]}',
        "--audience",
        "drive-mcp",
      ],
      io,
      baseEnv,
    );
    expect(res.exitCode).toBe(0);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const joined = out.join("");
    expect(joined).toContain("jti          00000000-0000-4000-8000-000000000001");
    const lines = joined.trimEnd().split("\n");
    expect(lines[lines.length - 1]).toBe(
      "eyJhbGciOiJFZERTQSJ9.PAYLOAD.SIG~policy~payload~audience~",
    );
  });

  it("exits 1 on a 409 quota error and prints the structured error", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        Response.json(
          { error: "quota_exceeded", message: "daily grant quota exceeded" },
          { status: 409 },
        ),
      ),
    );
    const { io, err } = makeIo();
    const res = await runAgent(
      [
        "mint",
        "--agent",
        "agent-1",
        "--on-behalf-of",
        "alice@example.com",
        "--tool",
        "pact.drive.search",
        "--scope",
        "{}",
        "--audience",
        "drive-mcp",
      ],
      io,
      baseEnv,
    );
    expect(res.exitCode).toBe(1);
    const joined = err.join("");
    expect(joined).toContain("quota_exceeded");
    expect(joined).toContain("daily grant quota exceeded");
    expect(joined).toContain("status 409");
  });

  it("exits 1 with a clear auth message on 401", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        Response.json({ error: "unauthorized", message: "bad token" }, { status: 401 }),
      ),
    );
    const { io, err } = makeIo();
    const res = await runAgent(
      [
        "mint",
        "--agent",
        "agent-1",
        "--on-behalf-of",
        "alice@example.com",
        "--tool",
        "t",
        "--scope",
        "{}",
        "--audience",
        "aud",
      ],
      io,
      baseEnv,
    );
    expect(res.exitCode).toBe(1);
    const joined = err.join("");
    expect(joined).toContain("unauthorized");
    expect(joined).toContain("bad token");
  });

  it("accepts --ttl preset like 1d and forwards ttl_seconds=86400", async () => {
    const fetchMock = vi.fn(async (_input: string | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      expect(body.ttl_seconds).toBe(86400);
      return Response.json(
        {
          jti: "00000000-0000-4000-8000-000000000003",
          sd_jwt: "eyJ.PAYLOAD.SIG~",
          exp: 1_700_000_000,
        },
        { status: 201 },
      );
    });
    vi.stubGlobal("fetch", fetchMock);
    const { io } = makeIo();
    const res = await runAgent(
      [
        "mint",
        "--agent",
        "agent-1",
        "--on-behalf-of",
        "alice@example.com",
        "--tool",
        "t",
        "--scope",
        "{}",
        "--audience",
        "aud",
        "--ttl",
        "1d",
      ],
      io,
      baseEnv,
    );
    expect(res.exitCode).toBe(0);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("accepts bare integer --ttl 3600 as raw seconds", async () => {
    const fetchMock = vi.fn(async (_input: string | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      expect(body.ttl_seconds).toBe(3600);
      return Response.json(
        { jti: "00000000-0000-4000-8000-000000000004", sd_jwt: "x~", exp: 1 },
        { status: 201 },
      );
    });
    vi.stubGlobal("fetch", fetchMock);
    const { io } = makeIo();
    const res = await runAgent(
      [
        "mint",
        "--agent",
        "agent-1",
        "--on-behalf-of",
        "alice@example.com",
        "--tool",
        "t",
        "--scope",
        "{}",
        "--audience",
        "aud",
        "--ttl",
        "3600",
      ],
      io,
      baseEnv,
    );
    expect(res.exitCode).toBe(0);
  });

  it("rejects a malformed --ttl value before any network call", async () => {
    const fetchMock = vi.fn(async () => {
      throw new Error("should not be called");
    });
    vi.stubGlobal("fetch", fetchMock);
    const { io, err } = makeIo();
    const res = await runAgent(
      [
        "mint",
        "--agent",
        "agent-1",
        "--on-behalf-of",
        "alice@example.com",
        "--tool",
        "t",
        "--scope",
        "{}",
        "--audience",
        "aud",
        "--ttl",
        "7y",
      ],
      io,
      baseEnv,
    );
    expect(res.exitCode).toBe(1);
    expect(err.join("")).toContain("--ttl");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("exits 1 when PACT_ADMIN_TOKEN is missing", async () => {
    const { io, err } = makeIo();
    const res = await runAgent(
      [
        "mint",
        "--agent",
        "agent-1",
        "--on-behalf-of",
        "alice@example.com",
        "--tool",
        "t",
        "--scope",
        "{}",
        "--audience",
        "aud",
      ],
      io,
      { PACT_API_BASE: "https://issuer.test" } as NodeJS.ProcessEnv,
    );
    expect(res.exitCode).toBe(1);
    expect(err.join("")).toContain("PACT_ADMIN_TOKEN");
  });
});

describe("runAgent revoke", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("calls DELETE /v1/capabilities/:jti and prints revoked list", async () => {
    const fetchMock = vi.fn(async (input: string | URL, init?: RequestInit) => {
      expect(String(input)).toBe(
        "https://issuer.test/v1/capabilities/00000000-0000-4000-8000-000000000099",
      );
      expect(init?.method).toBe("DELETE");
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      expect(body.cascade).toBe(true);
      expect(body.reason).toBe("leaked");
      return Response.json({
        revoked: ["00000000-0000-4000-8000-000000000099", "00000000-0000-4000-8000-0000000000aa"],
        count: 2,
      });
    });
    vi.stubGlobal("fetch", fetchMock);
    const { io, out } = makeIo();
    const res = await runAgent(
      ["revoke", "00000000-0000-4000-8000-000000000099", "--reason", "leaked"],
      io,
      baseEnv,
    );
    expect(res.exitCode).toBe(0);
    const joined = out.join("");
    expect(joined).toContain("00000000-0000-4000-8000-000000000099");
    expect(joined).toContain("00000000-0000-4000-8000-0000000000aa");
    expect(joined).toContain("revoked 2");
  });

  it("honors --no-cascade", async () => {
    const fetchMock = vi.fn(async (_input: string | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      expect(body.cascade).toBe(false);
      return Response.json({ revoked: ["00000000-0000-4000-8000-000000000099"], count: 1 });
    });
    vi.stubGlobal("fetch", fetchMock);
    const { io } = makeIo();
    const res = await runAgent(
      ["revoke", "00000000-0000-4000-8000-000000000099", "--no-cascade"],
      io,
      baseEnv,
    );
    expect(res.exitCode).toBe(0);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

describe("runAgent list", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("renders a table with status filter applied to the request", async () => {
    const fetchMock = vi.fn(async (input: string | URL) => {
      const u = new URL(String(input));
      expect(u.pathname).toBe("/v1/agents");
      expect(u.searchParams.get("workspace_id")).toBe("ws-1");
      expect(u.searchParams.get("status")).toBe("active");
      return Response.json({
        agents: [
          {
            id: "a-1",
            name: "agent one",
            status: "active",
            created_at: "2026-01-01T00:00:00Z",
          },
        ],
      });
    });
    vi.stubGlobal("fetch", fetchMock);
    const { io, out } = makeIo();
    const res = await runAgent(["list", "--status", "active"], io, baseEnv);
    expect(res.exitCode).toBe(0);
    const joined = out.join("");
    expect(joined).toContain("ID");
    expect(joined).toContain("a-1");
    expect(joined).toContain("agent one");
    expect(joined).toContain("active");
  });

  it("supports --format json", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Response.json({ agents: [{ id: "a-1", status: "active" }] })),
    );
    const { io, out } = makeIo();
    const res = await runAgent(["list", "--format", "json"], io, baseEnv);
    expect(res.exitCode).toBe(0);
    const parsed = JSON.parse(out.join("")) as { agents: Array<Record<string, unknown>> };
    expect(parsed.agents[0]?.id).toBe("a-1");
  });
});

describe("runAgent dispatch", () => {
  let originalFetch: typeof fetch;
  beforeEach(() => {
    originalFetch = globalThis.fetch;
  });
  afterEach(() => {
    globalThis.fetch = originalFetch;
  });

  it("prints usage and exits 1 on unknown subcommand", async () => {
    const { io, err } = makeIo();
    const res = await runAgent(["nope"], io, baseEnv);
    expect(res.exitCode).toBe(1);
    expect(err.join("")).toContain("usage: pact agent create");
    expect(err.join("")).toContain("pact agent generate-keypair");
  });
});

describe("buildCreateAgentBody", () => {
  it("emits snake_case keys and skips optional fields", () => {
    const body = buildCreateAgentBody({
      workspaceId: "ws-1",
      name: "smoke",
      ownerUserId: "00000000-0000-4000-8000-000000000001",
      pubkeyJwk: { kty: "OKP", crv: "Ed25519", x: "abc" },
    });
    expect(body).toEqual({
      name: "smoke",
      owner_user_id: "00000000-0000-4000-8000-000000000001",
      pubkey_jwk: { kty: "OKP", crv: "Ed25519", x: "abc" },
    });
    expect("kind" in body).toBe(false);
    expect("description" in body).toBe(false);
  });

  it("includes kind and description when provided", () => {
    const body = buildCreateAgentBody({
      workspaceId: "ws-1",
      name: "smoke",
      ownerUserId: "00000000-0000-4000-8000-000000000001",
      pubkeyJwk: { kty: "OKP", crv: "Ed25519", x: "abc" },
      kind: "user_delegated",
      description: "long-lived agent",
    });
    expect(body.kind).toBe("user_delegated");
    expect(body.description).toBe("long-lived agent");
  });
});

describe("runAgent create", () => {
  let tmp: string;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), "pact-agent-create-"));
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    rmSync(tmp, { recursive: true, force: true });
  });

  it("POSTs /v1/workspaces/:id/agents with the parsed body and prints the new agent", async () => {
    const keyFile = join(tmp, "pub.json");
    writeFileSync(keyFile, JSON.stringify({ kty: "OKP", crv: "Ed25519", x: "AAAA" }));
    const fetchMock = vi.fn(async (input: string | URL, init?: RequestInit) => {
      expect(String(input)).toBe("https://issuer.test/v1/workspaces/ws-1/agents");
      expect(init?.method).toBe("POST");
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      expect(body.name).toBe("smoke");
      expect(body.owner_user_id).toBe("00000000-0000-4000-8000-000000000001");
      expect(body.pubkey_jwk).toEqual({ kty: "OKP", crv: "Ed25519", x: "AAAA" });
      const headers = init?.headers as Record<string, string>;
      expect(headers.authorization).toBe("Bearer admin-token");
      return Response.json(
        {
          agent: {
            id: "00000000-0000-4000-8000-0000000000aa",
            name: "smoke",
            slug: "smoke",
            status: "active",
            owner_user_id: "00000000-0000-4000-8000-000000000001",
            created_at: "2026-05-17T12:00:00Z",
          },
        },
        { status: 201 },
      );
    });
    vi.stubGlobal("fetch", fetchMock);
    const { io, out } = makeIo();
    const res = await runAgent(
      [
        "create",
        "smoke",
        "--owner",
        "00000000-0000-4000-8000-000000000001",
        "--public-key",
        keyFile,
      ],
      io,
      baseEnv,
    );
    expect(res.exitCode).toBe(0);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const joined = out.join("");
    expect(joined).toContain("id           00000000-0000-4000-8000-0000000000aa");
    expect(joined).toContain("slug         smoke");
    expect(joined).toContain("status       active");
  });

  it("accepts an inline JWK string in --public-key", async () => {
    const fetchMock = vi.fn(async (_input: string | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      expect(body.pubkey_jwk).toEqual({ kty: "OKP", crv: "Ed25519", x: "BBBB" });
      return Response.json({ agent: { id: "id-1", status: "active" } }, { status: 201 });
    });
    vi.stubGlobal("fetch", fetchMock);
    const { io } = makeIo();
    const res = await runAgent(
      [
        "create",
        "smoke",
        "--owner",
        "00000000-0000-4000-8000-000000000001",
        "--public-key",
        '{"kty":"OKP","crv":"Ed25519","x":"BBBB"}',
      ],
      io,
      baseEnv,
    );
    expect(res.exitCode).toBe(0);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("accepts a wrapped {publicJwk,...} record from generate-keypair output", async () => {
    const keyFile = join(tmp, "wrapped.json");
    writeFileSync(
      keyFile,
      JSON.stringify({
        version: 1,
        publicJwk: { kty: "OKP", crv: "Ed25519", x: "CCCC" },
        privatePkcs8Base64: "AAAA",
      }),
    );
    const fetchMock = vi.fn(async (_input: string | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      expect(body.pubkey_jwk).toEqual({ kty: "OKP", crv: "Ed25519", x: "CCCC" });
      return Response.json({ agent: { id: "id-2", status: "active" } }, { status: 201 });
    });
    vi.stubGlobal("fetch", fetchMock);
    const { io } = makeIo();
    const res = await runAgent(
      [
        "create",
        "smoke",
        "--owner",
        "00000000-0000-4000-8000-000000000001",
        "--public-key",
        keyFile,
      ],
      io,
      baseEnv,
    );
    expect(res.exitCode).toBe(0);
  });

  it("forwards --kind and --description in the request body", async () => {
    const fetchMock = vi.fn(async (_input: string | URL, init?: RequestInit) => {
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      expect(body.kind).toBe("user_delegated");
      expect(body.description).toBe("ops bot");
      return Response.json({ agent: { id: "id-3", status: "active" } }, { status: 201 });
    });
    vi.stubGlobal("fetch", fetchMock);
    const { io } = makeIo();
    const res = await runAgent(
      [
        "create",
        "smoke",
        "--owner",
        "00000000-0000-4000-8000-000000000001",
        "--public-key",
        '{"kty":"OKP","crv":"Ed25519","x":"AAAA"}',
        "--kind",
        "user_delegated",
        "--description",
        "ops bot",
      ],
      io,
      baseEnv,
    );
    expect(res.exitCode).toBe(0);
  });

  it("exits 1 and points to generate-keypair when --public-key is missing", async () => {
    const fetchMock = vi.fn(async () => {
      throw new Error("should not be called");
    });
    vi.stubGlobal("fetch", fetchMock);
    const { io, err } = makeIo();
    const res = await runAgent(
      ["create", "smoke", "--owner", "00000000-0000-4000-8000-000000000001"],
      io,
      baseEnv,
    );
    expect(res.exitCode).toBe(1);
    const joined = err.join("");
    expect(joined).toContain("--public-key");
    expect(joined).toContain("generate-keypair");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("rejects a non-Ed25519 JWK before any network call", async () => {
    const fetchMock = vi.fn(async () => {
      throw new Error("should not be called");
    });
    vi.stubGlobal("fetch", fetchMock);
    const { io, err } = makeIo();
    const res = await runAgent(
      [
        "create",
        "smoke",
        "--owner",
        "00000000-0000-4000-8000-000000000001",
        "--public-key",
        '{"kty":"EC","crv":"P-256","x":"x","y":"y"}',
      ],
      io,
      baseEnv,
    );
    expect(res.exitCode).toBe(1);
    expect(err.join("")).toContain("Ed25519");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("surfaces a 409 conflict from the admin api", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        Response.json(
          { error: "conflict", code: "slug_taken", message: "agent slug already exists" },
          { status: 409 },
        ),
      ),
    );
    const { io, err } = makeIo();
    const res = await runAgent(
      [
        "create",
        "smoke",
        "--owner",
        "00000000-0000-4000-8000-000000000001",
        "--public-key",
        '{"kty":"OKP","crv":"Ed25519","x":"AAAA"}',
      ],
      io,
      baseEnv,
    );
    expect(res.exitCode).toBe(1);
    const joined = err.join("");
    expect(joined).toContain("conflict");
    expect(joined).toContain("agent slug already exists");
    expect(joined).toContain("status 409");
  });

  it("exits 1 when no workspace id is provided", async () => {
    const { io, err } = makeIo();
    const res = await runAgent(
      [
        "create",
        "smoke",
        "--owner",
        "00000000-0000-4000-8000-000000000001",
        "--public-key",
        '{"kty":"OKP","crv":"Ed25519","x":"AAAA"}',
      ],
      io,
      {
        PACT_API_BASE: "https://issuer.test",
        PACT_ADMIN_TOKEN: "admin-token",
      } as NodeJS.ProcessEnv,
    );
    expect(res.exitCode).toBe(1);
    expect(err.join("")).toContain("workspace");
  });
});

describe("generateKeypairRecord", () => {
  it("returns an Ed25519 OKP public JWK and base64 pkcs8 private", async () => {
    const record = await generateKeypairRecord();
    expect(record.publicJwk.kty).toBe("OKP");
    expect(record.publicJwk.crv).toBe("Ed25519");
    expect(record.publicJwk.x.length).toBeGreaterThan(0);
    expect(record.privatePkcs8Base64.length).toBeGreaterThan(0);
    expect(() => Buffer.from(record.privatePkcs8Base64, "base64")).not.toThrow();
  });
});

describe("runAgent generate-keypair", () => {
  let tmp: string;

  beforeEach(() => {
    tmp = mkdtempSync(join(tmpdir(), "pact-agent-genkey-"));
  });

  afterEach(() => {
    rmSync(tmp, { recursive: true, force: true });
  });

  it("prints a wrapped JSON record to stdout when --out is omitted", async () => {
    const { io, out } = makeIo();
    const res = await runAgent(["generate-keypair"], io, baseEnv);
    expect(res.exitCode).toBe(0);
    const parsed = JSON.parse(out.join("")) as {
      version: number;
      publicJwk: { kty: string; crv: string; x: string };
      privatePkcs8Base64: string;
    };
    expect(parsed.version).toBe(1);
    expect(parsed.publicJwk.kty).toBe("OKP");
    expect(parsed.publicJwk.crv).toBe("Ed25519");
    expect(parsed.privatePkcs8Base64.length).toBeGreaterThan(0);
  });

  it("writes the private key with mode 0600 when --out is set", async () => {
    const outPath = join(tmp, "key.json");
    const { io } = makeIo();
    const res = await runAgent(["generate-keypair", "--out", outPath], io, baseEnv);
    expect(res.exitCode).toBe(0);
    const mode = statSync(outPath).mode & 0o777;
    expect(mode).toBe(0o600);
    const parsed = JSON.parse(readFileSync(outPath, "utf8")) as {
      publicJwk: { x: string };
      privatePkcs8Base64: string;
    };
    expect(parsed.publicJwk.x.length).toBeGreaterThan(0);
    expect(parsed.privatePkcs8Base64.length).toBeGreaterThan(0);
  });

  it("writes a public-only JWK when --public-out is set", async () => {
    const privPath = join(tmp, "priv.json");
    const pubPath = join(tmp, "pub.json");
    const { io } = makeIo();
    const res = await runAgent(
      ["generate-keypair", "--out", privPath, "--public-out", pubPath],
      io,
      baseEnv,
    );
    expect(res.exitCode).toBe(0);
    const pub = JSON.parse(readFileSync(pubPath, "utf8")) as Record<string, unknown>;
    expect(pub.kty).toBe("OKP");
    expect(pub.crv).toBe("Ed25519");
    expect(typeof pub.x).toBe("string");
    expect("privatePkcs8Base64" in pub).toBe(false);
  });
});
