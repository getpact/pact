import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { buildMintBody, formatAgentsTable, parseFlags, runAgent } from "../commands/agent.js";

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
    expect(err.join("")).toContain("usage: pact agent mint");
  });
});
