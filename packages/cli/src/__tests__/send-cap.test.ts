import { afterEach, describe, expect, it, vi } from "vitest";
import {
  buildGrantBody,
  formatSendCapsTable,
  parseFlags,
  runSendCap,
} from "../commands/send-cap.js";

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
  PACT_WORKSPACE_ID: "00000000-0000-0000-0000-000000000099",
} as NodeJS.ProcessEnv;

describe("buildGrantBody", () => {
  it("snake_cases the body and elides unset fields", () => {
    expect(buildGrantBody({ granteeUserId: "u1" })).toEqual({ grantee_user_id: "u1" });
    expect(
      buildGrantBody({
        granteeUserId: "u1",
        scopePattern: { tag: "work" },
        maxUses: 5,
        expiresAt: "2099-01-01T00:00:00Z",
      }),
    ).toEqual({
      grantee_user_id: "u1",
      scope_pattern: { tag: "work" },
      max_uses: 5,
      expires_at: "2099-01-01T00:00:00Z",
    });
  });
});

describe("formatSendCapsTable", () => {
  it("renders a header and a row", () => {
    const out = formatSendCapsTable([
      {
        id: "cap-1",
        workspace_id: "ws",
        issuer_user_id: "alice",
        grantee_user_id: "bob",
        scope_pattern: {},
        max_uses: 5,
        used_count: 1,
        expires_at: null,
        created_at: "2026-01-01T00:00:00Z",
        revoked_at: null,
        revoked_reason: null,
      },
    ]);
    expect(out).toContain("ID");
    expect(out).toContain("cap-1");
    expect(out).toContain("alice");
    expect(out).toContain("1/5");
  });

  it("returns a friendly message when empty", () => {
    expect(formatSendCapsTable([])).toBe("no send caps\n");
  });
});

describe("parseFlags", () => {
  it("handles flags and positionals", () => {
    const p = parseFlags(["grant", "--to", "u1", "--max-uses", "3"]);
    expect(p.positional).toEqual(["grant"]);
    expect(p.flags.get("to")).toBe("u1");
    expect(p.flags.get("max-uses")).toBe("3");
  });
});

describe("runSendCap grant", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("POSTs to the workspace-scoped path with the admin token", async () => {
    const fetchMock = vi.fn(async (input: string | URL, init?: RequestInit) => {
      expect(String(input)).toBe(
        "https://issuer.test/v1/workspaces/00000000-0000-0000-0000-000000000099/send-caps",
      );
      expect(init?.method).toBe("POST");
      const headers = init?.headers as Record<string, string>;
      expect(headers.authorization).toBe("Bearer admin-token");
      expect(headers["x-pact-workspace-id"]).toBeUndefined();
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      expect(body.grantee_user_id).toBe("bob");
      expect(body.max_uses).toBe(5);
      return Response.json(
        {
          send_cap: {
            id: "cap-1",
            workspace_id: "ws",
            issuer_user_id: "alice",
            grantee_user_id: "bob",
            scope_pattern: {},
            max_uses: 5,
            used_count: 0,
            expires_at: null,
            created_at: "2026-01-01T00:00:00Z",
            revoked_at: null,
            revoked_reason: null,
          },
        },
        { status: 201 },
      );
    });
    vi.stubGlobal("fetch", fetchMock);

    const { io, out } = makeIo();
    const res = await runSendCap(["grant", "--to", "bob", "--max-uses", "5"], io, baseEnv);
    expect(res.exitCode).toBe(0);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    expect(out.join("")).toContain("cap-1");
  });

  it("exits 1 when PACT_ADMIN_TOKEN is missing", async () => {
    const { io, err } = makeIo();
    const res = await runSendCap(["grant", "--to", "bob"], io, {
      PACT_API_BASE: "https://issuer.test",
      PACT_WORKSPACE_ID: "ws",
    } as NodeJS.ProcessEnv);
    expect(res.exitCode).toBe(1);
    expect(err.join("")).toContain("PACT_ADMIN_TOKEN");
  });
});

describe("runSendCap list", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("GETs and applies filters", async () => {
    const fetchMock = vi.fn(async (input: string | URL) => {
      const u = new URL(String(input));
      expect(u.pathname).toBe("/v1/workspaces/00000000-0000-0000-0000-000000000099/send-caps");
      expect(u.searchParams.get("active")).toBe("true");
      expect(u.searchParams.get("from")).toBeNull();
      expect(u.searchParams.get("issuer_user_id")).toBe("alice");
      return Response.json({ send_caps: [] });
    });
    vi.stubGlobal("fetch", fetchMock);
    const { io } = makeIo();
    const res = await runSendCap(["list", "--from", "alice", "--active"], io, baseEnv);
    expect(res.exitCode).toBe(0);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });
});

describe("runSendCap revoke", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("DELETEs and forwards reason", async () => {
    const fetchMock = vi.fn(async (input: string | URL, init?: RequestInit) => {
      expect(String(input)).toBe(
        "https://issuer.test/v1/workspaces/00000000-0000-0000-0000-000000000099/send-caps/cap-1",
      );
      expect(init?.method).toBe("DELETE");
      const body = JSON.parse(String(init?.body)) as Record<string, unknown>;
      expect(body.reason).toBe("rotated");
      return Response.json({
        send_cap: {
          id: "cap-1",
          workspace_id: "ws",
          issuer_user_id: "alice",
          grantee_user_id: "bob",
          scope_pattern: {},
          max_uses: null,
          used_count: 0,
          expires_at: null,
          created_at: "2026-01-01T00:00:00Z",
          revoked_at: "2026-01-02T00:00:00Z",
          revoked_reason: "rotated",
        },
      });
    });
    vi.stubGlobal("fetch", fetchMock);
    const { io, out } = makeIo();
    const res = await runSendCap(["revoke", "cap-1", "--reason", "rotated"], io, baseEnv);
    expect(res.exitCode).toBe(0);
    expect(out.join("")).toContain("rotated");
  });

  it("prints structured error and exits 1 on a 403", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        Response.json(
          { error: "forbidden", message: "only the issuer may revoke a send_cap" },
          { status: 403 },
        ),
      ),
    );
    const { io, err } = makeIo();
    const res = await runSendCap(["revoke", "cap-1"], io, baseEnv);
    expect(res.exitCode).toBe(1);
    expect(err.join("")).toContain("forbidden");
  });
});

describe("runSendCap dispatch", () => {
  it("prints usage on unknown subcommand", async () => {
    const { io, err } = makeIo();
    const res = await runSendCap(["nope"], io, baseEnv);
    expect(res.exitCode).toBe(1);
    expect(err.join("")).toContain("usage: pact send-cap grant");
  });
});
