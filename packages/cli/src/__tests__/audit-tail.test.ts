import { afterEach, describe, expect, it, vi } from "vitest";
import { formatEventsTable, parseFlags, runAuditCmd } from "../commands/audit.js";

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
  PACT_ADMIN_API_BASE: "https://admin.test",
  PACT_ADMIN_TOKEN: "admin-token",
  PACT_WORKSPACE_ID: "ws-1",
} as NodeJS.ProcessEnv;

const sampleEvent = (overrides: Partial<Record<string, unknown>> = {}) => ({
  id: "ev-1",
  workspaceId: "ws-1",
  auditSeq: 1,
  ts: "2026-05-17T12:00:00.000Z",
  actorKind: "user",
  actorId: "alice@local.test",
  action: "admin.user.created",
  target: {},
  decision: "allow",
  supporting: {},
  signingKeyId: "k-1",
  prevHash: "",
  thisHash: "h",
  signature: "sig",
  ...overrides,
});

describe("parseFlags", () => {
  it("collects positionals, values, and bare booleans", () => {
    const p = parseFlags(["tail", "--limit", "10", "--format=json"]);
    expect(p.positional).toEqual(["tail"]);
    expect(p.flags.get("limit")).toBe("10");
    expect(p.flags.get("format")).toBe("json");
  });
});

describe("formatEventsTable", () => {
  it("renders header, separator, and rows", () => {
    const out = formatEventsTable([sampleEvent() as never]);
    expect(out).toContain("TS");
    expect(out).toContain("ACTION");
    expect(out).toContain("alice@local.test");
    expect(out).toContain("admin.user.created");
    expect(out).toContain("allow");
  });

  it("returns a friendly message when there are no rows", () => {
    expect(formatEventsTable([])).toBe("no audit events\n");
  });
});

describe("runAuditCmd tail", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("calls GET /v1/workspaces/:id/audit/events and renders a table", async () => {
    const fetchMock = vi.fn(async (input: string | URL, init?: RequestInit) => {
      const url = new URL(String(input));
      expect(url.pathname).toBe("/v1/workspaces/ws-1/audit/events");
      expect(url.searchParams.get("limit")).toBe("100");
      expect(url.searchParams.get("order")).toBe("desc");
      const headers = init?.headers as Record<string, string>;
      expect(headers.authorization).toBe("Bearer admin-token");
      return Response.json({
        events: [sampleEvent({ action: "agent.capability.minted" })],
        nextCursor: null,
      });
    });
    vi.stubGlobal("fetch", fetchMock);
    const { io, out } = makeIo();
    const res = await runAuditCmd(["tail"], io, baseEnv);
    expect(res.exitCode).toBe(0);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const joined = out.join("");
    expect(joined).toContain("TS");
    expect(joined).toContain("agent.capability.minted");
    expect(joined).toContain("alice@local.test");
  });

  it("forwards --limit, --after, and --action to the request", async () => {
    const fetchMock = vi.fn(async (input: string | URL) => {
      const url = new URL(String(input));
      expect(url.searchParams.get("limit")).toBe("25");
      expect(url.searchParams.get("cursor")).toBe("42");
      expect(url.searchParams.get("action")).toBe("admin.agent.created");
      return Response.json({ events: [], nextCursor: null });
    });
    vi.stubGlobal("fetch", fetchMock);
    const { io } = makeIo();
    const res = await runAuditCmd(
      ["tail", "--limit", "25", "--after", "42", "--action", "admin.agent.created"],
      io,
      baseEnv,
    );
    expect(res.exitCode).toBe(0);
  });

  it("emits JSON when --format json", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Response.json({ events: [sampleEvent()], nextCursor: "next" })),
    );
    const { io, out } = makeIo();
    const res = await runAuditCmd(["tail", "--format", "json"], io, baseEnv);
    expect(res.exitCode).toBe(0);
    const parsed = JSON.parse(out.join("")) as { events: unknown[]; nextCursor: string | null };
    expect(parsed.events.length).toBe(1);
    expect(parsed.nextCursor).toBe("next");
  });

  it("prints a next-cursor footer when the API returns one", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => Response.json({ events: [sampleEvent()], nextCursor: "abc" })),
    );
    const { io, out } = makeIo();
    const res = await runAuditCmd(["tail"], io, baseEnv);
    expect(res.exitCode).toBe(0);
    expect(out.join("")).toContain("next cursor: abc");
  });

  it("exits 1 with auth message on 401", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        Response.json({ error: "unauthorized", message: "bad token" }, { status: 401 }),
      ),
    );
    const { io, err } = makeIo();
    const res = await runAuditCmd(["tail"], io, baseEnv);
    expect(res.exitCode).toBe(1);
    const joined = err.join("");
    expect(joined).toContain("unauthorized");
    expect(joined).toContain("bad token");
    expect(joined).toContain("status 401");
  });

  it("exits 1 when PACT_ADMIN_TOKEN is missing", async () => {
    const { io, err } = makeIo();
    const res = await runAuditCmd(["tail"], io, {
      PACT_ADMIN_API_BASE: "https://admin.test",
      PACT_WORKSPACE_ID: "ws-1",
    } as NodeJS.ProcessEnv);
    expect(res.exitCode).toBe(1);
    expect(err.join("")).toContain("PACT_ADMIN_TOKEN");
  });

  it("exits 1 when no workspace id is provided", async () => {
    const { io, err } = makeIo();
    const res = await runAuditCmd(["tail"], io, {
      PACT_ADMIN_API_BASE: "https://admin.test",
      PACT_ADMIN_TOKEN: "t",
    } as NodeJS.ProcessEnv);
    expect(res.exitCode).toBe(1);
    expect(err.join("")).toContain("workspace");
  });

  it("rejects an invalid --limit before any network call", async () => {
    const fetchMock = vi.fn(async () => {
      throw new Error("should not be called");
    });
    vi.stubGlobal("fetch", fetchMock);
    const { io, err } = makeIo();
    const res = await runAuditCmd(["tail", "--limit", "abc"], io, baseEnv);
    expect(res.exitCode).toBe(1);
    expect(err.join("")).toContain("--limit");
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

describe("runAuditCmd dispatch", () => {
  it("prints usage on unknown subcommand", async () => {
    const { io, err } = makeIo();
    const res = await runAuditCmd(["nope"], io, baseEnv);
    expect(res.exitCode).toBe(1);
    expect(err.join("")).toContain("usage: pact audit tail");
  });
});
