import { describe, expect, it, vi } from "vitest";
import { createSlackAdapter, createSlackClient } from "../index.js";

describe("Slack adapter", () => {
  it("calls Slack auth.test with a bearer token", async () => {
    const fetchMock = vi.fn(async () =>
      Response.json({
        ok: true,
        team: "Acme",
        team_id: "T1",
        user: "pact",
        user_id: "U1",
        bot_id: "B1",
      }),
    );
    const client = createSlackClient({
      token: "xoxb-test",
      apiBaseUrl: "https://slack.test/api",
      fetch: fetchMock as unknown as typeof fetch,
    });

    const result = await client.authTest();

    expect(fetchMock).toHaveBeenCalledWith(
      "https://slack.test/api/auth.test",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({ authorization: "Bearer xoxb-test" }),
      }),
    );
    expect(result).toEqual({
      ok: true,
      team: "Acme",
      teamId: "T1",
      user: "pact",
      userId: "U1",
      botId: "B1",
    });
  });

  it("returns Slack error payloads", async () => {
    const fetchMock = vi.fn(async () => Response.json({ ok: false, error: "invalid_auth" }));
    const client = createSlackClient({ token: "bad", fetch: fetchMock as unknown as typeof fetch });

    await expect(client.authTest()).resolves.toEqual({ ok: false, error: "invalid_auth" });
  });

  it("lists conversations with cursor pagination", async () => {
    const fetchMock = vi.fn(async () =>
      Response.json({
        ok: true,
        channels: [
          { id: "C1", name: "general", is_private: false, is_member: true },
          { id: "C2", name: "random", is_private: false, is_member: false },
        ],
        response_metadata: { next_cursor: "abc==" },
      }),
    );
    const client = createSlackClient({
      token: "xoxb-test",
      apiBaseUrl: "https://slack.test/api",
      fetch: fetchMock as unknown as typeof fetch,
    });
    const result = await client.conversationsList({ limit: 50, types: "public_channel" });
    expect(result).toEqual({
      ok: true,
      channels: [
        { id: "C1", name: "general", isPrivate: false, isMember: true },
        { id: "C2", name: "random", isPrivate: false, isMember: false },
      ],
      nextCursor: "abc==",
    });
    expect(fetchMock).toHaveBeenCalledWith(
      "https://slack.test/api/conversations.list",
      expect.objectContaining({
        method: "POST",
        body: expect.stringContaining("limit=50"),
      }),
    );
  });

  it("returns nextCursor null when no more pages", async () => {
    const fetchMock = vi.fn(async () =>
      Response.json({
        ok: true,
        channels: [{ id: "C1", name: "only" }],
        response_metadata: { next_cursor: "" },
      }),
    );
    const client = createSlackClient({
      token: "xoxb-test",
      fetch: fetchMock as unknown as typeof fetch,
    });
    const result = await client.conversationsList();
    if (!result.ok) throw new Error("expected ok");
    expect(result.nextCursor).toBeNull();
    expect(result.channels.length).toBe(1);
  });

  it("propagates Slack error payload from conversationsList", async () => {
    const fetchMock = vi.fn(async () => Response.json({ ok: false, error: "missing_scope" }));
    const client = createSlackClient({
      token: "xoxb-test",
      fetch: fetchMock as unknown as typeof fetch,
    });
    await expect(client.conversationsList()).resolves.toEqual({
      ok: false,
      error: "missing_scope",
    });
  });

  it("exports adapter tools backed by an injected token loader", async () => {
    const calls: unknown[] = [];
    const adapter = createSlackAdapter({
      loadBotToken: async () => "xoxb-test",
      createClient: () => ({
        authTest: async () => ({ ok: true, team: "Acme" }),
        conversationsList: async (input) => {
          calls.push(input);
          return { ok: true, channels: [{ id: "C1", name: "general" }], nextCursor: null };
        },
      }),
    });
    const ctx = {
      workspaceId: "ws1",
      userId: "u1",
      email: "alice@example.com",
      groups: [],
      roles: ["admin"],
    };
    const deps = { databaseUrl: "postgres://unused", rawMek: new Uint8Array([1]) };

    const auth = await adapter.tools
      .find((tool) => tool.descriptor.name === "pact.slack.auth.test")
      ?.handler({}, ctx, deps);
    expect(auth?.content[0]?.text).toContain('"team": "Acme"');

    const channels = await adapter.tools
      .find((tool) => tool.descriptor.name === "pact.slack.channels.list")
      ?.handler({ limit: 25, cursor: "next", types: "public_channel" }, ctx, deps);
    expect(channels?.content[0]?.text).toContain("general");
    expect(calls[0]).toEqual({ limit: 25, cursor: "next", types: "public_channel" });
  });

  it("scopes adapter authorization resources to the workspace", () => {
    const adapter = createSlackAdapter({
      loadBotToken: async () => "xoxb-test",
      createClient: () => {
        throw new Error("should not build client");
      },
    });
    const ctx = {
      workspaceId: "ws1",
      userId: "u1",
      email: "alice@example.com",
      groups: [],
      roles: ["admin"],
    };

    const authTest = adapter.tools.find((tool) => tool.descriptor.name === "pact.slack.auth.test");
    const channels = adapter.tools.find(
      (tool) => tool.descriptor.name === "pact.slack.channels.list",
    );

    expect(authTest?.authorize?.({}, ctx)).toEqual({
      action: "slack.auth.test",
      resource: "slack:workspace:ws1",
    });
    expect(channels?.authorize?.({}, ctx)).toEqual({
      action: "slack.channels.list",
      resource: "slack:workspace:ws1:channels:public",
    });
  });

  it("adapter tools report missing vault prerequisites", async () => {
    const adapter = createSlackAdapter({
      loadBotToken: async () => null,
      createClient: () => {
        throw new Error("should not build client");
      },
    });
    const ctx = {
      workspaceId: "ws1",
      userId: "u1",
      email: "alice@example.com",
      groups: [],
      roles: ["admin"],
    };

    const noMek = await adapter.tools[0]?.handler({}, ctx, { databaseUrl: "postgres://unused" });
    expect(noMek?.isError).toBe(true);
    expect(noMek?.content[0]?.text).toBe("MEK is not configured");

    const noToken = await adapter.tools[0]?.handler({}, ctx, {
      databaseUrl: "postgres://unused",
      rawMek: new Uint8Array([1]),
    });
    expect(noToken?.isError).toBe(true);
    expect(noToken?.content[0]?.text).toBe("Slack bot token not found");
  });

  it("adapter tools surface Slack API errors as MCP errors", async () => {
    const adapter = createSlackAdapter({
      loadBotToken: async () => "xoxb-test",
      createClient: () => ({
        authTest: async () => ({ ok: false, error: "invalid_auth" }),
        conversationsList: async () => ({ ok: false, error: "missing_scope" }),
      }),
    });
    const ctx = {
      workspaceId: "ws1",
      userId: "u1",
      email: "alice@example.com",
      groups: [],
      roles: ["admin"],
    };
    const deps = { databaseUrl: "postgres://unused", rawMek: new Uint8Array([1]) };

    const auth = await adapter.tools
      .find((tool) => tool.descriptor.name === "pact.slack.auth.test")
      ?.handler({}, ctx, deps);
    expect(auth?.isError).toBe(true);
    expect(auth?.content[0]?.text).toBe("Slack API error: invalid_auth");

    const channels = await adapter.tools
      .find((tool) => tool.descriptor.name === "pact.slack.channels.list")
      ?.handler({}, ctx, deps);
    expect(channels?.isError).toBe(true);
    expect(channels?.content[0]?.text).toBe("Slack API error: missing_scope");
  });

  it("adapter channel listing rejects non-public Slack surfaces", async () => {
    const adapter = createSlackAdapter({
      loadBotToken: async () => "xoxb-test",
      createClient: () => ({
        authTest: async () => ({ ok: true }),
        conversationsList: async () => {
          throw new Error("should not call Slack");
        },
      }),
    });
    const ctx = {
      workspaceId: "ws1",
      userId: "u1",
      email: "alice@example.com",
      groups: [],
      roles: ["admin"],
    };

    const channels = await adapter.tools
      .find((tool) => tool.descriptor.name === "pact.slack.channels.list")
      ?.handler({ types: "private_channel,im" }, ctx, {
        databaseUrl: "postgres://unused",
        rawMek: new Uint8Array([1]),
      });

    expect(channels?.isError).toBe(true);
    expect(channels?.content[0]?.text).toBe("Slack channel types are restricted to public_channel");
  });
});
