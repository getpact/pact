import { describe, expect, it, vi } from "vitest";
import { createSlackClient } from "../index.js";

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
});
