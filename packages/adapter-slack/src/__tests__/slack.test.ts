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
});
