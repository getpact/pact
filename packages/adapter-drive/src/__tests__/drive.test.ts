import { describe, expect, it } from "vitest";

import { createDriveAdapter, createDriveClient, type DriveConnection } from "../index";

describe("createDriveClient", () => {
  it("lists files with bearer auth", async () => {
    const requests: Request[] = [];
    const client = createDriveClient({
      accessToken: "drive-token",
      apiBaseUrl: "https://drive.example/v3",
      fetch: async (input, init) => {
        requests.push(new Request(input, init));
        return Response.json({
          files: [{ id: "file_1", name: "Plan" }],
          nextPageToken: "next",
        });
      },
    });

    const result = await client.listFiles({
      pageSize: 200,
      pageToken: "cursor",
      q: "trashed = false",
    });

    expect(result.files).toEqual([{ id: "file_1", name: "Plan" }]);
    expect(result.nextPageToken).toBe("next");
    expect(requests[0]?.headers.get("authorization")).toBe("Bearer drive-token");
    expect(new URL(requests[0]?.url ?? "").searchParams.get("pageSize")).toBe("100");
    expect(new URL(requests[0]?.url ?? "").searchParams.get("q")).toBe("trashed = false");
  });

  it("exports a file as text", async () => {
    const urls: string[] = [];
    const client = createDriveClient({
      accessToken: "drive-token",
      apiBaseUrl: "https://drive.example/v3",
      fetch: async (input) => {
        urls.push(String(input));
        return new Response("hello");
      },
    });

    await expect(client.exportText({ fileId: "abc_123" })).resolves.toBe("hello");
    expect(urls[0]).toContain("/files/abc_123/export");
    expect(urls[0]).toContain("mimeType=text%2Fplain");
  });
});

describe("createDriveAdapter", () => {
  const connection: DriveConnection = {
    accessToken: "drive-token",
    refreshToken: "refresh",
    expiresAt: new Date(Date.now() + 60000).toISOString(),
  };

  it("declares user-scoped authorization for file listing", async () => {
    const adapter = createDriveAdapter();
    const tool = adapter.tools.find(
      (candidate) => candidate.descriptor.name === "pact.drive.files.list",
    );
    expect(tool?.authorize).toBeDefined();

    expect(
      tool?.authorize?.(
        {},
        { workspaceId: "w1", userId: "u1", email: "u@example.com", roles: [], groups: [] },
      ),
    ).toEqual({
      action: "drive.files.list",
      resource: "workspace:w1:drive:user:u1:files",
    });
  });

  it("returns a clear error when Drive is not connected", async () => {
    const adapter = createDriveAdapter({ loadConnection: async () => null });
    const tool = adapter.tools.find(
      (candidate) => candidate.descriptor.name === "pact.drive.files.list",
    );

    const result = await tool?.handler(
      {},
      { workspaceId: "w1", userId: "u1", email: "u@example.com", roles: [], groups: [] },
      { databaseUrl: "" },
    );

    expect(result?.isError).toBe(true);
    expect(result?.content[0]?.text).toContain("not connected");
  });

  it("caps returned file text", async () => {
    const adapter = createDriveAdapter({
      loadConnection: async () => connection,
      createClient: () => ({
        listFiles: async () => ({ files: [] }),
        exportText: async () => "abcdef",
      }),
    });
    const tool = adapter.tools.find(
      (candidate) => candidate.descriptor.name === "pact.drive.file.get",
    );

    const result = await tool?.handler(
      { fileId: "file_1", maxChars: 3 },
      { workspaceId: "w1", userId: "u1", email: "u@example.com", roles: [], groups: [] },
      { databaseUrl: "" },
    );

    expect(JSON.parse(result?.content[0]?.text ?? "{}")).toEqual({
      fileId: "file_1",
      mimeType: "text/plain",
      text: "abc",
      truncated: true,
    });
  });
});
