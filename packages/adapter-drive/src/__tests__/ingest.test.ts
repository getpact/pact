import { describe, expect, it, vi } from "vitest";

import {
  type BrainPutFn,
  type BrainPutInput,
  type IngestDriveClient,
  type IngestFile,
  ingestRecentDriveDocs,
} from "../ingest";

type Recorded = {
  input: BrainPutInput;
};

const baseCtx = {
  workspaceId: "00000000-0000-0000-0000-0000000000aa",
  userId: "00000000-0000-0000-0000-0000000000bb",
  email: "owner@example.com",
  groups: [] as string[],
  roles: [] as string[],
};

const fakeClient = (
  files: IngestFile[],
  texts: Record<string, string>,
  overrides: Partial<IngestDriveClient> = {},
): IngestDriveClient => ({
  async listFiles() {
    return { files };
  },
  async exportText({ fileId }) {
    const text = texts[fileId];
    if (text === undefined) throw new Error(`no text for ${fileId}`);
    return text;
  },
  async getText({ fileId }) {
    const text = texts[fileId];
    if (text === undefined) throw new Error(`no text for ${fileId}`);
    return text;
  },
  ...overrides,
});

const okPut =
  (idempotent = false): BrainPutFn =>
  async () => ({
    content: [
      {
        type: "text",
        text: JSON.stringify({
          page_id: "page_1",
          chunks_created: idempotent ? 0 : 4,
          idempotent,
        }),
      },
    ],
  });

describe("ingestRecentDriveDocs", () => {
  it("ingests a batch of Google Docs and calls brain.put per file", async () => {
    const files: IngestFile[] = Array.from({ length: 5 }, (_, i) => ({
      id: `doc_${i + 1}`,
      name: `Doc ${i + 1}`,
      mimeType: "application/vnd.google-apps.document",
      modifiedTime: "2026-05-10T00:00:00.000Z",
      owners: [{ emailAddress: `writer${i + 1}@example.com` }],
    }));
    const texts = Object.fromEntries(files.map((f) => [f.id, `body of ${f.name}`]));
    const captured: Recorded[] = [];
    const brainPut: BrainPutFn = async (input) => {
      captured.push({ input });
      return okPut(false)(input, baseCtx, { databaseUrl: "" });
    };

    const result = await ingestRecentDriveDocs({
      ...baseCtx,
      accessToken: "x",
      brainPut,
      databaseUrl: "",
      driveClient: fakeClient(files, texts),
    });

    expect(result.ingested).toBe(5);
    expect(result.duplicates).toBe(0);
    expect(result.skipped).toBe(0);
    expect(result.errors).toEqual([]);
    expect(captured).toHaveLength(5);
    expect(captured[0]?.input.source_uri).toBe("gdrive://doc_1");
    expect(captured[0]?.input.source_kind).toBe("connector");
    expect(captured[0]?.input.author).toBe("writer1@example.com");
    expect(captured[0]?.input.audience).toEqual(["gdrive_owner:writer1@example.com"]);
    expect(captured[0]?.input.title).toBe("Doc 1");
    expect(result.nextCursor).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it("skips unsupported mime types", async () => {
    const files: IngestFile[] = [
      {
        id: "bin_1",
        name: "image.png",
        mimeType: "image/png",
      },
      {
        id: "doc_2",
        name: "notes.md",
        mimeType: "text/markdown",
      },
    ];
    const texts = { doc_2: "hello markdown" };
    const brainPut = vi.fn(okPut(false));

    const result = await ingestRecentDriveDocs({
      ...baseCtx,
      accessToken: "x",
      brainPut,
      databaseUrl: "",
      driveClient: fakeClient(files, texts),
    });

    expect(result.ingested).toBe(1);
    expect(result.skipped).toBe(1);
    expect(brainPut).toHaveBeenCalledTimes(1);
    expect(brainPut.mock.calls[0]?.[0].source_uri).toBe("gdrive://doc_2");
  });

  it("treats brain.put idempotent responses as duplicates", async () => {
    const files: IngestFile[] = [
      {
        id: "doc_dup",
        name: "Dup",
        mimeType: "application/vnd.google-apps.document",
      },
    ];
    const texts = { doc_dup: "already ingested body" };

    const result = await ingestRecentDriveDocs({
      ...baseCtx,
      accessToken: "x",
      brainPut: okPut(true),
      databaseUrl: "",
      driveClient: fakeClient(files, texts),
    });

    expect(result.duplicates).toBe(1);
    expect(result.ingested).toBe(0);
    expect(result.errors).toEqual([]);
  });

  it("retries transient Drive errors and recovers", async () => {
    const files: IngestFile[] = [
      {
        id: "doc_flaky",
        name: "Flaky",
        mimeType: "application/vnd.google-apps.document",
      },
    ];
    let exportCalls = 0;
    const client: IngestDriveClient = {
      async listFiles() {
        return { files };
      },
      async exportText() {
        exportCalls += 1;
        if (exportCalls < 3) {
          throw new Error("Google Drive API failed (503): backend error");
        }
        return "recovered body";
      },
      async getText() {
        throw new Error("not used");
      },
    };

    const sleep = vi.fn(async () => {});
    const result = await ingestRecentDriveDocs({
      ...baseCtx,
      accessToken: "x",
      brainPut: okPut(false),
      databaseUrl: "",
      driveClient: client,
      retries: 3,
      retryDelayMs: 1,
      sleep,
    });

    expect(result.ingested).toBe(1);
    expect(exportCalls).toBe(3);
    expect(sleep).toHaveBeenCalledTimes(2);
  });

  it("records error after retries exhausted on permanent failure", async () => {
    const files: IngestFile[] = [
      {
        id: "doc_dead",
        name: "Dead",
        mimeType: "application/vnd.google-apps.document",
      },
    ];
    const client: IngestDriveClient = {
      async listFiles() {
        return { files };
      },
      async exportText() {
        throw new Error("Google Drive API failed (404): not found");
      },
      async getText() {
        throw new Error("not used");
      },
    };

    const result = await ingestRecentDriveDocs({
      ...baseCtx,
      accessToken: "x",
      brainPut: okPut(false),
      databaseUrl: "",
      driveClient: client,
      retries: 2,
      retryDelayMs: 1,
      sleep: async () => {},
    });

    expect(result.ingested).toBe(0);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]?.fileId).toBe("doc_dead");
    expect(result.errors[0]?.reason).toContain("404");
  });

  it("advances the cursor between runs so the second run filters older files", async () => {
    const firstFiles: IngestFile[] = [
      {
        id: "doc_a",
        name: "A",
        mimeType: "application/vnd.google-apps.document",
      },
    ];
    const seenQueries: string[] = [];
    const client = (files: IngestFile[]): IngestDriveClient => ({
      async listFiles(input) {
        seenQueries.push(input.q ?? "");
        return { files };
      },
      async exportText({ fileId }) {
        return `body ${fileId}`;
      },
      async getText({ fileId }) {
        return `body ${fileId}`;
      },
    });

    const first = await ingestRecentDriveDocs({
      ...baseCtx,
      accessToken: "x",
      brainPut: okPut(false),
      databaseUrl: "",
      driveClient: client(firstFiles),
      since: "2026-01-01T00:00:00.000Z",
    });

    expect(first.ingested).toBe(1);
    expect(seenQueries[0]).toContain("modifiedTime > '2026-01-01T00:00:00.000Z'");

    const second = await ingestRecentDriveDocs({
      ...baseCtx,
      accessToken: "x",
      brainPut: okPut(false),
      databaseUrl: "",
      driveClient: client([]),
      since: first.nextCursor,
    });

    expect(second.ingested).toBe(0);
    expect(seenQueries[1]).toContain(`modifiedTime > '${first.nextCursor}'`);
  });

  it("propagates brain.put errors into the error list without aborting the batch", async () => {
    const files: IngestFile[] = [
      {
        id: "doc_x",
        name: "X",
        mimeType: "application/vnd.google-apps.document",
      },
      {
        id: "doc_y",
        name: "Y",
        mimeType: "application/vnd.google-apps.document",
      },
    ];
    const texts = { doc_x: "x body", doc_y: "y body" };
    const brainPut: BrainPutFn = async (input) => {
      if (input.source_uri === "gdrive://doc_x") {
        return {
          content: [{ type: "text", text: "embedding provider not configured" }],
          isError: true,
        };
      }
      return okPut(false)(input, baseCtx, { databaseUrl: "" });
    };

    const result = await ingestRecentDriveDocs({
      ...baseCtx,
      accessToken: "x",
      brainPut,
      databaseUrl: "",
      driveClient: fakeClient(files, texts),
    });

    expect(result.ingested).toBe(1);
    expect(result.errors).toEqual([
      { fileId: "doc_x", reason: "embedding provider not configured" },
    ]);
  });
});
