import {
  type Adapter,
  type AdapterContext,
  type AdapterTool,
  errorResult,
  json,
  type ToolDeps,
  type ToolResult,
} from "@getpact/adapter-sdk";

export type DriveConnection = {
  accessToken: string;
  refreshToken?: string;
  expiresAt?: string;
  scope?: string;
  googleSub?: string;
  email?: string;
};

export type DriveFile = {
  id: string;
  name?: string;
  mimeType?: string;
  modifiedTime?: string;
  size?: string;
  webViewLink?: string;
};

export type DriveListFilesResponse = {
  files: DriveFile[];
  nextPageToken?: string;
};

export type FetchLike = typeof fetch;

export type DriveClient = {
  listFiles(input: {
    pageSize?: number;
    pageToken?: string;
    q?: string;
  }): Promise<DriveListFilesResponse>;
  exportText(input: { fileId: string; mimeType?: string }): Promise<string>;
};

export type DriveClientOptions = {
  accessToken: string;
  apiBaseUrl?: string;
  fetch?: FetchLike;
};

export type DriveAdapterOptions = {
  loadConnection?: (ctx: AdapterContext, deps: ToolDeps) => Promise<DriveConnection | null>;
  createClient?: (connection: DriveConnection) => DriveClient;
};

const defaultFields = "nextPageToken,files(id,name,mimeType,modifiedTime,size,webViewLink)";
const defaultExportMimeType = "text/plain";

export function createDriveClient(options: DriveClientOptions): DriveClient {
  const fetchImpl = options.fetch ?? fetch;
  const apiBaseUrl = trimTrailingSlash(options.apiBaseUrl ?? "https://www.googleapis.com/drive/v3");

  async function driveFetch(url: URL): Promise<Response> {
    const response = await fetchImpl(url, {
      headers: {
        authorization: `Bearer ${options.accessToken}`,
        accept: "application/json, text/plain",
      },
    });

    if (!response.ok) {
      throw new Error(await driveError(response));
    }

    return response;
  }

  return {
    async listFiles(input) {
      const url = new URL(`${apiBaseUrl}/files`);
      url.searchParams.set("fields", defaultFields);
      url.searchParams.set("pageSize", String(clampPageSize(input.pageSize)));
      if (input.pageToken) {
        url.searchParams.set("pageToken", input.pageToken);
      }
      if (input.q) {
        url.searchParams.set("q", input.q);
      }

      const body = (await (await driveFetch(url)).json()) as DriveListFilesResponse;
      const result: DriveListFilesResponse = {
        files: Array.isArray(body.files) ? body.files : [],
      };
      if (typeof body.nextPageToken === "string") result.nextPageToken = body.nextPageToken;
      return result;
    },

    async exportText(input) {
      assertSafeFileId(input.fileId);
      const url = new URL(`${apiBaseUrl}/files/${input.fileId}/export`);
      url.searchParams.set("mimeType", input.mimeType ?? defaultExportMimeType);
      return await (await driveFetch(url)).text();
    },
  };
}

export function createDriveAdapter(options: DriveAdapterOptions = {}): Adapter {
  const loadConnection = options.loadConnection ?? defaultLoadConnection;
  const createClient = options.createClient ?? createDriveClientFromConnection;

  const filesList: AdapterTool = {
    descriptor: {
      name: "pact.drive.files.list",
      description: "List Google Drive files for the connected user.",
      inputSchema: {
        type: "object",
        properties: {
          pageSize: { type: "number", minimum: 1, maximum: 100 },
          pageToken: { type: "string" },
          q: { type: "string", description: "Optional Google Drive query string." },
        },
      },
    },
    authorize: (args, ctx) => {
      const q = stringInput(args, "q")?.trim().replace(/\s+/g, " ");
      const queryPart = q ? `:query:${encodeURIComponent(q).slice(0, 200)}` : "";
      return {
        action: "drive.files.list",
        resource: `workspace:${ctx.workspaceId}:drive:user:${ctx.userId}:files${queryPart}`,
      };
    },
    async handler(input, ctx, deps) {
      const connection = await loadConnection(ctx, deps);
      const ready = validateUsableConnection(connection);
      if (!ready.ok) {
        return ready.result;
      }

      const client = createClient(ready.connection);
      const listInput: { pageSize?: number; pageToken?: string; q?: string } = {};
      const pageSize = numberInput(input, "pageSize");
      const pageToken = stringInput(input, "pageToken");
      const q = stringInput(input, "q");
      if (pageSize !== undefined) listInput.pageSize = pageSize;
      if (pageToken !== undefined) listInput.pageToken = pageToken;
      if (q !== undefined) listInput.q = q;
      const result = await client.listFiles(listInput);
      return json(result);
    },
  };

  const fileGet: AdapterTool = {
    descriptor: {
      name: "pact.drive.file.get",
      description: "Export a Google Drive file as text for agent context.",
      inputSchema: {
        type: "object",
        required: ["fileId"],
        properties: {
          fileId: { type: "string" },
          mimeType: { type: "string", enum: ["text/plain", "text/markdown"] },
          maxChars: { type: "number", minimum: 1, maximum: 50000 },
        },
      },
    },
    authorize: (input, ctx) => {
      const fileId = stringInput(input, "fileId");
      return {
        action: "drive.file.get",
        resource: `workspace:${ctx.workspaceId}:drive:user:${ctx.userId}:file:${isSafeFileId(fileId) ? fileId : "invalid"}`,
      };
    },
    async handler(input, ctx, deps) {
      const fileId = stringInput(input, "fileId");
      if (!fileId) {
        return errorResult("fileId is required");
      }

      const connection = await loadConnection(ctx, deps);
      const ready = validateUsableConnection(connection);
      if (!ready.ok) {
        return ready.result;
      }

      const client = createClient(ready.connection);
      const text = await client.exportText({
        fileId,
        mimeType: stringInput(input, "mimeType") ?? defaultExportMimeType,
      });
      const maxChars = numberInput(input, "maxChars") ?? 20000;
      return json({
        fileId,
        mimeType: stringInput(input, "mimeType") ?? defaultExportMimeType,
        text: text.slice(0, maxChars),
        truncated: text.length > maxChars,
      });
    },
  };

  return {
    name: "google-drive",
    tools: [filesList, fileGet],
  };
}

function createDriveClientFromConnection(connection: DriveConnection): DriveClient {
  return createDriveClient({ accessToken: connection.accessToken });
}

async function defaultLoadConnection(): Promise<DriveConnection | null> {
  return null;
}

function validateUsableConnection(
  connection: DriveConnection | null,
): { ok: true; connection: DriveConnection } | { ok: false; result: ToolResult } {
  if (!connection?.accessToken) {
    return { ok: false, result: errorResult("Google Drive is not connected for this user.") };
  }
  if (connection.expiresAt && Date.parse(connection.expiresAt) <= Date.now()) {
    return {
      ok: false,
      result: errorResult("Google Drive connection expired. Reconnect Drive in Pact."),
    };
  }
  return { ok: true, connection };
}

async function driveError(response: Response): Promise<string> {
  const contentType = response.headers.get("content-type") ?? "";
  if (contentType.includes("application/json")) {
    const body = (await response.json().catch(() => ({}))) as { error?: { message?: string } };
    if (body.error?.message) {
      return `Google Drive API failed: ${body.error.message}`;
    }
  }
  return `Google Drive API failed with HTTP ${response.status}`;
}

function numberInput(input: unknown, key: string): number | undefined {
  if (!input || typeof input !== "object") {
    return undefined;
  }
  const value = (input as Record<string, unknown>)[key];
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function stringInput(input: unknown, key: string): string | undefined {
  if (!input || typeof input !== "object") {
    return undefined;
  }
  const value = (input as Record<string, unknown>)[key];
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function clampPageSize(value: number | undefined): number {
  if (!value || !Number.isFinite(value)) {
    return 20;
  }
  return Math.min(100, Math.max(1, Math.floor(value)));
}

function trimTrailingSlash(value: string): string {
  return value.replace(/\/+$/, "");
}

function assertSafeFileId(fileId: string): void {
  if (!isSafeFileId(fileId)) {
    throw new Error("Google Drive file id contains invalid characters");
  }
}

function isSafeFileId(fileId: string | undefined): fileId is string {
  return !!fileId && /^[A-Za-z0-9_-]+$/.test(fileId);
}
