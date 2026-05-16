import type { AdapterContext, ToolDeps, ToolResult } from "@getpact/adapter-sdk";

import { createDriveClient, type DriveClient, type DriveFile, type FetchLike } from "./index.js";

export type BrainPutInput = {
  source_uri: string;
  source_kind: "manual" | "connector";
  content: string;
  title?: string;
  author?: string;
  audience?: string[];
};

export type BrainPutFn = (
  input: BrainPutInput,
  ctx: AdapterContext,
  deps: ToolDeps,
) => Promise<ToolResult>;

export type IngestFile = DriveFile & {
  owners?: Array<{ emailAddress?: string }>;
};

export type IngestListResponse = {
  files: IngestFile[];
  nextPageToken?: string;
};

export type IngestDriveClient = {
  listFiles(input: {
    pageSize?: number;
    pageToken?: string;
    q?: string;
    fields?: string;
  }): Promise<IngestListResponse>;
  exportText(input: { fileId: string; mimeType?: string }): Promise<string>;
  getText(input: { fileId: string }): Promise<string>;
};

export type IngestOptions = {
  workspaceId: string;
  userId: string;
  email: string;
  accessToken: string;
  since?: string;
  limit?: number;
  brainPut: BrainPutFn;
  databaseUrl: string;
  rawMek?: Uint8Array;
  providerConfig?: Record<string, string | undefined>;
  driveClient?: IngestDriveClient;
  apiBaseUrl?: string;
  fetch?: FetchLike;
  retries?: number;
  retryDelayMs?: number;
  sleep?: (ms: number) => Promise<void>;
  pageSize?: number;
  groups?: string[];
  roles?: string[];
};

export type IngestError = {
  fileId: string;
  reason: string;
};

export type IngestResult = {
  ingested: number;
  skipped: number;
  duplicates: number;
  errors: IngestError[];
  nextCursor: string;
};

const SUPPORTED_EXPORT_MIME_TYPES: Record<string, string> = {
  "application/vnd.google-apps.document": "text/plain",
};

const SUPPORTED_PLAIN_MIME_TYPES = new Set([
  "text/plain",
  "text/markdown",
  "text/x-markdown",
  "application/markdown",
]);

const DEFAULT_LIMIT = 50;
const DEFAULT_PAGE_SIZE = 50;
const DEFAULT_RETRIES = 3;
const DEFAULT_RETRY_DELAY_MS = 500;
const DRIVE_FIELDS =
  "nextPageToken,files(id,name,mimeType,modifiedTime,size,webViewLink,owners(emailAddress))";

const defaultSleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

const isTransientStatus = (status: number): boolean => {
  return status === 408 || status === 429 || status >= 500;
};

const parseDriveStatus = (message: string): number | null => {
  const match = /\((\d{3})\)|HTTP\s+(\d{3})/i.exec(message);
  const code = match?.[1] ?? match?.[2];
  return code ? Number(code) : null;
};

const sinceFloor = (since?: string): string => {
  if (since) {
    const parsed = Date.parse(since);
    if (Number.isFinite(parsed)) return new Date(parsed).toISOString();
  }
  const fallback = Date.now() - 30 * 24 * 60 * 60 * 1000;
  return new Date(fallback).toISOString();
};

const escapeDriveLiteral = (value: string): string => value.replace(/'/g, "\\'");

const buildClient = (opts: IngestOptions): IngestDriveClient => {
  if (opts.driveClient) return opts.driveClient;
  const raw = createDriveClient({
    accessToken: opts.accessToken,
    ...(opts.apiBaseUrl ? { apiBaseUrl: opts.apiBaseUrl } : {}),
    ...(opts.fetch ? { fetch: opts.fetch } : {}),
  });
  return wrapClient(raw, opts);
};

const wrapClient = (raw: DriveClient, opts: IngestOptions): IngestDriveClient => {
  const fetchImpl = opts.fetch ?? fetch;
  const apiBase = (opts.apiBaseUrl ?? "https://www.googleapis.com/drive/v3").replace(/\/+$/, "");
  return {
    async listFiles(input) {
      const url = new URL(`${apiBase}/files`);
      url.searchParams.set("fields", input.fields ?? DRIVE_FIELDS);
      url.searchParams.set("pageSize", String(input.pageSize ?? DEFAULT_PAGE_SIZE));
      if (input.pageToken) url.searchParams.set("pageToken", input.pageToken);
      if (input.q) url.searchParams.set("q", input.q);
      const response = await fetchImpl(url, {
        headers: {
          authorization: `Bearer ${opts.accessToken}`,
          accept: "application/json",
        },
      });
      if (!response.ok) {
        throw new Error(`Google Drive list failed (${response.status})`);
      }
      return (await response.json()) as IngestListResponse;
    },
    async exportText(input) {
      return raw.exportText(input);
    },
    async getText(input) {
      const url = new URL(`${apiBase}/files/${input.fileId}`);
      url.searchParams.set("alt", "media");
      const response = await fetchImpl(url, {
        headers: {
          authorization: `Bearer ${opts.accessToken}`,
          accept: "text/plain",
        },
      });
      if (!response.ok) {
        throw new Error(`Google Drive download failed (${response.status})`);
      }
      return response.text();
    },
  };
};

const withRetry = async <T>(
  fn: () => Promise<T>,
  retries: number,
  delayMs: number,
  sleep: (ms: number) => Promise<void>,
): Promise<T> => {
  let attempt = 0;
  let lastError: unknown;
  while (attempt <= retries) {
    try {
      return await fn();
    } catch (error) {
      lastError = error;
      const message = error instanceof Error ? error.message : String(error);
      const status = parseDriveStatus(message);
      const transient = status === null ? false : isTransientStatus(status);
      if (!transient || attempt === retries) {
        throw error;
      }
      await sleep(delayMs * 2 ** attempt);
      attempt += 1;
    }
  }
  throw lastError instanceof Error ? lastError : new Error("retry exhausted");
};

const fetchContent = async (
  client: IngestDriveClient,
  file: IngestFile,
): Promise<{ content: string; mimeType: string } | null> => {
  const mime = file.mimeType ?? "";
  if (mime in SUPPORTED_EXPORT_MIME_TYPES) {
    const target = SUPPORTED_EXPORT_MIME_TYPES[mime] as string;
    const text = await client.exportText({ fileId: file.id, mimeType: target });
    return { content: text, mimeType: target };
  }
  if (SUPPORTED_PLAIN_MIME_TYPES.has(mime)) {
    const text = await client.getText({ fileId: file.id });
    return { content: text, mimeType: mime };
  }
  return null;
};

const parseBrainPutResult = (result: ToolResult): { idempotent: boolean } => {
  const text = result.content[0]?.text ?? "";
  try {
    const parsed = JSON.parse(text) as { idempotent?: boolean };
    return { idempotent: Boolean(parsed.idempotent) };
  } catch {
    return { idempotent: false };
  }
};

export async function ingestRecentDriveDocs(opts: IngestOptions): Promise<IngestResult> {
  if (!opts.workspaceId) throw new Error("workspaceId is required");
  if (!opts.userId) throw new Error("userId is required");
  if (!opts.email) throw new Error("email is required");
  if (!opts.accessToken && !opts.driveClient) {
    throw new Error("accessToken or driveClient is required");
  }

  const limit = Math.max(1, Math.min(500, opts.limit ?? DEFAULT_LIMIT));
  const pageSize = Math.max(1, Math.min(100, opts.pageSize ?? DEFAULT_PAGE_SIZE));
  const retries = opts.retries ?? DEFAULT_RETRIES;
  const retryDelayMs = opts.retryDelayMs ?? DEFAULT_RETRY_DELAY_MS;
  const sleep = opts.sleep ?? defaultSleep;
  const cursorStart = sinceFloor(opts.since);
  const runStartedAt = new Date().toISOString();

  const client = buildClient(opts);
  const ctx: AdapterContext = {
    workspaceId: opts.workspaceId,
    userId: opts.userId,
    email: opts.email,
    groups: opts.groups ?? [],
    roles: opts.roles ?? [],
  };
  const deps: ToolDeps = {
    databaseUrl: opts.databaseUrl,
    ...(opts.rawMek ? { rawMek: opts.rawMek } : {}),
    ...(opts.providerConfig ? { providerConfig: opts.providerConfig } : {}),
  };

  const result: IngestResult = {
    ingested: 0,
    skipped: 0,
    duplicates: 0,
    errors: [],
    nextCursor: runStartedAt,
  };

  const query = `modifiedTime > '${escapeDriveLiteral(cursorStart)}' and trashed = false`;
  let pageToken: string | undefined;
  let processed = 0;

  while (processed < limit) {
    const remaining = limit - processed;
    const pageInput: { pageSize: number; q: string; pageToken?: string } = {
      pageSize: Math.min(pageSize, remaining),
      q: query,
    };
    if (pageToken) pageInput.pageToken = pageToken;

    let page: IngestListResponse;
    try {
      page = await withRetry(() => client.listFiles(pageInput), retries, retryDelayMs, sleep);
    } catch (error) {
      result.errors.push({
        fileId: "*",
        reason: error instanceof Error ? error.message : String(error),
      });
      break;
    }

    const files = page.files ?? [];
    if (files.length === 0) break;

    for (const file of files) {
      if (processed >= limit) break;
      processed += 1;
      if (!file.id) {
        result.skipped += 1;
        continue;
      }
      try {
        const fetched = await withRetry(
          () => fetchContent(client, file),
          retries,
          retryDelayMs,
          sleep,
        );
        if (!fetched) {
          result.skipped += 1;
          continue;
        }
        if (fetched.content.trim().length === 0) {
          result.skipped += 1;
          continue;
        }

        const ownerEmail = file.owners?.[0]?.emailAddress ?? opts.email;
        const audience = [`gdrive_owner:${ownerEmail}`];
        const input: BrainPutInput = {
          source_uri: `gdrive://${file.id}`,
          source_kind: "connector",
          content: fetched.content,
          author: ownerEmail,
          audience,
        };
        if (file.name) input.title = file.name;

        const putResult = await opts.brainPut(input, ctx, deps);
        if (putResult.isError) {
          const reason = putResult.content[0]?.text ?? "brain put failed";
          result.errors.push({ fileId: file.id, reason });
          continue;
        }
        const parsed = parseBrainPutResult(putResult);
        if (parsed.idempotent) {
          result.duplicates += 1;
        } else {
          result.ingested += 1;
        }
      } catch (error) {
        const reason = error instanceof Error ? error.message : String(error);
        result.errors.push({ fileId: file.id, reason });
      }
    }

    pageToken = page.nextPageToken;
    if (!pageToken) break;
  }

  return result;
}
