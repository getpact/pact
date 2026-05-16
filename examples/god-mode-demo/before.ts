import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

type DriveFile = {
  id: string;
  name: string;
  mimeType: string;
  parents: string[];
  modifiedTime: string;
  size: string;
};

type DriveFixture = {
  generatedAt: string;
  folders: { id: string; name: string }[];
  files: DriveFile[];
};

const here = dirname(fileURLToPath(import.meta.url));

function loadFixture(): DriveFixture {
  const raw = readFileSync(join(here, "drive-fixture.json"), "utf8");
  return JSON.parse(raw) as DriveFixture;
}

function loadGodModeToken(): string {
  const token = process.env.GOOGLE_DRIVE_TOKEN ?? "ya29.MOCK-god-mode-readonly-token";
  return token;
}

function listAllFiles(token: string, fixture: DriveFixture): DriveFile[] {
  if (!token) {
    throw new Error("missing OAuth token");
  }
  return fixture.files;
}

function main(): void {
  const token = loadGodModeToken();
  const fixture = loadFixture();
  const files = listAllFiles(token, fixture);

  const folderCounts = new Map<string, number>();
  for (const file of files) {
    for (const parent of file.parents) {
      folderCounts.set(parent, (folderCounts.get(parent) ?? 0) + 1);
    }
  }

  const breakdown = Array.from(folderCounts.entries())
    .map(([folderId, count]) => ({ folderId, count }))
    .sort((a, b) => b.count - a.count);

  const output = {
    path: "before",
    auth: "google-oauth-drive-readonly",
    scope: "drive.readonly (full account)",
    tokenSample: token.slice(0, 12) + "...",
    totalFiles: files.length,
    folders: fixture.folders.length,
    folderBreakdown: breakdown,
    sample: files.slice(0, 5),
  };

  process.stdout.write(JSON.stringify(output, null, 2) + "\n");
}

main();
