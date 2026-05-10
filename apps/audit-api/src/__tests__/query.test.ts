import { describe, expect, it } from "vitest";
import { formatCursor, parseCursor, type QueryRow } from "../query.js";

const row = {
  id: "event-1",
  workspaceId: "00000000-0000-0000-0000-000000000000",
  ts: new Date("2026-05-10T12:34:56.789Z"),
  actorKind: "user",
  actorId: "user-1",
  action: "verify.read",
  target: { resource: "doc:1" },
  decision: "allow",
  supporting: null,
  signingKeyId: "key-1",
  prevHash: "prev",
  thisHash: "hash",
  signature: "sig",
} satisfies QueryRow;

describe("audit query cursors", () => {
  it("parses server-formatted cursors with ISO timestamp colons", () => {
    expect(parseCursor(formatCursor(row))).toEqual({
      ts: row.ts,
      thisHash: row.thisHash,
    });
  });

  it("rejects malformed cursors", () => {
    expect(parseCursor("not-a-cursor")).toBeUndefined();
  });
});
