import { writeEvent } from "@getpact/audit";
import { fromBase64 } from "@getpact/crypto";
import { createClient, withWorkspace } from "@getpact/db";
import { workspaces } from "@getpact/db/schema";
import { loadActiveSigningKey } from "@getpact/keystore";
import { eq } from "drizzle-orm";

export type AdminAuditInput = {
  databaseUrl: string;
  mek: string;
  workspaceId: string;
  actorUserId: string;
  action: string;
  target: unknown;
  decision: "allow" | "deny";
  supporting?: unknown;
};

export const emitAdminAudit = async (input: AdminAuditInput): Promise<void> => {
  try {
    const rawMek = fromBase64(input.mek);
    const db = createClient(input.databaseUrl);
    const [ws] = await db
      .select({ id: workspaces.id, createdAt: workspaces.createdAt })
      .from(workspaces)
      .where(eq(workspaces.id, input.workspaceId))
      .limit(1);
    if (!ws) return;

    await withWorkspace(db, input.workspaceId, async (tx) => {
      const auditKey = await loadActiveSigningKey(tx, input.workspaceId, "audit", rawMek);
      await writeEvent(tx, {
        workspaceId: input.workspaceId,
        workspaceCreatedAt: ws.createdAt,
        signingKeyId: auditKey.id,
        signingKey: auditKey.privateKey,
        event: {
          actorKind: "admin",
          actorId: input.actorUserId,
          action: input.action,
          target: input.target,
          decision: input.decision,
          supporting: input.supporting ?? null,
        },
      });
    });
  } catch {
    // best-effort, never fail the admin op because audit failed
  }
};
