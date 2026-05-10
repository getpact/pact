import { writeEvent } from "@getpact/audit";
import type { Tx } from "@getpact/db";
import { workspaces } from "@getpact/db/schema";
import { loadActiveSigningKey } from "@getpact/keystore";
import { eq } from "drizzle-orm";

export type AdminAuditTxInput = {
  rawMek: Uint8Array;
  workspaceId: string;
  actorUserId: string;
  action: string;
  target: unknown;
  decision: "allow" | "deny";
  supporting?: unknown;
};

export const writeAdminAudit = async (tx: Tx, input: AdminAuditTxInput): Promise<void> => {
  const [ws] = await tx
    .select({ id: workspaces.id, createdAt: workspaces.createdAt })
    .from(workspaces)
    .where(eq(workspaces.id, input.workspaceId))
    .limit(1);
  if (!ws) throw new Error("workspace not found for admin audit");

  const auditKey = await loadActiveSigningKey(tx, input.workspaceId, "audit", input.rawMek);
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
};
