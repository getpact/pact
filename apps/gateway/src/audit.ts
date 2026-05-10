import { writeEvent } from "@getpact/audit";
import { fromBase64 } from "@getpact/crypto";
import type { DbClient } from "@getpact/db";
import { schema, withWorkspace } from "@getpact/db";
import { loadActiveSigningKey } from "@getpact/keystore";
import { eq } from "drizzle-orm";

export type GatewayAuditInput = {
  db: DbClient;
  mek: string | undefined;
  workspaceId: string;
  actorId: string | undefined;
  action: string;
  decision: "allow" | "deny";
  target: {
    resource: string;
    brain: string;
    path: string;
    method: string;
  };
  supporting: Record<string, unknown>;
};

export const emitGatewayAudit = async (input: GatewayAuditInput): Promise<void> => {
  if (!input.mek) return;
  try {
    const rawMek = fromBase64(input.mek);
    const [ws] = await input.db
      .select({ createdAt: schema.workspaces.createdAt })
      .from(schema.workspaces)
      .where(eq(schema.workspaces.id, input.workspaceId))
      .limit(1);
    if (!ws) return;

    await withWorkspace(input.db, input.workspaceId, async (tx) => {
      const auditKey = await loadActiveSigningKey(tx, input.workspaceId, "audit", rawMek);
      await writeEvent(tx, {
        workspaceId: input.workspaceId,
        workspaceCreatedAt: ws.createdAt,
        signingKeyId: auditKey.id,
        signingKey: auditKey.privateKey,
        event: {
          actorKind: "user",
          ...(input.actorId ? { actorId: input.actorId } : {}),
          action: input.action,
          target: input.target,
          decision: input.decision,
          supporting: input.supporting,
        },
      });
    });
  } catch {
    // best-effort: never fail gateway traffic because audit failed
  }
};
