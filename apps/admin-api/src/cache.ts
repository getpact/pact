export type KVNamespace = {
  put: (key: string, value: string, options?: { expirationTtl?: number }) => Promise<void>;
};

export const bustRevocationCache = async (
  kv: KVNamespace | undefined,
  workspaceId: string,
  jti: string,
): Promise<void> => {
  if (!kv) return;
  try {
    await kv.put(`rev:${workspaceId}:${jti}`, "revoked", { expirationTtl: 60 });
  } catch {
    // best-effort
  }
};
