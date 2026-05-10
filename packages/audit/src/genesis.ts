import { sha256, toBase64 } from "@getpact/crypto";

export const computeGenesisHash = async (
  workspaceId: string,
  workspaceCreatedAt: Date,
): Promise<string> => {
  const seed = new TextEncoder().encode(`${workspaceId}|${workspaceCreatedAt.toISOString()}`);
  const hash = await sha256(seed);
  return toBase64(hash);
};
