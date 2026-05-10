import { exportPublicSpki } from "@getpact/crypto";
import { createClient, withWorkspace } from "@getpact/db";
import { listVerifyingKeys, type SigningKeyKind } from "@getpact/keystore";

type Jwk = {
  kty: "OKP";
  crv: "Ed25519";
  x: string;
  kid: string;
  alg: "EdDSA";
  use: "sig";
};

const SPKI_HEADER_BYTES = 12;

const base64url = (bytes: Uint8Array): string => {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};

export const buildWorkspaceJwks = async (
  databaseUrl: string,
  workspaceId: string,
  kind: SigningKeyKind = "jwt",
): Promise<{ keys: Jwk[] }> => {
  const db = createClient(databaseUrl);
  return withWorkspace(db, workspaceId, async (tx) => {
    const verifying = await listVerifyingKeys(tx, workspaceId, kind);
    const keys = await Promise.all(
      verifying.map(async (k) => {
        const spki = await exportPublicSpki(k.publicKey);
        const raw = spki.slice(SPKI_HEADER_BYTES);
        return {
          kty: "OKP" as const,
          crv: "Ed25519" as const,
          x: base64url(raw),
          kid: k.id,
          alg: "EdDSA" as const,
          use: "sig" as const,
        };
      }),
    );
    return { keys };
  });
};
