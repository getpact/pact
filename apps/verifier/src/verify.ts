import { verifyJwt } from "@getpact/crypto";
import { createClient, withWorkspace } from "@getpact/db";
import { policies, revokedJtis } from "@getpact/db/schema";
import { listVerifyingKeys } from "@getpact/keystore";
import { evaluate, type Policy, type TokenClaims } from "@getpact/policy";
import { and, desc, eq, isNull, sql } from "drizzle-orm";
import { decodeJwt, decodeProtectedHeader } from "jose";

export type VerifyInput = {
  token: string;
  action: string;
  resource: string;
  audience: string;
};

export type VerifyOutput = {
  allow: boolean;
  reasons: string[];
  sub?: string;
};

export const verifyAction = async (
  databaseUrl: string,
  input: VerifyInput,
): Promise<VerifyOutput> => {
  let claims: ReturnType<typeof decodeJwt>;
  try {
    claims = decodeJwt(input.token);
  } catch {
    return { allow: false, reasons: ["malformed token"] };
  }
  const workspaceId = claims.org as string | undefined;
  const jti = claims.jti as string | undefined;
  const issuer = claims.iss as string | undefined;
  if (!workspaceId || !jti || !issuer) {
    return { allow: false, reasons: ["malformed token"] };
  }

  const db = createClient(databaseUrl);

  let kid: string | undefined;
  try {
    kid = decodeProtectedHeader(input.token).kid;
  } catch {
    return { allow: false, reasons: ["malformed token header"] };
  }
  if (!kid) {
    return { allow: false, reasons: ["missing kid"] };
  }

  const keys = await withWorkspace(db, workspaceId, (tx) =>
    listVerifyingKeys(tx, workspaceId, "jwt"),
  );
  const matched = keys.find((k) => k.id === kid);
  if (!matched) {
    return { allow: false, reasons: ["unknown kid"] };
  }
  try {
    await verifyJwt(input.token, {
      publicKey: matched.publicKey,
      issuer,
      audience: input.audience,
    });
  } catch {
    return { allow: false, reasons: ["signature invalid"] };
  }

  const revoked = await withWorkspace(db, workspaceId, (tx) =>
    tx
      .select({ jti: revokedJtis.jti })
      .from(revokedJtis)
      .where(and(eq(revokedJtis.workspaceId, workspaceId), eq(revokedJtis.jti, jti)))
      .limit(1),
  );
  if (revoked.length > 0) {
    return { allow: false, reasons: ["token revoked"] };
  }

  const policyRow = await withWorkspace(db, workspaceId, (tx) =>
    tx
      .select({ body: policies.body })
      .from(policies)
      .where(and(eq(policies.workspaceId, workspaceId), isNull(policies.replacedAt)))
      .orderBy(desc(policies.version))
      .limit(1),
  );

  const sub = claims.sub;
  if (policyRow.length === 0) {
    return sub
      ? { allow: false, reasons: ["no active policy"], sub }
      : { allow: false, reasons: ["no active policy"] };
  }

  const tokenClaims: TokenClaims = {
    sub: claims.sub ?? "",
    email: (claims.email as string | undefined) ?? "",
    groups: (claims.groups as string[] | undefined) ?? [],
    roles: (claims.scopes as string[] | undefined) ?? [],
  };

  const result = evaluate({
    token: tokenClaims,
    action: input.action,
    resource: input.resource,
    policy: policyRow[0]?.body as Policy,
  });

  void sql;
  return sub ? { ...result, sub } : result;
};
