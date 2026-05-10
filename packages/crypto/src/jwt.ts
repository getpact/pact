import { type JWTPayload, type JWTVerifyResult, jwtVerify, SignJWT } from "jose";

export type IssueOptions = {
  privateKey: CryptoKey;
  kid: string;
  issuer: string;
  audience: string;
  ttlSeconds: number;
  jti: string;
};

export const issueJwt = async (claims: JWTPayload, opts: IssueOptions): Promise<string> => {
  const now = Math.floor(Date.now() / 1000);
  return new SignJWT(claims)
    .setProtectedHeader({ alg: "EdDSA", kid: opts.kid })
    .setIssuer(opts.issuer)
    .setAudience(opts.audience)
    .setJti(opts.jti)
    .setIssuedAt(now)
    .setExpirationTime(now + opts.ttlSeconds)
    .sign(opts.privateKey);
};

export type VerifyOptions = {
  publicKey: CryptoKey;
  issuer: string;
  audience: string;
};

export const verifyJwt = async (token: string, opts: VerifyOptions): Promise<JWTVerifyResult> =>
  jwtVerify(token, opts.publicKey, {
    issuer: opts.issuer,
    audience: opts.audience,
    algorithms: ["EdDSA"],
  });
