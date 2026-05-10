import { createRemoteJWKSet, type JWTPayload, type JWTVerifyResult, jwtVerify } from "jose";

export type VerifierOptions = {
  jwksUrl: string;
  issuer: string;
  audience: string;
  cacheTtlMs?: number;
};

export type Verifier = {
  verify: (token: string) => Promise<JWTVerifyResult>;
  decodeClaims: (token: string) => Promise<JWTPayload>;
};

export const createVerifier = (options: VerifierOptions): Verifier => {
  const jwks = createRemoteJWKSet(new URL(options.jwksUrl), {
    cacheMaxAge: options.cacheTtlMs ?? 5 * 60 * 1000,
  });

  return {
    verify: (token) =>
      jwtVerify(token, jwks, {
        issuer: options.issuer,
        audience: options.audience,
        algorithms: ["EdDSA"],
      }),
    decodeClaims: async (token) => {
      const result = await jwtVerify(token, jwks, {
        issuer: options.issuer,
        audience: options.audience,
        algorithms: ["EdDSA"],
      });
      return result.payload;
    },
  };
};

export type StaticVerifierOptions = {
  publicKey: CryptoKey;
  issuer: string;
  audience: string;
};

export const createStaticVerifier = (options: StaticVerifierOptions): Verifier => ({
  verify: (token) =>
    jwtVerify(token, options.publicKey, {
      issuer: options.issuer,
      audience: options.audience,
      algorithms: ["EdDSA"],
    }),
  decodeClaims: async (token) => {
    const result = await jwtVerify(token, options.publicKey, {
      issuer: options.issuer,
      audience: options.audience,
      algorithms: ["EdDSA"],
    });
    return result.payload;
  },
});
