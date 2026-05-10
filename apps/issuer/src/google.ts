import { createRemoteJWKSet, jwtVerify } from "jose";

const DEFAULT_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
const DEFAULT_JWKS_URI = "https://www.googleapis.com/oauth2/v3/certs";
const DEFAULT_ISSUER = "https://accounts.google.com";

export type GoogleVerifiedIdentity = {
  email: string;
  emailVerified: boolean;
  sub: string;
};

export type ExchangeOptions = {
  clientId: string;
  clientSecret: string;
  code: string;
  codeVerifier: string;
  redirectUri: string;
  tokenEndpoint?: string;
  jwksUri?: string;
  expectedIssuer?: string;
};

const canonicalizeEmail = (raw: string): string => raw.trim().toLowerCase();

export const exchangeGoogleCode = async (
  opts: ExchangeOptions,
): Promise<GoogleVerifiedIdentity> => {
  const tokenEndpoint = opts.tokenEndpoint ?? DEFAULT_TOKEN_ENDPOINT;
  const jwksUri = opts.jwksUri ?? DEFAULT_JWKS_URI;
  const expectedIssuer = opts.expectedIssuer ?? DEFAULT_ISSUER;

  const tokenRes = await fetch(tokenEndpoint, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      client_id: opts.clientId,
      client_secret: opts.clientSecret,
      code: opts.code,
      code_verifier: opts.codeVerifier,
      grant_type: "authorization_code",
      redirect_uri: opts.redirectUri,
    }),
  });
  if (!tokenRes.ok) {
    const text = await tokenRes.text();
    throw new Error(`google token exchange failed (${tokenRes.status}): ${text}`);
  }
  const body = (await tokenRes.json()) as { id_token?: string };
  if (!body.id_token) {
    throw new Error("google token exchange returned no id_token");
  }

  const jwks = createRemoteJWKSet(new URL(jwksUri));
  const { payload } = await jwtVerify(body.id_token, jwks, {
    issuer: expectedIssuer,
    audience: opts.clientId,
    algorithms: ["RS256"],
  });

  const email = payload.email;
  const sub = payload.sub;
  if (typeof email !== "string" || typeof sub !== "string") {
    throw new Error("google id_token missing email or sub");
  }
  return {
    email: canonicalizeEmail(email),
    emailVerified: payload.email_verified === true,
    sub,
  };
};
