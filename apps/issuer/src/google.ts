import { createRemoteJWKSet, jwtVerify } from "jose";

const DEFAULT_TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
const DEFAULT_JWKS_URI = "https://www.googleapis.com/oauth2/v3/certs";
const DEFAULT_ISSUER = "https://accounts.google.com";

export class GoogleTokenExchangeError extends Error {
  readonly status: number;
  readonly googleError: string | undefined;

  constructor(status: number, message: string, googleError?: string) {
    super(message);
    this.name = "GoogleTokenExchangeError";
    this.status = status;
    this.googleError = googleError;
  }

  get invalidGrant(): boolean {
    return this.status === 400 && this.googleError === "invalid_grant";
  }
}

export class GoogleIdentityVerificationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "GoogleIdentityVerificationError";
  }
}

export type GoogleVerifiedIdentity = {
  email: string;
  emailVerified: boolean;
  emailAuthoritative: boolean;
  hostedDomain?: string;
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

const domainForEmail = (email: string): string | null => {
  const at = email.lastIndexOf("@");
  return at > 0 ? email.slice(at + 1).toLowerCase() : null;
};

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
    let googleError: string | undefined;
    try {
      const parsed = JSON.parse(text) as { error?: unknown };
      googleError = typeof parsed.error === "string" ? parsed.error : undefined;
    } catch {}
    throw new GoogleTokenExchangeError(
      tokenRes.status,
      `google token exchange failed (${tokenRes.status})`,
      googleError,
    );
  }
  const body = (await tokenRes.json()) as { id_token?: string };
  if (!body.id_token) {
    throw new GoogleIdentityVerificationError("google token exchange returned no id_token");
  }

  const jwks = createRemoteJWKSet(new URL(jwksUri));
  let payload: Awaited<ReturnType<typeof jwtVerify>>["payload"];
  try {
    ({ payload } = await jwtVerify(body.id_token, jwks, {
      issuer: expectedIssuer,
      audience: opts.clientId,
      algorithms: ["RS256"],
    }));
  } catch (e) {
    throw new GoogleIdentityVerificationError(
      e instanceof Error ? e.message : "google id_token verification failed",
    );
  }

  const email = payload.email;
  const sub = payload.sub;
  if (typeof email !== "string" || typeof sub !== "string") {
    throw new GoogleIdentityVerificationError("google id_token missing email or sub");
  }
  const canonicalEmail = canonicalizeEmail(email);
  const emailDomain = domainForEmail(canonicalEmail);
  const hostedDomain = typeof payload.hd === "string" ? payload.hd.trim().toLowerCase() : undefined;
  const googleHostedEmail = emailDomain === "gmail.com" || !!hostedDomain;
  return {
    email: canonicalEmail,
    emailVerified: payload.email_verified === true,
    emailAuthoritative: payload.email_verified === true && googleHostedEmail,
    ...(hostedDomain ? { hostedDomain } : {}),
    sub,
  };
};
