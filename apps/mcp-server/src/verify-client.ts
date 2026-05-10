export type VerifyResponse = {
  allow: boolean;
  reasons: string[];
  sub?: string;
};

export type VerifyClient = (input: {
  token: string;
  action: string;
  resource: string;
  audience: string;
}) => Promise<VerifyResponse>;

export const httpVerifyClient =
  (verifierUrl: string): VerifyClient =>
  async (input) => {
    try {
      const res = await fetch(`${verifierUrl.replace(/\/+$/, "")}/v1/verify`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(input),
      });
      const body = (await res.json()) as Partial<VerifyResponse>;
      if (typeof body.allow === "boolean" && Array.isArray(body.reasons)) {
        return {
          allow: body.allow,
          reasons: body.reasons,
          ...(typeof body.sub === "string" ? { sub: body.sub } : {}),
        };
      }
      return { allow: false, reasons: [`verifier returned ${res.status}`] };
    } catch {
      return { allow: false, reasons: ["verifier unavailable"] };
    }
  };
