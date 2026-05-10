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
  (verifierUrl: string, serviceToken?: string): VerifyClient =>
  async (input) => {
    try {
      const headers = new Headers({ "content-type": "application/json" });
      if (serviceToken) headers.set("authorization", `Bearer ${serviceToken}`);
      const res = await fetch(`${verifierUrl.replace(/\/+$/, "")}/v1/verify`, {
        method: "POST",
        headers,
        body: JSON.stringify(input),
      });
      const body = (await res.json()) as Partial<VerifyResponse>;
      if (res.ok && typeof body.allow === "boolean" && Array.isArray(body.reasons)) {
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
