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

export type VerifierTransport = string | { fetch: (request: Request) => Promise<Response> };

export const httpVerifyClient =
  (verifier: VerifierTransport, serviceToken?: string): VerifyClient =>
  async (input) => {
    try {
      const headers = new Headers({ "content-type": "application/json" });
      if (serviceToken) headers.set("authorization", `Bearer ${serviceToken}`);
      const init = {
        method: "POST",
        headers,
        body: JSON.stringify(input),
      };
      const res =
        typeof verifier === "string"
          ? await fetch(`${verifier.replace(/\/+$/, "")}/v1/verify`, init)
          : await verifier.fetch(new Request("https://verifier.internal/v1/verify", init));
      const body = (await res.json()) as Partial<VerifyResponse>;
      if (
        (res.ok || res.status === 403) &&
        typeof body.allow === "boolean" &&
        Array.isArray(body.reasons)
      ) {
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
