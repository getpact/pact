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

export type RedeemAllow = {
  allow: true;
  status: 200;
  scope_claim: Record<string, unknown>;
  agent_id: string;
  on_behalf_of: string | null;
  audience: string;
  delegation_depth: number;
};

export type RedeemDeny = {
  allow: false;
  status: number;
  reasons: string[];
};

export type RedeemResponse = RedeemAllow | RedeemDeny;

export type RedeemClient = (input: {
  sd_jwt: string;
  jti: string;
  tool_name: string;
  resource: Record<string, unknown>;
}) => Promise<RedeemResponse>;

export const httpRedeemClient =
  (verifier: VerifierTransport, serviceToken?: string): RedeemClient =>
  async (input) => {
    const path = `/v1/capabilities/${encodeURIComponent(input.jti)}/redeem`;
    const headers = new Headers({ "content-type": "application/json" });
    if (serviceToken) headers.set("authorization", `Bearer ${serviceToken}`);
    const init: RequestInit = {
      method: "POST",
      headers,
      body: JSON.stringify({
        sd_jwt: input.sd_jwt,
        tool_name: input.tool_name,
        resource: input.resource,
      }),
    };
    try {
      const res =
        typeof verifier === "string"
          ? await fetch(`${verifier.replace(/\/+$/, "")}${path}`, init)
          : await verifier.fetch(new Request(`https://verifier.internal${path}`, init));
      const body = (await res.json().catch(() => ({}))) as Record<string, unknown>;
      if (res.ok && body.allow === true) {
        return {
          allow: true,
          status: 200,
          scope_claim:
            typeof body.scope_claim === "object" && body.scope_claim !== null
              ? (body.scope_claim as Record<string, unknown>)
              : {},
          agent_id: typeof body.agent_id === "string" ? body.agent_id : "",
          on_behalf_of:
            typeof body.on_behalf_of === "string"
              ? body.on_behalf_of
              : body.on_behalf_of === null
                ? null
                : null,
          audience: typeof body.audience === "string" ? body.audience : input.tool_name,
          delegation_depth: typeof body.delegation_depth === "number" ? body.delegation_depth : 0,
        };
      }
      if (body.allow === false && Array.isArray(body.reasons)) {
        const reasons = (body.reasons as unknown[]).filter(
          (r): r is string => typeof r === "string",
        );
        return { allow: false, status: res.status, reasons };
      }
      return { allow: false, status: res.status, reasons: [`verifier returned ${res.status}`] };
    } catch {
      return { allow: false, status: 503, reasons: ["verifier unavailable"] };
    }
  };
