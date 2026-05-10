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
    const res = await fetch(`${verifierUrl.replace(/\/+$/, "")}/v1/verify`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(input),
    });
    const body = (await res.json()) as VerifyResponse;
    return body;
  };
