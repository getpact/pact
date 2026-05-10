type CreateWorkspaceResponse = {
  workspaceId: string;
  adminUserId: string;
  jwtKeyId: string;
  auditKeyId: string;
};

type IssueResponse = {
  token: string;
  jti: string;
  exp: number;
  userId: string;
  refreshToken: string;
  refreshExpiresAt: string;
};

const post = async <T>(endpoint: string, path: string, body: unknown): Promise<T> => {
  const res = await fetch(`${endpoint}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`${path} failed (${res.status}): ${text}`);
  }
  return (await res.json()) as T;
};

export const createWorkspace = (
  endpoint: string,
  body: { slug: string; name: string; adminEmail: string; adminName?: string },
): Promise<CreateWorkspaceResponse> => post(endpoint, "/v1/workspaces", body);

export const devIssue = (
  endpoint: string,
  body: { workspaceId: string; email: string; audience: string },
): Promise<IssueResponse> => post(endpoint, "/v1/dev/issue", body);

export const refresh = (
  endpoint: string,
  body: { workspaceId: string; refreshToken: string; audience: string },
): Promise<IssueResponse> => post(endpoint, "/v1/refresh", body);

export const googleExchange = (
  endpoint: string,
  body: {
    workspaceId: string;
    code: string;
    codeVerifier: string;
    redirectUri: string;
    audience: string;
  },
): Promise<IssueResponse> => post(endpoint, "/v1/oauth/google/exchange", body);
