const required = (name) => {
  const value = process.env[name];
  if (!value) throw new Error(`missing ${name}`);
  return value.replace(/\/$/, "");
};

const optional = (name) => {
  const value = process.env[name];
  return value ? value.replace(/\/$/, "") : undefined;
};

const check = async (name, url, init) => {
  const res = await fetch(url, init);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`${name} failed (${res.status}): ${text.slice(0, 500)}`);
  }
  console.log(`${name}: ${res.status}`);
  return res;
};

const checkAny = async (name, url, init, statuses) => {
  const res = await fetch(url, init);
  if (!statuses.includes(res.status)) {
    const text = await res.text();
    throw new Error(`${name} failed (${res.status}): ${text.slice(0, 500)}`);
  }
  console.log(`${name}: ${res.status}`);
  return res;
};

const parseJson = async (name, res) => {
  const body = await res.json();
  if (body?.error) {
    throw new Error(`${name} returned error: ${JSON.stringify(body.error)}`);
  }
  return body;
};

const health = [
  ["issuer", optional("PACT_ISSUER_URL")],
  ["verifier", optional("PACT_VERIFIER_URL")],
  ["mcp-server", optional("PACT_MCP_URL")],
  ["admin-api", optional("PACT_ADMIN_API_URL")],
  ["audit-api", optional("PACT_AUDIT_API_URL")],
  ["gateway", optional("PACT_GATEWAY_URL")],
].filter(([, url]) => url);

if (health.length === 0) {
  throw new Error("set at least one PACT_*_URL, for example PACT_ISSUER_URL");
}

for (const [name, baseUrl] of health) {
  await check(`${name} health`, `${baseUrl}/health`);
}

if (process.env.PACT_SMOKE_DEV_FLOW === "true") {
  const issuerUrl = required("PACT_ISSUER_URL");
  const verifierUrl = required("PACT_VERIFIER_URL");
  const mcpUrl = required("PACT_MCP_URL");
  const workspaceId = required("PACT_SMOKE_WORKSPACE_ID");
  const workspaceSlug = required("PACT_SMOKE_WORKSPACE_SLUG");
  const email = process.env.PACT_SMOKE_EMAIL ?? "smoke@example.com";
  const audience = process.env.PACT_SMOKE_AUDIENCE ?? "pact-mcp";

  const issue = await check(`${issuerUrl} dev issue`, `${issuerUrl}/v1/dev/issue`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ workspaceId, email, audience }),
  });
  const issued = await issue.json();
  if (!issued.token) throw new Error("dev issue response did not include token");

  const verifierAllow = await check("verifier allow path", `${verifierUrl}/v1/verify`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      token: issued.token,
      action: "smoke",
      resource: "smoke:health",
    }),
  });
  const verifierBody = await parseJson("verifier allow path", verifierAllow);
  if (verifierBody.allow !== true) {
    throw new Error(`verifier denied smoke path: ${JSON.stringify(verifierBody.reasons ?? [])}`);
  }

  await check("mcp initialize", `${mcpUrl}/${workspaceSlug}/mcp`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${issued.token}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "initialize" }),
  });

  const toolCall = await check("mcp pact.whoami", `${mcpUrl}/${workspaceSlug}/mcp`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${issued.token}`,
      "content-type": "application/json",
    },
    body: JSON.stringify({
      jsonrpc: "2.0",
      id: 2,
      method: "tools/call",
      params: { name: "pact.whoami", arguments: {} },
    }),
  });
  const toolBody = await parseJson("mcp pact.whoami", toolCall);
  const toolText = toolBody.result?.content?.[0]?.text;
  if (!toolText?.includes(email)) {
    throw new Error("mcp pact.whoami did not return the smoke identity");
  }

  const auditUrl = optional("PACT_AUDIT_API_URL");
  if (auditUrl) {
    const auditIssue = await check(
      `${issuerUrl} dev issue audit token`,
      `${issuerUrl}/v1/dev/issue`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ workspaceId, email, audience: "pact-audit" }),
      },
    );
    const auditIssued = await auditIssue.json();
    if (!auditIssued.token) throw new Error("audit token issue response did not include token");
    const auditEvents = await check(
      "audit contains mcp verifier event",
      `${auditUrl}/v1/workspaces/${workspaceId}/audit/events?action=verify.tool:pact.whoami&limit=5`,
      { headers: { authorization: `Bearer ${auditIssued.token}` } },
    );
    const auditBody = await auditEvents.json();
    const foundMcpAudit = auditBody.events?.some(
      (event) => event.action === "verify.tool:pact.whoami" && event.decision === "allow",
    );
    if (!foundMcpAudit) {
      throw new Error("audit chain did not include verify.tool:pact.whoami");
    }
  }

  if (process.env.PACT_SMOKE_GATEWAY_FLOW === "true") {
    const gatewayUrl = required("PACT_GATEWAY_URL");
    const brainKind = process.env.PACT_SMOKE_GATEWAY_BRAIN ?? "smoke-http";
    const gatewayPath = (process.env.PACT_SMOKE_GATEWAY_PATH ?? "get").replace(/^\/+/, "");
    const gatewayResource = `gateway:${brainKind}:/${gatewayPath}`;

    if (process.env.PACT_SMOKE_GATEWAY_BASE_URL) {
      const adminUrl = required("PACT_ADMIN_API_URL");
      const adminIssue = await check(
        `${issuerUrl} dev issue admin token`,
        `${issuerUrl}/v1/dev/issue`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ workspaceId, email, audience: "pact-admin" }),
        },
      );
      const adminIssued = await adminIssue.json();
      if (!adminIssued.token) throw new Error("admin token issue response did not include token");
      await checkAny(
        "admin seed gateway brain",
        `${adminUrl}/v1/workspaces/${workspaceId}/brains`,
        {
          method: "POST",
          headers: {
            authorization: `Bearer ${adminIssued.token}`,
            "content-type": "application/json",
          },
          body: JSON.stringify({
            kind: brainKind,
            baseUrl: process.env.PACT_SMOKE_GATEWAY_BASE_URL,
            authScheme: "none",
          }),
        },
        [201, 409],
      );
    }

    const gatewayIssue = await check(
      `${issuerUrl} dev issue gateway token`,
      `${issuerUrl}/v1/dev/issue`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ workspaceId, email, audience: "pact-gateway" }),
      },
    );
    const gatewayIssued = await gatewayIssue.json();
    if (!gatewayIssued.token) throw new Error("gateway token issue response did not include token");

    await check(
      `gateway ${gatewayResource}`,
      `${gatewayUrl}/${workspaceSlug}/gateway/${brainKind}/${gatewayPath}`,
      { headers: { authorization: `Bearer ${gatewayIssued.token}` } },
    );

    if (auditUrl) {
      const auditIssue = await check(
        `${issuerUrl} dev issue gateway audit token`,
        `${issuerUrl}/v1/dev/issue`,
        {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({ workspaceId, email, audience: "pact-audit" }),
        },
      );
      const auditIssued = await auditIssue.json();
      if (!auditIssued.token) throw new Error("audit token issue response did not include token");
      const auditEvents = await check(
        "audit contains gateway event",
        `${auditUrl}/v1/workspaces/${workspaceId}/audit/events?action=gateway.get&limit=5`,
        { headers: { authorization: `Bearer ${auditIssued.token}` } },
      );
      const auditBody = await auditEvents.json();
      const foundGatewayAudit = auditBody.events?.some(
        (event) =>
          event.action === "gateway.get" &&
          event.decision === "allow" &&
          event.target?.resource === gatewayResource,
      );
      if (!foundGatewayAudit) {
        throw new Error("audit chain did not include gateway.get");
      }
    }
  }
}
