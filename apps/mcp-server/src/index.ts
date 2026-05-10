import { Hono } from "hono";
import { authenticate } from "./auth.js";
import { handleMcp } from "./handler.js";

type Env = {
  DATABASE_URL: string;
  MCP_AUDIENCE?: string;
};

const app = new Hono<{ Bindings: Env }>();

app.get("/health", (c) => c.json({ ok: true }));

app.post("/:workspace/mcp", async (c) => {
  const workspace = c.req.param("workspace");
  const audience = c.env.MCP_AUDIENCE ?? "pact-mcp";

  let ctx: Awaited<ReturnType<typeof authenticate>>;
  try {
    ctx = await authenticate(
      c.env.DATABASE_URL,
      workspace,
      c.req.header("Authorization"),
      audience,
    );
  } catch (e) {
    const message = e instanceof Error ? e.message : "auth failed";
    return c.json({ error: "unauthorized", message }, 401);
  }

  const body = await c.req.json();
  const response = await handleMcp(body, ctx);
  return c.json(response);
});

export default app;
