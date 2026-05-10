import { securityHeaders } from "@getpact/core";
import { Hono } from "hono";

type Env = {
  ENVIRONMENT?: string;
};

const app = new Hono<{ Bindings: Env }>();

app.use("*", async (c, next) => {
  await next();
  const headers = securityHeaders({ production: c.env.ENVIRONMENT === "production" });
  for (const [k, v] of Object.entries(headers)) c.header(k, v);
});

app.all("/:workspace/proxy/:brain/*", (c) => c.text("proxy not implemented", 501));

export default app;
