import { Hono } from "hono";

const app = new Hono();

app.all("/:workspace/mcp", (c) => c.text("mcp not implemented", 501));

export default app;
