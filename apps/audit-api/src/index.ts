import { Hono } from "hono";

const app = new Hono();

app.get("/v1/audit/query", (c) => c.json({ events: [], cursor: null }));
app.get("/v1/audit/stream", (c) => c.text("not implemented", 501));

export default app;
