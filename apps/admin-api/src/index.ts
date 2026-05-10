import { Hono } from "hono";

const app = new Hono();

app.get("/v1/workspaces", (c) => c.json([]));
app.post("/v1/workspaces", (c) => c.text("not implemented", 501));

export default app;
