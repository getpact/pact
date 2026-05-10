import { Hono } from "hono";

const app = new Hono();

app.post("/v1/verify", (c) => c.json({ allow: false, reasons: ["not_implemented"] }, 501));

export default app;
