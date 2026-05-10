import { Hono } from "hono";

const app = new Hono();

app.get("/.well-known/jwks.json", (c) => c.json({ keys: [] }));
app.get("/oauth/google/authorize", (c) => c.text("not implemented", 501));
app.get("/oauth/google/callback", (c) => c.text("not implemented", 501));

export default app;
