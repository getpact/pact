import { Hono } from "hono";

const app = new Hono();

app.all("/:workspace/proxy/:brain/*", (c) => c.text("proxy not implemented", 501));

export default app;
