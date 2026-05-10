import type { Env } from "./env.js";
import app, { rotateAllStale } from "./index.js";

export default {
  fetch: (req: Request, env: Env, ctx: ExecutionContext) => app.fetch(req, env, ctx),
  scheduled: async (_event: ScheduledEvent, env: Env, ctx: ExecutionContext) => {
    ctx.waitUntil(rotateAllStale(env).then(() => undefined));
  },
};
