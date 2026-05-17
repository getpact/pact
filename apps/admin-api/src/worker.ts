import { createLogger } from "@getpact/logger";
import app, { type Env, pruneReplayLog } from "./index.js";

const logger = createLogger({ base: { app: "admin-api" } });

const runPrune = async (env: Env): Promise<void> => {
  try {
    const { deleted, days } = await pruneReplayLog(env);
    logger.info("scheduled.prune_replay_log", { deleted, retentionDays: days });
  } catch (err) {
    logger.error("scheduled.prune_replay_log_failed", { err });
  }
};

export default {
  fetch: (req: Request, env: Env, ctx: ExecutionContext) => app.fetch(req, env, ctx),
  scheduled: (_event: ScheduledEvent, env: Env, ctx: ExecutionContext) => {
    ctx.waitUntil(runPrune(env));
  },
};
