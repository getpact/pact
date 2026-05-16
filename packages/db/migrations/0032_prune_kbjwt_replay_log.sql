-- Retention helper for kbjwt_replay_log. The table is append-only and grows
-- unbounded as redeem calls fire. Rows older than the longest live capability
-- can no longer participate in a successful replay, so they are safe to drop.
--
-- The function runs as SECURITY DEFINER and is owned by the migration role,
-- which lets it bypass the table's FORCE ROW LEVEL SECURITY and prune across
-- every workspace in one pass. pact_app receives EXECUTE so the CLI (which
-- connects with whatever DATABASE_URL provides) can call it; ops invocation
-- via cron is the intended path.
CREATE OR REPLACE FUNCTION prune_kbjwt_replay_log(older_than interval)
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
  deleted bigint;
BEGIN
  IF older_than IS NULL OR older_than <= interval '0' THEN
    RAISE EXCEPTION 'older_than must be a positive interval';
  END IF;
  DELETE FROM kbjwt_replay_log
   WHERE presented_at < now() - older_than;
  GET DIAGNOSTICS deleted = ROW_COUNT;
  RETURN deleted;
END;
$$;

REVOKE ALL ON FUNCTION prune_kbjwt_replay_log(interval) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION prune_kbjwt_replay_log(interval) TO pact_app;
