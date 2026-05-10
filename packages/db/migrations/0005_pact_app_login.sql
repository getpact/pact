-- Allow pact_app to connect for runtime queries. Production uses a real password
-- supplied via environment; the value here is a sane local-dev default.
DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_roles WHERE rolname = 'pact_app' AND rolcanlogin
  ) THEN
    ALTER ROLE pact_app WITH LOGIN PASSWORD 'pact_app';
  END IF;
END
$$;
