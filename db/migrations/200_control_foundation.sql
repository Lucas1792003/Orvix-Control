-- ============================================================
-- 200: control schema, roles, settings, rate limits
--
-- PURPOSE  Foundation for Orvix Control. Creates the `control` schema and the three control roles.
--          No tenant (POS) object is created, referenced, altered or granted here.
-- ROLES    control_definer      NOLOGIN  owns control tables and every control.api_* function
--          control_audit_owner  NOLOGIN  owns the append-only audit log (migration 201)
--          control_app          LOGIN    the ONLY role the Next.js server uses: USAGE on schema
--                                        control + EXECUTE on control.api_* (granted per function).
--                                        Its password is set OUT OF BAND (scripts/migrate.ts), never here.
-- INVARIANT No control role is SUPERUSER, BYPASSRLS, CREATEROLE or CREATEDB. control_app holds no
--          table privilege anywhere (tests/sql/privileges.test.ts).
-- ROLLBACK DROP SCHEMA control CASCADE; DROP SCHEMA control_ext CASCADE; DROP ROLE control_app,
--          control_audit_owner, control_definer;
-- ============================================================

DO $pre$
BEGIN
  IF NOT (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) THEN
    RAISE EXCEPTION 'migration 200 must run as the database superuser';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = 'control') THEN
    RAISE EXCEPTION 'schema control already exists; refusing to re-create it';
  END IF;
END
$pre$;

-- ------------------------------------------------------------ roles
DO $roles$
DECLARE r text;
BEGIN
  FOREACH r IN ARRAY ARRAY['control_definer', 'control_audit_owner'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      EXECUTE format('CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS', r);
    END IF;
  END LOOP;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'control_app') THEN
    CREATE ROLE control_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS
      CONNECTION LIMIT 8;
  END IF;
END
$roles$;

ALTER ROLE control_app SET search_path = control, pg_catalog;
ALTER ROLE control_app SET statement_timeout = '5s';
ALTER ROLE control_app SET idle_in_transaction_session_timeout = '10s';
ALTER ROLE control_app SET lock_timeout = '3s';

-- Nobody but control_app (and the superuser) may connect; nobody gets implicit rights in public.
DO $db$
BEGIN
  EXECUTE format('REVOKE ALL ON DATABASE %I FROM PUBLIC', current_database());
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO control_app', current_database());
END
$db$;
REVOKE ALL ON SCHEMA public FROM PUBLIC;

-- ------------------------------------------------------------ extensions (isolated schema)
CREATE SCHEMA control_ext;
REVOKE ALL ON SCHEMA control_ext FROM PUBLIC;
CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA control_ext;
GRANT USAGE ON SCHEMA control_ext TO control_definer, control_audit_owner;

-- ------------------------------------------------------------ schema
CREATE SCHEMA control AUTHORIZATION control_definer;
REVOKE ALL ON SCHEMA control FROM PUBLIC;
GRANT USAGE ON SCHEMA control TO control_app, control_audit_owner;
-- control_audit_owner creates its tables in 201.
GRANT CREATE ON SCHEMA control TO control_audit_owner;

-- New functions must never be executable by PUBLIC by default.
ALTER DEFAULT PRIVILEGES FOR ROLE control_definer IN SCHEMA control REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE control_audit_owner IN SCHEMA control REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

SET ROLE control_definer;

-- ------------------------------------------------------------ settings
CREATE TABLE control.settings (
  key        text PRIMARY KEY CHECK (key ~ '^[a-z][a-z0-9_]{2,62}$'),
  value      jsonb NOT NULL,
  updated_at timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE control.settings ENABLE ROW LEVEL SECURITY;

INSERT INTO control.settings (key, value) VALUES
  ('session_idle_seconds',        '900'),    -- 15 min idle
  ('session_absolute_seconds',    '28800'),  -- 8 h absolute
  ('stepup_max_age_seconds',      '300'),    -- 5 min step-up recency
  ('challenge_ttl_seconds',       '300'),
  ('enrolment_token_ttl_seconds', '900'),    -- 15 min single-use
  ('login_global_limit',          '20'),     -- per window, all identities
  ('login_credential_limit',      '5'),      -- per window, per credential
  ('enrol_token_limit',           '10'),
  ('rate_window_seconds',         '900');

CREATE FUNCTION control.setting_int(p_key text) RETURNS integer
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = control, pg_temp AS $$
  SELECT (value #>> '{}')::integer FROM control.settings WHERE key = p_key
$$;

-- ------------------------------------------------------------ rate limits (in the DB, not per worker)
CREATE TABLE control.rate_limits (
  bucket       text NOT NULL,
  key          text NOT NULL,
  window_start timestamptz NOT NULL,
  hits         integer NOT NULL DEFAULT 0,
  PRIMARY KEY (bucket, key, window_start)
);
ALTER TABLE control.rate_limits ENABLE ROW LEVEL SECURITY;

-- Returns true when the call is ALLOWED. Counts the hit either way.
CREATE FUNCTION control.rate_limit_hit(p_bucket text, p_key text, p_limit integer) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE
  v_window integer := control.setting_int('rate_window_seconds');
  v_start  timestamptz := to_timestamp(floor(extract(epoch FROM now()) / v_window) * v_window);
  v_hits   integer;
BEGIN
  IF p_limit IS NULL OR v_window IS NULL THEN
    RETURN false;  -- fail closed on missing configuration
  END IF;
  INSERT INTO control.rate_limits AS r (bucket, key, window_start, hits)
  VALUES (p_bucket, p_key, v_start, 1)
  ON CONFLICT (bucket, key, window_start) DO UPDATE SET hits = r.hits + 1
  RETURNING hits INTO v_hits;
  RETURN v_hits <= p_limit;
END
$$;

-- ------------------------------------------------------------ helpers
CREATE FUNCTION control.sha(p text) RETURNS bytea
LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp AS $$
  SELECT sha256(convert_to(p, 'UTF8'))
$$;

CREATE FUNCTION control.new_secret() RETURNS text
LANGUAGE sql VOLATILE SET search_path = control_ext, pg_catalog, pg_temp AS $$
  SELECT encode(control_ext.gen_random_bytes(32), 'hex')
$$;

-- Contract version: the app refuses to start against an unexpected schema.
CREATE FUNCTION control.api_contract_version() RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = control, pg_temp AS $$
  SELECT 'orvix-control/0.1'::text
$$;

RESET ROLE;

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA control FROM PUBLIC;
GRANT EXECUTE ON FUNCTION control.api_contract_version() TO control_app;
