-- ============================================================
-- 202: platform identities, passkeys, challenges, sessions
--
-- PURPOSE  Platform operators live here, NOT in tenant GoTrue. There are no passwords. The only factor
--          in this foundation is a WebAuthn passkey with user verification.
-- TRUST    The DB cannot verify a WebAuthn signature. The Next.js server verifies the assertion with
--          @simplewebauthn/server, then calls the api_* function. The DB enforces the rest: the challenge
--          was issued by the DB, has the right purpose, is unexpired and unused (single use); the
--          credential and identity are active; sign counters never regress; sessions are opaque random
--          tokens of which only SHA-256 is stored; idle and absolute expiry; step-up recency.
-- RESULT   Every api_* returns jsonb {ok:true,...} or {ok:false,error:'CODE'}. Refusals do NOT raise,
--          so the audit row written for the refusal is committed. The app treats anything other than
--          ok=true as a refusal (fail closed).
-- ROLLBACK DROP the objects created below.
-- ============================================================

SET ROLE control_definer;

CREATE TABLE control.platform_identities (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email        text NOT NULL CHECK (email = lower(btrim(email)) AND email ~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' AND length(email) <= 254),
  display_name text NOT NULL CHECK (length(btrim(display_name)) BETWEEN 1 AND 80),
  role         text NOT NULL CHECK (role IN ('owner', 'admin')),
  state        text NOT NULL CHECK (state IN ('enrolling', 'active', 'revoked')),
  created_at   timestamptz NOT NULL DEFAULT now(),
  activated_at timestamptz,
  revoked_at   timestamptz
);
CREATE UNIQUE INDEX platform_identities_email_uq ON control.platform_identities (email);
ALTER TABLE control.platform_identities ENABLE ROW LEVEL SECURITY;

CREATE TABLE control.webauthn_credentials (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  identity_id   uuid NOT NULL REFERENCES control.platform_identities(id),
  -- (Postgres regex repetition counts are capped at 255, so the length bound is a separate term.)
  credential_id text NOT NULL UNIQUE CHECK (credential_id ~ '^[A-Za-z0-9_-]+$' AND length(credential_id) BETWEEN 16 AND 1366),
  public_key    bytea NOT NULL CHECK (length(public_key) BETWEEN 32 AND 2048),
  sign_count    bigint NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
  transports    text[] NOT NULL DEFAULT '{}',
  created_at    timestamptz NOT NULL DEFAULT now(),
  last_used_at  timestamptz,
  disabled_at   timestamptz,
  disabled_reason text
);
ALTER TABLE control.webauthn_credentials ENABLE ROW LEVEL SECURITY;

CREATE TABLE control.enrolment_tokens (
  token_hash  bytea PRIMARY KEY,
  identity_id uuid NOT NULL REFERENCES control.platform_identities(id),
  purpose     text NOT NULL CHECK (purpose IN ('owner_bootstrap')),
  expires_at  timestamptz NOT NULL,
  used_at     timestamptz
);
ALTER TABLE control.enrolment_tokens ENABLE ROW LEVEL SECURITY;

CREATE TABLE control.webauthn_challenges (
  challenge_hash  bytea PRIMARY KEY,
  purpose         text NOT NULL CHECK (purpose IN ('register', 'login', 'stepup')),
  identity_id     uuid REFERENCES control.platform_identities(id),
  session_id_hash bytea,
  created_at      timestamptz NOT NULL DEFAULT now(),
  expires_at      timestamptz NOT NULL,
  used_at         timestamptz
);
ALTER TABLE control.webauthn_challenges ENABLE ROW LEVEL SECURITY;

CREATE TABLE control.sessions (
  id_hash             bytea PRIMARY KEY CHECK (length(id_hash) = 32),
  identity_id         uuid NOT NULL REFERENCES control.platform_identities(id),
  credential_id       text NOT NULL,
  created_at          timestamptz NOT NULL DEFAULT now(),
  last_seen_at        timestamptz NOT NULL DEFAULT now(),
  absolute_expires_at timestamptz NOT NULL,
  stepup_at           timestamptz,
  revoked_at          timestamptz,
  revoke_reason       text CHECK (revoke_reason IN ('logout', 'idle_timeout', 'absolute_timeout', 'identity_inactive', 'admin'))
);
CREATE INDEX sessions_identity_idx ON control.sessions (identity_id) WHERE revoked_at IS NULL;
ALTER TABLE control.sessions ENABLE ROW LEVEL SECURITY;

CREATE TABLE control.bootstrap_state (
  singleton  boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  closed     boolean NOT NULL DEFAULT false,
  closed_at  timestamptz
);
INSERT INTO control.bootstrap_state DEFAULT VALUES;
ALTER TABLE control.bootstrap_state ENABLE ROW LEVEL SECURITY;

-- ------------------------------------------------------------ internal helpers (not granted to control_app)

CREATE FUNCTION control.err(p_code text) RETURNS jsonb
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT jsonb_build_object('ok', false, 'error', p_code)
$$;

-- Records a challenge minted by the app. Purpose-bound, short-lived, single-use.
CREATE FUNCTION control.challenge_store(p_challenge text, p_purpose text, p_identity uuid, p_session_hash bytea)
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
BEGIN
  IF p_challenge IS NULL OR p_challenge !~ '^[A-Za-z0-9_-]{32,128}$' THEN
    RETURN false;
  END IF;
  INSERT INTO control.webauthn_challenges (challenge_hash, purpose, identity_id, session_id_hash, expires_at)
  VALUES (control.sha(p_challenge), p_purpose, p_identity, p_session_hash,
          now() + make_interval(secs => control.setting_int('challenge_ttl_seconds')))
  ON CONFLICT (challenge_hash) DO NOTHING;
  RETURN FOUND;
END
$$;

-- Consumes a challenge exactly once. Returns the row only if purpose, binding and expiry all match.
CREATE FUNCTION control.challenge_consume(p_challenge text, p_purpose text)
RETURNS control.webauthn_challenges
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE v control.webauthn_challenges;
BEGIN
  UPDATE control.webauthn_challenges
     SET used_at = now()
   WHERE challenge_hash = control.sha(p_challenge)
     AND used_at IS NULL
  RETURNING * INTO v;
  IF v.challenge_hash IS NULL OR v.purpose <> p_purpose OR v.expires_at <= now() THEN
    RETURN NULL;
  END IF;
  RETURN v;
END
$$;

-- Resolves a session token. Applies idle/absolute expiry (revoking and auditing once), checks the identity
-- is still active, and touches last_seen_at. Returns NULL when the session is not usable.
CREATE TYPE control.session_ctx AS (
  id_hash      bytea,
  identity_id  uuid,
  email        text,
  display_name text,
  role         text,
  created_at   timestamptz,
  absolute_expires_at timestamptz,
  idle_expires_at     timestamptz,
  stepup_at    timestamptz
);

CREATE FUNCTION control.session_resolve(p_token text) RETURNS control.session_ctx
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE
  s       control.sessions;
  i       control.platform_identities;
  v_idle  interval := make_interval(secs => control.setting_int('session_idle_seconds'));
  v_reason text;
  r       control.session_ctx;
BEGIN
  IF p_token IS NULL OR p_token !~ '^[0-9a-f]{64}$' OR v_idle IS NULL THEN
    RETURN NULL;
  END IF;
  SELECT * INTO s FROM control.sessions WHERE id_hash = control.sha(p_token) FOR UPDATE;
  IF s.id_hash IS NULL OR s.revoked_at IS NOT NULL THEN
    RETURN NULL;
  END IF;
  SELECT * INTO i FROM control.platform_identities WHERE id = s.identity_id;
  IF now() >= s.absolute_expires_at THEN
    v_reason := 'absolute_timeout';
  ELSIF now() - s.last_seen_at >= v_idle THEN
    v_reason := 'idle_timeout';
  ELSIF i.state IS DISTINCT FROM 'active' THEN
    v_reason := 'identity_inactive';
  END IF;
  IF v_reason IS NOT NULL THEN
    UPDATE control.sessions SET revoked_at = now(), revoke_reason = v_reason WHERE id_hash = s.id_hash;
    PERFORM control.audit_append('platform_identity', i.id, i.display_name, 'platform.session_expired', 'success',
      'session', encode(substring(s.id_hash FROM 1 FOR 8), 'hex'), NULL, v_reason, '{}'::jsonb);
    RETURN NULL;
  END IF;
  UPDATE control.sessions SET last_seen_at = now() WHERE id_hash = s.id_hash;
  r := (s.id_hash, i.id, i.email, i.display_name, i.role, s.created_at, s.absolute_expires_at,
        now() + v_idle, s.stepup_at);
  RETURN r;
END
$$;

-- Authorisation gate used by every protected api_* function. Returns NULL when allowed, or the error
-- jsonb (after auditing the denial) when not.
CREATE FUNCTION control.authorize(c control.session_ctx, p_roles text[], p_need_stepup boolean,
                                  p_action_label text, p_request_id uuid)
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE v_code text;
BEGIN
  IF c.identity_id IS NULL THEN
    RETURN control.err('UNAUTHENTICATED');  -- not audited per request (no identity); see SECURITY_FINDINGS
  END IF;
  IF NOT (c.role = ANY (p_roles)) THEN
    v_code := 'FORBIDDEN';
  ELSIF p_need_stepup AND (c.stepup_at IS NULL OR
        now() - c.stepup_at > make_interval(secs => control.setting_int('stepup_max_age_seconds'))) THEN
    v_code := 'STEPUP_REQUIRED';
  END IF;
  IF v_code IS NULL THEN
    RETURN NULL;
  END IF;
  PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'platform.access_denied', 'denied',
    'api', p_action_label, p_request_id, v_code, '{}'::jsonb);
  RETURN control.err(v_code);
END
$$;

-- ------------------------------------------------------------ bootstrap and enrolment

-- Creates the first Owner identity and a single-use enrolment token (returned ONCE, stored hashed).
-- Callable by control_app (the CLI runs as control_app), but only ever succeeds once per install.
CREATE FUNCTION control.api_bootstrap_owner(p_email text, p_display_name text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE
  v_id    uuid;
  v_token text := control.new_secret();
  v_email text := lower(btrim(p_email));
BEGIN
  PERFORM pg_advisory_xact_lock(202, 1);
  IF (SELECT closed FROM control.bootstrap_state) OR EXISTS (SELECT 1 FROM control.platform_identities) THEN
    PERFORM control.audit_append('cli', NULL, 'bootstrap-cli', 'platform.owner_bootstrap_refused', 'denied',
      NULL, NULL, NULL, 'ALREADY_BOOTSTRAPPED', '{}'::jsonb);
    RETURN control.err('ALREADY_BOOTSTRAPPED');
  END IF;
  BEGIN
    INSERT INTO control.platform_identities (email, display_name, role, state)
    VALUES (v_email, btrim(p_display_name), 'owner', 'enrolling') RETURNING id INTO v_id;
  EXCEPTION WHEN check_violation OR not_null_violation THEN
    RETURN control.err('INVALID_INPUT');
  END;
  INSERT INTO control.enrolment_tokens (token_hash, identity_id, purpose, expires_at)
  VALUES (control.sha(v_token), v_id, 'owner_bootstrap',
          now() + make_interval(secs => control.setting_int('enrolment_token_ttl_seconds')));
  PERFORM control.audit_append('cli', NULL, 'bootstrap-cli', 'platform.owner_bootstrap_started', 'success',
    'platform_identity', v_id::text, NULL, NULL,
    jsonb_build_object('email_domain', split_part(v_email, '@', 2)));
  RETURN jsonb_build_object('ok', true, 'identity_id', v_id, 'enrolment_token', v_token,
                            'expires_in_seconds', control.setting_int('enrolment_token_ttl_seconds'));
END
$$;

-- Validates an enrolment token and records a registration challenge bound to its identity.
CREATE FUNCTION control.api_enrol_begin(p_token text, p_challenge text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE t control.enrolment_tokens; i control.platform_identities;
BEGIN
  IF NOT control.rate_limit_hit('enrol', 'global', control.setting_int('enrol_token_limit')) THEN
    PERFORM control.audit_append('anonymous', NULL, NULL, 'platform.rate_limited', 'denied', 'endpoint', 'enrol',
      NULL, 'RATE_LIMITED', '{}'::jsonb);
    RETURN control.err('RATE_LIMITED');
  END IF;
  SELECT * INTO t FROM control.enrolment_tokens
   WHERE p_token ~ '^[0-9a-f]{64}$' AND token_hash = control.sha(p_token);
  IF t.token_hash IS NULL OR t.used_at IS NOT NULL OR t.expires_at <= now() THEN
    PERFORM control.audit_append('anonymous', NULL, NULL, 'platform.enrol_failed', 'denied', NULL, NULL, NULL,
      'INVALID_TOKEN', '{}'::jsonb);
    RETURN control.err('INVALID_TOKEN');
  END IF;
  SELECT * INTO i FROM control.platform_identities WHERE id = t.identity_id;
  IF i.state <> 'enrolling' OR NOT control.challenge_store(p_challenge, 'register', i.id, NULL) THEN
    RETURN control.err('INVALID_TOKEN');
  END IF;
  RETURN jsonb_build_object('ok', true, 'identity_id', i.id, 'email', i.email, 'display_name', i.display_name);
END
$$;

-- Completes enrolment after the app verified the attestation against p_challenge.
CREATE FUNCTION control.api_enrol_complete(p_token text, p_challenge text, p_credential_id text,
                                           p_public_key bytea, p_sign_count bigint, p_transports text[])
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE t control.enrolment_tokens; c control.webauthn_challenges; i control.platform_identities;
BEGIN
  PERFORM pg_advisory_xact_lock(202, 1);
  SELECT * INTO t FROM control.enrolment_tokens
   WHERE p_token ~ '^[0-9a-f]{64}$' AND token_hash = control.sha(p_token) FOR UPDATE;
  c := control.challenge_consume(p_challenge, 'register');
  IF t.token_hash IS NULL OR t.used_at IS NOT NULL OR t.expires_at <= now()
     OR c.challenge_hash IS NULL OR c.identity_id IS DISTINCT FROM t.identity_id THEN
    PERFORM control.audit_append('anonymous', NULL, NULL, 'platform.enrol_failed', 'denied', NULL, NULL, NULL,
      'INVALID_TOKEN_OR_CHALLENGE', '{}'::jsonb);
    RETURN control.err('INVALID_TOKEN_OR_CHALLENGE');
  END IF;
  SELECT * INTO i FROM control.platform_identities WHERE id = t.identity_id FOR UPDATE;
  IF i.state <> 'enrolling' THEN
    RETURN control.err('INVALID_TOKEN_OR_CHALLENGE');
  END IF;
  BEGIN
    INSERT INTO control.webauthn_credentials (identity_id, credential_id, public_key, sign_count, transports)
    VALUES (i.id, p_credential_id, p_public_key, coalesce(p_sign_count, 0), coalesce(p_transports, '{}'));
  EXCEPTION WHEN unique_violation OR check_violation OR not_null_violation THEN
    PERFORM control.audit_append('anonymous', NULL, NULL, 'platform.enrol_failed', 'denied', 'platform_identity',
      i.id::text, NULL, 'INVALID_CREDENTIAL', '{}'::jsonb);
    RETURN control.err('INVALID_CREDENTIAL');
  END;
  UPDATE control.enrolment_tokens SET used_at = now() WHERE token_hash = t.token_hash;
  UPDATE control.platform_identities SET state = 'active', activated_at = now() WHERE id = i.id;
  IF i.role = 'owner' THEN
    UPDATE control.bootstrap_state SET closed = true, closed_at = now();
  END IF;
  PERFORM control.audit_append('platform_identity', i.id, i.display_name, 'platform.owner_enrolled', 'success',
    'platform_identity', i.id::text, NULL, NULL, jsonb_build_object('credential', left(p_credential_id, 8)));
  RETURN jsonb_build_object('ok', true);
END
$$;

-- ------------------------------------------------------------ login

CREATE FUNCTION control.api_login_begin(p_challenge text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
BEGIN
  IF NOT control.rate_limit_hit('login', 'global', control.setting_int('login_global_limit')) THEN
    PERFORM control.audit_append('anonymous', NULL, NULL, 'platform.rate_limited', 'denied', 'endpoint', 'login',
      NULL, 'RATE_LIMITED', '{}'::jsonb);
    RETURN control.err('RATE_LIMITED');
  END IF;
  IF NOT control.challenge_store(p_challenge, 'login', NULL, NULL) THEN
    RETURN control.err('INVALID_INPUT');
  END IF;
  RETURN jsonb_build_object('ok', true);
END
$$;

-- Public key lookup for signature verification (public keys are not secret). Only usable credentials.
CREATE FUNCTION control.api_credential_lookup(p_credential_id text) RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = control, pg_temp AS $$
  SELECT coalesce(
    (SELECT jsonb_build_object('ok', true, 'credential_id', c.credential_id,
                               'public_key', encode(c.public_key, 'base64'),
                               'sign_count', c.sign_count, 'transports', to_jsonb(c.transports))
       FROM control.webauthn_credentials c
       JOIN control.platform_identities i ON i.id = c.identity_id
      WHERE c.credential_id = p_credential_id AND c.disabled_at IS NULL AND i.state = 'active'),
    control.err('UNKNOWN_CREDENTIAL'))
$$;

-- Shared by login and step-up: checks credential, identity and sign counter. Returns an error code or NULL.
CREATE FUNCTION control.credential_accept(p_credential_id text, p_new_count bigint, p_identity uuid)
RETURNS text
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.webauthn_credentials; i control.platform_identities;
BEGIN
  SELECT * INTO c FROM control.webauthn_credentials WHERE credential_id = p_credential_id FOR UPDATE;
  IF c.id IS NULL OR c.disabled_at IS NOT NULL THEN RETURN 'UNKNOWN_CREDENTIAL'; END IF;
  SELECT * INTO i FROM control.platform_identities WHERE id = c.identity_id;
  IF i.state <> 'active' THEN RETURN 'IDENTITY_INACTIVE'; END IF;
  IF p_identity IS NOT NULL AND c.identity_id <> p_identity THEN RETURN 'CREDENTIAL_IDENTITY_MISMATCH'; END IF;
  IF p_new_count IS NULL OR p_new_count < 0 THEN RETURN 'INVALID_INPUT'; END IF;
  -- Authenticators that never count report 0 forever. Any authenticator that has counted must increase.
  IF (c.sign_count > 0 OR p_new_count > 0) AND p_new_count <= c.sign_count THEN
    UPDATE control.webauthn_credentials SET disabled_at = now(), disabled_reason = 'sign_count_regression'
     WHERE id = c.id;
    RETURN 'COUNTER_REGRESSION';
  END IF;
  UPDATE control.webauthn_credentials SET sign_count = p_new_count, last_used_at = now() WHERE id = c.id;
  RETURN NULL;
END
$$;

-- Called after the app verified the assertion signature against p_challenge. Creates the session.
CREATE FUNCTION control.api_login_complete(p_challenge text, p_credential_id text, p_new_sign_count bigint)
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE
  ch      control.webauthn_challenges;
  v_err   text;
  v_ident control.platform_identities;
  v_token text;
  v_abs   timestamptz;
BEGIN
  ch := control.challenge_consume(p_challenge, 'login');
  SELECT i.* INTO v_ident FROM control.webauthn_credentials c JOIN control.platform_identities i ON i.id = c.identity_id
   WHERE c.credential_id = p_credential_id;
  IF NOT control.rate_limit_hit('login_credential', coalesce(left(p_credential_id, 64), '-'),
                                control.setting_int('login_credential_limit')) THEN
    v_err := 'RATE_LIMITED';
  ELSIF ch.challenge_hash IS NULL THEN
    v_err := 'INVALID_CHALLENGE';
  ELSE
    v_err := control.credential_accept(p_credential_id, p_new_sign_count, NULL);
  END IF;
  IF v_err IS NOT NULL THEN
    PERFORM control.audit_append(CASE WHEN v_ident.id IS NULL THEN 'anonymous' ELSE 'platform_identity' END,
      v_ident.id, v_ident.display_name, 'platform.login_failed', 'denied', 'credential', left(p_credential_id, 8),
      NULL, v_err, '{}'::jsonb);
    RETURN control.err(v_err);
  END IF;
  v_token := control.new_secret();
  v_abs   := now() + make_interval(secs => control.setting_int('session_absolute_seconds'));
  INSERT INTO control.sessions (id_hash, identity_id, credential_id, absolute_expires_at)
  VALUES (control.sha(v_token), v_ident.id, p_credential_id, v_abs);
  PERFORM control.audit_append('platform_identity', v_ident.id, v_ident.display_name, 'platform.login_succeeded',
    'success', 'session', encode(substring(control.sha(v_token) FROM 1 FOR 8), 'hex'), NULL, NULL,
    jsonb_build_object('credential', left(p_credential_id, 8)));
  RETURN jsonb_build_object('ok', true, 'session_token', v_token, 'absolute_expires_at', v_abs,
                            'idle_seconds', control.setting_int('session_idle_seconds'));
END
$$;

-- The app reports a signature/verification failure: burn the challenge and audit.
CREATE FUNCTION control.api_auth_failed(p_purpose text, p_challenge text, p_credential_id text, p_reason text)
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE v_ident control.platform_identities;
BEGIN
  IF p_purpose NOT IN ('login', 'stepup', 'register') THEN
    RETURN control.err('INVALID_INPUT');
  END IF;
  PERFORM control.challenge_consume(p_challenge, p_purpose);
  SELECT i.* INTO v_ident FROM control.webauthn_credentials c JOIN control.platform_identities i ON i.id = c.identity_id
   WHERE c.credential_id = p_credential_id;
  PERFORM control.audit_append(CASE WHEN v_ident.id IS NULL THEN 'anonymous' ELSE 'platform_identity' END,
    v_ident.id, v_ident.display_name,
    CASE p_purpose WHEN 'login' THEN 'platform.login_failed' WHEN 'stepup' THEN 'platform.stepup_failed'
                   ELSE 'platform.enrol_failed' END,
    'denied', 'credential', left(p_credential_id, 8), NULL,
    left(regexp_replace(coalesce(p_reason, 'VERIFICATION_FAILED'), '[^A-Z_]', '', 'g'), 40), '{}'::jsonb);
  RETURN jsonb_build_object('ok', true);
END
$$;

-- ------------------------------------------------------------ session

CREATE FUNCTION control.api_session_get(p_token text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token);
BEGIN
  IF c.identity_id IS NULL THEN
    RETURN control.err('UNAUTHENTICATED');
  END IF;
  RETURN jsonb_build_object('ok', true, 'identity_id', c.identity_id, 'email', c.email,
    'display_name', c.display_name, 'role', c.role, 'absolute_expires_at', c.absolute_expires_at,
    'idle_expires_at', c.idle_expires_at, 'stepup_at', c.stepup_at,
    'stepup_valid', c.stepup_at IS NOT NULL AND now() - c.stepup_at <=
                    make_interval(secs => control.setting_int('stepup_max_age_seconds')));
END
$$;

CREATE FUNCTION control.api_session_revoke(p_token text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token);
BEGIN
  IF c.identity_id IS NULL THEN
    RETURN jsonb_build_object('ok', true);  -- already unusable; logout is idempotent
  END IF;
  UPDATE control.sessions SET revoked_at = now(), revoke_reason = 'logout' WHERE id_hash = c.id_hash;
  PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'platform.logout', 'success',
    'session', encode(substring(c.id_hash FROM 1 FOR 8), 'hex'), NULL, NULL, '{}'::jsonb);
  RETURN jsonb_build_object('ok', true);
END
$$;

-- ------------------------------------------------------------ step-up

CREATE FUNCTION control.api_stepup_begin(p_token text, p_challenge text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token);
BEGIN
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  IF NOT control.challenge_store(p_challenge, 'stepup', c.identity_id, c.id_hash) THEN
    RETURN control.err('INVALID_INPUT');
  END IF;
  RETURN jsonb_build_object('ok', true,
    'credential_ids', (SELECT coalesce(jsonb_agg(credential_id), '[]'::jsonb) FROM control.webauthn_credentials
                        WHERE identity_id = c.identity_id AND disabled_at IS NULL));
END
$$;

CREATE FUNCTION control.api_stepup_complete(p_token text, p_challenge text, p_credential_id text,
                                            p_new_sign_count bigint) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE
  c     control.session_ctx := control.session_resolve(p_token);
  ch    control.webauthn_challenges;
  v_err text;
BEGIN
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  ch := control.challenge_consume(p_challenge, 'stepup');
  IF ch.challenge_hash IS NULL OR ch.identity_id IS DISTINCT FROM c.identity_id
     OR ch.session_id_hash IS DISTINCT FROM c.id_hash THEN
    v_err := 'INVALID_CHALLENGE';
  ELSE
    v_err := control.credential_accept(p_credential_id, p_new_sign_count, c.identity_id);
  END IF;
  IF v_err IS NOT NULL THEN
    PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'platform.stepup_failed',
      'denied', 'session', encode(substring(c.id_hash FROM 1 FOR 8), 'hex'), NULL, v_err, '{}'::jsonb);
    RETURN control.err(v_err);
  END IF;
  UPDATE control.sessions SET stepup_at = now() WHERE id_hash = c.id_hash;
  PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'platform.stepup_succeeded',
    'success', 'session', encode(substring(c.id_hash FROM 1 FOR 8), 'hex'), NULL, NULL, '{}'::jsonb);
  RETURN jsonb_build_object('ok', true);
END
$$;

RESET ROLE;

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA control FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
  control.api_contract_version(),
  control.api_bootstrap_owner(text, text),
  control.api_enrol_begin(text, text),
  control.api_enrol_complete(text, text, text, bytea, bigint, text[]),
  control.api_login_begin(text),
  control.api_credential_lookup(text),
  control.api_login_complete(text, text, bigint),
  control.api_auth_failed(text, text, text, text),
  control.api_session_get(text),
  control.api_session_revoke(text),
  control.api_stepup_begin(text, text),
  control.api_stepup_complete(text, text, text, bigint)
TO control_app;
