-- ============================================================
-- 213: scoped login limits (C1.2, RM-2)
--
-- PROBLEM  One global login bucket (20 per 15 min) shared by every client: anyone who could reach the server
--          locked every operator out of sign-in. Behind the SSH tunnel every client is 127.0.0.1, so per-IP limits
--          cannot separate clients.
-- DESIGN   - A browser that has signed in before receives an opaque DEVICE TOKEN (32 random bytes, only SHA-256
--            stored, HttpOnly __Host- cookie). It carries NO authentication power; it only selects a private
--            challenge bucket (login_device_limit per window, per device) that an anonymous flood cannot drain.
--          - Unknown clients share the anonymous bucket (login_global_limit, unchanged), so first-time sign-in can
--            still be delayed by a flood; operators with a known device cannot.
--          - A hard CEILING on outstanding (unused, unexpired) login challenges bounds total creation across all
--            buckets: challenge creation is never unlimited.
--          - Expired login challenges are purged opportunistically (bounded per call).
--          - Device tokens die with the identity (revoked/recovered/emergency-revoked identities' devices are not
--            honoured: the bucket falls back to anonymous).
-- LIMITS   A flood still delays FIRST sign-in on a new device. A stolen device cookie only grants that device's
--          bucket (no access). See docs/RESIDUAL_RISKS_C1_2.md.
-- ============================================================

INSERT INTO control.settings (key, value) VALUES
  ('login_device_limit',        '10'),
  ('login_challenge_ceiling',   '500'),
  ('login_device_ttl_seconds',  '34560000');   -- 400 days

INSERT INTO control.audit_actions (action, description) VALUES
  ('platform.login_device_issued', 'A device token (rate-limit scope only) was issued at sign-in');

GRANT CREATE ON SCHEMA control TO control_auth;
SET ROLE control_auth;

CREATE TABLE control.login_devices (
  id           uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  token_hash   bytea NOT NULL UNIQUE CHECK (length(token_hash) = 32),
  identity_id  uuid NOT NULL REFERENCES control.platform_identities(id),
  created_at   timestamptz NOT NULL DEFAULT clock_timestamp(),
  last_used_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at   timestamptz NOT NULL,
  revoked_at   timestamptz
);
CREATE INDEX login_devices_identity ON control.login_devices (identity_id) WHERE revoked_at IS NULL;
ALTER TABLE control.login_devices ENABLE ROW LEVEL SECURITY;
CREATE INDEX webauthn_challenges_login_open ON control.webauthn_challenges (expires_at) WHERE purpose = 'login' AND used_at IS NULL;

-- A device counts only while unexpired, unrevoked and its identity is active.
CREATE FUNCTION control.login_device_resolve(p_token text) RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = control, pg_temp AS $$
  SELECT d.id FROM control.login_devices d JOIN control.platform_identities i ON i.id = d.identity_id
   WHERE p_token ~ '^[0-9a-f]{64}$' AND d.token_hash = control.sha(p_token) AND d.revoked_at IS NULL
     AND d.expires_at > clock_timestamp() AND i.state = 'active'
$$;

RESET ROLE;
REVOKE CREATE ON SCHEMA control FROM control_auth;

DROP FUNCTION control.api_login_begin();
DROP FUNCTION control.api_login_complete(text, bytea, bytea, bytea);

GRANT CREATE ON SCHEMA control TO control_auth;
SET ROLE control_auth;

CREATE FUNCTION control.api_login_begin(p_device_token text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE v_device uuid; v_scope text; v_ok boolean; v_open integer;
BEGIN
  PERFORM control.assert_fresh_transaction();
  -- bounded purge of long-expired login challenges keeps the table (and the ceiling count) small
  DELETE FROM control.webauthn_challenges WHERE ctid IN (
    SELECT ctid FROM control.webauthn_challenges WHERE purpose = 'login' AND expires_at < clock_timestamp() - interval '1 hour' LIMIT 200);
  SELECT count(*) INTO v_open FROM control.webauthn_challenges
   WHERE purpose = 'login' AND used_at IS NULL AND expires_at > clock_timestamp();
  v_device := control.login_device_resolve(p_device_token);
  IF v_device IS NOT NULL THEN
    v_scope := 'device';
    v_ok := control.rate_limit_hit('login_device', v_device::text, control.setting_int('login_device_limit'));
    UPDATE control.login_devices SET last_used_at = clock_timestamp() WHERE id = v_device;
  ELSE
    v_scope := 'anonymous';
    v_ok := control.rate_limit_hit('login', 'global', control.setting_int('login_global_limit'));
  END IF;
  IF NOT v_ok OR v_open >= control.setting_int('login_challenge_ceiling') THEN
    PERFORM control.audit_failure_limited('login', 'platform.rate_limited', 'RATE_LIMITED',
      jsonb_build_object('scope', v_scope, 'ceiling', v_open >= control.setting_int('login_challenge_ceiling')));
    RETURN control.err('RATE_LIMITED');
  END IF;
  RETURN jsonb_build_object('ok', true, 'scope', v_scope, 'challenge', control.challenge_issue('login', NULL, NULL, NULL, NULL));
END
$$;

-- As 208, plus: on success issue a device token for this identity unless the presented one already belongs to it.
CREATE FUNCTION control.api_login_complete(p_credential_id text, p_client_data bytea, p_authenticator_data bytea,
                                           p_signature bytea, p_device_token text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE a record; v_err text; i control.platform_identities; v_token text; v_abs timestamptz; v_device uuid; v_dev_token text;
BEGIN
  IF NOT control.rate_limit_hit('login_credential', coalesce(left(p_credential_id, 64), '-'),
                                control.setting_int('login_credential_limit')) THEN
    v_err := 'RATE_LIMITED';
  ELSE
    a := control.wa_assertion('login', p_credential_id, p_client_data, p_authenticator_data, p_signature, NULL);
    v_err := a.err;
  END IF;
  IF v_err IS NOT NULL THEN
    IF v_err <> 'COUNTER_REGRESSION' THEN
      PERFORM control.audit_failure_limited('login', 'platform.login_failed', v_err,
        jsonb_build_object('claimed_credential', left(regexp_replace(coalesce(p_credential_id, ''), '[^A-Za-z0-9_-]', '', 'g'), 8)));
    END IF;
    RETURN control.err(v_err);
  END IF;
  SELECT * INTO i FROM control.platform_identities WHERE id = a.identity_id;
  v_token := control.new_secret();
  v_abs := now() + make_interval(secs => control.setting_int('session_absolute_seconds'));
  INSERT INTO control.sessions (id_hash, identity_id, credential_id, absolute_expires_at)
  VALUES (control.sha(v_token), i.id, p_credential_id, v_abs);
  SELECT d.id INTO v_device FROM control.login_devices d
   WHERE d.id = control.login_device_resolve(p_device_token) AND d.identity_id = i.id;
  IF v_device IS NULL THEN
    v_dev_token := control.new_secret();
    INSERT INTO control.login_devices (token_hash, identity_id, expires_at)
    VALUES (control.sha(v_dev_token), i.id, clock_timestamp() + make_interval(secs => control.setting_int('login_device_ttl_seconds')));
  END IF;
  PERFORM control.audit_append('platform_identity', i.id, i.display_name, 'platform.login_succeeded', 'success',
    'session', encode(substring(control.sha(v_token) FROM 1 FOR 8), 'hex'), NULL, NULL,
    jsonb_build_object('credential', left(p_credential_id, 8), 'new_device', v_device IS NULL));
  RETURN jsonb_build_object('ok', true, 'session_token', v_token, 'absolute_expires_at', v_abs,
                            'idle_seconds', control.setting_int('session_idle_seconds'),
                            'device_token', v_dev_token,
                            'device_ttl_seconds', control.setting_int('login_device_ttl_seconds'));
END
$$;

RESET ROLE;
REVOKE CREATE ON SCHEMA control FROM control_auth;

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA control FROM PUBLIC;
GRANT EXECUTE ON FUNCTION control.api_login_begin(text), control.api_login_complete(text, bytea, bytea, bytea, text) TO control_app;
