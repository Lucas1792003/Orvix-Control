-- ============================================================
-- 208: fixes from the re-verification round (docs/REVIEW_C1_1.md, round 2)
--
-- MED  NEW-1 (audit): a number in an audit row's detail that JavaScript cannot represent exactly (e.g. an export
--            range beyond 2^53) made every later offline verification and anchor signing fail. audit_append now
--            stores any non-integer or out-of-range number in `detail` as a STRING; api_audit_export clamps its
--            range to the current head.
-- MED  N1 (recovery): the SUBJECT_ACTIVE guard and the subject's own cancel were a VETO, so a thief holding the
--            subject's passkey could block recovery forever. Now they are a DELAY: a contested request (subject
--            objected, or a non-flagged passkey of the subject was used after the request) can still be approved
--            by a different owner after recovery_contest_delay_seconds AND an explicit host confirmation. Activity
--            by a FLAGGED passkey (possible clone) never counts. New host-only emergency action:
--            host_revoke_operator_credentials (disables every passkey/session of one operator; grants nothing).
-- LOW  api_login_complete no longer attributes pre-signature failures to the claimed operator; those rows are
--            anonymous and rate-limited per purpose, with one "suppressed" summary row per window.
-- LOW  api_enrol_complete applies the invalid-token rate limit before writing any audit row.
-- LOW  pg_sleep revoked from PUBLIC. (An "explicit transaction" guard was tried and rejected: under the extended
--            query protocol statement_timestamp() differs from transaction_timestamp() even in autocommit, so it
--            refused legitimate calls. Holding row locks via an open transaction and rollback suppression stay
--            documented residuals; both need the control_app password.)
-- LOW  cancel vs redemption deadlock: cancellation locks tokens before the request (same order as redemption).
-- LOW  host_purge_expired (host-only) removes expired challenges, old rate-limit windows and used grants.
-- LOW  control_schema_owner attributes asserted.
-- ROLLBACK Restore from the pre-208 recovery point.
-- ============================================================

DO $chk$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'control_schema_owner'
              AND (rolsuper OR rolbypassrls OR rolcreaterole OR rolcreatedb OR rolreplication OR rolcanlogin))
     OR EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles a ON a.oid = m.roleid OR a.oid = m.member
                 WHERE a.rolname = 'control_schema_owner') THEN
    RAISE EXCEPTION 'control_schema_owner has unexpected attributes or memberships';
  END IF;
END
$chk$;

REVOKE EXECUTE ON FUNCTION pg_catalog.pg_sleep(double precision), pg_catalog.pg_sleep_for(interval),
  pg_catalog.pg_sleep_until(timestamptz) FROM PUBLIC;

INSERT INTO control.settings (key, value) VALUES
  ('recovery_contest_delay_seconds', '43200'),   -- 12 h (requests live 24 h)
  ('failure_audit_limit',            '60');

INSERT INTO control.audit_actions (action, description) VALUES
  ('platform.recovery_contested',               'Subject objected to a recovery request (delay + host confirmation now required)'),
  ('platform.recovery_host_confirmed',          'Host confirmed a contested recovery request'),
  ('platform.operator_credentials_revoked',     'Host emergency action: every passkey and session of an operator disabled'),
  ('platform.audit_suppressed',                 'Failure rows beyond the per-window limit were not written (counter only)'),
  ('platform.maintenance',                      'Host maintenance (purge of expired rows)');

ALTER TABLE control.recovery_requests ADD COLUMN contested_at timestamptz, ADD COLUMN host_confirmed_at timestamptz;

-- ------------------------------------------------------------ audit: numbers that cannot round-trip become strings
SET ROLE control_schema_owner;
CREATE FUNCTION control.audit_safe_detail(j jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE r jsonb; k text; v jsonb; n numeric;
BEGIN
  IF j IS NULL THEN RETURN '{}'::jsonb; END IF;
  CASE jsonb_typeof(j)
    WHEN 'object' THEN
      r := '{}'::jsonb;
      FOR k, v IN SELECT * FROM jsonb_each(j) LOOP r := r || jsonb_build_object(k, control.audit_safe_detail(v)); END LOOP;
      RETURN r;
    WHEN 'array' THEN
      RETURN coalesce((SELECT jsonb_agg(control.audit_safe_detail(e) ORDER BY o) FROM jsonb_array_elements(j) WITH ORDINALITY AS t(e, o)), '[]'::jsonb);
    WHEN 'number' THEN
      n := (j #>> '{}')::numeric;
      IF n = trunc(n) AND abs(n) <= 9007199254740991 AND (j #>> '{}') = trunc(n)::text THEN RETURN j; END IF;
      RETURN to_jsonb(j #>> '{}');
    ELSE RETURN j;
  END CASE;
END
$$;
RESET ROLE;
REVOKE EXECUTE ON FUNCTION control.audit_safe_detail(jsonb) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION control.audit_safe_detail(jsonb) TO control_audit_owner;

CREATE OR REPLACE FUNCTION control.audit_append(
  p_actor_type text, p_actor_id uuid, p_actor_label text, p_action text, p_outcome text,
  p_target_type text DEFAULT NULL, p_target_id text DEFAULT NULL, p_request_id uuid DEFAULT NULL,
  p_reason_code text DEFAULT NULL, p_detail jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE v_prev_seq bigint; v_prev_hash bytea; v_seq bigint; v_at timestamptz := date_trunc('microseconds', clock_timestamp());
        v_hash bytea; v_detail jsonb := control.audit_safe_detail(p_detail);
BEGIN
  PERFORM 1 FROM control.audit_lock FOR UPDATE;
  SELECT seq, row_hash INTO v_prev_seq, v_prev_hash FROM control.audit_events ORDER BY seq DESC LIMIT 1;
  IF v_prev_seq IS NULL THEN RAISE EXCEPTION 'AUDIT_NO_GENESIS'; END IF;
  v_seq := v_prev_seq + 1;
  v_hash := control.audit_row_hash(v_prev_hash, control.audit_canonical(v_seq, v_at, p_actor_type, p_actor_id, p_actor_label,
            p_action, p_outcome, p_target_type, p_target_id, p_request_id, p_reason_code, v_detail));
  PERFORM set_config('control.audit_writer', 'on', true);
  INSERT INTO control.audit_events (seq, occurred_at, actor_type, actor_id, actor_label, action, outcome,
                                    target_type, target_id, request_id, reason_code, detail, prev_hash, row_hash)
  VALUES (v_seq, v_at, p_actor_type, p_actor_id, p_actor_label, p_action, p_outcome, p_target_type, p_target_id,
          p_request_id, p_reason_code, v_detail, v_prev_hash, v_hash);
  PERFORM set_config('control.audit_writer', '', true);
  RETURN v_seq;
END
$$;

-- ------------------------------------------------------------ rate-limited failure auditing (auth owner)
-- Writes the failure row while under the per-purpose limit; exactly one 'audit_suppressed' row when it is first
-- exceeded in a window; nothing after that (the counter keeps counting).
CREATE FUNCTION control.audit_failure_limited(p_purpose text, p_action text, p_reason text, p_detail jsonb) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE v_limit integer := control.setting_int('failure_audit_limit'); v_window integer := control.setting_int('rate_window_seconds');
        v_hits integer;
BEGIN
  IF control.rate_limit_hit('failure_audit', p_purpose, v_limit) THEN
    PERFORM control.audit_append('anonymous', NULL, NULL, p_action, 'denied', 'challenge', p_purpose, NULL, p_reason, p_detail);
  ELSE
    SELECT hits INTO v_hits FROM control.rate_limits
     WHERE bucket = 'failure_audit' AND key = p_purpose
       AND window_start = to_timestamp(floor(extract(epoch FROM now()) / v_window) * v_window);
    IF v_hits = v_limit + 1 THEN
      PERFORM control.audit_append('system', NULL, 'rate-limiter', 'platform.audit_suppressed', 'denied', 'challenge', p_purpose,
        NULL, 'AUDIT_SUPPRESSED', jsonb_build_object('limit', v_limit, 'window_seconds', v_window));
    END IF;
  END IF;
END
$$;
ALTER FUNCTION control.audit_failure_limited(text, text, text, jsonb) OWNER TO control_auth;

CREATE OR REPLACE FUNCTION control.api_auth_failed(p_purpose text, p_challenge text, p_credential_id text, p_reason text)
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
BEGIN
  IF p_purpose NOT IN ('login', 'stepup', 'register', 'register_add', 'anchor') THEN RETURN control.err('INVALID_INPUT'); END IF;
  UPDATE control.webauthn_challenges SET used_at = now()
   WHERE p_challenge ~ '^[A-Za-z0-9_-]{32,128}$' AND challenge_hash = control.sha(p_challenge) AND used_at IS NULL;
  IF FOUND THEN
    PERFORM control.audit_failure_limited(p_purpose,
      CASE p_purpose WHEN 'login' THEN 'platform.login_failed' WHEN 'stepup' THEN 'platform.stepup_failed'
                     WHEN 'register_add' THEN 'platform.credential_add_failed' WHEN 'anchor' THEN 'audit.anchor_refused'
                     ELSE 'platform.enrol_failed' END,
      left(regexp_replace(coalesce(p_reason, 'VERIFICATION_FAILED'), '[^A-Z_]', '', 'g'), 40),
      jsonb_build_object('claimed_credential', left(regexp_replace(coalesce(p_credential_id, ''), '[^A-Za-z0-9_-]', '', 'g'), 8),
                         'precheck', 'app'));
  END IF;
  RETURN jsonb_build_object('ok', true);
END
$$;

-- Failures BEFORE a valid signature are anonymous + rate-limited; only signature-verified outcomes
-- (COUNTER_REGRESSION, written inside wa_assertion) name the operator.
CREATE OR REPLACE FUNCTION control.api_login_complete(p_credential_id text, p_client_data bytea, p_authenticator_data bytea,
                                                      p_signature bytea) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE a record; v_err text; i control.platform_identities; v_token text; v_abs timestamptz;
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
  PERFORM control.audit_append('platform_identity', i.id, i.display_name, 'platform.login_succeeded', 'success',
    'session', encode(substring(control.sha(v_token) FROM 1 FOR 8), 'hex'), NULL, NULL,
    jsonb_build_object('credential', left(p_credential_id, 8)));
  RETURN jsonb_build_object('ok', true, 'session_token', v_token, 'absolute_expires_at', v_abs,
                            'idle_seconds', control.setting_int('session_idle_seconds'));
END
$$;

-- Invalid token: rate-limited before any audit row; otherwise as 207. Lock order: bootstrap row, token, identity, request.
CREATE OR REPLACE FUNCTION control.api_enrol_complete(p_token text, p_attestation bytea, p_client_data bytea, p_nickname text)
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE t control.enrolment_tokens; i control.platform_identities; r control.recovery_requests; reg record;
        v_cred uuid; v_disabled integer; v_sessions integer;
BEGIN
  SELECT * INTO t FROM control.enrolment_tokens WHERE p_token ~ '^[0-9a-f]{64}$' AND token_hash = control.sha(p_token);
  IF t.token_hash IS NULL OR t.used_at IS NOT NULL OR t.expires_at <= now() THEN
    IF control.rate_limit_hit('enrol_invalid', 'global', control.setting_int('enrol_invalid_limit')) THEN
      PERFORM control.audit_append('anonymous', NULL, NULL, 'platform.enrol_failed', 'denied', NULL, NULL, NULL, 'INVALID_TOKEN', '{}'::jsonb);
    END IF;
    RETURN control.err('INVALID_TOKEN');
  END IF;
  PERFORM 1 FROM control.bootstrap_state FOR UPDATE;
  SELECT * INTO t FROM control.enrolment_tokens WHERE token_hash = t.token_hash FOR UPDATE;
  SELECT * INTO i FROM control.platform_identities WHERE id = t.identity_id FOR NO KEY UPDATE;
  IF t.recovery_request_id IS NOT NULL THEN
    SELECT * INTO r FROM control.recovery_requests WHERE id = t.recovery_request_id FOR UPDATE;
  END IF;
  reg := control.wa_registration('register', p_attestation, p_client_data);
  IF t.used_at IS NOT NULL OR t.expires_at <= now()
     OR (t.purpose = 'recovery' AND (r.state IS DISTINCT FROM 'approved' OR r.expires_at <= now())) THEN
    reg.err := 'INVALID_TOKEN';
  ELSIF reg.err IS NULL AND ((reg.ch).identity_id IS DISTINCT FROM t.identity_id
                             OR (reg.ch).action IS DISTINCT FROM 'enrol'
                             OR (reg.ch).target IS DISTINCT FROM encode(t.token_hash, 'hex')) THEN
    reg.err := 'INVALID_CHALLENGE';
  ELSIF reg.err IS NULL AND ((t.purpose = 'owner_bootstrap' AND i.state <> 'enrolling')
                             OR (t.purpose = 'recovery' AND i.state <> 'active')) THEN
    reg.err := 'INVALID_TOKEN';
  END IF;
  IF reg.err IS NULL AND t.purpose = 'recovery' THEN
    UPDATE control.sessions SET revoked_at = now(), revoke_reason = 'recovery' WHERE identity_id = i.id AND revoked_at IS NULL;
    GET DIAGNOSTICS v_sessions = ROW_COUNT;
    UPDATE control.webauthn_credentials SET disabled_at = now(), disabled_reason = 'recovered'
     WHERE identity_id = i.id AND disabled_at IS NULL;
    GET DIAGNOSTICS v_disabled = ROW_COUNT;
  END IF;
  IF reg.err IS NULL THEN
    BEGIN
      INSERT INTO control.webauthn_credentials (identity_id, credential_id, public_key, sign_count, nickname, created_via)
      VALUES (i.id, reg.cred_id, reg.cose, reg.sign_count, nullif(left(btrim(coalesce(p_nickname, '')), 60), ''),
              CASE t.purpose WHEN 'recovery' THEN 'recovery' ELSE 'bootstrap' END)
      RETURNING id INTO v_cred;
    EXCEPTION WHEN unique_violation OR check_violation THEN
      reg.err := 'INVALID_CREDENTIAL';
    END;
  END IF;
  IF reg.err IS NOT NULL THEN
    IF v_disabled IS NOT NULL THEN RAISE EXCEPTION 'RECOVERY_ENROL_FAILED'; END IF;
    PERFORM control.audit_failure_limited('register', 'platform.enrol_failed', reg.err, '{}'::jsonb);
    RETURN control.err(reg.err);
  END IF;
  UPDATE control.enrolment_tokens SET used_at = now() WHERE token_hash = t.token_hash;
  IF t.purpose = 'owner_bootstrap' THEN
    UPDATE control.platform_identities SET state = 'active', activated_at = now() WHERE id = i.id;
    UPDATE control.bootstrap_state SET closed = true, closed_at = now();
    PERFORM control.audit_append('platform_identity', i.id, i.display_name, 'platform.owner_enrolled', 'success',
      'credential', v_cred::text, NULL, NULL, '{}'::jsonb);
  ELSE
    UPDATE control.recovery_requests SET state = 'redeemed', redeemed_at = now() WHERE id = r.id;
    PERFORM control.audit_append('platform_identity', i.id, i.display_name, 'platform.recovery_completed', 'success',
      'recovery_request', r.id::text, NULL, NULL,
      jsonb_build_object('credentials_disabled', v_disabled, 'sessions_revoked', v_sessions, 'new_credential', v_cred));
  END IF;
  RETURN jsonb_build_object('ok', true, 'credential', v_cred);
END
$$;

-- ------------------------------------------------------------ recovery: delay instead of veto
-- Lock order for cancellation = redemption order: tokens, then the request.
CREATE OR REPLACE FUNCTION control.recovery_cancel_internal(p_request uuid, p_by text) RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE n integer;
BEGIN
  PERFORM 1 FROM control.enrolment_tokens WHERE recovery_request_id = p_request FOR UPDATE;
  UPDATE control.recovery_requests SET state = 'cancelled', cancelled_at = now(), cancelled_by = p_by
   WHERE id = p_request AND state IN ('pending', 'approved');
  GET DIAGNOSTICS n = ROW_COUNT;
  UPDATE control.enrolment_tokens SET used_at = now() WHERE recovery_request_id = p_request AND used_at IS NULL;
  RETURN n;
END
$$;

-- The SUBJECT contests (cannot cancel); another owner cancels (final). Tokens are locked before the request.
CREATE OR REPLACE FUNCTION control.api_recovery_cancel(p_token text, p_request uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token); r control.recovery_requests; v_code text;
BEGIN
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  PERFORM 1 FROM control.enrolment_tokens WHERE recovery_request_id = p_request FOR UPDATE;
  SELECT * INTO r FROM control.recovery_requests WHERE id = p_request FOR UPDATE;
  IF r.id IS NULL OR r.state NOT IN ('pending', 'approved') THEN v_code := 'NOT_FOUND';
  ELSIF r.subject_id <> c.identity_id AND c.role <> 'owner' THEN v_code := 'FORBIDDEN';
  ELSIF NOT control.stepup_consume_token(p_token, 'recovery_cancel', r.id::text) THEN v_code := 'STEPUP_REQUIRED';
  END IF;
  IF v_code IS NOT NULL THEN
    PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'platform.recovery_refused', 'denied',
      'recovery_request', p_request::text, NULL, v_code, '{}'::jsonb);
    RETURN control.err(v_code);
  END IF;
  IF r.subject_id = c.identity_id THEN
    UPDATE control.recovery_requests SET contested_at = coalesce(contested_at, now()) WHERE id = r.id;
    PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'platform.recovery_contested', 'success',
      'recovery_request', r.id::text, NULL, NULL, '{}'::jsonb);
    RETURN jsonb_build_object('ok', true, 'contested', true);
  END IF;
  PERFORM control.recovery_cancel_internal(r.id, c.identity_id::text);
  PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'platform.recovery_cancelled', 'success',
    'recovery_request', r.id::text, NULL, NULL, '{}'::jsonb);
  RETURN jsonb_build_object('ok', true, 'contested', false);
END
$$;

-- Host-only: acknowledge a contested request (after checking out of band that the subject really lost access).
CREATE FUNCTION control.host_recovery_confirm(p_request uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
BEGIN
  UPDATE control.recovery_requests SET host_confirmed_at = now() WHERE id = p_request AND state = 'pending';
  IF NOT FOUND THEN RETURN control.err('NOT_FOUND'); END IF;
  PERFORM control.audit_append('cli', NULL, 'host-recovery', 'platform.recovery_host_confirmed', 'success',
    'recovery_request', p_request::text, NULL, NULL, '{}'::jsonb);
  RETURN jsonb_build_object('ok', true);
END
$$;
ALTER FUNCTION control.host_recovery_confirm(uuid) OWNER TO control_auth;

-- Host-only emergency action: lock a compromised operator out (passkeys, sessions, grants). Grants nothing.
CREATE FUNCTION control.host_revoke_operator_credentials(p_email text, p_reason text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE i control.platform_identities; v_s integer; v_c integer;
BEGIN
  IF p_reason IS NULL OR length(btrim(p_reason)) < 10 THEN RETURN control.err('REASON_REQUIRED'); END IF;
  SELECT * INTO i FROM control.platform_identities WHERE email = lower(btrim(p_email)) FOR NO KEY UPDATE;
  IF i.id IS NULL THEN RETURN control.err('NOT_FOUND'); END IF;
  UPDATE control.sessions SET revoked_at = now(), revoke_reason = 'admin' WHERE identity_id = i.id AND revoked_at IS NULL;
  GET DIAGNOSTICS v_s = ROW_COUNT;
  UPDATE control.webauthn_credentials SET disabled_at = now(), disabled_reason = 'host_revoked' WHERE identity_id = i.id AND disabled_at IS NULL;
  GET DIAGNOSTICS v_c = ROW_COUNT;
  UPDATE control.stepup_grants SET used_at = now() WHERE identity_id = i.id AND used_at IS NULL;
  PERFORM control.audit_append('cli', NULL, 'host-emergency', 'platform.operator_credentials_revoked', 'success',
    'platform_identity', i.id::text, NULL, 'EMERGENCY',
    jsonb_build_object('credentials_disabled', v_c, 'sessions_revoked', v_s, 'reason', left(btrim(p_reason), 200)));
  RETURN jsonb_build_object('ok', true, 'credentials_disabled', v_c, 'sessions_revoked', v_s);
END
$$;
ALTER FUNCTION control.host_revoke_operator_credentials(text, text) OWNER TO control_auth;

CREATE OR REPLACE FUNCTION control.api_recovery_approve(p_token text, p_request uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token); r control.recovery_requests; v_code text; v_tok text;
        v_until timestamptz; v_contested boolean;
BEGIN
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  SELECT * INTO r FROM control.recovery_requests WHERE id = p_request FOR UPDATE;
  -- contested = the subject objected, or a NON-FLAGGED passkey of the subject was used after the request
  v_contested := r.contested_at IS NOT NULL OR EXISTS (
    SELECT 1 FROM control.webauthn_credentials
     WHERE identity_id = r.subject_id AND last_used_at > r.requested_at AND counter_suspect_at IS NULL AND disabled_at IS NULL);
  IF c.role <> 'owner' THEN v_code := 'FORBIDDEN';
  ELSIF r.id IS NULL OR r.state <> 'pending' OR r.expires_at <= now() THEN v_code := 'NOT_FOUND';
  ELSIF r.subject_id = c.identity_id THEN v_code := 'SELF_APPROVAL_FORBIDDEN';
  ELSIF NOT EXISTS (SELECT 1 FROM control.platform_identities WHERE id = r.subject_id AND state = 'active') THEN v_code := 'NOT_FOUND';
  ELSIF v_contested AND (r.host_confirmed_at IS NULL
        OR now() < r.requested_at + make_interval(secs => control.setting_int('recovery_contest_delay_seconds'))) THEN
    v_code := 'RECOVERY_CONTESTED';
  ELSIF NOT control.stepup_consume_token(p_token, 'recovery_approve', r.id::text) THEN v_code := 'STEPUP_REQUIRED';
  END IF;
  IF v_code IS NOT NULL THEN
    PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'platform.recovery_refused', 'denied',
      'recovery_request', p_request::text, NULL, v_code, jsonb_build_object('contested', v_contested));
    RETURN control.err(v_code);
  END IF;
  v_tok := control.new_secret();
  v_until := now() + make_interval(secs => control.setting_int('recovery_token_ttl_seconds'));
  INSERT INTO control.enrolment_tokens (token_hash, identity_id, purpose, expires_at, recovery_request_id)
  VALUES (control.sha(v_tok), r.subject_id, 'recovery', v_until, r.id);
  UPDATE control.recovery_requests SET state = 'approved', approved_by = c.identity_id, approved_at = now(), expires_at = v_until
   WHERE id = r.id;
  PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'platform.recovery_approved', 'success',
    'recovery_request', r.id::text, NULL, NULL, jsonb_build_object('subject', r.subject_id, 'contested', v_contested));
  RETURN jsonb_build_object('ok', true, 'enrolment_token', v_tok, 'expires_in_seconds', control.setting_int('recovery_token_ttl_seconds'));
END
$$;

CREATE OR REPLACE FUNCTION control.api_recovery_list(p_token text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token);
BEGIN
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  RETURN jsonb_build_object('ok', true, 'requests',
    (SELECT coalesce(jsonb_agg(jsonb_build_object('id', r.id, 'subject_display_name', i.display_name, 'subject_email', i.email,
        'subject_id', i.id, 'subject_is_you', r.subject_id = c.identity_id, 'reason', r.reason, 'state', r.state,
        'requested_at', r.requested_at, 'expires_at', r.expires_at, 'contested_at', r.contested_at,
        'host_confirmed_at', r.host_confirmed_at) ORDER BY r.requested_at DESC), '[]'::jsonb)
       FROM control.recovery_requests r JOIN control.platform_identities i ON i.id = r.subject_id
      WHERE r.state IN ('pending', 'approved') AND r.expires_at > now()
        AND (c.role = 'owner' OR r.subject_id = c.identity_id)));
END
$$;

-- ------------------------------------------------------------ export range clamp
CREATE OR REPLACE FUNCTION control.api_audit_export(p_token text, p_from bigint, p_to bigint) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token); v_denied jsonb; v_from bigint; v_to bigint; v_out jsonb; v_head bigint;
BEGIN
  v_denied := control.authorize(c, '{owner}', false, 'audit_export', NULL);
  IF v_denied IS NOT NULL THEN RETURN v_denied; END IF;
  SELECT max(seq) INTO v_head FROM control.audit_events;
  v_from := least(greatest(coalesce(p_from, 0), 0), v_head);
  v_to := least(coalesce(p_to, v_from + 4999), v_from + 4999, v_head);
  IF v_to < v_from THEN v_to := v_from; END IF;
  SELECT coalesce(jsonb_agg(jsonb_build_object(
      'seq', e.seq, 'occurred_at_us', (extract(epoch FROM e.occurred_at) * 1000000)::bigint, 'actor_type', e.actor_type,
      'actor_id', e.actor_id, 'actor_label', e.actor_label, 'action', e.action, 'outcome', e.outcome,
      'target_type', e.target_type, 'target_id', e.target_id, 'request_id', e.request_id, 'reason_code', e.reason_code,
      'detail', e.detail, 'prev_hash', encode(e.prev_hash, 'hex'), 'row_hash', encode(e.row_hash, 'hex'),
      'canonical', control.audit_canonical(e.seq, e.occurred_at, e.actor_type, e.actor_id, e.actor_label, e.action,
                                           e.outcome, e.target_type, e.target_id, e.request_id, e.reason_code, e.detail))
      ORDER BY e.seq), '[]'::jsonb)
    INTO v_out FROM control.audit_events e WHERE e.seq BETWEEN v_from AND v_to;
  PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'audit.exported', 'success',
    'audit', NULL, NULL, NULL, jsonb_build_object('kind', 'events', 'from', v_from, 'to', v_to, 'rows', jsonb_array_length(v_out)));
  RETURN jsonb_build_object('ok', true, 'format', 'orvix-control/audit-events/v1', 'from', v_from, 'to', v_to, 'events', v_out);
END
$$;

-- ------------------------------------------------------------ host-only maintenance
CREATE FUNCTION control.host_purge_expired() RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE a integer; b integer; g integer;
BEGIN
  DELETE FROM control.webauthn_challenges WHERE expires_at < now() - interval '1 day';
  GET DIAGNOSTICS a = ROW_COUNT;
  DELETE FROM control.rate_limits WHERE window_start < now() - interval '1 day';
  GET DIAGNOSTICS b = ROW_COUNT;
  DELETE FROM control.stepup_grants WHERE (used_at IS NOT NULL OR expires_at < now()) AND created_at < now() - interval '1 day';
  GET DIAGNOSTICS g = ROW_COUNT;
  PERFORM control.audit_append('cli', NULL, 'host-maintenance', 'platform.maintenance', 'success', NULL, NULL, NULL, NULL,
    jsonb_build_object('challenges', a, 'rate_limits', b, 'grants', g));
  RETURN jsonb_build_object('ok', true, 'challenges', a, 'rate_limits', b, 'grants', g);
END
$$;
ALTER FUNCTION control.host_purge_expired() OWNER TO control_auth;

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA control FROM PUBLIC;
GRANT EXECUTE ON FUNCTION control.audit_safe_detail(jsonb) TO control_audit_owner;
-- host_recovery_confirm, host_revoke_operator_credentials, host_purge_expired: no grants (superuser only).
