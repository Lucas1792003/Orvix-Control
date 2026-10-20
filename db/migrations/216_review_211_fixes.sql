-- ============================================================
-- 216: fixes from the independent review of migration 211 (docs/REVIEW_C1_2.md)
--
-- LOW  Passkey ACTIVITY was not inherited by a re-filed request (objections were, since 211): a subject who signed in
--      during request R made R contested, but a re-filed R2 started uncontested. Activity now counts from the
--      earliest request for that subject within recovery_max_lifetime_seconds.
-- INFO The LAST_OWNER guard in host_revoke_operator_credentials relies on READ COMMITTED (under REPEATABLE READ a
--      second concurrent revoke could pass on a stale snapshot). The host functions that guard owner counts now refuse
--      to run at any other isolation level.
-- ============================================================

CREATE OR REPLACE FUNCTION control.assert_read_committed() RETURNS void
LANGUAGE plpgsql VOLATILE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF current_setting('transaction_isolation') <> 'read committed' THEN
    RAISE EXCEPTION 'READ_COMMITTED_REQUIRED' USING ERRCODE = 'invalid_transaction_state';
  END IF;
END
$$;
ALTER FUNCTION control.assert_read_committed() OWNER TO control_schema_owner;
REVOKE EXECUTE ON FUNCTION control.assert_read_committed() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION control.assert_read_committed() TO control_auth;

-- As 211 + isolation assertion.
CREATE OR REPLACE FUNCTION control.host_revoke_operator_credentials(p_email text, p_reason text, p_force boolean DEFAULT false) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE i control.platform_identities; v_s integer; v_c integer; x record;
BEGIN
  PERFORM control.assert_read_committed();
  IF p_reason IS NULL OR length(btrim(p_reason)) < 10 THEN RETURN control.err('REASON_REQUIRED'); END IF;
  PERFORM 1 FROM control.bootstrap_state FOR UPDATE;
  SELECT * INTO i FROM control.platform_identities WHERE email = lower(btrim(p_email)) FOR NO KEY UPDATE;
  IF i.id IS NULL THEN RETURN control.err('NOT_FOUND'); END IF;
  IF i.role = 'owner' AND NOT coalesce(p_force, false) AND NOT EXISTS (
       SELECT 1 FROM control.platform_identities o JOIN control.webauthn_credentials w ON w.identity_id = o.id
        WHERE o.id <> i.id AND o.role = 'owner' AND o.state = 'active' AND control.credential_usable(w.id)) THEN
    RETURN control.err('LAST_OWNER');
  END IF;
  UPDATE control.platform_identities SET emergency_revoked_at = clock_timestamp() WHERE id = i.id;
  UPDATE control.sessions SET revoked_at = now(), revoke_reason = 'admin' WHERE identity_id = i.id AND revoked_at IS NULL;
  GET DIAGNOSTICS v_s = ROW_COUNT;
  UPDATE control.webauthn_credentials SET disabled_at = now(), disabled_reason = 'host_revoked' WHERE identity_id = i.id AND disabled_at IS NULL;
  GET DIAGNOSTICS v_c = ROW_COUNT;
  UPDATE control.stepup_grants SET used_at = now() WHERE identity_id = i.id AND used_at IS NULL;
  UPDATE control.login_devices SET revoked_at = clock_timestamp() WHERE identity_id = i.id AND revoked_at IS NULL;
  FOR x IN SELECT id FROM control.recovery_requests WHERE subject_id = i.id AND state IN ('pending', 'approved') LOOP
    PERFORM control.recovery_reopen_contested(x.id, false);
  END LOOP;
  PERFORM control.audit_append('cli', NULL, 'host-emergency', 'platform.operator_credentials_revoked', 'success',
    'platform_identity', i.id::text, NULL, 'EMERGENCY',
    jsonb_build_object('credentials_disabled', v_c, 'sessions_revoked', v_s, 'forced', coalesce(p_force, false),
                       'reason', left(btrim(p_reason), 200)));
  RETURN jsonb_build_object('ok', true, 'credentials_disabled', v_c, 'sessions_revoked', v_s);
END
$$;

-- As 210 + activity measured from the earliest request for the subject within the maximum lifetime.
CREATE OR REPLACE FUNCTION control.api_recovery_approve(p_token text, p_request uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token); r control.recovery_requests; v_code text; v_tok text;
        v_until timestamptz; v_contested boolean; v_subject control.platform_identities; v_now timestamptz := clock_timestamp();
        v_activity timestamptz; v_confirm_after timestamptz; v_delay_from timestamptz; v_since timestamptz;
BEGIN
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  SELECT * INTO r FROM control.recovery_requests WHERE id = p_request FOR UPDATE;
  SELECT * INTO v_subject FROM control.platform_identities WHERE id = r.subject_id;
  SELECT least(r.requested_at, min(requested_at)) INTO v_since FROM control.recovery_requests
   WHERE subject_id = r.subject_id
     AND requested_at > v_now - make_interval(secs => control.setting_int('recovery_max_lifetime_seconds'));
  SELECT max(last_used_at) INTO v_activity FROM control.webauthn_credentials
   WHERE identity_id = r.subject_id AND last_used_at > v_since AND counter_suspect_at IS NULL AND disabled_at IS NULL;
  v_contested := coalesce(r.contested_at IS NOT NULL OR v_activity IS NOT NULL
    OR v_subject.emergency_revoked_at >= r.requested_at - make_interval(secs => control.setting_int('recovery_request_ttl_seconds')), false);
  v_confirm_after := greatest(r.last_contested_at, v_activity, v_subject.emergency_revoked_at);
  v_delay_from := greatest(r.requested_at, r.contested_at, v_subject.emergency_revoked_at);
  IF c.role <> 'owner' THEN v_code := 'FORBIDDEN';
  ELSIF r.id IS NULL OR r.state <> 'pending' OR r.expires_at <= v_now THEN v_code := 'NOT_FOUND';
  ELSIF r.subject_id = c.identity_id THEN v_code := 'SELF_APPROVAL_FORBIDDEN';
  ELSIF v_subject.state IS DISTINCT FROM 'active' THEN v_code := 'NOT_FOUND';
  ELSIF v_contested AND (r.host_confirmed_at IS NULL
        OR (v_confirm_after IS NOT NULL AND r.host_confirmed_at <= v_confirm_after)
        OR v_now < v_delay_from + make_interval(secs => control.setting_int('recovery_contest_delay_seconds'))) THEN
    v_code := 'RECOVERY_CONTESTED';
  ELSIF NOT control.stepup_consume_token(p_token, 'recovery_approve', r.id::text) THEN v_code := 'STEPUP_REQUIRED';
  END IF;
  IF v_code IS NOT NULL THEN
    PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'platform.recovery_refused', 'denied',
      'recovery_request', p_request::text, NULL, v_code, jsonb_build_object('contested', v_contested));
    RETURN control.err(v_code);
  END IF;
  v_tok := control.new_secret();
  v_until := v_now + make_interval(secs => control.setting_int('recovery_token_ttl_seconds'));
  INSERT INTO control.enrolment_tokens (token_hash, identity_id, purpose, expires_at, recovery_request_id)
  VALUES (control.sha(v_tok), r.subject_id, 'recovery', v_until, r.id);
  UPDATE control.recovery_requests SET state = 'approved', approved_by = c.identity_id, approved_at = v_now, expires_at = v_until
   WHERE id = r.id;
  PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'platform.recovery_approved', 'success',
    'recovery_request', r.id::text, NULL, NULL, jsonb_build_object('subject', r.subject_id, 'contested', v_contested));
  RETURN jsonb_build_object('ok', true, 'enrolment_token', v_tok, 'expires_in_seconds', control.setting_int('recovery_token_ttl_seconds'));
END
$$;

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA control FROM PUBLIC;
GRANT EXECUTE ON FUNCTION control.assert_read_committed() TO control_auth;
