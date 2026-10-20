-- ============================================================
-- 209: round-3 re-verification fixes (recovery contest semantics)
--
-- LOW NEW-A  A host confirmation given BEFORE the subject objected pre-authorised overriding that objection.
--            Now: contesting clears any earlier host confirmation, and approval of a contested request needs a
--            confirmation made AFTER the (latest) objection.
-- LOW NEW-B  host_revoke_operator_credentials erased the "subject was active" signal, so the contest delay could be
--            skipped right after an emergency revoke. Now the revoke records platform_identities.emergency_revoked_at
--            and marks every open request of that operator as contested; a request is also contested when the
--            operator was emergency-revoked within the request lifetime before it was filed.
--            Consequence (intended): recovery after an emergency revoke always takes host confirmation + 12 h.
-- ROLLBACK Restore from the pre-209 recovery point.
-- ============================================================

ALTER TABLE control.platform_identities ADD COLUMN emergency_revoked_at timestamptz;

CREATE OR REPLACE FUNCTION control.host_revoke_operator_credentials(p_email text, p_reason text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE i control.platform_identities; v_s integer; v_c integer;
BEGIN
  IF p_reason IS NULL OR length(btrim(p_reason)) < 10 THEN RETURN control.err('REASON_REQUIRED'); END IF;
  SELECT * INTO i FROM control.platform_identities WHERE email = lower(btrim(p_email)) FOR NO KEY UPDATE;
  IF i.id IS NULL THEN RETURN control.err('NOT_FOUND'); END IF;
  UPDATE control.platform_identities SET emergency_revoked_at = now() WHERE id = i.id;
  UPDATE control.sessions SET revoked_at = now(), revoke_reason = 'admin' WHERE identity_id = i.id AND revoked_at IS NULL;
  GET DIAGNOSTICS v_s = ROW_COUNT;
  UPDATE control.webauthn_credentials SET disabled_at = now(), disabled_reason = 'host_revoked' WHERE identity_id = i.id AND disabled_at IS NULL;
  GET DIAGNOSTICS v_c = ROW_COUNT;
  UPDATE control.stepup_grants SET used_at = now() WHERE identity_id = i.id AND used_at IS NULL;
  UPDATE control.recovery_requests SET contested_at = now(), host_confirmed_at = NULL
   WHERE subject_id = i.id AND state = 'pending';
  PERFORM control.audit_append('cli', NULL, 'host-emergency', 'platform.operator_credentials_revoked', 'success',
    'platform_identity', i.id::text, NULL, 'EMERGENCY',
    jsonb_build_object('credentials_disabled', v_c, 'sessions_revoked', v_s, 'reason', left(btrim(p_reason), 200)));
  RETURN jsonb_build_object('ok', true, 'credentials_disabled', v_c, 'sessions_revoked', v_s);
END
$$;

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
    -- every objection resets any earlier host confirmation (NEW-A)
    UPDATE control.recovery_requests SET contested_at = now(), host_confirmed_at = NULL WHERE id = r.id;
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

CREATE OR REPLACE FUNCTION control.api_recovery_approve(p_token text, p_request uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token); r control.recovery_requests; v_code text; v_tok text;
        v_until timestamptz; v_contested boolean; v_subject control.platform_identities;
BEGIN
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  SELECT * INTO r FROM control.recovery_requests WHERE id = p_request FOR UPDATE;
  SELECT * INTO v_subject FROM control.platform_identities WHERE id = r.subject_id;
  -- contested = subject objected; OR a non-flagged, still-active passkey of the subject was used after the request;
  -- OR the subject was emergency-revoked shortly before / after the request (NEW-B)
  v_contested := r.contested_at IS NOT NULL
    OR EXISTS (SELECT 1 FROM control.webauthn_credentials
                WHERE identity_id = r.subject_id AND last_used_at > r.requested_at AND counter_suspect_at IS NULL AND disabled_at IS NULL)
    OR v_subject.emergency_revoked_at >= r.requested_at - make_interval(secs => control.setting_int('recovery_request_ttl_seconds'));
  IF c.role <> 'owner' THEN v_code := 'FORBIDDEN';
  ELSIF r.id IS NULL OR r.state <> 'pending' OR r.expires_at <= now() THEN v_code := 'NOT_FOUND';
  ELSIF r.subject_id = c.identity_id THEN v_code := 'SELF_APPROVAL_FORBIDDEN';
  ELSIF v_subject.state IS DISTINCT FROM 'active' THEN v_code := 'NOT_FOUND';
  ELSIF v_contested AND (r.host_confirmed_at IS NULL
        OR (r.contested_at IS NOT NULL AND r.host_confirmed_at <= r.contested_at)
        OR (v_subject.emergency_revoked_at IS NOT NULL AND r.host_confirmed_at <= v_subject.emergency_revoked_at)
        OR now() < greatest(r.requested_at, coalesce(r.contested_at, r.requested_at), coalesce(v_subject.emergency_revoked_at, r.requested_at))
                   + make_interval(secs => control.setting_int('recovery_contest_delay_seconds'))) THEN
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

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA control FROM PUBLIC;
