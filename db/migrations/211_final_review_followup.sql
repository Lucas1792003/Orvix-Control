-- ============================================================
-- 211: follow-ups from re-verification of 210 (all LOW / INFO; docs/REVIEW_C1_1.md, final round)
--
-- LOW  Two concurrent revoke-operator calls on the only two owners both passed the LAST_OWNER guard: owner revokes
--      are now serialised on the bootstrap_state row before the check.
-- LOW  A request that simply EXPIRED did not pass its objection on to a re-filed request (inherit window was the
--      24 h request TTL, but an objection extends the request by >= 24 h): the window is now the maximum request
--      lifetime (7 days).
-- INFO recovery_reopen_contested voids tokens again after updating the request (a token created by an approval that
--      raced the reopen can never remain live).
-- INFO wa_assertion records passkey use with clock_timestamp() (same clock as host confirmation).
-- INFO api_enrol_complete re-reads the clock after waiting for its locks.
-- ROLLBACK Restore from the pre-211 recovery point.
-- ============================================================

CREATE OR REPLACE FUNCTION control.host_revoke_operator_credentials(p_email text, p_reason text, p_force boolean DEFAULT false) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE i control.platform_identities; v_s integer; v_c integer; x record;
BEGIN
  IF p_reason IS NULL OR length(btrim(p_reason)) < 10 THEN RETURN control.err('REASON_REQUIRED'); END IF;
  PERFORM 1 FROM control.bootstrap_state FOR UPDATE;          -- serialises every owner-affecting host revoke
  SELECT * INTO i FROM control.platform_identities WHERE email = lower(btrim(p_email)) FOR NO KEY UPDATE;
  IF i.id IS NULL THEN RETURN control.err('NOT_FOUND'); END IF;
  IF i.role = 'owner' AND NOT coalesce(p_force, false) AND NOT EXISTS (
       SELECT 1 FROM control.platform_identities o JOIN control.webauthn_credentials w ON w.identity_id = o.id
        WHERE o.id <> i.id AND o.role = 'owner' AND o.state = 'active' AND w.disabled_at IS NULL
          AND w.usable_after <= clock_timestamp()) THEN
    RETURN control.err('LAST_OWNER');
  END IF;
  UPDATE control.platform_identities SET emergency_revoked_at = clock_timestamp() WHERE id = i.id;
  UPDATE control.sessions SET revoked_at = now(), revoke_reason = 'admin' WHERE identity_id = i.id AND revoked_at IS NULL;
  GET DIAGNOSTICS v_s = ROW_COUNT;
  UPDATE control.webauthn_credentials SET disabled_at = now(), disabled_reason = 'host_revoked' WHERE identity_id = i.id AND disabled_at IS NULL;
  GET DIAGNOSTICS v_c = ROW_COUNT;
  UPDATE control.stepup_grants SET used_at = now() WHERE identity_id = i.id AND used_at IS NULL;
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

CREATE OR REPLACE FUNCTION control.recovery_reopen_contested(p_request uuid, p_by_subject boolean) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE v_now timestamptz := clock_timestamp();
        v_delay interval := make_interval(secs => control.setting_int('recovery_contest_delay_seconds'));
        v_max interval := make_interval(secs => control.setting_int('recovery_max_lifetime_seconds'));
BEGIN
  PERFORM 1 FROM control.enrolment_tokens WHERE recovery_request_id = p_request FOR UPDATE;
  UPDATE control.enrolment_tokens SET used_at = now() WHERE recovery_request_id = p_request AND used_at IS NULL;
  UPDATE control.recovery_requests
     SET state = 'pending', approved_by = NULL, approved_at = NULL, host_confirmed_at = NULL,
         contested_at = CASE WHEN p_by_subject THEN coalesce(contested_at, v_now) ELSE contested_at END,
         last_contested_at = CASE WHEN p_by_subject THEN v_now ELSE last_contested_at END,
         expires_at = least(requested_at + v_max, greatest(expires_at, v_now + v_delay + interval '12 hours'))
   WHERE id = p_request AND state IN ('pending', 'approved');
  -- again, after the request row lock: a token inserted by an approval that committed in between is voided too
  UPDATE control.enrolment_tokens SET used_at = now() WHERE recovery_request_id = p_request AND used_at IS NULL;
END
$$;

CREATE OR REPLACE FUNCTION control.host_recovery_request(p_email text, p_reason text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE i control.platform_identities; v_id uuid; x record; v_prior timestamptz;
        v_ttl interval := make_interval(secs => control.setting_int('recovery_request_ttl_seconds'));
        v_max interval := make_interval(secs => control.setting_int('recovery_max_lifetime_seconds'));
BEGIN
  SELECT * INTO i FROM control.platform_identities WHERE email = lower(btrim(p_email)) AND state = 'active';
  IF i.id IS NULL THEN RETURN control.err('NOT_FOUND'); END IF;
  FOR x IN SELECT id FROM control.recovery_requests WHERE subject_id = i.id AND state IN ('pending', 'approved') AND expires_at <= clock_timestamp() LOOP
    PERFORM control.recovery_cancel_internal(x.id, 'expired');
  END LOOP;
  -- an objection made within the maximum request lifetime is inherited (covers expired AND cancelled requests)
  SELECT max(last_contested_at) INTO v_prior FROM control.recovery_requests
   WHERE subject_id = i.id AND last_contested_at > clock_timestamp() - v_max;
  BEGIN
    INSERT INTO control.recovery_requests (subject_id, reason, expires_at, contested_at, last_contested_at)
    VALUES (i.id, btrim(p_reason), clock_timestamp() + v_ttl, v_prior, v_prior)
    RETURNING id INTO v_id;
  EXCEPTION WHEN unique_violation THEN RETURN control.err('ALREADY_OPEN');
            WHEN check_violation OR not_null_violation THEN RETURN control.err('REASON_REQUIRED');
  END;
  IF v_prior IS NOT NULL THEN PERFORM control.recovery_reopen_contested(v_id, false); END IF;
  PERFORM control.audit_append('cli', NULL, 'host-recovery', 'platform.recovery_requested', 'success',
    'recovery_request', v_id::text, NULL, NULL, jsonb_build_object('subject', i.id, 'inherits_contest', v_prior IS NOT NULL));
  RETURN jsonb_build_object('ok', true, 'request_id', v_id, 'contested', v_prior IS NOT NULL);
END
$$;

-- As 207, with passkey use recorded on the wall clock.
CREATE OR REPLACE FUNCTION control.wa_assertion(p_purpose text, p_cred text, p_cdj bytea, p_ad bytea, p_sig bytea,
                                                p_session_hash bytea,
                                                OUT err text, OUT identity_id uuid, OUT ch control.webauthn_challenges)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE cd jsonb; c control.webauthn_credentials; i control.platform_identities; v_flags integer; v_count bigint;
BEGIN
  cd := control.wa_client_data(p_cdj, 'webauthn.get');
  IF cd IS NULL THEN err := 'BAD_CLIENT_DATA'; RETURN; END IF;
  ch := control.challenge_consume(cd ->> 'challenge', p_purpose);
  IF ch.challenge_hash IS NULL OR ch.session_id_hash IS DISTINCT FROM p_session_hash THEN err := 'INVALID_CHALLENGE'; RETURN; END IF;
  SELECT * INTO c FROM control.webauthn_credentials WHERE credential_id = p_cred FOR UPDATE;
  IF c.id IS NULL OR c.disabled_at IS NOT NULL THEN err := 'UNKNOWN_CREDENTIAL'; RETURN; END IF;
  identity_id := c.identity_id;
  SELECT * INTO i FROM control.platform_identities WHERE id = c.identity_id;
  IF i.state <> 'active' THEN err := 'IDENTITY_INACTIVE'; RETURN; END IF;
  IF ch.identity_id IS NOT NULL AND ch.identity_id <> c.identity_id THEN err := 'CREDENTIAL_IDENTITY_MISMATCH'; RETURN; END IF;
  IF c.usable_after > clock_timestamp() THEN err := 'CREDENTIAL_PENDING'; RETURN; END IF;
  IF p_ad IS NULL OR length(p_ad) < 37 OR length(p_ad) > 1024 THEN err := 'BAD_AUTHENTICATOR_DATA'; RETURN; END IF;
  IF substring(p_ad FROM 1 FOR 32) IS DISTINCT FROM sha256(convert_to(control.setting_text('webauthn_rp_id'), 'UTF8')) THEN
    err := 'RP_ID_MISMATCH'; RETURN;
  END IF;
  v_flags := get_byte(p_ad, 32);
  IF v_flags & 1 = 0 OR v_flags & 4 = 0 THEN err := 'USER_NOT_VERIFIED'; RETURN; END IF;
  IF v_flags & 64 <> 0 OR (v_flags & 128 = 0 AND length(p_ad) <> 37) THEN err := 'BAD_AUTHENTICATOR_DATA'; RETURN; END IF;
  v_count := control.b2n(substring(p_ad FROM 34 FOR 4))::bigint;
  IF NOT control.es256_verify(c.public_key, p_ad || sha256(p_cdj), p_sig) THEN err := 'SIGNATURE_INVALID'; RETURN; END IF;
  IF (c.sign_count > 0 OR v_count > 0) AND v_count <= c.sign_count THEN
    UPDATE control.webauthn_credentials SET counter_suspect_at = clock_timestamp() WHERE id = c.id;
    PERFORM control.audit_append('platform_identity', i.id, i.display_name, 'platform.credential_counter_regression', 'denied',
      'credential', c.id::text, NULL, 'COUNTER_REGRESSION', jsonb_build_object('stored', c.sign_count, 'presented', v_count));
    err := 'COUNTER_REGRESSION'; RETURN;
  END IF;
  UPDATE control.webauthn_credentials SET sign_count = v_count, last_used_at = clock_timestamp() WHERE id = c.id;
END
$$;

-- As 210, re-reading the clock after the locks are held.
CREATE OR REPLACE FUNCTION control.api_enrol_complete(p_token text, p_attestation bytea, p_client_data bytea, p_nickname text)
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE t control.enrolment_tokens; i control.platform_identities; r control.recovery_requests; reg record;
        v_cred uuid; v_disabled integer; v_sessions integer; v_now timestamptz;
BEGIN
  PERFORM control.assert_fresh_transaction();
  v_now := clock_timestamp();
  SELECT * INTO t FROM control.enrolment_tokens WHERE p_token ~ '^[0-9a-f]{64}$' AND token_hash = control.sha(p_token);
  IF t.token_hash IS NULL OR t.used_at IS NOT NULL OR t.expires_at <= v_now THEN
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
  v_now := clock_timestamp();
  reg := control.wa_registration('register', p_attestation, p_client_data);
  IF t.used_at IS NOT NULL OR t.expires_at <= v_now
     OR (t.purpose = 'recovery' AND (r.state IS DISTINCT FROM 'approved' OR r.expires_at <= v_now
                                     OR r.approved_at IS NULL OR r.last_contested_at > r.approved_at
                                     OR i.emergency_revoked_at >= r.approved_at)) THEN
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

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA control FROM PUBLIC;
