-- ============================================================
-- 219 (C1.3, provisional): authentication and recovery hardening. docs/C1_3_DESIGN.md section 2.
--
-- M1   Recovery redemption now undoes what the (possibly stolen) old credential set in motion: open invitations the
--      subject ISSUED are voided, recovery requests the subject APPROVED are reopened (link voided), the subject's
--      step-up grants are voided, and recovered_at is stamped. Host activation refuses an inviter recovered (or
--      suspended) after inviting; redemption refuses a link whose approver was recovered after approving.
-- M2   Every enrolment ceremony (bootstrap, invite, recovery) issues a DEVICE TOKEN to the enrolling browser, so a
--      newly recovered / activated owner's first sign-in uses a private bucket, never the shared anonymous one.
-- LOW  Emergency revoke contests a recovery whenever it happened after the subject's last recovery (no 24 h window).
-- LOW  Passkey activity by the subject after approval makes redemption refuse and reopens the request as contested.
-- LOW  An identity with an open recovery request (as subject) cannot approve, cancel others' requests or invite
--      (IDENTITY_UNDER_RECOVERY). Its own contest still works.
-- LOW  Expired requests cancelled by a new request are audited (recovery_cancelled / EXPIRED).
-- LOW  Host revoke audits each reopened recovery request (recovery_link_voided).
-- LOW  Suspended owners (emergency-revoked after their last recovery) leave the owner notice recipients and are
--      listed as 'suspended'.
-- LOW  A counter regression (possible clone) ends that passkey's sessions and grants; step-up and anchors refuse a
--      flagged passkey (CREDENTIAL_FLAGGED). Sign-in still works (no lockout; recovery via another owner).
-- REVIEW (C1.3) Flagged passkeys do not count as usable for LAST_OWNER / LAST_CREDENTIAL; void helpers lock every
--      affected row BEFORE writing audit rows (no deadlock with cancel/approve); an inviter/approver UNDER recovery cannot
--      have invitations activated or links redeemed; every step-up action except protective ones (revoke a passkey,
--      revoke an invitation, contest one's own recovery) is paused while the identity is under recovery.
-- Lock order unchanged: bootstrap_state -> identity -> sessions -> credentials -> grants; tokens before requests.
-- ============================================================

ALTER TABLE control.platform_identities ADD COLUMN recovered_at timestamptz;
ALTER TABLE control.sessions DROP CONSTRAINT sessions_revoke_reason_check;
ALTER TABLE control.sessions ADD CONSTRAINT sessions_revoke_reason_check
  CHECK (revoke_reason IN ('logout', 'idle_timeout', 'absolute_timeout', 'identity_inactive', 'admin',
                           'credential_revoked', 'recovery', 'upgrade', 'credential_flagged'));

INSERT INTO control.audit_actions (action, description) VALUES
  ('platform.recovery_link_voided', 'A recovery link was voided because its approver was revoked or recovered');

-- notice list (as 212) + recovery_link_voided
GRANT CREATE ON SCHEMA control TO control_audit_owner;
SET ROLE control_audit_owner;
CREATE OR REPLACE FUNCTION control.notify_actions() RETURNS text[]
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT ARRAY[
    'platform.owner_enrolled', 'platform.credential_added', 'platform.credential_revoked',
    'platform.credential_counter_regression', 'platform.recovery_requested', 'platform.recovery_approved',
    'platform.recovery_contested', 'platform.recovery_cancelled', 'platform.recovery_completed',
    'platform.recovery_host_confirmed', 'platform.operator_credentials_revoked', 'platform.audit_suppressed',
    'platform.notify_channel_added', 'platform.notify_channel_disabled',
    'platform.operator_invited', 'platform.operator_enrolled', 'platform.operator_approved',
    'platform.operator_invite_revoked', 'platform.watchdog_terminated', 'platform.recovery_link_voided',
    'platform.watchdog_intent_resolved']::text[]
$$;
RESET ROLE;
REVOKE CREATE ON SCHEMA control FROM control_audit_owner;

GRANT CREATE ON SCHEMA control TO control_auth;
SET ROLE control_auth;

-- Suspended = emergency-revoked after the identity's last successful recovery.
CREATE FUNCTION control.identity_suspended(p_id uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = control, pg_temp AS $$
  SELECT coalesce((SELECT emergency_revoked_at IS NOT NULL AND emergency_revoked_at > coalesce(recovered_at, '-infinity'::timestamptz)
                     FROM control.platform_identities WHERE id = p_id), false)
$$;
-- Under recovery = subject of an open, unexpired recovery request.
CREATE FUNCTION control.identity_under_recovery(p_id uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = control, pg_temp AS $$
  SELECT EXISTS (SELECT 1 FROM control.recovery_requests
                  WHERE subject_id = p_id AND state IN ('pending', 'approved') AND expires_at > clock_timestamp())
$$;

-- Owner notice recipients exclude suspended owners (their channels may sit on the compromised device).
CREATE OR REPLACE FUNCTION control.active_owner_ids() RETURNS uuid[]
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = control, pg_temp AS $$
  SELECT coalesce(array_agg(id), '{}') FROM control.platform_identities
   WHERE role = 'owner' AND state = 'active'
     AND NOT (emergency_revoked_at IS NOT NULL AND emergency_revoked_at > coalesce(recovered_at, '-infinity'::timestamptz))
$$;

-- A device token for an identity (rate-limit scope only). Shared by sign-in and enrolment.
CREATE FUNCTION control.login_device_issue(p_identity uuid) RETURNS text
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE v_tok text := control.new_secret();
BEGIN
  INSERT INTO control.login_devices (token_hash, identity_id, expires_at)
  VALUES (control.sha(v_tok), p_identity, clock_timestamp() + make_interval(secs => control.setting_int('login_device_ttl_seconds')));
  UPDATE control.login_devices SET revoked_at = clock_timestamp()
   WHERE id IN (SELECT id FROM control.login_devices WHERE identity_id = p_identity AND revoked_at IS NULL
                 ORDER BY last_used_at DESC, created_at DESC OFFSET control.setting_int('login_device_max_per_identity'));
  RETURN v_tok;
END
$$;

-- As 212 + flagged passkeys: a regression ends that passkey's sessions and grants; step-up/anchor refuse it.
CREATE OR REPLACE FUNCTION control.wa_assertion(p_purpose text, p_cred text, p_cdj bytea, p_ad bytea, p_sig bytea,
                                                p_session_hash bytea,
                                                OUT err text, OUT identity_id uuid, OUT ch control.webauthn_challenges)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE cd jsonb; c control.webauthn_credentials; i control.platform_identities; v_flags integer; v_count bigint; v_s integer;
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
  IF NOT control.credential_usable(c.id) THEN err := 'CREDENTIAL_PENDING'; RETURN; END IF;
  IF p_purpose <> 'login' AND c.counter_suspect_at IS NOT NULL THEN err := 'CREDENTIAL_FLAGGED'; RETURN; END IF;
  IF p_purpose = 'anchor' AND control.identity_under_recovery(c.identity_id) THEN err := 'IDENTITY_UNDER_RECOVERY'; RETURN; END IF;
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
    -- a clone may already hold sessions or grants from this passkey: end them (the passkey itself stays, flagged)
    UPDATE control.sessions SET revoked_at = now(), revoke_reason = 'credential_flagged'
     WHERE credential_id = c.credential_id AND revoked_at IS NULL;
    GET DIAGNOSTICS v_s = ROW_COUNT;
    UPDATE control.stepup_grants SET used_at = now() WHERE credential_id = c.credential_id AND used_at IS NULL;
    PERFORM control.audit_append('platform_identity', i.id, i.display_name, 'platform.credential_counter_regression', 'denied',
      'credential', c.id::text, NULL, 'COUNTER_REGRESSION',
      jsonb_build_object('stored', c.sign_count, 'presented', v_count, 'sessions_revoked', v_s));
    err := 'COUNTER_REGRESSION'; RETURN;
  END IF;
  UPDATE control.webauthn_credentials SET sign_count = v_count, last_used_at = clock_timestamp() WHERE id = c.id;
END
$$;

-- Protective actions stay available to an identity under recovery: revoking a passkey, revoking an invitation, and
-- contesting (cancelling) its OWN recovery request.
CREATE FUNCTION control.stepup_allowed_under_recovery(p_identity uuid, p_action text, p_target text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = control, pg_temp AS $$
  SELECT p_action = 'credential_revoke'
      OR (p_action = 'operator_invite' AND p_target LIKE 'revoke:%')
      OR (p_action = 'recovery_cancel' AND EXISTS (SELECT 1 FROM control.recovery_requests
                                                    WHERE id::text = p_target AND subject_id = p_identity))
$$;

-- As 210 + the grant's passkey must not be flagged.
CREATE OR REPLACE FUNCTION control.stepup_consume_token(p_token text, p_action text, p_target text) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE v_id bigint;
BEGIN
  PERFORM control.assert_fresh_transaction();
  IF p_token IS NULL OR p_token !~ '^[0-9a-f]{64}$' THEN RETURN false; END IF;
  SELECT g.id INTO v_id FROM control.stepup_grants g
    JOIN control.sessions s ON s.id_hash = g.session_id_hash AND s.revoked_at IS NULL
    JOIN control.webauthn_credentials w ON w.credential_id = g.credential_id AND w.disabled_at IS NULL AND w.counter_suspect_at IS NULL
   WHERE g.session_id_hash = control.sha(p_token) AND g.action = p_action AND g.target = p_target
     AND g.used_at IS NULL AND g.expires_at > clock_timestamp()
     AND (NOT control.identity_under_recovery(s.identity_id) OR control.stepup_allowed_under_recovery(s.identity_id, g.action, g.target))
   ORDER BY g.id LIMIT 1 FOR UPDATE OF g SKIP LOCKED;
  IF v_id IS NULL THEN RETURN false; END IF;
  UPDATE control.stepup_grants SET used_at = now() WHERE id = v_id;
  RETURN true;
END
$$;

-- As 215 + flagged passkeys are not offered.
CREATE OR REPLACE FUNCTION control.api_stepup_begin(p_token text, p_action text, p_target text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token);
BEGIN
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  IF p_action NOT IN ('tenant_transition', 'credential_add', 'credential_revoke', 'recovery_approve', 'recovery_cancel', 'operator_invite')
     OR p_target IS NULL OR p_target !~ '^[A-Za-z0-9:_-]{1,200}$' THEN
    RETURN control.err('INVALID_INPUT');
  END IF;
  IF control.identity_under_recovery(c.identity_id) AND NOT control.stepup_allowed_under_recovery(c.identity_id, p_action, p_target) THEN
    RETURN control.err('IDENTITY_UNDER_RECOVERY');
  END IF;
  RETURN jsonb_build_object('ok', true,
    'challenge', control.challenge_issue('stepup', c.identity_id, c.id_hash, p_action, p_target),
    'credential_ids', (SELECT coalesce(jsonb_agg(credential_id), '[]'::jsonb) FROM control.webauthn_credentials w
                        WHERE w.identity_id = c.identity_id AND control.credential_usable(w.id) AND w.counter_suspect_at IS NULL));
END
$$;

-- As 212 + not flagged.
CREATE OR REPLACE FUNCTION control.anchor_signer(p_credential_id text, p_signer uuid, OUT public_key bytea, OUT label text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = control, pg_temp AS $$
  SELECT c.public_key, i.display_name
    FROM control.webauthn_credentials c JOIN control.platform_identities i ON i.id = c.identity_id
   WHERE c.credential_id = p_credential_id AND c.identity_id = p_signer AND control.credential_usable(c.id)
     AND c.counter_suspect_at IS NULL AND i.state = 'active' AND i.role = 'owner'
$$;

-- As 216 + IDENTITY_UNDER_RECOVERY; emergency revoke contests whenever it is after the subject's last recovery.
CREATE OR REPLACE FUNCTION control.api_recovery_approve(p_token text, p_request uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token); r control.recovery_requests; v_code text; v_tok text;
        v_until timestamptz; v_contested boolean; v_subject control.platform_identities; v_now timestamptz := clock_timestamp();
        v_activity timestamptz; v_confirm_after timestamptz; v_delay_from timestamptz; v_since timestamptz; v_revoke timestamptz;
BEGIN
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  SELECT * INTO r FROM control.recovery_requests WHERE id = p_request FOR UPDATE;
  SELECT * INTO v_subject FROM control.platform_identities WHERE id = r.subject_id;
  SELECT least(r.requested_at, min(requested_at)) INTO v_since FROM control.recovery_requests
   WHERE subject_id = r.subject_id
     AND requested_at > v_now - make_interval(secs => control.setting_int('recovery_max_lifetime_seconds'));
  SELECT max(last_used_at) INTO v_activity FROM control.webauthn_credentials
   WHERE identity_id = r.subject_id AND last_used_at > v_since AND counter_suspect_at IS NULL AND disabled_at IS NULL;
  -- an emergency revoke after the subject's last recovery always contests (C1.2: only within 24 h of the request)
  v_revoke := CASE WHEN v_subject.emergency_revoked_at > coalesce(v_subject.recovered_at, '-infinity'::timestamptz)
                   THEN v_subject.emergency_revoked_at END;
  v_contested := coalesce(r.contested_at IS NOT NULL OR v_activity IS NOT NULL OR v_revoke IS NOT NULL, false);
  v_confirm_after := greatest(r.last_contested_at, v_activity, v_revoke);
  v_delay_from := greatest(r.requested_at, r.contested_at, v_revoke);
  IF c.role <> 'owner' THEN v_code := 'FORBIDDEN';
  ELSIF r.id IS NULL OR r.state <> 'pending' OR r.expires_at <= v_now THEN v_code := 'NOT_FOUND';
  ELSIF r.subject_id = c.identity_id THEN v_code := 'SELF_APPROVAL_FORBIDDEN';
  ELSIF control.identity_under_recovery(c.identity_id) THEN v_code := 'IDENTITY_UNDER_RECOVERY';
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

-- As 217 + an owner under recovery cannot cancel OTHER requests (the subject's own contest still works).
CREATE OR REPLACE FUNCTION control.api_recovery_cancel(p_token text, p_request uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token); r control.recovery_requests; v_code text;
BEGIN
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  PERFORM 1 FROM control.enrolment_tokens WHERE recovery_request_id = p_request FOR UPDATE;
  SELECT * INTO r FROM control.recovery_requests WHERE id = p_request FOR UPDATE;
  IF r.id IS NULL OR r.state NOT IN ('pending', 'approved') OR r.expires_at <= clock_timestamp() THEN v_code := 'NOT_FOUND';
  ELSIF r.subject_id <> c.identity_id AND c.role <> 'owner' THEN v_code := 'FORBIDDEN';
  ELSIF r.subject_id <> c.identity_id AND control.identity_under_recovery(c.identity_id) THEN v_code := 'IDENTITY_UNDER_RECOVERY';
  ELSIF NOT control.stepup_consume_token(p_token, 'recovery_cancel', r.id::text) THEN v_code := 'STEPUP_REQUIRED';
  END IF;
  IF v_code IS NOT NULL THEN
    PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'platform.recovery_refused', 'denied',
      'recovery_request', p_request::text, NULL, v_code, '{}'::jsonb);
    RETURN control.err(v_code);
  END IF;
  IF r.subject_id = c.identity_id THEN
    PERFORM control.recovery_reopen_contested(r.id, true);
    PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'platform.recovery_contested', 'success',
      'recovery_request', r.id::text, NULL, NULL, jsonb_build_object('was_approved', r.state = 'approved', 'subject', r.subject_id));
    RETURN jsonb_build_object('ok', true, 'contested', true, 'link_voided', r.state = 'approved');
  END IF;
  PERFORM control.recovery_cancel_internal(r.id, c.identity_id::text);
  PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'platform.recovery_cancelled', 'success',
    'recovery_request', r.id::text, NULL, NULL, jsonb_build_object('subject', r.subject_id));
  RETURN jsonb_build_object('ok', true, 'contested', false);
END
$$;

-- As 217 + IDENTITY_UNDER_RECOVERY.
CREATE OR REPLACE FUNCTION control.api_operator_invite(p_token text, p_email text, p_display_name text, p_role text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx; v_email text := lower(btrim(coalesce(p_email, ''))); v_code text; v_existing control.platform_identities;
        v_id uuid; v_inv uuid; v_tok text; v_ttl integer := control.setting_int('operator_invite_ttl_seconds'); v_replaced uuid;
BEGIN
  PERFORM 1 FROM control.bootstrap_state FOR UPDATE;
  c := control.session_resolve(p_token);
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  SELECT * INTO v_existing FROM control.platform_identities WHERE email = v_email FOR NO KEY UPDATE;
  IF c.role <> 'owner' THEN v_code := 'FORBIDDEN';
  ELSIF control.identity_under_recovery(c.identity_id) THEN v_code := 'IDENTITY_UNDER_RECOVERY';
  ELSIF p_role NOT IN ('owner', 'admin') OR v_email !~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' OR length(v_email) > 254
        OR length(btrim(coalesce(p_display_name, ''))) NOT BETWEEN 1 AND 80 THEN v_code := 'INVALID_INPUT';
  ELSIF v_existing.id IS NOT NULL AND (v_existing.state = 'active' OR v_existing.activated_at IS NOT NULL
        OR EXISTS (SELECT 1 FROM control.operator_invitations WHERE identity_id = v_existing.id AND state IN ('pending', 'enrolled')
                     AND expires_at > clock_timestamp())) THEN v_code := 'ALREADY_EXISTS';
  ELSIF NOT control.stepup_consume_token(p_token, 'operator_invite', p_role || ':' || encode(sha256(convert_to(v_email, 'UTF8')), 'hex')) THEN
    v_code := 'STEPUP_REQUIRED';
  END IF;
  IF v_code IS NOT NULL THEN
    PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'platform.operator_invite_refused', 'denied',
      'platform_identity', NULL, NULL, v_code, jsonb_build_object('role', p_role, 'email_domain', split_part(v_email, '@', 2)));
    RETURN control.err(v_code);
  END IF;
  IF v_existing.id IS NOT NULL THEN
    SELECT id INTO v_replaced FROM control.operator_invitations WHERE identity_id = v_existing.id ORDER BY created_at DESC LIMIT 1;
    UPDATE control.operator_invitations SET state = 'revoked', revoked_at = clock_timestamp()
     WHERE identity_id = v_existing.id AND state IN ('pending', 'enrolled');
    UPDATE control.enrolment_tokens SET used_at = now() WHERE identity_id = v_existing.id AND used_at IS NULL;
    UPDATE control.webauthn_credentials SET disabled_at = now(), disabled_reason = 'invite_replaced'
     WHERE identity_id = v_existing.id AND disabled_at IS NULL;
    UPDATE control.platform_identities SET role = p_role, display_name = btrim(p_display_name), state = 'enrolling', revoked_at = NULL
     WHERE id = v_existing.id;
    v_id := v_existing.id;
  ELSE
    INSERT INTO control.platform_identities (email, display_name, role, state)
    VALUES (v_email, btrim(p_display_name), p_role, 'enrolling') RETURNING id INTO v_id;
  END IF;
  INSERT INTO control.operator_invitations (identity_id, role, invited_by, expires_at)
  VALUES (v_id, p_role, c.identity_id, clock_timestamp() + make_interval(secs => v_ttl)) RETURNING id INTO v_inv;
  v_tok := control.new_secret();
  INSERT INTO control.enrolment_tokens (token_hash, identity_id, purpose, expires_at, invitation_id)
  VALUES (control.sha(v_tok), v_id, 'invite', clock_timestamp() + make_interval(secs => v_ttl), v_inv);
  PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'platform.operator_invited', 'success',
    'platform_identity', v_id::text, NULL, NULL,
    jsonb_build_object('role', p_role, 'invitation', v_inv, 'email_domain', split_part(v_email, '@', 2), 'subject', v_id,
                       'replaced_invitation', v_replaced, 'previous_role', v_existing.role, 'previous_state', v_existing.state));
  RETURN jsonb_build_object('ok', true, 'invitation_id', v_inv, 'identity_id', v_id, 'enrolment_token', v_tok,
                            'expires_in_seconds', v_ttl);
END
$$;

-- As 217 + the inviter must not have been recovered (or suspended) after inviting.
CREATE OR REPLACE FUNCTION control.host_approve_operator(p_email text, p_fingerprint text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE i control.platform_identities; inv control.operator_invitations; v_fp text; v_code text;
BEGIN
  PERFORM control.assert_read_committed();
  PERFORM 1 FROM control.bootstrap_state FOR UPDATE;
  SELECT * INTO i FROM control.platform_identities WHERE email = lower(btrim(p_email)) FOR NO KEY UPDATE;
  SELECT * INTO inv FROM control.operator_invitations WHERE identity_id = i.id AND state = 'enrolled' FOR UPDATE;
  SELECT control.credential_fingerprint(public_key) INTO v_fp FROM control.webauthn_credentials
   WHERE identity_id = i.id AND created_via = 'invite' AND disabled_at IS NULL;
  IF i.id IS NULL OR inv.id IS NULL OR i.state <> 'pending_approval' THEN v_code := 'NOT_FOUND';
  ELSIF inv.expires_at <= clock_timestamp() THEN v_code := 'EXPIRED';
  ELSIF v_fp IS NULL OR upper(regexp_replace(coalesce(p_fingerprint, ''), '[^0-9A-Fa-f]', '', 'g')) IS DISTINCT FROM replace(v_fp, '-', '') THEN
    v_code := 'FINGERPRINT_MISMATCH';
  ELSIF NOT EXISTS (SELECT 1 FROM control.platform_identities o WHERE o.id = inv.invited_by AND o.state = 'active' AND o.role = 'owner'
                      AND (o.emergency_revoked_at IS NULL OR o.emergency_revoked_at < inv.created_at)
                      AND (o.recovered_at IS NULL OR o.recovered_at < inv.created_at)) THEN
    v_code := 'INVITER_INACTIVE';
  ELSIF control.identity_under_recovery(inv.invited_by) THEN
    v_code := 'INVITER_UNDER_RECOVERY';      -- the inviter's credential may be in a thief's hands right now
  ELSIF NOT control.notification_delivered('platform.operator_enrolled', 'platform_identity', i.id::text) THEN
    v_code := 'NOTIFICATION_PENDING';
  END IF;
  IF v_code IS NOT NULL THEN
    PERFORM control.audit_append('cli', NULL, 'host-operator', 'platform.operator_approve_refused', 'denied',
      'platform_identity', i.id::text, NULL, v_code, '{}'::jsonb);
    RETURN control.err(v_code);
  END IF;
  UPDATE control.platform_identities SET state = 'active', activated_at = clock_timestamp() WHERE id = i.id;
  UPDATE control.operator_invitations SET state = 'approved', approved_at = clock_timestamp() WHERE id = inv.id;
  PERFORM control.audit_append('cli', NULL, 'host-operator', 'platform.operator_approved', 'success',
    'platform_identity', i.id::text, NULL, NULL, jsonb_build_object('role', i.role, 'fingerprint', v_fp, 'subject', i.id));
  RETURN jsonb_build_object('ok', true, 'identity_id', i.id, 'role', i.role);
END
$$;

-- Reopen every recovery request this identity APPROVED (links voided), one audit row + notice each.
CREATE FUNCTION control.recovery_void_approved_by(p_identity uuid, p_why text) RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE x record; n integer := 0;
BEGIN
  -- lock every affected token and request first (tokens before requests, by id), then write audit rows
  PERFORM 1 FROM control.enrolment_tokens
   WHERE recovery_request_id IN (SELECT id FROM control.recovery_requests WHERE approved_by = p_identity AND state = 'approved')
   ORDER BY token_hash FOR UPDATE;
  PERFORM 1 FROM control.recovery_requests WHERE approved_by = p_identity AND state = 'approved' ORDER BY id FOR UPDATE;
  FOR x IN SELECT id, subject_id FROM control.recovery_requests WHERE approved_by = p_identity AND state = 'approved' ORDER BY id LOOP
    PERFORM control.recovery_reopen_contested(x.id, false);
    PERFORM control.audit_append('cli', NULL, 'recovery-guard', 'platform.recovery_link_voided', 'success', 'recovery_request',
      x.id::text, NULL, p_why, jsonb_build_object('subject', x.subject_id, 'approver', p_identity));
    n := n + 1;
  END LOOP;
  RETURN n;
END
$$;

-- Void every open invitation this identity ISSUED (and, for an invitee, its own), one audit row + notice each.
CREATE FUNCTION control.invitations_void_issued_by(p_identity uuid, p_why text) RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE x record; n integer := 0;
BEGIN
  PERFORM 1 FROM control.operator_invitations
   WHERE (invited_by = p_identity OR identity_id = p_identity) AND state IN ('pending', 'enrolled') ORDER BY id FOR UPDATE;
  FOR x IN SELECT id, identity_id FROM control.operator_invitations
            WHERE (invited_by = p_identity OR identity_id = p_identity) AND state IN ('pending', 'enrolled') ORDER BY created_at LOOP
    PERFORM control.operator_invitation_void(x.id);
    PERFORM control.audit_append('cli', NULL, 'recovery-guard', 'platform.operator_invite_revoked', 'success',
      'operator_invitation', x.id::text, NULL, p_why, jsonb_build_object('subject', x.identity_id, 'inviter', p_identity));
    n := n + 1;
  END LOOP;
  RETURN n;
END
$$;

-- As 217, reusing the shared void helpers (per-request audit rows: C1.2 LOW-5).
CREATE OR REPLACE FUNCTION control.host_revoke_operator_credentials(p_email text, p_reason text, p_force boolean DEFAULT false) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE i control.platform_identities; v_s integer; v_c integer; x record; v_inv integer; v_links integer; v_own integer := 0;
BEGIN
  PERFORM control.assert_read_committed();
  IF p_reason IS NULL OR length(btrim(p_reason)) < 10 THEN RETURN control.err('REASON_REQUIRED'); END IF;
  PERFORM 1 FROM control.bootstrap_state FOR UPDATE;
  SELECT * INTO i FROM control.platform_identities WHERE email = lower(btrim(p_email)) FOR NO KEY UPDATE;
  IF i.id IS NULL THEN RETURN control.err('NOT_FOUND'); END IF;
  IF i.role = 'owner' AND NOT coalesce(p_force, false) AND NOT EXISTS (
       SELECT 1 FROM control.platform_identities o JOIN control.webauthn_credentials w ON w.identity_id = o.id
        WHERE o.id <> i.id AND o.role = 'owner' AND o.state = 'active' AND control.credential_usable(w.id) AND w.counter_suspect_at IS NULL
          AND NOT control.identity_suspended(o.id) AND NOT control.identity_under_recovery(o.id)) THEN
    RETURN control.err('LAST_OWNER');
  END IF;
  UPDATE control.platform_identities SET emergency_revoked_at = clock_timestamp() WHERE id = i.id;
  UPDATE control.sessions SET revoked_at = now(), revoke_reason = 'admin' WHERE identity_id = i.id AND revoked_at IS NULL;
  GET DIAGNOSTICS v_s = ROW_COUNT;
  UPDATE control.webauthn_credentials SET disabled_at = now(), disabled_reason = 'host_revoked' WHERE identity_id = i.id AND disabled_at IS NULL;
  GET DIAGNOSTICS v_c = ROW_COUNT;
  UPDATE control.stepup_grants SET used_at = now() WHERE identity_id = i.id AND used_at IS NULL;
  UPDATE control.login_devices SET revoked_at = clock_timestamp() WHERE identity_id = i.id AND revoked_at IS NULL;
  PERFORM 1 FROM control.enrolment_tokens
   WHERE recovery_request_id IN (SELECT id FROM control.recovery_requests WHERE subject_id = i.id AND state IN ('pending', 'approved'))
   ORDER BY token_hash FOR UPDATE;
  PERFORM 1 FROM control.recovery_requests WHERE subject_id = i.id AND state IN ('pending', 'approved') ORDER BY id FOR UPDATE;
  FOR x IN SELECT id, state FROM control.recovery_requests WHERE subject_id = i.id AND state IN ('pending', 'approved') ORDER BY id LOOP
    PERFORM control.recovery_reopen_contested(x.id, false);
    PERFORM control.audit_append('cli', NULL, 'host-emergency', 'platform.recovery_link_voided', 'success', 'recovery_request',
      x.id::text, NULL, 'SUBJECT_REVOKED', jsonb_build_object('subject', i.id, 'was_approved', x.state = 'approved'));
    v_own := v_own + 1;
  END LOOP;
  v_links := control.recovery_void_approved_by(i.id, 'APPROVER_REVOKED');
  v_inv := control.invitations_void_issued_by(i.id, 'INVITER_REVOKED');
  PERFORM control.audit_append('cli', NULL, 'host-emergency', 'platform.operator_credentials_revoked', 'success',
    'platform_identity', i.id::text, NULL, 'EMERGENCY',
    jsonb_build_object('credentials_disabled', v_c, 'sessions_revoked', v_s, 'forced', coalesce(p_force, false),
                       'approved_links_voided', v_links, 'invitations_voided', v_inv, 'own_requests_reopened', v_own,
                       'reason', left(btrim(p_reason), 200)));
  RETURN jsonb_build_object('ok', true, 'credentials_disabled', v_c, 'sessions_revoked', v_s,
                            'approved_links_voided', v_links, 'invitations_voided', v_inv, 'own_requests_reopened', v_own);
END
$$;

-- As 211 + expired requests cancelled here are audited (C1.2 LOW-4).
CREATE OR REPLACE FUNCTION control.host_recovery_request(p_email text, p_reason text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE i control.platform_identities; v_id uuid; x record; v_prior timestamptz;
        v_ttl interval := make_interval(secs => control.setting_int('recovery_request_ttl_seconds'));
        v_max interval := make_interval(secs => control.setting_int('recovery_max_lifetime_seconds'));
BEGIN
  SELECT * INTO i FROM control.platform_identities WHERE email = lower(btrim(p_email)) AND state = 'active';
  IF i.id IS NULL THEN RETURN control.err('NOT_FOUND'); END IF;
  FOR x IN SELECT id FROM control.recovery_requests WHERE subject_id = i.id AND state IN ('pending', 'approved') AND expires_at <= clock_timestamp() LOOP
    IF control.recovery_cancel_internal(x.id, 'expired') > 0 THEN
      PERFORM control.audit_append('cli', NULL, 'host-recovery', 'platform.recovery_cancelled', 'success',
        'recovery_request', x.id::text, NULL, 'EXPIRED', jsonb_build_object('subject', i.id));
    END IF;
  END LOOP;
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

-- As 217 + effective state 'suspended'.
CREATE OR REPLACE FUNCTION control.api_operator_list(p_token text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token);
BEGIN
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  IF c.role <> 'owner' THEN RETURN control.err('FORBIDDEN'); END IF;
  RETURN jsonb_build_object('ok', true,
    'operators', (SELECT coalesce(jsonb_agg(jsonb_build_object('id', i.id, 'email', i.email, 'display_name', i.display_name,
        'role', i.role, 'you', i.id = c.identity_id,
        'state', CASE WHEN i.state = 'active' AND control.identity_suspended(i.id) THEN 'suspended' ELSE i.state END,
        'under_recovery', control.identity_under_recovery(i.id),
        'usable_passkeys', (SELECT count(*) FROM control.webauthn_credentials w WHERE w.identity_id = i.id AND control.credential_usable(w.id)))
        ORDER BY i.created_at), '[]') FROM control.platform_identities i),
    'invitations', (SELECT coalesce(jsonb_agg(jsonb_build_object('id', v.id, 'identity_id', v.identity_id, 'email', i.email,
        'role', v.role, 'state', v.state, 'created_at', v.created_at, 'expires_at', v.expires_at,
        'fingerprint', (SELECT control.credential_fingerprint(w.public_key) FROM control.webauthn_credentials w
                         WHERE w.identity_id = v.identity_id AND w.created_via = 'invite' AND w.disabled_at IS NULL LIMIT 1))
        ORDER BY v.created_at DESC), '[]')
        FROM control.operator_invitations v JOIN control.platform_identities i ON i.id = v.identity_id
       WHERE v.state IN ('pending', 'enrolled')));
END
$$;

-- As 212 + a flagged passkey does not count as "another usable passkey" (it can no longer step up).
CREATE OR REPLACE FUNCTION control.api_credential_revoke(p_token text, p_credential uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx; w control.webauthn_credentials; v_code text; v_sessions integer; v_self boolean;
BEGIN
  PERFORM control.identity_lock_for_session(p_token);
  c := control.session_resolve(p_token);
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  SELECT * INTO w FROM control.webauthn_credentials WHERE id = p_credential AND identity_id = c.identity_id;
  IF w.id IS NULL OR w.disabled_at IS NOT NULL THEN
    v_code := 'NOT_FOUND';
  ELSIF control.credential_usable(w.id) AND (SELECT count(*) FROM control.webauthn_credentials x
          WHERE x.identity_id = c.identity_id AND x.id <> w.id AND control.credential_usable(x.id) AND x.counter_suspect_at IS NULL) < 1 THEN
    v_code := 'LAST_CREDENTIAL';
  ELSIF NOT control.stepup_consume_token(p_token, 'credential_revoke', w.id::text) THEN
    v_code := 'STEPUP_REQUIRED';
  END IF;
  IF v_code IS NOT NULL THEN
    PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'platform.credential_revoke_refused',
      'denied', 'credential', p_credential::text, NULL, v_code, '{}'::jsonb);
    RETURN control.err(v_code);
  END IF;
  UPDATE control.sessions SET revoked_at = now(), revoke_reason = 'credential_revoked'
   WHERE identity_id = c.identity_id AND credential_id = w.credential_id AND revoked_at IS NULL;
  GET DIAGNOSTICS v_sessions = ROW_COUNT;
  UPDATE control.webauthn_credentials SET disabled_at = now(), disabled_reason = 'revoked', disabled_by = c.identity_id WHERE id = w.id;
  UPDATE control.stepup_grants SET used_at = now() WHERE credential_id = w.credential_id AND used_at IS NULL;
  v_self := NOT EXISTS (SELECT 1 FROM control.sessions WHERE id_hash = c.id_hash AND revoked_at IS NULL);
  PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'platform.credential_revoked', 'success',
    'credential', w.id::text, NULL, NULL, jsonb_build_object('fingerprint', left(w.credential_id, 8), 'sessions_revoked', v_sessions,
    'was_pending', NOT control.credential_usable(w.id), 'was_flagged', w.counter_suspect_at IS NOT NULL));
  RETURN jsonb_build_object('ok', true, 'sessions_revoked', v_sessions, 'current_session_ended', v_self);
END
$$;

RESET ROLE;
REVOKE CREATE ON SCHEMA control FROM control_auth;

-- ------------------------------------------------------------ enrolment (as 217 + C1.3 recovery and device fixes)
CREATE OR REPLACE FUNCTION control.api_enrol_complete(p_token text, p_attestation bytea, p_client_data bytea, p_nickname text)
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE t control.enrolment_tokens; i control.platform_identities; r control.recovery_requests; inv control.operator_invitations;
        reg record; v_cred uuid; v_disabled integer; v_sessions integer; v_now timestamptz; v_fp text; v_dev text;
        v_links integer := 0; v_invs integer := 0; v_activity timestamptz;
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
  IF t.invitation_id IS NOT NULL THEN
    SELECT * INTO inv FROM control.operator_invitations WHERE id = t.invitation_id FOR UPDATE;
  END IF;
  v_now := clock_timestamp();
  reg := control.wa_registration('register', p_attestation, p_client_data);
  IF t.purpose = 'recovery' THEN
    SELECT max(last_used_at) INTO v_activity FROM control.webauthn_credentials
     WHERE identity_id = i.id AND last_used_at > r.approved_at AND counter_suspect_at IS NULL AND disabled_at IS NULL;
  END IF;
  IF t.used_at IS NOT NULL OR t.expires_at <= v_now
     OR (t.purpose = 'recovery' AND (r.state IS DISTINCT FROM 'approved' OR r.expires_at <= v_now
                                     OR r.approved_at IS NULL OR r.last_contested_at > r.approved_at
                                     OR i.emergency_revoked_at >= r.approved_at
                                     OR EXISTS (SELECT 1 FROM control.platform_identities a
                                                 WHERE a.id = r.approved_by
                                                   AND (a.emergency_revoked_at >= r.approved_at OR a.recovered_at >= r.approved_at))))
     OR (t.purpose = 'invite' AND (inv.state IS DISTINCT FROM 'pending' OR inv.expires_at <= v_now)) THEN
    reg.err := 'INVALID_TOKEN';
  ELSIF t.purpose = 'recovery' AND control.identity_under_recovery(r.approved_by) THEN
    reg.err := 'APPROVER_UNDER_RECOVERY';   -- the approver's credential may be compromised: wait for its recovery (link kept)
  ELSIF t.purpose = 'recovery' AND v_activity IS NOT NULL THEN
    reg.err := 'RECOVERY_CONTESTED';      -- the subject used a passkey after the approval: not lost after all
  ELSIF t.purpose = 'recovery' AND r.approved_at >= control.setting_text('notify_gate_since')::timestamptz
        AND NOT control.notification_delivered('platform.recovery_approved', 'recovery_request', r.id::text) THEN
    reg.err := 'NOTIFICATION_PENDING';
  ELSIF reg.err IS NULL AND ((reg.ch).identity_id IS DISTINCT FROM t.identity_id
                             OR (reg.ch).action IS DISTINCT FROM 'enrol'
                             OR (reg.ch).target IS DISTINCT FROM encode(t.token_hash, 'hex')) THEN
    reg.err := 'INVALID_CHALLENGE';
  ELSIF reg.err IS NULL AND ((t.purpose IN ('owner_bootstrap', 'invite') AND i.state <> 'enrolling')
                             OR (t.purpose = 'recovery' AND i.state <> 'active')) THEN
    reg.err := 'INVALID_TOKEN';
  END IF;
  IF reg.err = 'RECOVERY_CONTESTED' THEN
    PERFORM control.recovery_reopen_contested(r.id, false);           -- voids the link; a new approval sees the activity
    PERFORM control.audit_append('anonymous', NULL, 'recovery-link', 'platform.recovery_contested', 'success',
      'recovery_request', r.id::text, NULL, 'SUBJECT_ACTIVITY_AFTER_APPROVAL',
      jsonb_build_object('subject', i.id, 'activity_at', v_activity, 'approved_at', r.approved_at));
    RETURN control.err('RECOVERY_CONTESTED');
  END IF;
  IF reg.err IS NULL AND t.purpose = 'recovery' THEN
    UPDATE control.sessions SET revoked_at = now(), revoke_reason = 'recovery' WHERE identity_id = i.id AND revoked_at IS NULL;
    GET DIAGNOSTICS v_sessions = ROW_COUNT;
    UPDATE control.webauthn_credentials SET disabled_at = now(), disabled_reason = 'recovered'
     WHERE identity_id = i.id AND disabled_at IS NULL;
    GET DIAGNOSTICS v_disabled = ROW_COUNT;
    UPDATE control.stepup_grants SET used_at = now() WHERE identity_id = i.id AND used_at IS NULL;
    UPDATE control.login_devices SET revoked_at = clock_timestamp() WHERE identity_id = i.id AND revoked_at IS NULL;
  END IF;
  IF reg.err IS NULL THEN
    BEGIN
      INSERT INTO control.webauthn_credentials (identity_id, credential_id, public_key, sign_count, nickname, created_via)
      VALUES (i.id, reg.cred_id, reg.cose, reg.sign_count, nullif(left(btrim(coalesce(p_nickname, '')), 60), ''),
              CASE t.purpose WHEN 'recovery' THEN 'recovery' WHEN 'invite' THEN 'invite' ELSE 'bootstrap' END)
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
  v_fp := control.credential_fingerprint(reg.cose);
  UPDATE control.enrolment_tokens SET used_at = now() WHERE token_hash = t.token_hash;
  IF t.purpose = 'owner_bootstrap' THEN
    UPDATE control.platform_identities SET state = 'active', activated_at = now() WHERE id = i.id;
    UPDATE control.bootstrap_state SET closed = true, closed_at = now();
    PERFORM control.audit_append('platform_identity', i.id, i.display_name, 'platform.owner_enrolled', 'success',
      'credential', v_cred::text, NULL, NULL, '{}'::jsonb);
  ELSIF t.purpose = 'invite' THEN
    UPDATE control.platform_identities SET state = 'pending_approval' WHERE id = i.id;
    UPDATE control.operator_invitations SET state = 'enrolled', enrolled_at = clock_timestamp() WHERE id = inv.id;
    PERFORM control.audit_append('platform_identity', i.id, i.display_name, 'platform.operator_enrolled', 'success',
      'platform_identity', i.id::text, NULL, NULL,
      jsonb_build_object('role', i.role, 'invitation', inv.id, 'fingerprint', v_fp, 'subject', i.id));
  ELSE
    -- M1: what the old (possibly stolen) credential set in motion does not survive the recovery
    v_links := control.recovery_void_approved_by(i.id, 'APPROVER_RECOVERED');
    v_invs := control.invitations_void_issued_by(i.id, 'INVITER_RECOVERED');
    UPDATE control.platform_identities SET recovered_at = clock_timestamp() WHERE id = i.id;
    UPDATE control.recovery_requests SET state = 'redeemed', redeemed_at = now() WHERE id = r.id;
    PERFORM control.audit_append('platform_identity', i.id, i.display_name, 'platform.recovery_completed', 'success',
      'recovery_request', r.id::text, NULL, NULL,
      jsonb_build_object('credentials_disabled', v_disabled, 'sessions_revoked', v_sessions, 'new_credential', v_cred,
                         'approved_links_voided', v_links, 'invitations_voided', v_invs, 'subject', i.id));
  END IF;
  v_dev := control.login_device_issue(i.id);           -- M2: this browser gets its own login bucket
  RETURN jsonb_build_object('ok', true, 'credential', v_cred, 'purpose', t.purpose,
                            'fingerprint', v_fp, 'awaiting_host_approval', t.purpose = 'invite',
                            'device_token', v_dev, 'device_ttl_seconds', control.setting_int('login_device_ttl_seconds'));
END
$$;

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA control FROM PUBLIC;
GRANT EXECUTE ON FUNCTION control.identity_suspended(uuid), control.identity_under_recovery(uuid) TO control_audit_owner;
