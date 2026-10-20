-- ============================================================
-- 215: operator (second-owner / admin) invitations with two-party activation (C1.2, R-1)
--
-- FLOW     1. INVITE   An active OWNER, with a step-up bound to ('operator_invite', '<role>:<sha256(lower(email))>'),
--                      creates an invitation: a new identity in state 'enrolling' with the role FIXED by the invitation,
--                      and a single-use enrolment link (48 h), returned once. Out-of-band notice to all owners + host.
--          2. ENROL    The invitee proves possession of a passkey (registration verified in the database, as for
--                      bootstrap). The identity becomes 'pending_approval' (cannot sign in). Out-of-band notice
--                      ('operator_enrolled') carries the passkey fingerprint.
--          3. ACTIVATE The HOST runs host_approve_operator(email, fingerprint) after confirming the fingerprint with the
--                      invitee out of band. Refused unless the 'operator_enrolled' notice was delivered, the invitation
--                      is still valid and the inviter is still an active owner. Out-of-band notice ('operator_approved').
-- PROPERTIES  - The first owner cannot silently create an active second owner: activation needs the host, and every
--              step is announced out of band (212).
--             - Enrolment needs cryptographic proof (passkey) AND the link; the role cannot be changed after invite.
--             - Links expire, are single-use, hashed at rest; revocation voids them; concurrent redemption -> one.
--             - Admins cannot invite; nobody can approve via the app; the host cannot change the role.
-- POLICY   Who approves activation (host only - implemented default; alternatives: a different owner, or host + delay)
--          is an OWNER DECISION, documented in docs/RECOVERY.md (R-1).
-- ============================================================

INSERT INTO control.settings (key, value) VALUES ('operator_invite_ttl_seconds', '172800');   -- 48 h

INSERT INTO control.audit_actions (action, description) VALUES
  ('platform.operator_invited',        'Owner invited an operator (role fixed by the invitation)'),
  ('platform.operator_invite_refused', 'Operator invitation refused'),
  ('platform.operator_enrolled',       'Invited operator registered a passkey; awaiting host approval'),
  ('platform.operator_approved',       'Host approved an invited operator; identity active'),
  ('platform.operator_approve_refused','Host approval of an invited operator refused'),
  ('platform.operator_invite_revoked', 'Operator invitation revoked');

ALTER TABLE control.platform_identities DROP CONSTRAINT platform_identities_state_check;
ALTER TABLE control.platform_identities ADD CONSTRAINT platform_identities_state_check
  CHECK (state IN ('enrolling', 'pending_approval', 'active', 'revoked'));
ALTER TABLE control.webauthn_credentials DROP CONSTRAINT webauthn_credentials_created_via_check;
ALTER TABLE control.webauthn_credentials ADD CONSTRAINT webauthn_credentials_created_via_check
  CHECK (created_via IN ('bootstrap', 'added', 'recovery', 'invite'));
ALTER TABLE control.enrolment_tokens DROP CONSTRAINT enrolment_tokens_purpose_check;
ALTER TABLE control.enrolment_tokens ADD CONSTRAINT enrolment_tokens_purpose_check
  CHECK (purpose IN ('owner_bootstrap', 'recovery', 'invite'));

GRANT CREATE ON SCHEMA control TO control_auth;
SET ROLE control_auth;

CREATE TABLE control.operator_invitations (
  id            uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  identity_id   uuid NOT NULL REFERENCES control.platform_identities(id),
  role          text NOT NULL CHECK (role IN ('owner', 'admin')),
  invited_by    uuid NOT NULL REFERENCES control.platform_identities(id),
  created_at    timestamptz NOT NULL DEFAULT clock_timestamp(),
  expires_at    timestamptz NOT NULL,
  state         text NOT NULL DEFAULT 'pending' CHECK (state IN ('pending', 'enrolled', 'approved', 'revoked')),
  enrolled_at   timestamptz,
  approved_at   timestamptz,
  revoked_at    timestamptz,
  CHECK (invited_by <> identity_id)
);
CREATE UNIQUE INDEX operator_invitations_open ON control.operator_invitations (identity_id) WHERE state IN ('pending', 'enrolled');
ALTER TABLE control.operator_invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE control.enrolment_tokens ADD COLUMN invitation_id uuid REFERENCES control.operator_invitations(id);

-- ------------------------------------------------------------ invite (owner, step-up bound to role + email hash)
CREATE FUNCTION control.api_operator_invite(p_token text, p_email text, p_display_name text, p_role text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx; v_email text := lower(btrim(coalesce(p_email, ''))); v_code text; v_existing control.platform_identities;
        v_id uuid; v_inv uuid; v_tok text; v_ttl integer := control.setting_int('operator_invite_ttl_seconds');
BEGIN
  -- lock order (same as host revoke / enrolment / approval): bootstrap_state row FIRST, then sessions, then identities
  PERFORM 1 FROM control.bootstrap_state FOR UPDATE;      -- serialises invitations (email reuse, owner counts)
  c := control.session_resolve(p_token);
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  SELECT * INTO v_existing FROM control.platform_identities WHERE email = v_email FOR NO KEY UPDATE;
  IF c.role <> 'owner' THEN v_code := 'FORBIDDEN';
  ELSIF p_role NOT IN ('owner', 'admin') OR v_email !~ '^[^@\s]+@[^@\s]+\.[^@\s]+$' OR length(v_email) > 254
        OR length(btrim(coalesce(p_display_name, ''))) NOT BETWEEN 1 AND 80 THEN v_code := 'INVALID_INPUT';
  -- an email may be re-invited only if its identity never completed enrolment (enrolling, no open invitation)
  ELSIF v_existing.id IS NOT NULL AND (v_existing.state <> 'enrolling'
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
    -- stale enrolling identity from an expired invitation: close the old invitation and reuse the identity
    UPDATE control.operator_invitations SET state = 'revoked', revoked_at = clock_timestamp()
     WHERE identity_id = v_existing.id AND state IN ('pending', 'enrolled');
    UPDATE control.enrolment_tokens SET used_at = now() WHERE identity_id = v_existing.id AND used_at IS NULL;
    UPDATE control.platform_identities SET role = p_role, display_name = btrim(p_display_name) WHERE id = v_existing.id;
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
    jsonb_build_object('role', p_role, 'invitation', v_inv, 'email_domain', split_part(v_email, '@', 2), 'subject', v_id));
  RETURN jsonb_build_object('ok', true, 'invitation_id', v_inv, 'identity_id', v_id, 'enrolment_token', v_tok,
                            'expires_in_seconds', v_ttl);
END
$$;

CREATE FUNCTION control.api_operator_invite_revoke(p_token text, p_invitation uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx; inv control.operator_invitations; v_code text;
BEGIN
  PERFORM 1 FROM control.bootstrap_state FOR UPDATE;
  c := control.session_resolve(p_token);
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  SELECT * INTO inv FROM control.operator_invitations WHERE id = p_invitation FOR UPDATE;
  IF c.role <> 'owner' THEN v_code := 'FORBIDDEN';
  ELSIF inv.id IS NULL OR inv.state NOT IN ('pending', 'enrolled') THEN v_code := 'NOT_FOUND';
  ELSIF NOT control.stepup_consume_token(p_token, 'operator_invite', 'revoke:' || inv.id::text) THEN v_code := 'STEPUP_REQUIRED';
  END IF;
  IF v_code IS NOT NULL THEN
    PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'platform.operator_invite_refused', 'denied',
      'operator_invitation', p_invitation::text, NULL, v_code, '{}'::jsonb);
    RETURN control.err(v_code);
  END IF;
  UPDATE control.operator_invitations SET state = 'revoked', revoked_at = clock_timestamp() WHERE id = inv.id;
  UPDATE control.enrolment_tokens SET used_at = now() WHERE invitation_id = inv.id AND used_at IS NULL;
  UPDATE control.webauthn_credentials SET disabled_at = now(), disabled_reason = 'invite_revoked'
   WHERE identity_id = inv.identity_id AND disabled_at IS NULL;
  UPDATE control.platform_identities SET state = 'revoked', revoked_at = clock_timestamp()
   WHERE id = inv.identity_id AND state IN ('enrolling', 'pending_approval');
  PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'platform.operator_invite_revoked', 'success',
    'operator_invitation', inv.id::text, NULL, NULL, jsonb_build_object('subject', inv.identity_id));
  RETURN jsonb_build_object('ok', true);
END
$$;

CREATE FUNCTION control.api_operator_list(p_token text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token);
BEGIN
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  IF c.role <> 'owner' THEN RETURN control.err('FORBIDDEN'); END IF;
  RETURN jsonb_build_object('ok', true,
    'operators', (SELECT coalesce(jsonb_agg(jsonb_build_object('id', i.id, 'email', i.email, 'display_name', i.display_name,
        'role', i.role, 'state', i.state, 'you', i.id = c.identity_id,
        'usable_passkeys', (SELECT count(*) FROM control.webauthn_credentials w WHERE w.identity_id = i.id AND control.credential_usable(w.id)))
        ORDER BY i.created_at), '[]') FROM control.platform_identities i),
    'invitations', (SELECT coalesce(jsonb_agg(jsonb_build_object('id', v.id, 'identity_id', v.identity_id, 'email', i.email,
        'role', v.role, 'state', v.state, 'created_at', v.created_at, 'expires_at', v.expires_at,
        'fingerprint', (SELECT left(w.credential_id, 8) FROM control.webauthn_credentials w
                         WHERE w.identity_id = v.identity_id AND w.created_via = 'invite' AND w.disabled_at IS NULL LIMIT 1))
        ORDER BY v.created_at DESC), '[]')
        FROM control.operator_invitations v JOIN control.platform_identities i ON i.id = v.identity_id
       WHERE v.state IN ('pending', 'enrolled')));
END
$$;

-- ------------------------------------------------------------ host activation (no grants)
CREATE FUNCTION control.host_approve_operator(p_email text, p_fingerprint text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE i control.platform_identities; inv control.operator_invitations; v_fp text; v_code text;
BEGIN
  PERFORM 1 FROM control.bootstrap_state FOR UPDATE;
  SELECT * INTO i FROM control.platform_identities WHERE email = lower(btrim(p_email)) FOR NO KEY UPDATE;
  SELECT * INTO inv FROM control.operator_invitations WHERE identity_id = i.id AND state = 'enrolled' FOR UPDATE;
  SELECT left(credential_id, 8) INTO v_fp FROM control.webauthn_credentials
   WHERE identity_id = i.id AND created_via = 'invite' AND disabled_at IS NULL;
  IF i.id IS NULL OR inv.id IS NULL OR i.state <> 'pending_approval' THEN v_code := 'NOT_FOUND';
  ELSIF inv.expires_at <= clock_timestamp() THEN v_code := 'EXPIRED';
  ELSIF v_fp IS NULL OR p_fingerprint IS DISTINCT FROM v_fp THEN v_code := 'FINGERPRINT_MISMATCH';
  ELSIF NOT EXISTS (SELECT 1 FROM control.platform_identities WHERE id = inv.invited_by AND state = 'active' AND role = 'owner') THEN
    v_code := 'INVITER_INACTIVE';
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

-- ------------------------------------------------------------ step-up allow-list (as 207) + invitation actions
CREATE OR REPLACE FUNCTION control.api_stepup_begin(p_token text, p_action text, p_target text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token);
BEGIN
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  IF p_action NOT IN ('tenant_transition', 'credential_add', 'credential_revoke', 'recovery_approve', 'recovery_cancel', 'operator_invite')
     OR p_target IS NULL OR p_target !~ '^[A-Za-z0-9:_-]{1,200}$' THEN
    RETURN control.err('INVALID_INPUT');
  END IF;
  RETURN jsonb_build_object('ok', true,
    'challenge', control.challenge_issue('stepup', c.identity_id, c.id_hash, p_action, p_target),
    'credential_ids', (SELECT coalesce(jsonb_agg(credential_id), '[]'::jsonb) FROM control.webauthn_credentials w
                        WHERE w.identity_id = c.identity_id AND control.credential_usable(w.id)));
END
$$;

RESET ROLE;
REVOKE CREATE ON SCHEMA control FROM control_auth;

-- ------------------------------------------------------------ enrolment: 'invite' tokens (as 210/212 + invite branch)
CREATE OR REPLACE FUNCTION control.api_enrol_begin(p_token text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE t control.enrolment_tokens; i control.platform_identities; v_ch text; r control.recovery_requests;
        inv control.operator_invitations; v_now timestamptz;
BEGIN
  PERFORM control.assert_fresh_transaction();
  v_now := clock_timestamp();
  SELECT * INTO t FROM control.enrolment_tokens WHERE p_token ~ '^[0-9a-f]{64}$' AND token_hash = control.sha(p_token);
  IF t.recovery_request_id IS NOT NULL THEN SELECT * INTO r FROM control.recovery_requests WHERE id = t.recovery_request_id; END IF;
  IF t.invitation_id IS NOT NULL THEN SELECT * INTO inv FROM control.operator_invitations WHERE id = t.invitation_id; END IF;
  IF t.token_hash IS NULL OR t.used_at IS NOT NULL OR t.expires_at <= v_now
     OR (t.purpose = 'recovery' AND (r.state IS DISTINCT FROM 'approved' OR r.expires_at <= v_now))
     OR (t.purpose = 'invite' AND (inv.state IS DISTINCT FROM 'pending' OR inv.expires_at <= v_now)) THEN
    IF control.rate_limit_hit('enrol_invalid', 'global', control.setting_int('enrol_invalid_limit')) THEN
      PERFORM control.audit_append('anonymous', NULL, NULL, 'platform.enrol_failed', 'denied', NULL, NULL, NULL, 'INVALID_TOKEN', '{}'::jsonb);
    END IF;
    RETURN control.err('INVALID_TOKEN');
  END IF;
  IF NOT control.rate_limit_hit('enrol_token', encode(t.token_hash, 'hex'), control.setting_int('enrol_token_limit')) THEN
    RETURN control.err('RATE_LIMITED');
  END IF;
  SELECT * INTO i FROM control.platform_identities WHERE id = t.identity_id;
  IF (t.purpose IN ('owner_bootstrap', 'invite') AND i.state <> 'enrolling') OR (t.purpose = 'recovery' AND i.state <> 'active') THEN
    RETURN control.err('INVALID_TOKEN');
  END IF;
  v_ch := control.challenge_issue('register', i.id, NULL, 'enrol', encode(t.token_hash, 'hex'));
  RETURN jsonb_build_object('ok', true, 'challenge', v_ch, 'identity_id', i.id, 'email', i.email,
    'display_name', i.display_name, 'purpose', t.purpose, 'role', i.role,
    'expires_in_seconds', greatest(0, extract(epoch FROM t.expires_at - v_now)::integer),
    'exclude_credential_ids', (SELECT coalesce(jsonb_agg(credential_id), '[]'::jsonb) FROM control.webauthn_credentials
                                WHERE identity_id = i.id AND disabled_at IS NULL));
END
$$;

CREATE OR REPLACE FUNCTION control.api_enrol_complete(p_token text, p_attestation bytea, p_client_data bytea, p_nickname text)
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE t control.enrolment_tokens; i control.platform_identities; r control.recovery_requests; inv control.operator_invitations;
        reg record; v_cred uuid; v_disabled integer; v_sessions integer; v_now timestamptz;
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
  IF t.used_at IS NOT NULL OR t.expires_at <= v_now
     OR (t.purpose = 'recovery' AND (r.state IS DISTINCT FROM 'approved' OR r.expires_at <= v_now
                                     OR r.approved_at IS NULL OR r.last_contested_at > r.approved_at
                                     OR i.emergency_revoked_at >= r.approved_at))
     OR (t.purpose = 'invite' AND (inv.state IS DISTINCT FROM 'pending' OR inv.expires_at <= v_now)) THEN
    reg.err := 'INVALID_TOKEN';
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
      jsonb_build_object('role', i.role, 'invitation', inv.id, 'fingerprint', left(reg.cred_id, 8), 'subject', i.id));
  ELSE
    UPDATE control.recovery_requests SET state = 'redeemed', redeemed_at = now() WHERE id = r.id;
    PERFORM control.audit_append('platform_identity', i.id, i.display_name, 'platform.recovery_completed', 'success',
      'recovery_request', r.id::text, NULL, NULL,
      jsonb_build_object('credentials_disabled', v_disabled, 'sessions_revoked', v_sessions, 'new_credential', v_cred));
  END IF;
  RETURN jsonb_build_object('ok', true, 'credential', v_cred, 'purpose', t.purpose,
                            'fingerprint', left(reg.cred_id, 8), 'awaiting_host_approval', t.purpose = 'invite');
END
$$;

CREATE OR REPLACE FUNCTION control.api_contract_version() RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = control, pg_temp AS $$
  SELECT 'orvix-control/0.4'::text
$$;

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA control FROM PUBLIC;
GRANT EXECUTE ON FUNCTION control.api_contract_version() TO control_app;
GRANT EXECUTE ON FUNCTION control.api_operator_invite(text, text, text, text), control.api_operator_invite_revoke(text, uuid),
  control.api_operator_list(text) TO control_app;
-- host_approve_operator: no grants (superuser only).
