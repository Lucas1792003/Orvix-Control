-- ============================================================
-- 210: fixes from the final C1.1 checkpoint review (five independent reviewers; docs/REVIEW_C1_1.md)
--
-- MED  Recovery contest could still act as a veto: each objection restarted the 12 h delay, which could run past the
--      request's expiry. Now: the delay runs from the FIRST objection (or the request / an emergency revoke), never
--      from later ones; the host confirmation must post-date the LATEST objection, the latest qualifying passkey use
--      and any emergency revoke; contesting extends the request so delay + 12 h always fit (bounded by 7 days).
--      A subject who keeps objecting is stopped by the host's revoke-operator (two people: host + second owner).
-- MED  An objection after approval was accepted but ignored: it now voids the outstanding link and returns the
--      request to pending (contested). Redemption also refuses if an objection or emergency revoke post-dates approval.
-- LOW  Emergency revoke ignored already-approved requests: they are returned to pending with their links voided.
--      Revoking the LAST owner's credentials now needs p_force (it is a permanent lockout on a single-owner install).
-- LOW  Expiry checks used transaction start time: auth entry points refuse a transaction older than 5 s
--      (assert_fresh_transaction), so a held-open transaction cannot outlive session/grant/token/request expiry.
-- LOW  Cross-role SELECT policies let a table owner run policy code as the reader: the audit read API is now owned by
--      control_audit_owner (its own tables), and the anchor signer lookup is a control_auth function. No runtime role
--      keeps any privilege on a table owned by a different runtime role.
-- LOW  Security-critical helpers search pg_catalog first (search_path = pg_catalog, pg_temp; all calls qualified).
-- LOW  audit_safe_detail depth-capped; pg_notify revoked from PUBLIC; control_app temp_file_limit (superuser-set).
-- ROLLBACK Restore from the pre-210 recovery point.
-- ============================================================

-- ------------------------------------------------------------ helpers (inert owner)
SET ROLE control_schema_owner;
CREATE FUNCTION control.assert_fresh_transaction() RETURNS void
LANGUAGE plpgsql VOLATILE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF clock_timestamp() - now() > interval '5 seconds' THEN
    RAISE EXCEPTION 'STALE_TRANSACTION' USING ERRCODE = 'invalid_transaction_state';
  END IF;
END
$$;

CREATE FUNCTION control.audit_safe_detail_d(j jsonb, depth integer) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE r jsonb; k text; v jsonb; n numeric;
BEGIN
  IF j IS NULL THEN RETURN 'null'::jsonb; END IF;
  IF depth > 32 THEN RETURN to_jsonb(j::text); END IF;   -- deep structures are stored as text
  CASE jsonb_typeof(j)
    WHEN 'object' THEN
      r := '{}'::jsonb;
      FOR k, v IN SELECT * FROM jsonb_each(j) LOOP r := r || jsonb_build_object(k, control.audit_safe_detail_d(v, depth + 1)); END LOOP;
      RETURN r;
    WHEN 'array' THEN
      RETURN coalesce((SELECT jsonb_agg(control.audit_safe_detail_d(e, depth + 1) ORDER BY o)
                         FROM jsonb_array_elements(j) WITH ORDINALITY AS t(e, o)), '[]'::jsonb);
    WHEN 'number' THEN
      n := (j #>> '{}')::numeric;
      IF n = trunc(n) AND abs(n) <= 9007199254740991 AND (j #>> '{}') = trunc(n)::text THEN RETURN j; END IF;
      RETURN to_jsonb(j #>> '{}');
    ELSE RETURN j;
  END CASE;
END
$$;

CREATE OR REPLACE FUNCTION control.audit_safe_detail(j jsonb) RETURNS jsonb
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE WHEN j IS NULL THEN '{}'::jsonb ELSE control.audit_safe_detail_d(j, 0) END
$$;
RESET ROLE;

-- crypto / canonical helpers: pg_catalog first (all control.* references are qualified)
ALTER FUNCTION control.b2n(bytea)                          SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION control.modp(numeric, numeric)              SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION control.modpow(numeric, numeric, numeric)   SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION control.p256_on_curve(numeric, numeric)     SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION control.p256_dbl(numeric[])                 SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION control.p256_add(numeric[], numeric[])      SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION control.p256_verify(numeric, numeric, numeric, numeric, numeric) SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION control.der_ecdsa_sig(bytea)                SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION control.cose_es256_xy(bytea)                SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION control.es256_verify(bytea, bytea, bytea)   SET search_path = pg_catalog, pg_temp;
ALTER FUNCTION control.anchor_challenge(bigint, bytea, bytea) SET search_path = pg_catalog, pg_temp;

REVOKE EXECUTE ON FUNCTION pg_catalog.pg_notify(text, text) FROM PUBLIC;
ALTER ROLE control_app SET temp_file_limit = '256MB';   -- superuser-only GUC: control_app cannot raise it

INSERT INTO control.settings (key, value) VALUES ('recovery_max_lifetime_seconds', '604800');  -- 7 days
ALTER TABLE control.recovery_requests ADD COLUMN last_contested_at timestamptz;
UPDATE control.recovery_requests SET last_contested_at = contested_at WHERE contested_at IS NOT NULL;

-- ------------------------------------------------------------ auth entry points refuse stale transactions
CREATE OR REPLACE FUNCTION control.challenge_consume(p_challenge text, p_purpose text)
RETURNS control.webauthn_challenges
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE v control.webauthn_challenges;
BEGIN
  PERFORM control.assert_fresh_transaction();
  IF p_challenge IS NULL OR p_challenge !~ '^[A-Za-z0-9_-]{32,128}$' THEN RETURN NULL; END IF;
  UPDATE control.webauthn_challenges SET used_at = now()
   WHERE challenge_hash = control.sha(p_challenge) AND used_at IS NULL
  RETURNING * INTO v;
  IF v.challenge_hash IS NULL OR v.purpose <> p_purpose OR v.expires_at <= clock_timestamp() THEN RETURN NULL; END IF;
  RETURN v;
END
$$;

CREATE OR REPLACE FUNCTION control.session_resolve(p_token text) RETURNS control.session_ctx
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE
  s control.sessions; i control.platform_identities;
  v_idle interval := make_interval(secs => control.setting_int('session_idle_seconds'));
  v_reason text; r control.session_ctx; v_now timestamptz;
BEGIN
  PERFORM control.assert_fresh_transaction();
  v_now := clock_timestamp();
  IF p_token IS NULL OR p_token !~ '^[0-9a-f]{64}$' OR v_idle IS NULL THEN RETURN NULL; END IF;
  SELECT * INTO s FROM control.sessions WHERE id_hash = control.sha(p_token) FOR UPDATE;
  IF s.id_hash IS NULL OR s.revoked_at IS NOT NULL THEN RETURN NULL; END IF;
  SELECT * INTO i FROM control.platform_identities WHERE id = s.identity_id;
  IF v_now >= s.absolute_expires_at THEN v_reason := 'absolute_timeout';
  ELSIF v_now - s.last_seen_at >= v_idle THEN v_reason := 'idle_timeout';
  ELSIF i.state IS DISTINCT FROM 'active' THEN v_reason := 'identity_inactive';
  ELSIF NOT EXISTS (SELECT 1 FROM control.webauthn_credentials c
                     WHERE c.credential_id = s.credential_id AND c.disabled_at IS NULL) THEN v_reason := 'credential_revoked';
  END IF;
  IF v_reason IS NOT NULL THEN
    UPDATE control.sessions SET revoked_at = now(), revoke_reason = v_reason WHERE id_hash = s.id_hash;
    PERFORM control.audit_append('platform_identity', i.id, i.display_name, 'platform.session_expired', 'success',
      'session', encode(substring(s.id_hash FROM 1 FOR 8), 'hex'), NULL, v_reason, '{}'::jsonb);
    RETURN NULL;
  END IF;
  UPDATE control.sessions SET last_seen_at = v_now WHERE id_hash = s.id_hash;
  r := (s.id_hash, i.id, i.email, i.display_name, i.role, s.created_at, s.absolute_expires_at, v_now + v_idle, NULL);
  RETURN r;
END
$$;

CREATE OR REPLACE FUNCTION control.stepup_consume_token(p_token text, p_action text, p_target text) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE v_id bigint;
BEGIN
  PERFORM control.assert_fresh_transaction();
  IF p_token IS NULL OR p_token !~ '^[0-9a-f]{64}$' THEN RETURN false; END IF;
  SELECT g.id INTO v_id FROM control.stepup_grants g
    JOIN control.sessions s ON s.id_hash = g.session_id_hash AND s.revoked_at IS NULL
    JOIN control.webauthn_credentials w ON w.credential_id = g.credential_id AND w.disabled_at IS NULL
   WHERE g.session_id_hash = control.sha(p_token) AND g.action = p_action AND g.target = p_target
     AND g.used_at IS NULL AND g.expires_at > clock_timestamp()
   ORDER BY g.id LIMIT 1 FOR UPDATE OF g SKIP LOCKED;
  IF v_id IS NULL THEN RETURN false; END IF;
  UPDATE control.stepup_grants SET used_at = now() WHERE id = v_id;
  RETURN true;
END
$$;

-- ------------------------------------------------------------ anchor signer lookup without cross-role table reads
-- (control_auth needs CREATE only for this statement; granted and revoked around it)
GRANT CREATE ON SCHEMA control TO control_auth;
SET ROLE control_auth;
CREATE FUNCTION control.anchor_signer(p_credential_id text, p_signer uuid, OUT public_key bytea, OUT label text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = control, pg_temp AS $$
  SELECT c.public_key, i.display_name
    FROM control.webauthn_credentials c JOIN control.platform_identities i ON i.id = c.identity_id
   WHERE c.credential_id = p_credential_id AND c.identity_id = p_signer AND c.disabled_at IS NULL
     AND c.usable_after <= clock_timestamp() AND i.state = 'active' AND i.role = 'owner'
$$;
RESET ROLE;
REVOKE CREATE ON SCHEMA control FROM control_auth;
REVOKE EXECUTE ON FUNCTION control.anchor_signer(text, uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION control.anchor_signer(text, uuid) TO control_audit_owner;

CREATE OR REPLACE FUNCTION control.audit_anchor_insert_signed(p_seq bigint, p_head bytea, p_nonce bytea, p_signer uuid,
  p_signer_label text, p_credential_id text, p_public_key bytea, p_client_data bytea, p_authenticator_data bytea,
  p_signature bytea, p_note text) RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE cd jsonb; v_id bigint; s record;
        v_rp text := control.setting_text('webauthn_rp_id'); v_origin text := control.setting_text('webauthn_origin');
BEGIN
  PERFORM 1 FROM control.audit_lock FOR UPDATE;
  IF NOT EXISTS (SELECT 1 FROM control.audit_events WHERE seq = p_seq AND row_hash = p_head) THEN
    RAISE EXCEPTION 'ANCHOR_HEAD_MISMATCH';
  END IF;
  SELECT * INTO s FROM control.anchor_signer(p_credential_id, p_signer);
  IF s.public_key IS NULL OR s.public_key IS DISTINCT FROM p_public_key THEN RAISE EXCEPTION 'ANCHOR_SIGNER_INVALID'; END IF;
  BEGIN
    cd := convert_from(p_client_data, 'UTF8')::jsonb;
  EXCEPTION WHEN OTHERS THEN RAISE EXCEPTION 'ANCHOR_SIGNATURE_INVALID';
  END;
  IF jsonb_typeof(cd) IS DISTINCT FROM 'object'
     OR cd ->> 'type' IS DISTINCT FROM 'webauthn.get'
     OR cd ->> 'origin' IS DISTINCT FROM v_origin
     OR cd ->> 'challenge' IS DISTINCT FROM control.anchor_challenge(p_seq, p_head, p_nonce)
     OR coalesce(cd -> 'crossOrigin', 'false'::jsonb) <> 'false'::jsonb OR cd ? 'topOrigin'
     OR p_authenticator_data IS NULL OR length(p_authenticator_data) < 37
     OR substring(p_authenticator_data FROM 1 FOR 32) IS DISTINCT FROM sha256(convert_to(v_rp, 'UTF8'))
     OR get_byte(p_authenticator_data, 32) & 5 <> 5
     OR NOT control.es256_verify(s.public_key, p_authenticator_data || sha256(p_client_data), p_signature) THEN
    RAISE EXCEPTION 'ANCHOR_SIGNATURE_INVALID';
  END IF;
  INSERT INTO control.audit_anchors (seq, head_hash, created_by, note, nonce, signer_identity, signer_label, credential_id,
    public_key, rp_id, origin, client_data, authenticator_data, signature)
  VALUES (p_seq, p_head, p_signer, left(p_note, 200), p_nonce, p_signer, s.label, p_credential_id, s.public_key,
    v_rp, v_origin, p_client_data, p_authenticator_data, p_signature)
  RETURNING id INTO v_id;
  RETURN v_id;
END
$$;
DROP POLICY credentials_audit_read ON control.webauthn_credentials;
DROP POLICY identities_audit_read ON control.platform_identities;
REVOKE SELECT ON control.webauthn_credentials, control.platform_identities FROM control_audit_owner;

-- The audit READ API moves to the audit owner (its own tables); control_definer loses every audit-table privilege.
GRANT EXECUTE ON FUNCTION control.session_resolve(text) TO control_audit_owner;
GRANT EXECUTE ON FUNCTION control.authorize(control.session_ctx, text[], boolean, text, uuid) TO control_audit_owner;
GRANT EXECUTE ON FUNCTION control.err(text) TO control_audit_owner;
ALTER FUNCTION control.api_audit_list(text, integer, bigint)       OWNER TO control_audit_owner;
ALTER FUNCTION control.api_audit_verify(text)                      OWNER TO control_audit_owner;
ALTER FUNCTION control.api_anchor_list(text)                       OWNER TO control_audit_owner;
ALTER FUNCTION control.api_anchor_export(text, bigint)             OWNER TO control_audit_owner;
ALTER FUNCTION control.api_audit_export(text, bigint, bigint)      OWNER TO control_audit_owner;
DROP POLICY audit_events_definer_read  ON control.audit_events;
DROP POLICY audit_anchors_definer_read ON control.audit_anchors;
DROP POLICY audit_actions_definer_read ON control.audit_actions;
REVOKE ALL ON control.audit_events, control.audit_anchors, control.audit_actions FROM control_definer;
REVOKE EXECUTE ON FUNCTION control.audit_canonical(bigint, timestamptz, text, uuid, text, text, text, text, text, uuid, text, jsonb) FROM control_definer;
REVOKE EXECUTE ON FUNCTION control.b64url_encode(bytea) FROM control_definer;

-- ------------------------------------------------------------ recovery: contest is a bounded delay, never a veto
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
END
$$;
ALTER FUNCTION control.recovery_reopen_contested(uuid, boolean) OWNER TO control_auth;

CREATE OR REPLACE FUNCTION control.api_recovery_cancel(p_token text, p_request uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token); r control.recovery_requests; v_code text;
BEGIN
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  PERFORM 1 FROM control.enrolment_tokens WHERE recovery_request_id = p_request FOR UPDATE;
  SELECT * INTO r FROM control.recovery_requests WHERE id = p_request FOR UPDATE;
  IF r.id IS NULL OR r.state NOT IN ('pending', 'approved') OR r.expires_at <= clock_timestamp() THEN v_code := 'NOT_FOUND';
  ELSIF r.subject_id <> c.identity_id AND c.role <> 'owner' THEN v_code := 'FORBIDDEN';
  ELSIF NOT control.stepup_consume_token(p_token, 'recovery_cancel', r.id::text) THEN v_code := 'STEPUP_REQUIRED';
  END IF;
  IF v_code IS NOT NULL THEN
    PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'platform.recovery_refused', 'denied',
      'recovery_request', p_request::text, NULL, v_code, '{}'::jsonb);
    RETURN control.err(v_code);
  END IF;
  IF r.subject_id = c.identity_id THEN
    -- objection: voids any outstanding link, returns the request to pending, clears host confirmation
    PERFORM control.recovery_reopen_contested(r.id, true);
    PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'platform.recovery_contested', 'success',
      'recovery_request', r.id::text, NULL, NULL, jsonb_build_object('was_approved', r.state = 'approved'));
    RETURN jsonb_build_object('ok', true, 'contested', true, 'link_voided', r.state = 'approved');
  END IF;
  PERFORM control.recovery_cancel_internal(r.id, c.identity_id::text);
  PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'platform.recovery_cancelled', 'success',
    'recovery_request', r.id::text, NULL, NULL, '{}'::jsonb);
  RETURN jsonb_build_object('ok', true, 'contested', false);
END
$$;

DROP FUNCTION control.host_revoke_operator_credentials(text, text);
CREATE FUNCTION control.host_revoke_operator_credentials(p_email text, p_reason text, p_force boolean DEFAULT false) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE i control.platform_identities; v_s integer; v_c integer; x record;
BEGIN
  IF p_reason IS NULL OR length(btrim(p_reason)) < 10 THEN RETURN control.err('REASON_REQUIRED'); END IF;
  SELECT * INTO i FROM control.platform_identities WHERE email = lower(btrim(p_email)) FOR NO KEY UPDATE;
  IF i.id IS NULL THEN RETURN control.err('NOT_FOUND'); END IF;
  IF i.role = 'owner' AND NOT coalesce(p_force, false) AND NOT EXISTS (
       SELECT 1 FROM control.platform_identities o JOIN control.webauthn_credentials w ON w.identity_id = o.id
        WHERE o.id <> i.id AND o.role = 'owner' AND o.state = 'active' AND w.disabled_at IS NULL AND w.usable_after <= now()) THEN
    RETURN control.err('LAST_OWNER');   -- would make recovery impossible; requires p_force
  END IF;
  UPDATE control.platform_identities SET emergency_revoked_at = clock_timestamp() WHERE id = i.id;
  UPDATE control.sessions SET revoked_at = now(), revoke_reason = 'admin' WHERE identity_id = i.id AND revoked_at IS NULL;
  GET DIAGNOSTICS v_s = ROW_COUNT;
  UPDATE control.webauthn_credentials SET disabled_at = now(), disabled_reason = 'host_revoked' WHERE identity_id = i.id AND disabled_at IS NULL;
  GET DIAGNOSTICS v_c = ROW_COUNT;
  UPDATE control.stepup_grants SET used_at = now() WHERE identity_id = i.id AND used_at IS NULL;
  FOR x IN SELECT id FROM control.recovery_requests WHERE subject_id = i.id AND state IN ('pending', 'approved') LOOP
    PERFORM control.recovery_reopen_contested(x.id, false);   -- approved links voided; confirmation cleared
  END LOOP;
  PERFORM control.audit_append('cli', NULL, 'host-emergency', 'platform.operator_credentials_revoked', 'success',
    'platform_identity', i.id::text, NULL, 'EMERGENCY',
    jsonb_build_object('credentials_disabled', v_c, 'sessions_revoked', v_s, 'forced', coalesce(p_force, false),
                       'reason', left(btrim(p_reason), 200)));
  RETURN jsonb_build_object('ok', true, 'credentials_disabled', v_c, 'sessions_revoked', v_s);
END
$$;
ALTER FUNCTION control.host_revoke_operator_credentials(text, text, boolean) OWNER TO control_auth;

-- A new request inherits a recent objection (re-filing does not wipe the contest).
CREATE OR REPLACE FUNCTION control.host_recovery_request(p_email text, p_reason text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE i control.platform_identities; v_id uuid; x record; v_prior timestamptz;
        v_ttl interval := make_interval(secs => control.setting_int('recovery_request_ttl_seconds'));
BEGIN
  SELECT * INTO i FROM control.platform_identities WHERE email = lower(btrim(p_email)) AND state = 'active';
  IF i.id IS NULL THEN RETURN control.err('NOT_FOUND'); END IF;
  FOR x IN SELECT id FROM control.recovery_requests WHERE subject_id = i.id AND state IN ('pending', 'approved') AND expires_at <= clock_timestamp() LOOP
    PERFORM control.recovery_cancel_internal(x.id, 'expired');
  END LOOP;
  SELECT max(last_contested_at) INTO v_prior FROM control.recovery_requests
   WHERE subject_id = i.id AND last_contested_at > clock_timestamp() - v_ttl;
  BEGIN
    INSERT INTO control.recovery_requests (subject_id, reason, expires_at, contested_at, last_contested_at)
    VALUES (i.id, btrim(p_reason), clock_timestamp() + v_ttl, v_prior, v_prior)
    RETURNING id INTO v_id;
  EXCEPTION WHEN unique_violation THEN RETURN control.err('ALREADY_OPEN');
            WHEN check_violation OR not_null_violation THEN RETURN control.err('REASON_REQUIRED');
  END;
  IF v_prior IS NOT NULL THEN
    PERFORM control.recovery_reopen_contested(v_id, false);   -- extends the lifetime so delay + window fit
  END IF;
  PERFORM control.audit_append('cli', NULL, 'host-recovery', 'platform.recovery_requested', 'success',
    'recovery_request', v_id::text, NULL, NULL, jsonb_build_object('subject', i.id, 'inherits_contest', v_prior IS NOT NULL));
  RETURN jsonb_build_object('ok', true, 'request_id', v_id, 'contested', v_prior IS NOT NULL);
END
$$;

CREATE OR REPLACE FUNCTION control.host_recovery_confirm(p_request uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
BEGIN
  UPDATE control.recovery_requests SET host_confirmed_at = clock_timestamp()
   WHERE id = p_request AND state = 'pending' AND expires_at > clock_timestamp();
  IF NOT FOUND THEN RETURN control.err('NOT_FOUND'); END IF;
  PERFORM control.audit_append('cli', NULL, 'host-recovery', 'platform.recovery_host_confirmed', 'success',
    'recovery_request', p_request::text, NULL, NULL, '{}'::jsonb);
  RETURN jsonb_build_object('ok', true);
END
$$;

CREATE OR REPLACE FUNCTION control.api_recovery_approve(p_token text, p_request uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token); r control.recovery_requests; v_code text; v_tok text;
        v_until timestamptz; v_contested boolean; v_subject control.platform_identities; v_now timestamptz := clock_timestamp();
        v_activity timestamptz; v_confirm_after timestamptz; v_delay_from timestamptz;
BEGIN
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  SELECT * INTO r FROM control.recovery_requests WHERE id = p_request FOR UPDATE;
  SELECT * INTO v_subject FROM control.platform_identities WHERE id = r.subject_id;
  SELECT max(last_used_at) INTO v_activity FROM control.webauthn_credentials
   WHERE identity_id = r.subject_id AND last_used_at > r.requested_at AND counter_suspect_at IS NULL AND disabled_at IS NULL;
  v_contested := coalesce(r.contested_at IS NOT NULL OR v_activity IS NOT NULL
    OR v_subject.emergency_revoked_at >= r.requested_at - make_interval(secs => control.setting_int('recovery_request_ttl_seconds')), false);
  -- confirmation must post-date the LATEST objection / activity / emergency revoke;
  -- the delay runs from the FIRST objection (or the request, or the revoke) and never restarts
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

CREATE OR REPLACE FUNCTION control.api_enrol_begin(p_token text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE t control.enrolment_tokens; i control.platform_identities; v_ch text; r control.recovery_requests; v_now timestamptz;
BEGIN
  PERFORM control.assert_fresh_transaction();
  v_now := clock_timestamp();
  SELECT * INTO t FROM control.enrolment_tokens WHERE p_token ~ '^[0-9a-f]{64}$' AND token_hash = control.sha(p_token);
  IF t.recovery_request_id IS NOT NULL THEN SELECT * INTO r FROM control.recovery_requests WHERE id = t.recovery_request_id; END IF;
  IF t.token_hash IS NULL OR t.used_at IS NOT NULL OR t.expires_at <= v_now
     OR (t.purpose = 'recovery' AND (r.state IS DISTINCT FROM 'approved' OR r.expires_at <= v_now)) THEN
    IF control.rate_limit_hit('enrol_invalid', 'global', control.setting_int('enrol_invalid_limit')) THEN
      PERFORM control.audit_append('anonymous', NULL, NULL, 'platform.enrol_failed', 'denied', NULL, NULL, NULL, 'INVALID_TOKEN', '{}'::jsonb);
    END IF;
    RETURN control.err('INVALID_TOKEN');
  END IF;
  IF NOT control.rate_limit_hit('enrol_token', encode(t.token_hash, 'hex'), control.setting_int('enrol_token_limit')) THEN
    RETURN control.err('RATE_LIMITED');
  END IF;
  SELECT * INTO i FROM control.platform_identities WHERE id = t.identity_id;
  IF (t.purpose = 'owner_bootstrap' AND i.state <> 'enrolling') OR (t.purpose = 'recovery' AND i.state <> 'active') THEN
    RETURN control.err('INVALID_TOKEN');
  END IF;
  v_ch := control.challenge_issue('register', i.id, NULL, 'enrol', encode(t.token_hash, 'hex'));
  RETURN jsonb_build_object('ok', true, 'challenge', v_ch, 'identity_id', i.id, 'email', i.email,
    'display_name', i.display_name, 'purpose', t.purpose,
    'expires_in_seconds', greatest(0, extract(epoch FROM t.expires_at - v_now)::integer),
    'exclude_credential_ids', (SELECT coalesce(jsonb_agg(credential_id), '[]'::jsonb) FROM control.webauthn_credentials
                                WHERE identity_id = i.id AND disabled_at IS NULL));
END
$$;

-- As 208, plus: fresh transaction; recovery redemption refuses if an objection or emergency revoke post-dates approval.
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

CREATE OR REPLACE FUNCTION control.api_contract_version() RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = control, pg_temp AS $$
  SELECT 'orvix-control/0.3'::text
$$;

-- ------------------------------------------------------------ grants
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA control FROM PUBLIC;
GRANT EXECUTE ON FUNCTION control.assert_fresh_transaction() TO control_auth;
GRANT EXECUTE ON FUNCTION control.audit_safe_detail_d(jsonb, integer) TO control_audit_owner;
GRANT EXECUTE ON FUNCTION control.audit_safe_detail(jsonb) TO control_audit_owner;
GRANT EXECUTE ON FUNCTION control.api_contract_version() TO control_app;
-- host_* : no grants (superuser only).
