-- ============================================================
-- 207: fixes from the four independent reviews of 204–206 (docs/REVIEW_C1_1.md has the full list)
--
-- HIGH  P-F1  control_definer could hijack control_auth / control_audit_owner: it owned schema `control` and
--             the invoker-rights helpers (crypto, sha, new_secret, err, b64url) that those roles execute, and it
--             owned control.settings (WebAuthn origin / RP ID). It could also shadow pg_catalog functions.
--             FIX: schema `control` and every shared invoker-rights helper now belong to control_schema_owner,
--             a NOLOGIN role that no function ever runs as (it owns no SECURITY DEFINER function). No runtime
--             role keeps CREATE on any schema. Settings, rate limits and their accessors move to control_auth;
--             session_ctx moves to control_auth. A test enforces: every invoker-rights function a runtime role
--             can execute is owned by that role or by control_schema_owner.
-- MED   counter regression no longer disables a passkey (it could remove the last one and lock out a
--             single-owner install): the assertion is refused and the passkey is FLAGGED for the operator.
-- MED   recovery tokens are bound to their request (approved, unexpired, locked); requests can be cancelled
--             (host or another owner with step-up); cancelling kills outstanding tokens; approval refuses when
--             the subject has used a passkey since the request (silent-takeover guard).
-- MED   enrolment rate limit is per token (no global lockout); invalid tokens share a separate bucket.
-- MED   api_auth_failed writes an audit row only for a challenge that existed, attributes it to "anonymous"
--             (the claimed credential goes in detail), and is rate-limited.
-- MED   passkeys added in-session are PENDING for 15 minutes (cannot sign in or step up), visible and
--             revocable from every session: a relayed ceremony no longer yields an immediately usable backdoor.
-- MED   advisory locks (callable by control_app) replaced by row locks on owner-only tables.
-- LOW   lock order identity -> sessions -> credentials -> grants everywhere (revoke vs step-up deadlock);
--             step-up grants die with their passkey; strict bounds in wa_registration; anchor insert looks up
--             the signer's credential and is NULL-safe; unique public keys; bootstrap token can be re-issued while
--             the owner is still enrolling; global default privileges actually revoke PUBLIC EXECUTE;
--             large-object creation revoked from PUBLIC; stepup_consume takes the session TOKEN (a caller can no
--             longer forge a session context to consume another session's grants).
-- ROLLBACK Restore from the pre-207 recovery point (ownership model change).
-- ============================================================

-- ------------------------------------------------------------ preflight: role attributes are what we expect
DO $chk$
DECLARE r record;
BEGIN
  FOR r IN SELECT rolname, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolreplication, rolcanlogin
             FROM pg_roles WHERE rolname IN ('control_app', 'control_auth', 'control_definer', 'control_audit_owner') LOOP
    IF r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication
       OR r.rolcanlogin <> (r.rolname = 'control_app') THEN
      RAISE EXCEPTION 'role % has unexpected attributes', r.rolname;
    END IF;
  END LOOP;
  IF EXISTS (SELECT 1 FROM pg_auth_members m JOIN pg_roles a ON a.oid = m.roleid OR a.oid = m.member
              WHERE a.rolname IN ('control_app', 'control_auth', 'control_definer', 'control_audit_owner')) THEN
    RAISE EXCEPTION 'a control role has role memberships';
  END IF;
END
$chk$;

DO $r$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'control_schema_owner') THEN
    CREATE ROLE control_schema_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
  END IF;
END
$r$;

-- ------------------------------------------------------------ P-F1: neutral schema owner, no runtime CREATE
ALTER SCHEMA control OWNER TO control_schema_owner;
REVOKE ALL ON SCHEMA control FROM PUBLIC, control_definer, control_auth, control_audit_owner, control_app;
GRANT USAGE ON SCHEMA control TO control_definer, control_auth, control_audit_owner, control_app;
REVOKE CREATE ON SCHEMA control_ext FROM PUBLIC;
GRANT USAGE ON SCHEMA control_ext TO control_schema_owner;

-- Pure / invoker-rights helpers executed by more than one role -> control_schema_owner.
ALTER FUNCTION control.err(text)                       OWNER TO control_schema_owner;
ALTER FUNCTION control.sha(text)                       OWNER TO control_schema_owner;
ALTER FUNCTION control.new_secret()                    OWNER TO control_schema_owner;
ALTER FUNCTION control.b64url_encode(bytea)            OWNER TO control_schema_owner;
ALTER FUNCTION control.b64url_decode(text)             OWNER TO control_schema_owner;
ALTER FUNCTION control.b2n(bytea)                      OWNER TO control_schema_owner;
ALTER FUNCTION control.modp(numeric, numeric)          OWNER TO control_schema_owner;
ALTER FUNCTION control.modpow(numeric, numeric, numeric) OWNER TO control_schema_owner;
ALTER FUNCTION control.p256_p()                        OWNER TO control_schema_owner;
ALTER FUNCTION control.p256_n()                        OWNER TO control_schema_owner;
ALTER FUNCTION control.p256_b()                        OWNER TO control_schema_owner;
ALTER FUNCTION control.p256_gx()                       OWNER TO control_schema_owner;
ALTER FUNCTION control.p256_gy()                       OWNER TO control_schema_owner;
ALTER FUNCTION control.p256_on_curve(numeric, numeric) OWNER TO control_schema_owner;
ALTER FUNCTION control.p256_dbl(numeric[])             OWNER TO control_schema_owner;
ALTER FUNCTION control.p256_add(numeric[], numeric[])  OWNER TO control_schema_owner;
ALTER FUNCTION control.p256_verify(numeric, numeric, numeric, numeric, numeric) OWNER TO control_schema_owner;
ALTER FUNCTION control.der_ecdsa_sig(bytea)            OWNER TO control_schema_owner;
ALTER FUNCTION control.cose_es256_xy(bytea)            OWNER TO control_schema_owner;
ALTER FUNCTION control.es256_verify(bytea, bytea, bytea) OWNER TO control_schema_owner;
ALTER FUNCTION control.anchor_challenge(bigint, bytea, bytea) OWNER TO control_schema_owner;
ALTER FUNCTION control.audit_canonical(bigint, timestamptz, text, uuid, text, text, text, text, text, uuid, text, jsonb) OWNER TO control_schema_owner;
ALTER FUNCTION control.audit_row_hash(bytea, text)     OWNER TO control_schema_owner;

-- Settings (WebAuthn origin / RP ID, TTLs) and rate limits belong to the auth owner.
ALTER TABLE control.settings    OWNER TO control_auth;
ALTER TABLE control.rate_limits OWNER TO control_auth;
ALTER FUNCTION control.setting_int(text)                   OWNER TO control_auth;
ALTER FUNCTION control.setting_text(text)                  OWNER TO control_auth;
ALTER FUNCTION control.rate_limit_hit(text, text, integer) OWNER TO control_auth;
ALTER TYPE control.session_ctx OWNER TO control_auth;

-- Default privileges: the GLOBAL form is the one that removes PUBLIC EXECUTE (the IN SCHEMA form cannot).
ALTER DEFAULT PRIVILEGES FOR ROLE control_definer      REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE control_auth         REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE control_audit_owner  REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES FOR ROLE control_schema_owner REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

-- Large objects would let control_app fill the disk.
REVOKE EXECUTE ON FUNCTION pg_catalog.lo_create(oid), pg_catalog.lo_creat(integer), pg_catalog.lo_from_bytea(oid, bytea)
  FROM PUBLIC;

-- ------------------------------------------------------------ schema changes
ALTER TABLE control.webauthn_credentials
  ADD COLUMN usable_after       timestamptz NOT NULL DEFAULT '-infinity',
  ADD COLUMN counter_suspect_at timestamptz;
CREATE UNIQUE INDEX webauthn_credentials_public_key_uq ON control.webauthn_credentials (sha256(public_key));

ALTER TABLE control.recovery_requests DROP CONSTRAINT recovery_requests_state_check;
ALTER TABLE control.recovery_requests ADD CONSTRAINT recovery_requests_state_check
  CHECK (state IN ('pending', 'approved', 'redeemed', 'cancelled'));
ALTER TABLE control.recovery_requests ADD COLUMN cancelled_at timestamptz, ADD COLUMN cancelled_by text;

INSERT INTO control.settings (key, value) VALUES
  ('credential_activation_delay_seconds', '900'),
  ('enrol_invalid_limit',                  '30'),
  ('auth_failed_limit',                    '60');

INSERT INTO control.audit_actions (action, description) VALUES
  ('platform.credential_counter_regression', 'Validly signed assertion with a non-increasing counter refused; passkey flagged'),
  ('platform.recovery_cancelled',            'Recovery request cancelled; any outstanding token voided'),
  ('platform.owner_bootstrap_reissued',      'Expired owner enrolment link re-issued by the host');

-- Row locks replace advisory locks (advisory-lock functions are callable by every role, including control_app).
GRANT CREATE ON SCHEMA control TO control_audit_owner;
SET ROLE control_audit_owner;
CREATE TABLE control.audit_lock (singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton));
INSERT INTO control.audit_lock DEFAULT VALUES;
ALTER TABLE control.audit_lock ENABLE ROW LEVEL SECURITY;
RESET ROLE;
REVOKE CREATE ON SCHEMA control FROM control_audit_owner;
REVOKE ALL ON control.audit_lock FROM PUBLIC;

-- ============================================================ audit owner functions (CREATE OR REPLACE keeps owner/ACL)
CREATE OR REPLACE FUNCTION control.audit_append(
  p_actor_type text, p_actor_id uuid, p_actor_label text, p_action text, p_outcome text,
  p_target_type text DEFAULT NULL, p_target_id text DEFAULT NULL, p_request_id uuid DEFAULT NULL,
  p_reason_code text DEFAULT NULL, p_detail jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE v_prev_seq bigint; v_prev_hash bytea; v_seq bigint; v_at timestamptz := date_trunc('microseconds', clock_timestamp()); v_hash bytea;
BEGIN
  PERFORM 1 FROM control.audit_lock FOR UPDATE;
  SELECT seq, row_hash INTO v_prev_seq, v_prev_hash FROM control.audit_events ORDER BY seq DESC LIMIT 1;
  IF v_prev_seq IS NULL THEN RAISE EXCEPTION 'AUDIT_NO_GENESIS'; END IF;
  v_seq := v_prev_seq + 1;
  v_hash := control.audit_row_hash(v_prev_hash, control.audit_canonical(v_seq, v_at, p_actor_type, p_actor_id, p_actor_label,
            p_action, p_outcome, p_target_type, p_target_id, p_request_id, p_reason_code, p_detail));
  PERFORM set_config('control.audit_writer', 'on', true);
  INSERT INTO control.audit_events (seq, occurred_at, actor_type, actor_id, actor_label, action, outcome,
                                    target_type, target_id, request_id, reason_code, detail, prev_hash, row_hash)
  VALUES (v_seq, v_at, p_actor_type, p_actor_id, p_actor_label, p_action, p_outcome, p_target_type, p_target_id,
          p_request_id, p_reason_code, coalesce(p_detail, '{}'::jsonb), v_prev_hash, v_hash);
  PERFORM set_config('control.audit_writer', '', true);
  RETURN v_seq;
END
$$;

CREATE OR REPLACE FUNCTION control.audit_anchor_insert(p_created_by uuid, p_note text) RETURNS TABLE (seq bigint, head_hash text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE v_seq bigint; v_hash bytea;
BEGIN
  PERFORM 1 FROM control.audit_lock FOR UPDATE;
  SELECT e.seq, e.row_hash INTO v_seq, v_hash FROM control.audit_events e ORDER BY e.seq DESC LIMIT 1;
  INSERT INTO control.audit_anchors (seq, head_hash, created_by, note) VALUES (v_seq, v_hash, p_created_by, p_note);
  RETURN QUERY SELECT v_seq, encode(v_hash, 'hex');
END
$$;

-- Re-verification that does not trust the caller: the signer's credential is looked up (active, owner, ES256)
-- and every clientData comparison is NULL-safe.
GRANT SELECT ON control.webauthn_credentials, control.platform_identities TO control_audit_owner;
CREATE POLICY credentials_audit_read ON control.webauthn_credentials FOR SELECT TO control_audit_owner USING (true);
CREATE POLICY identities_audit_read  ON control.platform_identities  FOR SELECT TO control_audit_owner USING (true);
CREATE OR REPLACE FUNCTION control.audit_anchor_insert_signed(p_seq bigint, p_head bytea, p_nonce bytea, p_signer uuid,
  p_signer_label text, p_credential_id text, p_public_key bytea, p_client_data bytea, p_authenticator_data bytea,
  p_signature bytea, p_note text) RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE cd jsonb; v_id bigint; v_key bytea; v_label text;
        v_rp text := control.setting_text('webauthn_rp_id'); v_origin text := control.setting_text('webauthn_origin');
BEGIN
  PERFORM 1 FROM control.audit_lock FOR UPDATE;
  IF NOT EXISTS (SELECT 1 FROM control.audit_events WHERE seq = p_seq AND row_hash = p_head) THEN
    RAISE EXCEPTION 'ANCHOR_HEAD_MISMATCH';
  END IF;
  SELECT c.public_key, i.display_name INTO v_key, v_label
    FROM control.webauthn_credentials c JOIN control.platform_identities i ON i.id = c.identity_id
   WHERE c.credential_id = p_credential_id AND c.identity_id = p_signer AND c.disabled_at IS NULL
     AND c.usable_after <= now() AND i.state = 'active' AND i.role = 'owner';
  IF v_key IS NULL OR v_key IS DISTINCT FROM p_public_key THEN RAISE EXCEPTION 'ANCHOR_SIGNER_INVALID'; END IF;
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
     OR NOT control.es256_verify(v_key, p_authenticator_data || sha256(p_client_data), p_signature) THEN
    RAISE EXCEPTION 'ANCHOR_SIGNATURE_INVALID';
  END IF;
  INSERT INTO control.audit_anchors (seq, head_hash, created_by, note, nonce, signer_identity, signer_label, credential_id,
    public_key, rp_id, origin, client_data, authenticator_data, signature)
  VALUES (p_seq, p_head, p_signer, left(p_note, 200), p_nonce, p_signer, v_label, p_credential_id, v_key,
    v_rp, v_origin, p_client_data, p_authenticator_data, p_signature)
  RETURNING id INTO v_id;
  RETURN v_id;
END
$$;

-- ============================================================ auth owner functions
-- Lock order everywhere: identity -> sessions -> credentials -> grants.

-- Only the session TOKEN can consume a grant (a caller can no longer forge a session context). The grant's
-- passkey must still be active.
CREATE FUNCTION control.stepup_consume_token(p_token text, p_action text, p_target text) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE v_id bigint;
BEGIN
  IF p_token IS NULL OR p_token !~ '^[0-9a-f]{64}$' THEN RETURN false; END IF;
  SELECT g.id INTO v_id FROM control.stepup_grants g
    JOIN control.sessions s ON s.id_hash = g.session_id_hash AND s.revoked_at IS NULL
    JOIN control.webauthn_credentials w ON w.credential_id = g.credential_id AND w.disabled_at IS NULL
   WHERE g.session_id_hash = control.sha(p_token) AND g.action = p_action AND g.target = p_target
     AND g.used_at IS NULL AND g.expires_at > now()
   ORDER BY g.id LIMIT 1 FOR UPDATE OF g SKIP LOCKED;
  IF v_id IS NULL THEN RETURN false; END IF;
  UPDATE control.stepup_grants SET used_at = now() WHERE id = v_id;
  RETURN true;
END
$$;
ALTER FUNCTION control.stepup_consume_token(text, text, text) OWNER TO control_auth;
REVOKE EXECUTE ON FUNCTION control.stepup_consume(control.session_ctx, text, text) FROM control_definer;
DROP FUNCTION control.stepup_consume(control.session_ctx, text, text);

-- Same checks as 205, plus: a PENDING passkey cannot assert, and a counter regression is refused and FLAGGED
-- (never auto-disabled: that could remove an operator's last passkey).
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
  IF c.usable_after > now() THEN err := 'CREDENTIAL_PENDING'; RETURN; END IF;
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
    UPDATE control.webauthn_credentials SET counter_suspect_at = now() WHERE id = c.id;
    PERFORM control.audit_append('platform_identity', i.id, i.display_name, 'platform.credential_counter_regression', 'denied',
      'credential', c.id::text, NULL, 'COUNTER_REGRESSION', jsonb_build_object('stored', c.sign_count, 'presented', v_count));
    err := 'COUNTER_REGRESSION'; RETURN;
  END IF;
  UPDATE control.webauthn_credentials SET sign_count = v_count, last_used_at = now() WHERE id = c.id;
END
$$;

-- Same as 205 with strict bounds before every byte read.
CREATE OR REPLACE FUNCTION control.wa_registration(p_purpose text, p_att bytea, p_cdj bytea,
                                                   OUT err text, OUT ch control.webauthn_challenges,
                                                   OUT cred_id text, OUT cose bytea, OUT sign_count bigint)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE
  cd jsonb; hdr bytea := '\xa363666d74646e6f6e656761747453746d74a0686175746844617461'::bytea;
  ad bytea; adlen integer; start integer; v_flags integer; l integer; rest integer;
BEGIN
  cd := control.wa_client_data(p_cdj, 'webauthn.create');
  IF cd IS NULL THEN err := 'BAD_CLIENT_DATA'; RETURN; END IF;
  ch := control.challenge_consume(cd ->> 'challenge', p_purpose);
  IF ch.challenge_hash IS NULL THEN err := 'INVALID_CHALLENGE'; RETURN; END IF;
  IF p_att IS NULL OR length(p_att) < 32 OR length(p_att) > 2048 OR substring(p_att FROM 1 FOR 28) <> hdr THEN
    err := 'UNSUPPORTED_ATTESTATION'; RETURN;
  END IF;
  IF get_byte(p_att, 28) = 88 THEN adlen := get_byte(p_att, 29); start := 31;
  ELSIF get_byte(p_att, 28) = 89 THEN adlen := get_byte(p_att, 29) * 256 + get_byte(p_att, 30); start := 32;
  ELSE err := 'UNSUPPORTED_ATTESTATION'; RETURN;
  END IF;
  IF start - 1 + adlen <> length(p_att) THEN err := 'UNSUPPORTED_ATTESTATION'; RETURN; END IF;
  ad := substring(p_att FROM start FOR adlen);
  IF length(ad) < 55 + 16 + 77 THEN err := 'BAD_AUTHENTICATOR_DATA'; RETURN; END IF;
  IF substring(ad FROM 1 FOR 32) IS DISTINCT FROM sha256(convert_to(control.setting_text('webauthn_rp_id'), 'UTF8')) THEN
    err := 'RP_ID_MISMATCH'; RETURN;
  END IF;
  v_flags := get_byte(ad, 32);
  IF v_flags & 1 = 0 OR v_flags & 4 = 0 THEN err := 'USER_NOT_VERIFIED'; RETURN; END IF;
  IF v_flags & 64 = 0 THEN err := 'BAD_AUTHENTICATOR_DATA'; RETURN; END IF;
  sign_count := control.b2n(substring(ad FROM 34 FOR 4))::bigint;
  l := get_byte(ad, 53) * 256 + get_byte(ad, 54);
  IF l < 16 OR l > 1023 OR length(ad) < 55 + l + 77 THEN err := 'BAD_AUTHENTICATOR_DATA'; RETURN; END IF;
  cose := substring(ad FROM 56 + l FOR 77);
  IF control.cose_es256_xy(cose) IS NULL THEN err := 'UNSUPPORTED_KEY'; RETURN; END IF;
  rest := length(ad) - (55 + l + 77);
  IF rest > 0 AND v_flags & 128 = 0 THEN err := 'BAD_AUTHENTICATOR_DATA'; RETURN; END IF;
  cred_id := control.b64url_encode(substring(ad FROM 56 FOR l));
END
$$;

-- Host-only bootstrap; re-issues the link (and only the link) while the first owner is still enrolling.
CREATE OR REPLACE FUNCTION control.host_bootstrap_owner(p_email text, p_display_name text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE v_id uuid; v_token text := control.new_secret(); v_email text := lower(btrim(p_email)); v_state text; v_n integer;
BEGIN
  PERFORM 1 FROM control.bootstrap_state FOR UPDATE;
  SELECT count(*) INTO v_n FROM control.platform_identities;
  SELECT id, state INTO v_id, v_state FROM control.platform_identities WHERE email = v_email;
  IF NOT (SELECT closed FROM control.bootstrap_state) AND v_n = 1 AND v_state = 'enrolling'
     AND NOT EXISTS (SELECT 1 FROM control.enrolment_tokens WHERE identity_id = v_id AND used_at IS NULL AND expires_at > now()) THEN
    INSERT INTO control.enrolment_tokens (token_hash, identity_id, purpose, expires_at)
    VALUES (control.sha(v_token), v_id, 'owner_bootstrap', now() + make_interval(secs => control.setting_int('enrolment_token_ttl_seconds')));
    PERFORM control.audit_append('cli', NULL, 'host-bootstrap', 'platform.owner_bootstrap_reissued', 'success',
      'platform_identity', v_id::text, NULL, NULL, '{}'::jsonb);
    RETURN jsonb_build_object('ok', true, 'identity_id', v_id, 'enrolment_token', v_token, 'reissued', true,
                              'expires_in_seconds', control.setting_int('enrolment_token_ttl_seconds'));
  END IF;
  IF (SELECT closed FROM control.bootstrap_state) OR v_n > 0 THEN
    PERFORM control.audit_append('cli', NULL, 'host-bootstrap', 'platform.owner_bootstrap_refused', 'denied',
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
  VALUES (control.sha(v_token), v_id, 'owner_bootstrap', now() + make_interval(secs => control.setting_int('enrolment_token_ttl_seconds')));
  PERFORM control.audit_append('cli', NULL, 'host-bootstrap', 'platform.owner_bootstrap_started', 'success',
    'platform_identity', v_id::text, NULL, NULL, jsonb_build_object('email_domain', split_part(v_email, '@', 2)));
  RETURN jsonb_build_object('ok', true, 'identity_id', v_id, 'enrolment_token', v_token,
                            'expires_in_seconds', control.setting_int('enrolment_token_ttl_seconds'));
END
$$;

-- Rate limit per token (a valid link cannot be locked out by strangers); invalid tokens share their own bucket.
CREATE OR REPLACE FUNCTION control.api_enrol_begin(p_token text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE t control.enrolment_tokens; i control.platform_identities; v_ch text; r control.recovery_requests;
BEGIN
  SELECT * INTO t FROM control.enrolment_tokens WHERE p_token ~ '^[0-9a-f]{64}$' AND token_hash = control.sha(p_token);
  IF t.recovery_request_id IS NOT NULL THEN SELECT * INTO r FROM control.recovery_requests WHERE id = t.recovery_request_id; END IF;
  IF t.token_hash IS NULL OR t.used_at IS NOT NULL OR t.expires_at <= now()
     OR (t.purpose = 'recovery' AND (r.state IS DISTINCT FROM 'approved' OR r.expires_at <= now())) THEN
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
    'expires_in_seconds', greatest(0, extract(epoch FROM t.expires_at - now())::integer),
    'exclude_credential_ids', (SELECT coalesce(jsonb_agg(credential_id), '[]'::jsonb) FROM control.webauthn_credentials
                                WHERE identity_id = i.id AND disabled_at IS NULL));
END
$$;

CREATE OR REPLACE FUNCTION control.api_enrol_complete(p_token text, p_attestation bytea, p_client_data bytea, p_nickname text)
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE t control.enrolment_tokens; i control.platform_identities; r control.recovery_requests; reg record;
        v_cred uuid; v_disabled integer; v_sessions integer;
BEGIN
  PERFORM 1 FROM control.bootstrap_state FOR UPDATE;
  SELECT * INTO t FROM control.enrolment_tokens
   WHERE p_token ~ '^[0-9a-f]{64}$' AND token_hash = control.sha(p_token) FOR UPDATE;
  -- identity first (lock order), then the recovery request
  SELECT * INTO i FROM control.platform_identities WHERE id = t.identity_id FOR NO KEY UPDATE;
  IF t.recovery_request_id IS NOT NULL THEN
    SELECT * INTO r FROM control.recovery_requests WHERE id = t.recovery_request_id FOR UPDATE;
  END IF;
  reg := control.wa_registration('register', p_attestation, p_client_data);
  IF t.token_hash IS NULL OR t.used_at IS NOT NULL OR t.expires_at <= now()
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
    -- sessions before credentials (lock order); then the new passkey
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
    -- (if the recovery branch already ran, the exception-free error path below commits nothing harmful:
    --  we raise so the whole transaction, including the disables, rolls back)
    IF v_disabled IS NOT NULL THEN RAISE EXCEPTION 'RECOVERY_ENROL_FAILED'; END IF;
    PERFORM control.audit_append('anonymous', NULL, NULL, 'platform.enrol_failed', 'denied', NULL, NULL, NULL, reg.err, '{}'::jsonb);
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

-- Audits only for a challenge that existed; the claimed credential is NOT used as the actor; rate-limited.
CREATE OR REPLACE FUNCTION control.api_auth_failed(p_purpose text, p_challenge text, p_credential_id text, p_reason text)
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE v_burned boolean;
BEGIN
  IF p_purpose NOT IN ('login', 'stepup', 'register', 'register_add', 'anchor') THEN RETURN control.err('INVALID_INPUT'); END IF;
  UPDATE control.webauthn_challenges SET used_at = now()
   WHERE p_challenge ~ '^[A-Za-z0-9_-]{32,128}$' AND challenge_hash = control.sha(p_challenge) AND used_at IS NULL;
  v_burned := FOUND;
  IF v_burned AND control.rate_limit_hit('auth_failed', 'global', control.setting_int('auth_failed_limit')) THEN
    PERFORM control.audit_append('anonymous', NULL, NULL,
      CASE p_purpose WHEN 'login' THEN 'platform.login_failed' WHEN 'stepup' THEN 'platform.stepup_failed'
                     WHEN 'register_add' THEN 'platform.credential_add_failed' WHEN 'anchor' THEN 'audit.anchor_refused'
                     ELSE 'platform.enrol_failed' END,
      'denied', 'challenge', p_purpose, NULL,
      left(regexp_replace(coalesce(p_reason, 'VERIFICATION_FAILED'), '[^A-Z_]', '', 'g'), 40),
      jsonb_build_object('claimed_credential', left(regexp_replace(coalesce(p_credential_id, ''), '[^A-Za-z0-9_-]', '', 'g'), 8),
                         'precheck', 'app'));
  END IF;
  RETURN jsonb_build_object('ok', true);
END
$$;

CREATE OR REPLACE FUNCTION control.api_session_get(p_token text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token);
BEGIN
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  RETURN jsonb_build_object('ok', true, 'identity_id', c.identity_id, 'email', c.email, 'display_name', c.display_name,
    'role', c.role, 'absolute_expires_at', c.absolute_expires_at, 'idle_expires_at', c.idle_expires_at,
    'active_credentials', (SELECT count(*) FROM control.webauthn_credentials
                            WHERE identity_id = c.identity_id AND disabled_at IS NULL AND usable_after <= now()),
    'pending_credentials', (SELECT count(*) FROM control.webauthn_credentials
                             WHERE identity_id = c.identity_id AND disabled_at IS NULL AND usable_after > now()),
    'flagged_credentials', (SELECT count(*) FROM control.webauthn_credentials
                             WHERE identity_id = c.identity_id AND disabled_at IS NULL AND counter_suspect_at IS NOT NULL));
END
$$;

CREATE OR REPLACE FUNCTION control.api_stepup_begin(p_token text, p_action text, p_target text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token);
BEGIN
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  IF p_action NOT IN ('tenant_transition', 'credential_add', 'credential_revoke', 'recovery_approve', 'recovery_cancel')
     OR p_target IS NULL OR p_target !~ '^[A-Za-z0-9:_-]{1,200}$' THEN
    RETURN control.err('INVALID_INPUT');
  END IF;
  RETURN jsonb_build_object('ok', true,
    'challenge', control.challenge_issue('stepup', c.identity_id, c.id_hash, p_action, p_target),
    'credential_ids', (SELECT coalesce(jsonb_agg(credential_id), '[]'::jsonb) FROM control.webauthn_credentials
                        WHERE identity_id = c.identity_id AND disabled_at IS NULL AND usable_after <= now()));
END
$$;

CREATE OR REPLACE FUNCTION control.api_credential_list(p_token text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token); v_current text;
BEGIN
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  SELECT credential_id INTO v_current FROM control.sessions WHERE id_hash = c.id_hash;
  RETURN jsonb_build_object('ok', true, 'credentials',
    (SELECT coalesce(jsonb_agg(jsonb_build_object('id', w.id, 'nickname', w.nickname, 'created_via', w.created_via,
        'created_at', w.created_at, 'last_used_at', w.last_used_at, 'disabled_at', w.disabled_at,
        'disabled_reason', w.disabled_reason, 'fingerprint', left(w.credential_id, 8),
        'pending_until', CASE WHEN w.usable_after > now() THEN w.usable_after END,
        'counter_suspect_at', w.counter_suspect_at,
        'current', w.credential_id = v_current) ORDER BY w.created_at), '[]'::jsonb)
       FROM control.webauthn_credentials w WHERE w.identity_id = c.identity_id));
END
$$;

-- New passkeys added in-session are PENDING for credential_activation_delay_seconds.
CREATE OR REPLACE FUNCTION control.api_credential_add_complete(p_token text, p_attestation bytea, p_client_data bytea, p_nickname text)
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx; reg record; v_cred uuid; v_until timestamptz;
BEGIN
  PERFORM control.identity_lock_for_session(p_token);
  c := control.session_resolve(p_token);
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  reg := control.wa_registration('register_add', p_attestation, p_client_data);
  IF reg.err IS NULL AND ((reg.ch).identity_id IS DISTINCT FROM c.identity_id OR (reg.ch).session_id_hash IS DISTINCT FROM c.id_hash) THEN
    reg.err := 'INVALID_CHALLENGE';
  END IF;
  IF reg.err IS NULL AND (SELECT count(*) FROM control.webauthn_credentials WHERE identity_id = c.identity_id AND disabled_at IS NULL)
                         >= control.setting_int('max_credentials_per_identity') THEN
    reg.err := 'TOO_MANY_CREDENTIALS';
  END IF;
  v_until := now() + make_interval(secs => control.setting_int('credential_activation_delay_seconds'));
  IF reg.err IS NULL THEN
    BEGIN
      INSERT INTO control.webauthn_credentials (identity_id, credential_id, public_key, sign_count, nickname, created_via, usable_after)
      VALUES (c.identity_id, reg.cred_id, reg.cose, reg.sign_count, nullif(left(btrim(coalesce(p_nickname, '')), 60), ''), 'added', v_until)
      RETURNING id INTO v_cred;
    EXCEPTION WHEN unique_violation OR check_violation THEN
      reg.err := 'INVALID_CREDENTIAL';
    END;
  END IF;
  IF reg.err IS NOT NULL THEN
    PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'platform.credential_add_failed',
      'denied', 'platform_identity', c.identity_id::text, NULL, reg.err, '{}'::jsonb);
    RETURN control.err(reg.err);
  END IF;
  PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'platform.credential_added', 'success',
    'credential', v_cred::text, NULL, NULL, jsonb_build_object('fingerprint', left(reg.cred_id, 8), 'usable_after', v_until));
  RETURN jsonb_build_object('ok', true, 'credential', v_cred, 'usable_after', v_until);
END
$$;

CREATE OR REPLACE FUNCTION control.api_credential_add_begin(p_token text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx; v_code text;
BEGIN
  PERFORM control.identity_lock_for_session(p_token);
  c := control.session_resolve(p_token);
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  IF (SELECT count(*) FROM control.webauthn_credentials WHERE identity_id = c.identity_id AND disabled_at IS NULL)
     >= control.setting_int('max_credentials_per_identity') THEN
    v_code := 'TOO_MANY_CREDENTIALS';
  ELSIF NOT control.stepup_consume_token(p_token, 'credential_add', c.identity_id::text) THEN
    v_code := 'STEPUP_REQUIRED';
  END IF;
  IF v_code IS NOT NULL THEN
    PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'platform.credential_add_failed',
      'denied', 'platform_identity', c.identity_id::text, NULL, v_code, '{}'::jsonb);
    RETURN control.err(v_code);
  END IF;
  RETURN jsonb_build_object('ok', true,
    'challenge', control.challenge_issue('register_add', c.identity_id, c.id_hash, 'credential_add', c.identity_id::text),
    'identity_id', c.identity_id, 'email', c.email, 'display_name', c.display_name,
    'exclude_credential_ids', (SELECT coalesce(jsonb_agg(credential_id), '[]'::jsonb) FROM control.webauthn_credentials
                                WHERE identity_id = c.identity_id AND disabled_at IS NULL));
END
$$;

-- Lock order identity -> sessions -> credential -> grants. A pending passkey can be revoked; the last USABLE
-- (active, not pending) passkey cannot.
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
  ELSIF w.usable_after <= now() AND (SELECT count(*) FROM control.webauthn_credentials
          WHERE identity_id = c.identity_id AND disabled_at IS NULL AND usable_after <= now() AND id <> w.id) < 1 THEN
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
    'was_pending', w.usable_after > now()));
  RETURN jsonb_build_object('ok', true, 'sessions_revoked', v_sessions, 'current_session_ended', v_self);
END
$$;

-- ------------------------------------------------------------ recovery
CREATE FUNCTION control.recovery_cancel_internal(p_request uuid, p_by text) RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE n integer;
BEGIN
  UPDATE control.recovery_requests SET state = 'cancelled', cancelled_at = now(), cancelled_by = p_by
   WHERE id = p_request AND state IN ('pending', 'approved');
  GET DIAGNOSTICS n = ROW_COUNT;
  UPDATE control.enrolment_tokens SET used_at = now() WHERE recovery_request_id = p_request AND used_at IS NULL;
  RETURN n;
END
$$;
ALTER FUNCTION control.recovery_cancel_internal(uuid, text) OWNER TO control_auth;

CREATE OR REPLACE FUNCTION control.host_recovery_request(p_email text, p_reason text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE i control.platform_identities; v_id uuid; x record;
BEGIN
  SELECT * INTO i FROM control.platform_identities WHERE email = lower(btrim(p_email)) AND state = 'active';
  IF i.id IS NULL THEN RETURN control.err('NOT_FOUND'); END IF;
  FOR x IN SELECT id FROM control.recovery_requests WHERE subject_id = i.id AND state IN ('pending', 'approved') AND expires_at <= now() LOOP
    PERFORM control.recovery_cancel_internal(x.id, 'expired');
  END LOOP;
  BEGIN
    INSERT INTO control.recovery_requests (subject_id, reason, expires_at)
    VALUES (i.id, btrim(p_reason), now() + make_interval(secs => control.setting_int('recovery_request_ttl_seconds')))
    RETURNING id INTO v_id;
  EXCEPTION WHEN unique_violation THEN RETURN control.err('ALREADY_OPEN');
            WHEN check_violation OR not_null_violation THEN RETURN control.err('REASON_REQUIRED');
  END;
  PERFORM control.audit_append('cli', NULL, 'host-recovery', 'platform.recovery_requested', 'success',
    'recovery_request', v_id::text, NULL, NULL, jsonb_build_object('subject', i.id));
  RETURN jsonb_build_object('ok', true, 'request_id', v_id);
END
$$;

-- Host-only cancel (no grant).
CREATE FUNCTION control.host_recovery_cancel(p_request uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
BEGIN
  IF control.recovery_cancel_internal(p_request, 'host') = 0 THEN RETURN control.err('NOT_FOUND'); END IF;
  PERFORM control.audit_append('cli', NULL, 'host-recovery', 'platform.recovery_cancelled', 'success',
    'recovery_request', p_request::text, NULL, NULL, '{}'::jsonb);
  RETURN jsonb_build_object('ok', true);
END
$$;
ALTER FUNCTION control.host_recovery_cancel(uuid) OWNER TO control_auth;

-- The subject (if they still have a session) or any other owner may cancel, with a step-up bound to the request.
CREATE FUNCTION control.api_recovery_cancel(p_token text, p_request uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token); r control.recovery_requests; v_code text;
BEGIN
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
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
  PERFORM control.recovery_cancel_internal(r.id, c.identity_id::text);
  PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'platform.recovery_cancelled', 'success',
    'recovery_request', r.id::text, NULL, NULL, '{}'::jsonb);
  RETURN jsonb_build_object('ok', true);
END
$$;
ALTER FUNCTION control.api_recovery_cancel(text, uuid) OWNER TO control_auth;

CREATE OR REPLACE FUNCTION control.api_recovery_list(p_token text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token);
BEGIN
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  RETURN jsonb_build_object('ok', true, 'requests',
    (SELECT coalesce(jsonb_agg(jsonb_build_object('id', r.id, 'subject_display_name', i.display_name, 'subject_email', i.email,
        'subject_id', i.id, 'subject_is_you', r.subject_id = c.identity_id, 'reason', r.reason, 'state', r.state,
        'requested_at', r.requested_at, 'expires_at', r.expires_at) ORDER BY r.requested_at DESC), '[]'::jsonb)
       FROM control.recovery_requests r JOIN control.platform_identities i ON i.id = r.subject_id
      WHERE r.state IN ('pending', 'approved') AND r.expires_at > now()
        AND (c.role = 'owner' OR r.subject_id = c.identity_id)));
END
$$;

CREATE OR REPLACE FUNCTION control.api_recovery_approve(p_token text, p_request uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token); r control.recovery_requests; v_code text; v_tok text;
        v_until timestamptz;
BEGIN
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  SELECT * INTO r FROM control.recovery_requests WHERE id = p_request FOR UPDATE;
  IF c.role <> 'owner' THEN v_code := 'FORBIDDEN';
  ELSIF r.id IS NULL OR r.state <> 'pending' OR r.expires_at <= now() THEN v_code := 'NOT_FOUND';
  ELSIF r.subject_id = c.identity_id THEN v_code := 'SELF_APPROVAL_FORBIDDEN';
  ELSIF NOT EXISTS (SELECT 1 FROM control.platform_identities WHERE id = r.subject_id AND state = 'active') THEN v_code := 'NOT_FOUND';
  -- silent-takeover guard: a subject who has used a passkey since the request did not lose access
  ELSIF EXISTS (SELECT 1 FROM control.webauthn_credentials WHERE identity_id = r.subject_id AND last_used_at > r.requested_at) THEN
    v_code := 'SUBJECT_ACTIVE';
  ELSIF NOT control.stepup_consume_token(p_token, 'recovery_approve', r.id::text) THEN v_code := 'STEPUP_REQUIRED';
  END IF;
  IF v_code IS NOT NULL THEN
    PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'platform.recovery_refused', 'denied',
      'recovery_request', p_request::text, NULL, v_code, '{}'::jsonb);
    RETURN control.err(v_code);
  END IF;
  v_tok := control.new_secret();
  v_until := now() + make_interval(secs => control.setting_int('recovery_token_ttl_seconds'));
  INSERT INTO control.enrolment_tokens (token_hash, identity_id, purpose, expires_at, recovery_request_id)
  VALUES (control.sha(v_tok), r.subject_id, 'recovery', v_until, r.id);
  -- the request now lives exactly as long as its token
  UPDATE control.recovery_requests SET state = 'approved', approved_by = c.identity_id, approved_at = now(), expires_at = v_until
   WHERE id = r.id;
  PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'platform.recovery_approved', 'success',
    'recovery_request', r.id::text, NULL, NULL, jsonb_build_object('subject', r.subject_id));
  RETURN jsonb_build_object('ok', true, 'enrolment_token', v_tok, 'expires_in_seconds', control.setting_int('recovery_token_ttl_seconds'));
END
$$;

-- ============================================================ control_definer: tenant transition uses the token-bound grant
CREATE OR REPLACE FUNCTION control.authorize(c control.session_ctx, p_roles text[], p_need_stepup boolean,
                                             p_action_label text, p_request_id uuid)
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE v_code text;
BEGIN
  IF p_need_stepup THEN RAISE EXCEPTION 'authorize(): step-up must use stepup_consume_token'; END IF;
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  IF NOT (c.role = ANY (p_roles)) THEN v_code := 'FORBIDDEN'; END IF;
  IF v_code IS NULL THEN RETURN NULL; END IF;
  PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'platform.access_denied', 'denied',
    'api', p_action_label, p_request_id, v_code, '{}'::jsonb);
  RETURN control.err(v_code);
END
$$;

CREATE OR REPLACE FUNCTION control.api_tenant_transition(p_token text, p_tenant_id uuid, p_to_state text,
                                                         p_reason_code text, p_note text, p_request_id uuid)
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE
  c control.session_ctx := control.session_resolve(p_token);
  t control.tenants; x control.tenant_transitions; v_code text; v_seq bigint;
  v_prior control.request_results; v_result jsonb;
BEGIN
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  IF p_request_id IS NULL THEN RETURN control.err('REQUEST_ID_REQUIRED'); END IF;
  PERFORM pg_advisory_xact_lock(203, hashtext(p_request_id::text));
  SELECT * INTO v_prior FROM control.request_results WHERE request_id = p_request_id;
  IF v_prior.request_id IS NOT NULL THEN
    IF v_prior.identity_id <> c.identity_id OR v_prior.action <> 'tenant_transition' THEN RETURN control.err('REQUEST_ID_CONFLICT'); END IF;
    RETURN v_prior.result || jsonb_build_object('replayed', true);
  END IF;
  SELECT * INTO t FROM control.tenants WHERE id = p_tenant_id FOR UPDATE;
  IF t.id IS NULL THEN RETURN control.err('NOT_FOUND'); END IF;
  SELECT * INTO x FROM control.tenant_transitions WHERE from_state = t.status AND to_state = p_to_state;
  IF x.from_state IS NULL THEN v_code := 'TRANSITION_NOT_ALLOWED';
  ELSIF NOT x.available THEN v_code := 'NOT_AVAILABLE_IN_FOUNDATION';
  ELSIF NOT (c.role = ANY (x.allowed_roles)) THEN v_code := 'FORBIDDEN';
  ELSIF x.requires_reason AND (p_reason_code IS NULL
        OR p_reason_code NOT IN ('owner_request', 'abuse', 'security', 'notice', 'test', 'other')
        OR length(btrim(coalesce(p_note, ''))) < 10 OR length(p_note) > 500) THEN v_code := 'REASON_REQUIRED';
  ELSIF x.requires_stepup AND NOT control.stepup_consume_token(p_token, 'tenant_transition', t.id::text || ':' || p_to_state) THEN
    v_code := 'STEPUP_REQUIRED';
  END IF;
  IF v_code IS NOT NULL THEN
    PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'tenant.transition_refused',
      'denied', 'tenant', t.id::text, p_request_id, v_code, jsonb_build_object('from', t.status, 'to', p_to_state, 'synthetic', true));
    RETURN control.err(v_code);
  END IF;
  UPDATE control.tenants SET status = p_to_state, status_reason = p_reason_code, status_note = p_note, status_changed_at = now()
   WHERE id = t.id;
  v_seq := control.audit_append('platform_identity', c.identity_id, c.display_name, 'tenant.transitioned', 'success',
    'tenant', t.id::text, p_request_id, p_reason_code, jsonb_build_object('from', t.status, 'to', p_to_state, 'synthetic', true));
  INSERT INTO control.tenant_status_history (tenant_id, from_state, to_state, reason_code, note, actor_id, audit_seq)
  VALUES (t.id, t.status, p_to_state, p_reason_code, p_note, c.identity_id, v_seq);
  v_result := jsonb_build_object('ok', true, 'tenant_id', t.id, 'from', t.status, 'to', p_to_state, 'audit_seq', v_seq);
  INSERT INTO control.request_results (request_id, identity_id, action, result) VALUES (p_request_id, c.identity_id, 'tenant_transition', v_result);
  RETURN v_result;
END
$$;

-- ============================================================ grants
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA control FROM PUBLIC;
-- pure helpers (owned by control_schema_owner) for the roles that call them
GRANT EXECUTE ON FUNCTION control.err(text) TO control_auth, control_definer;
GRANT EXECUTE ON FUNCTION control.sha(text), control.new_secret() TO control_auth;
GRANT EXECUTE ON FUNCTION control.audit_canonical(bigint, timestamptz, text, uuid, text, text, text, text, text, uuid, text, jsonb),
  control.audit_row_hash(bytea, text) TO control_audit_owner;
GRANT EXECUTE ON FUNCTION control.audit_canonical(bigint, timestamptz, text, uuid, text, text, text, text, text, uuid, text, jsonb) TO control_definer;
GRANT EXECUTE ON FUNCTION control.anchor_challenge(bigint, bytea, bytea) TO control_auth, control_audit_owner;
GRANT EXECUTE ON FUNCTION control.setting_text(text) TO control_audit_owner;
GRANT EXECUTE ON FUNCTION control.stepup_consume_token(text, text, text) TO control_definer;
GRANT EXECUTE ON FUNCTION control.api_recovery_cancel(text, uuid) TO control_app;
-- host_recovery_cancel, host_recovery_request, host_bootstrap_owner: no grants (superuser only).
GRANT EXECUTE ON FUNCTION control.b64url_encode(bytea) TO control_definer;
