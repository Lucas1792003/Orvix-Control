-- ============================================================
-- 212: out-of-band security notifications (C1.2, RM-1)
--
-- PROBLEM  A compromised console origin (server code or XSS) can relay one genuine passkey ceremony into any
--          step-up action, e.g. adding its own passkey. The only notice was a same-origin banner served by that
--          same compromised app, so it is not independent.
-- DESIGN   1. Security-relevant audit rows enqueue a notification IN THE SAME TRANSACTION, from an AFTER INSERT
--             trigger on control.audit_events (owner control_audit_owner). The effect and its notification commit
--             or roll back together; control_app has no privilege on the outbox and cannot skip, edit or delete it.
--          2. Delivery is done by a SEPARATE process (scripts/sentinel.ts) under a SEPARATE login role,
--             control_sentinel, whose only rights are EXECUTE on sentinel_claim / sentinel_ack. Its password lives
--             in .env.sentinel, which the web server never loads (and the server refuses to start if it sees it).
--          3. Channels (where notices go) are configured ONLY by the host (host_add_notify_channel, superuser):
--             'file' (append-only JSONL on the host) and 'webhook' (HTTP POST signed with HMAC-SHA256 using a
--             per-channel secret that control_app can never read). Free; no third-party service is required.
--          4. Delivery GATES the dangerous outcomes:
--             - a passkey added in-session becomes usable only after its 'credential_added' notice was delivered to
--               every snapshot channel (and the 15-minute delay passed);
--             - a recovery link can be redeemed only after its 'recovery_approved' notice was delivered;
--             - (215) a new operator can be activated only after its 'operator_enrolled' notice was delivered.
--             No configured channel => not deliverable => the gated action stays blocked (fail closed).
-- LIMITS   Independence holds against a compromised APP (origin, Next.js process, control_app password). It does
--          not hold against a host/superuser compromise, or if the host routes notices to a channel the attacker
--          also controls. In local development the sentinel runs as the same OS user as the app: that separation
--          is by credential only (documented in docs/OOB_NOTIFICATIONS.md).
-- ROLLBACK db/rollback/212-215 restore drill (docs/MIGRATIONS_C1_2.md).
-- ============================================================

DO $r$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'control_sentinel') THEN
    CREATE ROLE control_sentinel LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS
      CONNECTION LIMIT 3;
  END IF;
END
$r$;
ALTER ROLE control_sentinel SET search_path = control, pg_catalog;
ALTER ROLE control_sentinel SET statement_timeout = '10s';
ALTER ROLE control_sentinel SET idle_in_transaction_session_timeout = '10s';
DO $db$ BEGIN EXECUTE format('GRANT CONNECT ON DATABASE %I TO control_sentinel', current_database()); END $db$;
GRANT USAGE ON SCHEMA control TO control_sentinel;

-- Gating applies to items created from now on (older items never had a notice and must not be locked out).
INSERT INTO control.settings (key, value) VALUES ('notify_gate_since', to_jsonb(clock_timestamp()::text));

INSERT INTO control.audit_actions (action, description) VALUES
  ('platform.notify_channel_added', 'Host added an out-of-band notification channel'),
  ('platform.notify_channel_disabled', 'Host disabled an out-of-band notification channel');

-- ------------------------------------------------------------ tables (owner: control_audit_owner)
GRANT CREATE ON SCHEMA control TO control_audit_owner;
SET ROLE control_audit_owner;

CREATE TABLE control.notify_channels (
  id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  recipient   text NOT NULL CHECK (recipient IN ('host', 'identity')),
  identity_id uuid,
  kind        text NOT NULL CHECK (kind IN ('file', 'webhook')),
  target      text NOT NULL CHECK (length(target) BETWEEN 1 AND 500),
  secret      bytea CHECK (secret IS NULL OR length(secret) >= 32),
  enabled     boolean NOT NULL DEFAULT true,
  created_at  timestamptz NOT NULL DEFAULT now(),
  CHECK ((recipient = 'host') = (identity_id IS NULL)),
  CHECK (kind <> 'webhook' OR (secret IS NOT NULL AND target ~ '^https?://'))
);
ALTER TABLE control.notify_channels ENABLE ROW LEVEL SECURITY;

CREATE TABLE control.notify_outbox (
  id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  audit_seq   bigint NOT NULL,
  action      text NOT NULL,
  target_type text,
  target_id   text,
  subject_id  uuid,
  payload     jsonb NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX notify_outbox_lookup ON control.notify_outbox (action, target_type, target_id, id DESC);
ALTER TABLE control.notify_outbox ENABLE ROW LEVEL SECURITY;

CREATE TABLE control.notify_deliveries (
  outbox_id       bigint NOT NULL REFERENCES control.notify_outbox(id),
  channel_id      bigint NOT NULL REFERENCES control.notify_channels(id),
  attempts        integer NOT NULL DEFAULT 0,
  claimed_until   timestamptz,
  last_attempt_at timestamptz,
  last_error      text,
  delivered_at    timestamptz,
  PRIMARY KEY (outbox_id, channel_id)
);
CREATE INDEX notify_deliveries_pending ON control.notify_deliveries (delivered_at, claimed_until) WHERE delivered_at IS NULL;
ALTER TABLE control.notify_deliveries ENABLE ROW LEVEL SECURITY;

-- Rows here are evidence: no deletes/updates except the delivery bookkeeping columns.
CREATE FUNCTION control.notify_outbox_immutable() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  RAISE EXCEPTION 'NOTIFY_OUTBOX_APPEND_ONLY' USING ERRCODE = 'insufficient_privilege';
END
$$;
CREATE TRIGGER notify_outbox_no_change BEFORE UPDATE OR DELETE ON control.notify_outbox
  FOR EACH ROW EXECUTE FUNCTION control.notify_outbox_immutable();
CREATE TRIGGER notify_outbox_no_truncate BEFORE TRUNCATE ON control.notify_outbox
  FOR EACH STATEMENT EXECUTE FUNCTION control.notify_outbox_immutable();
CREATE TRIGGER notify_deliveries_no_delete BEFORE DELETE ON control.notify_deliveries
  FOR EACH ROW EXECUTE FUNCTION control.notify_outbox_immutable();

RESET ROLE;

-- ------------------------------------------------------------ helpers owned by control_auth (no cross-role table reads)
GRANT CREATE ON SCHEMA control TO control_auth;
SET ROLE control_auth;
-- Active owners (recipients of every security notice).
CREATE FUNCTION control.active_owner_ids() RETURNS uuid[]
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = control, pg_temp AS $$
  SELECT coalesce(array_agg(id), '{}') FROM control.platform_identities WHERE role = 'owner' AND state = 'active'
$$;
-- Identity that owns a credential (for credential_* notices).
CREATE FUNCTION control.credential_identity(p_credential uuid) RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = control, pg_temp AS $$
  SELECT identity_id FROM control.webauthn_credentials WHERE id = p_credential
$$;
RESET ROLE;
REVOKE CREATE ON SCHEMA control FROM control_auth;
REVOKE EXECUTE ON FUNCTION control.active_owner_ids(), control.credential_identity(uuid) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION control.active_owner_ids(), control.credential_identity(uuid) TO control_audit_owner;

-- ------------------------------------------------------------ enqueue + gating + sentinel API (owner: control_audit_owner)
SET ROLE control_audit_owner;

-- Which audit actions are security notices. Kept as a function so tests and docs share one list.
CREATE FUNCTION control.notify_actions() RETURNS text[]
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT ARRAY[
    'platform.owner_enrolled', 'platform.credential_added', 'platform.credential_revoked',
    'platform.credential_counter_regression', 'platform.recovery_requested', 'platform.recovery_approved',
    'platform.recovery_contested', 'platform.recovery_cancelled', 'platform.recovery_completed',
    'platform.recovery_host_confirmed', 'platform.operator_credentials_revoked', 'platform.audit_suppressed',
    'platform.notify_channel_added', 'platform.notify_channel_disabled',
    'platform.operator_invited', 'platform.operator_enrolled', 'platform.operator_approved',
    'platform.operator_invite_revoked', 'platform.watchdog_terminated']::text[]
$$;

CREATE FUNCTION control.notify_enqueue() RETURNS trigger
LANGUAGE plpgsql SET search_path = control, pg_temp AS $$
DECLARE v_subject uuid; v_id bigint; v_owners uuid[];
BEGIN
  -- step-up grants for sensitive actions are notices too (a relayed prompt surfaces immediately)
  IF NOT (NEW.action = ANY (control.notify_actions())
          OR (NEW.action = 'platform.stepup_succeeded'
              AND NEW.detail ->> 'action' IN ('credential_add', 'credential_revoke', 'recovery_approve', 'recovery_cancel', 'operator_invite'))) THEN
    RETURN NULL;
  END IF;
  v_subject := CASE
    WHEN NEW.detail ? 'subject' AND (NEW.detail ->> 'subject') ~ '^[0-9a-f-]{36}$' THEN (NEW.detail ->> 'subject')::uuid
    WHEN NEW.target_type = 'platform_identity' AND NEW.target_id ~ '^[0-9a-f-]{36}$' THEN NEW.target_id::uuid
    WHEN NEW.target_type = 'credential' AND NEW.target_id ~ '^[0-9a-f-]{36}$' THEN control.credential_identity(NEW.target_id::uuid)
    ELSE NEW.actor_id END;
  INSERT INTO control.notify_outbox (audit_seq, action, target_type, target_id, subject_id, payload)
  VALUES (NEW.seq, NEW.action, NEW.target_type, NEW.target_id, v_subject,
    jsonb_build_object('v', 1, 'seq', NEW.seq, 'action', NEW.action, 'outcome', NEW.outcome,
      'actor', coalesce(NEW.actor_label, NEW.actor_type), 'target_type', NEW.target_type, 'target_id', NEW.target_id,
      'reason_code', NEW.reason_code, 'occurred_at', NEW.occurred_at, 'row_hash', encode(NEW.row_hash, 'hex'),
      'detail', NEW.detail))
  RETURNING id INTO v_id;
  v_owners := control.active_owner_ids();
  -- snapshot of recipients: every enabled host channel, every active owner, and the subject
  INSERT INTO control.notify_deliveries (outbox_id, channel_id)
  SELECT v_id, ch.id FROM control.notify_channels ch
   WHERE ch.enabled AND (ch.recipient = 'host' OR ch.identity_id = ANY (v_owners) OR ch.identity_id = v_subject);
  RETURN NULL;
END
$$;
CREATE TRIGGER audit_events_notify AFTER INSERT ON control.audit_events
  FOR EACH ROW EXECUTE FUNCTION control.notify_enqueue();

-- True only when the newest matching notice exists, had at least one HOST recipient, and was delivered to every
-- recipient in its snapshot.
CREATE FUNCTION control.notification_delivered(p_action text, p_target_type text, p_target_id text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = control, pg_temp AS $$
  WITH o AS (SELECT id FROM control.notify_outbox
              WHERE action = p_action AND target_type IS NOT DISTINCT FROM p_target_type AND target_id = p_target_id
              ORDER BY id DESC LIMIT 1)
  SELECT coalesce((
    SELECT bool_and(d.delivered_at IS NOT NULL) AND bool_or(c.recipient = 'host')
      FROM o JOIN control.notify_deliveries d ON d.outbox_id = o.id JOIN control.notify_channels c ON c.id = d.channel_id), false)
$$;

-- Sentinel: claim up to p_limit pending deliveries (lease 30 s, exponential backoff, max 20 attempts).
CREATE FUNCTION control.sentinel_claim(p_limit integer)
RETURNS TABLE (outbox_id bigint, channel_id bigint, kind text, target text, secret bytea, payload jsonb, attempts integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
BEGIN
  RETURN QUERY
  WITH c AS (
    SELECT d.outbox_id, d.channel_id FROM control.notify_deliveries d JOIN control.notify_channels ch ON ch.id = d.channel_id
     WHERE d.delivered_at IS NULL AND ch.enabled AND d.attempts < 20
       AND (d.claimed_until IS NULL OR d.claimed_until < clock_timestamp())
       AND (d.last_attempt_at IS NULL OR d.last_attempt_at < clock_timestamp() - make_interval(secs => least(300, 2 ^ d.attempts)::integer))
     ORDER BY d.outbox_id LIMIT least(greatest(p_limit, 1), 100)
     FOR UPDATE OF d SKIP LOCKED)
  UPDATE control.notify_deliveries d SET claimed_until = clock_timestamp() + interval '30 seconds', attempts = d.attempts + 1,
         last_attempt_at = clock_timestamp()
    FROM c, control.notify_channels ch, control.notify_outbox o
   WHERE d.outbox_id = c.outbox_id AND d.channel_id = c.channel_id AND ch.id = d.channel_id AND o.id = d.outbox_id
  RETURNING d.outbox_id, d.channel_id, ch.kind, ch.target, ch.secret, o.payload || jsonb_build_object('notice_id', o.id), d.attempts;
END
$$;

CREATE FUNCTION control.sentinel_ack(p_outbox bigint, p_channel bigint, p_ok boolean, p_error text) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
BEGIN
  UPDATE control.notify_deliveries
     SET delivered_at = CASE WHEN p_ok THEN clock_timestamp() ELSE NULL END,
         last_error = CASE WHEN p_ok THEN NULL ELSE left(regexp_replace(coalesce(p_error, 'error'), '[^ -~]', '?', 'g'), 200) END,
         claimed_until = NULL
   WHERE outbox_id = p_outbox AND channel_id = p_channel AND delivered_at IS NULL;
  RETURN FOUND;
END
$$;

-- Host-only channel management (no grants).
CREATE FUNCTION control.host_add_notify_channel_internal(p_recipient text, p_identity uuid, p_kind text, p_target text, p_secret bytea)
RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE v_id bigint;
BEGIN
  INSERT INTO control.notify_channels (recipient, identity_id, kind, target, secret)
  VALUES (p_recipient, p_identity, p_kind, p_target, p_secret) RETURNING id INTO v_id;
  PERFORM control.audit_append('cli', NULL, 'host-notify', 'platform.notify_channel_added', 'success', 'notify_channel',
    v_id::text, NULL, NULL, jsonb_build_object('recipient', p_recipient, 'kind', p_kind, 'identity', p_identity));
  RETURN v_id;
END
$$;

CREATE FUNCTION control.host_disable_notify_channel(p_id bigint) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
BEGIN
  UPDATE control.notify_channels SET enabled = false WHERE id = p_id AND enabled;
  IF NOT FOUND THEN RETURN jsonb_build_object('ok', false, 'error', 'NOT_FOUND'); END IF;
  PERFORM control.audit_append('cli', NULL, 'host-notify', 'platform.notify_channel_disabled', 'success', 'notify_channel',
    p_id::text, NULL, NULL, '{}'::jsonb);
  RETURN jsonb_build_object('ok', true);
END
$$;

-- Host status view of undelivered notices (for the host CLI).
CREATE FUNCTION control.host_notify_status() RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = control, pg_temp AS $$
  SELECT jsonb_build_object('ok', true,
    'channels', (SELECT coalesce(jsonb_agg(jsonb_build_object('id', id, 'recipient', recipient, 'identity', identity_id,
                  'kind', kind, 'target', target, 'enabled', enabled) ORDER BY id), '[]') FROM control.notify_channels),
    'undelivered', (SELECT count(*) FROM control.notify_deliveries WHERE delivered_at IS NULL),
    'failing', (SELECT count(*) FROM control.notify_deliveries WHERE delivered_at IS NULL AND attempts >= 3),
    'notices_without_recipients', (SELECT count(*) FROM control.notify_outbox o
                                    WHERE NOT EXISTS (SELECT 1 FROM control.notify_deliveries d WHERE d.outbox_id = o.id)))
$$;
RESET ROLE;
REVOKE CREATE ON SCHEMA control FROM control_audit_owner;

-- host_add_notify_channel resolves an operator by email through control_auth, then calls the audit-owner insert.
GRANT CREATE ON SCHEMA control TO control_auth;
SET ROLE control_auth;
CREATE FUNCTION control.host_add_notify_channel(p_recipient text, p_email text, p_kind text, p_target text, p_secret_hex text)
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE v_identity uuid; v_id bigint;
BEGIN
  IF p_recipient = 'identity' THEN
    SELECT id INTO v_identity FROM control.platform_identities WHERE email = lower(btrim(p_email));
    IF v_identity IS NULL THEN RETURN control.err('NOT_FOUND'); END IF;
  END IF;
  BEGIN
    v_id := control.host_add_notify_channel_internal(p_recipient, v_identity, p_kind, p_target,
              CASE WHEN p_secret_hex IS NULL THEN NULL ELSE decode(p_secret_hex, 'hex') END);
  EXCEPTION WHEN check_violation OR invalid_parameter_value THEN RETURN control.err('INVALID_INPUT');
  END;
  RETURN jsonb_build_object('ok', true, 'channel_id', v_id);
END
$$;
RESET ROLE;
REVOKE CREATE ON SCHEMA control FROM control_auth;
GRANT EXECUTE ON FUNCTION control.host_add_notify_channel_internal(text, uuid, text, text, bytea) TO control_auth;

-- ------------------------------------------------------------ delivery gating in the auth module
GRANT EXECUTE ON FUNCTION control.notification_delivered(text, text, text) TO control_auth;

-- One definition of "usable passkey" (owner control_auth): not disabled, past its delay, and - if it was added
-- in-session - its out-of-band notice was delivered.
GRANT CREATE ON SCHEMA control TO control_auth;
SET ROLE control_auth;
CREATE FUNCTION control.credential_usable(p_id uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = control, pg_temp AS $$
  SELECT coalesce((SELECT c.disabled_at IS NULL AND c.usable_after <= clock_timestamp()
                          AND (c.created_via <> 'added' OR c.created_at < control.setting_text('notify_gate_since')::timestamptz
                               OR control.notification_delivered('platform.credential_added', 'credential', c.id::text))
                     FROM control.webauthn_credentials c WHERE c.id = p_id), false)
$$;
RESET ROLE;
REVOKE CREATE ON SCHEMA control FROM control_auth;
REVOKE EXECUTE ON FUNCTION control.credential_usable(uuid) FROM PUBLIC;

-- wa_assertion (as 211) with the usable check now including delivery of the out-of-band notice.
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
  IF NOT control.credential_usable(c.id) THEN err := 'CREDENTIAL_PENDING'; RETURN; END IF;
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

-- Session view: pending = not yet usable (delay OR undelivered notice).
CREATE OR REPLACE FUNCTION control.api_session_get(p_token text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token);
BEGIN
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  RETURN jsonb_build_object('ok', true, 'identity_id', c.identity_id, 'email', c.email, 'display_name', c.display_name,
    'role', c.role, 'absolute_expires_at', c.absolute_expires_at, 'idle_expires_at', c.idle_expires_at,
    'active_credentials', (SELECT count(*) FROM control.webauthn_credentials w
                            WHERE w.identity_id = c.identity_id AND control.credential_usable(w.id)),
    'pending_credentials', (SELECT count(*) FROM control.webauthn_credentials w
                             WHERE w.identity_id = c.identity_id AND w.disabled_at IS NULL AND NOT control.credential_usable(w.id)),
    'flagged_credentials', (SELECT count(*) FROM control.webauthn_credentials
                             WHERE identity_id = c.identity_id AND disabled_at IS NULL AND counter_suspect_at IS NOT NULL));
END
$$;

-- Revocation (as 207): "last usable" now uses credential_usable.
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
          WHERE x.identity_id = c.identity_id AND x.id <> w.id AND control.credential_usable(x.id)) < 1 THEN
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
    'was_pending', NOT control.credential_usable(w.id)));
  RETURN jsonb_build_object('ok', true, 'sessions_revoked', v_sessions, 'current_session_ended', v_self);
END
$$;

-- Anchor signer must also be a usable (delivered) credential.
CREATE OR REPLACE FUNCTION control.anchor_signer(p_credential_id text, p_signer uuid, OUT public_key bytea, OUT label text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = control, pg_temp AS $$
  SELECT c.public_key, i.display_name
    FROM control.webauthn_credentials c JOIN control.platform_identities i ON i.id = c.identity_id
   WHERE c.credential_id = p_credential_id AND c.identity_id = p_signer AND control.credential_usable(c.id)
     AND i.state = 'active' AND i.role = 'owner'
$$;

-- Recovery redemption (as 211) additionally requires the approval notice to have been delivered.
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
  ELSIF t.purpose = 'recovery' AND r.approved_at >= control.setting_text('notify_gate_since')::timestamptz
        AND NOT control.notification_delivered('platform.recovery_approved', 'recovery_request', r.id::text) THEN
    reg.err := 'NOTIFICATION_PENDING';     -- the approval must reach the out-of-band channels first (token NOT consumed)
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

-- ------------------------------------------------------------ grants
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA control FROM PUBLIC;
GRANT EXECUTE ON FUNCTION control.sentinel_claim(integer), control.sentinel_ack(bigint, bigint, boolean, text) TO control_sentinel;
GRANT EXECUTE ON FUNCTION control.notify_actions(), control.active_owner_ids(), control.credential_identity(uuid)
  TO control_audit_owner;
GRANT EXECUTE ON FUNCTION control.notification_delivered(text, text, text), control.credential_usable(uuid) TO control_auth;
GRANT EXECUTE ON FUNCTION control.host_add_notify_channel_internal(text, uuid, text, text, bytea) TO control_auth;
-- host_add_notify_channel, host_disable_notify_channel, host_notify_status: no grants (superuser only).
