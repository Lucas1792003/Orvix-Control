-- ============================================================
-- 217: fixes from the four independent C1.2 reviews (docs/REVIEW_C1_2.md, Part B)
--
-- HIGH  H1  control_app could crash the sentinel: the watchdog's own audit row waited on the audit lock behind a queued
--           control_app backend that inherited the lock after the kill (sentinel statement_timeout -> exit). The
--           watchdog now (a) only acts on its own database, (b) also terminates backends queued behind a victim, and
--           (c) records each kill WITHOUT the audit lock (watchdog_kills + an immediate out-of-band notice), folding
--           the record into the hash chain later when the lock is free (1 s try per pass). Re-review: the first
--           version still let reconnecting backends suppress the kill record; the lock-free record closes that.
-- HIGH  H2  Forged shadow lines: every shadow line now carries HMAC-SHA256 over its exact JSON text, keyed by a secret
--           only control_audit_owner (and the superuser) can read, and the database name. scripts/audit-shadow.ts
--           drops lines whose MAC does not verify and reports them as forged. plpgsql USAGE is revoked from PUBLIC so
--           control_app can no longer run DO blocks (RAISE LOG) at all.
-- MED       Operator activation fingerprint is now derived from the PUBLIC KEY (SHA-256, 64 bits), not the
--           authenticator-chosen credential id.
-- MED       Host emergency revoke now also voids the revoked identity's open invitations (as inviter or invitee) and
--           reopens recovery requests it APPROVED; host approval refuses an inviter emergency-revoked after inviting;
--           recovery redemption refuses a link whose approver was emergency-revoked after approving.
-- MED       LAST_OWNER no longer counts an owner who is mid-recovery (open request as subject).
-- MED       The 15-minute reaction window for an added passkey now starts at DELIVERY of its notice, not creation.
-- MED       Deliveries are retried forever (backoff capped at 300 s) instead of giving up after 20 attempts; the host
--           status shows stuck deliveries, deliveries blocked by a disabled channel, and the sentinel heartbeat.
-- MED       Session-level advisory locks (invisible to the watchdog) are revoked from PUBLIC.
-- MED       Webhook targets must be https, or http on loopback only; file targets must be absolute paths. (The
--           sentinel additionally requires an ack HMAC from the receiver: scripts/sentinel.ts.)
-- LOW       Re-invite allowed for a never-activated identity (expired, or revoked invitation); the audit row records the
--           replaced invitation and previous role/state. Login devices: per-identity cap + purge; recovery redemption
--           revokes the subject's devices. New-device sign-ins are out-of-band notices. Subject recorded on
--           host-confirmed / cancelled recovery notices. host_approve_operator asserts READ COMMITTED. The claim lease
--           covers a whole delivery pass.
-- ============================================================

INSERT INTO control.settings (key, value) VALUES ('login_device_max_per_identity', '5');

-- ------------------------------------------------------------ H2: shadow-line MAC key (owner control_audit_owner)
GRANT CREATE ON SCHEMA control TO control_audit_owner;
SET ROLE control_audit_owner;
CREATE TABLE control.audit_shadow_key (
  id  integer PRIMARY KEY CHECK (id = 1),
  key bytea NOT NULL CHECK (length(key) = 32)
);
ALTER TABLE control.audit_shadow_key ENABLE ROW LEVEL SECURITY;
INSERT INTO control.audit_shadow_key (id, key) VALUES (1, control_ext.gen_random_bytes(32));

CREATE TABLE control.sentinel_heartbeat (
  id            integer PRIMARY KEY CHECK (id = 1),
  last_claim_at timestamptz NOT NULL
);
ALTER TABLE control.sentinel_heartbeat ENABLE ROW LEVEL SECURITY;

-- Watchdog kill records are written WITHOUT the audit lock (a control_app backend can hold that lock, and reconnecting
-- backends can keep re-taking it), so the kill and its out-of-band notice can never be held back. They are folded into
-- the hash chain later, whenever the audit lock is free.
CREATE TABLE control.watchdog_kills (
  id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  terminated  integer NOT NULL,
  pids        integer[] NOT NULL,
  audit_seq   bigint
);
ALTER TABLE control.watchdog_kills ENABLE ROW LEVEL SECURITY;
CREATE TRIGGER watchdog_kills_no_delete BEFORE DELETE ON control.watchdog_kills
  FOR EACH ROW EXECUTE FUNCTION control.notify_outbox_immutable();
CREATE TRIGGER watchdog_kills_no_truncate BEFORE TRUNCATE ON control.watchdog_kills
  FOR EACH STATEMENT EXECUTE FUNCTION control.notify_outbox_immutable();
ALTER TABLE control.notify_outbox ALTER COLUMN audit_seq DROP NOT NULL;   -- NULL: notice not (yet) in the audit chain

-- As 214 + MAC and database name on the shadow line.
CREATE OR REPLACE FUNCTION control.audit_append(
  p_actor_type text, p_actor_id uuid, p_actor_label text, p_action text, p_outcome text,
  p_target_type text DEFAULT NULL, p_target_id text DEFAULT NULL, p_request_id uuid DEFAULT NULL,
  p_reason_code text DEFAULT NULL, p_detail jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE v_prev_seq bigint; v_prev_hash bytea; v_seq bigint; v_at timestamptz := date_trunc('microseconds', clock_timestamp());
        v_hash bytea; v_detail jsonb := control.audit_safe_detail(p_detail); v_shadow uuid := gen_random_uuid(); v_line text;
BEGIN
  -- written to the server log immediately; survives ROLLBACK of the caller's transaction. The MAC (key readable only
  -- by this function's owner and the superuser) lets the host tool tell genuine lines from forged ones.
  v_line := jsonb_build_object('shadow_id', v_shadow, 'db', current_database(), 'xid', txid_current(), 'at', v_at,
    'session_user', session_user, 'actor_type', p_actor_type, 'actor_id', p_actor_id, 'action', p_action,
    'outcome', p_outcome, 'target_type', p_target_type, 'target_id', p_target_id, 'reason_code', p_reason_code)::text;
  RAISE LOG 'ORVIX_AUDIT_SHADOW % %',
    encode(control_ext.hmac(convert_to(v_line, 'UTF8'), (SELECT key FROM control.audit_shadow_key WHERE id = 1), 'sha256'), 'hex'),
    v_line;
  PERFORM 1 FROM control.audit_lock FOR UPDATE;
  SELECT seq, row_hash INTO v_prev_seq, v_prev_hash FROM control.audit_events ORDER BY seq DESC LIMIT 1;
  IF v_prev_seq IS NULL THEN RAISE EXCEPTION 'AUDIT_NO_GENESIS'; END IF;
  v_seq := v_prev_seq + 1;
  v_hash := control.audit_row_hash(v_prev_hash, control.audit_canonical(v_seq, v_at, p_actor_type, p_actor_id, p_actor_label,
            p_action, p_outcome, p_target_type, p_target_id, p_request_id, p_reason_code, v_detail));
  PERFORM set_config('control.audit_writer', 'on', true);
  INSERT INTO control.audit_events (seq, occurred_at, actor_type, actor_id, actor_label, action, outcome,
                                    target_type, target_id, request_id, reason_code, detail, prev_hash, row_hash, shadow_id)
  VALUES (v_seq, v_at, p_actor_type, p_actor_id, p_actor_label, p_action, p_outcome, p_target_type, p_target_id,
          p_request_id, p_reason_code, v_detail, v_prev_hash, v_hash, v_shadow);
  PERFORM set_config('control.audit_writer', '', true);
  RETURN v_seq;
END
$$;

-- ------------------------------------------------------------ notifications
-- As 212 + new-device sign-ins are notices (a relayed login ceremony surfaces out of band).
CREATE OR REPLACE FUNCTION control.notify_enqueue() RETURNS trigger
LANGUAGE plpgsql SET search_path = control, pg_temp AS $$
DECLARE v_subject uuid; v_id bigint; v_owners uuid[];
BEGIN
  -- a folded watchdog kill record was already announced when it happened (watchdog_record)
  IF NEW.action = 'platform.watchdog_terminated' AND NEW.detail ? 'kill_record' THEN RETURN NULL; END IF;
  IF NOT (NEW.action = ANY (control.notify_actions())
          OR (NEW.action = 'platform.stepup_succeeded'
              AND NEW.detail ->> 'action' IN ('credential_add', 'credential_revoke', 'recovery_approve', 'recovery_cancel', 'operator_invite'))
          OR (NEW.action = 'platform.login_succeeded' AND NEW.detail ->> 'new_device' = 'true')) THEN
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
  INSERT INTO control.notify_deliveries (outbox_id, channel_id)
  SELECT v_id, ch.id FROM control.notify_channels ch
   WHERE ch.enabled AND (ch.recipient = 'host' OR ch.identity_id = ANY (v_owners) OR ch.identity_id = v_subject);
  RETURN NULL;
END
$$;

-- When the newest matching notice reached every snapshot recipient (at least one a host channel): the time of the
-- LAST delivery; otherwise NULL. Reaction windows start here.
CREATE FUNCTION control.notification_delivered_at(p_action text, p_target_type text, p_target_id text) RETURNS timestamptz
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = control, pg_temp AS $$
  WITH o AS (SELECT id FROM control.notify_outbox
              WHERE action = p_action AND target_type IS NOT DISTINCT FROM p_target_type AND target_id = p_target_id
              ORDER BY id DESC LIMIT 1)
  SELECT CASE WHEN bool_and(d.delivered_at IS NOT NULL) AND bool_or(c.recipient = 'host') THEN max(d.delivered_at) END
    FROM o JOIN control.notify_deliveries d ON d.outbox_id = o.id JOIN control.notify_channels c ON c.id = d.channel_id
$$;

-- Lock-free kill record + immediate notice to every host channel and every active owner.
CREATE FUNCTION control.watchdog_record(p_terminated integer, p_pids integer[]) RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE v_id bigint; v_out bigint; v_owners uuid[];
BEGIN
  INSERT INTO control.watchdog_kills (terminated, pids) VALUES (p_terminated, coalesce(p_pids, '{}')) RETURNING id INTO v_id;
  INSERT INTO control.notify_outbox (audit_seq, action, target_type, target_id, subject_id, payload)
  VALUES (NULL, 'platform.watchdog_terminated', 'watchdog_kill', v_id::text, NULL,
    jsonb_build_object('v', 1, 'seq', NULL, 'action', 'platform.watchdog_terminated', 'outcome', 'success', 'actor', 'watchdog',
      'target_type', 'watchdog_kill', 'target_id', v_id::text, 'reason_code', 'STALE_TRANSACTION',
      'occurred_at', clock_timestamp(), 'row_hash', NULL,
      'detail', jsonb_build_object('terminated', p_terminated, 'pids', to_jsonb(coalesce(p_pids, '{}')), 'in_audit_chain', false)))
  RETURNING id INTO v_out;
  v_owners := control.active_owner_ids();
  INSERT INTO control.notify_deliveries (outbox_id, channel_id)
  SELECT v_out, ch.id FROM control.notify_channels ch
   WHERE ch.enabled AND (ch.recipient = 'host' OR ch.identity_id = ANY (v_owners));
  RETURN v_id;
END
$$;

-- Fold pending kill records into the hash chain (caller sets a short lock_timeout).
CREATE FUNCTION control.watchdog_fold() RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE k record; v_seq bigint; n integer := 0;
BEGIN
  FOR k IN SELECT * FROM control.watchdog_kills WHERE audit_seq IS NULL ORDER BY id LIMIT 50 FOR UPDATE SKIP LOCKED LOOP
    v_seq := control.audit_append('system', NULL, 'watchdog', 'platform.watchdog_terminated', 'success', 'watchdog_kill',
      k.id::text, NULL, 'STALE_TRANSACTION',
      jsonb_build_object('terminated', k.terminated, 'pids', to_jsonb(k.pids), 'kill_record', k.id, 'recorded_at', k.recorded_at));
    UPDATE control.watchdog_kills SET audit_seq = v_seq WHERE id = k.id;
    n := n + 1;
  END LOOP;
  RETURN n;
END
$$;

-- Retries never give up (backoff capped at 300 s); the lease covers a whole pass (<= 7 s per item); heartbeat.
-- Fewest attempts first, so a dead receiver's backlog never delays fresh notices.
CREATE OR REPLACE FUNCTION control.sentinel_claim(p_limit integer)
RETURNS TABLE (outbox_id bigint, channel_id bigint, kind text, target text, secret bytea, payload jsonb, attempts integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE v_limit integer := least(greatest(coalesce(p_limit, 1), 1), 100);
BEGIN
  INSERT INTO control.sentinel_heartbeat (id, last_claim_at) VALUES (1, clock_timestamp())
  ON CONFLICT (id) DO UPDATE SET last_claim_at = EXCLUDED.last_claim_at;
  RETURN QUERY
  WITH c AS (
    SELECT d.outbox_id, d.channel_id FROM control.notify_deliveries d JOIN control.notify_channels ch ON ch.id = d.channel_id
     WHERE d.delivered_at IS NULL AND ch.enabled
       AND (d.claimed_until IS NULL OR d.claimed_until < clock_timestamp())
       AND (d.last_attempt_at IS NULL
            OR d.last_attempt_at < clock_timestamp() - make_interval(secs => least(300, 2 ^ least(d.attempts, 9))::integer))
     ORDER BY d.attempts, d.outbox_id LIMIT v_limit
     FOR UPDATE OF d SKIP LOCKED)
  UPDATE control.notify_deliveries d
     SET claimed_until = clock_timestamp() + make_interval(secs => greatest(30, v_limit * 7)), attempts = d.attempts + 1,
         last_attempt_at = clock_timestamp()
    FROM c, control.notify_channels ch, control.notify_outbox o
   WHERE d.outbox_id = c.outbox_id AND d.channel_id = c.channel_id AND ch.id = d.channel_id AND o.id = d.outbox_id
  RETURNING d.outbox_id, d.channel_id, ch.kind, ch.target, ch.secret, o.payload || jsonb_build_object('notice_id', o.id), d.attempts;
END
$$;

CREATE OR REPLACE FUNCTION control.host_notify_status() RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = control, pg_temp AS $$
  SELECT jsonb_build_object('ok', true,
    'channels', (SELECT coalesce(jsonb_agg(jsonb_build_object('id', id, 'recipient', recipient, 'identity', identity_id,
                  'kind', kind, 'target', target, 'enabled', enabled) ORDER BY id), '[]') FROM control.notify_channels),
    'undelivered', (SELECT count(*) FROM control.notify_deliveries WHERE delivered_at IS NULL),
    'failing', (SELECT count(*) FROM control.notify_deliveries WHERE delivered_at IS NULL AND attempts >= 3),
    'stuck', (SELECT count(*) FROM control.notify_deliveries WHERE delivered_at IS NULL AND attempts >= 20),
    'blocked_by_disabled_channel', (SELECT count(*) FROM control.notify_deliveries d JOIN control.notify_channels c ON c.id = d.channel_id
                                     WHERE d.delivered_at IS NULL AND NOT c.enabled),
    'notices_without_recipients', (SELECT count(*) FROM control.notify_outbox o
                                    WHERE NOT EXISTS (SELECT 1 FROM control.notify_deliveries d WHERE d.outbox_id = o.id)),
    'watchdog_kills_not_in_chain', (SELECT count(*) FROM control.watchdog_kills WHERE audit_seq IS NULL),
    'sentinel_last_claim_at', (SELECT last_claim_at FROM control.sentinel_heartbeat WHERE id = 1))
$$;
RESET ROLE;
REVOKE CREATE ON SCHEMA control FROM control_audit_owner;

ALTER TABLE control.notify_channels ADD CONSTRAINT notify_channels_target_safe CHECK (
  (kind <> 'webhook' OR target ~ '^https://' OR target ~ '^http://(127\.0\.0\.1|\[::1\]|localhost)(:[0-9]{1,5})?(/|$)')
  AND (kind <> 'file' OR target ~ '^/')) NOT VALID;

-- ------------------------------------------------------------ helpers
-- Activation fingerprint: from the PUBLIC KEY (the credential id is chosen by the authenticator). 64 bits, grouped.
CREATE FUNCTION control.credential_fingerprint(p_public_key bytea) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE WHEN p_public_key IS NULL THEN NULL ELSE
    (SELECT upper(substr(h, 1, 4) || '-' || substr(h, 5, 4) || '-' || substr(h, 9, 4) || '-' || substr(h, 13, 4))
       FROM (SELECT encode(substring(sha256(p_public_key) FROM 1 FOR 8), 'hex') AS h) x) END
$$;
ALTER FUNCTION control.credential_fingerprint(bytea) OWNER TO control_schema_owner;

GRANT CREATE ON SCHEMA control TO control_auth;
SET ROLE control_auth;

-- As 212, but an added passkey's delay counts from DELIVERY of its notice (reaction time is real).
CREATE OR REPLACE FUNCTION control.credential_usable(p_id uuid) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = control, pg_temp AS $$
  SELECT coalesce((SELECT c.disabled_at IS NULL AND c.usable_after <= clock_timestamp()
                          AND (c.created_via <> 'added' OR c.created_at < control.setting_text('notify_gate_since')::timestamptz
                               OR coalesce(control.notification_delivered_at('platform.credential_added', 'credential', c.id::text)
                                           + make_interval(secs => control.setting_int('credential_activation_delay_seconds'))
                                           <= clock_timestamp(), false))
                     FROM control.webauthn_credentials c WHERE c.id = p_id), false)
$$;

-- As 213 + bounded purge of dead device rows.
CREATE OR REPLACE FUNCTION control.api_login_begin(p_device_token text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE v_device uuid; v_scope text; v_ok boolean; v_open integer;
BEGIN
  PERFORM control.assert_fresh_transaction();
  DELETE FROM control.webauthn_challenges WHERE ctid IN (
    SELECT ctid FROM control.webauthn_challenges WHERE purpose = 'login' AND expires_at < clock_timestamp() - interval '1 hour' LIMIT 200);
  DELETE FROM control.login_devices WHERE ctid IN (
    SELECT ctid FROM control.login_devices
     WHERE expires_at < clock_timestamp() OR revoked_at < clock_timestamp() - interval '30 days' LIMIT 100);
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

-- As 213 + at most login_device_max_per_identity live devices per identity (the least recently used are revoked):
-- one passkey holder can no longer mint enough buckets to reach the global challenge ceiling.
CREATE OR REPLACE FUNCTION control.api_login_complete(p_credential_id text, p_client_data bytea, p_authenticator_data bytea,
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
    UPDATE control.login_devices SET revoked_at = clock_timestamp()
     WHERE id IN (SELECT id FROM control.login_devices WHERE identity_id = i.id AND revoked_at IS NULL
                   ORDER BY last_used_at DESC, created_at DESC OFFSET control.setting_int('login_device_max_per_identity'));
  END IF;
  PERFORM control.audit_append('platform_identity', i.id, i.display_name, 'platform.login_succeeded', 'success',
    'session', encode(substring(control.sha(v_token) FROM 1 FOR 8), 'hex'), NULL, NULL,
    jsonb_build_object('credential', left(p_credential_id, 8), 'new_device', v_device IS NULL, 'subject', i.id));
  RETURN jsonb_build_object('ok', true, 'session_token', v_token, 'absolute_expires_at', v_abs,
                            'idle_seconds', control.setting_int('session_idle_seconds'),
                            'device_token', v_dev_token,
                            'device_ttl_seconds', control.setting_int('login_device_ttl_seconds'));
END
$$;

-- Revoke one invitation (shared by the owner API and the host emergency revoke). Caller holds bootstrap_state.
CREATE FUNCTION control.operator_invitation_void(p_invitation uuid) RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE inv control.operator_invitations;
BEGIN
  SELECT * INTO inv FROM control.operator_invitations WHERE id = p_invitation AND state IN ('pending', 'enrolled') FOR UPDATE;
  IF inv.id IS NULL THEN RETURN; END IF;
  UPDATE control.operator_invitations SET state = 'revoked', revoked_at = clock_timestamp() WHERE id = inv.id;
  UPDATE control.enrolment_tokens SET used_at = now() WHERE invitation_id = inv.id AND used_at IS NULL;
  UPDATE control.webauthn_credentials SET disabled_at = now(), disabled_reason = 'invite_revoked'
   WHERE identity_id = inv.identity_id AND disabled_at IS NULL
     AND EXISTS (SELECT 1 FROM control.platform_identities WHERE id = inv.identity_id AND state IN ('enrolling', 'pending_approval'));
  UPDATE control.platform_identities SET state = 'revoked', revoked_at = clock_timestamp()
   WHERE id = inv.identity_id AND state IN ('enrolling', 'pending_approval');
END
$$;

-- As 215 + re-invite of a never-activated identity (expired or revoked invitation) with an audit trail of what it
-- replaces. Active (or once-active) identities can never be re-invited.
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

CREATE OR REPLACE FUNCTION control.api_operator_invite_revoke(p_token text, p_invitation uuid) RETURNS jsonb
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
  PERFORM control.operator_invitation_void(inv.id);
  PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'platform.operator_invite_revoked', 'success',
    'operator_invitation', inv.id::text, NULL, NULL, jsonb_build_object('subject', inv.identity_id));
  RETURN jsonb_build_object('ok', true);
END
$$;

CREATE OR REPLACE FUNCTION control.api_operator_list(p_token text) RETURNS jsonb
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
        'fingerprint', (SELECT control.credential_fingerprint(w.public_key) FROM control.webauthn_credentials w
                         WHERE w.identity_id = v.identity_id AND w.created_via = 'invite' AND w.disabled_at IS NULL LIMIT 1))
        ORDER BY v.created_at DESC), '[]')
        FROM control.operator_invitations v JOIN control.platform_identities i ON i.id = v.identity_id
       WHERE v.state IN ('pending', 'enrolled')));
END
$$;

-- As 215 + READ COMMITTED; public-key fingerprint; the inviter must not have been emergency-revoked after inviting.
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
                      AND (o.emergency_revoked_at IS NULL OR o.emergency_revoked_at < inv.created_at)) THEN
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

-- As 216 + (a) owners mid-recovery do not count as "another usable owner"; (b) recovery links this identity APPROVED
-- are voided; (c) open invitations this identity issued, or is the subject of, are voided.
CREATE OR REPLACE FUNCTION control.host_revoke_operator_credentials(p_email text, p_reason text, p_force boolean DEFAULT false) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE i control.platform_identities; v_s integer; v_c integer; x record; v_inv integer := 0; v_links integer := 0;
BEGIN
  PERFORM control.assert_read_committed();
  IF p_reason IS NULL OR length(btrim(p_reason)) < 10 THEN RETURN control.err('REASON_REQUIRED'); END IF;
  PERFORM 1 FROM control.bootstrap_state FOR UPDATE;
  SELECT * INTO i FROM control.platform_identities WHERE email = lower(btrim(p_email)) FOR NO KEY UPDATE;
  IF i.id IS NULL THEN RETURN control.err('NOT_FOUND'); END IF;
  IF i.role = 'owner' AND NOT coalesce(p_force, false) AND NOT EXISTS (
       SELECT 1 FROM control.platform_identities o JOIN control.webauthn_credentials w ON w.identity_id = o.id
        WHERE o.id <> i.id AND o.role = 'owner' AND o.state = 'active' AND control.credential_usable(w.id)
          AND NOT EXISTS (SELECT 1 FROM control.recovery_requests q WHERE q.subject_id = o.id
                            AND q.state IN ('pending', 'approved') AND q.expires_at > clock_timestamp())) THEN
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
  FOR x IN SELECT id FROM control.recovery_requests WHERE approved_by = i.id AND state = 'approved' LOOP
    PERFORM control.recovery_reopen_contested(x.id, false);
    v_links := v_links + 1;
  END LOOP;
  FOR x IN SELECT id, identity_id FROM control.operator_invitations
            WHERE (invited_by = i.id OR identity_id = i.id) AND state IN ('pending', 'enrolled') ORDER BY created_at LOOP
    PERFORM control.operator_invitation_void(x.id);
    PERFORM control.audit_append('cli', NULL, 'host-emergency', 'platform.operator_invite_revoked', 'success',
      'operator_invitation', x.id::text, NULL, 'INVITER_REVOKED', jsonb_build_object('subject', x.identity_id));
    v_inv := v_inv + 1;
  END LOOP;
  PERFORM control.audit_append('cli', NULL, 'host-emergency', 'platform.operator_credentials_revoked', 'success',
    'platform_identity', i.id::text, NULL, 'EMERGENCY',
    jsonb_build_object('credentials_disabled', v_c, 'sessions_revoked', v_s, 'forced', coalesce(p_force, false),
                       'approved_links_voided', v_links, 'invitations_voided', v_inv, 'reason', left(btrim(p_reason), 200)));
  RETURN jsonb_build_object('ok', true, 'credentials_disabled', v_c, 'sessions_revoked', v_s,
                            'approved_links_voided', v_links, 'invitations_voided', v_inv);
END
$$;

-- As 210 + subject recorded (so the subject's own channel receives the notice).
CREATE OR REPLACE FUNCTION control.host_recovery_confirm(p_request uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE v_subject uuid;
BEGIN
  UPDATE control.recovery_requests SET host_confirmed_at = clock_timestamp()
   WHERE id = p_request AND state = 'pending' AND expires_at > clock_timestamp()
  RETURNING subject_id INTO v_subject;
  IF NOT FOUND THEN RETURN control.err('NOT_FOUND'); END IF;
  PERFORM control.audit_append('cli', NULL, 'host-recovery', 'platform.recovery_host_confirmed', 'success',
    'recovery_request', p_request::text, NULL, NULL, jsonb_build_object('subject', v_subject));
  RETURN jsonb_build_object('ok', true);
END
$$;

CREATE OR REPLACE FUNCTION control.host_recovery_cancel(p_request uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE v_subject uuid;
BEGIN
  SELECT subject_id INTO v_subject FROM control.recovery_requests WHERE id = p_request;
  IF control.recovery_cancel_internal(p_request, 'host') = 0 THEN RETURN control.err('NOT_FOUND'); END IF;
  PERFORM control.audit_append('cli', NULL, 'host-recovery', 'platform.recovery_cancelled', 'success',
    'recovery_request', p_request::text, NULL, NULL, jsonb_build_object('subject', v_subject));
  RETURN jsonb_build_object('ok', true);
END
$$;

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

RESET ROLE;
REVOKE CREATE ON SCHEMA control FROM control_auth;

-- ------------------------------------------------------------ enrolment (as 215 + review fixes)
CREATE OR REPLACE FUNCTION control.api_enrol_complete(p_token text, p_attestation bytea, p_client_data bytea, p_nickname text)
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE t control.enrolment_tokens; i control.platform_identities; r control.recovery_requests; inv control.operator_invitations;
        reg record; v_cred uuid; v_disabled integer; v_sessions integer; v_now timestamptz; v_fp text;
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
                                     OR i.emergency_revoked_at >= r.approved_at
                                     -- the approving owner was emergency-revoked after approving: the link is void
                                     OR EXISTS (SELECT 1 FROM control.platform_identities a
                                                 WHERE a.id = r.approved_by AND a.emergency_revoked_at >= r.approved_at)))
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
    UPDATE control.recovery_requests SET state = 'redeemed', redeemed_at = now() WHERE id = r.id;
    PERFORM control.audit_append('platform_identity', i.id, i.display_name, 'platform.recovery_completed', 'success',
      'recovery_request', r.id::text, NULL, NULL,
      jsonb_build_object('credentials_disabled', v_disabled, 'sessions_revoked', v_sessions, 'new_credential', v_cred));
  END IF;
  RETURN jsonb_build_object('ok', true, 'credential', v_cred, 'purpose', t.purpose,
                            'fingerprint', v_fp, 'awaiting_host_approval', t.purpose = 'invite');
END
$$;

-- ------------------------------------------------------------ H1: watchdog that cannot be stalled by control_app
GRANT CREATE ON SCHEMA control TO control_watchdog_owner;
SET ROLE control_watchdog_owner;
CREATE OR REPLACE FUNCTION control.sentinel_watchdog(p_idle_seconds integer DEFAULT 5, p_xact_seconds integer DEFAULT 15) RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE r record; n integer := 0; v_pids integer[] := '{}';
BEGIN
  FOR r IN
    SELECT a.pid FROM pg_stat_activity a
     WHERE a.usename = 'control_app' AND a.datname = current_database() AND a.pid <> pg_backend_pid()
       AND a.backend_type = 'client backend'
       AND ((a.state LIKE 'idle in transaction%' AND clock_timestamp() - a.state_change > make_interval(secs => greatest(p_idle_seconds, 2)))
            OR (a.xact_start IS NOT NULL AND clock_timestamp() - a.xact_start > make_interval(secs => greatest(p_xact_seconds, 5))))
  LOOP
    IF pg_terminate_backend(r.pid, 250) THEN n := n + 1; v_pids := v_pids || r.pid; END IF;
  END LOOP;
  IF n > 0 THEN
    -- backends queued behind a victim would inherit its locks: terminate them too (fresh view: pg_stat_activity is
    -- otherwise cached for the whole transaction)
    PERFORM pg_stat_clear_snapshot();
    FOR r IN
      SELECT a.pid FROM pg_stat_activity a
       WHERE a.usename = 'control_app' AND a.datname = current_database() AND a.pid <> pg_backend_pid()
         AND a.backend_type = 'client backend' AND NOT (a.pid = ANY (v_pids))
         AND (a.state LIKE 'idle in transaction%' OR a.wait_event_type = 'Lock')
    LOOP
      IF pg_terminate_backend(r.pid, 250) THEN n := n + 1; v_pids := v_pids || r.pid; END IF;
    END LOOP;
    -- lock-free record and out-of-band notice: control_app cannot hold this back
    PERFORM control.watchdog_record(n, v_pids);
  END IF;
  -- fold pending kill records into the hash chain if the audit lock is free; otherwise a later pass does it
  BEGIN
    PERFORM set_config('lock_timeout', '1000ms', true);
    PERFORM control.watchdog_fold();
  EXCEPTION WHEN lock_not_available THEN
    NULL;
  END;
  PERFORM set_config('lock_timeout', '0', true);
  RETURN n;
END
$$;
RESET ROLE;
REVOKE CREATE ON SCHEMA control FROM control_watchdog_owner;

-- ------------------------------------------------------------ MED: session advisory locks, plpgsql DO blocks
-- Session-level advisory locks outlive transactions (invisible to the watchdog's transaction checks) and can fill the
-- shared lock table. Only transaction-scoped locks remain, and only for the function-owner roles that use them.
DO $adv$
DECLARE f record;
BEGIN
  FOR f IN SELECT p.oid::regprocedure AS sig FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = 'pg_catalog' AND p.proname LIKE 'pg\_%advisory%' LOOP
    EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC', f.sig);
  END LOOP;
  FOR f IN SELECT p.oid::regprocedure AS sig FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = 'pg_catalog' AND p.proname IN ('pg_advisory_xact_lock', 'pg_try_advisory_xact_lock') LOOP
    EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO control_definer, control_auth, control_audit_owner', f.sig);
  END LOOP;
END
$adv$;
-- DO blocks (and new plpgsql functions) need USAGE on the language; only the function-owner roles keep it.
REVOKE USAGE ON LANGUAGE plpgsql FROM PUBLIC;
GRANT USAGE ON LANGUAGE plpgsql TO control_definer, control_auth, control_audit_owner, control_schema_owner, control_watchdog_owner;

-- ------------------------------------------------------------ grants
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA control FROM PUBLIC;
GRANT EXECUTE ON FUNCTION control.notification_delivered_at(text, text, text) TO control_auth;
GRANT EXECUTE ON FUNCTION control.credential_fingerprint(bytea) TO control_auth;
GRANT EXECUTE ON FUNCTION control.operator_invitation_void(uuid) TO control_auth;
GRANT EXECUTE ON FUNCTION control.watchdog_record(integer, integer[]), control.watchdog_fold() TO control_watchdog_owner;
GRANT EXECUTE ON FUNCTION control.active_owner_ids() TO control_audit_owner;
-- unchanged API grants re-stated for the replaced functions (CREATE OR REPLACE keeps ACLs; this is belt and braces)
GRANT EXECUTE ON FUNCTION control.api_login_begin(text), control.api_login_complete(text, bytea, bytea, bytea, text),
  control.api_operator_invite(text, text, text, text), control.api_operator_invite_revoke(text, uuid),
  control.api_operator_list(text), control.api_recovery_cancel(text, uuid),
  control.api_enrol_complete(text, bytea, bytea, text) TO control_app;
GRANT EXECUTE ON FUNCTION control.sentinel_claim(integer), control.sentinel_watchdog(integer, integer) TO control_sentinel;
