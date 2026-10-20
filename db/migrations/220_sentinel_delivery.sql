-- ============================================================
-- 220 (C1.3, provisional): sentinel delivery isolation and truthful status. docs/C1_3_DESIGN.md section 2.
--
-- M6   Claims can be per CHANNEL (sentinel_claim(limit, channel)); a claim takes at most 5 deliveries per channel and
--      leases them for 40 s (was limit x 7 s = 350 s). The sentinel runs one worker per channel, so a stalled webhook
--      only stalls its own channel. Ordering: fewest attempts first, then oldest.
-- M7   host_notify_status reports per-channel state (healthy / busy / retrying / delayed / failing / disabled /
--      disabled_blocking) from the oldest undelivered age and the last error, per-component sentinel liveness
--      (delivery, watchdog; busy flag), watchdog intent health and the NOTIFY queue usage. The overall state is the worst.
-- LOW  claim_token: an ack must present the token of the claim it answers, so a stale claimer cannot clear another
--      sentinel's lease or mark its delivery.
-- LOW  Deliveries to a channel the HOST disabled stop counting for the gate; at least one host channel must still have
--      delivered. (Disabling is a host action and is audited + announced.)
-- LOW  control_sentinel CONNECTION LIMIT 12 (two sentinels with per-channel workers fit).
-- REVIEW (C1.3) A webhook channel may carry a separate ACK KEY (host + receiver only; the sentinel never reads it): the
--      receiver's X-Orvix-Ack is then verified IN THE DATABASE by sentinel_ack, so the sentinel credential alone cannot
--      mark such a delivery delivered. File channels cannot prove delivery to the database (sentinel trust; documented).
--      Heartbeat on every idle tick; overall status includes the watchdog and "no enabled host channel"; the gate
--      waiver needs an ENABLED host channel that delivered, and the reaction window counts from the disable time.
-- ============================================================

ALTER ROLE control_sentinel CONNECTION LIMIT 12;
ALTER TABLE control.notify_deliveries ADD COLUMN claim_token uuid;
ALTER TABLE control.notify_channels ADD COLUMN ack_secret bytea CHECK (ack_secret IS NULL OR length(ack_secret) >= 32),
                                    ADD COLUMN disabled_at timestamptz;
CREATE INDEX notify_deliveries_claimable ON control.notify_deliveries (channel_id, attempts, outbox_id) WHERE delivered_at IS NULL;
INSERT INTO control.audit_actions (action, description) VALUES
  ('platform.notify_channel_ack_key_set', 'Host set the database-verified acknowledgement key of a webhook channel');

REVOKE EXECUTE ON FUNCTION control.sentinel_claim(integer), control.sentinel_ack(bigint, bigint, boolean, text) FROM control_sentinel;
DROP FUNCTION control.sentinel_claim(integer);
DROP FUNCTION control.sentinel_ack(bigint, bigint, boolean, text);

GRANT CREATE ON SCHEMA control TO control_audit_owner;
SET ROLE control_audit_owner;

CREATE FUNCTION control.sentinel_claim(p_limit integer, p_channel bigint DEFAULT NULL)
RETURNS TABLE (outbox_id bigint, channel_id bigint, claim_token uuid, kind text, target text, secret bytea, payload jsonb, attempts integer,
               ack_verified_in_db boolean, body text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE v_limit integer := least(greatest(coalesce(p_limit, 1), 1), 100);
BEGIN
  RETURN QUERY
  WITH cand AS (
    SELECT x.outbox_id, x.channel_id FROM (
      SELECT d.outbox_id, d.channel_id, d.attempts,
             row_number() OVER (PARTITION BY d.channel_id ORDER BY d.attempts, d.outbox_id) AS rn
        FROM control.notify_deliveries d JOIN control.notify_channels ch ON ch.id = d.channel_id
       WHERE d.delivered_at IS NULL AND ch.enabled AND (p_channel IS NULL OR d.channel_id = p_channel)
         AND (d.claimed_until IS NULL OR d.claimed_until < clock_timestamp())
         AND (d.last_attempt_at IS NULL
              OR d.last_attempt_at < clock_timestamp() - make_interval(secs => least(300, 2 ^ least(d.attempts, 9))::integer))) x
     WHERE x.rn <= 5
     ORDER BY x.attempts, x.outbox_id LIMIT v_limit),
  c AS (
    SELECT d.outbox_id, d.channel_id FROM control.notify_deliveries d JOIN cand ON cand.outbox_id = d.outbox_id AND cand.channel_id = d.channel_id
     WHERE d.delivered_at IS NULL AND (d.claimed_until IS NULL OR d.claimed_until < clock_timestamp())
     FOR UPDATE OF d SKIP LOCKED)
  UPDATE control.notify_deliveries d
     SET claimed_until = clock_timestamp() + interval '40 seconds', attempts = d.attempts + 1,
         last_attempt_at = clock_timestamp(), claim_token = gen_random_uuid()
    FROM c, control.notify_channels ch, control.notify_outbox o
   WHERE d.outbox_id = c.outbox_id AND d.channel_id = c.channel_id AND ch.id = d.channel_id AND o.id = d.outbox_id
  RETURNING d.outbox_id, d.channel_id, d.claim_token, ch.kind, ch.target, ch.secret,
            o.payload || jsonb_build_object('notice_id', o.id), d.attempts, (ch.kind = 'webhook' AND ch.ack_secret IS NOT NULL),
            (o.payload || jsonb_build_object('notice_id', o.id))::text;      -- the exact bytes to send (the ack binds their hash)
  PERFORM control.sentinel_beat('delivery', EXISTS (SELECT 1 FROM control.notify_deliveries x
                                                     WHERE x.delivered_at IS NULL AND x.claimed_until > clock_timestamp()));
END
$$;

-- p_ok is the SENTINEL's verdict. For a webhook channel with an ack key, the database also requires the receiver's
-- X-Orvix-Ack = hex(HMAC-SHA256(ack_key, "ack." || notice_id || "." || timestamp || "." || hex(sha256(body)))), where body is
-- the canonical notice text returned by sentinel_claim: the sentinel cannot compute it, nor get a forged body acked.
CREATE FUNCTION control.sentinel_ack(p_outbox bigint, p_channel bigint, p_claim_token uuid, p_ok boolean, p_error text,
                                     p_ack_ts text DEFAULT NULL, p_ack text DEFAULT NULL) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE ch control.notify_channels; v_ok boolean := coalesce(p_ok, false); v_err text := p_error; v_found boolean;
BEGIN
  SELECT * INTO ch FROM control.notify_channels WHERE id = p_channel;
  IF v_ok AND ch.kind = 'webhook' AND ch.ack_secret IS NOT NULL THEN
    v_ok := coalesce(p_ack_ts ~ '^[0-9]{1,12}$' AND p_ack ~ '^[0-9a-f]{64}$'
            AND p_ack = encode(control_ext.hmac(convert_to('ack.' || p_outbox::text || '.' || p_ack_ts || '.' ||
                  encode(sha256(convert_to((SELECT (o.payload || jsonb_build_object('notice_id', o.id))::text
                                              FROM control.notify_outbox o WHERE o.id = p_outbox), 'UTF8')), 'hex'), 'UTF8'),
                  ch.ack_secret, 'sha256'), 'hex'), false);
    IF NOT v_ok THEN v_err := 'ack rejected by database'; END IF;
  END IF;
  UPDATE control.notify_deliveries
     SET delivered_at = CASE WHEN v_ok THEN clock_timestamp() ELSE NULL END,
         last_error = CASE WHEN v_ok THEN NULL ELSE left(regexp_replace(coalesce(v_err, 'error'), '[^ -~]', '?', 'g'), 200) END,
         claimed_until = NULL, claim_token = NULL
   WHERE outbox_id = p_outbox AND channel_id = p_channel AND delivered_at IS NULL
     AND claim_token IS NOT NULL AND claim_token = p_claim_token;
  v_found := FOUND;
  PERFORM control.sentinel_beat('delivery', EXISTS (SELECT 1 FROM control.notify_deliveries
                                                     WHERE delivered_at IS NULL AND claimed_until > clock_timestamp()));
  RETURN v_found AND v_ok;
END
$$;

-- Host-only (no grant): set the database-verified ack key of a webhook channel.
CREATE FUNCTION control.host_set_notify_ack_key(p_id bigint, p_ack_hex text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
BEGIN
  UPDATE control.notify_channels SET ack_secret = decode(p_ack_hex, 'hex') WHERE id = p_id AND kind = 'webhook';
  IF NOT FOUND THEN RETURN jsonb_build_object('ok', false, 'error', 'NOT_FOUND'); END IF;
  PERFORM control.audit_append('cli', NULL, 'host-notify', 'platform.notify_channel_ack_key_set', 'success', 'notify_channel',
    p_id::text, NULL, NULL, '{}'::jsonb);
  RETURN jsonb_build_object('ok', true);
EXCEPTION WHEN check_violation OR invalid_parameter_value THEN
  RETURN jsonb_build_object('ok', false, 'error', 'INVALID_INPUT');
END
$$;

-- As 212 + records when the host disabled the channel (the reaction window then counts from that moment).
CREATE OR REPLACE FUNCTION control.host_disable_notify_channel(p_id bigint) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
BEGIN
  UPDATE control.notify_channels SET enabled = false, disabled_at = clock_timestamp() WHERE id = p_id AND enabled;
  IF NOT FOUND THEN RETURN jsonb_build_object('ok', false, 'error', 'NOT_FOUND'); END IF;
  PERFORM control.audit_append('cli', NULL, 'host-notify', 'platform.notify_channel_disabled', 'success', 'notify_channel',
    p_id::text, NULL, NULL, '{}'::jsonb);
  RETURN jsonb_build_object('ok', true);
END
$$;

-- Channels that have claimable work now (the sentinel starts one worker per channel).
-- Also the delivery heartbeat of an idle sentinel (called every second).
CREATE FUNCTION control.sentinel_pending_channels() RETURNS TABLE (channel_id bigint)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
  SELECT control.sentinel_beat('delivery', EXISTS (SELECT 1 FROM control.notify_deliveries
                                                    WHERE delivered_at IS NULL AND claimed_until > clock_timestamp()));
  SELECT DISTINCT d.channel_id FROM control.notify_deliveries d JOIN control.notify_channels ch ON ch.id = d.channel_id
   WHERE d.delivered_at IS NULL AND ch.enabled
     AND (d.claimed_until IS NULL OR d.claimed_until < clock_timestamp())
     AND (d.last_attempt_at IS NULL
          OR d.last_attempt_at < clock_timestamp() - make_interval(secs => least(300, 2 ^ least(d.attempts, 9))::integer))
$$;

-- Gate (as 212/217) + deliveries to host-DISABLED channels no longer count; >= 1 host channel must have delivered.
CREATE OR REPLACE FUNCTION control.notification_delivered(p_action text, p_target_type text, p_target_id text) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = control, pg_temp AS $$
  WITH o AS (SELECT id FROM control.notify_outbox
              WHERE action = p_action AND target_type IS NOT DISTINCT FROM p_target_type AND target_id = p_target_id
              ORDER BY id DESC LIMIT 1)
  SELECT coalesce((
    SELECT bool_and(d.delivered_at IS NOT NULL OR NOT c.enabled) AND bool_or(c.recipient = 'host' AND c.enabled AND d.delivered_at IS NOT NULL)
      FROM o JOIN control.notify_deliveries d ON d.outbox_id = o.id JOIN control.notify_channels c ON c.id = d.channel_id), false)
$$;

CREATE OR REPLACE FUNCTION control.notification_delivered_at(p_action text, p_target_type text, p_target_id text) RETURNS timestamptz
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = control, pg_temp AS $$
  WITH o AS (SELECT id FROM control.notify_outbox
              WHERE action = p_action AND target_type IS NOT DISTINCT FROM p_target_type AND target_id = p_target_id
              ORDER BY id DESC LIMIT 1)
  -- the reaction window starts at the LAST delivery, or when the host disabled a channel that had not delivered
  SELECT CASE WHEN bool_and(d.delivered_at IS NOT NULL OR NOT c.enabled) AND bool_or(c.recipient = 'host' AND c.enabled AND d.delivered_at IS NOT NULL)
              THEN greatest(max(d.delivered_at), max(c.disabled_at) FILTER (WHERE d.delivered_at IS NULL)) END
    FROM o JOIN control.notify_deliveries d ON d.outbox_id = o.id JOIN control.notify_channels c ON c.id = d.channel_id
$$;

-- Truthful host status (M7).
CREATE OR REPLACE FUNCTION control.host_notify_status() RETURNS jsonb
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = control, pg_temp AS $$
  WITH ch AS (
    SELECT c.id, c.recipient, c.identity_id, c.kind, c.target, c.enabled, (c.ack_secret IS NOT NULL) AS ack_key,
           (SELECT count(*) FROM control.notify_deliveries d WHERE d.channel_id = c.id AND d.delivered_at IS NULL) AS undelivered,
           (SELECT min(o.created_at) FROM control.notify_deliveries d JOIN control.notify_outbox o ON o.id = d.outbox_id
             WHERE d.channel_id = c.id AND d.delivered_at IS NULL) AS oldest,
           (SELECT count(*) FROM control.notify_deliveries d
             WHERE d.channel_id = c.id AND d.delivered_at IS NULL AND d.claimed_until > clock_timestamp()) AS in_flight,
           (SELECT max(d.delivered_at) FROM control.notify_deliveries d WHERE d.channel_id = c.id) AS last_success,
           (SELECT d.last_error FROM control.notify_deliveries d
             WHERE d.channel_id = c.id AND d.delivered_at IS NULL AND d.last_error IS NOT NULL
             ORDER BY d.last_attempt_at DESC NULLS LAST LIMIT 1) AS last_error,
           (SELECT max(d.attempts) FROM control.notify_deliveries d WHERE d.channel_id = c.id AND d.delivered_at IS NULL) AS max_attempts
      FROM control.notify_channels c),
  cs AS (
    SELECT ch.*, CASE
      WHEN NOT enabled THEN CASE WHEN undelivered > 0 THEN 'disabled_pending' ELSE 'disabled' END
      WHEN undelivered = 0 THEN 'healthy'
      WHEN clock_timestamp() - oldest < interval '60 seconds' THEN CASE WHEN last_error IS NOT NULL THEN 'retrying' ELSE 'busy' END
      WHEN last_error IS NOT NULL THEN 'failing'
      ELSE 'delayed' END AS state
      FROM ch),
  live AS (
    SELECT (SELECT extract(epoch FROM clock_timestamp() - last_seen)::integer FROM control.sentinel_liveness WHERE component = 'delivery') AS delivery_age,
           (SELECT busy_since IS NOT NULL FROM control.sentinel_liveness WHERE component = 'delivery') AS delivery_busy,
           (SELECT extract(epoch FROM clock_timestamp() - last_seen)::integer FROM control.sentinel_liveness WHERE component = 'watchdog') AS watchdog_age),
  tot AS (SELECT coalesce(sum(undelivered) FILTER (WHERE enabled), 0) AS undelivered FROM cs)
  SELECT jsonb_build_object('ok', true,
    'state', CASE
       WHEN coalesce((SELECT delivery_age FROM live), 1e9) > 30 THEN 'sentinel_down'          -- idle sentinels beat every second
       WHEN coalesce((SELECT watchdog_age FROM live), 1e9) > 30 THEN 'watchdog_down'
       WHEN NOT EXISTS (SELECT 1 FROM cs WHERE enabled AND recipient = 'host') THEN 'no_host_channel'
       WHEN EXISTS (SELECT 1 FROM cs WHERE state = 'failing') THEN 'failing'
       WHEN EXISTS (SELECT 1 FROM cs WHERE state = 'delayed') THEN 'delayed'
       WHEN EXISTS (SELECT 1 FROM cs WHERE state IN ('busy', 'retrying')) THEN 'busy'
       ELSE 'healthy' END,
    'sentinel', (SELECT jsonb_build_object('delivery_last_seen_seconds', delivery_age, 'delivery_busy', coalesce(delivery_busy, false),
                   'watchdog_last_seen_seconds', watchdog_age,
                   'watchdog_state', CASE WHEN watchdog_age IS NULL THEN 'never_seen' WHEN watchdog_age > 30 THEN 'down' ELSE 'up' END)
                 FROM live),
    'channels', (SELECT coalesce(jsonb_agg(jsonb_build_object('id', id, 'recipient', recipient, 'identity', identity_id, 'kind', kind,
                   'target', target, 'enabled', enabled, 'state', state, 'ack_verified_in_db', ack_key, 'undelivered', undelivered, 'in_flight', in_flight,
                   'oldest_undelivered_seconds', extract(epoch FROM clock_timestamp() - oldest)::integer,
                   'last_success_at', last_success, 'last_error', last_error, 'max_attempts', max_attempts) ORDER BY id), '[]') FROM cs),
    'undelivered', (SELECT undelivered FROM tot),
    'failing', (SELECT count(*) FROM cs WHERE state = 'failing'),
    'stuck', (SELECT count(*) FROM control.notify_deliveries WHERE delivered_at IS NULL AND attempts >= 20),
    'blocked_by_disabled_channel', (SELECT count(*) FROM control.notify_deliveries d JOIN control.notify_channels c ON c.id = d.channel_id
                                     WHERE d.delivered_at IS NULL AND NOT c.enabled),
    'notices_without_recipients', (SELECT count(*) FROM control.notify_outbox o
                                    WHERE NOT EXISTS (SELECT 1 FROM control.notify_deliveries d WHERE d.outbox_id = o.id)),
    'notices_without_host_recipient', (SELECT count(*) FROM control.notify_outbox o
                                        WHERE EXISTS (SELECT 1 FROM control.notify_deliveries d WHERE d.outbox_id = o.id)
                                          AND NOT EXISTS (SELECT 1 FROM control.notify_deliveries d JOIN control.notify_channels c ON c.id = d.channel_id
                                                           WHERE d.outbox_id = o.id AND c.recipient = 'host')),
    'watchdog', jsonb_build_object(
       'open_intents', (SELECT count(*) FROM control.watchdog_intents WHERE state IN ('planned', 'armed')),
       'interrupted_intents', (SELECT count(*) FROM control.watchdog_intents
                                WHERE state IN ('planned', 'armed') AND state_at < clock_timestamp() - interval '30 seconds'),
       'not_in_chain', (SELECT count(*) FROM control.watchdog_intents WHERE audit_seq IS NULL AND state NOT IN ('planned', 'armed')),
       'legacy_kills_not_in_chain', (SELECT count(*) FROM control.watchdog_kills WHERE audit_seq IS NULL),
       'unconfirmed_terminations', (SELECT count(*) FROM control.watchdog_intents WHERE state = 'terminated_unconfirmed')),
    'notify_queue_usage', pg_notification_queue_usage(),
    -- kept for compatibility with 217 consumers
    'watchdog_kills_not_in_chain', (SELECT count(*) FROM control.watchdog_kills WHERE audit_seq IS NULL),
    'sentinel_last_claim_at', (SELECT last_seen FROM control.sentinel_liveness WHERE component = 'delivery'))
$$;

RESET ROLE;
REVOKE CREATE ON SCHEMA control FROM control_audit_owner;

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA control FROM PUBLIC;
GRANT EXECUTE ON FUNCTION control.sentinel_claim(integer, bigint), control.sentinel_ack(bigint, bigint, uuid, boolean, text, text, text),
  control.sentinel_pending_channels() TO control_sentinel;
GRANT EXECUTE ON FUNCTION control.notification_delivered_at(text, text, text) TO control_auth;
