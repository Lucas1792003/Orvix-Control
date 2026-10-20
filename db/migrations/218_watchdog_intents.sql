-- ============================================================
-- 218 (C1.3, provisional): crash-consistent watchdog (W-1). Design: docs/C1_3_DESIGN.md section 3.
--
-- PROBLEM  217's sentinel_watchdog terminated a backend and recorded the kill in the SAME transaction. A crash after
--          pg_terminate_backend (which cannot be rolled back) and before COMMIT left no evidence and no notice
--          (reproduced in C1.2 runtime validation by SIGKILL of the watchdog's postgres backend).
-- PROTOCOL Four steps, each its own transaction (the sentinel calls them as separate autocommit statements):
--          PLAN      insert an intent (pid, backend_start, xact_start, reason) + enqueue an intent notice  -> COMMIT
--          ARM       planned -> armed, only if the target is still the same session                     -> COMMIT
--          EXECUTE   only an ARMED intent; re-verify identity (pid + backend_start + xact_start), then
--                    pg_terminate_backend and armed -> terminated (or -> skipped)                        -> COMMIT
--          RECONCILE intents left planned/armed by a crash are resolved by target presence
--                    (armed + target gone => terminated_unconfirmed); resolved intents are folded into
--                    the hash chain (audit lock taken BEFORE the shadow line, so a lock timeout leaves none)
--          No committed armed intent => no termination. An interrupted intent is never re-executed; a later pass
--          creates a NEW intent (and a new notice).
-- ENFORCED (C1.3 review H-1/H-2/M-1/L-1/L-3/L-5): ARM and EXECUTE refuse to run in a transaction that has already
--          written anything (each must be its own transaction, so the committed intent cannot be rolled back with the
--          kill); PLAN/ARM/EXECUTE/RECONCILE force synchronous_commit=on; EXECUTE locks the intent row and re-checks it
--          (RECONCILE skips locked rows), so a concurrent reconcile cannot misrecord a kill; the caller-controlled successor
--          sweep is gone; 'terminated' means confirmed within 250 ms, otherwise 'terminated_unconfirmed'; RECONCILE resolves
--          open intents of any database name (e.g. after a rename/restore).
-- REPLACES control.sentinel_watchdog (dropped: it was the only path that could terminate without prior evidence).
--          217's watchdog_kills rows that are not yet in the chain are still folded (legacy).
-- ============================================================

INSERT INTO control.audit_actions (action, description) VALUES
  ('platform.watchdog_intent',          'Watchdog recorded a durable intent to terminate a control_app session (before acting)'),
  ('platform.watchdog_intent_resolved', 'Watchdog intent resolved without a termination (target gone, changed or abandoned)');

GRANT CREATE ON SCHEMA control TO control_audit_owner;
SET ROLE control_audit_owner;

CREATE TABLE control.watchdog_intents (
  id                   bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  created_at           timestamptz NOT NULL DEFAULT clock_timestamp(),
  datname              text NOT NULL DEFAULT current_database(),
  target_pid           integer NOT NULL,
  target_backend_start timestamptz NOT NULL,
  target_xact_start    timestamptz,
  reason               text NOT NULL CHECK (reason IN ('idle_in_transaction', 'transaction_age', 'successor')),
  state                text NOT NULL DEFAULT 'planned' CHECK (state IN ('planned', 'armed', 'terminated', 'skipped',
                         'terminated_unconfirmed', 'abandoned', 'abandoned_target_gone', 'abandoned_armed')),
  state_at             timestamptz NOT NULL DEFAULT clock_timestamp(),
  resolved_at          timestamptz,
  planned_by           text NOT NULL DEFAULT session_user,
  audit_seq            bigint
);
-- at most ONE open intent per target session+transaction (two sentinels cannot both act on it)
CREATE UNIQUE INDEX watchdog_intents_open_target ON control.watchdog_intents
  (target_pid, target_backend_start, coalesce(target_xact_start, '-infinity'::timestamptz)) WHERE state IN ('planned', 'armed');
CREATE INDEX watchdog_intents_unfolded ON control.watchdog_intents (id) WHERE audit_seq IS NULL;
ALTER TABLE control.watchdog_intents ENABLE ROW LEVEL SECURITY;
CREATE TRIGGER watchdog_intents_no_delete BEFORE DELETE ON control.watchdog_intents
  FOR EACH ROW EXECUTE FUNCTION control.notify_outbox_immutable();
CREATE TRIGGER watchdog_intents_no_truncate BEFORE TRUNCATE ON control.watchdog_intents
  FOR EACH STATEMENT EXECUTE FUNCTION control.notify_outbox_immutable();

-- Updates may only move an intent forward along the protocol and set audit_seq once (closes C1.2 W-2 for intents).
CREATE FUNCTION control.watchdog_intents_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF NEW.id <> OLD.id OR NEW.target_pid <> OLD.target_pid OR NEW.target_backend_start <> OLD.target_backend_start
     OR NEW.target_xact_start IS DISTINCT FROM OLD.target_xact_start OR NEW.reason <> OLD.reason
     OR NEW.created_at <> OLD.created_at OR NEW.datname <> OLD.datname OR NEW.planned_by <> OLD.planned_by
     OR (OLD.audit_seq IS NOT NULL AND NEW.audit_seq IS DISTINCT FROM OLD.audit_seq)
     OR (OLD.resolved_at IS NOT NULL AND NEW.resolved_at IS DISTINCT FROM OLD.resolved_at)
     OR NOT (NEW.state = OLD.state
             OR (OLD.state = 'planned' AND NEW.state IN ('armed', 'abandoned', 'abandoned_target_gone'))
             OR (OLD.state = 'armed' AND NEW.state IN ('terminated', 'skipped', 'terminated_unconfirmed', 'abandoned_armed'))) THEN
    RAISE EXCEPTION 'WATCHDOG_INTENT_IMMUTABLE' USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER watchdog_intents_guard BEFORE UPDATE ON control.watchdog_intents
  FOR EACH ROW EXECUTE FUNCTION control.watchdog_intents_guard();

-- Liveness per sentinel component (C1.3 M7): last_seen, and busy_since while a unit of work is in progress.
CREATE TABLE control.sentinel_liveness (
  component  text PRIMARY KEY CHECK (component IN ('delivery', 'watchdog')),
  last_seen  timestamptz NOT NULL,
  busy_since timestamptz
);
ALTER TABLE control.sentinel_liveness ENABLE ROW LEVEL SECURITY;

CREATE FUNCTION control.sentinel_beat(p_component text, p_busy boolean) RETURNS void
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
  INSERT INTO control.sentinel_liveness (component, last_seen, busy_since)
  VALUES (p_component, clock_timestamp(), CASE WHEN p_busy THEN clock_timestamp() END)
  ON CONFLICT (component) DO UPDATE
     SET last_seen = EXCLUDED.last_seen,
         busy_since = CASE WHEN p_busy THEN coalesce(control.sentinel_liveness.busy_since, EXCLUDED.last_seen) END
$$;

-- Insert an intent and its out-of-band notice (host channels + active owners), atomically. NULL when an open intent
-- for the same target already exists.
CREATE FUNCTION control.watchdog_intent_insert(p_pid integer, p_backend_start timestamptz, p_xact_start timestamptz, p_reason text)
RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE v_id bigint; v_out bigint; v_owners uuid[];
BEGIN
  INSERT INTO control.watchdog_intents (target_pid, target_backend_start, target_xact_start, reason)
  VALUES (p_pid, p_backend_start, p_xact_start, p_reason)
  ON CONFLICT DO NOTHING RETURNING id INTO v_id;
  IF v_id IS NULL THEN RETURN NULL; END IF;
  INSERT INTO control.notify_outbox (audit_seq, action, target_type, target_id, subject_id, payload)
  VALUES (NULL, 'platform.watchdog_intent', 'watchdog_intent', v_id::text, NULL,
    jsonb_build_object('v', 1, 'seq', NULL, 'action', 'platform.watchdog_intent', 'outcome', 'planned', 'actor', 'watchdog',
      'target_type', 'watchdog_intent', 'target_id', v_id::text, 'reason_code', upper(p_reason), 'occurred_at', clock_timestamp(),
      'row_hash', NULL, 'detail', jsonb_build_object('pid', p_pid, 'backend_start', p_backend_start, 'xact_start', p_xact_start,
        'reason', p_reason, 'in_audit_chain', false)))
  RETURNING id INTO v_out;
  v_owners := control.active_owner_ids();
  INSERT INTO control.notify_deliveries (outbox_id, channel_id)
  SELECT v_out, ch.id FROM control.notify_channels ch
   WHERE ch.enabled AND (ch.recipient = 'host' OR ch.identity_id = ANY (v_owners));
  RETURN v_id;
END
$$;

CREATE FUNCTION control.watchdog_intent_get(p_id bigint) RETURNS control.watchdog_intents
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = control, pg_temp AS $$
  SELECT * FROM control.watchdog_intents WHERE id = p_id
$$;

-- Open intents older than p_stale_seconds, LOCKED (rows an EXECUTE currently holds are skipped, never misresolved).
CREATE FUNCTION control.watchdog_intent_open(p_stale_seconds integer) RETURNS SETOF control.watchdog_intents
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
  SELECT * FROM control.watchdog_intents
   WHERE state IN ('planned', 'armed') AND state_at < clock_timestamp() - make_interval(secs => greatest(p_stale_seconds, 5))
   ORDER BY id FOR UPDATE SKIP LOCKED
$$;

-- The intent row, LOCKED for the rest of the caller's transaction (EXECUTE).
CREATE FUNCTION control.watchdog_intent_lock(p_id bigint) RETURNS control.watchdog_intents
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
  SELECT * FROM control.watchdog_intents WHERE id = p_id FOR UPDATE
$$;

-- Take the audit lock (the caller sets lock_timeout); used by RECONCILE before any shadow line is written.
CREATE FUNCTION control.watchdog_audit_lock() RETURNS void
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
  SELECT NULL::void FROM control.audit_lock FOR UPDATE
$$;

CREATE FUNCTION control.watchdog_intent_transition(p_id bigint, p_from text, p_to text) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
BEGIN
  UPDATE control.watchdog_intents
     SET state = p_to, state_at = clock_timestamp(),
         resolved_at = CASE WHEN p_to IN ('planned', 'armed') THEN NULL ELSE clock_timestamp() END
   WHERE id = p_id AND state = p_from;
  RETURN FOUND;
END
$$;

-- Fold resolved intents (and 217 legacy kill records) into the hash chain. The CALLER sets a short lock_timeout; the
-- audit lock is taken FIRST, so audit_append's shadow line is only written once the append can no longer time out
-- (no false "rolled back" shadow lines: C1.2 W-4).
CREATE FUNCTION control.watchdog_fold_intents() RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE k record; v_seq bigint; n integer := 0;
BEGIN
  PERFORM 1 FROM control.audit_lock FOR UPDATE;
  FOR k IN SELECT * FROM control.watchdog_intents
            WHERE audit_seq IS NULL AND state NOT IN ('planned', 'armed') ORDER BY id LIMIT 50 FOR UPDATE SKIP LOCKED LOOP
    v_seq := control.audit_append('system', NULL, 'watchdog',
      CASE WHEN k.state IN ('terminated', 'terminated_unconfirmed') THEN 'platform.watchdog_terminated' ELSE 'platform.watchdog_intent_resolved' END,
      'success', 'watchdog_intent', k.id::text, NULL, upper(k.state),
      jsonb_build_object('intent', k.id, 'pid', k.target_pid, 'backend_start', k.target_backend_start, 'xact_start', k.target_xact_start,
                         'reason', k.reason, 'state', k.state, 'planned_at', k.created_at, 'resolved_at', k.resolved_at,
                         'planned_by', k.planned_by));
    UPDATE control.watchdog_intents SET audit_seq = v_seq WHERE id = k.id;
    n := n + 1;
  END LOOP;
  n := n + control.watchdog_fold();      -- 217 legacy watchdog_kills rows (audit lock already held: no wait)
  RETURN n;
END
$$;

RESET ROLE;
REVOKE CREATE ON SCHEMA control FROM control_audit_owner;

-- ------------------------------------------------------------ protocol steps (owner control_watchdog_owner)
GRANT CREATE ON SCHEMA control TO control_watchdog_owner;
SET ROLE control_watchdog_owner;

-- Each protocol step must be its OWN transaction: a step that runs after this transaction already wrote anything
-- (e.g. BEGIN; plan; arm; execute; ROLLBACK) is refused, so the committed intent can never vanish with the kill.
CREATE FUNCTION control.watchdog_assert_own_transaction() RETURNS void
LANGUAGE plpgsql VOLATILE SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF pg_current_xact_id_if_assigned() IS NOT NULL THEN
    RAISE EXCEPTION 'WATCHDOG_STEP_MUST_BE_OWN_TRANSACTION' USING ERRCODE = 'invalid_transaction_state';
  END IF;
  PERFORM set_config('synchronous_commit', 'on', true);   -- the commit of this step is durable before the next step
END
$$;

-- PLAN: one intent per qualifying control_app backend of THIS database (no caller-chosen target classes).
CREATE FUNCTION control.watchdog_plan(p_idle_seconds integer DEFAULT 5, p_xact_seconds integer DEFAULT 15) RETURNS bigint[]
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE r record; v_ids bigint[] := '{}'; v_id bigint;
BEGIN
  PERFORM control.watchdog_assert_own_transaction();
  PERFORM control.sentinel_beat('watchdog', false);
  FOR r IN
    SELECT a.pid, a.backend_start, a.xact_start,
           CASE WHEN a.state LIKE 'idle in transaction%'
                     AND clock_timestamp() - a.state_change > make_interval(secs => greatest(p_idle_seconds, 2)) THEN 'idle_in_transaction'
                ELSE 'transaction_age' END AS reason
      FROM pg_stat_activity a
     WHERE a.usename = 'control_app' AND a.datname = current_database() AND a.pid <> pg_backend_pid()
       AND a.backend_type = 'client backend' AND a.backend_start IS NOT NULL AND a.xact_start IS NOT NULL
       AND ((a.state LIKE 'idle in transaction%'
             AND clock_timestamp() - a.state_change > make_interval(secs => greatest(p_idle_seconds, 2)))
            OR clock_timestamp() - a.xact_start > make_interval(secs => greatest(p_xact_seconds, 5)))
  LOOP
    v_id := control.watchdog_intent_insert(r.pid, r.backend_start, r.xact_start, r.reason);
    IF v_id IS NOT NULL THEN v_ids := v_ids || v_id; END IF;
  END LOOP;
  RETURN v_ids;
END
$$;

-- ARM: durable "a kill may follow" marker, only while the target is still the same session and transaction.
CREATE FUNCTION control.watchdog_arm(p_id bigint) RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE i control.watchdog_intents;
BEGIN
  PERFORM control.watchdog_assert_own_transaction();            -- the planned row seen here was committed by PLAN
  i := control.watchdog_intent_lock(p_id);
  IF i.id IS NULL OR i.state <> 'planned' OR i.datname <> current_database() THEN RETURN false; END IF;
  PERFORM pg_stat_clear_snapshot();
  IF NOT EXISTS (SELECT 1 FROM pg_stat_activity a
                  WHERE a.pid = i.target_pid AND a.backend_start = i.target_backend_start
                    AND a.xact_start IS NOT DISTINCT FROM i.target_xact_start
                    AND a.usename = 'control_app' AND a.datname = current_database() AND a.backend_type = 'client backend') THEN
    PERFORM control.watchdog_intent_transition(p_id, 'planned', 'abandoned_target_gone');
    RETURN false;
  END IF;
  RETURN control.watchdog_intent_transition(p_id, 'planned', 'armed');
END
$$;

-- EXECUTE: the ONLY path that terminates a backend. Own transaction; the ARMED intent row is locked and re-read; the
-- target must be the same session in the same (still open, > 5 s old) transaction.
CREATE FUNCTION control.watchdog_execute(p_id bigint) RETURNS text
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE i control.watchdog_intents; v_pid integer; v_to text;
BEGIN
  PERFORM control.watchdog_assert_own_transaction();            -- the armed row seen here was committed by ARM
  i := control.watchdog_intent_lock(p_id);                      -- RECONCILE skips this row while we hold it
  IF i.id IS NULL OR i.state <> 'armed' OR i.datname <> current_database() THEN RETURN 'not_armed'; END IF;
  PERFORM pg_stat_clear_snapshot();
  SELECT a.pid INTO v_pid FROM pg_stat_activity a
   WHERE a.pid = i.target_pid AND a.backend_start = i.target_backend_start
     AND a.xact_start IS NOT DISTINCT FROM i.target_xact_start
     AND (a.state LIKE 'idle in transaction%' OR a.xact_start < clock_timestamp() - interval '5 seconds')   -- still qualifies
     AND a.usename = 'control_app' AND a.datname = current_database() AND a.backend_type = 'client backend';
  IF v_pid IS NULL THEN
    v_to := 'skipped';
  ELSE
    -- true: the backend is gone within 250 ms (confirmed). false: signalled (or already gone) but not confirmed.
    v_to := CASE WHEN pg_terminate_backend(v_pid, 250) THEN 'terminated' ELSE 'terminated_unconfirmed' END;
  END IF;
  IF NOT control.watchdog_intent_transition(p_id, 'armed', v_to) THEN
    RAISE EXCEPTION 'WATCHDOG_INTENT_TRANSITION_FAILED';         -- cannot happen while the row is locked; never silent
  END IF;
  PERFORM control.sentinel_beat('watchdog', false);              -- liveness (after the work; also a crash-test hook)
  RETURN v_to;
END
$$;

-- RECONCILE: resolve interrupted intents (of any database name) by target presence, then fold into the chain.
CREATE FUNCTION control.watchdog_reconcile(p_stale_seconds integer DEFAULT 10) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE i control.watchdog_intents; v_present boolean; v_resolved integer := 0; v_folded integer := 0; v_lock boolean;
BEGIN
  PERFORM set_config('synchronous_commit', 'on', true);
  PERFORM control.sentinel_beat('watchdog', false);
  PERFORM pg_stat_clear_snapshot();
  FOR i IN SELECT * FROM control.watchdog_intent_open(p_stale_seconds) LOOP
    v_present := i.datname = current_database()
                 AND EXISTS (SELECT 1 FROM pg_stat_activity a WHERE a.pid = i.target_pid AND a.backend_start = i.target_backend_start);
    IF control.watchdog_intent_transition(i.id, i.state,
         CASE WHEN i.state = 'planned' THEN CASE WHEN v_present THEN 'abandoned' ELSE 'abandoned_target_gone' END
              ELSE CASE WHEN v_present THEN 'abandoned_armed' ELSE 'terminated_unconfirmed' END END) THEN
      v_resolved := v_resolved + 1;
    END IF;
  END LOOP;
  -- the audit lock is taken (1 s at most) BEFORE any shadow line can be written; then appends run without a timeout
  BEGIN
    PERFORM set_config('lock_timeout', '1000ms', true);
    PERFORM control.watchdog_audit_lock();
    v_lock := true;
  EXCEPTION WHEN lock_not_available THEN
    v_lock := false;
  END;
  PERFORM set_config('lock_timeout', '0', true);
  IF v_lock THEN v_folded := control.watchdog_fold_intents(); END IF;
  RETURN jsonb_build_object('resolved', v_resolved, 'folded', v_folded, 'audit_lock_available', v_lock);
END
$$;
RESET ROLE;
REVOKE CREATE ON SCHEMA control FROM control_watchdog_owner;

-- ------------------------------------------------------------ remove the non-intent kill path
REVOKE EXECUTE ON FUNCTION control.sentinel_watchdog(integer, integer) FROM control_sentinel;
DROP FUNCTION control.sentinel_watchdog(integer, integer);

-- ------------------------------------------------------------ grants
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA control FROM PUBLIC;
GRANT EXECUTE ON FUNCTION control.sentinel_beat(text, boolean), control.watchdog_intent_insert(integer, timestamptz, timestamptz, text),
  control.watchdog_intent_get(bigint), control.watchdog_intent_open(integer), control.watchdog_intent_lock(bigint),
  control.watchdog_audit_lock(), control.watchdog_intent_transition(bigint, text, text),
  control.watchdog_fold_intents() TO control_watchdog_owner;
GRANT EXECUTE ON FUNCTION control.watchdog_plan(integer, integer), control.watchdog_arm(bigint),
  control.watchdog_execute(bigint), control.watchdog_reconcile(integer) TO control_sentinel;
