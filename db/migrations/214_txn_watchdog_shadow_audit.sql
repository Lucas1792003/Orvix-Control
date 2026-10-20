-- ============================================================
-- 214: open-transaction controls and independent audit evidence (C1.2, RM-3)
--
-- PROBLEM  With the control_app password an attacker can (a) hold an open transaction after an audited call, keeping
--          the audit row lock and stalling every audited action; (b) ROLLBACK to suppress refusal/read audit rows
--          and to undo rate-limit counts. control_app can change its own session timeouts.
-- MITIGATIONS (what this file adds)
--   1. transaction_timeout = 10s as a role default (PostgreSQL 17). A DEFAULT only: control_app can override it.
--   2. WATCHDOG enforcement that control_app cannot override: control.sentinel_watchdog() terminates control_app
--      backends that are idle in a transaction > 5 s or whose transaction is older than 15 s. It runs as
--      control_watchdog_owner (NOLOGIN, member of pg_signal_backend + pg_read_all_stats WITH INHERIT) and touches
--      ONLY backends whose user is control_app. Executed by the sentinel process every few seconds; each kill is
--      audited ('platform.watchdog_terminated', which is also an out-of-band notice).
--   3. SHADOW AUDIT EVIDENCE outside the transaction: audit_append also emits RAISE LOG 'ORVIX_AUDIT_SHADOW {...}'
--      to the PostgreSQL server log BEFORE inserting. Server-log lines are not rolled back, and control_app cannot
--      lower log_min_messages (superuser-only). Each row stores the same shadow_id, so scripts/audit-shadow.ts (host
--      tool) can list audit events that were written and then ROLLED BACK (suppressed refusals/reads), with xid.
-- INHERENT LIMITS (not fixable while the attacker holds a DB credential that can open transactions)
--   - Between the offending statement and the watchdog pass (<= ~poll interval + 5 s), audited calls can stall
--     (fail closed, lock_timeout 3 s).
--   - Rolled-back rows are DETECTED (shadow log), not PREVENTED; rate-limit counts can still be undone (CPU only).
--   - A superuser can still disable logging or the watchdog (infrastructure trust).
-- ============================================================

ALTER ROLE control_app SET transaction_timeout = '10s';

INSERT INTO control.audit_actions (action, description) VALUES
  ('platform.watchdog_terminated', 'Watchdog terminated control_app sessions holding transactions open');

ALTER TABLE control.audit_events ADD COLUMN shadow_id uuid;   -- matches the server-log shadow line (not hashed)

-- ------------------------------------------------------------ shadow evidence in audit_append
CREATE OR REPLACE FUNCTION control.audit_append(
  p_actor_type text, p_actor_id uuid, p_actor_label text, p_action text, p_outcome text,
  p_target_type text DEFAULT NULL, p_target_id text DEFAULT NULL, p_request_id uuid DEFAULT NULL,
  p_reason_code text DEFAULT NULL, p_detail jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE v_prev_seq bigint; v_prev_hash bytea; v_seq bigint; v_at timestamptz := date_trunc('microseconds', clock_timestamp());
        v_hash bytea; v_detail jsonb := control.audit_safe_detail(p_detail); v_shadow uuid := gen_random_uuid();
BEGIN
  -- written to the server log immediately; survives ROLLBACK of the caller's transaction
  RAISE LOG 'ORVIX_AUDIT_SHADOW %', jsonb_build_object('shadow_id', v_shadow, 'xid', txid_current(), 'at', v_at,
    'session_user', session_user, 'actor_type', p_actor_type, 'actor_id', p_actor_id, 'action', p_action,
    'outcome', p_outcome, 'target_type', p_target_type, 'target_id', p_target_id, 'reason_code', p_reason_code)::text;
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

-- ------------------------------------------------------------ watchdog
DO $r$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'control_watchdog_owner') THEN
    CREATE ROLE control_watchdog_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOREPLICATION NOBYPASSRLS;
  END IF;
END
$r$;
GRANT pg_signal_backend TO control_watchdog_owner WITH INHERIT TRUE;
GRANT pg_read_all_stats TO control_watchdog_owner WITH INHERIT TRUE;
GRANT USAGE ON SCHEMA control TO control_watchdog_owner;
GRANT EXECUTE ON FUNCTION control.audit_append(text, uuid, text, text, text, text, text, uuid, text, jsonb) TO control_watchdog_owner;
ALTER DEFAULT PRIVILEGES FOR ROLE control_watchdog_owner REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

GRANT CREATE ON SCHEMA control TO control_watchdog_owner;
SET ROLE control_watchdog_owner;
CREATE FUNCTION control.sentinel_watchdog(p_idle_seconds integer DEFAULT 5, p_xact_seconds integer DEFAULT 15) RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE r record; n integer := 0; v_pids integer[] := '{}';
BEGIN
  FOR r IN
    SELECT a.pid, a.state, (clock_timestamp() - a.xact_start) AS xact_age
      FROM pg_stat_activity a
     WHERE a.usename = 'control_app' AND a.pid <> pg_backend_pid() AND a.backend_type = 'client backend'
       AND ((a.state LIKE 'idle in transaction%' AND clock_timestamp() - a.state_change > make_interval(secs => greatest(p_idle_seconds, 2)))
            OR (a.xact_start IS NOT NULL AND clock_timestamp() - a.xact_start > make_interval(secs => greatest(p_xact_seconds, 5))))
  LOOP
    IF pg_terminate_backend(r.pid) THEN n := n + 1; v_pids := v_pids || r.pid; END IF;
  END LOOP;
  IF n > 0 THEN
    PERFORM control.audit_append('system', NULL, 'watchdog', 'platform.watchdog_terminated', 'success', 'backend',
      NULL, NULL, 'STALE_TRANSACTION', jsonb_build_object('terminated', n, 'pids', to_jsonb(v_pids)));
  END IF;
  RETURN n;
END
$$;
RESET ROLE;
REVOKE CREATE ON SCHEMA control FROM control_watchdog_owner;

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA control FROM PUBLIC;
GRANT EXECUTE ON FUNCTION control.sentinel_watchdog(integer, integer) TO control_sentinel;
