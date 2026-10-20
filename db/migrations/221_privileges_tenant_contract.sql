-- ============================================================
-- 221 (C1.3, provisional): database ACL re-assertion, tenant replay isolation, contract 0.5.
--
-- M4   The control database's ACL is re-asserted here AND on every migrate run (scripts/migrator.ts): PUBLIC has no
--      CONNECT/TEMP; only control_app and control_sentinel may connect. A restore into a plain CREATE DATABASE (PUBLIC
--      default ACL) is therefore corrected by the next migrate run, and the app/sentinel startup checks refuse to run
--      until it is (src/server/db/api.ts, scripts/sentinel.ts).
-- M3   Cross-database exposure is enforced outside this database: db/cluster/pg_hba.conf (control roles may only reach
--      control databases) and scripts/harden-cluster.ts (PUBLIC CONNECT/TEMP revoked on postgres/template1). The app
--      and the sentinel refuse to run while their role can CONNECT to any non-control database.
-- LOW  A tenant transition replay must match the tenant AND the target state; reusing a request id on another tenant
--      returns REQUEST_ID_CONFLICT instead of tenant A's cached result.
-- ============================================================

DO $acl$
BEGIN
  -- every privilege, also per-role extras (e.g. CREATE granted later), then exactly CONNECT for the two login roles
  EXECUTE format('REVOKE ALL ON DATABASE %I FROM PUBLIC, control_app, control_sentinel', current_database());
  EXECUTE format('GRANT CONNECT ON DATABASE %I TO control_app, control_sentinel', current_database());
END
$acl$;

-- REVIEW (C1.3) built-ins that let any role write unbounded WAL or burn transaction ids (disk / wraparound DoS)
DO $wal$
DECLARE f record;
BEGIN
  FOR f IN SELECT p.oid::regprocedure AS sig FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname = 'pg_catalog' AND p.proname IN ('pg_logical_emit_message', 'txid_current', 'pg_current_xact_id') LOOP
    EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC', f.sig);
  END LOOP;
END
$wal$;
GRANT EXECUTE ON FUNCTION pg_catalog.txid_current() TO control_audit_owner;   -- audit_append's shadow line (xid)

-- As 207 + the replay must be for the same tenant and target state.
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
    IF v_prior.identity_id <> c.identity_id OR v_prior.action <> 'tenant_transition'
       OR v_prior.result ->> 'tenant_id' IS DISTINCT FROM p_tenant_id::text
       OR v_prior.result ->> 'to' IS DISTINCT FROM p_to_state THEN
      RETURN control.err('REQUEST_ID_CONFLICT');
    END IF;
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

CREATE OR REPLACE FUNCTION control.api_contract_version() RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = control, pg_temp AS $$
  SELECT 'orvix-control/0.5'::text
$$;

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA control FROM PUBLIC;
GRANT EXECUTE ON FUNCTION control.api_contract_version(), control.api_tenant_transition(text, uuid, text, text, text, uuid) TO control_app;
