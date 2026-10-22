-- ============================================================
-- 223 (Step 6, provisional): POS recovery bridge OVER THE NETWORK, contract orvix-control/0.7.
--
-- PURPOSE  222 called the POS-owned operator interface (recovery_v1.operator_*) inside Control's own database, which
--          assumed a single shared database. Control and the POS are SEPARATE systems with separate databases. 223
--          keeps 222's API, policy, step-up and audit rules unchanged and reaches the POS over the network instead:
--          dblink from this database to the POS database, logging in as a dedicated POS LOGIN role (deployment step
--          owned by the POS owner: `orvix_control_bridge`, member of orvix_recovery_operator only, inherit-only).
-- BOUNDARY (unchanged from 222) Control holds NO recovery-release authority and NO signing key; it calls ONLY the seven
--          operator functions, never reads a POS table, and never sets ACTIVE. In addition:
--          * the network credential lives in a USER MAPPING for control_definer (NOLOGIN), readable only by the cluster
--            superuser and that role; control_app, control_sentinel and PUBLIC cannot execute any dblink function and
--            have no user mapping (startup check, src/server/db/privilegeCheck.ts);
--          * the remote SQL is built only inside the seven api_pos_recovery_* functions, with every value quoted (%L);
--          * on every call the bridge first checks, ON THE POS, that its login is not superuser / bypassrls / createrole
--            / createdb / replication, is a member of nothing but orvix_recovery_operator, and can execute all seven
--            contract functions (SECURITY DEFINER, jsonb, not owned by the login). Otherwise POS_RECOVERY_UNAVAILABLE.
--          * 222's single-database grant (orvix_recovery_operator -> control_definer) is no longer used or tolerated.
-- ATOMICITY The POS call runs in an explicit REMOTE transaction that is committed LAST, after Control's audit row and
--          request result are written: a Control failure before that point rolls the POS back. If the remote COMMIT
--          itself fails or its reply is lost, the POS outcome is unknown: Control records POS_RECOVERY_IN_DOUBT (audited,
--          with the request id, which is also carried in the POS-side actor label for correlation). Reads always roll
--          the remote transaction back.
-- CONFIG   Deployment-specific, by the host (superuser) with scripts/pos-bridge.ts: SERVER orvix_pos_recovery
--          (dblink_fdw: host, port, dbname, sslmode [+ sslrootcert], connect_timeout, remote statement/lock/idle
--          timeouts), USAGE to control_definer, USER MAPPING for control_definer (user, password), and the BINDING row
--          (control.pos_bridge_binding): the bridge works only in the database it was configured in (system identifier,
--          database oid and name) — a restored or copied Control database (a drill, a staging copy) never inherits a
--          working bridge to the POS — and records whether TLS is required. TLS (verify-full) is required unless the host
--          explicitly configured an insecure DEVELOPMENT bridge, which is recorded and audited on every call.
--          Not configured => every API returns POS_RECOVERY_UNAVAILABLE (audited).
-- ROLLBACK Restore only (222's functions were CREATE, not OR REPLACE, and 223 drops two of its helpers): restore the
--          pre-223 recovery point, then reconcile POS changes made since then against the POS audit (actor labels carry
--          the Control request id). A full backup of a configured Control database contains the bridge credential
--          (user mapping): treat Control backups as secrets.
-- ============================================================

-- ------------------------------------------------------------ dblink, executable by control_definer ONLY
CREATE EXTENSION IF NOT EXISTS dblink WITH SCHEMA control_ext;
DO $grants$
DECLARE f regprocedure;
BEGIN
  FOR f IN SELECT p.oid::regprocedure FROM pg_proc p JOIN pg_depend d ON d.classid = 'pg_proc'::regclass AND d.objid = p.oid
            WHERE d.refclassid = 'pg_extension'::regclass AND d.deptype = 'e'
              AND d.refobjid = (SELECT oid FROM pg_extension WHERE extname = 'dblink') LOOP
    EXECUTE format('REVOKE ALL ON FUNCTION %s FROM PUBLIC', f);
  END LOOP;
END
$grants$;
GRANT EXECUTE ON FUNCTION control_ext.dblink_connect(text, text), control_ext.dblink(text, text), control_ext.dblink_exec(text, text),
  control_ext.dblink_disconnect(text), control_ext.dblink_get_connections() TO control_definer;

INSERT INTO control.audit_actions (action, description) VALUES
  ('pos.recovery_in_doubt', 'POS recovery call whose remote commit could not be confirmed (outcome unknown; check the POS audit by request id)');

-- The bridge's binding to THIS database (written by the host with scripts/pos-bridge.ts, as the superuser; readable by
-- control_definer only). One row.
CREATE TABLE control.pos_bridge_binding (
  id                smallint PRIMARY KEY CHECK (id = 1),
  system_identifier text NOT NULL,
  database_oid      oid NOT NULL,
  database_name     name NOT NULL,
  tls_required      boolean NOT NULL,
  configured_at     timestamptz NOT NULL DEFAULT clock_timestamp());
REVOKE ALL ON control.pos_bridge_binding FROM PUBLIC;
ALTER TABLE control.pos_bridge_binding OWNER TO control_definer;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON control.pos_bridge_binding FROM control_definer;
GRANT SELECT ON control.pos_bridge_binding TO control_definer;
ALTER TABLE control.pos_bridge_binding ENABLE ROW LEVEL SECURITY;   -- every control table (privileges.test.ts); the owner reads it

-- out-of-band notices: an in-doubt containment / submission reaches the owners like a successful one (as 222 + in_doubt)
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
    'platform.watchdog_intent_resolved',
    'pos.recovery_transitioned', 'pos.recovery_device_contained', 'pos.recovery_submitted', 'pos.recovery_in_doubt']::text[]
$$;
RESET ROLE;
REVOKE CREATE ON SCHEMA control FROM control_audit_owner;

-- ------------------------------------------------------------ the network bridge (tenant-model owner)
GRANT CREATE ON SCHEMA control TO control_definer;
SET ROLE control_definer;

-- Configured by the host: the server exists, this role may use it, and a user mapping for this role exists.
CREATE FUNCTION control.pos_bridge_configured() RETURNS boolean
LANGUAGE sql STABLE SET search_path = control, pg_catalog, pg_temp AS $$
  SELECT EXISTS (SELECT 1 FROM pg_foreign_server s JOIN pg_foreign_data_wrapper w ON w.oid = s.srvfdw
                  WHERE s.srvname = 'orvix_pos_recovery' AND w.fdwname = 'dblink_fdw'
                    AND has_server_privilege(s.oid, 'USAGE'))
     AND EXISTS (SELECT 1 FROM pg_user_mappings m WHERE m.srvname = 'orvix_pos_recovery' AND m.usename = current_user)
     -- configured in THIS database: a restore or copy elsewhere does not carry a working bridge
     AND EXISTS (SELECT 1 FROM control.pos_bridge_binding b
                  WHERE b.system_identifier = (SELECT c.system_identifier::text FROM pg_control_system() c)
                    AND b.database_oid = (SELECT d.oid FROM pg_database d WHERE d.datname = current_database())
                    AND b.database_name = current_database())
$$;

-- Close this backend's bridge connection, committing (p_commit) or abandoning its remote transaction. A failed COMMIT raises
-- (the caller records the outcome) and leaves the connection for an abandoning close.
CREATE FUNCTION control.pos_bridge_close(p_commit boolean) RETURNS void
LANGUAGE plpgsql VOLATILE SET search_path = control, pg_temp AS $$
DECLARE v_status text;
BEGIN
  IF NOT ('orvix_pos' = ANY (coalesce(control_ext.dblink_get_connections(), '{}'::text[]))) THEN RETURN; END IF;
  IF p_commit THEN
    v_status := control_ext.dblink_exec('orvix_pos', 'COMMIT');
    IF v_status IS DISTINCT FROM 'COMMIT' THEN
      RAISE EXCEPTION 'POS_BRIDGE_COMMIT_NOT_CONFIRMED: %', left(v_status, 40) USING ERRCODE = '40003';
    END IF;
  END IF;
  -- Not committing = disconnecting: the POS aborts the open remote transaction when its connection closes. No ROLLBACK is
  -- sent, so an error path never waits on a POS that has stopped answering.
  PERFORM control_ext.dblink_disconnect('orvix_pos');
END
$$;

-- Commit the remote transaction of a call the POS REFUSED (its own refusal audit row, rate-limit counters), best effort —
-- only for the contract's refusal outcomes; anything else (NULL, an unknown outcome) is abandoned, never committed.
CREATE FUNCTION control.pos_bridge_keep_refusal(p_outcome text) RETURNS void
LANGUAGE plpgsql VOLATILE SET search_path = control, pg_temp AS $$
BEGIN
  IF p_outcome IS NULL OR p_outcome NOT IN ('refused', 'denied') THEN
    PERFORM control.pos_bridge_close(false);
    RETURN;
  END IF;
  PERFORM control.pos_bridge_close(true);
EXCEPTION WHEN OTHERS OR query_canceled THEN
  PERFORM control.pos_bridge_close(false);
END
$$;

-- Open the bridge: connect, verify the POS-side login and the contract, BEGIN a remote transaction.
-- Returns NULL when ready, else the reason (recorded in the audit detail; the API answers POS_RECOVERY_UNAVAILABLE).
CREATE FUNCTION control.pos_bridge_open() RETURNS text
LANGUAGE plpgsql VOLATILE SET search_path = control, pg_temp AS $$
DECLARE v jsonb;
BEGIN
  PERFORM control.pos_bridge_close(false);   -- a stale connection of this backend (an aborted earlier call) is rolled back
  IF NOT control.pos_bridge_configured() THEN RETURN 'not_configured'; END IF;
  -- TIME BOUND: dblink connects without libpq's connect_timeout (non-blocking connect), and a POS whose processes stop
  -- answering accepts TCP but never completes the handshake. Every bridge step is therefore bounded by the CALLER's
  -- statement_timeout (the web server sets 5 s): the cancellation is caught here and answered as unavailable (Step 6, I09).
  BEGIN
    PERFORM control_ext.dblink_connect('orvix_pos', 'orvix_pos_recovery');
  EXCEPTION WHEN query_canceled THEN
    PERFORM control.pos_bridge_close(false);
    RETURN 'timeout';
  WHEN OTHERS THEN
    RETURN 'unreachable';
  END;
  BEGIN
    SELECT r::jsonb INTO v FROM control_ext.dblink('orvix_pos', format($q$
      SELECT jsonb_build_object(
        'privileged', (SELECT r.rolsuper OR r.rolbypassrls OR r.rolcreaterole OR r.rolcreatedb OR r.rolreplication
                         FROM pg_catalog.pg_roles r WHERE r.rolname = session_user),
        'otherRoles', (SELECT count(*) FROM pg_catalog.pg_roles g
                        WHERE g.rolname NOT IN (session_user::text, 'orvix_recovery_operator')
                          AND pg_catalog.pg_has_role(session_user, g.oid, 'MEMBER')),
        'functions', (SELECT count(*) FROM unnest(%L::text[]) s(sig)
                        JOIN pg_catalog.pg_proc p ON p.oid = pg_catalog.to_regprocedure(s.sig)
                       WHERE p.prorettype = 'jsonb'::pg_catalog.regtype AND p.prosecdef AND p.prokind = 'f'
                         AND pg_catalog.pg_get_userbyid(p.proowner) <> session_user
                         AND pg_catalog.has_function_privilege(session_user, p.oid, 'EXECUTE')))::text $q$,
      control.pos_recovery_contract())) AS t(r text);
  EXCEPTION WHEN query_canceled THEN
    PERFORM control.pos_bridge_close(false);
    RETURN 'timeout';
  WHEN OTHERS THEN
    PERFORM control.pos_bridge_close(false);
    RETURN 'unreachable';
  END;
  IF coalesce((v ->> 'privileged')::boolean, true) OR coalesce((v ->> 'otherRoles')::int, 1) <> 0 THEN
    PERFORM control.pos_bridge_close(false);
    RETURN 'bridge_login_overprivileged';
  END IF;
  IF coalesce((v ->> 'functions')::int, 0) <> cardinality(control.pos_recovery_contract()) THEN
    PERFORM control.pos_bridge_close(false);
    RETURN 'contract_incomplete';
  END IF;
  -- TLS: required unless the host configured an explicitly insecure development bridge (recorded in the binding)
  IF (SELECT b.tls_required FROM control.pos_bridge_binding b WHERE b.id = 1) THEN
    BEGIN
      SELECT r::jsonb INTO v FROM control_ext.dblink('orvix_pos',
        'SELECT jsonb_build_object(''ssl'', coalesce((SELECT s.ssl FROM pg_catalog.pg_stat_ssl s WHERE s.pid = pg_catalog.pg_backend_pid()), false))::text') AS t(r text);
    EXCEPTION WHEN OTHERS OR query_canceled THEN
      PERFORM control.pos_bridge_close(false);
      RETURN 'unreachable';
    END;
    IF NOT coalesce((v ->> 'ssl')::boolean, false) THEN
      PERFORM control.pos_bridge_close(false);
      RETURN 'tls_required';
    END IF;
  END IF;
  BEGIN
    PERFORM control_ext.dblink_exec('orvix_pos', 'BEGIN ISOLATION LEVEL READ COMMITTED');
  EXCEPTION WHEN OTHERS OR query_canceled THEN
    PERFORM control.pos_bridge_close(false);
    RETURN 'unreachable';
  END;
  RETURN NULL;
END
$$;

-- One remote call (SQL built by the api_* wrappers with quoted values only). Remote errors propagate with their SQLSTATE
-- and primary message (dblink), so 222's error mapping still applies.
CREATE FUNCTION control.pos_bridge_call(p_sql text) RETURNS jsonb
LANGUAGE sql VOLATILE SET search_path = control, pg_temp AS $$
  SELECT r::jsonb FROM control_ext.dblink('orvix_pos', p_sql) AS t(r text)
$$;

-- POS exception -> stable code (as 222, plus network classes: connection failures, cancellation / timeout, shutdown).
CREATE OR REPLACE FUNCTION control.pos_recovery_error_code(p_state text, p_message text) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE
    WHEN p_message LIKE 'RECOVERY_V1_OPERATOR_INVALID%' THEN 'NOT_FOUND'
    WHEN p_message LIKE 'RECOVERY_V1_DEVICE_CONTAIN_INVALID%' THEN 'POS_RECOVERY_INVALID'
    WHEN p_message LIKE 'RECOVERY_V1_RECONCILIATION_STATE%' THEN 'POS_RECOVERY_STATE'
    WHEN p_message LIKE 'RECOVERY_V1_%RATE_LIMITED%' THEN 'RATE_LIMITED'
    WHEN p_state IN ('42501', '42883', '3F000', '42P01') THEN 'POS_RECOVERY_UNAVAILABLE'
    WHEN p_state LIKE '08%' OR p_state IN ('57014', '57P01', '57P02', '57P03') THEN 'POS_RECOVERY_UNAVAILABLE'
    ELSE 'POS_RECOVERY_ERROR' END
$$;

-- Actor label carried to the POS (the POS prefixes 'operator:' and appends '@' || session_user): mutating calls carry the
-- Control request id so that a POS audit row can always be matched with its Control audit row (including in-doubt ones).
CREATE FUNCTION control.pos_recovery_actor(c control.session_ctx, p_request_id uuid) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT 'control:' || c.role || ':' || c.identity_id::text || ':' || p_request_id::text
$$;

-- Refusal: roll back any open remote transaction, one audit row, then the error. (Internal; as control_definer.)
CREATE OR REPLACE FUNCTION control.pos_recovery_refuse(c control.session_ctx, p_action text, p_target text, p_request_id uuid,
                                                       p_code text, p_detail jsonb) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SET search_path = control, pg_temp AS $$
BEGIN
  PERFORM control.pos_bridge_close(false);
  PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, p_action, 'denied', 'pos_organization',
    p_target, p_request_id, p_code, coalesce(p_detail, '{}'::jsonb));
  RETURN control.err(p_code);
END
$$;

-- The commit of a mutating call: Control's audit row and request result, THEN the remote COMMIT.
--  * a failure before the remote COMMIT (local) or a COMMIT the POS answers with an error: the POS rolled back, the local
--    rows are undone (subtransaction), and the call is refused as POS_RECOVERY_ERROR (nothing changed anywhere);
--  * the connection lost during the COMMIT (no answer): the POS outcome is unknown -> POS_RECOVERY_IN_DOUBT, audited with
--    the actor label the POS recorded (it carries the request id) so the two audit trails can be matched.
CREATE FUNCTION control.pos_recovery_commit(c control.session_ctx, p_action text, p_refused_action text, p_api text, p_org text,
                                            p_request_id uuid, p_detail jsonb, p_result jsonb) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SET search_path = control, pg_temp AS $$
DECLARE v_seq bigint; v_state text; v_msg text; v_result jsonb; v_phase text := 'local';
BEGIN
  BEGIN
    v_seq := control.audit_append('platform_identity', c.identity_id, c.display_name, p_action, 'success',
      'pos_organization', p_org, p_request_id, NULL, p_detail);
    v_result := p_result || jsonb_build_object('audit_seq', v_seq);
    INSERT INTO control.request_results (request_id, identity_id, action, result) VALUES (p_request_id, c.identity_id, p_api, v_result);
    v_phase := 'remote_commit';
    PERFORM control.pos_bridge_close(true);
    RETURN v_result;
  EXCEPTION WHEN OTHERS OR query_canceled THEN
    GET STACKED DIAGNOSTICS v_state = RETURNED_SQLSTATE, v_msg = MESSAGE_TEXT;
  END;
  PERFORM control.pos_bridge_close(false);
  -- no answer to the COMMIT (connection lost, POS shutting down, or no reply within the caller's statement timeout): unknown
  IF v_phase = 'remote_commit' AND (v_state LIKE '08%' OR v_state IN ('40003', '57014', '57P01', '57P02', '57P03')) THEN
    PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'pos.recovery_in_doubt', 'denied',
      'pos_organization', p_org, p_request_id, 'POS_RECOVERY_IN_DOUBT',
      jsonb_build_object('api', p_api, 'sqlstate', v_state, 'pos_actor', control.pos_recovery_actor(c, p_request_id)) || coalesce(p_detail, '{}'::jsonb));
    -- a replay of this request id answers "in doubt" again instead of running the POS call a second time (which could, e.g.,
    -- create a second suspension event and make an already-signed reinstatement stale)
    INSERT INTO control.request_results (request_id, identity_id, action, result)
    VALUES (p_request_id, c.identity_id, p_api, control.err('POS_RECOVERY_IN_DOUBT') || jsonb_build_object('org', p_org, 'target', p_result ->> 'target'));
    RETURN control.err('POS_RECOVERY_IN_DOUBT');
  END IF;
  PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, p_refused_action, 'denied',
    'pos_organization', p_org, p_request_id, 'POS_RECOVERY_ERROR',
    jsonb_build_object('api', p_api, 'phase', v_phase, 'sqlstate', v_state, 'pos_error', control.pos_recovery_error_token(v_msg), 'pos_rolled_back', true));
  RETURN control.err('POS_RECOVERY_ERROR');
END
$$;

-- One organization as Control shows it (as 222), plus each enrollment's current suspension event: an owner's device-reinstate
-- authorization must name it, and without it a suspended till could only be reinstated with direct POS database access.
CREATE OR REPLACE FUNCTION control.pos_recovery_org_view(j jsonb) RETURNS jsonb
LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE o jsonb; rep jsonb; hard jsonb; blocked jsonb := '[]'::jsonb;
BEGIN
  IF jsonb_typeof(j) IS DISTINCT FROM 'object' THEN RETURN NULL; END IF;
  o := control.pos_recovery_pick(j, ARRAY['orgId', 'state', 'incidentId', 'recoveryEpoch', 'activation']);
  o := o || jsonb_build_object('reopening',
         control.pos_recovery_pick(j -> 'reopening', ARRAY['reopenId', 'decision', 'acceptedBlockers', 'uncertainties', 'byKey', 'at']));
  rep := control.pos_recovery_pick(j -> 'lastReport', ARRAY['reportId', 'digest', 'blockers', 'at', 'facts']);
  IF rep IS NOT NULL THEN
    SELECT coalesce(jsonb_agg(x), '[]'::jsonb) INTO hard
      FROM jsonb_array_elements_text(CASE WHEN jsonb_typeof(rep -> 'blockers') = 'array' THEN rep -> 'blockers' ELSE '[]'::jsonb END) x
     WHERE control.pos_recovery_is_hard(x);
    rep := rep || jsonb_build_object('hardBlockers', hard);
  END IF;
  o := o || jsonb_build_object('lastReport', rep,
    'devices', jsonb_build_object(
      'pendingRequests', CASE WHEN jsonb_typeof(j #> '{devices,pendingRequests}') = 'number' THEN j #> '{devices,pendingRequests}' ELSE '0'::jsonb END,
      'enrollments', control.pos_recovery_pick_all(j #> '{devices,enrollments}',
                       ARRAY['enrollmentId', 'shopId', 'deviceId', 'keyFingerprint', 'state', 'notAfter', 'replaces', 'suspensionEventId'])),
    'ownerAuthority', control.pos_recovery_pick_all(j -> 'ownerAuthority', ARRAY['keyId', 'fingerprint', 'scope']));
  IF j ? 'deviceRequests' THEN
    o := o || jsonb_build_object('deviceRequests', control.pos_recovery_pick_all(j -> 'deviceRequests',
      ARRAY['requestId', 'shopId', 'deviceId', 'keyFingerprint', 'shortCode', 'requestNonce', 'replaces', 'requestedAt', 'requestedBy']));
  END IF;
  IF jsonb_array_length(o -> 'ownerAuthority') = 0 THEN blocked := blocked || '"no_owner_authority"'::jsonb; END IF;
  IF o ->> 'state' IS DISTINCT FROM 'ACTIVE' THEN
    IF o ->> 'state' IS DISTINCT FROM 'RECONCILING' THEN blocked := blocked || '"not_reconciling"'::jsonb; END IF;
    IF rep IS NULL THEN blocked := blocked || '"no_report"'::jsonb;
    ELSIF jsonb_array_length(rep -> 'hardBlockers') > 0 THEN blocked := blocked || '"hard_blockers"'::jsonb; END IF;
  END IF;
  RETURN o || jsonb_build_object('reopenBlockedBy', blocked);
END
$$;

-- ------------------------------------------------------------ read API (remote transaction always rolled back)
CREATE OR REPLACE FUNCTION control.api_pos_recovery_overview(p_token text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token); v_denied jsonb; v jsonb; v_state text; v_msg text; v_code text; v_open text;
BEGIN
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  v_denied := control.authorize(c, ARRAY['owner', 'admin'], false, 'pos_recovery_overview', NULL);
  IF v_denied IS NOT NULL THEN RETURN v_denied; END IF;
  v_open := control.pos_bridge_open();
  IF v_open IS NOT NULL THEN
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_read_refused', '*', NULL, 'POS_RECOVERY_UNAVAILABLE',
      jsonb_build_object('api', 'overview', 'bridge', v_open));
  END IF;
  BEGIN
    v := control.pos_bridge_call('SELECT recovery_v1.operator_overview()::text');
  EXCEPTION WHEN OTHERS OR query_canceled THEN
    GET STACKED DIAGNOSTICS v_state = RETURNED_SQLSTATE, v_msg = MESSAGE_TEXT;
    v_code := control.pos_recovery_error_code(v_state, v_msg);
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_read_refused', '*', NULL, v_code,
      jsonb_build_object('api', 'overview', 'sqlstate', v_state, 'pos_error', control.pos_recovery_error_token(v_msg)));
  END;
  PERFORM control.pos_bridge_close(false);
  SELECT coalesce(jsonb_agg(control.pos_recovery_org_view(x) ORDER BY o), '[]'::jsonb) INTO v
    FROM jsonb_array_elements(CASE WHEN jsonb_typeof(v) = 'array' THEN v ELSE '[]'::jsonb END) WITH ORDINALITY t(x, o);
  PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'pos.recovery_viewed', 'success',
    'pos_organization', '*', NULL, NULL, jsonb_build_object('api', 'overview', 'organizations', jsonb_array_length(v)));
  RETURN jsonb_build_object('ok', true, 'organizations', v);
END
$$;

CREATE OR REPLACE FUNCTION control.api_pos_recovery_org(p_token text, p_org text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token); v_denied jsonb; v jsonb; v_state text; v_msg text; v_open text;
BEGIN
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  v_denied := control.authorize(c, ARRAY['owner', 'admin'], false, 'pos_recovery_org', NULL);
  IF v_denied IS NOT NULL THEN RETURN v_denied; END IF;
  IF NOT control.pos_recovery_org_ok(p_org) THEN
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_read_refused', left(p_org, 100), NULL, 'INVALID_INPUT', '{"api":"organization"}');
  END IF;
  v_open := control.pos_bridge_open();
  IF v_open IS NOT NULL THEN
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_read_refused', p_org, NULL, 'POS_RECOVERY_UNAVAILABLE',
      jsonb_build_object('api', 'organization', 'bridge', v_open));
  END IF;
  BEGIN
    v := control.pos_bridge_call(format('SELECT recovery_v1.operator_organization(%L)::text', p_org));
  EXCEPTION WHEN OTHERS OR query_canceled THEN
    GET STACKED DIAGNOSTICS v_state = RETURNED_SQLSTATE, v_msg = MESSAGE_TEXT;
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_read_refused', p_org, NULL, control.pos_recovery_error_code(v_state, v_msg),
      jsonb_build_object('api', 'organization', 'sqlstate', v_state, 'pos_error', control.pos_recovery_error_token(v_msg)));
  END;
  PERFORM control.pos_bridge_close(false);
  PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'pos.recovery_viewed', 'success',
    'pos_organization', p_org, NULL, NULL, '{"api":"organization"}'::jsonb);
  RETURN jsonb_build_object('ok', true, 'organization', control.pos_recovery_org_view(v));
END
$$;

CREATE OR REPLACE FUNCTION control.api_pos_recovery_audit(p_token text, p_org text, p_limit integer) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token); v_denied jsonb; v jsonb; v_state text; v_msg text; v_open text;
BEGIN
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  v_denied := control.authorize(c, ARRAY['owner', 'admin'], false, 'pos_recovery_audit', NULL);
  IF v_denied IS NOT NULL THEN RETURN v_denied; END IF;
  IF NOT control.pos_recovery_org_ok(p_org) OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 200 THEN
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_read_refused', left(p_org, 100), NULL, 'INVALID_INPUT', '{"api":"audit"}');
  END IF;
  v_open := control.pos_bridge_open();
  IF v_open IS NOT NULL THEN
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_read_refused', p_org, NULL, 'POS_RECOVERY_UNAVAILABLE',
      jsonb_build_object('api', 'audit', 'bridge', v_open));
  END IF;
  BEGIN
    v := control.pos_bridge_call(format('SELECT recovery_v1.operator_audit(%L, %s)::text', p_org, p_limit));
  EXCEPTION WHEN OTHERS OR query_canceled THEN
    GET STACKED DIAGNOSTICS v_state = RETURNED_SQLSTATE, v_msg = MESSAGE_TEXT;
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_read_refused', p_org, NULL, control.pos_recovery_error_code(v_state, v_msg),
      jsonb_build_object('api', 'audit', 'sqlstate', v_state, 'pos_error', control.pos_recovery_error_token(v_msg)));
  END;
  PERFORM control.pos_bridge_close(false);
  PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'pos.recovery_viewed', 'success',
    'pos_organization', p_org, NULL, NULL, '{"api":"audit"}'::jsonb);
  RETURN jsonb_build_object('ok', true, 'events', control.pos_recovery_pick_all(v, ARRAY['id', 'kind', 'detail', 'actor', 'at']));
END
$$;

-- ------------------------------------------------------------ containment
CREATE OR REPLACE FUNCTION control.api_pos_recovery_transition(p_token text, p_org text, p_to_state text, p_reason text,
                                                               p_evidence_reference text, p_request_id uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token); v_denied jsonb; v_prior jsonb; v jsonb; v_state text; v_msg text;
        v_target text; v_open text;
BEGIN
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  IF p_request_id IS NULL THEN RETURN control.err('REQUEST_ID_REQUIRED'); END IF;
  v_target := left(p_org, 100) || ':' || left(coalesce(p_to_state, ''), 20);
  v_prior := control.pos_recovery_replay(c, p_request_id, 'pos_recovery_transition', p_org, v_target);
  IF v_prior IS NOT NULL THEN RETURN v_prior; END IF;
  v_denied := control.authorize(c, ARRAY['owner', 'admin'], false, 'pos_recovery_transition', p_request_id);
  IF v_denied IS NOT NULL THEN RETURN v_denied; END IF;
  IF NOT control.pos_recovery_org_ok(p_org) THEN
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_transition_refused', left(p_org, 100), p_request_id, 'INVALID_INPUT', '{}');
  END IF;
  -- Control never sets ACTIVE: only an owner-signed reopening, verified by the POS, does.
  IF p_to_state IS NULL OR p_to_state NOT IN ('RESTRICTED', 'RECONCILING', 'QUARANTINED') THEN
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_transition_refused', p_org, p_request_id, 'TRANSITION_NOT_ALLOWED',
      jsonb_build_object('to', left(p_to_state, 40)));
  END IF;
  IF length(btrim(coalesce(p_reason, ''))) NOT BETWEEN 10 AND 500
     OR length(btrim(coalesce(p_evidence_reference, ''))) NOT BETWEEN 3 AND 500 THEN
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_transition_refused', p_org, p_request_id, 'REASON_REQUIRED', jsonb_build_object('to', p_to_state));
  END IF;
  v_open := control.pos_bridge_open();
  IF v_open IS NOT NULL THEN
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_transition_refused', p_org, p_request_id, 'POS_RECOVERY_UNAVAILABLE',
      jsonb_build_object('to', p_to_state, 'bridge', v_open));
  END IF;
  IF NOT control.stepup_consume_token(p_token, 'pos_recovery_transition', p_org || ':' || p_to_state) THEN
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_transition_refused', p_org, p_request_id, 'STEPUP_REQUIRED', jsonb_build_object('to', p_to_state));
  END IF;
  BEGIN
    v := control.pos_bridge_call(format('SELECT recovery_v1.operator_transition(%L, %L, %L, %L, %L)::text',
      p_org, p_to_state, btrim(p_reason), btrim(p_evidence_reference), control.pos_recovery_actor(c, p_request_id)));
  EXCEPTION WHEN OTHERS OR query_canceled THEN
    GET STACKED DIAGNOSTICS v_state = RETURNED_SQLSTATE, v_msg = MESSAGE_TEXT;
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_transition_refused', p_org, p_request_id, control.pos_recovery_error_code(v_state, v_msg),
      jsonb_build_object('to', p_to_state, 'sqlstate', v_state, 'pos_error', control.pos_recovery_error_token(v_msg)));
  END;
  IF v ->> 'outcome' IS DISTINCT FROM 'applied' THEN
    PERFORM control.pos_bridge_keep_refusal(v ->> 'outcome');
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_transition_refused', p_org, p_request_id, 'POS_RECOVERY_DENIED',
      jsonb_build_object('to', p_to_state, 'pos_outcome', left(v ->> 'outcome', 40)));
  END IF;
  RETURN control.pos_recovery_commit(c, 'pos.recovery_transitioned', 'pos.recovery_transition_refused', 'pos_recovery_transition', p_org, p_request_id,
    jsonb_build_object('to', v ->> 'state', 'incident_id', v ->> 'incidentId', 'recovery_epoch', v -> 'recoveryEpoch',
                       'evidence_reference', left(btrim(p_evidence_reference), 200)),
    jsonb_build_object('ok', true, 'org', p_org, 'target', v_target, 'outcome', 'applied', 'state', v ->> 'state',
                       'incidentId', v ->> 'incidentId', 'recoveryEpoch', v -> 'recoveryEpoch'));
END
$$;

CREATE OR REPLACE FUNCTION control.api_pos_recovery_contain_device(p_token text, p_org text, p_enrollment uuid, p_action text,
                                                                   p_reason text, p_request_id uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token); v_denied jsonb; v_prior jsonb; v jsonb; v_state text; v_msg text;
        v_target text; v_open text;
BEGIN
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  IF p_request_id IS NULL THEN RETURN control.err('REQUEST_ID_REQUIRED'); END IF;
  v_target := left(p_org, 100) || ':' || coalesce(p_enrollment::text, '') || ':' || left(coalesce(p_action, ''), 10);
  v_prior := control.pos_recovery_replay(c, p_request_id, 'pos_recovery_contain', p_org, v_target);
  IF v_prior IS NOT NULL THEN RETURN v_prior; END IF;
  v_denied := control.authorize(c, ARRAY['owner', 'admin'], false, 'pos_recovery_contain', p_request_id);
  IF v_denied IS NOT NULL THEN RETURN v_denied; END IF;
  IF NOT control.pos_recovery_org_ok(p_org) OR p_enrollment IS NULL OR p_action IS NULL OR p_action NOT IN ('suspend', 'revoke') THEN
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_contain_refused', left(p_org, 100), p_request_id, 'INVALID_INPUT', '{}');
  END IF;
  IF length(btrim(coalesce(p_reason, ''))) NOT BETWEEN 10 AND 300 THEN
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_contain_refused', p_org, p_request_id, 'REASON_REQUIRED',
      jsonb_build_object('enrollment_id', p_enrollment, 'action', p_action));
  END IF;
  v_open := control.pos_bridge_open();
  IF v_open IS NOT NULL THEN
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_contain_refused', p_org, p_request_id, 'POS_RECOVERY_UNAVAILABLE',
      jsonb_build_object('enrollment_id', p_enrollment, 'action', p_action, 'bridge', v_open));
  END IF;
  IF NOT control.stepup_consume_token(p_token, 'pos_recovery_contain', p_org || ':' || p_enrollment::text || ':' || p_action) THEN
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_contain_refused', p_org, p_request_id, 'STEPUP_REQUIRED',
      jsonb_build_object('enrollment_id', p_enrollment, 'action', p_action));
  END IF;
  BEGIN
    v := control.pos_bridge_call(format('SELECT recovery_v1.operator_contain_device(%L, %L::uuid, %L, %L, %L)::text',
      p_org, p_enrollment, p_action, btrim(p_reason), control.pos_recovery_actor(c, p_request_id)));
  EXCEPTION WHEN OTHERS OR query_canceled THEN
    GET STACKED DIAGNOSTICS v_state = RETURNED_SQLSTATE, v_msg = MESSAGE_TEXT;
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_contain_refused', p_org, p_request_id, control.pos_recovery_error_code(v_state, v_msg),
      jsonb_build_object('enrollment_id', p_enrollment, 'action', p_action, 'sqlstate', v_state, 'pos_error', control.pos_recovery_error_token(v_msg)));
  END;
  IF v ->> 'outcome' IS NULL OR v ->> 'outcome' NOT IN ('suspended', 'revoked') THEN
    PERFORM control.pos_bridge_keep_refusal(v ->> 'outcome');
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_contain_refused', p_org, p_request_id, 'POS_RECOVERY_DENIED',
      jsonb_build_object('enrollment_id', p_enrollment, 'action', p_action, 'pos_outcome', left(v ->> 'outcome', 40)));
  END IF;
  RETURN control.pos_recovery_commit(c, 'pos.recovery_device_contained', 'pos.recovery_contain_refused', 'pos_recovery_contain', p_org, p_request_id,
    jsonb_build_object('enrollment_id', p_enrollment, 'action', p_action, 'state', v ->> 'state'),
    jsonb_build_object('ok', true, 'org', p_org, 'target', v_target, 'outcome', v ->> 'outcome',
                       'enrollmentId', v ->> 'enrollmentId', 'state', v ->> 'state'));
END
$$;

CREATE OR REPLACE FUNCTION control.api_pos_recovery_report(p_token text, p_org text, p_request_id uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token); v_denied jsonb; v_prior jsonb; v jsonb; v_state text; v_msg text; v_open text;
BEGIN
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  IF p_request_id IS NULL THEN RETURN control.err('REQUEST_ID_REQUIRED'); END IF;
  v_prior := control.pos_recovery_replay(c, p_request_id, 'pos_recovery_report', p_org, left(p_org, 100));
  IF v_prior IS NOT NULL THEN RETURN v_prior; END IF;
  v_denied := control.authorize(c, ARRAY['owner', 'admin'], false, 'pos_recovery_report', p_request_id);
  IF v_denied IS NOT NULL THEN RETURN v_denied; END IF;
  IF NOT control.pos_recovery_org_ok(p_org) THEN
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_report_refused', left(p_org, 100), p_request_id, 'INVALID_INPUT', '{}');
  END IF;
  v_open := control.pos_bridge_open();
  IF v_open IS NOT NULL THEN
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_report_refused', p_org, p_request_id, 'POS_RECOVERY_UNAVAILABLE',
      jsonb_build_object('bridge', v_open));
  END IF;
  BEGIN
    v := control.pos_bridge_call(format('SELECT recovery_v1.operator_reconciliation_report(%L, %L)::text',
      p_org, control.pos_recovery_actor(c, p_request_id)));
  EXCEPTION WHEN OTHERS OR query_canceled THEN
    GET STACKED DIAGNOSTICS v_state = RETURNED_SQLSTATE, v_msg = MESSAGE_TEXT;
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_report_refused', p_org, p_request_id, control.pos_recovery_error_code(v_state, v_msg),
      jsonb_build_object('sqlstate', v_state, 'pos_error', control.pos_recovery_error_token(v_msg)));
  END;
  IF v ->> 'outcome' IS DISTINCT FROM 'reported' THEN
    PERFORM control.pos_bridge_keep_refusal(v ->> 'outcome');
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_report_refused', p_org, p_request_id, 'POS_RECOVERY_DENIED',
      jsonb_build_object('pos_outcome', left(v ->> 'outcome', 40)));
  END IF;
  -- signingTarget is the POS database binding the owner's reopening must name (database, system identifier, install time)
  RETURN control.pos_recovery_commit(c, 'pos.recovery_reported', 'pos.recovery_report_refused', 'pos_recovery_report', p_org, p_request_id,
    jsonb_build_object('report_id', v ->> 'reportId', 'incident_id', v ->> 'incidentId', 'recovery_epoch', v -> 'recoveryEpoch',
                       'digest', v ->> 'digest', 'blockers', v -> 'blockers'),
    control.pos_recovery_pick(v, ARRAY['outcome', 'reportId', 'orgId', 'incidentId', 'recoveryEpoch', 'digest', 'facts',
                                       'blockers', 'hardBlockers'])
      || jsonb_build_object('ok', true, 'org', p_org, 'target', left(p_org, 100), 'signingTarget', v -> 'target'));
END
$$;

-- ------------------------------------------------------------ owner-signed authorizations (transport only)
CREATE OR REPLACE FUNCTION control.api_pos_recovery_submit(p_token text, p_authorization text, p_signature text, p_request_id uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token); v_denied jsonb; v_prior jsonb; v jsonb; v_state text; v_msg text;
        a jsonb; v_purpose text; v_org text; v_hash text; v_target text; v_open text;
BEGIN
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  IF p_request_id IS NULL THEN RETURN control.err('REQUEST_ID_REQUIRED'); END IF;
  IF p_authorization IS NULL OR octet_length(p_authorization) NOT BETWEEN 2 AND 65536 THEN
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_submit_refused', NULL, p_request_id, 'INVALID_INPUT', '{}');
  END IF;
  v_hash := encode(sha256(convert_to(p_authorization, 'UTF8')), 'hex');
  BEGIN
    a := p_authorization::jsonb;
  EXCEPTION WHEN OTHERS THEN a := NULL;
  END;
  IF jsonb_typeof(a) = 'object' THEN v_purpose := a ->> 'purpose'; v_org := a ->> 'scope'; END IF;
  v_target := coalesce(left(v_purpose, 40), '') || ':' || v_hash;
  v_prior := control.pos_recovery_replay(c, p_request_id, 'pos_recovery_submit', v_org, v_target);
  IF v_prior IS NOT NULL THEN RETURN v_prior; END IF;
  -- Control reads purpose and scope only to choose the policy and the step-up target. The authority is the owner's
  -- signature, which only the POS verifies.
  IF v_purpose IS NULL OR v_purpose NOT IN ('enroll-device', 'device-reinstate', 'reopen-organization')
     OR NOT control.pos_recovery_org_ok(v_org)
     OR p_signature IS NULL OR p_signature !~ '^[0-9a-fA-F]+$' OR length(p_signature) NOT BETWEEN 2 AND 4096
     OR length(p_signature) % 2 <> 0 THEN
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_submit_refused', left(v_org, 100), p_request_id, 'INVALID_INPUT',
      jsonb_build_object('purpose', left(v_purpose, 40), 'authorization_sha256', v_hash));
  END IF;
  -- reopening an organization (the only path to ACTIVE) is carried by an OWNER only
  v_denied := control.authorize(c, CASE WHEN v_purpose = 'reopen-organization' THEN ARRAY['owner'] ELSE ARRAY['owner', 'admin'] END,
                                false, 'pos_recovery_submit', p_request_id);
  IF v_denied IS NOT NULL THEN RETURN v_denied; END IF;
  v_open := control.pos_bridge_open();
  IF v_open IS NOT NULL THEN
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_submit_refused', v_org, p_request_id, 'POS_RECOVERY_UNAVAILABLE',
      jsonb_build_object('purpose', v_purpose, 'authorization_sha256', v_hash, 'bridge', v_open));
  END IF;
  IF NOT control.stepup_consume_token(p_token, 'pos_recovery_submit', v_target) THEN
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_submit_refused', v_org, p_request_id, 'STEPUP_REQUIRED',
      jsonb_build_object('purpose', v_purpose, 'authorization_sha256', v_hash));
  END IF;
  BEGIN
    v := control.pos_bridge_call(format('SELECT recovery_v1.operator_submit(%L, %L, %L)::text',
      p_authorization, lower(p_signature), control.pos_recovery_actor(c, p_request_id)));
  EXCEPTION WHEN OTHERS OR query_canceled THEN
    GET STACKED DIAGNOSTICS v_state = RETURNED_SQLSTATE, v_msg = MESSAGE_TEXT;
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_submit_refused', v_org, p_request_id, control.pos_recovery_error_code(v_state, v_msg),
      jsonb_build_object('purpose', v_purpose, 'authorization_sha256', v_hash, 'sqlstate', v_state, 'pos_error', control.pos_recovery_error_token(v_msg)));
  END;
  IF v ->> 'outcome' IS NULL OR v ->> 'outcome' NOT IN ('enrolled', 'reinstated', 'reopened') THEN
    -- the POS verifier refused (bad signature, stale incident, blockers, ...): its refusal row is committed on the POS,
    -- its reason is recorded here, never trusted
    PERFORM control.pos_bridge_keep_refusal(v ->> 'outcome');
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_submit_refused', v_org, p_request_id, 'POS_RECOVERY_REFUSED',
      jsonb_build_object('purpose', v_purpose, 'authorization_sha256', v_hash, 'pos_outcome', left(v ->> 'outcome', 40),
                         'pos_error', control.pos_recovery_error_token(v ->> 'reason'), 'pos_reason', left(v ->> 'reason', 300)));
  END IF;
  RETURN control.pos_recovery_commit(c, 'pos.recovery_submitted', 'pos.recovery_submit_refused', 'pos_recovery_submit', v_org, p_request_id,
    jsonb_build_object('purpose', v_purpose, 'authorization_sha256', v_hash, 'outcome', v ->> 'outcome',
                       'enrollment_id', v ->> 'enrollmentId', 'reopen_id', v ->> 'reopenId', 'state', v ->> 'state'),
    control.pos_recovery_pick(v, ARRAY['outcome', 'enrollmentId', 'reopenId', 'state', 'decision', 'uncertainties', 'deviceId'])
      || jsonb_build_object('ok', true, 'org', v_org, 'target', v_target, 'purpose', v_purpose));
END
$$;

-- 222's local hook check and actor label are gone with the single-database model.
DROP FUNCTION control.pos_recovery_hook_ok();
DROP FUNCTION control.pos_recovery_actor(control.session_ctx);

RESET ROLE;
REVOKE CREATE ON SCHEMA control FROM control_definer;

CREATE OR REPLACE FUNCTION control.api_contract_version() RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = control, pg_temp AS $$
  SELECT 'orvix-control/0.7'::text
$$;

-- ------------------------------------------------------------ grants (as 222; the new internals are not granted)
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA control FROM PUBLIC;
GRANT EXECUTE ON FUNCTION control.api_contract_version(), control.api_stepup_begin(text, text, text),
  control.api_pos_recovery_overview(text), control.api_pos_recovery_org(text, text),
  control.api_pos_recovery_audit(text, text, integer),
  control.api_pos_recovery_transition(text, text, text, text, text, uuid),
  control.api_pos_recovery_contain_device(text, text, uuid, text, text, uuid),
  control.api_pos_recovery_report(text, text, uuid),
  control.api_pos_recovery_submit(text, text, text, uuid) TO control_app;
