-- ============================================================
-- 222 (Step 5, provisional): POS recovery bridge, contract orvix-control/0.6.
--
-- PURPOSE  Lets platform operators see and contain the POS's Recovery V1 state (schema recovery_v1, Orvix POS
--          RECOVERY_V1_guards.sql, Step 5) and TRANSPORT owner-signed authorizations to its verifier, through the
--          POS-owned interface functions `recovery_v1.operator_*` (contract: docs/pos_recovery_contract.json).
-- BOUNDARY Control holds NO recovery-release authority and NO signing key:
--          * it never reads a POS table (public.* or recovery_v1.*); it only calls the seven operator functions;
--          * it has no function that sets ACTIVE: api_pos_recovery_transition refuses ACTIVE (and anything other than
--            RESTRICTED / RECONCILING / QUARANTINED) before calling the POS; only an OWNER-SIGNED reopening, verified by
--            the POS, sets ACTIVE, and Control merely carries its text + hex signature;
--          * the only new privilege is the POS-owner's decision `GRANT orvix_recovery_operator TO control_definer`
--            (inherit, no SET, no ADMIN) in a single-database deployment. Nothing here grants or assumes it: without it
--            (or without the recovery_v1 hook) every api_pos_recovery_* returns POS_RECOVERY_UNAVAILABLE (audited) and
--            never falls back to anything else. The app's startup check (src/server/db/privilegeCheck.ts) tolerates
--            exactly that one membership and nothing else.
-- POLICY   (role = platform role of the session; step-up = single-use grant bound to action + target, 5 min)
--          | API                         | roles          | step-up action / target                                   |
--          | overview, org, audit (read) | owner, admin   | none                                                      |
--          | report (record a report)    | owner, admin   | none (request id; POS: only while RECONCILING)            |
--          | transition (containment)    | owner, admin   | pos_recovery_transition  <org>:<RESTRICTED|RECONCILING|QUARANTINED> |
--          | contain_device              | owner, admin   | pos_recovery_contain     <org>:<enrollment uuid>:<suspend|revoke> |
--          | submit enroll-device /      | owner, admin   | pos_recovery_submit      <purpose>:<sha256 hex of the authorization text> |
--          |   device-reinstate          |                |                                                           |
--          | submit reopen-organization  | OWNER only     | pos_recovery_submit      reopen-organization:<sha256 hex>  |
--          Step-up actions are paused while the operator is under recovery (219). Containment is protective, so an
--          admin may contain; trust is created ONLY by the owner's offline signature, which the POS verifies.
-- AUDIT    Every call that passes session resolution writes exactly one Control audit row in the same transaction as
--          the POS call (success, POS refusal, local refusal, POS unavailable). A POS exception is caught in a
--          subtransaction (its partial effects roll back) and mapped to a code; POS text never reaches the client.
-- ROLLBACK Restore from the pre-222 recovery point (as 218-221), or DROP the functions below and re-run 221's
--          api_contract_version / api_stepup_begin / notify_actions definitions.
-- ============================================================

INSERT INTO control.audit_actions (action, description) VALUES
  ('pos.recovery_viewed',             'POS recovery metadata read through the recovery_v1 operator interface'),
  ('pos.recovery_read_refused',       'POS recovery read refused (input, unknown organization, or POS hook unavailable)'),
  ('pos.recovery_transitioned',       'POS organization moved to a containment state (RESTRICTED / RECONCILING / QUARANTINED)'),
  ('pos.recovery_transition_refused', 'POS containment transition refused (locally or by the POS)'),
  ('pos.recovery_device_contained',   'POS till enrollment suspended or revoked'),
  ('pos.recovery_contain_refused',    'POS device containment refused (locally or by the POS)'),
  ('pos.recovery_reported',           'POS reconciliation report recorded'),
  ('pos.recovery_report_refused',     'POS reconciliation report refused (locally or by the POS)'),
  ('pos.recovery_submitted',          'Owner-signed authorization carried to the POS verifier and accepted'),
  ('pos.recovery_submit_refused',     'Owner-signed authorization refused (locally or by the POS verifier)');

-- ------------------------------------------------------------ step-up actions (auth owner)
GRANT CREATE ON SCHEMA control TO control_auth;
SET ROLE control_auth;

-- As 219 + the three POS recovery actions.
CREATE OR REPLACE FUNCTION control.api_stepup_begin(p_token text, p_action text, p_target text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token);
BEGIN
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  IF p_action NOT IN ('tenant_transition', 'credential_add', 'credential_revoke', 'recovery_approve', 'recovery_cancel', 'operator_invite',
                      'pos_recovery_transition', 'pos_recovery_contain', 'pos_recovery_submit')
     OR p_target IS NULL OR p_target !~ '^[A-Za-z0-9:_-]{1,200}$' THEN
    RETURN control.err('INVALID_INPUT');
  END IF;
  IF control.identity_under_recovery(c.identity_id) AND NOT control.stepup_allowed_under_recovery(c.identity_id, p_action, p_target) THEN
    RETURN control.err('IDENTITY_UNDER_RECOVERY');
  END IF;
  RETURN jsonb_build_object('ok', true,
    'challenge', control.challenge_issue('stepup', c.identity_id, c.id_hash, p_action, p_target),
    'credential_ids', (SELECT coalesce(jsonb_agg(credential_id), '[]'::jsonb) FROM control.webauthn_credentials w
                        WHERE w.identity_id = c.identity_id AND control.credential_usable(w.id) AND w.counter_suspect_at IS NULL));
END
$$;

RESET ROLE;
REVOKE CREATE ON SCHEMA control FROM control_auth;

-- ------------------------------------------------------------ out-of-band notices (audit owner)
-- POS containment and owner-authorization submissions reach the owners and the host out of band (212).
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
    'pos.recovery_transitioned', 'pos.recovery_device_contained', 'pos.recovery_submitted']::text[]
$$;
RESET ROLE;
REVOKE CREATE ON SCHEMA control FROM control_audit_owner;

-- ------------------------------------------------------------ the bridge (tenant-model owner)
GRANT CREATE ON SCHEMA control TO control_definer;
SET ROLE control_definer;

-- The POS interface Control depends on: exact identity signatures (docs/pos_recovery_contract.json).
CREATE FUNCTION control.pos_recovery_contract() RETURNS text[]
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT ARRAY['recovery_v1.operator_overview()', 'recovery_v1.operator_organization(text)',
               'recovery_v1.operator_submit(text,text,text)', 'recovery_v1.operator_contain_device(text,uuid,text,text,text)',
               'recovery_v1.operator_transition(text,text,text,text,text)', 'recovery_v1.operator_reconciliation_report(text,text)',
               'recovery_v1.operator_audit(text,integer)']::text[]
$$;

-- True only when ALL seven functions exist with those signatures, return jsonb, are SECURITY DEFINER, are NOT owned by a
-- control role (they are the POS's, never Control's own code), and the CURRENT role (control_definer inside the api_*
-- wrappers) may use the schema and execute each of them. All or nothing.
CREATE FUNCTION control.pos_recovery_hook_ok() RETURNS boolean
LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE s text; o regprocedure;
BEGIN
  IF to_regnamespace('recovery_v1') IS NULL THEN RETURN false; END IF;
  IF NOT has_schema_privilege('recovery_v1', 'USAGE') THEN RETURN false; END IF;
  FOREACH s IN ARRAY control.pos_recovery_contract() LOOP
    o := to_regprocedure(s);
    IF o IS NULL THEN RETURN false; END IF;
    IF NOT has_function_privilege(o, 'EXECUTE') THEN RETURN false; END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_proc p WHERE p.oid = o AND p.prorettype = 'jsonb'::regtype AND p.prosecdef AND p.prokind = 'f'
                     AND pg_get_userbyid(p.proowner) !~ '^control_') THEN
      RETURN false;
    END IF;
  END LOOP;
  RETURN true;
END
$$;

-- POS exception -> stable code. Never the POS's text.
CREATE FUNCTION control.pos_recovery_error_code(p_state text, p_message text) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE
    WHEN p_message LIKE 'RECOVERY_V1_OPERATOR_INVALID%' THEN 'NOT_FOUND'
    WHEN p_message LIKE 'RECOVERY_V1_DEVICE_CONTAIN_INVALID%' THEN 'POS_RECOVERY_INVALID'
    WHEN p_message LIKE 'RECOVERY_V1_RECONCILIATION_STATE%' THEN 'POS_RECOVERY_STATE'
    WHEN p_message LIKE 'RECOVERY_V1_%RATE_LIMITED%' THEN 'RATE_LIMITED'
    WHEN p_state IN ('42501', '42883', '3F000', '42P01') THEN 'POS_RECOVERY_UNAVAILABLE'
    ELSE 'POS_RECOVERY_ERROR' END
$$;

-- The leading RECOVERY_V1_* token of a POS message (for the Control audit detail), or NULL.
CREATE FUNCTION control.pos_recovery_error_token(p_message text) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT substring(p_message FROM '^(RECOVERY_V1_[A-Z0-9_]{1,80})')
$$;

-- Mirrors the POS rule recovery_v1.is_hard_blocker (contract hardBlockerRule): never acceptable by an owner decision.
CREATE FUNCTION control.pos_recovery_is_hard(b text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT b LIKE 'integrity:%' OR b IN ('ledger_in_flight', 'state_not_reconciling')
$$;

CREATE FUNCTION control.pos_recovery_pick(j jsonb, p_keys text[]) RETURNS jsonb
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE WHEN jsonb_typeof(j) = 'object'
              THEN coalesce((SELECT jsonb_object_agg(e.key, e.value) FROM jsonb_each(j) e WHERE e.key = ANY (p_keys)), '{}'::jsonb) END
$$;

CREATE FUNCTION control.pos_recovery_pick_all(j jsonb, p_keys text[]) RETURNS jsonb
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE WHEN jsonb_typeof(j) = 'array'
              THEN coalesce((SELECT jsonb_agg(control.pos_recovery_pick(x, p_keys) ORDER BY o) FROM jsonb_array_elements(j) WITH ORDINALITY t(x, o)), '[]'::jsonb)
              ELSE '[]'::jsonb END
$$;

-- One organization as Control shows it: ONLY the documented contract keys (a future POS field is not passed through),
-- plus Control's own reading of what blocks a reopening.
CREATE FUNCTION control.pos_recovery_org_view(j jsonb) RETURNS jsonb
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
                       ARRAY['enrollmentId', 'shopId', 'deviceId', 'keyFingerprint', 'state', 'notAfter', 'replaces'])),
    'ownerAuthority', control.pos_recovery_pick_all(j -> 'ownerAuthority', ARRAY['keyId', 'fingerprint', 'scope']));
  IF j ? 'deviceRequests' THEN
    o := o || jsonb_build_object('deviceRequests', control.pos_recovery_pick_all(j -> 'deviceRequests',
      ARRAY['requestId', 'shopId', 'deviceId', 'keyFingerprint', 'shortCode', 'requestNonce', 'replaces', 'requestedAt', 'requestedBy']));
  END IF;
  -- What stands between this organization and an (owner-signed) reopening, as far as Control can tell.
  IF jsonb_array_length(o -> 'ownerAuthority') = 0 THEN blocked := blocked || '"no_owner_authority"'::jsonb; END IF;
  IF o ->> 'state' IS DISTINCT FROM 'ACTIVE' THEN
    IF o ->> 'state' IS DISTINCT FROM 'RECONCILING' THEN blocked := blocked || '"not_reconciling"'::jsonb; END IF;
    IF rep IS NULL THEN blocked := blocked || '"no_report"'::jsonb;
    ELSIF jsonb_array_length(rep -> 'hardBlockers') > 0 THEN blocked := blocked || '"hard_blockers"'::jsonb; END IF;
  END IF;
  RETURN o || jsonb_build_object('reopenBlockedBy', blocked);
END
$$;

-- Stable actor label passed to the POS as p_actor (the POS appends '@' || session_user).
CREATE FUNCTION control.pos_recovery_actor(c control.session_ctx) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT 'control:' || c.role || ':' || c.identity_id::text
$$;

CREATE FUNCTION control.pos_recovery_org_ok(p_org text) RETURNS boolean
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT p_org IS NOT NULL AND p_org ~ '^[A-Za-z0-9_-]{1,100}$'
$$;

-- Refusal: one audit row, then the error. (Internal; executed by the wrappers as control_definer.)
CREATE FUNCTION control.pos_recovery_refuse(c control.session_ctx, p_action text, p_target text, p_request_id uuid,
                                            p_code text, p_detail jsonb) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SET search_path = control, pg_temp AS $$
BEGIN
  PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, p_action, 'denied', 'pos_organization',
    p_target, p_request_id, p_code, coalesce(p_detail, '{}'::jsonb));
  RETURN control.err(p_code);
END
$$;

-- Replay of a mutating call: same identity, same action, same organization and target; otherwise a conflict.
CREATE FUNCTION control.pos_recovery_replay(c control.session_ctx, p_request_id uuid, p_action text, p_org text, p_target text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SET search_path = control, pg_temp AS $$
DECLARE v_prior control.request_results;
BEGIN
  PERFORM pg_advisory_xact_lock(222, hashtext(p_request_id::text));
  SELECT * INTO v_prior FROM control.request_results WHERE request_id = p_request_id;
  IF v_prior.request_id IS NULL THEN RETURN NULL; END IF;
  IF v_prior.identity_id <> c.identity_id OR v_prior.action <> p_action
     OR v_prior.result ->> 'org' IS DISTINCT FROM p_org OR v_prior.result ->> 'target' IS DISTINCT FROM p_target THEN
    RETURN control.err('REQUEST_ID_CONFLICT');
  END IF;
  RETURN v_prior.result || jsonb_build_object('replayed', true);
END
$$;

-- ------------------------------------------------------------ read API
CREATE FUNCTION control.api_pos_recovery_overview(p_token text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token); v_denied jsonb; v jsonb; v_state text; v_msg text; v_code text;
BEGIN
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  v_denied := control.authorize(c, ARRAY['owner', 'admin'], false, 'pos_recovery_overview', NULL);
  IF v_denied IS NOT NULL THEN RETURN v_denied; END IF;
  IF NOT control.pos_recovery_hook_ok() THEN
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_read_refused', '*', NULL, 'POS_RECOVERY_UNAVAILABLE', '{"api":"overview"}');
  END IF;
  BEGIN
    v := recovery_v1.operator_overview();
  EXCEPTION WHEN OTHERS THEN
    GET STACKED DIAGNOSTICS v_state = RETURNED_SQLSTATE, v_msg = MESSAGE_TEXT;
    v_code := control.pos_recovery_error_code(v_state, v_msg);
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_read_refused', '*', NULL, v_code,
      jsonb_build_object('api', 'overview', 'sqlstate', v_state, 'pos_error', control.pos_recovery_error_token(v_msg)));
  END;
  SELECT coalesce(jsonb_agg(control.pos_recovery_org_view(x) ORDER BY o), '[]'::jsonb) INTO v
    FROM jsonb_array_elements(CASE WHEN jsonb_typeof(v) = 'array' THEN v ELSE '[]'::jsonb END) WITH ORDINALITY t(x, o);
  PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'pos.recovery_viewed', 'success',
    'pos_organization', '*', NULL, NULL, jsonb_build_object('api', 'overview', 'organizations', jsonb_array_length(v)));
  RETURN jsonb_build_object('ok', true, 'organizations', v);
END
$$;

CREATE FUNCTION control.api_pos_recovery_org(p_token text, p_org text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token); v_denied jsonb; v jsonb; v_state text; v_msg text;
BEGIN
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  v_denied := control.authorize(c, ARRAY['owner', 'admin'], false, 'pos_recovery_org', NULL);
  IF v_denied IS NOT NULL THEN RETURN v_denied; END IF;
  IF NOT control.pos_recovery_org_ok(p_org) THEN
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_read_refused', left(p_org, 100), NULL, 'INVALID_INPUT', '{"api":"organization"}');
  END IF;
  IF NOT control.pos_recovery_hook_ok() THEN
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_read_refused', p_org, NULL, 'POS_RECOVERY_UNAVAILABLE', '{"api":"organization"}');
  END IF;
  BEGIN
    v := recovery_v1.operator_organization(p_org);
  EXCEPTION WHEN OTHERS THEN
    GET STACKED DIAGNOSTICS v_state = RETURNED_SQLSTATE, v_msg = MESSAGE_TEXT;
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_read_refused', p_org, NULL, control.pos_recovery_error_code(v_state, v_msg),
      jsonb_build_object('api', 'organization', 'sqlstate', v_state, 'pos_error', control.pos_recovery_error_token(v_msg)));
  END;
  PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'pos.recovery_viewed', 'success',
    'pos_organization', p_org, NULL, NULL, '{"api":"organization"}'::jsonb);
  RETURN jsonb_build_object('ok', true, 'organization', control.pos_recovery_org_view(v));
END
$$;

CREATE FUNCTION control.api_pos_recovery_audit(p_token text, p_org text, p_limit integer) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token); v_denied jsonb; v jsonb; v_state text; v_msg text;
BEGIN
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  v_denied := control.authorize(c, ARRAY['owner', 'admin'], false, 'pos_recovery_audit', NULL);
  IF v_denied IS NOT NULL THEN RETURN v_denied; END IF;
  IF NOT control.pos_recovery_org_ok(p_org) OR p_limit IS NULL OR p_limit NOT BETWEEN 1 AND 200 THEN
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_read_refused', left(p_org, 100), NULL, 'INVALID_INPUT', '{"api":"audit"}');
  END IF;
  IF NOT control.pos_recovery_hook_ok() THEN
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_read_refused', p_org, NULL, 'POS_RECOVERY_UNAVAILABLE', '{"api":"audit"}');
  END IF;
  BEGIN
    v := recovery_v1.operator_audit(p_org, p_limit);
  EXCEPTION WHEN OTHERS THEN
    GET STACKED DIAGNOSTICS v_state = RETURNED_SQLSTATE, v_msg = MESSAGE_TEXT;
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_read_refused', p_org, NULL, control.pos_recovery_error_code(v_state, v_msg),
      jsonb_build_object('api', 'audit', 'sqlstate', v_state, 'pos_error', control.pos_recovery_error_token(v_msg)));
  END;
  PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'pos.recovery_viewed', 'success',
    'pos_organization', p_org, NULL, NULL, '{"api":"audit"}'::jsonb);
  RETURN jsonb_build_object('ok', true, 'events', control.pos_recovery_pick_all(v, ARRAY['id', 'kind', 'detail', 'actor', 'at']));
END
$$;

-- ------------------------------------------------------------ containment
CREATE FUNCTION control.api_pos_recovery_transition(p_token text, p_org text, p_to_state text, p_reason text,
                                                    p_evidence_reference text, p_request_id uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token); v_denied jsonb; v_prior jsonb; v jsonb; v_state text; v_msg text;
        v_target text; v_result jsonb; v_seq bigint;
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
  IF NOT control.pos_recovery_hook_ok() THEN
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_transition_refused', p_org, p_request_id, 'POS_RECOVERY_UNAVAILABLE', jsonb_build_object('to', p_to_state));
  END IF;
  IF NOT control.stepup_consume_token(p_token, 'pos_recovery_transition', p_org || ':' || p_to_state) THEN
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_transition_refused', p_org, p_request_id, 'STEPUP_REQUIRED', jsonb_build_object('to', p_to_state));
  END IF;
  BEGIN
    v := recovery_v1.operator_transition(p_org, p_to_state, btrim(p_reason), btrim(p_evidence_reference), control.pos_recovery_actor(c));
  EXCEPTION WHEN OTHERS THEN
    GET STACKED DIAGNOSTICS v_state = RETURNED_SQLSTATE, v_msg = MESSAGE_TEXT;
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_transition_refused', p_org, p_request_id, control.pos_recovery_error_code(v_state, v_msg),
      jsonb_build_object('to', p_to_state, 'sqlstate', v_state, 'pos_error', control.pos_recovery_error_token(v_msg)));
  END;
  IF v ->> 'outcome' IS DISTINCT FROM 'applied' THEN
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_transition_refused', p_org, p_request_id, 'POS_RECOVERY_DENIED',
      jsonb_build_object('to', p_to_state, 'pos_outcome', left(v ->> 'outcome', 40)));
  END IF;
  v_seq := control.audit_append('platform_identity', c.identity_id, c.display_name, 'pos.recovery_transitioned', 'success',
    'pos_organization', p_org, p_request_id, NULL,
    jsonb_build_object('to', v ->> 'state', 'incident_id', v ->> 'incidentId', 'recovery_epoch', v -> 'recoveryEpoch',
                       'evidence_reference', left(btrim(p_evidence_reference), 200)));
  v_result := jsonb_build_object('ok', true, 'org', p_org, 'target', v_target, 'outcome', 'applied', 'state', v ->> 'state',
    'incidentId', v ->> 'incidentId', 'recoveryEpoch', v -> 'recoveryEpoch', 'audit_seq', v_seq);
  INSERT INTO control.request_results (request_id, identity_id, action, result) VALUES (p_request_id, c.identity_id, 'pos_recovery_transition', v_result);
  RETURN v_result;
END
$$;

CREATE FUNCTION control.api_pos_recovery_contain_device(p_token text, p_org text, p_enrollment uuid, p_action text,
                                                        p_reason text, p_request_id uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token); v_denied jsonb; v_prior jsonb; v jsonb; v_state text; v_msg text;
        v_target text; v_result jsonb; v_seq bigint;
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
  IF NOT control.pos_recovery_hook_ok() THEN
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_contain_refused', p_org, p_request_id, 'POS_RECOVERY_UNAVAILABLE',
      jsonb_build_object('enrollment_id', p_enrollment, 'action', p_action));
  END IF;
  IF NOT control.stepup_consume_token(p_token, 'pos_recovery_contain', p_org || ':' || p_enrollment::text || ':' || p_action) THEN
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_contain_refused', p_org, p_request_id, 'STEPUP_REQUIRED',
      jsonb_build_object('enrollment_id', p_enrollment, 'action', p_action));
  END IF;
  BEGIN
    v := recovery_v1.operator_contain_device(p_org, p_enrollment, p_action, btrim(p_reason), control.pos_recovery_actor(c));
  EXCEPTION WHEN OTHERS THEN
    GET STACKED DIAGNOSTICS v_state = RETURNED_SQLSTATE, v_msg = MESSAGE_TEXT;
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_contain_refused', p_org, p_request_id, control.pos_recovery_error_code(v_state, v_msg),
      jsonb_build_object('enrollment_id', p_enrollment, 'action', p_action, 'sqlstate', v_state, 'pos_error', control.pos_recovery_error_token(v_msg)));
  END;
  IF v ->> 'outcome' IS NULL OR v ->> 'outcome' NOT IN ('suspended', 'revoked') THEN
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_contain_refused', p_org, p_request_id, 'POS_RECOVERY_DENIED',
      jsonb_build_object('enrollment_id', p_enrollment, 'action', p_action, 'pos_outcome', left(v ->> 'outcome', 40)));
  END IF;
  v_seq := control.audit_append('platform_identity', c.identity_id, c.display_name, 'pos.recovery_device_contained', 'success',
    'pos_organization', p_org, p_request_id, NULL,
    jsonb_build_object('enrollment_id', p_enrollment, 'action', p_action, 'state', v ->> 'state'));
  v_result := jsonb_build_object('ok', true, 'org', p_org, 'target', v_target, 'outcome', v ->> 'outcome',
    'enrollmentId', v ->> 'enrollmentId', 'state', v ->> 'state', 'audit_seq', v_seq);
  INSERT INTO control.request_results (request_id, identity_id, action, result) VALUES (p_request_id, c.identity_id, 'pos_recovery_contain', v_result);
  RETURN v_result;
END
$$;

CREATE FUNCTION control.api_pos_recovery_report(p_token text, p_org text, p_request_id uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token); v_denied jsonb; v_prior jsonb; v jsonb; v_state text; v_msg text;
        v_result jsonb; v_seq bigint;
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
  IF NOT control.pos_recovery_hook_ok() THEN
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_report_refused', p_org, p_request_id, 'POS_RECOVERY_UNAVAILABLE', '{}');
  END IF;
  BEGIN
    v := recovery_v1.operator_reconciliation_report(p_org, control.pos_recovery_actor(c));
  EXCEPTION WHEN OTHERS THEN
    GET STACKED DIAGNOSTICS v_state = RETURNED_SQLSTATE, v_msg = MESSAGE_TEXT;
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_report_refused', p_org, p_request_id, control.pos_recovery_error_code(v_state, v_msg),
      jsonb_build_object('sqlstate', v_state, 'pos_error', control.pos_recovery_error_token(v_msg)));
  END;
  IF v ->> 'outcome' IS DISTINCT FROM 'reported' THEN
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_report_refused', p_org, p_request_id, 'POS_RECOVERY_DENIED',
      jsonb_build_object('pos_outcome', left(v ->> 'outcome', 40)));
  END IF;
  v_seq := control.audit_append('platform_identity', c.identity_id, c.display_name, 'pos.recovery_reported', 'success',
    'pos_organization', p_org, p_request_id, NULL,
    jsonb_build_object('report_id', v ->> 'reportId', 'incident_id', v ->> 'incidentId', 'recovery_epoch', v -> 'recoveryEpoch',
                       'digest', v ->> 'digest', 'blockers', v -> 'blockers'));
  -- signingTarget is the POS database binding the owner's reopening must name (database, system identifier, install time)
  v_result := control.pos_recovery_pick(v, ARRAY['outcome', 'reportId', 'orgId', 'incidentId', 'recoveryEpoch', 'digest', 'facts',
                                                  'blockers', 'hardBlockers'])
           || jsonb_build_object('ok', true, 'org', p_org, 'target', left(p_org, 100), 'signingTarget', v -> 'target', 'audit_seq', v_seq);
  INSERT INTO control.request_results (request_id, identity_id, action, result) VALUES (p_request_id, c.identity_id, 'pos_recovery_report', v_result);
  RETURN v_result;
END
$$;

-- ------------------------------------------------------------ owner-signed authorizations (transport only)
CREATE FUNCTION control.api_pos_recovery_submit(p_token text, p_authorization text, p_signature text, p_request_id uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token); v_denied jsonb; v_prior jsonb; v jsonb; v_state text; v_msg text;
        a jsonb; v_purpose text; v_org text; v_hash text; v_target text; v_result jsonb; v_seq bigint;
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
  IF NOT control.pos_recovery_hook_ok() THEN
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_submit_refused', v_org, p_request_id, 'POS_RECOVERY_UNAVAILABLE',
      jsonb_build_object('purpose', v_purpose, 'authorization_sha256', v_hash));
  END IF;
  IF NOT control.stepup_consume_token(p_token, 'pos_recovery_submit', v_target) THEN
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_submit_refused', v_org, p_request_id, 'STEPUP_REQUIRED',
      jsonb_build_object('purpose', v_purpose, 'authorization_sha256', v_hash));
  END IF;
  BEGIN
    v := recovery_v1.operator_submit(p_authorization, lower(p_signature), control.pos_recovery_actor(c));
  EXCEPTION WHEN OTHERS THEN
    GET STACKED DIAGNOSTICS v_state = RETURNED_SQLSTATE, v_msg = MESSAGE_TEXT;
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_submit_refused', v_org, p_request_id, control.pos_recovery_error_code(v_state, v_msg),
      jsonb_build_object('purpose', v_purpose, 'authorization_sha256', v_hash, 'sqlstate', v_state, 'pos_error', control.pos_recovery_error_token(v_msg)));
  END;
  IF v ->> 'outcome' IS NULL OR v ->> 'outcome' NOT IN ('enrolled', 'reinstated', 'reopened') THEN
    -- the POS verifier refused (bad signature, stale incident, blockers, ...): its reason is recorded, never trusted
    RETURN control.pos_recovery_refuse(c, 'pos.recovery_submit_refused', v_org, p_request_id, 'POS_RECOVERY_REFUSED',
      jsonb_build_object('purpose', v_purpose, 'authorization_sha256', v_hash, 'pos_outcome', left(v ->> 'outcome', 40),
                         'pos_error', control.pos_recovery_error_token(v ->> 'reason'), 'pos_reason', left(v ->> 'reason', 300)));
  END IF;
  v_seq := control.audit_append('platform_identity', c.identity_id, c.display_name, 'pos.recovery_submitted', 'success',
    'pos_organization', v_org, p_request_id, NULL,
    jsonb_build_object('purpose', v_purpose, 'authorization_sha256', v_hash, 'outcome', v ->> 'outcome',
                       'enrollment_id', v ->> 'enrollmentId', 'reopen_id', v ->> 'reopenId', 'state', v ->> 'state'));
  v_result := control.pos_recovery_pick(v, ARRAY['outcome', 'enrollmentId', 'reopenId', 'state', 'decision', 'uncertainties', 'deviceId'])
           || jsonb_build_object('ok', true, 'org', v_org, 'target', v_target, 'purpose', v_purpose, 'audit_seq', v_seq);
  INSERT INTO control.request_results (request_id, identity_id, action, result) VALUES (p_request_id, c.identity_id, 'pos_recovery_submit', v_result);
  RETURN v_result;
END
$$;

RESET ROLE;
REVOKE CREATE ON SCHEMA control FROM control_definer;

CREATE OR REPLACE FUNCTION control.api_contract_version() RETURNS text
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = control, pg_temp AS $$
  SELECT 'orvix-control/0.6'::text
$$;

-- ------------------------------------------------------------ grants
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA control FROM PUBLIC;
GRANT EXECUTE ON FUNCTION control.api_contract_version(), control.api_stepup_begin(text, text, text),
  control.api_pos_recovery_overview(text), control.api_pos_recovery_org(text, text),
  control.api_pos_recovery_audit(text, text, integer),
  control.api_pos_recovery_transition(text, text, text, text, text, uuid),
  control.api_pos_recovery_contain_device(text, text, uuid, text, text, uuid),
  control.api_pos_recovery_report(text, text, uuid),
  control.api_pos_recovery_submit(text, text, text, uuid) TO control_app;
