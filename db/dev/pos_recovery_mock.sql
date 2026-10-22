-- DEV/TEST FIXTURE ONLY: a MOCK of the POS-owned Recovery V1 operator interface (not a control migration, not in the
-- ledger, never applied to a real POS database).
--
-- It reproduces EXACTLY the seven signatures of the POS functions `recovery_v1.operator_*` (Orvix POS,
-- supabase/migrations-provisional/RECOVERY_V1_guards.sql, Step 5; checked-in contract: docs/pos_recovery_contract.json)
-- with synthetic state in mock tables. It does NOT verify owner signatures: a signature beginning with "bad" is refused,
-- any other is accepted. All data is invented.
--
-- Step 6 (223): the mock is loaded into its OWN database (a stand-in for the separate POS database), never into a
-- control database. Control reaches it over the network bridge (dblink) as a POS login that is a member of
-- orvix_recovery_operator only (tests/helpers/db.ts installPosRecoveryMock). For the REAL POS, see the POS repository
-- tools/recovery-v1/step6/.
--
-- Like the POS: the functions are SECURITY DEFINER with a pinned search_path, EXECUTE is granted ONLY to the NOLOGIN
-- role orvix_recovery_operator, and they return recovery metadata and counts only. The mock reads no public.* table.
DO $role$
BEGIN
  IF to_regrole('orvix_recovery_operator') IS NULL THEN
    CREATE ROLE orvix_recovery_operator NOLOGIN NOSUPERUSER NOINHERIT NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
END
$role$;

CREATE SCHEMA IF NOT EXISTS recovery_v1;
REVOKE ALL ON SCHEMA recovery_v1 FROM PUBLIC;
GRANT USAGE ON SCHEMA recovery_v1 TO orvix_recovery_operator;

CREATE TABLE IF NOT EXISTS recovery_v1.mock_orgs (
  org_id text PRIMARY KEY, state text NOT NULL CHECK (state IN ('ACTIVE', 'RESTRICTED', 'RECONCILING', 'QUARANTINED')),
  incident_id uuid, recovery_epoch integer NOT NULL DEFAULT 0, reopen_id uuid, reason text, changed_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS recovery_v1.mock_owner_keys (key_id text PRIMARY KEY, fingerprint text NOT NULL, scope text NOT NULL);
CREATE TABLE IF NOT EXISTS recovery_v1.mock_enrollments (
  enrollment_id uuid PRIMARY KEY, org_id text NOT NULL REFERENCES recovery_v1.mock_orgs, shop_id text NOT NULL, device_id text NOT NULL,
  key_fingerprint text NOT NULL, state text NOT NULL CHECK (state IN ('ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED')),
  not_after timestamptz NOT NULL, replaces uuid, approved_at timestamptz NOT NULL DEFAULT now(), suspension_event_id bigint);
CREATE TABLE IF NOT EXISTS recovery_v1.mock_requests (
  request_id uuid PRIMARY KEY, org_id text NOT NULL REFERENCES recovery_v1.mock_orgs, shop_id text NOT NULL, device_id text NOT NULL,
  key_fingerprint text NOT NULL, request_nonce uuid NOT NULL, replaces uuid, requested_at timestamptz NOT NULL DEFAULT now(), requested_by text NOT NULL);
-- synthetic reconciliation facts (counts only) per organization
CREATE TABLE IF NOT EXISTS recovery_v1.mock_facts (org_id text PRIMARY KEY REFERENCES recovery_v1.mock_orgs, facts jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS recovery_v1.mock_reports (
  report_id uuid PRIMARY KEY, org_id text NOT NULL, incident_id uuid, recovery_epoch integer, digest text NOT NULL, facts jsonb NOT NULL,
  blockers jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT clock_timestamp(), created_by text NOT NULL);
CREATE TABLE IF NOT EXISTS recovery_v1.mock_reopenings (
  reopen_id uuid PRIMARY KEY, org_id text NOT NULL, decision text NOT NULL, accepted_blockers jsonb NOT NULL, uncertainties jsonb NOT NULL,
  owner_key_id text NOT NULL, at timestamptz NOT NULL DEFAULT clock_timestamp());
CREATE TABLE IF NOT EXISTS recovery_v1.mock_audit (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY, org_id text, kind text NOT NULL, detail jsonb NOT NULL, actor text, at timestamptz NOT NULL DEFAULT clock_timestamp());
REVOKE ALL ON ALL TABLES IN SCHEMA recovery_v1 FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA recovery_v1 FROM PUBLIC;

-- ------------------------------------------------------------ internal helpers (not granted)
CREATE OR REPLACE FUNCTION recovery_v1.mock_actor(p_actor text) RETURNS text LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT 'operator:' || left(coalesce(p_actor, '?'), 120) || '@' || session_user $$;

CREATE OR REPLACE FUNCTION recovery_v1.mock_is_hard_blocker(b text) RETURNS boolean LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT b LIKE 'integrity:%' OR b IN ('ledger_in_flight', 'state_not_reconciling') $$;

CREATE OR REPLACE FUNCTION recovery_v1.mock_blockers(f jsonb) RETURNS jsonb LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT coalesce(jsonb_agg(b ORDER BY b), '[]'::jsonb) FROM (
    SELECT 'integrity:' || (f->>'integrity') AS b WHERE f->>'integrity' IS NOT NULL
    UNION ALL SELECT 'state_not_reconciling' WHERE f->>'state' IS DISTINCT FROM 'RECONCILING'
    UNION ALL SELECT 'ledger_in_flight' WHERE (f#>>'{ledger,inFlight}')::bigint > 0
    UNION ALL SELECT 'offline_operations_possibly_unsynced' WHERE (f#>>'{offline,possiblyUnsyncedCapabilities}')::bigint > 0
    UNION ALL SELECT 'refund_requests_pending' WHERE (f#>>'{refunds,pendingRequests}')::bigint > 0
    UNION ALL SELECT 'device_evidence_missing' WHERE (f#>>'{devices,withoutEvidence}')::bigint > 0) q $$;

CREATE OR REPLACE FUNCTION recovery_v1.mock_facts_now(p_org text) RETURNS jsonb LANGUAGE sql STABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT jsonb_build_object('protocol', 'orvix-reconciliation-facts-v1', 'orgId', o.org_id, 'incidentId', o.incident_id,
           'recoveryEpoch', o.recovery_epoch, 'state', o.state, 'integrity', NULL) || coalesce(f.facts, '{}'::jsonb)
    FROM recovery_v1.mock_orgs o LEFT JOIN recovery_v1.mock_facts f ON f.org_id = o.org_id WHERE o.org_id = p_org $$;

CREATE OR REPLACE FUNCTION recovery_v1.mock_overview(p_org text) RETURNS jsonb LANGUAGE plpgsql STABLE SET search_path = pg_catalog, pg_temp AS $$
DECLARE s recovery_v1.mock_orgs; o recovery_v1.mock_reopenings; rep recovery_v1.mock_reports;
BEGIN
  SELECT * INTO s FROM recovery_v1.mock_orgs WHERE org_id = p_org;
  SELECT * INTO o FROM recovery_v1.mock_reopenings WHERE reopen_id = s.reopen_id;
  SELECT * INTO rep FROM recovery_v1.mock_reports WHERE org_id = p_org AND incident_id IS NOT DISTINCT FROM s.incident_id ORDER BY created_at DESC LIMIT 1;
  RETURN jsonb_build_object('orgId', p_org, 'state', coalesce(s.state, 'RESTRICTED'), 'incidentId', s.incident_id, 'recoveryEpoch', s.recovery_epoch,
    'activation', CASE WHEN s.state = 'ACTIVE' THEN 'verified' END,
    'reopening', CASE WHEN o.reopen_id IS NULL THEN NULL ELSE jsonb_build_object('reopenId', o.reopen_id, 'decision', o.decision,
       'acceptedBlockers', o.accepted_blockers, 'uncertainties', o.uncertainties, 'byKey', o.owner_key_id, 'at', o.at) END,
    'lastReport', CASE WHEN rep.report_id IS NULL THEN NULL ELSE jsonb_build_object('reportId', rep.report_id, 'digest', rep.digest,
       'blockers', rep.blockers, 'at', rep.created_at, 'facts', rep.facts) END,
    'devices', jsonb_build_object(
       'pendingRequests', (SELECT count(*) FROM recovery_v1.mock_requests q WHERE q.org_id = p_org
                            AND NOT EXISTS (SELECT 1 FROM recovery_v1.mock_enrollments e WHERE e.enrollment_id = q.request_id)),
       'enrollments', (SELECT coalesce(jsonb_agg(jsonb_build_object('enrollmentId', e.enrollment_id, 'shopId', e.shop_id, 'deviceId', e.device_id,
            'keyFingerprint', e.key_fingerprint, 'state', e.state, 'notAfter', e.not_after, 'replaces', e.replaces,
            'suspensionEventId', CASE WHEN e.state = 'SUSPENDED' THEN e.suspension_event_id END) ORDER BY e.approved_at), '[]'::jsonb)
          FROM recovery_v1.mock_enrollments e WHERE e.org_id = p_org)),
    'ownerAuthority', (SELECT coalesce(jsonb_agg(jsonb_build_object('keyId', k.key_id, 'fingerprint', k.fingerprint, 'scope', k.scope) ORDER BY k.key_id), '[]'::jsonb)
          FROM recovery_v1.mock_owner_keys k WHERE k.scope IN ('*', p_org)));
END $$;

-- ------------------------------------------------------------ the seven operator functions (POS contract signatures)
CREATE OR REPLACE FUNCTION recovery_v1.operator_overview() RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT coalesce(jsonb_agg(recovery_v1.mock_overview(o.org_id) ORDER BY o.org_id), '[]'::jsonb) FROM recovery_v1.mock_orgs o $$;

CREATE OR REPLACE FUNCTION recovery_v1.operator_organization(p_org text) RETURNS jsonb LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM recovery_v1.mock_orgs WHERE org_id = p_org) THEN
    RAISE EXCEPTION 'RECOVERY_V1_OPERATOR_INVALID: unknown organization' USING ERRCODE = '22023';
  END IF;
  RETURN recovery_v1.mock_overview(p_org) || jsonb_build_object('deviceRequests', (SELECT coalesce(jsonb_agg(jsonb_build_object(
      'requestId', q.request_id, 'shopId', q.shop_id, 'deviceId', q.device_id, 'keyFingerprint', q.key_fingerprint,
      'shortCode', upper(left(q.key_fingerprint, 16)), 'requestNonce', q.request_nonce, 'replaces', q.replaces,
      'requestedAt', q.requested_at, 'requestedBy', q.requested_by) ORDER BY q.requested_at), '[]'::jsonb)
    FROM recovery_v1.mock_requests q WHERE q.org_id = p_org
     AND NOT EXISTS (SELECT 1 FROM recovery_v1.mock_enrollments e WHERE e.enrollment_id = q.request_id)));
END $$;

CREATE OR REPLACE FUNCTION recovery_v1.operator_submit(p_auth text, p_sig text, p_actor text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE a jsonb; v_purpose text; v_org text; v_err text; v_by text := recovery_v1.mock_actor(p_actor);
        s recovery_v1.mock_orgs; rep recovery_v1.mock_reports; q recovery_v1.mock_requests; v_id uuid; v_n integer;
BEGIN
  BEGIN a := p_auth::jsonb; v_purpose := a->>'purpose'; v_org := a->>'scope'; EXCEPTION WHEN OTHERS THEN a := NULL; END;
  BEGIN
    IF a IS NULL OR jsonb_typeof(a) <> 'object' THEN RAISE EXCEPTION 'RECOVERY_V1_OWNER_AUTHORIZATION_INVALID: not JSON'; END IF;
    IF a->>'protocol' IS DISTINCT FROM 'orvix-owner-authorization-v1' THEN RAISE EXCEPTION 'RECOVERY_V1_OWNER_AUTHORIZATION_INVALID: wrong protocol'; END IF;
    IF v_purpose IS NULL OR v_purpose NOT IN ('enroll-device', 'device-reinstate', 'reopen-organization') THEN
      RAISE EXCEPTION 'RECOVERY_V1_OWNER_AUTHORIZATION_INVALID: this entry point accepts enroll-device, device-reinstate and reopen-organization only';
    END IF;
    SELECT * INTO s FROM recovery_v1.mock_orgs WHERE org_id = v_org FOR UPDATE;
    IF s.org_id IS NULL OR NOT EXISTS (SELECT 1 FROM recovery_v1.mock_owner_keys WHERE key_id = a->>'keyId' AND scope IN ('*', v_org)) THEN
      RAISE EXCEPTION 'RECOVERY_V1_OWNER_AUTHORIZATION_SCOPE: the authorization must name one organization that its key covers';
    END IF;
    -- MOCK: no RSA verification. "bad..." stands for a signature that does not verify.
    IF p_sig IS NULL OR lower(p_sig) LIKE 'bad%' THEN RAISE EXCEPTION 'RECOVERY_V1_OWNER_AUTHORIZATION_INVALID: signature does not verify'; END IF;
    IF v_purpose = 'enroll-device' THEN
      SELECT * INTO q FROM recovery_v1.mock_requests WHERE request_id = (a->>'requestId')::uuid AND org_id = v_org;
      IF q.request_id IS NULL OR EXISTS (SELECT 1 FROM recovery_v1.mock_enrollments WHERE enrollment_id = q.request_id) THEN
        RAISE EXCEPTION 'RECOVERY_V1_DEVICE_APPROVE_INVALID: no open request with that id';
      END IF;
      INSERT INTO recovery_v1.mock_enrollments VALUES (q.request_id, v_org, q.shop_id, q.device_id, q.key_fingerprint, 'ACTIVE', now() + interval '365 days', q.replaces);
      INSERT INTO recovery_v1.mock_audit (org_id, kind, detail, actor) VALUES (v_org, 'device_enrolled', jsonb_build_object('enrollmentId', q.request_id, 'submittedBy', v_by), v_by);
      RETURN jsonb_build_object('outcome', 'enrolled', 'enrollmentId', q.request_id, 'orgId', v_org, 'deviceId', q.device_id, 'state', 'ACTIVE');
    ELSIF v_purpose = 'device-reinstate' THEN
      -- the real POS payload shape: device.{enrollmentId, keyFingerprint, suspensionEventId}
      UPDATE recovery_v1.mock_enrollments SET state = 'ACTIVE', suspension_event_id = NULL WHERE enrollment_id = (a#>>'{device,enrollmentId}')::uuid AND org_id = v_org AND state = 'SUSPENDED'
         AND suspension_event_id IS NOT DISTINCT FROM (a#>>'{device,suspensionEventId}')::bigint;
      GET DIAGNOSTICS v_n = ROW_COUNT;
      IF v_n = 0 THEN RAISE EXCEPTION 'RECOVERY_V1_DEVICE_REINSTATE_INVALID: only a suspended enrollment of this organization'; END IF;
      INSERT INTO recovery_v1.mock_audit (org_id, kind, detail, actor) VALUES (v_org, 'device_reinstated', jsonb_build_object('enrollmentId', a#>>'{device,enrollmentId}', 'submittedBy', v_by), v_by);
      RETURN jsonb_build_object('outcome', 'reinstated', 'enrollmentId', a#>>'{device,enrollmentId}', 'orgId', v_org, 'state', 'ACTIVE');
    ELSE
      IF s.state <> 'RECONCILING' THEN RAISE EXCEPTION 'RECOVERY_V1_REOPEN_STATE: reopening requires the organization to be RECONCILING (now %)', s.state; END IF;
      SELECT * INTO rep FROM recovery_v1.mock_reports WHERE org_id = v_org AND incident_id IS NOT DISTINCT FROM s.incident_id ORDER BY created_at DESC LIMIT 1;
      IF rep.report_id IS NULL OR a#>>'{reopen,reportDigest}' IS DISTINCT FROM rep.digest THEN
        RAISE EXCEPTION 'RECOVERY_V1_REOPEN_REPORT_MISSING: no recorded reconciliation report of this incident has that digest';
      END IF;
      IF EXISTS (SELECT 1 FROM jsonb_array_elements_text(rep.blockers) x WHERE recovery_v1.mock_is_hard_blocker(x)) THEN
        RAISE EXCEPTION 'RECOVERY_V1_REOPEN_BLOCKED: blockers that no owner decision can accept: %', rep.blockers;
      END IF;
      IF a#>>'{reopen,decision}' = 'verified' AND rep.blockers <> '[]'::jsonb THEN RAISE EXCEPTION 'RECOVERY_V1_REOPEN_BLOCKED: a verified reopening needs no open blocker'; END IF;
      IF coalesce(a#>>'{reopen,decision}', '') NOT IN ('verified', 'limited') THEN RAISE EXCEPTION 'RECOVERY_V1_REOPEN_INVALID: decision must be verified or limited'; END IF;
      v_id := gen_random_uuid();
      INSERT INTO recovery_v1.mock_reopenings VALUES (v_id, v_org, a#>>'{reopen,decision}', coalesce(a#>'{reopen,acceptedBlockers}', '[]'::jsonb),
        coalesce(a#>'{reopen,uncertainties}', '[]'::jsonb), a->>'keyId');
      UPDATE recovery_v1.mock_orgs SET state = 'ACTIVE', reopen_id = v_id, reason = 'Owner-authorized reopening', changed_at = now() WHERE org_id = v_org;
      INSERT INTO recovery_v1.mock_audit (org_id, kind, detail, actor) VALUES (v_org, 'organization_reopened',
        jsonb_build_object('reopenId', v_id, 'decision', a#>>'{reopen,decision}', 'byKey', a->>'keyId', 'submittedBy', v_by), v_by);
      RETURN jsonb_build_object('outcome', 'reopened', 'reopenId', v_id, 'orgId', v_org, 'state', 'ACTIVE', 'decision', a#>>'{reopen,decision}',
        'uncertainties', coalesce(a#>'{reopen,uncertainties}', '[]'::jsonb));
    END IF;
  EXCEPTION WHEN OTHERS THEN
    GET STACKED DIAGNOSTICS v_err = MESSAGE_TEXT;
    INSERT INTO recovery_v1.mock_audit (org_id, kind, detail, actor)
    VALUES (CASE WHEN EXISTS (SELECT 1 FROM recovery_v1.mock_orgs WHERE org_id = v_org) THEN v_org END, 'owner_authorization_refused',
      jsonb_build_object('purpose', left(v_purpose, 40), 'scope', left(v_org, 200), 'reason', left(v_err, 500), 'submittedBy', v_by), v_by);
    RETURN jsonb_build_object('outcome', 'refused', 'purpose', v_purpose, 'reason', left(v_err, 500));
  END;
END $$;

CREATE OR REPLACE FUNCTION recovery_v1.operator_contain_device(p_org text, p_enrollment uuid, p_action text, p_reason text, p_actor text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE e recovery_v1.mock_enrollments; v_state text; v_by text := recovery_v1.mock_actor(p_actor); v_ev bigint;
BEGIN
  SELECT * INTO e FROM recovery_v1.mock_enrollments WHERE enrollment_id = p_enrollment AND org_id = p_org FOR UPDATE;
  IF e.enrollment_id IS NULL OR p_action IS NULL OR p_action NOT IN ('suspend', 'revoke') OR length(btrim(coalesce(p_reason, ''))) NOT BETWEEN 3 AND 300 THEN
    RAISE EXCEPTION 'RECOVERY_V1_DEVICE_CONTAIN_INVALID: enrollment of this organization, action suspend|revoke and a reason (3-300 characters) required' USING ERRCODE = '22023';
  END IF;
  -- a revoked enrollment stays revoked
  v_state := CASE WHEN e.state = 'REVOKED' OR p_action = 'revoke' THEN 'REVOKED' ELSE 'SUSPENDED' END;
  INSERT INTO recovery_v1.mock_audit (org_id, kind, detail, actor) VALUES (p_org, CASE p_action WHEN 'suspend' THEN 'device_suspended' ELSE 'device_revoked' END,
    jsonb_build_object('enrollmentId', e.enrollment_id, 'deviceId', e.device_id, 'reason', btrim(p_reason), 'by', v_by), v_by) RETURNING id INTO v_ev;
  UPDATE recovery_v1.mock_enrollments SET state = v_state, suspension_event_id = v_ev WHERE enrollment_id = e.enrollment_id;
  RETURN jsonb_build_object('outcome', CASE p_action WHEN 'suspend' THEN 'suspended' ELSE 'revoked' END, 'enrollmentId', e.enrollment_id, 'state', v_state, 'eventId', v_ev);
END $$;

-- containment only: ACTIVE (or anything else) is always denied; only an owner-signed reopening sets ACTIVE
CREATE OR REPLACE FUNCTION recovery_v1.operator_transition(p_org text, p_state text, p_reason text, p_evidence_reference text, p_actor text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE s recovery_v1.mock_orgs; v_by text := recovery_v1.mock_actor(p_actor);
BEGIN
  SELECT * INTO s FROM recovery_v1.mock_orgs WHERE org_id = p_org FOR UPDATE;
  IF p_state IS NULL OR p_state NOT IN ('RESTRICTED', 'RECONCILING', 'QUARANTINED') OR nullif(btrim(p_reason), '') IS NULL
     OR nullif(btrim(p_evidence_reference), '') IS NULL OR s.org_id IS NULL THEN
    INSERT INTO recovery_v1.mock_audit (org_id, kind, detail, actor) VALUES (s.org_id, 'transition_denied',
      jsonb_build_object('requested_org', left(p_org, 200), 'requested_state', left(p_state, 40), 'by', v_by,
        'reason', 'only RESTRICTED, RECONCILING or QUARANTINED with a reason and evidence reference; ACTIVE needs an owner-signed reopening'), v_by);
    RETURN jsonb_build_object('outcome', 'denied', 'reopen_authorized', false);
  END IF;
  IF s.state = 'ACTIVE' THEN   -- leaving ACTIVE opens a new incident and a new recovery epoch
    UPDATE recovery_v1.mock_orgs SET incident_id = gen_random_uuid(), recovery_epoch = recovery_epoch + 1, reopen_id = NULL WHERE org_id = p_org;
  END IF;
  UPDATE recovery_v1.mock_orgs SET state = p_state, reason = left(p_reason, 500), changed_at = now() WHERE org_id = p_org RETURNING * INTO s;
  INSERT INTO recovery_v1.mock_audit (org_id, kind, detail, actor) VALUES (p_org, 'transition_applied',
    jsonb_build_object('to', p_state, 'evidence_reference', left(p_evidence_reference, 500), 'by', v_by, 'incidentId', s.incident_id), v_by);
  RETURN jsonb_build_object('outcome', 'applied', 'state', p_state, 'reopen_authorized', false, 'incidentId', s.incident_id, 'recoveryEpoch', s.recovery_epoch);
END $$;

CREATE OR REPLACE FUNCTION recovery_v1.operator_reconciliation_report(p_org text, p_actor text) RETURNS jsonb LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
DECLARE s recovery_v1.mock_orgs; f jsonb; b jsonb; v_digest text; v_id uuid := gen_random_uuid(); v_by text := recovery_v1.mock_actor(p_actor);
BEGIN
  SELECT * INTO s FROM recovery_v1.mock_orgs WHERE org_id = p_org FOR UPDATE;
  IF s.org_id IS NULL OR s.state IS DISTINCT FROM 'RECONCILING' THEN
    RAISE EXCEPTION 'RECOVERY_V1_RECONCILIATION_STATE: a reconciliation report is recorded only while the organization is RECONCILING' USING ERRCODE = '42501';
  END IF;
  f := recovery_v1.mock_facts_now(p_org);
  v_digest := encode(sha256(convert_to(f::text, 'UTF8')), 'hex');
  b := recovery_v1.mock_blockers(f);
  INSERT INTO recovery_v1.mock_reports VALUES (v_id, p_org, s.incident_id, s.recovery_epoch, v_digest, f, b, clock_timestamp(), v_by);
  INSERT INTO recovery_v1.mock_audit (org_id, kind, detail, actor) VALUES (p_org, 'reconciliation_reported',
    jsonb_build_object('reportId', v_id, 'incidentId', s.incident_id, 'recoveryEpoch', s.recovery_epoch, 'digest', v_digest, 'blockers', b, 'by', v_by), v_by);
  RETURN jsonb_build_object('outcome', 'reported', 'reportId', v_id, 'orgId', p_org, 'incidentId', s.incident_id, 'recoveryEpoch', s.recovery_epoch,
    'digest', v_digest, 'facts', f, 'blockers', b,
    'hardBlockers', (SELECT coalesce(jsonb_agg(x), '[]'::jsonb) FROM jsonb_array_elements_text(b) x WHERE recovery_v1.mock_is_hard_blocker(x)),
    'target', jsonb_build_object('database', current_database(), 'systemIdentifier', 'mock-system-identifier', 'recoveryV1InstalledAt', '2026-10-21T00:00:00.000000Z'));
END $$;

CREATE OR REPLACE FUNCTION recovery_v1.operator_audit(p_org text, p_limit int) RETURNS jsonb LANGUAGE sql STABLE SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS $$
  SELECT coalesce(jsonb_agg(jsonb_build_object('id', a.id, 'kind', a.kind, 'detail', a.detail, 'actor', a.actor, 'at', a.at) ORDER BY a.id DESC), '[]'::jsonb)
    FROM (SELECT * FROM recovery_v1.mock_audit WHERE org_id = p_org ORDER BY id DESC LIMIT least(greatest(coalesce(p_limit, 50), 1), 200)) a $$;

REVOKE ALL ON ALL FUNCTIONS IN SCHEMA recovery_v1 FROM PUBLIC;
GRANT EXECUTE ON FUNCTION recovery_v1.operator_overview(), recovery_v1.operator_organization(text), recovery_v1.operator_submit(text, text, text),
  recovery_v1.operator_contain_device(text, uuid, text, text, text), recovery_v1.operator_transition(text, text, text, text, text),
  recovery_v1.operator_reconciliation_report(text, text), recovery_v1.operator_audit(text, int) TO orvix_recovery_operator;

-- ------------------------------------------------------------ synthetic data (re-runnable)
INSERT INTO recovery_v1.mock_orgs (org_id, state, incident_id, recovery_epoch, reason) VALUES
  ('org-synthetic-a', 'ACTIVE',     '0a000000-0000-4000-8000-00000000000a', 1, 'Owner-authorized reopening (synthetic)'),
  ('org-synthetic-b', 'RESTRICTED', '0b000000-0000-4000-8000-00000000000b', 2, 'Synthetic incident: till reported a clock jump')
ON CONFLICT DO NOTHING;
INSERT INTO recovery_v1.mock_owner_keys VALUES
  ('owner-key-synthetic-1', 'SHA256:5ynth371cf1n63rpr1n7000000000000000000000000000000', 'org-synthetic-a')
ON CONFLICT DO NOTHING;
INSERT INTO recovery_v1.mock_facts VALUES
  ('org-synthetic-a', '{"ledger":{"inFlight":0,"fences":0},"offline":{"possiblyUnsyncedCapabilities":0},"refunds":{"pendingRequests":0},"devices":{"active":1,"withoutEvidence":0}}'),
  ('org-synthetic-b', '{"ledger":{"inFlight":1,"fences":1},"offline":{"possiblyUnsyncedCapabilities":2},"refunds":{"pendingRequests":0},"devices":{"active":1,"withoutEvidence":1}}')
ON CONFLICT DO NOTHING;
INSERT INTO recovery_v1.mock_enrollments (enrollment_id, org_id, shop_id, device_id, key_fingerprint, state, not_after) VALUES
  ('e1000000-0000-4000-8000-0000000000a1', 'org-synthetic-a', 'shop-synthetic-a1', 'till-a1', 'a1f00000000000000000000000000000000000000000000000000000000000a1', 'ACTIVE', now() + interval '300 days'),
  ('e1000000-0000-4000-8000-0000000000b1', 'org-synthetic-b', 'shop-synthetic-b1', 'till-b1', 'b1f00000000000000000000000000000000000000000000000000000000000b1', 'ACTIVE', now() + interval '200 days')
ON CONFLICT DO NOTHING;
INSERT INTO recovery_v1.mock_requests (request_id, org_id, shop_id, device_id, key_fingerprint, request_nonce, requested_by) VALUES
  ('a2000000-0000-4000-8000-0000000000b2', 'org-synthetic-b', 'shop-synthetic-b1', 'till-b2', 'b2f00000000000000000000000000000000000000000000000000000000000b2',
   'c2000000-0000-4000-8000-0000000000b2', 'user:synthetic-admin-b')
ON CONFLICT DO NOTHING;
