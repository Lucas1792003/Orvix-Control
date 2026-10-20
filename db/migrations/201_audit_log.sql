-- ============================================================
-- 201: tamper-evident, append-only audit log
--
-- PURPOSE  control.audit_events: every control action writes exactly one row, in the same transaction
--          as the action. Rows are hash-chained: row_hash = sha256(prev_hash || canonical(row)).
-- LAYERS   1. Grants: only control_audit_owner (NOLOGIN) owns the table. No login role has INSERT,
--             UPDATE, DELETE or TRUNCATE. control_definer gets SELECT + EXECUTE on audit_append.
--          2. Triggers: UPDATE/DELETE/TRUNCATE always raise AUDIT_APPEND_ONLY; INSERT is refused unless
--             it comes from audit_append (current_user + transaction-local marker).
--          3. Chain: audit_verify() recomputes every hash and reports the first mismatch.
--          4. Anchors: control.audit_anchors records (seq, head_hash). Real tamper evidence against a
--             superuser needs OFF-HOST copies of anchors (not built here; see docs/SECURITY_FINDINGS.md).
-- LIMIT    A Postgres superuser can disable triggers and recompute the whole tail. Only an off-host
--          anchor that predates the rewrite detects that.
-- ROLLBACK Export the table first. Then DROP the objects below.
-- ============================================================

SET ROLE control_audit_owner;

CREATE TABLE control.audit_actions (
  action      text PRIMARY KEY CHECK (action ~ '^[a-z]+(\.[a-z_]+)+$'),
  description text NOT NULL
);
ALTER TABLE control.audit_actions ENABLE ROW LEVEL SECURITY;

INSERT INTO control.audit_actions (action, description) VALUES
  ('audit.genesis',                     'Chain genesis row'),
  ('audit.anchor_created',              'Head hash anchored'),
  ('audit.verified',                    'Chain verification run'),
  ('platform.owner_bootstrap_started',  'First owner identity created; enrolment token issued'),
  ('platform.owner_bootstrap_refused',  'Bootstrap refused (already bootstrapped or closed)'),
  ('platform.enrol_failed',             'Enrolment attempt refused'),
  ('platform.owner_enrolled',           'Owner passkey registered; identity active'),
  ('platform.login_succeeded',          'Passkey login succeeded; session created'),
  ('platform.login_failed',             'Passkey login refused'),
  ('platform.rate_limited',             'Request refused by rate limit'),
  ('platform.stepup_succeeded',         'Step-up assertion recorded'),
  ('platform.stepup_failed',            'Step-up refused'),
  ('platform.session_expired',          'Session ended by idle or absolute timeout'),
  ('platform.logout',                   'Session revoked by its holder'),
  ('platform.access_denied',            'Authenticated request refused by role or step-up policy'),
  ('tenant.transitioned',               'Synthetic tenant lifecycle transition'),
  ('tenant.transition_refused',         'Synthetic tenant lifecycle transition refused');

CREATE TABLE control.audit_events (
  seq          bigint PRIMARY KEY CHECK (seq >= 0),
  occurred_at  timestamptz NOT NULL,
  actor_type   text NOT NULL CHECK (actor_type IN ('platform_identity', 'system', 'cli', 'anonymous')),
  actor_id     uuid,
  actor_label  text,
  action       text NOT NULL REFERENCES control.audit_actions(action),
  outcome      text NOT NULL CHECK (outcome IN ('success', 'denied', 'failed')),
  target_type  text,
  target_id    text,
  request_id   uuid,
  reason_code  text,
  detail       jsonb NOT NULL DEFAULT '{}'::jsonb,
  prev_hash    bytea NOT NULL CHECK (length(prev_hash) = 32),
  row_hash     bytea NOT NULL CHECK (length(row_hash) = 32)
);
ALTER TABLE control.audit_events ENABLE ROW LEVEL SECURITY;
CREATE INDEX audit_events_actor_idx  ON control.audit_events (actor_id, seq);
CREATE INDEX audit_events_action_idx ON control.audit_events (action, seq);
CREATE INDEX audit_events_target_idx ON control.audit_events (target_type, target_id, seq);

CREATE TABLE control.audit_anchors (
  id         bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  seq        bigint NOT NULL REFERENCES control.audit_events(seq),
  head_hash  bytea NOT NULL CHECK (length(head_hash) = 32),
  created_at timestamptz NOT NULL DEFAULT now(),
  created_by uuid,
  note       text
);
ALTER TABLE control.audit_anchors ENABLE ROW LEVEL SECURITY;

-- Canonical text of a row, excluding the hashes. Timestamps are rendered as integer microseconds since
-- the epoch so the hash never depends on the session time zone or DateStyle. jsonb::text is
-- deterministic (keys sorted and de-duplicated by jsonb).
CREATE FUNCTION control.audit_canonical(
  p_seq bigint, p_occurred_at timestamptz, p_actor_type text, p_actor_id uuid, p_actor_label text,
  p_action text, p_outcome text, p_target_type text, p_target_id text, p_request_id uuid,
  p_reason_code text, p_detail jsonb
) RETURNS text
LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT jsonb_build_array(
    p_seq,
    (extract(epoch FROM p_occurred_at) * 1000000)::bigint,
    p_actor_type, p_actor_id, p_actor_label, p_action, p_outcome,
    p_target_type, p_target_id, p_request_id, p_reason_code, coalesce(p_detail, '{}'::jsonb)
  )::text
$$;

CREATE FUNCTION control.audit_row_hash(p_prev bytea, p_canonical text) RETURNS bytea
LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp AS $$
  SELECT sha256(p_prev || convert_to(p_canonical, 'UTF8'))
$$;

-- The ONLY write path. Serialised by an advisory lock so seq is gap-free and the chain is linear.
CREATE FUNCTION control.audit_append(
  p_actor_type text, p_actor_id uuid, p_actor_label text, p_action text, p_outcome text,
  p_target_type text DEFAULT NULL, p_target_id text DEFAULT NULL, p_request_id uuid DEFAULT NULL,
  p_reason_code text DEFAULT NULL, p_detail jsonb DEFAULT '{}'::jsonb
) RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE
  v_prev_seq  bigint;
  v_prev_hash bytea;
  v_seq       bigint;
  v_at        timestamptz := date_trunc('microseconds', clock_timestamp());
  v_hash      bytea;
BEGIN
  PERFORM pg_advisory_xact_lock(201, 1);
  SELECT seq, row_hash INTO v_prev_seq, v_prev_hash
    FROM control.audit_events ORDER BY seq DESC LIMIT 1;
  IF v_prev_seq IS NULL THEN
    RAISE EXCEPTION 'AUDIT_NO_GENESIS';
  END IF;
  v_seq  := v_prev_seq + 1;
  v_hash := control.audit_row_hash(v_prev_hash, control.audit_canonical(
              v_seq, v_at, p_actor_type, p_actor_id, p_actor_label, p_action, p_outcome,
              p_target_type, p_target_id, p_request_id, p_reason_code, p_detail));
  PERFORM set_config('control.audit_writer', 'on', true);
  INSERT INTO control.audit_events (seq, occurred_at, actor_type, actor_id, actor_label, action, outcome,
                                    target_type, target_id, request_id, reason_code, detail, prev_hash, row_hash)
  VALUES (v_seq, v_at, p_actor_type, p_actor_id, p_actor_label, p_action, p_outcome,
          p_target_type, p_target_id, p_request_id, p_reason_code, coalesce(p_detail, '{}'::jsonb),
          v_prev_hash, v_hash);
  PERFORM set_config('control.audit_writer', '', true);
  RETURN v_seq;
END
$$;

-- Recompute the chain. Returns the first bad seq (NULL when intact).
CREATE FUNCTION control.audit_verify(p_from bigint DEFAULT 0, p_to bigint DEFAULT NULL)
RETURNS TABLE (ok boolean, checked bigint, first_bad_seq bigint, head_seq bigint, head_hash text)
LANGUAGE plpgsql STABLE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE
  r          record;
  v_expected bytea;
  v_prev     bytea;
  v_n        bigint := 0;
  v_bad      bigint;
  v_last_seq bigint;
  v_last     bytea;
BEGIN
  IF p_from > 0 THEN
    SELECT row_hash INTO v_prev FROM control.audit_events WHERE seq = p_from - 1;
    IF v_prev IS NULL THEN v_bad := p_from - 1; END IF;
  END IF;
  IF v_bad IS NULL THEN
    FOR r IN SELECT * FROM control.audit_events
             WHERE seq >= p_from AND (p_to IS NULL OR seq <= p_to) ORDER BY seq LOOP
      v_n := v_n + 1;
      IF r.seq = 0 THEN
        v_prev := decode(repeat('00', 32), 'hex');
      ELSIF v_prev IS NULL OR r.seq <> v_last_seq + 1 AND v_last_seq IS NOT NULL THEN
        v_bad := r.seq; EXIT;  -- gap in seq (deleted row)
      END IF;
      v_expected := control.audit_row_hash(v_prev, control.audit_canonical(
                      r.seq, r.occurred_at, r.actor_type, r.actor_id, r.actor_label, r.action, r.outcome,
                      r.target_type, r.target_id, r.request_id, r.reason_code, r.detail));
      IF r.prev_hash IS DISTINCT FROM v_prev OR r.row_hash IS DISTINCT FROM v_expected THEN
        v_bad := r.seq; EXIT;
      END IF;
      v_prev := r.row_hash; v_last_seq := r.seq; v_last := r.row_hash;
    END LOOP;
  END IF;
  RETURN QUERY SELECT v_bad IS NULL, v_n, v_bad, v_last_seq, encode(v_last, 'hex');
END
$$;

-- ------------------------------------------------------------ append-only enforcement
CREATE FUNCTION control.audit_refuse_change() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  RAISE EXCEPTION 'AUDIT_APPEND_ONLY: % on % is not permitted', TG_OP, TG_TABLE_NAME
    USING ERRCODE = 'insufficient_privilege';
END
$$;

CREATE FUNCTION control.audit_guard_insert() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$
BEGIN
  -- Genesis is written by this migration while the marker is set (see below).
  IF current_user <> 'control_audit_owner'
     OR coalesce(current_setting('control.audit_writer', true), '') <> 'on' THEN
    RAISE EXCEPTION 'AUDIT_APPEND_ONLY: direct INSERT is not permitted; use control.audit_append'
      USING ERRCODE = 'insufficient_privilege';
  END IF;
  RETURN NEW;
END
$$;

CREATE TRIGGER audit_events_no_update_delete BEFORE UPDATE OR DELETE ON control.audit_events
  FOR EACH ROW EXECUTE FUNCTION control.audit_refuse_change();
CREATE TRIGGER audit_events_no_truncate BEFORE TRUNCATE ON control.audit_events
  FOR EACH STATEMENT EXECUTE FUNCTION control.audit_refuse_change();
CREATE TRIGGER audit_events_insert_guard BEFORE INSERT ON control.audit_events
  FOR EACH ROW EXECUTE FUNCTION control.audit_guard_insert();
CREATE TRIGGER audit_anchors_no_update_delete BEFORE UPDATE OR DELETE ON control.audit_anchors
  FOR EACH ROW EXECUTE FUNCTION control.audit_refuse_change();
CREATE TRIGGER audit_anchors_no_truncate BEFORE TRUNCATE ON control.audit_anchors
  FOR EACH STATEMENT EXECUTE FUNCTION control.audit_refuse_change();
CREATE TRIGGER audit_actions_no_update_delete BEFORE UPDATE OR DELETE ON control.audit_actions
  FOR EACH ROW EXECUTE FUNCTION control.audit_refuse_change();

-- Genesis row (seq 0, prev_hash = 32 zero bytes).
DO $genesis$
DECLARE
  v_at   timestamptz := date_trunc('microseconds', clock_timestamp());
  v_zero bytea := decode(repeat('00', 32), 'hex');
BEGIN
  PERFORM set_config('control.audit_writer', 'on', true);
  INSERT INTO control.audit_events (seq, occurred_at, actor_type, actor_label, action, outcome, detail, prev_hash, row_hash)
  VALUES (0, v_at, 'system', 'migration-201', 'audit.genesis', 'success', '{}'::jsonb, v_zero,
          control.audit_row_hash(v_zero, control.audit_canonical(0, v_at, 'system', NULL, 'migration-201',
            'audit.genesis', 'success', NULL, NULL, NULL, NULL, '{}'::jsonb)));
  PERFORM set_config('control.audit_writer', '', true);
END
$genesis$;

-- Anchor writes go through this function only.
CREATE FUNCTION control.audit_anchor_insert(p_created_by uuid, p_note text) RETURNS TABLE (seq bigint, head_hash text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE v_seq bigint; v_hash bytea;
BEGIN
  PERFORM pg_advisory_xact_lock(201, 1);
  SELECT e.seq, e.row_hash INTO v_seq, v_hash FROM control.audit_events e ORDER BY e.seq DESC LIMIT 1;
  INSERT INTO control.audit_anchors (seq, head_hash, created_by, note) VALUES (v_seq, v_hash, p_created_by, p_note);
  RETURN QUERY SELECT v_seq, encode(v_hash, 'hex');
END
$$;

RESET ROLE;

-- Privileges: nobody writes the table except through the owner-defined functions.
REVOKE ALL ON control.audit_events, control.audit_anchors, control.audit_actions FROM PUBLIC;
GRANT SELECT ON control.audit_events, control.audit_anchors, control.audit_actions TO control_definer;
-- RLS is on with no write policy for anyone. control_definer (not the owner) needs an explicit READ policy,
-- otherwise every read it makes (audit list, anchor cross-check) silently returns zero rows.
CREATE POLICY audit_events_definer_read  ON control.audit_events  FOR SELECT TO control_definer USING (true);
CREATE POLICY audit_anchors_definer_read ON control.audit_anchors FOR SELECT TO control_definer USING (true);
CREATE POLICY audit_actions_definer_read ON control.audit_actions FOR SELECT TO control_definer USING (true);
REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA control FROM PUBLIC;
GRANT EXECUTE ON FUNCTION control.audit_append(text, uuid, text, text, text, text, text, uuid, text, jsonb) TO control_definer;
GRANT EXECUTE ON FUNCTION control.audit_verify(bigint, bigint) TO control_definer;
GRANT EXECUTE ON FUNCTION control.audit_anchor_insert(uuid, text) TO control_definer;
GRANT EXECUTE ON FUNCTION control.api_contract_version() TO control_app;
-- control_audit_owner no longer needs to create objects.
REVOKE CREATE ON SCHEMA control FROM control_audit_owner;
