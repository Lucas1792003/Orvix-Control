-- ============================================================
-- 203: tenant lifecycle MODEL (synthetic records only) + audit read API
--
-- PURPOSE  Models the provisioning/suspension state machine from the control-plane plan (CP G.1/G.2)
--          inside the control schema, so lifecycle rules, role/step-up policy and audit behaviour can be
--          built and tested BEFORE any POS integration exists.
-- NOT REAL Rows here are not POS organisations. control.tenants.is_synthetic is CHECKed to be true, and
--          nothing here reads or writes any tenant (POS) table. Transitions that need POS hooks
--          (invite/redeem/activate: CP G.2, reconciliation §4 items 7-9) are present in the transition
--          table but marked available=false, and refused with NOT_AVAILABLE_IN_FOUNDATION.
--          No billing: past_due is a manual notice flag; there is no billing integration.
--          No recovery-release: nothing here touches recovery holds (POS migration 087/088).
-- ROLLBACK DROP the objects below.
-- ============================================================

SET ROLE control_definer;

CREATE TABLE control.tenant_states (
  state         text PRIMARY KEY,
  tenant_access text NOT NULL,
  description   text NOT NULL
);
INSERT INTO control.tenant_states (state, tenant_access, description) VALUES
  ('draft',              'none',          'Row created, slug reserved'),
  ('provisioning',       'none',          'Settings, branches and defaults being applied'),
  ('invited',            'none',          'Org-admin invitation outstanding'),
  ('pending_activation', 'admin_setup',   'Admin redeemed invitation; activation checks pending'),
  ('active',             'full',          'Live'),
  ('past_due',           'full_notice',   'Notice period; banner only; no enforcement'),
  ('suspended',          'held',          'Reversible block (HTTP 503 ORG_SUSPENDED in the POS, later)'),
  ('locked',             'held_sessions_revoked', 'Security lock'),
  ('abandoned',          'none',          'Provisioning given up; no tenant data ever written'),
  ('archived',           'none',          'Terminated; data retained read-only');
ALTER TABLE control.tenant_states ENABLE ROW LEVEL SECURITY;

CREATE TABLE control.tenant_transitions (
  from_state      text NOT NULL REFERENCES control.tenant_states(state),
  to_state        text NOT NULL REFERENCES control.tenant_states(state),
  allowed_roles   text[] NOT NULL CHECK (allowed_roles <@ ARRAY['owner','admin']::text[] AND cardinality(allowed_roles) > 0),
  requires_stepup boolean NOT NULL,
  requires_reason boolean NOT NULL,
  available       boolean NOT NULL,  -- false = needs POS integration; refused in the foundation
  PRIMARY KEY (from_state, to_state)
);
ALTER TABLE control.tenant_transitions ENABLE ROW LEVEL SECURITY;

INSERT INTO control.tenant_transitions VALUES
  -- provisioning (POS-dependent steps unavailable)
  ('draft',              'provisioning',       '{owner,admin}', false, false, true),
  ('provisioning',       'invited',            '{owner,admin}', true,  false, false),
  ('invited',            'pending_activation', '{owner,admin}', false, false, false),
  ('pending_activation', 'active',             '{owner,admin}', true,  false, false),
  ('draft',              'abandoned',          '{owner,admin}', true,  true,  true),
  ('provisioning',       'abandoned',          '{owner,admin}', true,  true,  true),
  ('invited',            'abandoned',          '{owner,admin}', true,  true,  true),
  -- notice (no billing integration)
  ('active',             'past_due',           '{owner,admin}', false, true,  true),
  ('past_due',           'active',             '{owner,admin}', false, false, true),
  -- suspension: admins may suspend with a reason; only the owner reactivates (OD-C6 / D-21 default)
  ('active',             'suspended',          '{owner,admin}', true,  true,  true),
  ('past_due',           'suspended',          '{owner,admin}', true,  true,  true),
  ('suspended',          'active',             '{owner}',       true,  false, true),
  -- security lock: owner-only unlock
  ('active',             'locked',             '{owner,admin}', true,  true,  true),
  ('past_due',           'locked',             '{owner,admin}', true,  true,  true),
  ('suspended',          'locked',             '{owner,admin}', true,  true,  true),
  ('pending_activation', 'locked',             '{owner,admin}', true,  true,  true),
  ('locked',             'suspended',          '{owner}',       true,  true,  true),
  ('locked',             'active',             '{owner}',       true,  true,  true),
  -- termination
  ('suspended',          'archived',           '{owner}',       true,  true,  true);

CREATE TABLE control.tenants (
  id                uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  slug              text NOT NULL CHECK (slug ~ '^[a-z0-9](?:[a-z0-9-]{1,38}[a-z0-9])$'),
  display_name      text NOT NULL CHECK (length(btrim(display_name)) BETWEEN 2 AND 80),
  status            text NOT NULL DEFAULT 'draft' REFERENCES control.tenant_states(state),
  status_reason     text,
  status_note       text,
  status_changed_at timestamptz NOT NULL DEFAULT now(),
  shop_count        integer NOT NULL DEFAULT 0 CHECK (shop_count >= 0),     -- synthetic metadata only
  user_count        integer NOT NULL DEFAULT 0 CHECK (user_count >= 0),     -- synthetic metadata only
  admin_mfa_verified boolean NOT NULL DEFAULT false,                        -- synthetic metadata only
  created_at        timestamptz NOT NULL DEFAULT now(),
  is_synthetic      boolean NOT NULL DEFAULT true CHECK (is_synthetic)      -- foundation: synthetic only
);
CREATE UNIQUE INDEX tenants_slug_uq ON control.tenants (lower(slug));
ALTER TABLE control.tenants ENABLE ROW LEVEL SECURITY;

CREATE TABLE control.tenant_status_history (
  id          bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  tenant_id   uuid NOT NULL REFERENCES control.tenants(id),
  from_state  text NOT NULL,
  to_state    text NOT NULL,
  reason_code text,
  note        text,
  actor_id    uuid NOT NULL REFERENCES control.platform_identities(id),
  audit_seq   bigint NOT NULL,
  changed_at  timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE control.tenant_status_history ENABLE ROW LEVEL SECURITY;

-- Idempotency: one effect per request id.
CREATE TABLE control.request_results (
  request_id  uuid PRIMARY KEY,
  identity_id uuid NOT NULL,
  action      text NOT NULL,
  result      jsonb NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now()
);
ALTER TABLE control.request_results ENABLE ROW LEVEL SECURITY;

-- ------------------------------------------------------------ read API (metadata only)

CREATE FUNCTION control.tenant_json(t control.tenants) RETURNS jsonb
LANGUAGE sql STABLE SET search_path = control, pg_temp AS $$
  SELECT jsonb_build_object('id', t.id, 'slug', t.slug, 'display_name', t.display_name, 'status', t.status,
    'status_reason', t.status_reason, 'status_changed_at', t.status_changed_at, 'shop_count', t.shop_count,
    'user_count', t.user_count, 'admin_mfa_verified', t.admin_mfa_verified, 'created_at', t.created_at,
    'is_synthetic', t.is_synthetic)
$$;

CREATE FUNCTION control.api_tenant_list(p_token text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token); v_denied jsonb;
BEGIN
  v_denied := control.authorize(c, '{owner,admin}', false, 'tenant_list', NULL);
  IF v_denied IS NOT NULL THEN RETURN v_denied; END IF;
  RETURN jsonb_build_object('ok', true, 'tenants',
    (SELECT coalesce(jsonb_agg(control.tenant_json(t) ORDER BY t.display_name), '[]'::jsonb) FROM control.tenants t));
END
$$;

CREATE FUNCTION control.api_tenant_get(p_token text, p_tenant_id uuid) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token); v_denied jsonb; t control.tenants;
BEGIN
  v_denied := control.authorize(c, '{owner,admin}', false, 'tenant_get', NULL);
  IF v_denied IS NOT NULL THEN RETURN v_denied; END IF;
  SELECT * INTO t FROM control.tenants WHERE id = p_tenant_id;
  IF t.id IS NULL THEN RETURN control.err('NOT_FOUND'); END IF;
  RETURN jsonb_build_object('ok', true, 'tenant', control.tenant_json(t),
    'history', (SELECT coalesce(jsonb_agg(jsonb_build_object('from', h.from_state, 'to', h.to_state,
                  'reason_code', h.reason_code, 'changed_at', h.changed_at, 'audit_seq', h.audit_seq)
                  ORDER BY h.id DESC), '[]'::jsonb)
                FROM control.tenant_status_history h WHERE h.tenant_id = t.id),
    'transitions', (SELECT coalesce(jsonb_agg(jsonb_build_object('to', x.to_state, 'allowed_roles', x.allowed_roles,
                  'requires_stepup', x.requires_stepup, 'requires_reason', x.requires_reason, 'available', x.available)
                  ORDER BY x.to_state), '[]'::jsonb)
                FROM control.tenant_transitions x WHERE x.from_state = t.status));
END
$$;

-- ------------------------------------------------------------ lifecycle transition

CREATE FUNCTION control.api_tenant_transition(p_token text, p_tenant_id uuid, p_to_state text,
                                              p_reason_code text, p_note text, p_request_id uuid)
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE
  c        control.session_ctx := control.session_resolve(p_token);
  v_denied jsonb;
  t        control.tenants;
  x        control.tenant_transitions;
  v_code   text;
  v_seq    bigint;
  v_prior  control.request_results;
  v_result jsonb;
BEGIN
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  IF p_request_id IS NULL THEN RETURN control.err('REQUEST_ID_REQUIRED'); END IF;

  -- Idempotent replay: same request id from the same identity returns the stored result, no new effect.
  PERFORM pg_advisory_xact_lock(203, hashtext(p_request_id::text));
  SELECT * INTO v_prior FROM control.request_results WHERE request_id = p_request_id;
  IF v_prior.request_id IS NOT NULL THEN
    IF v_prior.identity_id <> c.identity_id OR v_prior.action <> 'tenant_transition' THEN
      RETURN control.err('REQUEST_ID_CONFLICT');
    END IF;
    RETURN v_prior.result || jsonb_build_object('replayed', true);
  END IF;

  SELECT * INTO t FROM control.tenants WHERE id = p_tenant_id FOR UPDATE;
  IF t.id IS NULL THEN RETURN control.err('NOT_FOUND'); END IF;
  SELECT * INTO x FROM control.tenant_transitions WHERE from_state = t.status AND to_state = p_to_state;

  IF x.from_state IS NULL THEN
    v_code := 'TRANSITION_NOT_ALLOWED';
  ELSIF NOT x.available THEN
    v_code := 'NOT_AVAILABLE_IN_FOUNDATION';
  ELSIF NOT (c.role = ANY (x.allowed_roles)) THEN
    v_code := 'FORBIDDEN';
  ELSIF x.requires_stepup AND (c.stepup_at IS NULL OR
        now() - c.stepup_at > make_interval(secs => control.setting_int('stepup_max_age_seconds'))) THEN
    v_code := 'STEPUP_REQUIRED';
  ELSIF x.requires_reason AND (p_reason_code IS NULL
        OR p_reason_code NOT IN ('owner_request', 'abuse', 'security', 'notice', 'test', 'other')
        OR length(btrim(coalesce(p_note, ''))) < 10 OR length(p_note) > 500) THEN
    v_code := 'REASON_REQUIRED';
  END IF;

  IF v_code IS NOT NULL THEN
    PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'tenant.transition_refused',
      'denied', 'tenant', t.id::text, p_request_id, v_code,
      jsonb_build_object('from', t.status, 'to', p_to_state, 'synthetic', true));
    RETURN control.err(v_code);
  END IF;

  UPDATE control.tenants
     SET status = p_to_state, status_reason = p_reason_code, status_note = p_note, status_changed_at = now()
   WHERE id = t.id;
  v_seq := control.audit_append('platform_identity', c.identity_id, c.display_name, 'tenant.transitioned',
    'success', 'tenant', t.id::text, p_request_id, p_reason_code,
    jsonb_build_object('from', t.status, 'to', p_to_state, 'synthetic', true));
  INSERT INTO control.tenant_status_history (tenant_id, from_state, to_state, reason_code, note, actor_id, audit_seq)
  VALUES (t.id, t.status, p_to_state, p_reason_code, p_note, c.identity_id, v_seq);

  v_result := jsonb_build_object('ok', true, 'tenant_id', t.id, 'from', t.status, 'to', p_to_state, 'audit_seq', v_seq);
  INSERT INTO control.request_results (request_id, identity_id, action, result)
  VALUES (p_request_id, c.identity_id, 'tenant_transition', v_result);
  RETURN v_result;
END
$$;

-- ------------------------------------------------------------ audit read API

CREATE FUNCTION control.api_audit_list(p_token text, p_limit integer, p_before_seq bigint) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token); v_denied jsonb; v_limit integer;
BEGIN
  v_denied := control.authorize(c, '{owner,admin}', false, 'audit_list', NULL);
  IF v_denied IS NOT NULL THEN RETURN v_denied; END IF;
  v_limit := least(greatest(coalesce(p_limit, 50), 1), 200);
  RETURN jsonb_build_object('ok', true, 'scope', CASE c.role WHEN 'owner' THEN 'all' ELSE 'own' END, 'events',
    (SELECT coalesce(jsonb_agg(jsonb_build_object('seq', e.seq, 'occurred_at', e.occurred_at,
              'actor_type', e.actor_type, 'actor_label', e.actor_label, 'action', e.action, 'outcome', e.outcome,
              'target_type', e.target_type, 'target_id', e.target_id, 'request_id', e.request_id,
              'reason_code', e.reason_code, 'detail', e.detail, 'row_hash', left(encode(e.row_hash, 'hex'), 16))
            ORDER BY e.seq DESC), '[]'::jsonb)
       FROM (SELECT * FROM control.audit_events e
              WHERE (p_before_seq IS NULL OR e.seq < p_before_seq)
                AND (c.role = 'owner' OR e.actor_id = c.identity_id)
              ORDER BY e.seq DESC LIMIT v_limit) e));
END
$$;

-- Verifies the chain AND every on-host anchor (an anchor whose row is missing or whose hash differs means
-- the history was rewritten or truncated after the anchor). Owner only. The run itself is audited.
CREATE FUNCTION control.api_audit_verify(p_token text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE
  c control.session_ctx := control.session_resolve(p_token);
  v_denied jsonb; v record; v_anchor_bad bigint; v_ok boolean;
BEGIN
  v_denied := control.authorize(c, '{owner}', false, 'audit_verify', NULL);
  IF v_denied IS NOT NULL THEN RETURN v_denied; END IF;
  SELECT * INTO v FROM control.audit_verify(0, NULL);
  SELECT a.id INTO v_anchor_bad FROM control.audit_anchors a
    LEFT JOIN control.audit_events e ON e.seq = a.seq
   WHERE e.seq IS NULL OR e.row_hash <> a.head_hash ORDER BY a.id LIMIT 1;
  v_ok := v.ok AND v_anchor_bad IS NULL;
  PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'audit.verified',
    CASE WHEN v_ok THEN 'success' ELSE 'failed' END, 'audit', NULL, NULL,
    CASE WHEN v_ok THEN NULL WHEN NOT v.ok THEN 'CHAIN_BROKEN' ELSE 'ANCHOR_MISMATCH' END,
    jsonb_build_object('checked', v.checked, 'first_bad_seq', v.first_bad_seq, 'bad_anchor_id', v_anchor_bad,
                       'head_seq', v.head_seq));
  RETURN jsonb_build_object('ok', true, 'intact', v_ok, 'checked', v.checked, 'first_bad_seq', v.first_bad_seq,
    'bad_anchor_id', v_anchor_bad, 'head_seq', v.head_seq, 'head_fingerprint', left(v.head_hash, 16));
END
$$;

CREATE FUNCTION control.api_audit_anchor_create(p_token text, p_note text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token); v_denied jsonb; a record;
BEGIN
  v_denied := control.authorize(c, '{owner}', true, 'audit_anchor_create', NULL);
  IF v_denied IS NOT NULL THEN RETURN v_denied; END IF;
  SELECT * INTO a FROM control.audit_anchor_insert(c.identity_id, left(p_note, 200));
  PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'audit.anchor_created',
    'success', 'audit_anchor', a.seq::text, NULL, NULL, jsonb_build_object('head_fingerprint', left(a.head_hash, 16)));
  RETURN jsonb_build_object('ok', true, 'seq', a.seq, 'head_hash', a.head_hash);
END
$$;

RESET ROLE;

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA control FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
  control.api_tenant_list(text),
  control.api_tenant_get(text, uuid),
  control.api_tenant_transition(text, uuid, text, text, text, uuid),
  control.api_audit_list(text, integer, bigint),
  control.api_audit_verify(text),
  control.api_audit_anchor_create(text, text)
TO control_app;
