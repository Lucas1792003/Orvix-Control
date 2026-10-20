-- ============================================================
-- 206: passkey-signed audit anchors and an independently verifiable audit export
--
-- WHY      On-host anchors (201) can be rewritten by a superuser together with the chain. A signature by the
--          owner's passkey cannot: the private key never leaves the authenticator, and the server holds no
--          signing key. An exported anchor bundle plus an exported event range can be checked OFFLINE with
--          scripts/verify-audit.ts (Node/OpenSSL, independent of the database verifier).
-- HOW      api_anchor_begin fixes (seq, head_hash) and a 16-byte nonce, and issues the WebAuthn challenge
--            challenge = base64url( SHA-256( "orvix-control/anchor/v1|" || seq || "|" || hex(head) || "|" || hex(nonce) ) )
--          The owner signs it with a passkey (UV required). api_anchor_complete verifies the assertion
--          (wa_assertion, 205); audit_anchor_insert_signed re-checks the derivation and the signature itself,
--          then stores the full WebAuthn evidence with the anchor.
-- TRUST    Detects any change to events at or before an anchored seq, including a full chain recompute and a
--          tail truncation, PROVIDED the verifier holds a copy of the bundle made before the tampering and
--          pins the owner's public-key fingerprint. Events after the newest anchor are not protected.
--          No off-host destination is configured (out of scope).
-- ROLLBACK Drop the new functions; the added columns are nullable and can stay.
-- ============================================================

ALTER TABLE control.audit_anchors
  ADD COLUMN nonce              bytea CHECK (nonce IS NULL OR length(nonce) = 16),
  ADD COLUMN signer_identity    uuid,
  ADD COLUMN signer_label       text,
  ADD COLUMN credential_id      text,
  ADD COLUMN public_key         bytea,
  ADD COLUMN rp_id              text,
  ADD COLUMN origin             text,
  ADD COLUMN client_data        bytea,
  ADD COLUMN authenticator_data bytea,
  ADD COLUMN signature          bytea,
  ADD CONSTRAINT audit_anchors_signed_complete CHECK (
    (nonce IS NULL AND signature IS NULL) OR
    (nonce IS NOT NULL AND signer_identity IS NOT NULL AND credential_id IS NOT NULL AND public_key IS NOT NULL
     AND rp_id IS NOT NULL AND origin IS NOT NULL AND client_data IS NOT NULL AND authenticator_data IS NOT NULL
     AND signature IS NOT NULL));

INSERT INTO control.audit_actions (action, description) VALUES
  ('audit.anchor_signed',   'Head hash anchored and signed with the owner''s passkey'),
  ('audit.anchor_refused',  'Signed anchor refused'),
  ('audit.exported',        'Audit events exported for offline verification');

GRANT EXECUTE ON FUNCTION control.b64url_encode(bytea), control.b2n(bytea), control.modp(numeric, numeric),
  control.modpow(numeric, numeric, numeric), control.p256_p(), control.p256_n(), control.p256_b(), control.p256_gx(),
  control.p256_gy(), control.p256_on_curve(numeric, numeric), control.p256_dbl(numeric[]),
  control.p256_add(numeric[], numeric[]), control.p256_verify(numeric, numeric, numeric, numeric, numeric),
  control.der_ecdsa_sig(bytea), control.cose_es256_xy(bytea), control.es256_verify(bytea, bytea, bytea),
  control.setting_text(text)
TO control_audit_owner;

GRANT CREATE ON SCHEMA control TO control_audit_owner;
SET ROLE control_audit_owner;

CREATE FUNCTION control.anchor_challenge(p_seq bigint, p_head bytea, p_nonce bytea) RETURNS text
LANGUAGE sql IMMUTABLE STRICT SET search_path = control, pg_catalog, pg_temp AS $$
  SELECT control.b64url_encode(sha256(convert_to(
    'orvix-control/anchor/v1|' || p_seq::text || '|' || encode(p_head, 'hex') || '|' || encode(p_nonce, 'hex'), 'UTF8')))
$$;

-- Current head (seq, hash). Read-only.
CREATE FUNCTION control.audit_head(OUT seq bigint, OUT row_hash bytea)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = control, pg_temp AS $$
  SELECT e.seq, e.row_hash FROM control.audit_events e ORDER BY e.seq DESC LIMIT 1
$$;

-- Stores a signed anchor. Independently re-checks: the head still matches, the WebAuthn challenge is the
-- derivation of (seq, head, nonce), clientDataJSON type/origin, RP ID hash, UP+UV, and the ES256 signature.
CREATE FUNCTION control.audit_anchor_insert_signed(p_seq bigint, p_head bytea, p_nonce bytea, p_signer uuid,
  p_signer_label text, p_credential_id text, p_public_key bytea, p_client_data bytea, p_authenticator_data bytea,
  p_signature bytea, p_note text) RETURNS bigint
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE cd jsonb; v_id bigint; v_rp text := control.setting_text('webauthn_rp_id'); v_origin text := control.setting_text('webauthn_origin');
BEGIN
  PERFORM pg_advisory_xact_lock(201, 1);
  IF NOT EXISTS (SELECT 1 FROM control.audit_events WHERE seq = p_seq AND row_hash = p_head) THEN
    RAISE EXCEPTION 'ANCHOR_HEAD_MISMATCH';
  END IF;
  cd := convert_from(p_client_data, 'UTF8')::jsonb;
  IF cd ->> 'type' <> 'webauthn.get' OR cd ->> 'origin' <> v_origin
     OR cd ->> 'challenge' <> control.anchor_challenge(p_seq, p_head, p_nonce)
     OR substring(p_authenticator_data FROM 1 FOR 32) <> sha256(convert_to(v_rp, 'UTF8'))
     OR get_byte(p_authenticator_data, 32) & 5 <> 5
     OR NOT control.es256_verify(p_public_key, p_authenticator_data || sha256(p_client_data), p_signature) THEN
    RAISE EXCEPTION 'ANCHOR_SIGNATURE_INVALID';
  END IF;
  INSERT INTO control.audit_anchors (seq, head_hash, created_by, note, nonce, signer_identity, signer_label, credential_id,
    public_key, rp_id, origin, client_data, authenticator_data, signature)
  VALUES (p_seq, p_head, p_signer, left(p_note, 200), p_nonce, p_signer, p_signer_label, p_credential_id, p_public_key,
    v_rp, v_origin, p_client_data, p_authenticator_data, p_signature)
  RETURNING id INTO v_id;
  RETURN v_id;
END
$$;

RESET ROLE;
REVOKE CREATE ON SCHEMA control FROM control_audit_owner;

-- ------------------------------------------------------------ signing ceremony (owner control_auth)
GRANT CREATE ON SCHEMA control TO control_auth;
GRANT EXECUTE ON FUNCTION control.audit_head(), control.anchor_challenge(bigint, bytea, bytea),
  control.audit_anchor_insert_signed(bigint, bytea, bytea, uuid, text, text, bytea, bytea, bytea, bytea, text) TO control_auth;
SET ROLE control_auth;

CREATE FUNCTION control.api_anchor_begin(p_token text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token); h record; v_nonce bytea; v_ch text;
BEGIN
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  IF c.role <> 'owner' THEN
    PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'audit.anchor_refused', 'denied',
      'audit', NULL, NULL, 'FORBIDDEN', '{}'::jsonb);
    RETURN control.err('FORBIDDEN');
  END IF;
  SELECT * INTO h FROM control.audit_head();
  v_nonce := decode(left(control.new_secret(), 32), 'hex');
  v_ch := control.challenge_issue('anchor', c.identity_id, c.id_hash, 'anchor',
            h.seq::text || ':' || encode(h.row_hash, 'hex') || ':' || encode(v_nonce, 'hex'),
            control.anchor_challenge(h.seq, h.row_hash, v_nonce));
  RETURN jsonb_build_object('ok', true, 'challenge', v_ch, 'seq', h.seq, 'head_hash', encode(h.row_hash, 'hex'),
    'nonce', encode(v_nonce, 'hex'),
    'credential_ids', (SELECT coalesce(jsonb_agg(credential_id), '[]'::jsonb) FROM control.webauthn_credentials
                        WHERE identity_id = c.identity_id AND disabled_at IS NULL));
END
$$;

CREATE FUNCTION control.api_anchor_complete(p_token text, p_credential_id text, p_client_data bytea,
                                            p_authenticator_data bytea, p_signature bytea, p_note text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token); a record; v_err text; parts text[];
        w control.webauthn_credentials; v_id bigint;
BEGIN
  IF c.identity_id IS NULL THEN RETURN control.err('UNAUTHENTICATED'); END IF;
  IF c.role <> 'owner' THEN v_err := 'FORBIDDEN';
  ELSE
    a := control.wa_assertion('anchor', p_credential_id, p_client_data, p_authenticator_data, p_signature, c.id_hash);
    v_err := a.err;
    IF v_err IS NULL AND a.identity_id IS DISTINCT FROM c.identity_id THEN v_err := 'CREDENTIAL_IDENTITY_MISMATCH'; END IF;
  END IF;
  IF v_err IS NULL THEN
    parts := string_to_array((a.ch).target, ':');
    SELECT * INTO w FROM control.webauthn_credentials WHERE credential_id = p_credential_id;
    BEGIN
      v_id := control.audit_anchor_insert_signed(parts[1]::bigint, decode(parts[2], 'hex'), decode(parts[3], 'hex'),
        c.identity_id, c.display_name, p_credential_id, w.public_key, p_client_data, p_authenticator_data, p_signature, p_note);
    EXCEPTION WHEN OTHERS THEN
      v_err := CASE WHEN SQLERRM LIKE 'ANCHOR_HEAD_MISMATCH%' THEN 'HEAD_CHANGED' ELSE 'SIGNATURE_INVALID' END;
    END;
  END IF;
  IF v_err IS NOT NULL THEN
    PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'audit.anchor_refused', 'denied',
      'audit', NULL, NULL, v_err, '{}'::jsonb);
    RETURN control.err(v_err);
  END IF;
  PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'audit.anchor_signed', 'success',
    'audit_anchor', v_id::text, NULL, NULL,
    jsonb_build_object('seq', parts[1]::bigint, 'head_fingerprint', left(parts[2], 16), 'credential', left(p_credential_id, 8)));
  RETURN jsonb_build_object('ok', true, 'anchor_id', v_id, 'seq', parts[1]::bigint, 'head_hash', parts[2]);
END
$$;

RESET ROLE;
REVOKE CREATE ON SCHEMA control FROM control_auth;

-- ------------------------------------------------------------ read/export API (owner control_definer)
GRANT EXECUTE ON FUNCTION control.audit_canonical(bigint, timestamptz, text, uuid, text, text, text, text, text, uuid, text, jsonb)
  TO control_definer;
REVOKE EXECUTE ON FUNCTION control.audit_anchor_insert(uuid, text) FROM control_definer;

SET ROLE control_definer;

CREATE FUNCTION control.api_anchor_list(p_token text) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token); v_denied jsonb;
BEGIN
  v_denied := control.authorize(c, '{owner}', false, 'anchor_list', NULL);
  IF v_denied IS NOT NULL THEN RETURN v_denied; END IF;
  RETURN jsonb_build_object('ok', true, 'anchors',
    (SELECT coalesce(jsonb_agg(jsonb_build_object('id', a.id, 'seq', a.seq, 'head_fingerprint', left(encode(a.head_hash, 'hex'), 16),
        'created_at', a.created_at, 'signed', a.signature IS NOT NULL, 'signer', a.signer_label, 'note', a.note)
        ORDER BY a.id DESC), '[]'::jsonb) FROM control.audit_anchors a));
END
$$;

CREATE FUNCTION control.api_anchor_export(p_token text, p_anchor_id bigint) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token); v_denied jsonb; a control.audit_anchors;
BEGIN
  v_denied := control.authorize(c, '{owner}', false, 'anchor_export', NULL);
  IF v_denied IS NOT NULL THEN RETURN v_denied; END IF;
  SELECT * INTO a FROM control.audit_anchors WHERE id = p_anchor_id AND signature IS NOT NULL;
  IF a.id IS NULL THEN RETURN control.err('NOT_FOUND'); END IF;
  PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'audit.exported', 'success',
    'audit_anchor', a.id::text, NULL, NULL, jsonb_build_object('kind', 'anchor_bundle'));
  RETURN jsonb_build_object('ok', true, 'bundle', jsonb_build_object(
    'format', 'orvix-control/anchor-bundle/v1',
    'anchor', jsonb_build_object('id', a.id, 'seq', a.seq, 'head_hash', encode(a.head_hash, 'hex'),
                                 'nonce', encode(a.nonce, 'hex'), 'created_at', a.created_at),
    'signer', jsonb_build_object('identity_id', a.signer_identity, 'label', a.signer_label, 'credential_id', a.credential_id,
                                 'public_key_cose', control.b64url_encode(a.public_key),
                                 'public_key_fingerprint', encode(sha256(a.public_key), 'hex')),
    'webauthn', jsonb_build_object('rp_id', a.rp_id, 'origin', a.origin,
                                   'client_data_json', control.b64url_encode(a.client_data),
                                   'authenticator_data', control.b64url_encode(a.authenticator_data),
                                   'signature', control.b64url_encode(a.signature))));
END
$$;

-- Exports a contiguous event range with everything needed to recompute the chain offline, including the
-- database's canonical text for each row (the verifier checks it semantically against the fields).
CREATE FUNCTION control.api_audit_export(p_token text, p_from bigint, p_to bigint) RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = control, pg_temp AS $$
DECLARE c control.session_ctx := control.session_resolve(p_token); v_denied jsonb; v_from bigint; v_to bigint; v_out jsonb;
BEGIN
  v_denied := control.authorize(c, '{owner}', false, 'audit_export', NULL);
  IF v_denied IS NOT NULL THEN RETURN v_denied; END IF;
  v_from := greatest(coalesce(p_from, 0), 0);
  v_to := least(coalesce(p_to, v_from + 4999), v_from + 4999);
  SELECT coalesce(jsonb_agg(jsonb_build_object(
      'seq', e.seq, 'occurred_at_us', (extract(epoch FROM e.occurred_at) * 1000000)::bigint, 'actor_type', e.actor_type,
      'actor_id', e.actor_id, 'actor_label', e.actor_label, 'action', e.action, 'outcome', e.outcome,
      'target_type', e.target_type, 'target_id', e.target_id, 'request_id', e.request_id, 'reason_code', e.reason_code,
      'detail', e.detail, 'prev_hash', encode(e.prev_hash, 'hex'), 'row_hash', encode(e.row_hash, 'hex'),
      'canonical', control.audit_canonical(e.seq, e.occurred_at, e.actor_type, e.actor_id, e.actor_label, e.action,
                                           e.outcome, e.target_type, e.target_id, e.request_id, e.reason_code, e.detail))
      ORDER BY e.seq), '[]'::jsonb)
    INTO v_out FROM control.audit_events e WHERE e.seq BETWEEN v_from AND v_to;
  PERFORM control.audit_append('platform_identity', c.identity_id, c.display_name, 'audit.exported', 'success',
    'audit', NULL, NULL, NULL, jsonb_build_object('kind', 'events', 'from', v_from, 'to', v_to, 'rows', jsonb_array_length(v_out)));
  RETURN jsonb_build_object('ok', true, 'format', 'orvix-control/audit-events/v1', 'from', v_from, 'to', v_to, 'events', v_out);
END
$$;

RESET ROLE;

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA control FROM PUBLIC;
GRANT EXECUTE ON FUNCTION
  control.api_anchor_begin(text),
  control.api_anchor_complete(text, text, bytea, bytea, bytea, text),
  control.api_anchor_list(text),
  control.api_anchor_export(text, bigint),
  control.api_audit_export(text, bigint, bigint)
TO control_app;
