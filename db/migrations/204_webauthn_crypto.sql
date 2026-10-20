-- ============================================================
-- 204: in-database WebAuthn evidence verification primitives (ES256 / P-256 only)
--
-- WHY      Before 204 the database trusted the application to have verified a passkey signature
--          (SECURITY_FINDINGS S-1). Anyone holding the control_app password could mint an owner session
--          with no passkey. From 205 on, session creation and step-up require the RAW WebAuthn evidence
--          (clientDataJSON, authenticatorData, signature), which these functions verify inside Postgres.
-- WHAT     base64url helpers; bytea -> numeric; P-256 point arithmetic (Jacobian coordinates, a = -3);
--          ECDSA verification (verify only: all inputs are public, so constant-time is not required);
--          strict DER signature parsing; strict COSE EC2/ES256 key parsing (CTAP2 canonical encoding).
-- SCOPE    Pure functions. No tables, no grants to control_app. Owned by control_definer, EXECUTE granted
--          to the auth owner in 205.
-- LIMITS   ES256 only (COSE alg -7, crv P-256). RS256/EdDSA authenticators are refused at registration.
--          Verified against Node's crypto on random and malformed vectors (tests/sql/crypto.test.ts).
-- ROLLBACK DROP the functions below (nothing depends on them until 205).
-- ============================================================

SET ROLE control_definer;

CREATE FUNCTION control.b64url_encode(p bytea) RETURNS text
LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp AS $$
  SELECT translate(rtrim(replace(encode(p, 'base64'), E'\n', ''), '='), '+/', '-_')
$$;

-- Returns NULL for anything that is not strict unpadded base64url.
CREATE FUNCTION control.b64url_decode(p text) RETURNS bytea
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp AS $$
DECLARE v text;
BEGIN
  IF p !~ '^[A-Za-z0-9_-]*$' OR length(p) % 4 = 1 THEN
    RETURN NULL;
  END IF;
  v := translate(p, '-_', '+/');
  v := v || repeat('=', (4 - length(v) % 4) % 4);
  RETURN decode(v, 'base64');
EXCEPTION WHEN OTHERS THEN
  RETURN NULL;
END
$$;

-- Big-endian unsigned bytes -> numeric.
CREATE FUNCTION control.b2n(p bytea) RETURNS numeric
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp AS $$
DECLARE v numeric := 0; i integer;
BEGIN
  FOR i IN 0 .. length(p) - 1 LOOP
    v := v * 256 + get_byte(p, i);
  END LOOP;
  RETURN v;
END
$$;

CREATE FUNCTION control.modp(a numeric, m numeric) RETURNS numeric
LANGUAGE sql IMMUTABLE STRICT SET search_path = pg_catalog, pg_temp AS $$
  SELECT CASE WHEN mod(a, m) < 0 THEN mod(a, m) + m ELSE mod(a, m) END
$$;

CREATE FUNCTION control.modpow(b numeric, e numeric, m numeric) RETURNS numeric
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = control, pg_catalog, pg_temp AS $$
DECLARE r numeric := 1; x numeric := control.modp(b, m); k numeric := e;
BEGIN
  WHILE k > 0 LOOP
    IF mod(k, 2) = 1 THEN r := mod(r * x, m); END IF;
    x := mod(x * x, m);
    k := div(k, 2);
  END LOOP;
  RETURN r;
END
$$;

-- P-256 domain parameters.
CREATE FUNCTION control.p256_p() RETURNS numeric LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT 115792089210356248762697446949407573530086143415290314195533631308867097853951::numeric $$;
CREATE FUNCTION control.p256_n() RETURNS numeric LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT 115792089210356248762697446949407573529996955224135760342422259061068512044369::numeric $$;
CREATE FUNCTION control.p256_b() RETURNS numeric LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT 41058363725152142129326129780047268409114441015993725554835256314039467401291::numeric $$;
CREATE FUNCTION control.p256_gx() RETURNS numeric LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT 48439561293906451759052585252797914202762949526041747995844080717082404635286::numeric $$;
CREATE FUNCTION control.p256_gy() RETURNS numeric LANGUAGE sql IMMUTABLE SET search_path = pg_catalog, pg_temp AS $$
  SELECT 36134250956749795798585127919587881956611106672985015071877198253568414405109::numeric $$;

CREATE FUNCTION control.p256_on_curve(x numeric, y numeric) RETURNS boolean
LANGUAGE sql IMMUTABLE STRICT SET search_path = control, pg_catalog, pg_temp AS $$
  SELECT x >= 0 AND x < control.p256_p() AND y >= 0 AND y < control.p256_p()
     AND control.modp(y * y - (x * x * x - 3 * x + control.p256_b()), control.p256_p()) = 0
$$;

-- Jacobian doubling (dbl-2001-b, a = -3). Point = ARRAY[X, Y, Z]; Z = 0 is the point at infinity.
CREATE FUNCTION control.p256_dbl(pt numeric[]) RETURNS numeric[]
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = control, pg_catalog, pg_temp AS $$
DECLARE
  p numeric := control.p256_p();
  x1 numeric := pt[1]; y1 numeric := pt[2]; z1 numeric := pt[3];
  delta numeric; gamma numeric; beta numeric; alpha numeric; x3 numeric; y3 numeric; z3 numeric;
BEGIN
  IF z1 = 0 OR y1 = 0 THEN
    RETURN ARRAY[0, 1, 0]::numeric[];
  END IF;
  delta := mod(z1 * z1, p);
  gamma := mod(y1 * y1, p);
  beta  := mod(x1 * gamma, p);
  alpha := control.modp(3 * (x1 - delta) * (x1 + delta), p);
  x3 := control.modp(alpha * alpha - 8 * beta, p);
  z3 := control.modp((y1 + z1) * (y1 + z1) - gamma - delta, p);
  y3 := control.modp(alpha * (4 * beta - x3) - 8 * gamma * gamma, p);
  RETURN ARRAY[x3, y3, z3];
END
$$;

-- Jacobian addition (add-2007-bl) with the exceptional cases handled explicitly.
CREATE FUNCTION control.p256_add(a numeric[], b numeric[]) RETURNS numeric[]
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = control, pg_catalog, pg_temp AS $$
DECLARE
  p numeric := control.p256_p();
  z1z1 numeric; z2z2 numeric; u1 numeric; u2 numeric; s1 numeric; s2 numeric; h numeric; r numeric;
  i numeric; j numeric; v numeric; x3 numeric; y3 numeric; z3 numeric;
BEGIN
  IF a[3] = 0 THEN RETURN b; END IF;
  IF b[3] = 0 THEN RETURN a; END IF;
  z1z1 := mod(a[3] * a[3], p);
  z2z2 := mod(b[3] * b[3], p);
  u1 := mod(a[1] * z2z2, p);
  u2 := mod(b[1] * z1z1, p);
  s1 := mod(a[2] * b[3] * z2z2, p);
  s2 := mod(b[2] * a[3] * z1z1, p);
  h := control.modp(u2 - u1, p);
  r := control.modp(2 * (s2 - s1), p);
  IF h = 0 THEN
    IF r = 0 THEN
      RETURN control.p256_dbl(a);
    END IF;
    RETURN ARRAY[0, 1, 0]::numeric[];
  END IF;
  i := mod(4 * h * h, p);
  j := mod(h * i, p);
  v := mod(u1 * i, p);
  x3 := control.modp(r * r - j - 2 * v, p);
  y3 := control.modp(r * (v - x3) - 2 * s1 * j, p);
  z3 := control.modp(((a[3] + b[3]) * (a[3] + b[3]) - z1z1 - z2z2) * h, p);
  RETURN ARRAY[x3, y3, z3];
END
$$;

-- ECDSA P-256 verification of a 256-bit message hash e against public key (qx, qy).
CREATE FUNCTION control.p256_verify(qx numeric, qy numeric, e numeric, r numeric, s numeric) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path = control, pg_catalog, pg_temp AS $$
DECLARE
  p  numeric := control.p256_p();
  n  numeric := control.p256_n();
  w  numeric; u1 numeric; u2 numeric; k1 numeric; k2 numeric;
  b1 integer[] := '{}'; b2 integer[] := '{}';
  g  numeric[]; q numeric[]; gq numeric[]; acc numeric[] := ARRAY[0, 1, 0]::numeric[];
  zi numeric; x numeric; i integer;
BEGIN
  IF qx IS NULL OR qy IS NULL OR e IS NULL OR r IS NULL OR s IS NULL THEN RETURN false; END IF;
  IF r < 1 OR r >= n OR s < 1 OR s >= n OR e < 0 THEN RETURN false; END IF;
  IF NOT control.p256_on_curve(qx, qy) THEN RETURN false; END IF;
  w  := control.modpow(s, n - 2, n);
  u1 := mod(e * w, n);
  u2 := mod(r * w, n);
  k1 := u1; k2 := u2;
  FOR i IN 1 .. 256 LOOP
    b1 := array_append(b1, mod(k1, 2)::integer); k1 := div(k1, 2);
    b2 := array_append(b2, mod(k2, 2)::integer); k2 := div(k2, 2);
  END LOOP;
  g  := ARRAY[control.p256_gx(), control.p256_gy(), 1];
  q  := ARRAY[qx, qy, 1];
  gq := control.p256_add(g, q);
  FOR i IN REVERSE 256 .. 1 LOOP
    acc := control.p256_dbl(acc);
    IF b1[i] = 1 AND b2[i] = 1 THEN acc := control.p256_add(acc, gq);
    ELSIF b1[i] = 1 THEN acc := control.p256_add(acc, g);
    ELSIF b2[i] = 1 THEN acc := control.p256_add(acc, q);
    END IF;
  END LOOP;
  IF acc[3] = 0 THEN RETURN false; END IF;
  zi := control.modpow(acc[3], p - 2, p);
  x  := mod(acc[1] * zi * zi, p);
  RETURN mod(x, n) = r;
END
$$;

-- Strict DER: SEQUENCE { INTEGER r, INTEGER s }, short-form lengths, minimal positive integers, no trailing data.
CREATE FUNCTION control.der_ecdsa_sig(sig bytea) RETURNS numeric[]
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = control, pg_catalog, pg_temp AS $$
DECLARE len integer := length(sig); rl integer; sl integer; rb bytea; sb bytea;
BEGIN
  IF len < 8 OR len > 72 OR get_byte(sig, 0) <> 48 OR get_byte(sig, 1) <> len - 2 OR get_byte(sig, 2) <> 2 THEN
    RETURN NULL;
  END IF;
  rl := get_byte(sig, 3);
  IF rl < 1 OR rl > 33 OR 4 + rl + 2 > len THEN RETURN NULL; END IF;
  rb := substring(sig FROM 5 FOR rl);
  IF get_byte(sig, 4 + rl) <> 2 THEN RETURN NULL; END IF;
  sl := get_byte(sig, 5 + rl);
  IF sl < 1 OR sl > 33 OR 6 + rl + sl <> len THEN RETURN NULL; END IF;
  sb := substring(sig FROM 7 + rl FOR sl);
  IF get_byte(rb, 0) >= 128 OR get_byte(sb, 0) >= 128 THEN RETURN NULL; END IF;                  -- negative
  IF (rl > 1 AND get_byte(rb, 0) = 0 AND get_byte(rb, 1) < 128)
     OR (sl > 1 AND get_byte(sb, 0) = 0 AND get_byte(sb, 1) < 128) THEN RETURN NULL; END IF;       -- non-minimal
  RETURN ARRAY[control.b2n(rb), control.b2n(sb)];
END
$$;

-- COSE_Key EC2 / ES256 / P-256 in CTAP2 canonical form (77 bytes): {1:2, 3:-7, -1:1, -2:x, -3:y}.
-- Returns ARRAY[x, y] only for a point on the curve; NULL otherwise.
CREATE FUNCTION control.cose_es256_xy(k bytea) RETURNS numeric[]
LANGUAGE plpgsql IMMUTABLE STRICT SET search_path = control, pg_catalog, pg_temp AS $$
DECLARE x numeric; y numeric;
BEGIN
  IF length(k) <> 77
     OR substring(k FROM 1 FOR 10) <> '\xa5010203262001215820'::bytea
     OR substring(k FROM 43 FOR 3) <> '\x225820'::bytea THEN
    RETURN NULL;
  END IF;
  x := control.b2n(substring(k FROM 11 FOR 32));
  y := control.b2n(substring(k FROM 46 FOR 32));
  IF NOT control.p256_on_curve(x, y) THEN RETURN NULL; END IF;
  RETURN ARRAY[x, y];
END
$$;

-- Verify an ECDSA-SHA256 signature over a message with a COSE ES256 key.
CREATE FUNCTION control.es256_verify(cose bytea, msg bytea, der_sig bytea) RETURNS boolean
LANGUAGE plpgsql IMMUTABLE SET search_path = control, pg_catalog, pg_temp AS $$
DECLARE xy numeric[]; rs numeric[];
BEGIN
  IF cose IS NULL OR msg IS NULL OR der_sig IS NULL THEN RETURN false; END IF;
  xy := control.cose_es256_xy(cose);
  rs := control.der_ecdsa_sig(der_sig);
  IF xy IS NULL OR rs IS NULL THEN RETURN false; END IF;
  RETURN control.p256_verify(xy[1], xy[2], control.b2n(sha256(msg)), rs[1], rs[2]);
END
$$;

RESET ROLE;

REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA control FROM PUBLIC;
