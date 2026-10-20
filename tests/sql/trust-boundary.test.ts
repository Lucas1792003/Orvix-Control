// The control_app credential alone must not be able to create a session, a step-up grant or a credential.
// Every attempt below is made AS control_app, the role an attacker who stole the app's DB password holds.
import { generateKeyPairSync, createSign, randomBytes } from "node:crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  assertionParts, createTestDb, ownerWithSession, resetRateLimits, type Operator, type TestDb,
} from "../helpers/db";
import { SoftAuthenticator } from "../helpers/softAuthenticator";

let db: TestDb;
let owner: Operator;
const sessions = async () => Number((await db.su.query("SELECT count(*) n FROM control.sessions")).rows[0].n);
const grants = async () => Number((await db.su.query("SELECT count(*) n FROM control.stepup_grants")).rows[0].n);
const counter = async () => Number((await db.su.query("SELECT sign_count FROM control.webauthn_credentials WHERE credential_id = $1", [owner.auth.id])).rows[0].sign_count);
const loginWith = (a: { id: string; cdj: Buffer; ad: Buffer; sig: Buffer }) => db.api("api_login_complete", a.id, a.cdj, a.ad, a.sig);

beforeAll(async () => { db = await createTestDb({ seed: true }); owner = await ownerWithSession(db); });
afterAll(async () => { await db?.drop(); });
beforeEach(async () => { await resetRateLimits(db); });

describe("forged session creation (as control_app)", () => {
  it("the pre-205 'trust me' signature no longer exists", async () => {
    const err = await db.app.query("SELECT control.api_login_complete($1, $2, $3::bigint)", ["x".repeat(43), owner.auth.id, 5]).catch((e) => e);
    expect(err.code).toBe("42883"); // function does not exist
  });

  it("random signature bytes over a real DB challenge are refused", async () => {
    const before = await sessions();
    const b = await db.api("api_login_begin");
    const a = assertionParts(owner.auth.assert({ challenge: b.challenge }));
    expect((await loginWith({ ...a, sig: randomBytes(70) })).error).toBe("SIGNATURE_INVALID");
    expect(await sessions()).toBe(before);
  });

  it("a validly formed assertion signed by the ATTACKER's key under the owner's credential id is refused", async () => {
    const before = await sessions();
    const attacker = new SoftAuthenticator();
    const b = await db.api("api_login_begin");
    const a = assertionParts(attacker.assert({ challenge: b.challenge }));
    expect((await loginWith({ ...a, id: owner.auth.id })).error).toBe("SIGNATURE_INVALID");
    expect(await sessions()).toBe(before);
  });

  it("a genuine owner signature over a challenge the attacker invented is refused", async () => {
    const a = assertionParts(owner.auth.assert({ challenge: randomBytes(32).toString("base64url") }));
    expect((await loginWith(a)).error).toBe("INVALID_CHALLENGE");
  });

  it("altering clientDataJSON or authenticatorData after signing breaks the signature", async () => {
    const b = await db.api("api_login_begin");
    const a = assertionParts(owner.auth.assert({ challenge: b.challenge }));
    const cd = JSON.parse(a.cdj.toString()); cd.extra = 1;
    expect((await loginWith({ ...a, cdj: Buffer.from(JSON.stringify(cd)) })).error).toBe("SIGNATURE_INVALID");
    const b2 = await db.api("api_login_begin");
    const a2 = assertionParts(owner.auth.assert({ challenge: b2.challenge }));
    const ad = Buffer.from(a2.ad); ad.writeUInt32BE(999_999, 33); // bump the counter without re-signing
    expect((await loginWith({ ...a2, ad })).error).toBe("SIGNATURE_INVALID");
  });

  it("a forged assertion cannot move the signature counter (no DoS by counter poisoning)", async () => {
    const c0 = await counter();
    const b = await db.api("api_login_begin");
    const a = assertionParts(new SoftAuthenticator().assert({ challenge: b.challenge }, { counter: 4_000_000_000 }));
    await loginWith({ ...a, id: owner.auth.id });
    expect(await counter()).toBe(c0);
    const { rows } = await db.su.query("SELECT disabled_at FROM control.webauthn_credentials WHERE credential_id = $1", [owner.auth.id]);
    expect(rows[0].disabled_at).toBeNull();
  });

  it("signed evidence with UV off, a foreign origin, a foreign RP ID or the wrong ceremony type is refused", async () => {
    for (const [opts, code] of [[{ uv: false }, "USER_NOT_VERIFIED"], [{ origin: "https://evil.example" }, "BAD_CLIENT_DATA"],
                                [{ rpId: "evil.example" }, "RP_ID_MISMATCH"], [{ type: "webauthn.create" }, "BAD_CLIENT_DATA"]] as const) {
      const b = await db.api("api_login_begin");
      expect((await loginWith(assertionParts(owner.auth.assert({ challenge: b.challenge }, opts)))).error, JSON.stringify(opts)).toBe(code);
    }
  });

  it("garbage evidence of every shape fails closed", async () => {
    const b = await db.api("api_login_begin");
    const cases: [unknown, unknown, unknown][] = [
      [null, null, null], [Buffer.alloc(0), Buffer.alloc(0), Buffer.alloc(0)], [Buffer.from("{"), Buffer.alloc(37), Buffer.alloc(8)],
      [Buffer.from(JSON.stringify({ type: "webauthn.get", origin: "http://localhost:3410", challenge: b.challenge })), Buffer.alloc(5000), Buffer.alloc(70)],
    ];
    for (const [cdj, ad, sig] of cases) {
      const r = await db.api("api_login_complete", owner.auth.id, cdj, ad, sig);
      expect(r.ok).toBe(false);
    }
  });

  it("an ECDSA signature by a key that is not on file is refused even with a perfect envelope", async () => {
    const { privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const b = await db.api("api_login_begin");
    const a = assertionParts(owner.auth.assert({ challenge: b.challenge }));
    const sig = createSign("SHA256").update(Buffer.concat([a.ad, (await import("node:crypto")).createHash("sha256").update(a.cdj).digest()])).sign(privateKey);
    expect((await loginWith({ ...a, sig })).error).toBe("SIGNATURE_INVALID");
  });
});

describe("forged step-up and credential creation (as control_app)", () => {
  it("a step-up grant cannot be obtained without a valid signature", async () => {
    const g0 = await grants();
    const b = await db.api("api_stepup_begin", owner.token, "credential_add", owner.identityId);
    const a = assertionParts(new SoftAuthenticator().assert({ challenge: b.challenge }));
    expect((await db.api("api_stepup_complete", owner.token, owner.auth.id, a.cdj, a.ad, a.sig)).error).toBe("SIGNATURE_INVALID");
    expect(await grants()).toBe(g0);
  });

  it("a credential cannot be added with a session alone", async () => {
    expect((await db.api("api_credential_add_begin", owner.token)).error).toBe("STEPUP_REQUIRED");
  });
});

describe("privilege boundaries between control roles", () => {
  const authTables = ["platform_identities", "webauthn_credentials", "enrolment_tokens", "webauthn_challenges", "sessions",
                      "bootstrap_state", "stepup_grants", "recovery_requests"];

  it("control_auth owns every authentication table", async () => {
    const { rows } = await db.su.query(
      `SELECT c.relname, pg_get_userbyid(c.relowner) o FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'control' AND c.relname = ANY($1)`, [authTables]);
    expect(rows).toHaveLength(authTables.length);
    for (const r of rows) expect(r.o, r.relname).toBe("control_auth");
  });

  it("control_definer (tenant/audit API) has no privilege on any authentication table", async () => {
    const { rows } = await db.su.query(
      `SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'control' AND c.relname = ANY($1)
          AND has_table_privilege('control_definer', c.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')`, [authTables]);
    expect(rows).toEqual([]);
  });

  it("control_definer may call only session_resolve and stepup_consume_token from the auth module", async () => {
    const { rows } = await db.su.query(
      `SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'control' AND pg_get_userbyid(p.proowner) = 'control_auth'
          AND has_function_privilege('control_definer', p.oid, 'EXECUTE') ORDER BY 1`);
    expect(rows.map((r) => r.proname)).toEqual(["session_resolve", "stepup_consume_token"]);
  });

  it("control_auth cannot read or write tenants, tenant history, request results or the audit table", async () => {
    const { rows } = await db.su.query(
      `SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname IN ('control','pos_mock') AND c.relkind = 'r' AND pg_get_userbyid(c.relowner) <> 'control_auth'
          AND has_table_privilege('control_auth', c.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE')`);
    expect(rows).toEqual([]);
  });

  it("internal verification and host functions are not callable by control_app or control_definer", async () => {
    const internal = ["challenge_issue", "challenge_consume", "wa_assertion", "wa_registration", "wa_client_data",
      "session_resolve", "stepup_consume_token", "host_bootstrap_owner", "host_recovery_request", "host_recovery_cancel",
      "recovery_cancel_internal", "audit_append", "audit_anchor_insert_signed", "es256_verify", "p256_verify"];
    const { rows } = await db.su.query(
      `SELECT p.proname, has_function_privilege('control_app', p.oid, 'EXECUTE') app,
              has_function_privilege('control_definer', p.oid, 'EXECUTE') def
         FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'control' AND p.proname = ANY($1)`, [internal]);
    expect(rows.length).toBe(internal.length);
    for (const r of rows) {
      expect(r.app, r.proname).toBe(false);
      if (!["session_resolve", "stepup_consume_token", "audit_append"].includes(r.proname)) expect(r.def, r.proname).toBe(false);
    }
    for (const sql of ["SELECT control.challenge_issue('login', NULL, NULL, NULL, NULL)",
                       "SELECT control.host_recovery_cancel(gen_random_uuid())",
                       "SELECT control.session_resolve(repeat('a',64))",
                       "INSERT INTO control.sessions (id_hash, identity_id, credential_id, absolute_expires_at) VALUES ('\\x00', gen_random_uuid(), 'x', now())",
                       "INSERT INTO control.stepup_grants (session_id_hash, identity_id, credential_id, action, target, expires_at) VALUES ('\\x00', gen_random_uuid(), 'x', 'a', 'b', now())",
                       "UPDATE control.settings SET value = '\"https://evil.example\"' WHERE key = 'webauthn_origin'"]) {
      const err = await db.app.query(sql).catch((e) => e);
      expect(err.code, sql).toBe("42501");
    }
  });

  it("no control role can change the WebAuthn origin or RP ID through any granted function", async () => {
    const { rows } = await db.su.query(
      `SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'control' AND p.prokind = 'f' AND has_function_privilege('control_app', p.oid, 'EXECUTE')
          AND pg_get_functiondef(p.oid) ~* 'update\\s+control\\.settings|insert\\s+into\\s+control\\.settings'`);
    expect(rows).toEqual([]);
  });

  // Review P-F1 (HIGH): an owner role must not be able to run code as another owner role.
  it("no runtime role can execute an invoker-rights function owned by a DIFFERENT runtime role", async () => {
    const { rows } = await db.su.query(
      `SELECT r.rolname AS caller, p.proname, pg_get_userbyid(p.proowner) AS owner
         FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace CROSS JOIN pg_roles r
        WHERE n.nspname = 'control' AND NOT p.prosecdef
          AND r.rolname IN ('control_app', 'control_auth', 'control_definer', 'control_audit_owner')
          AND has_function_privilege(r.oid, p.oid, 'EXECUTE')
          AND pg_get_userbyid(p.proowner) NOT IN (r.rolname, 'control_schema_owner')`);
    expect(rows).toEqual([]);
  });

  it("the schema owner is an inert NOLOGIN role that owns no SECURITY DEFINER function; no runtime role has CREATE anywhere", async () => {
    const { rows } = await db.su.query(
      `SELECT nspname, pg_get_userbyid(nspowner) o FROM pg_namespace WHERE nspname IN ('control', 'control_ext')`);
    expect(rows.find((r) => r.nspname === "control")!.o).toBe("control_schema_owner");
    const sd = await db.su.query(
      `SELECT p.proname FROM pg_proc p WHERE pg_get_userbyid(p.proowner) = 'control_schema_owner' AND p.prosecdef`);
    expect(sd.rows).toEqual([]);
    expect((await db.su.query(`SELECT rolcanlogin FROM pg_roles WHERE rolname = 'control_schema_owner'`)).rows[0].rolcanlogin).toBe(false);
    const create = await db.su.query(
      `SELECT r.rolname, n.nspname FROM pg_namespace n CROSS JOIN pg_roles r
        WHERE r.rolname IN ('control_app', 'control_auth', 'control_definer', 'control_audit_owner')
          AND n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema' AND has_schema_privilege(r.oid, n.oid, 'CREATE')`);
    expect(create.rows).toEqual([]);
  });

  it("the reviewer's exploit steps now fail when run AS control_definer", async () => {
    const c = await db.su.connect();
    try {
      for (const sql of [
        "CREATE OR REPLACE FUNCTION control.es256_verify(cose bytea, msg bytea, der_sig bytea) RETURNS boolean LANGUAGE sql AS 'SELECT true'",
        "CREATE FUNCTION control.make_interval(secs integer) RETURNS interval LANGUAGE sql AS $$SELECT interval '100 years'$$",
        "CREATE OR REPLACE FUNCTION control.new_secret() RETURNS text LANGUAGE sql AS $$SELECT repeat('0',64)$$",
        "DROP TABLE control.sessions CASCADE",
        "DROP TABLE control.audit_events CASCADE",
        "UPDATE control.settings SET value = '\"https://evil.example\"' WHERE key = 'webauthn_origin'",
        "ALTER TYPE control.session_ctx ADD ATTRIBUTE x int",
      ]) {
        await c.query("BEGIN; SET LOCAL ROLE control_definer");
        const err = await c.query(sql).catch((e) => e);
        await c.query("ROLLBACK");
        expect(err?.code, sql).toBe("42501");
      }
    } finally {
      c.release();
    }
  });

  it("control_auth and control_audit_owner cannot redefine each other's code either", async () => {
    const c = await db.su.connect();
    try {
      for (const [role, sql] of [
        ["control_audit_owner", "CREATE OR REPLACE FUNCTION control.wa_client_data(p bytea, p_type text) RETURNS jsonb LANGUAGE sql AS $$SELECT '{}'::jsonb$$"],
        ["control_auth", "CREATE OR REPLACE FUNCTION control.audit_row_hash(p_prev bytea, p_canonical text) RETURNS bytea LANGUAGE sql AS $$SELECT p_prev$$"],
        ["control_auth", "CREATE OR REPLACE FUNCTION control.audit_canonical(bigint, timestamptz, text, uuid, text, text, text, text, text, uuid, text, jsonb) RETURNS text LANGUAGE sql AS $$SELECT ''$$"],
      ] as const) {
        await c.query(`BEGIN; SET LOCAL ROLE ${role}`);
        const err = await c.query(sql).catch((e) => e);
        await c.query("ROLLBACK");
        expect(err?.code, `${role}: ${sql}`).toBe("42501");
      }
    } finally {
      c.release();
    }
  });
});

describe("availability: control_app cannot block audited actions with advisory locks", () => {
  it("an app connection holding the old audit advisory lock does not stop logins or audit writes", async () => {
    const holder = await db.app.connect();
    try {
      await holder.query("SELECT pg_advisory_lock(201, 1), pg_advisory_lock(202, 1)");
      expect((await db.api("api_audit_list", owner.token, 1, null)).ok).toBe(true);
      expect((await db.api("api_login_begin")).ok).toBe(true);
      await db.api("api_auth_failed", "login", (await db.api("api_login_begin")).challenge, "x", "TEST");
    } finally {
      await holder.query("SELECT pg_advisory_unlock_all()");
      holder.release();
    }
  });

  it("control_app cannot create large objects", async () => {
    const err = await db.app.query("SELECT lo_from_bytea(0, '\\x00')").catch((e) => e);
    expect(err.code).toBe("42501");
  });
});

describe("failure auditing (review F3/M-3, round 2)", () => {
  it("login failures before a valid signature are anonymous, and the flood is capped with one summary row", async () => {
    const before = Number((await db.su.query("SELECT max(seq) m FROM control.audit_events")).rows[0].m);
    await db.su.query("DELETE FROM control.rate_limits");
    for (let i = 0; i < 70; i++) {
      await db.api("api_login_complete", owner.auth.id + (i % 2 ? "" : "x"), Buffer.from("{}"), Buffer.alloc(37), Buffer.alloc(8));
      if (i % 4 === 3) await db.su.query("DELETE FROM control.rate_limits WHERE bucket = 'login_credential'");
    }
    const { rows } = await db.su.query("SELECT actor_type, action FROM control.audit_events WHERE seq > $1", [before]);
    expect(rows.every((r) => r.actor_type !== "platform_identity")).toBe(true);
    expect(rows.filter((r) => r.action === "platform.login_failed").length).toBe(60);
    expect(rows.filter((r) => r.action === "platform.audit_suppressed").length).toBe(1);
  });

  it("control_app cannot call pg_sleep (used to hold locks open)", async () => {
    const err = await db.app.query("SELECT pg_sleep(0)").catch((e) => e);
    expect(err.code).toBe("42501");
  });
});

describe("stale transactions (final review)", () => {
  it("a control_app transaction held open past 5 s cannot resolve sessions or consume challenges", async () => {
    const c = await db.app.connect();
    try {
      await c.query("BEGIN");
      await c.query("SELECT 1");
      await new Promise((r) => setTimeout(r, 5500));
      const err = await c.query("SELECT control.api_session_get($1)", [owner.token]).catch((e) => e);
      expect(err.message).toMatch(/STALE_TRANSACTION/);
      await c.query("ROLLBACK");
    } finally {
      c.release();
    }
    expect((await db.api("api_session_get", owner.token)).ok).toBe(true); // autocommit calls are unaffected
  }, 20_000);

  it("control_app cannot use pg_notify and its temp_file_limit is superuser-set", async () => {
    expect((await db.app.query("SELECT pg_notify('x', 'y')").catch((e) => e)).code).toBe("42501");
    expect((await db.app.query("SET temp_file_limit = '10GB'").catch((e) => e)).code).toBe("42501");
  });
});
