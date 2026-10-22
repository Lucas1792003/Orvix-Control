// Step 5 (222) + Step 6 (223): the POS recovery bridge. Control calls ONLY the POS-owned recovery_v1.operator_* interface
// (here the dev mock db/dev/pos_recovery_mock.sql, checked against docs/pos_recovery_contract.json) in a SEPARATE database,
// over the network bridge (dblink, a POS login that is a member of orvix_recovery_operator only), through control_definer;
// role + step-up policy, one Control audit row per call, remote commit last, POS_RECOVERY_UNAVAILABLE without (or with a
// wrong) bridge, never ACTIVE, and no tenant-table access.
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import net from "node:net";
import { PRIVILEGE_CHECK_SQL, privilegeProblems } from "../../src/server/db/privilegeCheck";
import { ROOT } from "../../scripts/env";
import { bridgeSettingsFromEnv, configurePosBridge, removePosBridge } from "../../scripts/pos-bridge";
import { adminWithSession, createTestDb, installPosRecoveryMock, lastAudit, operatorFixture, ownerWithSession,
         stepup, type Operator, type PosMock, type TestDb } from "../helpers/db";

type ContractFn = { name: string; identityArguments: string; returns: string; volatility: string; securityDefiner: boolean };
const CONTRACT = JSON.parse(readFileSync(path.join(ROOT, "docs", "pos_recovery_contract.json"), "utf8")) as
  { schema: string; role: string; functions: ContractFn[] };

const A = "org-synthetic-a";   // ACTIVE, owner key scoped to it
const B = "org-synthetic-b";   // RESTRICTED, no owner authority, hard blocker (ledger_in_flight)
const ENR_A = "e1000000-0000-4000-8000-0000000000a1";
const ENR_B = "e1000000-0000-4000-8000-0000000000b1";

let db: TestDb;      // the Control database, bridged to the POS mock
let pos: PosMock;    // the separate "POS" database
let bare: TestDb;    // a Control database without any bridge
let owner: Operator;
let admin: Operator;
let bareOwner: Operator;

const sha = (s: string) => createHash("sha256").update(s, "utf8").digest("hex");
const headSeq = async (d: TestDb) => (await d.su.query("SELECT max(seq)::int s FROM control.audit_events")).rows[0].s as number;
const mockState = async (org: string) => (await pos.su.query("SELECT state, incident_id::text, recovery_epoch FROM recovery_v1.mock_orgs WHERE org_id = $1", [org])).rows[0];
const enrollment = async (id: string) => (await pos.su.query("SELECT state FROM recovery_v1.mock_enrollments WHERE enrollment_id = $1", [id])).rows[0]?.state;
const posAudit = async (org: string) => (await pos.su.query("SELECT kind, detail, actor FROM recovery_v1.mock_audit WHERE org_id = $1 ORDER BY id DESC", [org])).rows;
const unusedGrants = async (d: TestDb, action: string) =>
  (await d.su.query("SELECT count(*)::int n FROM control.stepup_grants WHERE action = $1 AND used_at IS NULL", [action])).rows[0].n as number;
const bridgeConns = async () => (await pos.su.query("SELECT count(*)::int n FROM pg_stat_activity WHERE usename = $1", [pos.bridgeUser])).rows[0].n as number;
const withBridge = async (f: (c: import("pg").PoolClient) => Promise<void>, body: () => Promise<void>) => {
  const c = await db.su.connect();
  try { await f(c); await body(); } finally { await configurePosBridge(c, pos.settings); c.release(); }
};

const transition = (op: Operator, org: string, to: string, rid = randomUUID(), d: TestDb = db,
                    reason = "synthetic incident under review", evidence = "INC-SYN-0001") =>
  d.api("api_pos_recovery_transition", op.token, org, to, reason, evidence, rid);
const contain = (op: Operator, org: string, enr: string, action: string, rid = randomUUID(), reason = "till reported as stolen (synthetic)") =>
  db.api("api_pos_recovery_contain_device", op.token, org, enr, action, reason, rid);
const submit = (op: Operator, auth: string, sig: string, rid = randomUUID()) => db.api("api_pos_recovery_submit", op.token, auth, sig, rid);

function authorization(purpose: string, scope: string, extra: Record<string, unknown> = {}) {
  return JSON.stringify({ protocol: "orvix-owner-authorization-v1", purpose, scope, keyId: "owner-key-synthetic-1",
    nonce: randomUUID(), ...extra });
}

beforeAll(async () => {
  bare = await createTestDb({ seed: true });
  db = await createTestDb({ seed: true });
  bareOwner = await ownerWithSession(bare);
  owner = await ownerWithSession(db);
  admin = await adminWithSession(db);
  pos = await installPosRecoveryMock(db);
});
afterAll(async () => {
  await pos?.drop();
  await db?.drop();
  await bare?.drop();
});
beforeEach(async () => { await db.su.query("DELETE FROM control.rate_limits"); });

// =====================================================================================================================
describe("contract", () => {
  it("the mock implements exactly the checked-in POS contract (identity arguments, return type, volatility, definer)", async () => {
    const { rows } = await pos.su.query(
      `SELECT p.proname AS name, pg_get_function_identity_arguments(p.oid) AS args, format_type(p.prorettype, NULL) AS ret,
              p.provolatile AS vol, p.prosecdef AS def, p.proconfig AS cfg
         FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = $1 AND p.proname LIKE 'operator\\_%' ORDER BY 1`, [CONTRACT.schema]);
    const vol: Record<string, string> = { s: "stable", v: "volatile", i: "immutable" };
    expect(rows.map((r) => ({ name: r.name, identityArguments: r.args, returns: r.ret, volatility: vol[r.vol], securityDefiner: r.def })))
      .toEqual([...CONTRACT.functions].sort((x, y) => x.name.localeCompare(y.name)));
    for (const r of rows) expect((r.cfg ?? []).some((c: string) => c.startsWith("search_path=")), r.name).toBe(true);
  });

  it("migration 222's contract list names the same seven signatures", async () => {
    const { rows } = await pos.su.query(
      `SELECT p.proname AS name, pg_get_function_identity_arguments(p.oid) AS args
         FROM unnest($1::text[]) s JOIN pg_proc p ON p.oid = to_regprocedure(s)::oid ORDER BY 1`,
      [(await db.su.query("SELECT control.pos_recovery_contract() AS c")).rows[0].c]);
    expect(rows.map((r) => `${r.name}(${r.args})`)).toEqual(
      [...CONTRACT.functions].sort((x, y) => x.name.localeCompare(y.name)).map((f) => `${f.name}(${f.identityArguments})`));
  });

  it("the POS role is NOLOGIN and is the ONLY grantee of the operator functions; the bridge login only inherits it", async () => {
    const role = (await pos.su.query("SELECT rolcanlogin, rolsuper, rolinherit FROM pg_roles WHERE rolname = $1", [CONTRACT.role])).rows[0];
    expect(role).toEqual({ rolcanlogin: false, rolsuper: false, rolinherit: false });
    const { rows } = await pos.su.query(
      `SELECT p.proname, a.grantee::regrole::text AS grantee FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
         CROSS JOIN LATERAL aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
        WHERE n.nspname = 'recovery_v1' AND a.privilege_type = 'EXECUTE' AND a.grantee <> p.proowner ORDER BY 1`);
    expect(new Set(rows.map((r) => r.grantee))).toEqual(new Set([CONTRACT.role]));
    expect(rows.map((r) => r.proname).sort()).toEqual(CONTRACT.functions.map((f) => f.name).sort());
    const m = (await pos.su.query(`SELECT g.rolname, a.inherit_option, a.set_option, a.admin_option FROM pg_auth_members a
      JOIN pg_roles g ON g.oid = a.roleid JOIN pg_roles r ON r.oid = a.member WHERE r.rolname = $1`, [pos.bridgeUser])).rows;
    expect(m).toEqual([{ rolname: CONTRACT.role, inherit_option: true, set_option: false, admin_option: false }]);
  });

  it("the Control database holds no POS schema at all: control_app cannot reach the operator interface locally", async () => {
    expect((await db.su.query("SELECT to_regnamespace('recovery_v1') IS NULL AS x")).rows[0].x).toBe(true);
    const e = await db.app.query("SELECT recovery_v1.operator_overview()").catch((x) => x);
    expect(e.code).toBe("3F000");
    // and control_app cannot use dblink, the foreign server or the user mapping itself
    for (const q of ["SELECT control_ext.dblink_connect('x', 'orvix_pos_recovery')", "SELECT * FROM control_ext.dblink('orvix_pos_recovery', 'SELECT 1') t(x int)"]) {
      expect((await db.app.query(q).catch((x) => x)).code, q).toBe("42501");
    }
    expect((await db.app.query("SELECT umoptions FROM pg_user_mappings WHERE srvname = 'orvix_pos_recovery'")).rows).toEqual([{ umoptions: null }]);
  });

  it("the mock POS itself denies ACTIVE and refuses a bad signature", async () => {
    const t = (await pos.su.query("SELECT recovery_v1.operator_transition($1, 'ACTIVE', 'reason', 'evidence', 'test') AS r", [B])).rows[0].r;
    expect(t).toEqual({ outcome: "denied", reopen_authorized: false });
    const s = (await pos.su.query("SELECT recovery_v1.operator_submit($1, 'bad', 'test') AS r", [authorization("reopen-organization", A)])).rows[0].r;
    expect(s).toMatchObject({ outcome: "refused", purpose: "reopen-organization" });
    expect((await mockState(B)).state).toBe("RESTRICTED");
  });

  it("contract version 0.7; the new step-up actions are accepted, unknown ones still refused", async () => {
    expect((await db.app.query("SELECT control.api_contract_version() AS v")).rows[0].v).toBe("orvix-control/0.7");
    for (const a of ["pos_recovery_transition", "pos_recovery_contain", "pos_recovery_submit"]) {
      expect((await db.api("api_stepup_begin", owner.token, a, `${B}:RECONCILING`)).ok).toBe(true);
    }
    expect((await db.api("api_stepup_begin", owner.token, "pos_recovery_activate", `${B}:ACTIVE`)).error).toBe("INVALID_INPUT");
  });
});

// =====================================================================================================================
describe("bridge unavailable", () => {
  it("not configured: every API returns POS_RECOVERY_UNAVAILABLE, audited, and a step-up grant is not consumed", async () => {
    const before = await headSeq(bare);
    expect(await bare.api("api_pos_recovery_overview", bareOwner.token)).toEqual({ ok: false, error: "POS_RECOVERY_UNAVAILABLE" });
    expect(await bare.api("api_pos_recovery_org", bareOwner.token, A)).toEqual({ ok: false, error: "POS_RECOVERY_UNAVAILABLE" });
    expect(await bare.api("api_pos_recovery_audit", bareOwner.token, A, 10)).toEqual({ ok: false, error: "POS_RECOVERY_UNAVAILABLE" });
    expect((await bare.api("api_pos_recovery_report", bareOwner.token, A, randomUUID())).error).toBe("POS_RECOVERY_UNAVAILABLE");
    await stepup(bare, bareOwner.token, bareOwner.auth, "pos_recovery_transition", `${B}:RECONCILING`);
    expect((await transition(bareOwner, B, "RECONCILING", randomUUID(), bare)).error).toBe("POS_RECOVERY_UNAVAILABLE");
    expect(await unusedGrants(bare, "pos_recovery_transition")).toBe(1);
    const auth = authorization("enroll-device", B);
    expect((await bare.api("api_pos_recovery_submit", bareOwner.token, auth, "abcd", randomUUID())).error).toBe("POS_RECOVERY_UNAVAILABLE");
    expect((await bare.api("api_pos_recovery_contain_device", bareOwner.token, B, ENR_B, "suspend", "a long enough reason", randomUUID())).error)
      .toBe("POS_RECOVERY_UNAVAILABLE");
    const rows = (await bare.su.query("SELECT action, outcome, reason_code, detail FROM control.audit_events WHERE seq > $1 AND action LIKE 'pos.%' ORDER BY seq", [before])).rows;
    expect(rows).toHaveLength(7);
    for (const r of rows) expect([r.outcome, r.reason_code, r.detail.bridge]).toEqual(["denied", "POS_RECOVERY_UNAVAILABLE", "not_configured"]);
  });

  it("POS unreachable (nothing listening) or the POS login refused (wrong password): unavailable, step-up kept, no fallback", async () => {
    for (const bad of [{ port: 1 }, { password: "x".repeat(48) }]) {
      await withBridge((c) => configurePosBridge(c, { ...pos.settings, ...bad }), async () => {
        const t0 = Date.now();
        expect(await db.api("api_pos_recovery_overview", owner.token)).toEqual({ ok: false, error: "POS_RECOVERY_UNAVAILABLE" });
        expect(Date.now() - t0).toBeLessThan(4500);   // bounded by connect_timeout, inside the app's statement timeout
        const [a] = await lastAudit(db);
        expect([a.action, a.reason_code, a.detail.bridge]).toEqual(["pos.recovery_read_refused", "POS_RECOVERY_UNAVAILABLE", "unreachable"]);
        await stepup(db, owner.token, owner.auth, "pos_recovery_transition", `${B}:QUARANTINED`);
        expect((await transition(owner, B, "QUARANTINED")).error).toBe("POS_RECOVERY_UNAVAILABLE");
        expect(await unusedGrants(db, "pos_recovery_transition")).toBe(1);
        await db.su.query("UPDATE control.stepup_grants SET used_at = now() WHERE used_at IS NULL");
      });
    }
    expect((await mockState(B)).state).toBe("RESTRICTED");
    expect((await db.api("api_pos_recovery_overview", owner.token)).ok).toBe(true);
  });

  it("an over-privileged POS login is refused before any call (superuser-like attributes or any other role membership)", async () => {
    const u = pos.bridgeUser;
    for (const [grant, revoke] of <[string, string][]>[[`ALTER ROLE ${u} CREATEROLE`, `ALTER ROLE ${u} NOCREATEROLE`],
                                   [`ALTER ROLE ${u} BYPASSRLS`, `ALTER ROLE ${u} NOBYPASSRLS`],
                                   [`GRANT pg_read_all_data TO ${u}`, `REVOKE pg_read_all_data FROM ${u}`]]) {
      await pos.su.query(grant);
      try {
        expect(await db.api("api_pos_recovery_overview", owner.token), grant).toEqual({ ok: false, error: "POS_RECOVERY_UNAVAILABLE" });
        expect((await lastAudit(db))[0].detail.bridge, grant).toBe("bridge_login_overprivileged");
      } finally { await pos.su.query(revoke); }
    }
    expect((await db.api("api_pos_recovery_overview", owner.token)).ok).toBe(true);
  });

  it("all-or-nothing contract: one missing EXECUTE, or an operator function owned by the login itself, makes the bridge unavailable", async () => {
    await pos.su.query("REVOKE EXECUTE ON FUNCTION recovery_v1.operator_audit(text, integer) FROM orvix_recovery_operator");
    try {
      expect((await db.api("api_pos_recovery_overview", owner.token)).error).toBe("POS_RECOVERY_UNAVAILABLE");
      expect((await lastAudit(db))[0].detail.bridge).toBe("contract_incomplete");
    } finally {
      await pos.su.query("GRANT EXECUTE ON FUNCTION recovery_v1.operator_audit(text, integer) TO orvix_recovery_operator");
    }
    await pos.su.query(`ALTER FUNCTION recovery_v1.operator_audit(text, integer) OWNER TO ${pos.bridgeUser}`);
    try {
      expect((await db.api("api_pos_recovery_overview", owner.token)).error).toBe("POS_RECOVERY_UNAVAILABLE");
      expect((await lastAudit(db))[0].detail.bridge).toBe("contract_incomplete");
    } finally {
      await pos.su.query("ALTER FUNCTION recovery_v1.operator_audit(text, integer) OWNER TO CURRENT_USER");
      await pos.su.query("GRANT EXECUTE ON FUNCTION recovery_v1.operator_audit(text, integer) TO orvix_recovery_operator");
    }
    expect((await db.api("api_pos_recovery_overview", owner.token)).ok).toBe(true);
  });

  it("a POS that accepts the connection but never answers (frozen) is answered within the caller's statement timeout as unavailable, audited", async () => {
    // dblink's non-blocking connect ignores connect_timeout: the bound is the caller's statement_timeout (the server: 5 s)
    const silent = net.createServer(() => { /* accept, never answer */ });
    await new Promise<void>((r) => silent.listen(0, "127.0.0.1", () => r()));
    const port = (silent.address() as net.AddressInfo).port;
    const c = await db.app.connect();
    try {
      await withBridge((s) => configurePosBridge(s, { ...pos.settings, port }), async () => {
        await c.query("SET statement_timeout = 2000");
        const t0 = Date.now();
        const r = (await c.query("SELECT control.api_pos_recovery_overview($1) AS r", [owner.token])).rows[0].r;
        expect(r).toEqual({ ok: false, error: "POS_RECOVERY_UNAVAILABLE" });
        expect(Date.now() - t0).toBeLessThan(3500);
        const [a] = await lastAudit(db);
        expect([a.action, a.reason_code, a.detail.bridge]).toEqual(["pos.recovery_read_refused", "POS_RECOVERY_UNAVAILABLE", "timeout"]);
        // a containment attempt: unavailable, the step-up grant is NOT consumed
        await stepup(db, owner.token, owner.auth, "pos_recovery_transition", `${B}:QUARANTINED`);
        const t = (await c.query("SELECT control.api_pos_recovery_transition($1, $2, 'QUARANTINED', 'frozen POS check (synthetic)', 'INC-SYN-FZ', $3) AS r",
          [owner.token, B, randomUUID()])).rows[0].r;
        expect(t.error).toBe("POS_RECOVERY_UNAVAILABLE");
        expect(await unusedGrants(db, "pos_recovery_transition")).toBe(1);
        await db.su.query("UPDATE control.stepup_grants SET used_at = now() WHERE used_at IS NULL");
      });
    } finally { await c.query("RESET statement_timeout").catch(() => undefined); c.release(); silent.close(); }
    expect((await mockState(B)).state).toBe("RESTRICTED");
  });

  it("no connection is left open on the POS after reads, refusals or errors", async () => {
    await db.api("api_pos_recovery_overview", owner.token);
    await db.api("api_pos_recovery_org", owner.token, "org-unknown");
    await transition(owner, B, "RECONCILING");   // STEPUP_REQUIRED after opening the bridge
    await new Promise((r) => setTimeout(r, 300));
    expect(await bridgeConns()).toBe(0);
  });
});

// =====================================================================================================================
describe("reads (owner and admin)", () => {
  it("overview: contract keys only, blocked reasons, one audit row", async () => {
    for (const op of [owner, admin]) {
      const before = await headSeq(db);
      const r = await db.api("api_pos_recovery_overview", op.token);
      expect(r.ok).toBe(true);
      expect(r.organizations.map((o: { orgId: string }) => o.orgId)).toEqual([A, B]);
      const b = r.organizations[1];
      expect(Object.keys(b).sort()).toEqual(["activation", "devices", "incidentId", "lastReport", "orgId", "ownerAuthority",
        "recoveryEpoch", "reopenBlockedBy", "reopening", "state"]);
      expect(b).toMatchObject({ state: "RESTRICTED", ownerAuthority: [], activation: null });
      expect(b.reopenBlockedBy).toEqual(expect.arrayContaining(["no_owner_authority", "not_reconciling", "no_report"]));
      expect(r.organizations[0]).toMatchObject({ state: "ACTIVE", activation: "verified", reopenBlockedBy: [] });
      expect(await headSeq(db)).toBe(before + 1);
      const [a] = await lastAudit(db);
      expect([a.action, a.outcome, a.actor_id, a.target_id]).toEqual(["pos.recovery_viewed", "success", op.identityId, "*"]);
    }
  });

  it("organization detail includes open device requests; unknown and malformed organizations are refused and audited", async () => {
    const r = await db.api("api_pos_recovery_org", admin.token, B);
    expect(r.ok).toBe(true);
    expect(r.organization.deviceRequests).toHaveLength(1);
    expect(r.organization.deviceRequests[0]).toMatchObject({ deviceId: "till-b2", shortCode: "B2F0000000000000" });
    expect(r.organization.devices).toMatchObject({ pendingRequests: 1 });
    expect(await db.api("api_pos_recovery_org", admin.token, "org-unknown")).toEqual({ ok: false, error: "NOT_FOUND" });
    let [a] = await lastAudit(db);
    expect([a.action, a.reason_code, a.detail.pos_error, a.detail.sqlstate]).toEqual(["pos.recovery_read_refused", "NOT_FOUND", "RECOVERY_V1_OPERATOR_INVALID", "22023"]);
    expect(await db.api("api_pos_recovery_org", admin.token, "bad org; drop")).toEqual({ ok: false, error: "INVALID_INPUT" });
    [a] = await lastAudit(db);
    expect([a.action, a.reason_code]).toEqual(["pos.recovery_read_refused", "INVALID_INPUT"]);
  });

  it("quoting: hostile text inside an authorization reaches the POS as one value, never as SQL", async () => {
    const auth = authorization("enroll-device", A, { requestId: randomUUID(),
      note: "x'); SELECT pg_sleep(10); --", other: "$$ $q$ \\ '' E'\\x27'" });
    await stepup(db, admin.token, admin.auth, "pos_recovery_submit", `enroll-device:${sha(auth)}`);
    const t0 = Date.now();
    expect(await submit(admin, auth, "0a0b")).toEqual({ ok: false, error: "POS_RECOVERY_REFUSED" });
    expect(Date.now() - t0).toBeLessThan(3000);
    const [p] = await posAudit(A);
    expect(p.kind).toBe("owner_authorization_refused");
    expect(p.detail.reason).toMatch(/^RECOVERY_V1_DEVICE_APPROVE_INVALID/);
    expect((await lastAudit(db))[0].detail.authorization_sha256).toBe(sha(auth));
  });

  it("audit history and input bounds", async () => {
    const r = await db.api("api_pos_recovery_audit", owner.token, B, 50);
    expect(r.ok).toBe(true);
    expect(Array.isArray(r.events)).toBe(true);
    expect((await db.api("api_pos_recovery_audit", owner.token, B, 0)).error).toBe("INVALID_INPUT");
    expect((await db.api("api_pos_recovery_audit", owner.token, B, 201)).error).toBe("INVALID_INPUT");
  });

  it("no session: refused before anything else (and before the POS is contacted)", async () => {
    expect(await db.api("api_pos_recovery_overview", null)).toEqual({ ok: false, error: "UNAUTHENTICATED" });
    expect(await db.api("api_pos_recovery_org", "0".repeat(64), A)).toEqual({ ok: false, error: "UNAUTHENTICATED" });
    expect((await db.api("api_pos_recovery_transition", null, B, "RECONCILING", "x", "y", randomUUID())).error).toBe("UNAUTHENTICATED");
  });
});

// =====================================================================================================================
describe("containment transitions", () => {
  it("never ACTIVE: refused by Control before the POS is called, even with a matching step-up", async () => {
    const posBefore = (await posAudit(B)).length;
    await stepup(db, owner.token, owner.auth, "pos_recovery_transition", `${B}:ACTIVE`);
    expect((await transition(owner, B, "ACTIVE")).error).toBe("TRANSITION_NOT_ALLOWED");
    expect((await posAudit(B)).length).toBe(posBefore);
    expect(await unusedGrants(db, "pos_recovery_transition")).toBeGreaterThanOrEqual(1);
    const [a] = await lastAudit(db);
    expect([a.action, a.outcome, a.reason_code]).toEqual(["pos.recovery_transition_refused", "denied", "TRANSITION_NOT_ALLOWED"]);
    expect((await transition(owner, B, "DELETED")).error).toBe("TRANSITION_NOT_ALLOWED");
    expect((await mockState(B)).state).toBe("RESTRICTED");
    await db.su.query("UPDATE control.stepup_grants SET used_at = now() WHERE used_at IS NULL");
  });

  it("requires a step-up bound to that organization and state; reason and evidence first", async () => {
    expect((await transition(admin, B, "RECONCILING")).error).toBe("STEPUP_REQUIRED");
    let [a] = await lastAudit(db);
    expect([a.action, a.reason_code, a.actor_id]).toEqual(["pos.recovery_transition_refused", "STEPUP_REQUIRED", admin.identityId]);
    await stepup(db, admin.token, admin.auth, "pos_recovery_transition", `${B}:QUARANTINED`);   // other target
    expect((await transition(admin, B, "RECONCILING")).error).toBe("STEPUP_REQUIRED");
    await stepup(db, admin.token, admin.auth, "pos_recovery_transition", `${B}:RECONCILING`);
    expect((await transition(admin, B, "RECONCILING", randomUUID(), db, "short")).error).toBe("REASON_REQUIRED");
    expect((await transition(admin, B, "RECONCILING", randomUUID(), db, "a long enough reason", "")).error).toBe("REASON_REQUIRED");
    expect((await mockState(B)).state).toBe("RESTRICTED");
    const rid = randomUUID();
    const before = await headSeq(db);
    const ok = await transition(admin, B, "RECONCILING", rid);
    expect(ok).toMatchObject({ ok: true, outcome: "applied", state: "RECONCILING", org: B });
    expect(await headSeq(db)).toBe(before + 1);
    expect((await mockState(B)).state).toBe("RECONCILING");
    [a] = await lastAudit(db);
    expect([a.action, a.outcome, a.request_id, a.detail.to]).toEqual(["pos.recovery_transitioned", "success", rid, "RECONCILING"]);
    const [p] = await posAudit(B);
    expect(p.kind).toBe("transition_applied");
    // the POS records WHO in Control did it, the Control request id, and the POS login that carried it
    expect(p.actor).toBe(`operator:control:admin:${admin.identityId}:${rid}@${pos.bridgeUser}`);
    // replay: same result, no second effect, no second audit row; reuse for another organization is a conflict
    const seq = await headSeq(db);
    const posRows = (await posAudit(B)).length;
    expect(await transition(admin, B, "RECONCILING", rid)).toEqual({ ...ok, replayed: true });
    expect(await headSeq(db)).toBe(seq);
    expect((await posAudit(B)).length).toBe(posRows);
    expect((await transition(admin, A, "RECONCILING", rid)).error).toBe("REQUEST_ID_CONFLICT");
    expect((await transition(owner, B, "RECONCILING", rid)).error).toBe("REQUEST_ID_CONFLICT");
    expect((await db.api("api_pos_recovery_transition", admin.token, B, "RECONCILING", "x", "y", null)).error).toBe("REQUEST_ID_REQUIRED");
  });
});

// =====================================================================================================================
describe("atomicity across the two databases (remote commit last)", () => {
  it("a Control failure BEFORE the remote commit rolls the POS back: POS_RECOVERY_ERROR, nothing changed on either side", async () => {
    const rid = randomUUID();
    await db.su.query(`CREATE FUNCTION control.zz_test_fail() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN IF NEW.request_id = '${rid}' THEN RAISE EXCEPTION 'injected local failure'; END IF; RETURN NEW; END $$`);
    await db.su.query("CREATE TRIGGER zz_test_fail BEFORE INSERT ON control.request_results FOR EACH ROW EXECUTE FUNCTION control.zz_test_fail()");
    try {
      await stepup(db, owner.token, owner.auth, "pos_recovery_transition", `${B}:QUARANTINED`);
      const posRows = (await posAudit(B)).length;
      expect(await transition(owner, B, "QUARANTINED", rid)).toEqual({ ok: false, error: "POS_RECOVERY_ERROR" });
      expect((await mockState(B)).state).toBe("RECONCILING");
      expect((await posAudit(B)).length).toBe(posRows);
      const rows = (await db.su.query("SELECT action, outcome, reason_code, detail FROM control.audit_events WHERE request_id = $1 ORDER BY seq", [rid])).rows;
      expect(rows.map((r) => [r.action, r.outcome, r.reason_code, r.detail.phase, r.detail.pos_rolled_back]))
        .toEqual([["pos.recovery_transition_refused", "denied", "POS_RECOVERY_ERROR", "local", true]]);
    } finally {
      await db.su.query("DROP TRIGGER zz_test_fail ON control.request_results; DROP FUNCTION control.zz_test_fail()");
    }
  });

  it("the POS refuses the COMMIT itself (deferred check): POS_RECOVERY_ERROR, POS unchanged, no success row in Control", async () => {
    await pos.su.query(`CREATE FUNCTION recovery_v1.zz_test_defer() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN IF NEW.detail->>'to' = 'QUARANTINED' THEN RAISE EXCEPTION 'injected commit-time failure'; END IF; RETURN NULL; END $$`);
    await pos.su.query(`CREATE CONSTRAINT TRIGGER zz_test_defer AFTER INSERT ON recovery_v1.mock_audit DEFERRABLE INITIALLY DEFERRED
      FOR EACH ROW EXECUTE FUNCTION recovery_v1.zz_test_defer()`);
    try {
      const rid = randomUUID();
      await stepup(db, owner.token, owner.auth, "pos_recovery_transition", `${B}:QUARANTINED`);
      expect(await transition(owner, B, "QUARANTINED", rid)).toEqual({ ok: false, error: "POS_RECOVERY_ERROR" });
      expect((await mockState(B)).state).toBe("RECONCILING");
      const rows = (await db.su.query("SELECT action, reason_code, detail FROM control.audit_events WHERE request_id = $1", [rid])).rows;
      expect(rows.map((r) => [r.action, r.reason_code, r.detail.phase])).toEqual([["pos.recovery_transition_refused", "POS_RECOVERY_ERROR", "remote_commit"]]);
      expect((await db.su.query("SELECT count(*)::int n FROM control.request_results WHERE request_id = $1", [rid])).rows[0].n).toBe(0);
    } finally {
      await pos.su.query("DROP TRIGGER zz_test_defer ON recovery_v1.mock_audit; DROP FUNCTION recovery_v1.zz_test_defer()");
    }
  });

  it("the connection is lost during the COMMIT: POS_RECOVERY_IN_DOUBT, audited with the actor label the POS would have recorded", async () => {
    // the POS backend dies at commit time: the reply never arrives
    await pos.su.query(`CREATE FUNCTION recovery_v1.zz_test_die() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER AS $$
      BEGIN IF NEW.detail->>'to' = 'QUARANTINED' THEN PERFORM pg_terminate_backend(pg_backend_pid()); PERFORM pg_sleep(5); END IF; RETURN NULL; END $$`);
    await pos.su.query(`CREATE CONSTRAINT TRIGGER zz_test_die AFTER INSERT ON recovery_v1.mock_audit DEFERRABLE INITIALLY DEFERRED
      FOR EACH ROW EXECUTE FUNCTION recovery_v1.zz_test_die()`);
    try {
      const rid = randomUUID();
      await stepup(db, owner.token, owner.auth, "pos_recovery_transition", `${B}:QUARANTINED`);
      expect(await transition(owner, B, "QUARANTINED", rid)).toEqual({ ok: false, error: "POS_RECOVERY_IN_DOUBT" });
      const rows = (await db.su.query("SELECT action, outcome, reason_code, detail FROM control.audit_events WHERE request_id = $1", [rid])).rows;
      expect(rows).toHaveLength(1);
      expect([rows[0].action, rows[0].outcome, rows[0].reason_code]).toEqual(["pos.recovery_in_doubt", "denied", "POS_RECOVERY_IN_DOUBT"]);
      expect(rows[0].detail.sqlstate).toMatch(/^08|^57P0/);
      expect(rows[0].detail.pos_actor).toBe(`control:owner:${owner.identityId}:${rid}`);
      // the owners are told out of band, and a replay of the request id answers "in doubt" without calling the POS again
      expect((await db.su.query("SELECT count(*)::int n FROM control.notify_outbox o JOIN control.audit_events a ON a.seq = o.audit_seq WHERE a.request_id = $1", [rid])).rows[0].n).toBe(1);
      const posRows = (await posAudit(B)).length;
      expect(await transition(owner, B, "QUARANTINED", rid)).toMatchObject({ ok: false, error: "POS_RECOVERY_IN_DOUBT", replayed: true });
      expect((await posAudit(B)).length).toBe(posRows);
      // here the backend died before committing, so the POS is unchanged; in general Control cannot know, hence "in doubt"
      expect((await mockState(B)).state).toBe("RECONCILING");
    } finally {
      await pos.su.query("DROP TRIGGER zz_test_die ON recovery_v1.mock_audit; DROP FUNCTION recovery_v1.zz_test_die()");
    }
  });

  it("the POS never answers the COMMIT within the caller's statement timeout: POS_RECOVERY_IN_DOUBT (57014), audited, nothing left open", async () => {
    await pos.su.query(`CREATE FUNCTION recovery_v1.zz_test_slow() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN IF NEW.detail->>'to' = 'QUARANTINED' THEN PERFORM pg_sleep(4); END IF; RETURN NULL; END $$`);
    await pos.su.query(`CREATE CONSTRAINT TRIGGER zz_test_slow AFTER INSERT ON recovery_v1.mock_audit DEFERRABLE INITIALLY DEFERRED
      FOR EACH ROW EXECUTE FUNCTION recovery_v1.zz_test_slow()`);
    const c = await db.app.connect();
    try {
      const rid = randomUUID();
      await stepup(db, owner.token, owner.auth, "pos_recovery_transition", `${B}:QUARANTINED`);
      await c.query("SET statement_timeout = 2000");
      const r = (await c.query("SELECT control.api_pos_recovery_transition($1, $2, 'QUARANTINED', 'slow commit check (synthetic)', 'INC-SYN-SL', $3) AS r",
        [owner.token, B, rid])).rows[0].r;
      expect(r).toEqual({ ok: false, error: "POS_RECOVERY_IN_DOUBT" });
      const rows = (await db.su.query("SELECT action, detail FROM control.audit_events WHERE request_id = $1", [rid])).rows;
      expect(rows.map((x) => [x.action, x.detail.sqlstate])).toEqual([["pos.recovery_in_doubt", "57014"]]);
      expect((await db.su.query("SELECT result->>'error' AS e FROM control.request_results WHERE request_id = $1", [rid])).rows.map((x) => x.e)).toEqual(["POS_RECOVERY_IN_DOUBT"]);
    } finally {
      await c.query("RESET statement_timeout").catch(() => undefined); c.release();
      await new Promise((r) => setTimeout(r, 4500));   // let the slow remote commit finish
      await pos.su.query("DROP TRIGGER zz_test_slow ON recovery_v1.mock_audit; DROP FUNCTION recovery_v1.zz_test_slow()");
    }
    // the POS may or may not have committed: the honest answer was "in doubt"; restore the precondition either way
    if ((await mockState(B)).state !== "RECONCILING") {
      await stepup(db, owner.token, owner.auth, "pos_recovery_transition", `${B}:RECONCILING`);
      expect((await transition(owner, B, "RECONCILING")).ok).toBe(true);
    }
  });

  it("documented limit: once the call returned, a LATER rollback of the caller's own transaction cannot undo the POS (no two-phase commit); the POS audit row carries the request id", async () => {
    await stepup(db, owner.token, owner.auth, "pos_recovery_transition", `${B}:QUARANTINED`);
    const rid = randomUUID();
    const c = await db.app.connect();
    try {
      await c.query("BEGIN");
      const r = (await c.query("SELECT control.api_pos_recovery_transition($1, $2, 'QUARANTINED', 'synthetic rollback check', 'INC-SYN-RB', $3) AS r",
        [owner.token, B, rid])).rows[0].r;
      expect(r.ok).toBe(true);
      await c.query("ROLLBACK");
    } finally { c.release(); }
    expect((await mockState(B)).state).toBe("QUARANTINED");
    expect((await db.su.query("SELECT count(*)::int n FROM control.audit_events WHERE request_id = $1", [rid])).rows[0].n).toBe(0);
    expect((await posAudit(B))[0].actor).toContain(rid);
    // restore the precondition of the later tests
    await stepup(db, owner.token, owner.auth, "pos_recovery_transition", `${B}:RECONCILING`);
    expect((await transition(owner, B, "RECONCILING")).ok).toBe(true);
  });
});

// =====================================================================================================================
describe("device containment", () => {
  it("suspend then revoke need a step-up each (owner or admin); every attempt is audited", async () => {
    expect((await contain(admin, B, ENR_B, "suspend")).error).toBe("STEPUP_REQUIRED");
    expect(await enrollment(ENR_B)).toBe("ACTIVE");
    await stepup(db, admin.token, admin.auth, "pos_recovery_contain", `${B}:${ENR_B}:suspend`);
    expect((await contain(admin, B, ENR_B, "suspend", randomUUID(), "short")).error).toBe("REASON_REQUIRED");
    expect(await contain(admin, B, ENR_B, "suspend")).toMatchObject({ ok: true, outcome: "suspended", state: "SUSPENDED" });
    expect(await enrollment(ENR_B)).toBe("SUSPENDED");
    let [a] = await lastAudit(db);
    expect([a.action, a.detail.action, a.detail.state]).toEqual(["pos.recovery_device_contained", "suspend", "SUSPENDED"]);
    await stepup(db, owner.token, owner.auth, "pos_recovery_contain", `${B}:${ENR_B}:revoke`);
    expect(await contain(owner, B, ENR_B, "revoke")).toMatchObject({ ok: true, outcome: "revoked", state: "REVOKED" });
    [a] = await lastAudit(db);
    expect(a.action).toBe("pos.recovery_device_contained");
  });

  it("a POS exception is caught: its partial effects roll back, the refusal is audited, POS text is not returned", async () => {
    const wrong = randomUUID();
    await stepup(db, admin.token, admin.auth, "pos_recovery_contain", `${B}:${wrong}:suspend`);
    const before = await headSeq(db);
    expect(await contain(admin, B, wrong, "suspend")).toEqual({ ok: false, error: "POS_RECOVERY_INVALID" });
    expect(await headSeq(db)).toBe(before + 1);
    const [a] = await lastAudit(db);
    expect([a.action, a.reason_code, a.detail.pos_error, a.detail.sqlstate])
      .toEqual(["pos.recovery_contain_refused", "POS_RECOVERY_INVALID", "RECOVERY_V1_DEVICE_CONTAIN_INVALID", "22023"]);
    // an enrollment of ANOTHER organization is not reachable through this one
    await stepup(db, admin.token, admin.auth, "pos_recovery_contain", `${B}:${ENR_A}:suspend`);
    expect((await contain(admin, B, ENR_A, "suspend")).error).toBe("POS_RECOVERY_INVALID");
    expect(await enrollment(ENR_A)).toBe("ACTIVE");
    expect((await contain(admin, B, ENR_B, "wipe")).error).toBe("INVALID_INPUT");
  });
});

// =====================================================================================================================
describe("reconciliation report", () => {
  it("only while RECONCILING (POS refusal mapped and audited); hard blockers flagged", async () => {
    expect((await db.api("api_pos_recovery_report", admin.token, A, randomUUID())).error).toBe("POS_RECOVERY_STATE");
    let [a] = await lastAudit(db);
    expect([a.action, a.reason_code, a.detail.pos_error]).toEqual(["pos.recovery_report_refused", "POS_RECOVERY_STATE", "RECOVERY_V1_RECONCILIATION_STATE"]);
    const r = await db.api("api_pos_recovery_report", admin.token, B, randomUUID());
    expect(r).toMatchObject({ ok: true, outcome: "reported", orgId: B, hardBlockers: ["ledger_in_flight"] });
    expect(r.blockers).toEqual(expect.arrayContaining(["ledger_in_flight", "offline_operations_possibly_unsynced", "device_evidence_missing"]));
    expect(r.signingTarget).toMatchObject({ database: pos.name });   // the POS database, not Control's
    [a] = await lastAudit(db);
    expect([a.action, a.detail.digest]).toEqual(["pos.recovery_reported", r.digest]);
    const o = (await db.api("api_pos_recovery_org", owner.token, B)).organization;
    expect(o.lastReport.hardBlockers).toEqual(["ledger_in_flight"]);
    expect(o.reopenBlockedBy).toEqual(["no_owner_authority", "hard_blockers"]);
  });
});

// =====================================================================================================================
describe("owner-signed authorizations (transport only)", () => {
  it("a reopening is carried by an OWNER only, with a step-up bound to the exact document", async () => {
    const auth = authorization("reopen-organization", A, { reopen: { orgId: A, decision: "verified" } });
    await stepup(db, admin.token, admin.auth, "pos_recovery_submit", `reopen-organization:${sha(auth)}`);
    expect((await submit(admin, auth, "abcd")).error).toBe("FORBIDDEN");
    const [a] = await lastAudit(db);
    expect([a.action, a.reason_code, a.target_id]).toEqual(["platform.access_denied", "FORBIDDEN", "pos_recovery_submit"]);
    expect((await submit(owner, auth, "abcd")).error).toBe("STEPUP_REQUIRED");
    await stepup(db, owner.token, owner.auth, "pos_recovery_submit", `reopen-organization:${sha(auth + " ")}`);   // other bytes
    expect((await submit(owner, auth, "abcd")).error).toBe("STEPUP_REQUIRED");
    await db.su.query("UPDATE control.stepup_grants SET used_at = now() WHERE used_at IS NULL");
  });

  it("malformed input is refused locally (audited) and never reaches the POS", async () => {
    const posBefore = (await pos.su.query("SELECT count(*)::int n FROM recovery_v1.mock_audit")).rows[0].n;
    expect((await submit(owner, "not json", "abcd")).error).toBe("INVALID_INPUT");
    expect((await submit(owner, authorization("migration", A), "abcd")).error).toBe("INVALID_INPUT");
    expect((await submit(owner, authorization("reopen-organization", A), "not-hex")).error).toBe("INVALID_INPUT");
    expect((await submit(owner, authorization("reopen-organization", A), "abc")).error).toBe("INVALID_INPUT");
    expect((await pos.su.query("SELECT count(*)::int n FROM recovery_v1.mock_audit")).rows[0].n).toBe(posBefore);
    const [a] = await lastAudit(db);
    expect([a.action, a.reason_code]).toEqual(["pos.recovery_submit_refused", "INVALID_INPUT"]);
  });

  it("a signature the POS verifier refuses: POS_RECOVERY_REFUSED, audited on BOTH sides (the POS refusal row is committed), nothing changes", async () => {
    await stepup(db, owner.token, owner.auth, "pos_recovery_transition", `${A}:RECONCILING`);
    expect((await transition(owner, A, "RECONCILING")).ok).toBe(true);
    const rep = await db.api("api_pos_recovery_report", owner.token, A, randomUUID());
    expect(rep).toMatchObject({ ok: true, blockers: [], hardBlockers: [] });
    const auth = authorization("reopen-organization", A, { reopen: { orgId: A, decision: "verified", reportDigest: rep.digest } });
    await stepup(db, owner.token, owner.auth, "pos_recovery_submit", `reopen-organization:${sha(auth)}`);
    expect(await submit(owner, auth, "badbad")).toEqual({ ok: false, error: "POS_RECOVERY_REFUSED" });
    expect(await unusedGrants(db, "pos_recovery_submit")).toBe(0);   // the attempt used the grant
    const [a] = await lastAudit(db);
    expect([a.action, a.reason_code, a.detail.authorization_sha256, a.detail.pos_error])
      .toEqual(["pos.recovery_submit_refused", "POS_RECOVERY_REFUSED", sha(auth), "RECOVERY_V1_OWNER_AUTHORIZATION_INVALID"]);
    expect((await posAudit(A))[0].kind).toBe("owner_authorization_refused");
    expect((await mockState(A)).state).toBe("RECONCILING");
  });

  it("an owner-signed reopening accepted by the POS sets ACTIVE (the only path); Control audits and notifies", async () => {
    const o = (await db.api("api_pos_recovery_org", owner.token, A)).organization;
    expect(o.state).toBe("RECONCILING");
    const auth = authorization("reopen-organization", A, { reopen: { orgId: A, decision: "verified", reportDigest: o.lastReport.digest } });
    await stepup(db, owner.token, owner.auth, "pos_recovery_submit", `reopen-organization:${sha(auth)}`);
    const rid = randomUUID();
    const r = await submit(owner, auth, "ABCDEF0123", rid);
    expect(r).toMatchObject({ ok: true, outcome: "reopened", state: "ACTIVE", org: A, purpose: "reopen-organization" });
    expect((await mockState(A)).state).toBe("ACTIVE");
    const [a] = await lastAudit(db);
    expect([a.action, a.outcome, a.request_id, a.detail.reopen_id]).toEqual(["pos.recovery_submitted", "success", rid, r.reopenId]);
    expect((await db.su.query("SELECT count(*)::int n FROM control.notify_outbox WHERE audit_seq = $1", [a.seq])).rows[0].n).toBe(1);
    expect((await posAudit(A))[0]).toMatchObject({ kind: "organization_reopened", actor: `operator:control:owner:${owner.identityId}:${rid}@${pos.bridgeUser}` });
    expect(await submit(owner, auth, "ABCDEF0123", rid)).toEqual({ ...r, replayed: true });
  });

  it("device enrollment: an admin may carry it (step-up), the POS decides", async () => {
    const req = randomUUID();
    await pos.su.query(`INSERT INTO recovery_v1.mock_requests (request_id, org_id, shop_id, device_id, key_fingerprint, request_nonce, requested_by)
      VALUES ($1, $2, 'shop-synthetic-a1', 'till-a2', 'a2f0000000000000000000000000000000000000000000000000000000000a2', gen_random_uuid(), 'user:synthetic')`, [req, A]);
    const auth = authorization("enroll-device", A, { requestId: req });
    await stepup(db, admin.token, admin.auth, "pos_recovery_submit", `enroll-device:${sha(auth)}`);
    expect(await submit(admin, auth, "0a0b")).toMatchObject({ ok: true, outcome: "enrolled", enrollmentId: req });
    expect(await enrollment(req)).toBe("ACTIVE");
    // organization B has no owner authority: the POS refuses whatever Control carries
    const authB = authorization("enroll-device", B, { requestId: "a2000000-0000-4000-8000-0000000000b2" });
    await stepup(db, admin.token, admin.auth, "pos_recovery_submit", `enroll-device:${sha(authB)}`);
    expect((await submit(admin, authB, "0a0b")).error).toBe("POS_RECOVERY_REFUSED");
  });

  it("device reinstatement: Control shows the current suspension event, and only an authorization naming it reinstates", async () => {
    await stepup(db, admin.token, admin.auth, "pos_recovery_contain", `${A}:${ENR_A}:suspend`);
    const s = await contain(admin, A, ENR_A, "suspend");
    expect(s).toMatchObject({ ok: true, state: "SUSPENDED" });
    const shown = (await db.api("api_pos_recovery_org", owner.token, A)).organization.devices.enrollments.find((e: { enrollmentId: string }) => e.enrollmentId === ENR_A);
    expect(shown).toMatchObject({ state: "SUSPENDED", suspensionEventId: expect.any(Number) });
    const stale = authorization("device-reinstate", A, { device: { enrollmentId: ENR_A, suspensionEventId: shown.suspensionEventId + 1000 } });
    await stepup(db, admin.token, admin.auth, "pos_recovery_submit", `device-reinstate:${sha(stale)}`);
    expect((await submit(admin, stale, "0a0b")).error).toBe("POS_RECOVERY_REFUSED");
    const good = authorization("device-reinstate", A, { device: { enrollmentId: ENR_A, suspensionEventId: shown.suspensionEventId } });
    await stepup(db, admin.token, admin.auth, "pos_recovery_submit", `device-reinstate:${sha(good)}`);
    expect(await submit(admin, good, "0a0b")).toMatchObject({ ok: true, outcome: "reinstated" });
    const after = (await db.api("api_pos_recovery_org", owner.token, A)).organization.devices.enrollments.find((e: { enrollmentId: string }) => e.enrollmentId === ENR_A);
    expect(after).toMatchObject({ state: "ACTIVE", suspensionEventId: null });
  });
});

// =====================================================================================================================
describe("boundaries", () => {
  it("no tenant-table access for control_app or control_definer in the Control database", async () => {
    const e = await db.app.query("SELECT * FROM pos_mock.sales").catch((x) => x);
    expect(e.code).toBe("42501");
    const { rows } = await db.su.query(
      `SELECT r.rolname, n.nspname || '.' || c.relname AS rel FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace CROSS JOIN pg_roles r
        WHERE r.rolname IN ('control_app', 'control_definer', 'control_auth', 'control_audit_owner') AND n.nspname IN ('pos_mock', 'public', 'recovery_v1')
          AND c.relkind IN ('r', 'v', 'm', 'p') AND has_table_privilege(r.oid, c.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE')`);
    expect(rows).toEqual([]);
    const usage = (await db.su.query(
      `SELECT r.rolname, n.nspname FROM pg_namespace n CROSS JOIN pg_roles r
        WHERE r.rolname IN ('control_definer', 'control_app') AND n.nspname IN ('pos_mock', 'public') AND has_schema_privilege(r.oid, n.oid, 'USAGE')`)).rows;
    expect(usage).toEqual([]);
  });

  it("the POS login reads no POS table directly (on the POS side): only the seven functions", async () => {
    const { rows } = await pos.su.query(
      `SELECT n.nspname || '.' || c.relname AS rel FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname NOT IN ('pg_catalog', 'information_schema') AND c.relkind IN ('r', 'v', 'm', 'p', 'f')
          AND has_table_privilege($1, c.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE')`, [pos.bridgeUser]);
    expect(rows).toEqual([]);
  });

  it("no control function reads a POS table or sets ACTIVE itself; remote SQL is built only with quoted values", async () => {
    const { rows } = await db.su.query(
      `SELECT p.proname, p.prosrc FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'control' AND (p.proname LIKE '%pos\\_recovery%' OR p.proname LIKE 'pos\\_bridge%')`);
    expect(rows.length).toBeGreaterThanOrEqual(12);
    for (const r of rows) {
      expect(/\b(public|pos_mock)\.\w+/i.test(r.prosrc), r.proname).toBe(false);
      // the only recovery_v1 references are the seven operator functions
      for (const m of r.prosrc.matchAll(/recovery_v1\.(\w+)/g)) expect(m[1], r.proname).toMatch(/^operator_/);
      expect(/state\s*=\s*'ACTIVE'|operator_transition\([^)]*'ACTIVE'/i.test(r.prosrc), r.proname).toBe(false);
      // every format() placeholder for a value is %L (or %s for a validated integer limit)
      for (const m of r.prosrc.matchAll(/format\('SELECT recovery_v1\.operator_\w+\(([^)]*)\)/g)) {
        expect(m[1].replace(/%L(::uuid)?|%s|,|\s/g, ""), r.proname).toBe("");
      }
    }
  });

  it("the startup privilege check: control_app cannot use the bridge, and no control role membership is tolerated any more", async () => {
    expect(privilegeProblems((await db.app.query(PRIVILEGE_CHECK_SQL)).rows[0])).toEqual([]);
    const MEMBER = "a control role has an unexpected role membership";
    const BRIDGE = "role can use the POS network bridge (dblink/foreign server/user mapping): only control_definer may";
    const check = async (grant: string, revoke: string, msg: string) => {
      await db.su.query(grant);
      try { expect(privilegeProblems((await db.app.query(PRIVILEGE_CHECK_SQL)).rows[0]), grant).toContain(msg); }
      finally { await db.su.query(revoke); }
      expect(privilegeProblems((await db.app.query(PRIVILEGE_CHECK_SQL)).rows[0])).toEqual([]);
    };
    // 222's single-database grant is no longer tolerated (the role exists cluster-wide here because of the mock)
    await check("GRANT orvix_recovery_operator TO control_definer WITH INHERIT TRUE, SET FALSE, ADMIN FALSE",
                "REVOKE orvix_recovery_operator FROM control_definer", MEMBER);
    await check("GRANT pg_read_all_data TO control_definer", "REVOKE pg_read_all_data FROM control_definer", MEMBER);
    await check("GRANT orvix_recovery_operator TO control_app", "REVOKE orvix_recovery_operator FROM control_app", MEMBER);
    // the bridge belongs to control_definer only
    await check("GRANT EXECUTE ON FUNCTION control_ext.dblink(text, text) TO control_app",
                "REVOKE EXECUTE ON FUNCTION control_ext.dblink(text, text) FROM control_app", BRIDGE);
    await check("GRANT USAGE ON FOREIGN SERVER orvix_pos_recovery TO control_app",
                "REVOKE USAGE ON FOREIGN SERVER orvix_pos_recovery FROM control_app", BRIDGE);
    await check("CREATE USER MAPPING FOR PUBLIC SERVER orvix_pos_recovery OPTIONS (user 'x', password 'y')",
                "DROP USER MAPPING FOR PUBLIC SERVER orvix_pos_recovery", BRIDGE);
    await check("GRANT EXECUTE ON FUNCTION control_ext.dblink_connect_u(text, text) TO PUBLIC",
                "REVOKE EXECUTE ON FUNCTION control_ext.dblink_connect_u(text, text) FROM PUBLIC", BRIDGE);
  });

  it("the chain verifies after all POS recovery activity", async () => {
    expect(await db.api("api_audit_verify", owner.token)).toMatchObject({ ok: true, intact: true });
    expect(await bare.api("api_audit_verify", bareOwner.token)).toMatchObject({ ok: true, intact: true });
  });
});

// a second-owner fixture keeps the role split visible in reports
describe("role split", () => {
  it("a second owner may reopen, an admin never", async () => {
    const o2 = await operatorFixture(db, "owner", "owner2@example.invalid");
    const auth = authorization("reopen-organization", B, { reopen: { orgId: B, decision: "limited" } });
    expect((await submit(o2, auth, "abcd")).error).toBe("STEPUP_REQUIRED");
    expect((await submit(admin, auth, "abcd")).error).toBe("FORBIDDEN");
  });
});

describe("bridge binding and transport (review 4 H1/H2)", () => {
  it("a restored or copied Control database has no working bridge: the binding names another database", async () => {
    await db.su.query("UPDATE control.pos_bridge_binding SET database_oid = 0");
    try {
      expect(await db.api("api_pos_recovery_overview", owner.token)).toEqual({ ok: false, error: "POS_RECOVERY_UNAVAILABLE" });
      expect((await lastAudit(db))[0].detail.bridge).toBe("not_configured");
    } finally { await withBridge((c) => configurePosBridge(c, pos.settings), async () => undefined); }
    await db.su.query("UPDATE control.pos_bridge_binding SET system_identifier = '0'");
    try {
      expect((await db.api("api_pos_recovery_overview", owner.token)).error).toBe("POS_RECOVERY_UNAVAILABLE");
    } finally { await withBridge((c) => configurePosBridge(c, pos.settings), async () => undefined); }
    expect((await db.api("api_pos_recovery_overview", owner.token)).ok).toBe(true);
  });

  it("TLS is required unless an insecure development bridge was configured explicitly: without TLS the bridge refuses", async () => {
    await db.su.query("UPDATE control.pos_bridge_binding SET tls_required = true");
    try {
      expect(await db.api("api_pos_recovery_overview", owner.token)).toEqual({ ok: false, error: "POS_RECOVERY_UNAVAILABLE" });
      expect((await lastAudit(db))[0].detail.bridge).toBe("tls_required");
    } finally { await db.su.query("UPDATE control.pos_bridge_binding SET tls_required = false"); }
    expect((await db.api("api_pos_recovery_overview", owner.token)).ok).toBe(true);
  });

  it("the host configuration refuses anything but verify-full TLS unless the development flag is set; the binding is not writable by control roles", async () => {
    const env = { ORVIX_POS_BRIDGE_HOST: "pos.example.invalid", ORVIX_POS_BRIDGE_PORT: "5432", ORVIX_POS_BRIDGE_DBNAME: "postgres",
      ORVIX_POS_BRIDGE_USER: "orvix_control_bridge", ORVIX_POS_BRIDGE_PASSWORD: "x".repeat(32) } as unknown as NodeJS.ProcessEnv;
    expect(() => bridgeSettingsFromEnv(env)).toThrow(/verify-full/);
    expect(() => bridgeSettingsFromEnv({ ...env, ORVIX_POS_BRIDGE_SSLMODE: "prefer", ORVIX_POS_BRIDGE_SSLROOTCERT: "/etc/ssl/ca.pem" })).toThrow(/verify-full/);
    expect(bridgeSettingsFromEnv({ ...env, ORVIX_POS_BRIDGE_SSLMODE: "verify-full", ORVIX_POS_BRIDGE_SSLROOTCERT: "/etc/ssl/ca.pem" }).insecureDev).toBe(false);
    expect(bridgeSettingsFromEnv({ ...env, ORVIX_POS_BRIDGE_SSLMODE: "disable", ORVIX_POS_BRIDGE_INSECURE_DEV: "1" }).insecureDev).toBe(true);
    for (const r of ["control_app", "control_definer", "control_auth", "control_audit_owner", "control_sentinel"]) {
      expect((await db.su.query("SELECT has_table_privilege($1, 'control.pos_bridge_binding', 'INSERT,UPDATE,DELETE,TRUNCATE') AS w", [r])).rows[0].w, r).toBe(false);
    }
    expect((await db.su.query("SELECT has_table_privilege('control_app', 'control.pos_bridge_binding', 'SELECT') AS r")).rows[0].r).toBe(false);
  });
});

describe("bridge removal", () => {
  it("removing the bridge (host) closes it at once: unavailable, audited", async () => {
    await withBridge((c) => removePosBridge(c), async () => {
      expect(await db.api("api_pos_recovery_overview", owner.token)).toEqual({ ok: false, error: "POS_RECOVERY_UNAVAILABLE" });
      expect((await lastAudit(db))[0].detail.bridge).toBe("not_configured");
    });
  });
});
