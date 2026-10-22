// Step 5 (222): the POS recovery bridge. Control calls ONLY the POS-owned recovery_v1.operator_* interface (here the
// dev mock db/dev/pos_recovery_mock.sql, checked against docs/pos_recovery_contract.json), through control_definer;
// role + step-up policy, one Control audit row per call in the same transaction, POS_RECOVERY_UNAVAILABLE without the
// hook, never ACTIVE, and no tenant-table access.
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createHash, randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import { PRIVILEGE_CHECK_SQL, privilegeProblems } from "../../src/server/db/privilegeCheck";
import pg from "pg";
import { loadDevEnv, ROOT, superuserConfig } from "../../scripts/env";
import { adminWithSession, createTestDb, installPosRecoveryMock, lastAudit, operatorFixture, ownerWithSession,
         revokePosRecoveryGrant, stepup, type Operator, type TestDb } from "../helpers/db";

type ContractFn = { name: string; identityArguments: string; returns: string; volatility: string; securityDefiner: boolean };
const CONTRACT = JSON.parse(readFileSync(path.join(ROOT, "docs", "pos_recovery_contract.json"), "utf8")) as
  { schema: string; role: string; functions: ContractFn[] };

const A = "org-synthetic-a";   // ACTIVE, owner key scoped to it
const B = "org-synthetic-b";   // RESTRICTED, no owner authority, hard blocker (ledger_in_flight)
const ENR_A = "e1000000-0000-4000-8000-0000000000a1";
const ENR_B = "e1000000-0000-4000-8000-0000000000b1";

let db: TestDb;      // with the POS mock
let bare: TestDb;    // without any POS hook
let owner: Operator;
let admin: Operator;
let bareOwner: Operator;

const sha = (s: string) => createHash("sha256").update(s, "utf8").digest("hex");
const headSeq = async (d: TestDb) => (await d.su.query("SELECT max(seq)::int s FROM control.audit_events")).rows[0].s as number;
const mockState = async (org: string) => (await db.su.query("SELECT state, incident_id::text, recovery_epoch FROM recovery_v1.mock_orgs WHERE org_id = $1", [org])).rows[0];
const enrollment = async (id: string) => (await db.su.query("SELECT state FROM recovery_v1.mock_enrollments WHERE enrollment_id = $1", [id])).rows[0]?.state;
const posAudit = async (org: string) => (await db.su.query("SELECT kind, detail, actor FROM recovery_v1.mock_audit WHERE org_id = $1 ORDER BY id DESC", [org])).rows;
const unusedGrants = async (d: TestDb, action: string) =>
  (await d.su.query("SELECT count(*)::int n FROM control.stepup_grants WHERE action = $1 AND used_at IS NULL", [action])).rows[0].n as number;

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
  // every database first: migration 207 refuses to run while a control role holds a membership (cluster-wide)
  loadDevEnv();
  const su0 = new pg.Pool({ ...superuserConfig(), database: "orvix_control", max: 1 });
  try { await revokePosRecoveryGrant(su0); } finally { await su0.end(); }   // a crashed earlier run may have left it
  bare = await createTestDb({ seed: true });
  db = await createTestDb({ seed: true });
  bareOwner = await ownerWithSession(bare);
  owner = await ownerWithSession(db);
  admin = await adminWithSession(db);
  await installPosRecoveryMock(db);
});
afterAll(async () => {
  if (db) await revokePosRecoveryGrant(db.su);
  await db?.drop();
  await bare?.drop();
});
beforeEach(async () => { await db.su.query("DELETE FROM control.rate_limits"); });

// =====================================================================================================================
describe("contract", () => {
  it("the mock implements exactly the checked-in POS contract (identity arguments, return type, volatility, definer)", async () => {
    const { rows } = await db.su.query(
      `SELECT p.proname AS name, pg_get_function_identity_arguments(p.oid) AS args, format_type(p.prorettype, NULL) AS ret,
              p.provolatile AS vol, p.prosecdef AS def, p.proconfig AS cfg
         FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = $1 AND p.proname LIKE 'operator\\_%' ORDER BY 1`, [CONTRACT.schema]);
    const vol: Record<string, string> = { s: "stable", v: "volatile", i: "immutable" };
    expect(rows.map((r) => ({ name: r.name, identityArguments: r.args, returns: r.ret, volatility: vol[r.vol], securityDefiner: r.def })))
      .toEqual([...CONTRACT.functions].sort((x, y) => x.name.localeCompare(y.name)));
    for (const r of rows) expect((r.cfg ?? []).some((c: string) => c.startsWith("search_path=")), r.name).toBe(true);
  });

  it("migration 222's hook list names the same seven signatures", async () => {
    const { rows } = await db.su.query(
      `SELECT p.proname AS name, pg_get_function_identity_arguments(p.oid) AS args
         FROM unnest(control.pos_recovery_contract()) s JOIN pg_proc p ON p.oid = to_regprocedure(s)::oid ORDER BY 1`);
    expect(rows.map((r) => `${r.name}(${r.args})`)).toEqual(
      [...CONTRACT.functions].sort((x, y) => x.name.localeCompare(y.name)).map((f) => `${f.name}(${f.identityArguments})`));
  });

  it("the POS role is NOLOGIN and is the ONLY grantee of the operator functions; control_app and PUBLIC cannot call them", async () => {
    const role = (await db.su.query("SELECT rolcanlogin, rolsuper, rolinherit FROM pg_roles WHERE rolname = $1", [CONTRACT.role])).rows[0];
    expect(role).toEqual({ rolcanlogin: false, rolsuper: false, rolinherit: false });
    const { rows } = await db.su.query(
      `SELECT p.proname, a.grantee::regrole::text AS grantee FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
         CROSS JOIN LATERAL aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a
        WHERE n.nspname = 'recovery_v1' AND a.privilege_type = 'EXECUTE' AND a.grantee <> p.proowner ORDER BY 1`);
    expect(new Set(rows.map((r) => r.grantee))).toEqual(new Set([CONTRACT.role]));
    expect(rows.map((r) => r.proname).sort()).toEqual(CONTRACT.functions.map((f) => f.name).sort());
    const e = await db.app.query("SELECT recovery_v1.operator_overview()").catch((x) => x);
    expect(e.code).toBe("42501");
  });

  it("the mock POS itself denies ACTIVE and refuses a bad signature", async () => {
    const t = (await db.su.query("SELECT recovery_v1.operator_transition($1, 'ACTIVE', 'reason', 'evidence', 'test') AS r", [B])).rows[0].r;
    expect(t).toEqual({ outcome: "denied", reopen_authorized: false });
    const s = (await db.su.query("SELECT recovery_v1.operator_submit($1, 'bad', 'test') AS r", [authorization("reopen-organization", A)])).rows[0].r;
    expect(s).toMatchObject({ outcome: "refused", purpose: "reopen-organization" });
    expect((await mockState(B)).state).toBe("RESTRICTED");
  });

  it("contract version 0.6; the new step-up actions are accepted, unknown ones still refused", async () => {
    expect((await db.app.query("SELECT control.api_contract_version() AS v")).rows[0].v).toBe("orvix-control/0.6");
    for (const a of ["pos_recovery_transition", "pos_recovery_contain", "pos_recovery_submit"]) {
      expect((await db.api("api_stepup_begin", owner.token, a, `${B}:RECONCILING`)).ok).toBe(true);
    }
    expect((await db.api("api_stepup_begin", owner.token, "pos_recovery_activate", `${B}:ACTIVE`)).error).toBe("INVALID_INPUT");
  });
});

// =====================================================================================================================
describe("hook unavailable", () => {
  it("without recovery_v1: every API returns POS_RECOVERY_UNAVAILABLE, audited, and a step-up grant is not consumed", async () => {
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
    const rows = (await bare.su.query("SELECT action, outcome, reason_code FROM control.audit_events WHERE seq > $1 AND action LIKE 'pos.%' ORDER BY seq", [before])).rows;
    expect(rows).toHaveLength(7);
    for (const r of rows) expect([r.outcome, r.reason_code]).toEqual(["denied", "POS_RECOVERY_UNAVAILABLE"]);
  });

  it("without the POS-owner's grant to control_definer: unavailable (no fallback)", async () => {
    await revokePosRecoveryGrant(db.su);
    try {
      expect(await db.api("api_pos_recovery_overview", owner.token)).toEqual({ ok: false, error: "POS_RECOVERY_UNAVAILABLE" });
    } finally {
      await db.su.query("GRANT orvix_recovery_operator TO control_definer WITH INHERIT TRUE, SET FALSE, ADMIN FALSE");
    }
    expect((await db.api("api_pos_recovery_overview", owner.token)).ok).toBe(true);
  });

  it("all-or-nothing: one missing EXECUTE in the seven makes the whole bridge unavailable", async () => {
    await db.su.query("REVOKE EXECUTE ON FUNCTION recovery_v1.operator_audit(text, integer) FROM orvix_recovery_operator");
    try {
      expect((await db.api("api_pos_recovery_overview", owner.token)).error).toBe("POS_RECOVERY_UNAVAILABLE");
    } finally {
      await db.su.query("GRANT EXECUTE ON FUNCTION recovery_v1.operator_audit(text, integer) TO orvix_recovery_operator");
    }
    // an "operator" function owned by a control role is not the POS's interface
    await db.su.query("ALTER FUNCTION recovery_v1.operator_audit(text, integer) OWNER TO control_definer");
    try {
      expect((await db.api("api_pos_recovery_overview", owner.token)).error).toBe("POS_RECOVERY_UNAVAILABLE");
    } finally {
      await db.su.query("ALTER FUNCTION recovery_v1.operator_audit(text, integer) OWNER TO CURRENT_USER");
      await db.su.query("GRANT EXECUTE ON FUNCTION recovery_v1.operator_audit(text, integer) TO orvix_recovery_operator");
    }
    expect((await db.api("api_pos_recovery_overview", owner.token)).ok).toBe(true);
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
    expect([a.action, a.reason_code, a.detail.pos_error]).toEqual(["pos.recovery_read_refused", "NOT_FOUND", "RECOVERY_V1_OPERATOR_INVALID"]);
    expect(await db.api("api_pos_recovery_org", admin.token, "bad org; drop")).toEqual({ ok: false, error: "INVALID_INPUT" });
    [a] = await lastAudit(db);
    expect([a.action, a.reason_code]).toEqual(["pos.recovery_read_refused", "INVALID_INPUT"]);
  });

  it("audit history and input bounds", async () => {
    const r = await db.api("api_pos_recovery_audit", owner.token, B, 50);
    expect(r.ok).toBe(true);
    expect(Array.isArray(r.events)).toBe(true);
    expect((await db.api("api_pos_recovery_audit", owner.token, B, 0)).error).toBe("INVALID_INPUT");
    expect((await db.api("api_pos_recovery_audit", owner.token, B, 201)).error).toBe("INVALID_INPUT");
  });

  it("no session: refused before anything else", async () => {
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
    expect(p.actor).toBe(`operator:control:admin:${admin.identityId}@control_app`);
    // replay: same result, no second effect, no second audit row; reuse for another organization is a conflict
    const seq = await headSeq(db);
    expect(await transition(admin, B, "RECONCILING", rid)).toEqual({ ...ok, replayed: true });
    expect(await headSeq(db)).toBe(seq);
    expect((await transition(admin, A, "RECONCILING", rid)).error).toBe("REQUEST_ID_CONFLICT");
    expect((await transition(owner, B, "RECONCILING", rid)).error).toBe("REQUEST_ID_CONFLICT");
    expect((await db.api("api_pos_recovery_transition", admin.token, B, "RECONCILING", "x", "y", null)).error).toBe("REQUEST_ID_REQUIRED");
  });

  it("the POS call and the Control audit row commit or roll back together", async () => {
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
    expect((await mockState(B)).state).toBe("RECONCILING");
    expect((await db.su.query("SELECT count(*)::int n FROM control.audit_events WHERE request_id = $1", [rid])).rows[0].n).toBe(0);
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
    expect(r.signingTarget).toMatchObject({ database: db.name });
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
    const posBefore = (await db.su.query("SELECT count(*)::int n FROM recovery_v1.mock_audit")).rows[0].n;
    expect((await submit(owner, "not json", "abcd")).error).toBe("INVALID_INPUT");
    expect((await submit(owner, authorization("migration", A), "abcd")).error).toBe("INVALID_INPUT");
    expect((await submit(owner, authorization("reopen-organization", A), "not-hex")).error).toBe("INVALID_INPUT");
    expect((await submit(owner, authorization("reopen-organization", A), "abc")).error).toBe("INVALID_INPUT");
    expect((await db.su.query("SELECT count(*)::int n FROM recovery_v1.mock_audit")).rows[0].n).toBe(posBefore);
    const [a] = await lastAudit(db);
    expect([a.action, a.reason_code]).toEqual(["pos.recovery_submit_refused", "INVALID_INPUT"]);
  });

  it("a signature the POS verifier refuses: POS_RECOVERY_REFUSED, audited on both sides, nothing changes", async () => {
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
    expect((await posAudit(A))[0]).toMatchObject({ kind: "organization_reopened", actor: `operator:control:owner:${owner.identityId}@control_app` });
    expect(await submit(owner, auth, "ABCDEF0123", rid)).toEqual({ ...r, replayed: true });
  });

  it("device enrollment: an admin may carry it (step-up), the POS decides", async () => {
    const req = randomUUID();
    await db.su.query(`INSERT INTO recovery_v1.mock_requests (request_id, org_id, shop_id, device_id, key_fingerprint, request_nonce, requested_by)
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
});

// =====================================================================================================================
describe("boundaries", () => {
  it("no tenant-table access for control_app or control_definer, even with the POS role", async () => {
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

  it("no control function reads a POS table or sets ACTIVE itself", async () => {
    const { rows } = await db.su.query(
      `SELECT p.proname, p.prosrc FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'control' AND (p.proname LIKE '%pos\\_recovery%')`);
    expect(rows.length).toBeGreaterThanOrEqual(7);
    for (const r of rows) {
      expect(/\b(public|pos_mock)\.\w+/i.test(r.prosrc), r.proname).toBe(false);
      // the only recovery_v1 references are the seven operator functions
      for (const m of r.prosrc.matchAll(/recovery_v1\.(\w+)/g)) expect(m[1], r.proname).toMatch(/^operator_/);
      expect(/state\s*=\s*'ACTIVE'|operator_transition\([^)]*'ACTIVE'/i.test(r.prosrc), r.proname).toBe(false);
    }
  });

  it("the startup privilege check tolerates ONLY the inherit-only POS role membership", async () => {
    expect(privilegeProblems((await db.app.query(PRIVILEGE_CHECK_SQL)).rows[0])).toEqual([]);
    const MSG = "a control role has an unexpected role membership (only orvix_recovery_operator -> control_definer, inherit-only, is tolerated)";
    const check = async (grant: string, revoke: string) => {
      await db.su.query(grant);
      try { expect(privilegeProblems((await db.app.query(PRIVILEGE_CHECK_SQL)).rows[0])).toContain(MSG); }
      finally { await db.su.query(revoke); }
      expect(privilegeProblems((await db.app.query(PRIVILEGE_CHECK_SQL)).rows[0])).toEqual([]);
    };
    // SET ROLE allowed on the POS role
    await check("GRANT orvix_recovery_operator TO control_definer WITH SET TRUE",
                "GRANT orvix_recovery_operator TO control_definer WITH SET FALSE");
    // the POS role itself inherits something more
    await check("GRANT pg_read_all_data TO orvix_recovery_operator", "REVOKE pg_read_all_data FROM orvix_recovery_operator");
    // any other membership of a control role
    await check("GRANT pg_read_all_data TO control_definer", "REVOKE pg_read_all_data FROM control_definer");
    await check("GRANT orvix_recovery_operator TO control_app", "REVOKE orvix_recovery_operator FROM control_app");
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
