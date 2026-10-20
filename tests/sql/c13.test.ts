// Phase C1.3: watchdog intent protocol (W-1), recovery/auth hardening (M1, M2 + LOWs), database-privilege
// preconditions (M3, M4), sentinel delivery isolation, durability and status (M5-M7 + LOWs), tenant replay isolation.
// Crash injection that kills PostgreSQL processes lives in tests/crash (it restarts the whole cluster).
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { linkSync, mkdirSync, mkdtempSync, readFileSync, symlinkSync, writeFileSync } from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import pg from "pg";
import { appConfig, sentinelConfig, superuserConfig } from "../../scripts/env";
import { enforceDatabaseAcl, migrate } from "../../scripts/migrator";
import { DeliveryWorkers, ackWebhook, appendVerified, deliverOnce, watchdogOnce } from "../../scripts/sentinel";
import { PRIVILEGE_CHECK_SQL, privilegeProblems } from "../../src/server/db/privilegeCheck";
import {
  createTestDb, deliverAll, enrolWithToken, lastAudit, login, operatorFixture, ownerWithSession, resetRateLimits, stepup,
  type Operator, type TestDb,
} from "../helpers/db";
import { SoftAuthenticator } from "../helpers/softAuthenticator";

const sha = (s: string) => createHash("sha256").update(s).digest("hex");
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const sentinelPool = (db: TestDb, max = 3) => new pg.Pool({ ...sentinelConfig(), database: db.name, max });
const errCode = (p: Promise<unknown>) => p.then(() => "OK", (e: { code?: string }) => e.code);
const one = async (db: TestDb, sql: string, p: unknown[] = []) => (await db.su.query(sql, p)).rows[0];

async function staleAppSession(db: TestDb) {
  const c = new pg.Client({ ...appConfig(), database: db.name });
  c.on("error", () => {});
  await c.connect();
  await c.query("SET idle_in_transaction_session_timeout = 0; SET transaction_timeout = 0");
  await c.query("BEGIN"); await c.query("SELECT control.api_contract_version()");
  const pid = (await c.query("SELECT pg_backend_pid() AS p")).rows[0].p as number;
  return { c, pid };
}
const alive = async (db: TestDb, pid: number) => !!(await one(db, "SELECT 1 AS x FROM pg_stat_activity WHERE pid = $1", [pid]));
async function invite(db: TestDb, owner: Operator, email: string, role: "owner" | "admin") {
  await stepup(db, owner.token, owner.auth, "operator_invite", `${role}:${sha(email.toLowerCase())}`);
  return db.api("api_operator_invite", owner.token, email, email.split("@")[0], role);
}

// =====================================================================================================================
describe("W-1 watchdog intent protocol (non-crash boundaries; crash boundaries: tests/crash)", () => {
  let db: TestDb; let sp: pg.Pool;
  beforeAll(async () => { db = await createTestDb({ seed: false }); await ownerWithSession(db); sp = sentinelPool(db); });
  afterAll(async () => { await sp?.end(); await db?.drop(); });

  it("happy path: PLAN commits an intent + notice BEFORE the kill; EXECUTE terminates; RECONCILE folds into the chain", async () => {
    const v = await staleAppSession(db);
    await sleep(2500);
    const ids = (await sp.query("SELECT control.watchdog_plan(2, 15) AS ids")).rows[0].ids as string[];
    expect(ids).toHaveLength(1);
    expect(await one(db, "SELECT state, target_pid FROM control.watchdog_intents WHERE id = $1", [ids[0]])).toEqual({ state: "planned", target_pid: v.pid });
    expect((await one(db, "SELECT count(*)::int n FROM control.notify_outbox WHERE action = 'platform.watchdog_intent' AND target_id = $1", [ids[0]])).n).toBe(1);
    expect(await alive(db, v.pid)).toBe(true);                                   // nothing terminated by PLAN
    expect((await sp.query("SELECT control.watchdog_arm($1) AS a", [ids[0]])).rows[0].a).toBe(true);
    expect(await alive(db, v.pid)).toBe(true);                                   // nothing terminated by ARM
    expect((await sp.query("SELECT control.watchdog_execute($1) AS r", [ids[0]])).rows[0].r).toBe("terminated");
    await sleep(300);
    expect(await alive(db, v.pid)).toBe(false);
    await sp.query("SELECT control.watchdog_reconcile(10)");
    const i = await one(db, "SELECT state, audit_seq FROM control.watchdog_intents WHERE id = $1", [ids[0]]);
    expect(i.state).toBe("terminated"); expect(i.audit_seq).not.toBeNull();
    const ev = (await lastAudit(db, 5)).find((e) => e.action === "platform.watchdog_terminated");
    expect(ev?.detail).toMatchObject({ intent: Number(ids[0]), pid: v.pid, state: "terminated" });
  }, 20_000);

  it("EXECUTE without a committed ARMED intent never terminates (persistence failure prevents termination)", async () => {
    const v = await staleAppSession(db);
    await sleep(2500);
    const id = (await sp.query("SELECT control.watchdog_plan(2, 15) AS ids")).rows[0].ids[0];
    expect((await sp.query("SELECT control.watchdog_execute($1) AS r", [id])).rows[0].r).toBe("not_armed");   // planned, not armed
    expect((await sp.query("SELECT control.watchdog_execute(999999999) AS r")).rows[0].r).toBe("not_armed"); // no intent at all
    expect(await alive(db, v.pid)).toBe(true);
    // an EXECUTE attempt inside a transaction that cannot commit the ARM first: armed only in an aborted txn
    const c = await sp.connect();
    try {
      await c.query("BEGIN"); await c.query("SELECT control.watchdog_arm($1)", [id]); await c.query("ROLLBACK");
    } finally { c.release(); }
    expect((await sp.query("SELECT control.watchdog_execute($1) AS r", [id])).rows[0].r).toBe("not_armed");
    expect(await alive(db, v.pid)).toBe(true);
    await v.c.end();
  }, 20_000);

  it("a target whose transaction changed is never terminated (no silent kill of an unrelated transaction)", async () => {
    const v = await staleAppSession(db);
    await sleep(2500);
    const id = (await sp.query("SELECT control.watchdog_plan(2, 15) AS ids")).rows[0].ids[0];
    expect((await sp.query("SELECT control.watchdog_arm($1) AS a", [id])).rows[0].a).toBe(true);
    await v.c.query("COMMIT"); await v.c.query("BEGIN"); await v.c.query("SELECT 1");     // same pid, NEW transaction
    expect((await sp.query("SELECT control.watchdog_execute($1) AS r", [id])).rows[0].r).toBe("skipped");
    expect(await alive(db, v.pid)).toBe(true);
    await v.c.end();
  }, 20_000);

  it("an interrupted intent (sentinel gone after PLAN or ARM) is resolved by RECONCILE and never re-executed", async () => {
    const v1 = await staleAppSession(db); const v2 = await staleAppSession(db);
    await sleep(2500);
    const ids = (await sp.query("SELECT control.watchdog_plan(2, 15) AS ids")).rows[0].ids as string[];
    expect(ids).toHaveLength(2);
    // plan order follows pg_stat_activity, not session creation: pick the intents by target
    const byPid = new Map((await db.su.query("SELECT id::text, target_pid FROM control.watchdog_intents WHERE id = ANY($1)", [ids])).rows
      .map((r) => [r.target_pid as number, r.id as string]));
    const planned = byPid.get(v1.pid)!, armed = byPid.get(v2.pid)!;
    await sp.query("SELECT control.watchdog_arm($1)", [armed]);
    // "crash": the sentinel stops here. Age the intents past the 10 s staleness threshold.
    await db.su.query("UPDATE control.watchdog_intents SET state_at = state_at - interval '1 minute' WHERE id = ANY($1)", [ids]);
    await v2.c.end();                                                            // armed target has gone meanwhile
    await sleep(300);
    await sp.query("SELECT control.watchdog_reconcile(10)");
    const st = (await db.su.query("SELECT id::text, state, audit_seq IS NOT NULL AS chained FROM control.watchdog_intents WHERE id = ANY($1) ORDER BY id", [ids])).rows;
    expect(st).toEqual(expect.arrayContaining([{ id: planned, state: "abandoned", chained: true }, { id: armed, state: "terminated_unconfirmed", chained: true }]));
    expect(await alive(db, v1.pid)).toBe(true);                                  // the planned one was not acted on
    expect((await sp.query("SELECT control.watchdog_execute($1) AS r", [planned])).rows[0].r).toBe("not_armed");
    const resolved = (await db.su.query("SELECT target_id, action, reason_code FROM control.audit_events WHERE target_type = 'watchdog_intent' AND target_id = ANY($1)", [ids])).rows;
    expect(resolved).toEqual(expect.arrayContaining([{ target_id: planned, action: "platform.watchdog_intent_resolved", reason_code: "ABANDONED" },
                                                     { target_id: armed, action: "platform.watchdog_terminated", reason_code: "TERMINATED_UNCONFIRMED" }]));
    await v1.c.end();
  }, 20_000);

  it("two watchdogs cannot both act on one target; intents can only move forward (no edit, no delete)", async () => {
    const v = await staleAppSession(db);
    await sleep(2500);
    const sp2 = sentinelPool(db, 1);
    try {
      const [a, b] = await Promise.all([sp.query("SELECT control.watchdog_plan(2, 15) AS ids"), sp2.query("SELECT control.watchdog_plan(2, 15) AS ids")]);
      const all = [...a.rows[0].ids, ...b.rows[0].ids];
      expect(all).toHaveLength(1);
      const id = all[0];
      const arms = await Promise.all([sp.query("SELECT control.watchdog_arm($1) AS a", [id]), sp2.query("SELECT control.watchdog_arm($1) AS a", [id])]);
      expect(arms.filter((r) => r.rows[0].a === true)).toHaveLength(1);
      expect(await errCode(db.su.query("UPDATE control.watchdog_intents SET state = 'planned' WHERE id = $1", [id]))).toBe("42501");
      expect(await errCode(db.su.query("UPDATE control.watchdog_intents SET target_pid = 1 WHERE id = $1", [id]))).toBe("42501");
      expect(await errCode(db.su.query("DELETE FROM control.watchdog_intents WHERE id = $1", [id]))).toBe("42501");
      await sp.query("SELECT control.watchdog_execute($1)", [id]);
    } finally { await sp2.end(); try { await v.c.end(); } catch { /* terminated */ } }
  }, 20_000);

  it("the console credential cannot reach the protocol; the sentinel cannot terminate non-control_app sessions", async () => {
    for (const sql of ["SELECT control.watchdog_plan(2, 15)", "SELECT control.watchdog_arm(1)", "SELECT control.watchdog_execute(1)",
      "SELECT control.watchdog_reconcile(10)", "SELECT * FROM control.watchdog_intents", "SELECT control.watchdog_intent_insert(1, now(), now(), 'successor')"]) {
      expect(await errCode(db.app.query(sql)), sql).toBe("42501");
    }
    expect(await errCode(sp.query("SELECT control.watchdog_intent_insert(1, now(), now(), 'successor')"))).toBe("42501");
    expect(await errCode(sp.query("SELECT control.watchdog_intent_transition(1, 'planned', 'armed')"))).toBe("42501");
    const su = await db.su.connect();
    try {
      await su.query("BEGIN"); await su.query("SELECT 1");
      await sleep(2500);
      expect((await sp.query("SELECT control.watchdog_plan(2, 2) AS ids")).rows[0].ids).toEqual([]);
      await su.query("ROLLBACK");
    } finally { su.release(); }
  }, 20_000);

  it("the full sentinel pass (watchdogOnce) terminates, records and folds; host status shows watchdog health", async () => {
    const v = await staleAppSession(db);
    await sleep(2500);
    expect(await watchdogOnce(sp, 2, 15)).toBe(1);
    const st = (await one(db, "SELECT control.host_notify_status() AS r")).r;
    expect(st.watchdog).toMatchObject({ open_intents: 0, interrupted_intents: 0, not_in_chain: 0 });
    expect(st.sentinel.watchdog_state).toBe("up");
    try { await v.c.end(); } catch { /* terminated */ }
  }, 20_000);
});

// =====================================================================================================================
describe("M1/M2 + recovery LOWs", () => {
  it("M1: recovery voids the invitations the old credential issued and the recovery links it approved", async () => {
    const d = await createTestDb({ seed: false });
    try {
      const o1 = await ownerWithSession(d, "o1@example.invalid");                    // o1's passkey is in a thief's hands
      const o2 = await operatorFixture(d, "owner", "o2@example.invalid");
      await operatorFixture(d, "owner", "o3@example.invalid");
      await d.su.query("UPDATE control.webauthn_credentials SET last_used_at = now() - interval '1 day'");
      const inv = await invite(d, o1, "accomplice@example.invalid", "owner");     // thief invites an accomplice
      expect(inv.ok).toBe(true);
      const acc = new SoftAuthenticator();
      const ae = await enrolWithToken(d, inv.enrolment_token, acc);
      const rq3 = (await one(d, "SELECT control.host_recovery_request('o3@example.invalid', 'o3 lost device synthetic') AS r")).r;
      await stepup(d, o1.token, o1.auth, "recovery_approve", rq3.request_id);
      const thiefLink = await d.api("api_recovery_approve", o1.token, rq3.request_id); // thief approves o3's recovery
      expect(thiefLink.ok).toBe(true);
      // the real o1 recovers through o2 (the ordinary path, not a host emergency revoke)
      await d.su.query("UPDATE control.webauthn_credentials SET last_used_at = now() - interval '1 day' WHERE identity_id = $1", [o1.identityId]);
      const rq1 = (await one(d, "SELECT control.host_recovery_request('o1@example.invalid', 'o1 laptop stolen synthetic') AS r")).r;
      await stepup(d, o2.token, o2.auth, "recovery_approve", rq1.request_id);
      const ok1 = await d.api("api_recovery_approve", o2.token, rq1.request_id);
      expect(ok1.ok).toBe(true);
      const red = await enrolWithToken(d, ok1.enrolment_token, new SoftAuthenticator());
      expect(red).toMatchObject({ ok: true, purpose: "recovery" });
      expect(red.device_token).toMatch(/^[0-9a-f]{64}$/);                            // M2
      await deliverAll(d);
      expect((await one(d, "SELECT control.host_approve_operator('accomplice@example.invalid', $1) AS r", [ae.fingerprint])).r.error).toBe("NOT_FOUND");
      expect((await enrolWithToken(d, thiefLink.enrolment_token, new SoftAuthenticator())).error).toBe("INVALID_TOKEN");
      expect((await one(d, "SELECT state FROM control.recovery_requests WHERE id = $1", [rq3.request_id])).state).toBe("pending");
      const rows = (await d.su.query(`SELECT action, reason_code FROM control.audit_events
                                       WHERE action IN ('platform.operator_invite_revoked', 'platform.recovery_link_voided') ORDER BY seq`)).rows;
      expect(rows).toEqual([{ action: "platform.recovery_link_voided", reason_code: "APPROVER_RECOVERED" },
                            { action: "platform.operator_invite_revoked", reason_code: "INVITER_RECOVERED" }]);
      expect((await one(d, "SELECT recovered_at IS NOT NULL AS r FROM control.platform_identities WHERE id = $1", [o1.identityId])).r).toBe(true);
    } finally { await d.drop(); }
  });

  it("M2: a recovered owner signs in on the recovery browser even while the anonymous bucket is exhausted", async () => {
    const d = await createTestDb({ seed: false });
    try {
      await ownerWithSession(d, "a@example.invalid");
      const b = await operatorFixture(d, "owner", "b@example.invalid");
      await d.su.query("UPDATE control.webauthn_credentials SET last_used_at = now() - interval '1 day'");
      const rq = (await one(d, "SELECT control.host_recovery_request('a@example.invalid', 'lost device synthetic') AS r")).r;
      await stepup(d, b.token, b.auth, "recovery_approve", rq.request_id);
      const ap = await d.api("api_recovery_approve", b.token, rq.request_id);
      const k = new SoftAuthenticator();
      const red = await enrolWithToken(d, ap.enrolment_token, k);
      await resetRateLimits(d);
      for (let i = 0; i < 25; i++) await d.api("api_login_begin", null);       // flood: anonymous bucket exhausted
      expect((await d.api("api_login_begin", null)).error).toBe("RATE_LIMITED");
      const lb = await d.api("api_login_begin", red.device_token);
      expect(lb).toMatchObject({ ok: true, scope: "device" });
      const l = await login(d, k, {}, red.device_token);
      expect(l.ok).toBe(true);
    } finally { await d.drop(); }
  });

  it("an emergency revoke contests recovery no matter how old it is (no 24 h window)", async () => {
    const d = await createTestDb({ seed: false });
    try {
      await ownerWithSession(d, "v@example.invalid");
      const b = await operatorFixture(d, "owner", "b@example.invalid");
      await operatorFixture(d, "owner", "c@example.invalid");
      expect((await one(d, "SELECT control.host_revoke_operator_credentials('v@example.invalid', 'stolen device synthetic') AS r")).r.ok).toBe(true);
      await d.su.query("UPDATE control.platform_identities SET emergency_revoked_at = emergency_revoked_at - interval '25 hours' WHERE email = 'v@example.invalid'");
      const rq = (await one(d, "SELECT control.host_recovery_request('v@example.invalid', 'filed 25 h after the revoke') AS r")).r;
      await stepup(d, b.token, b.auth, "recovery_approve", rq.request_id);
      expect((await d.api("api_recovery_approve", b.token, rq.request_id)).error).toBe("RECOVERY_CONTESTED");
    } finally { await d.drop(); }
  });

  it("subject activity after the approval makes redemption refuse and reopens the request as contested", async () => {
    const d = await createTestDb({ seed: false });
    try {
      const a = await ownerWithSession(d, "a@example.invalid");
      const b = await operatorFixture(d, "owner", "b@example.invalid");
      await d.su.query("UPDATE control.webauthn_credentials SET last_used_at = now() - interval '1 day'");
      const rq = (await one(d, "SELECT control.host_recovery_request('a@example.invalid', 'maybe lost synthetic') AS r")).r;
      await stepup(d, b.token, b.auth, "recovery_approve", rq.request_id);
      const ap = await d.api("api_recovery_approve", b.token, rq.request_id);
      await resetRateLimits(d);
      expect((await login(d, a.auth)).ok).toBe(true);                               // the subject still has the passkey
      expect((await enrolWithToken(d, ap.enrolment_token, new SoftAuthenticator())).error).toBe("RECOVERY_CONTESTED");
      expect(await one(d, "SELECT state, approved_at FROM control.recovery_requests WHERE id = $1", [rq.request_id])).toEqual({ state: "pending", approved_at: null });
      expect((await enrolWithToken(d, ap.enrolment_token, new SoftAuthenticator())).error).toBe("INVALID_TOKEN");
      expect((await lastAudit(d, 10)).some((e) => e.action === "platform.recovery_contested" && e.reason_code === "SUBJECT_ACTIVITY_AFTER_APPROVAL")).toBe(true);
    } finally { await d.drop(); }
  });

  it("an owner under recovery cannot approve, cancel others' requests or invite; their own contest still works", async () => {
    const d = await createTestDb({ seed: false });
    try {
      const a = await ownerWithSession(d, "a@example.invalid");
      await operatorFixture(d, "owner", "b@example.invalid");
      await operatorFixture(d, "owner", "c@example.invalid");
      const ra = (await one(d, "SELECT control.host_recovery_request('a@example.invalid', 'a is under recovery') AS r")).r;
      const rb = (await one(d, "SELECT control.host_recovery_request('b@example.invalid', 'b is under recovery') AS r")).r;
      await stepup(d, a.token, a.auth, "recovery_approve", rb.request_id);
      expect((await d.api("api_recovery_approve", a.token, rb.request_id)).error).toBe("IDENTITY_UNDER_RECOVERY");
      await stepup(d, a.token, a.auth, "recovery_cancel", rb.request_id);
      expect((await d.api("api_recovery_cancel", a.token, rb.request_id)).error).toBe("IDENTITY_UNDER_RECOVERY");
      expect((await invite(d, a, "x@example.invalid", "admin")).error).toBe("IDENTITY_UNDER_RECOVERY");
      await stepup(d, a.token, a.auth, "recovery_cancel", ra.request_id);
      expect(await d.api("api_recovery_cancel", a.token, ra.request_id)).toMatchObject({ ok: true, contested: true });
    } finally { await d.drop(); }
  });

  it("expired requests cancelled by a new request are audited; host revoke audits each voided link", async () => {
    const d = await createTestDb({ seed: false });
    try {
      await ownerWithSession(d, "a@example.invalid");
      const b = await operatorFixture(d, "owner", "b@example.invalid");
      await operatorFixture(d, "owner", "c@example.invalid");
      const r1 = (await one(d, "SELECT control.host_recovery_request('a@example.invalid', 'first request synthetic') AS r")).r;
      await d.su.query("UPDATE control.recovery_requests SET expires_at = now() - interval '1 second' WHERE id = $1", [r1.request_id]);
      await one(d, "SELECT control.host_recovery_request('a@example.invalid', 'second request synthetic') AS r");
      expect(await one(d, "SELECT reason_code, detail->>'subject' AS s FROM control.audit_events WHERE action = 'platform.recovery_cancelled' AND target_id = $1", [r1.request_id]))
        .toEqual({ reason_code: "EXPIRED", s: expect.any(String) });
      const r2 = (await one(d, "SELECT id FROM control.recovery_requests WHERE state = 'pending' ORDER BY requested_at DESC LIMIT 1")).id;
      await d.su.query("UPDATE control.webauthn_credentials SET last_used_at = now() - interval '1 day'");
      await stepup(d, b.token, b.auth, "recovery_approve", r2);
      expect((await d.api("api_recovery_approve", b.token, r2)).ok).toBe(true);
      await one(d, "SELECT control.host_revoke_operator_credentials('b@example.invalid', 'b device stolen synthetic') AS r");
      expect(await one(d, "SELECT reason_code FROM control.audit_events WHERE action = 'platform.recovery_link_voided' AND target_id = $1", [r2]))
        .toEqual({ reason_code: "APPROVER_REVOKED" });
    } finally { await d.drop(); }
  });

  it("a suspended (emergency-revoked) owner is listed as suspended and no longer receives owner notices", async () => {
    const d = await createTestDb({ seed: false, notify: false });
    try {
      const a = await ownerWithSession(d, "a@example.invalid");
      await operatorFixture(d, "owner", "b@example.invalid");
      await d.su.query("SELECT control.host_add_notify_channel('host', NULL, 'file', '/tmp/x-host.jsonl', NULL)");
      const ch = (await one(d, "SELECT control.host_add_notify_channel('identity', 'b@example.invalid', 'file', '/tmp/x-b.jsonl', NULL) AS r")).r.channel_id;
      await one(d, "SELECT control.host_revoke_operator_credentials('b@example.invalid', 'b suspended synthetic') AS r");
      expect((await d.api("api_operator_list", a.token)).operators.find((o: { email: string }) => o.email === "b@example.invalid").state).toBe("suspended");
      await one(d, "SELECT control.host_recovery_request('a@example.invalid', 'notice recipient test') AS r");
      const n = await one(d, `SELECT count(*)::int n FROM control.notify_deliveries d JOIN control.notify_outbox o ON o.id = d.outbox_id
                               WHERE d.channel_id = $1 AND o.action = 'platform.recovery_requested'`, [ch]);
      expect(n.n).toBe(0);
    } finally { await d.drop(); }
  });

  it("a host-disabled channel stops blocking the gate (a host channel must still have delivered)", async () => {
    const d = await createTestDb({ seed: false, notify: false });
    try {
      const a = await ownerWithSession(d, "a@example.invalid");
      const b = await operatorFixture(d, "owner", "b@example.invalid");
      await d.su.query("SELECT control.host_add_notify_channel('host', NULL, 'file', '/tmp/y-host.jsonl', NULL)");
      const dead = (await one(d, "SELECT control.host_add_notify_channel('identity', 'b@example.invalid', 'webhook', 'http://127.0.0.1:9/never', $1) AS r", [randomBytes(32).toString("hex")])).r.channel_id;
      await d.su.query("UPDATE control.webauthn_credentials SET last_used_at = now() - interval '1 day'");
      const rq = (await one(d, "SELECT control.host_recovery_request('a@example.invalid', 'gate waiver synthetic') AS r")).r;
      await stepup(d, b.token, b.auth, "recovery_approve", rq.request_id);
      const ap = await d.api("api_recovery_approve", b.token, rq.request_id);
      const sp = sentinelPool(d);
      try {
        const rows = (await sp.query("SELECT * FROM control.sentinel_claim(100, NULL)")).rows;
        for (const r of rows) await sp.query("SELECT control.sentinel_ack($1, $2, $3, $4, NULL)", [r.outbox_id, r.channel_id, r.claim_token, String(r.channel_id) !== String(dead)]);
      } finally { await sp.end(); }
      const k = new SoftAuthenticator();
      expect((await enrolWithToken(d, ap.enrolment_token, k, "x", { deliver: false })).error).toBe("NOTIFICATION_PENDING");
      await d.su.query("SELECT control.host_disable_notify_channel($1)", [dead]);
      expect((await enrolWithToken(d, ap.enrolment_token, k, "x", { deliver: false })).ok).toBe(true);
      void a;
    } finally { await d.drop(); }
  });
});

// =====================================================================================================================
describe("M3/M4 database privileges and restore", () => {
  it("the control roles cannot reach postgres or template1 (pg_hba reject + PUBLIC CONNECT revoked)", async () => {
    for (const cfg of [appConfig(), sentinelConfig()]) {
      for (const database of ["postgres", "template1"]) {
        const c = new pg.Client({ ...cfg, database });
        const e = await c.connect().then(() => null, (x: { code?: string }) => x.code);
        await c.end().catch(() => {});
        expect(e, `${cfg.user}@${database}`).toBe("28000");                       // invalid_authorization_specification
      }
    }
  });

  it("the shared privilege check passes on a migrated database for both roles", async () => {
    const d = await createTestDb({ seed: false });
    const sp = sentinelPool(d, 1);
    try {
      expect(privilegeProblems((await d.app.query(PRIVILEGE_CHECK_SQL)).rows[0])).toEqual([]);
      expect(privilegeProblems((await sp.query(PRIVILEGE_CHECK_SQL)).rows[0])).toEqual([]);
    } finally { await sp.end(); await d.drop(); }
  });

  it("RESTORE: a dump restored into a plain database is REFUSED by the startup check until the next migrate fixes the ACL", async () => {
    const d = await createTestDb({ seed: true });
    const restored = `orvix_control_test_${randomBytes(5).toString("hex")}`;
    const dir = mkdtempSync(path.join(os.tmpdir(), "orvix-c13-dump-"));
    try {
      const dump = execFileSync("docker", ["exec", "orvix-control-db", "pg_dump", "-U", "orvix_control_super", "-Fc", d.name], { maxBuffer: 64 << 20 });
      writeFileSync(path.join(dir, "d.dump"), dump);
      const admin = new pg.Client({ ...superuserConfig(), database: "orvix_control" }); await admin.connect();
      await admin.query(`CREATE DATABASE ${restored}`); await admin.end();
      execFileSync("docker", ["exec", "-i", "orvix-control-db", "pg_restore", "-U", "orvix_control_super", "-d", restored], { input: dump });
      const app = new pg.Client({ ...appConfig(), database: restored }); await app.connect();
      const before = privilegeProblems((await app.query(PRIVILEGE_CHECK_SQL)).rows[0]);
      expect(before).toEqual(expect.arrayContaining(["role has TEMP on the control database", "control database ACL grants CONNECT/TEMP to PUBLIC"]));
      await app.end();
      const m = new pg.Client({ ...superuserConfig(), database: restored }); await m.connect();
      expect((await migrate(m)).applied).toEqual([]);                               // nothing pending, ACL re-asserted anyway
      await m.end();
      const app2 = new pg.Client({ ...appConfig(), database: restored }); await app2.connect();
      expect(privilegeProblems((await app2.query(PRIVILEGE_CHECK_SQL)).rows[0])).toEqual([]);
      expect(await errCode(app2.query("CREATE TEMP TABLE t (x int)"))).toBe("42501");
      await app2.end();
      void enforceDatabaseAcl;
    } finally {
      const admin = new pg.Client({ ...superuserConfig(), database: "orvix_control" }); await admin.connect();
      await admin.query(`DROP DATABASE IF EXISTS ${restored} WITH (FORCE)`); await admin.end();
      await d.drop();
    }
  }, 60_000);
});

// =====================================================================================================================
describe("M5 file-notice durability", () => {
  const dir = mkdtempSync(path.join(os.tmpdir(), "orvix-c13-file-"));
  it("a complete write is fsync'ed and verified; each notice is framed by newlines", async () => {
    const f = path.join(dir, "ok.jsonl");
    expect(await appendVerified(f, JSON.stringify({ a: 1 }))).toBeNull();
    expect(await appendVerified(f, JSON.stringify({ a: 2 }))).toBeNull();
    expect(readFileSync(f, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l))).toEqual([{ a: 1 }, { a: 2 }]);
  });
  it("a SHORT WRITE (file size limit, as on a full disk) is never acknowledged; the next notice still parses", async () => {
    const f = path.join(dir, "short.jsonl");
    writeFileSync(f, "x".repeat(300));
    const big = JSON.stringify({ notice_id: 1, pad: "y".repeat(400) });
    const code = `import("${path.resolve("scripts/sentinel.ts").replace(/\\/g, "/")}").then(async m => { process.stdout.write(String(await m.appendVerified(${JSON.stringify(f)}, ${JSON.stringify(big)}))); })`;
    const r = spawnSync("prlimit", ["--fsize=512", process.execPath, "--import", "tsx", "-e", code], { encoding: "utf8" });
    expect(r.stdout).toMatch(/^(EFBIG|ENOSPC|short write)/);                       // torn write => NOT acknowledged
    expect(await appendVerified(f, JSON.stringify({ notice_id: 2 }))).toBeNull();
    const lines = readFileSync(f, "utf8").split("\n");
    expect(JSON.parse(lines.at(-2)!)).toEqual({ notice_id: 2 });                  // never glued to the torn line
  });
  it("hard links, FIFOs, non-regular files, symlinked parents and writable directories are refused", async () => {
    const victim = path.join(dir, "victim.conf"); writeFileSync(victim, "x");
    const hard = path.join(dir, "hard.jsonl"); linkSync(victim, hard);
    expect(await appendVerified(hard, "{}")).toMatch(/more than one link/);
    const fifo = path.join(dir, "fifo"); execFileSync("mkfifo", [fifo]);
    expect(await appendVerified(fifo, "{}")).toMatch(/regular file/);
    const real = path.join(dir, "real"); mkdirSync(real); const link = path.join(dir, "linkdir"); symlinkSync(real, link);
    expect(await appendVerified(path.join(link, "n.jsonl"), "{}")).toMatch(/symlink/);
    expect(await appendVerified("relative.jsonl", "{}")).toMatch(/absolute/);
    expect(readFileSync(victim, "utf8")).toBe("x");
    const open = path.join(dir, "open"); mkdirSync(open, { mode: 0o777 }); execFileSync("chmod", ["0777", open]);
    expect(await appendVerified(path.join(open, "n.jsonl"), "{}")).toMatch(/group\/world writable/);
  });
  it("concurrent appenders do not turn verified writes into failures (read-back searches the appended region)", async () => {
    const f = path.join(dir, "busy.jsonl");
    const res = await Promise.all(Array.from({ length: 200 }, (_, i) => appendVerified(f, JSON.stringify({ notice_id: i }))));
    expect(res.filter((r) => r !== null)).toEqual([]);
    const ids = readFileSync(f, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l).notice_id).sort((a: number, b: number) => a - b);
    expect(ids).toEqual(Array.from({ length: 200 }, (_, i) => i));
  });
});

// =====================================================================================================================
describe("M6/M7 + sentinel LOWs: per-channel isolation, claim tokens, truthful status", () => {
  it("a black-holed webhook does not delay the file channel; status reports the stalled channel", async () => {
    const hole = http.createServer(() => { /* accept, never answer */ });
    await new Promise<void>((r) => hole.listen(0, "127.0.0.1", r));
    const port = (hole.address() as { port: number }).port;
    const d = await createTestDb({ seed: false, notify: false });
    const dir = mkdtempSync(path.join(os.tmpdir(), "orvix-c13-iso-"));
    const file = path.join(dir, "host.jsonl");
    const sp = sentinelPool(d, 4);
    try {
      await d.su.query("SELECT control.host_add_notify_channel('host', NULL, 'file', $1, NULL)", [file]);
      await d.su.query("SELECT control.host_add_notify_channel('host', NULL, 'webhook', $1, $2)", [`http://127.0.0.1:${port}/h`, randomBytes(32).toString("hex")]);
      await ownerWithSession(d, "a@example.invalid");
      for (let i = 0; i < 12; i++) await d.su.query("SELECT control.audit_append('cli', NULL, 'x', 'platform.recovery_requested', 'success')");
      const w = new DeliveryWorkers(sp);
      const t0 = Date.now();
      await w.tick();
      const fresh = async () => readFileSync(file, "utf8").split("\n").filter(Boolean).length;
      await sleep(200);
      await d.su.query("SELECT control.audit_append('cli', NULL, 'x', 'platform.recovery_cancelled', 'success')");
      let got = -1;
      for (let i = 0; i < 40 && got < 0; i++) {
        await w.tick(); await sleep(250);
        const lines = readFileSync(file, "utf8").split("\n").filter(Boolean).map((l) => JSON.parse(l));
        if (lines.some((l) => l.action === "platform.recovery_cancelled")) got = Date.now() - t0;
      }
      expect(got).toBeGreaterThan(0);
      expect(got).toBeLessThan(6000);                                                // C1.2: 145 s behind a black hole
      expect(await fresh()).toBeGreaterThan(12);
      const st = (await one(d, "SELECT control.host_notify_status() AS r")).r;
      const web = st.channels.find((c: { kind: string }) => c.kind === "webhook");
      expect(["busy", "retrying"]).toContain(web.state);
      expect(st.channels.find((c: { kind: string }) => c.kind === "file").state).toBe("healthy");
      // the outbox is append-only (even created_at cannot be backdated): wait for real until the oldest notice is > 60 s old
      for (let i = 0; i < 70; i++) { await w.tick(); await sleep(1000); }
      await sp.query("SELECT control.watchdog_reconcile(10)");                       // watchdog heartbeat (else: watchdog_down)
      const st2 = (await one(d, "SELECT control.host_notify_status() AS r")).r;
      expect(st2.channels.find((c: { kind: string }) => c.kind === "webhook").state).toMatch(/failing|delayed/);
      expect(st2.state).toMatch(/failing|delayed/);
    } finally { await sp.end(); await d.drop(); hole.close(); }
  }, 150_000);

  it("claim tokens: a stale claimer's ack cannot clear or settle another claim; leases are 40 s", async () => {
    const d = await createTestDb({ seed: false });
    const sp = sentinelPool(d, 2);
    try {
      await ownerWithSession(d);
      const a = (await sp.query("SELECT * FROM control.sentinel_claim(1, NULL)")).rows[0];
      const lease = await one(d, "SELECT round(extract(epoch FROM claimed_until - now()))::int s FROM control.notify_deliveries WHERE outbox_id = $1 AND channel_id = $2", [a.outbox_id, a.channel_id]);
      expect(lease.s).toBeLessThanOrEqual(40);
      await d.su.query("UPDATE control.notify_deliveries SET claimed_until = now() - interval '1 second', last_attempt_at = now() - interval '1 hour' WHERE outbox_id = $1 AND channel_id = $2", [a.outbox_id, a.channel_id]);
      const b = (await sp.query("SELECT * FROM control.sentinel_claim(10, NULL)")).rows.find((r) => r.outbox_id === a.outbox_id && r.channel_id === a.channel_id);
      expect(b.claim_token).not.toBe(a.claim_token);
      expect((await sp.query("SELECT control.sentinel_ack($1, $2, $3, true, NULL) AS ok", [a.outbox_id, a.channel_id, a.claim_token])).rows[0].ok).toBe(false);
      const row = await one(d, "SELECT delivered_at, claimed_until IS NOT NULL AS leased FROM control.notify_deliveries WHERE outbox_id = $1 AND channel_id = $2", [a.outbox_id, a.channel_id]);
      expect(row).toEqual({ delivered_at: null, leased: true });
      expect((await sp.query("SELECT control.sentinel_ack($1, $2, $3, true, NULL) AS ok", [b.outbox_id, b.channel_id, b.claim_token])).rows[0].ok).toBe(true);
    } finally { await sp.end(); await d.drop(); }
  });

  it("status: sentinel_down when the delivery heartbeat is stale and work is waiting; webhook ack still required end to end", async () => {
    const d = await createTestDb({ seed: false, notify: false });
    const sp = sentinelPool(d);
    const srv = http.createServer((q, r) => { let b = ""; q.on("data", (c) => (b += c)); q.on("end", () => {
      r.setHeader("x-orvix-ack", ackWebhook(secret, String(JSON.parse(b).notice_id), String(q.headers["x-orvix-timestamp"]))); r.statusCode = 204; r.end(); }); });
    const secret = randomBytes(32);
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    try {
      await d.su.query("SELECT control.host_add_notify_channel('host', NULL, 'webhook', $1, $2)", [`http://127.0.0.1:${(srv.address() as { port: number }).port}/h`, secret.toString("hex")]);
      await ownerWithSession(d);
      expect((await deliverOnce(sp)).delivered).toBeGreaterThan(0);
      await d.su.query("SELECT control.audit_append('cli', NULL, 'x', 'platform.recovery_requested', 'success')");
      await d.su.query("UPDATE control.sentinel_liveness SET last_seen = now() - interval '5 minutes'");
      expect((await one(d, "SELECT control.host_notify_status() AS r")).r.state).toBe("sentinel_down");
      await deliverOnce(sp);
      await sp.query("SELECT control.watchdog_reconcile(10)");                       // watchdog heartbeat
      expect((await one(d, "SELECT control.host_notify_status() AS r")).r.state).toBe("healthy");
    } finally { await sp.end(); await d.drop(); srv.close(); }
  });
});

// =====================================================================================================================
describe("tenant request-id isolation", () => {
  it("re-using a request id on another tenant is REQUEST_ID_CONFLICT (no cached result from tenant A)", async () => {
    const d = await createTestDb({ seed: true });
    try {
      const o = await ownerWithSession(d);
      const tA = (await one(d, "SELECT id FROM control.tenants WHERE slug = 'syn-golden-lotus'")).id;
      const tB = (await one(d, "SELECT id FROM control.tenants WHERE slug = 'syn-river-bazaar'")).id;
      const req = randomUUID();
      await stepup(d, o.token, o.auth, "tenant_transition", `${tA}:suspended`);
      expect((await d.api("api_tenant_transition", o.token, tA, "suspended", "test", "synthetic isolation test", req)).ok).toBe(true);
      expect((await d.api("api_tenant_transition", o.token, tB, "suspended", "test", "synthetic isolation test", req)).error).toBe("REQUEST_ID_CONFLICT");
      expect((await d.api("api_tenant_transition", o.token, tA, "suspended", "test", "synthetic isolation test", req)).replayed).toBe(true);
    } finally { await d.drop(); }
  });
});

// =====================================================================================================================
describe("upgrade 217 -> 221, rollback by restore, re-upgrade", () => {
  it("217 state survives the upgrade; legacy watchdog kills fold; a 217-era claim is re-claimable; restore + re-upgrade is clean", async () => {
    const d = await createTestDb({ seed: true, upTo: "217" });
    const restored = `orvix_control_test_${randomBytes(5).toString("hex")}`;
    try {
      await d.su.query("SELECT control.host_bootstrap_owner('owner@example.invalid', 'Owner')");
      // 217-era state: a legacy kill record not yet in the chain, and a delivery claimed by a 217 sentinel (no token)
      await d.su.query("SELECT control.watchdog_record(1, '{4242}')");
      const claimed = (await d.su.query("SELECT * FROM control.sentinel_claim(1)")).rows[0];
      expect(claimed).toBeTruthy();
      const head217 = (await d.su.query("SELECT max(seq)::int s FROM control.audit_events")).rows[0].s;
      const dump = execFileSync("docker", ["exec", "orvix-control-db", "pg_dump", "-U", "orvix_control_super", "-Fc", d.name], { maxBuffer: 64 << 20 });
      const c = new pg.Client({ ...superuserConfig(), database: d.name }); await c.connect();
      const { applied } = await migrate(c);
      expect(applied).toEqual(["218_watchdog_intents.sql", "219_recovery_auth_hardening.sql", "220_sentinel_delivery.sql", "221_privileges_tenant_contract.sql"]);
      expect((await c.query("SELECT ok FROM control.audit_verify()")).rows[0].ok).toBe(true);
      expect((await c.query("SELECT count(*)::int n FROM control.audit_events WHERE seq <= $1", [head217])).rows[0].n).toBe(head217 + 1);
      expect((await c.query("SELECT control.api_contract_version() AS v")).rows[0].v).toBe("orvix-control/0.5");
      await c.end();
      const sp = sentinelPool(d);
      try {
        await sp.query("SELECT control.watchdog_reconcile(10)");                    // folds the legacy 217 kill record
        expect((await one(d, "SELECT audit_seq IS NOT NULL AS c FROM control.watchdog_kills")).c).toBe(true);
        await d.su.query("UPDATE control.notify_deliveries SET claimed_until = now() - interval '1 second', last_attempt_at = now() - interval '1 hour' WHERE outbox_id = $1 AND channel_id = $2", [claimed.outbox_id, claimed.channel_id]);
        const again = (await sp.query("SELECT * FROM control.sentinel_claim(100, NULL)")).rows.find((r) => r.outbox_id === claimed.outbox_id);
        expect(again?.claim_token).toBeTruthy();                                     // the old (tokenless) claim is re-claimable
      } finally { await sp.end(); }
      expect(privilegeProblems((await d.app.query(PRIVILEGE_CHECK_SQL)).rows[0])).toEqual([]);
      // rollback = restore the 217 dump into a fresh database; then re-upgrade
      const admin = new pg.Client({ ...superuserConfig(), database: "orvix_control" }); await admin.connect();
      await admin.query(`CREATE DATABASE ${restored}`); await admin.end();
      execFileSync("docker", ["exec", "-i", "orvix-control-db", "pg_restore", "-U", "orvix_control_super", "-d", restored], { input: dump });
      const r = new pg.Client({ ...superuserConfig(), database: restored }); await r.connect();
      expect((await r.query("SELECT max(version) v FROM control_ledger.schema_migrations")).rows[0].v).toBe("217");
      expect((await r.query("SELECT to_regclass('control.watchdog_intents') AS t")).rows[0].t).toBeNull();
      expect((await r.query("SELECT ok FROM control.audit_verify()")).rows[0].ok).toBe(true);
      const re = await migrate(r);
      expect(re.applied).toHaveLength(4);
      expect((await r.query("SELECT ok FROM control.audit_verify()")).rows[0].ok).toBe(true);
      await r.end();
      const app = new pg.Client({ ...appConfig(), database: restored }); await app.connect();
      expect(privilegeProblems((await app.query(PRIVILEGE_CHECK_SQL)).rows[0])).toEqual([]);   // ACL re-asserted by the re-upgrade
      await app.end();
    } finally {
      const admin = new pg.Client({ ...superuserConfig(), database: "orvix_control" }); await admin.connect();
      await admin.query(`DROP DATABASE IF EXISTS ${restored} WITH (FORCE)`); await admin.end();
      await d.drop();
    }
  }, 90_000);
});

// =====================================================================================================================
describe("C1.3 independent-review fixes (regressions)", () => {
  it("H-1: PLAN/ARM/EXECUTE cannot share a transaction (no kill that can be rolled back with its evidence)", async () => {
    const d = await createTestDb({ seed: false });
    const sp = sentinelPool(d, 2);
    try {
      await ownerWithSession(d);
      const v = await staleAppSession(d);
      await sleep(2500);
      const c = await sp.connect();
      try {
        await c.query("BEGIN");
        const id = (await c.query("SELECT control.watchdog_plan(2, 15) AS ids")).rows[0].ids[0];
        expect(id).toBeTruthy();
        expect((await c.query("SELECT control.watchdog_arm($1)", [id]).catch((e) => e)).message).toMatch(/WATCHDOG_STEP_MUST_BE_OWN_TRANSACTION/);
        await c.query("ROLLBACK");
        const id2 = (await c.query("SELECT control.watchdog_plan(2, 15) AS ids")).rows[0].ids[0];   // autocommit: committed
        expect((await c.query("SELECT control.watchdog_arm($1) AS a", [id2])).rows[0].a).toBe(true);
        await c.query("BEGIN");
        await c.query("SELECT control.watchdog_plan(2, 15)");                                    // this transaction has written
        expect((await c.query("SELECT control.watchdog_execute($1)", [id2]).catch((e) => e)).message).toMatch(/WATCHDOG_STEP_MUST_BE_OWN_TRANSACTION/);
        await c.query("ROLLBACK");
      } finally { c.release(); }
      expect(await alive(d, v.pid)).toBe(true);
      expect(await errCode(sp.query("SELECT control.watchdog_plan(2, 15, true)"))).toBe("42883");   // no caller-chosen successor sweep
      await v.c.end();
    } finally { await sp.end(); await d.drop(); }
  }, 30_000);

  it("H-2: RECONCILE never resolves an intent an EXECUTE holds; the kill is recorded as terminated", async () => {
    const d = await createTestDb({ seed: false });
    const sp = sentinelPool(d, 2);
    try {
      await ownerWithSession(d);
      const v = await staleAppSession(d);
      await sleep(2500);
      const id = (await sp.query("SELECT control.watchdog_plan(2, 15) AS ids")).rows[0].ids[0];
      await sp.query("SELECT control.watchdog_arm($1)", [id]);
      const holder = await d.su.connect();                                                    // stands in for an in-flight EXECUTE
      try {
        await holder.query("BEGIN");
        await holder.query("UPDATE control.watchdog_intents SET state_at = state_at - interval '1 minute' WHERE id = $1", [id]);
        await sp.query("SELECT control.watchdog_reconcile(10)");                              // SKIP LOCKED
        await holder.query("COMMIT");
      } finally { holder.release(); }
      expect((await one(d, "SELECT state FROM control.watchdog_intents WHERE id = $1", [id])).state).toBe("armed");
      expect((await sp.query("SELECT control.watchdog_execute($1) AS r", [id])).rows[0].r).toBe("terminated");
      await sp.query("SELECT control.watchdog_reconcile(10)");
      expect((await one(d, "SELECT state, audit_seq IS NOT NULL AS c FROM control.watchdog_intents WHERE id = $1", [id]))).toEqual({ state: "terminated", c: true });
    } finally { await sp.end(); await d.drop(); }
  }, 30_000);

  it("L-2/L-7: an intent resolved WITHOUT a kill is announced too", async () => {
    const d = await createTestDb({ seed: false });
    const sp = sentinelPool(d, 2);
    try {
      await ownerWithSession(d);
      const v = await staleAppSession(d);
      await sleep(2500);
      const id = (await sp.query("SELECT control.watchdog_plan(2, 15) AS ids")).rows[0].ids[0];
      await v.c.end(); await sleep(300);
      expect((await sp.query("SELECT control.watchdog_arm($1) AS a", [id])).rows[0].a).toBe(false);   // target gone
      await sp.query("SELECT control.watchdog_reconcile(10)");
      expect((await one(d, "SELECT count(*)::int n FROM control.notify_outbox WHERE action = 'platform.watchdog_intent_resolved' AND target_id = $1", [String(id)])).n).toBe(1);
    } finally { await sp.end(); await d.drop(); }
  }, 30_000);

  it("auth M-1: an owner whose only passkey is flagged does not count for LAST_OWNER or LAST_CREDENTIAL", async () => {
    const d = await createTestDb({ seed: false });
    try {
      const a = await ownerWithSession(d, "a@example.invalid");
      const b = await operatorFixture(d, "owner", "b@example.invalid");
      await d.su.query("UPDATE control.webauthn_credentials SET counter_suspect_at = now() WHERE identity_id = $1", [b.identityId]);
      expect((await one(d, "SELECT control.host_revoke_operator_credentials('a@example.invalid', 'would leave only a flagged owner') AS r")).r.error).toBe("LAST_OWNER");
      // a: good passkey + a flagged second one -> the good one cannot be revoked
      await d.su.query(`INSERT INTO control.webauthn_credentials (identity_id, credential_id, public_key, created_via, counter_suspect_at)
                        VALUES ($1, 'flaggedcred00000001', $2, 'bootstrap', now())`, [a.identityId, new SoftAuthenticator().cosePublicKey]);
      const good = (await one(d, "SELECT id FROM control.webauthn_credentials WHERE identity_id = $1 AND counter_suspect_at IS NULL", [a.identityId])).id;
      await stepup(d, a.token, a.auth, "credential_revoke", good);
      expect((await d.api("api_credential_revoke", a.token, good)).error).toBe("LAST_CREDENTIAL");
    } finally { await d.drop(); }
  });

  it("auth L2/L3: while an owner is under recovery, its invitations and approved links are frozen and step-up is paused (protective actions excepted)", async () => {
    const d = await createTestDb({ seed: false });
    try {
      const o1 = await ownerWithSession(d, "o1@example.invalid");
      const o2 = await operatorFixture(d, "owner", "o2@example.invalid");
      await operatorFixture(d, "owner", "o3@example.invalid");
      await d.su.query("UPDATE control.webauthn_credentials SET last_used_at = now() - interval '1 day'");
      const inv = await invite(d, o1, "acc@example.invalid", "admin");
      const e = await enrolWithToken(d, inv.enrolment_token, new SoftAuthenticator());
      const r3 = (await one(d, "SELECT control.host_recovery_request('o3@example.invalid', 'o3 lost device synthetic') AS r")).r;
      await stepup(d, o1.token, o1.auth, "recovery_approve", r3.request_id);
      const link = await d.api("api_recovery_approve", o1.token, r3.request_id);
      expect(link.ok).toBe(true);
      const r1 = (await one(d, "SELECT control.host_recovery_request('o1@example.invalid', 'o1 device stolen synthetic') AS r")).r;
      await deliverAll(d);
      expect((await one(d, "SELECT control.host_approve_operator('acc@example.invalid', $1) AS r", [e.fingerprint])).r.error).toBe("INVITER_UNDER_RECOVERY");
      expect((await enrolWithToken(d, link.enrolment_token, new SoftAuthenticator())).error).toBe("APPROVER_UNDER_RECOVERY");
      const t = (await one(d, "SELECT id FROM control.tenants LIMIT 1"))?.id ?? randomUUID();
      expect((await d.api("api_stepup_begin", o1.token, "tenant_transition", `${t}:suspended`)).error).toBe("IDENTITY_UNDER_RECOVERY");
      expect((await d.api("api_stepup_begin", o1.token, "credential_add", o1.identityId)).error).toBe("IDENTITY_UNDER_RECOVERY");
      expect((await d.api("api_stepup_begin", o1.token, "recovery_cancel", r1.request_id)).ok).toBe(true);   // own contest
      expect((await d.api("api_stepup_begin", o1.token, "operator_invite", `revoke:${inv.invitation_id}`)).ok).toBe(true);
      void o2;
    } finally { await d.drop(); }
  });

  it("auth L4: host revoke audits each of the subject's own reopened requests", async () => {
    const d = await createTestDb({ seed: false });
    try {
      await ownerWithSession(d, "a@example.invalid");
      await operatorFixture(d, "owner", "b@example.invalid");
      const r = (await one(d, "SELECT control.host_recovery_request('b@example.invalid', 'b lost device synthetic') AS r")).r;
      const rv = (await one(d, "SELECT control.host_revoke_operator_credentials('b@example.invalid', 'b device stolen synthetic') AS r")).r;
      expect(rv.own_requests_reopened).toBe(1);
      expect(await one(d, "SELECT reason_code FROM control.audit_events WHERE action = 'platform.recovery_link_voided' AND target_id = $1", [r.request_id]))
        .toEqual({ reason_code: "SUBJECT_REVOKED" });
    } finally { await d.drop(); }
  });

  it("priv F1/F2/F3/F5: unhardened sibling databases, --no-owner restores, WAL/xid built-ins and extra grants are all caught", async () => {
    const d = await createTestDb({ seed: true });
    const sib = await createTestDb({ seed: false, upTo: "100" });                  // control-named, never migrated (PUBLIC ACL)
    const noOwner = `orvix_control_test_${randomBytes(5).toString("hex")}`;
    try {
      expect(privilegeProblems((await d.app.query(PRIVILEGE_CHECK_SQL)).rows[0])).toContain("role can CONNECT to a non-control or unhardened database");
      await sib.drop();
      expect(privilegeProblems((await d.app.query(PRIVILEGE_CHECK_SQL)).rows[0])).toEqual([]);
      for (const sql of ["SELECT pg_logical_emit_message(false, 'p', 'x')", "SELECT txid_current()", "SELECT pg_current_xact_id()"]) {
        expect(await errCode(d.app.query(sql)), sql).toBe("42501");
      }
      await d.su.query(`GRANT CREATE ON DATABASE ${d.name} TO control_app`);
      expect(privilegeProblems((await d.app.query(PRIVILEGE_CHECK_SQL)).rows[0])).toContain("role has CREATE on the control database");
      const m = new pg.Client({ ...superuserConfig(), database: d.name }); await m.connect(); await migrate(m); await m.end();
      expect(privilegeProblems((await d.app.query(PRIVILEGE_CHECK_SQL)).rows[0])).toEqual([]);
      const dump = execFileSync("docker", ["exec", "orvix-control-db", "pg_dump", "-U", "orvix_control_super", "-Fc", d.name], { maxBuffer: 64 << 20 });
      const admin = new pg.Client({ ...superuserConfig(), database: "orvix_control" }); await admin.connect();
      await admin.query(`CREATE DATABASE ${noOwner}`); await admin.end();
      execFileSync("docker", ["exec", "-i", "orvix-control-db", "pg_restore", "--no-owner", "-U", "orvix_control_super", "-d", noOwner], { input: dump });
      const r = new pg.Client({ ...superuserConfig(), database: noOwner }); await r.connect(); await migrate(r); await r.end();
      const app = new pg.Client({ ...appConfig(), database: noOwner }); await app.connect();
      expect(privilegeProblems((await app.query(PRIVILEGE_CHECK_SQL)).rows[0])).toContain("control objects are owned by a superuser or another unexpected role (restored with --no-owner?)");
      await app.end();
    } finally {
      const admin = new pg.Client({ ...superuserConfig(), database: "orvix_control" }); await admin.connect();
      await admin.query(`DROP DATABASE IF EXISTS ${noOwner} WITH (FORCE)`); await admin.end();
      await d.drop();
    }
  }, 90_000);

  it("priv F4/F7: sentinel role drift is detected and reset by migrate; the control roles cannot use the local socket", async () => {
    const d = await createTestDb({ seed: false });
    const sp = sentinelPool(d, 1);
    try {
      const { privilegeSelfCheck } = await import("../../scripts/sentinel");
      expect(await privilegeSelfCheck(sp)).toEqual([]);
      await d.su.query("ALTER ROLE control_sentinel SET statement_timeout = 0");
      expect(await privilegeSelfCheck(sp)).toContain("sentinel role defaults are not the canonical set (run npm run db:migrate)");
      const { setAppPassword } = await import("../../scripts/migrator");
      const m = new pg.Client({ ...superuserConfig(), database: d.name }); await m.connect();
      await setAppPassword(m, process.env.ORVIX_DB_APP_PASSWORD!); await m.end();
      expect(await privilegeSelfCheck(sp)).toEqual([]);
      // per-database drift (C1.3 verification round): also detected, also reset by the migrator
      await d.su.query(`ALTER ROLE control_sentinel IN DATABASE ${d.name} SET statement_timeout = 0`);
      const sp2 = sentinelPool(d, 1);
      try { expect(await privilegeSelfCheck(sp2)).toContain("sentinel role defaults are not the canonical set (run npm run db:migrate)"); }
      finally { await sp2.end(); }
      const m2 = new pg.Client({ ...superuserConfig(), database: d.name }); await m2.connect();
      await setAppPassword(m2, process.env.ORVIX_DB_APP_PASSWORD!); await m2.end();
      const sock = spawnSync("gosu", ["postgres", "psql", "-U", "control_app", "-d", d.name, "-tAc", "SELECT 1"], { encoding: "utf8" });
      expect(sock.status).not.toBe(0);
      expect(sock.stderr).toMatch(/pg_hba\.conf rejects/);
    } finally { await sp.end(); await d.drop(); }
  });

  it("sentinel M-1: a webhook with a database-verified ack key cannot be marked delivered by the sentinel credential alone", async () => {
    const d = await createTestDb({ seed: false, notify: false });
    const sp = sentinelPool(d, 2);
    const ackKey = randomBytes(32);
    const srv = http.createServer((q, r) => { let b = ""; q.on("data", (c) => (b += c)); q.on("end", () => {
      r.setHeader("x-orvix-ack", ackWebhook(ackKey, String(JSON.parse(b).notice_id), String(q.headers["x-orvix-timestamp"]), b)); r.statusCode = 204; r.end(); }); });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    try {
      const signKey = randomBytes(32);
      const url = `http://127.0.0.1:${(srv.address() as { port: number }).port}/h`;
      const ch = (await one(d, "SELECT control.host_add_notify_channel('host', NULL, 'webhook', $1, $2) AS r",
        [url, signKey.toString("hex")])).r.channel_id;
      expect((await one(d, "SELECT control.host_set_notify_ack_key($1, $2) AS r", [ch, ackKey.toString("hex")])).r.ok).toBe(true);
      await ownerWithSession(d);
      // forged: the sentinel claims ok without a valid receiver ack
      const c = (await sp.query("SELECT * FROM control.sentinel_claim(1, NULL)")).rows[0];
      expect(c.ack_verified_in_db).toBe(true);
      expect((await sp.query("SELECT control.sentinel_ack($1, $2, $3, true, NULL) AS ok", [c.outbox_id, c.channel_id, c.claim_token])).rows[0].ok).toBe(false);
      expect((await one(d, "SELECT delivered_at, last_error FROM control.notify_deliveries WHERE outbox_id = $1", [c.outbox_id])))
        .toEqual({ delivered_at: null, last_error: "ack rejected by database" });
      // forged CONTENT under the real notice id: the receiver acks what it got, the database recomputes the real body's hash
      await d.su.query("UPDATE control.notify_deliveries SET last_attempt_at = now() - interval '1 hour'");
      const c2 = (await sp.query("SELECT * FROM control.sentinel_claim(1, NULL)")).rows[0];
      const fake = JSON.stringify({ action: "platform.harmless", notice_id: Number(c2.outbox_id) });
      const ts = String(Math.floor(Date.now() / 1000));
      const { signWebhook } = await import("../../scripts/sentinel");
      const fr = await fetch(url, { method: "POST", body: fake, headers: { "x-orvix-timestamp": ts, "x-orvix-signature": signWebhook(signKey, ts, fake) } });
      const fakeAck = fr.headers.get("x-orvix-ack");
      expect((await sp.query("SELECT control.sentinel_ack($1, $2, $3, true, NULL, $4, $5) AS ok", [c2.outbox_id, c2.channel_id, c2.claim_token, ts, fakeAck])).rows[0].ok).toBe(false);
      await d.su.query("UPDATE control.notify_deliveries SET last_attempt_at = now() - interval '1 hour'");
      // honest: the real receiver's ack (computed with a key the sentinel never sees) is accepted
      expect((await deliverOnce(sp)).delivered).toBeGreaterThan(0);
      expect((await one(d, "SELECT count(*)::int n FROM control.notify_deliveries WHERE delivered_at IS NULL")).n).toBe(0);
      expect(await errCode(sp.query("SELECT ack_secret FROM control.notify_channels"))).toBe("42501");
    } finally { await sp.end(); await d.drop(); srv.close(); }
  });

  it("sentinel L-1/L-2 + M-2: the waiver needs an ENABLED host channel; the window counts from the disable; idle heartbeat; watchdog_down", async () => {
    const d = await createTestDb({ seed: false, notify: false });
    const sp = sentinelPool(d, 2);
    try {
      const h1 = (await one(d, "SELECT control.host_add_notify_channel('host', NULL, 'file', '/tmp/c13-h1.jsonl', NULL) AS r")).r.channel_id;
      const h2 = (await one(d, "SELECT control.host_add_notify_channel('host', NULL, 'file', '/tmp/c13-h2.jsonl', NULL) AS r")).r.channel_id;
      await ownerWithSession(d);
      await d.su.query("SELECT control.audit_append('cli', NULL, 'x', 'platform.recovery_approved', 'success', 'recovery_request', 'rq-1')");
      const rows = (await sp.query("SELECT * FROM control.sentinel_claim(100, NULL)")).rows;
      for (const r of rows) if (String(r.channel_id) === String(h1)) await sp.query("SELECT control.sentinel_ack($1, $2, $3, true, NULL)", [r.outbox_id, r.channel_id, r.claim_token]);
      const gate = async () => (await one(d, "SELECT control.notification_delivered('platform.recovery_approved', 'recovery_request', 'rq-1') AS g")).g;
      expect(await gate()).toBe(false);                                                  // h2 pending
      await d.su.query("SELECT control.host_disable_notify_channel($1)", [h2]);
      expect(await gate()).toBe(true);                                                   // waiver: h1 (enabled host) delivered
      const at = (await one(d, "SELECT control.notification_delivered_at('platform.recovery_approved', 'recovery_request', 'rq-1') AS t")).t;
      const dis = (await one(d, "SELECT disabled_at FROM control.notify_channels WHERE id = $1", [h2])).disabled_at;
      expect(new Date(at).getTime()).toBe(new Date(dis).getTime());                       // window counts from the disable
      await d.su.query("SELECT control.host_disable_notify_channel($1)", [h1]);
      expect(await gate()).toBe(false);                                                  // no ENABLED host channel delivered
      await sp.query("SELECT * FROM control.sentinel_pending_channels()");               // an idle tick is a heartbeat
      await sp.query("SELECT control.watchdog_reconcile(10)");
      const st = (await one(d, "SELECT control.host_notify_status() AS r")).r;
      expect(st.state).toBe("no_host_channel");
      await d.su.query("UPDATE control.sentinel_liveness SET last_seen = now() - interval '5 minutes' WHERE component = 'watchdog'");
      expect((await one(d, "SELECT control.host_notify_status() AS r")).r.state).toBe("watchdog_down");
    } finally { await sp.end(); await d.drop(); }
  });
});

describe("C1.3 verification-round fixes", () => {
  it("anchor signing is paused while the owner is under recovery", async () => {
    const d = await createTestDb({ seed: false });
    try {
      const o = await ownerWithSession(d, "a@example.invalid");
      await operatorFixture(d, "owner", "b@example.invalid");
      await d.su.query("SELECT control.host_recovery_request('a@example.invalid', 'anchor pause synthetic')");
      const b = await d.api("api_anchor_begin", o.token);
      if (b.ok) {
        const { assertionParts } = await import("../helpers/db");
        const a = assertionParts(o.auth.assert({ challenge: b.challenge }));
        expect((await d.api("api_anchor_complete", o.token, a.id, a.cdj, a.ad, a.sig, "x")).ok).not.toBe(true);
      } else {
        expect(b.ok).toBe(false);
      }
    } finally { await d.drop(); }
  });

  it("harden-cluster reports a control-named sibling database that is behind on migrations", async () => {
    const sib = await createTestDb({ seed: false, upTo: "206" });
    try {
      const r = spawnSync(process.execPath, ["--import", "tsx", "scripts/harden-cluster.ts", "--check"], { encoding: "utf8" });
      expect(r.status).toBe(3);
      expect(r.stdout).toContain(`control database ${sib.name} is at migration 206`);
    } finally { await sib.drop(); }
  }, 60_000);
});
