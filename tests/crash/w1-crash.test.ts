// W-1 crash injection (C1.3): REAL process crashes at every boundary of the watchdog intent protocol.
// Killing a PostgreSQL backend with SIGKILL makes the postmaster restart the WHOLE cluster, so this suite runs alone
// (vitest.crash.config.mts) and only inside a disposable cluster: it refuses unless ORVIX_CRASH_TESTS=disposable-cluster
// and it runs in the same PID namespace as PostgreSQL (it must be able to signal backend PIDs).
import { spawn, type ChildProcess } from "node:child_process";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import pg from "pg";
import { appConfig, sentinelConfig, superuserConfig } from "../../scripts/env";
import { createTestDb, ownerWithSession, type TestDb } from "../helpers/db";

const allowed = process.env.ORVIX_CRASH_TESTS === "disposable-cluster";
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
const q = async (db: TestDb, sql: string, p: unknown[] = []) => {
  const c = new pg.Client({ ...superuserConfig(), database: db.name });
  await c.connect();
  try { return (await c.query(sql, p)).rows; } finally { await c.end(); }
};
async function waitUp(db: TestDb) {
  for (let i = 0; i < 60; i++) { try { await q(db, "SELECT 1"); return; } catch { await sleep(500); } }
  throw new Error("cluster did not come back");
}
async function client(cfg: pg.ClientConfig) { const c = new pg.Client(cfg); c.on("error", () => {}); await c.connect(); return c; }
async function victim(db: TestDb) {
  const c = await client({ ...appConfig(), database: db.name });
  await c.query("SET idle_in_transaction_session_timeout = 0; SET transaction_timeout = 0");
  await c.query("BEGIN"); await c.query("SELECT control.api_contract_version()");
  return { c, pid: (await c.query("SELECT pg_backend_pid() AS p")).rows[0].p as number };
}
const backendAlive = async (db: TestDb, pid: number) => (await q(db, "SELECT 1 FROM pg_stat_activity WHERE pid = $1", [pid])).length > 0;
async function waitBlocked(db: TestDb, pid: number) {
  for (let i = 0; i < 60; i++) {
    const r = await q(db, "SELECT wait_event_type FROM pg_stat_activity WHERE pid = $1", [pid]);
    if (r[0]?.wait_event_type === "Lock") return true;
    await sleep(100);
  }
  return false;
}
const crashBackend = (pid: number) => process.kill(pid, "SIGKILL");     // postmaster then restarts the cluster

describe.skipIf(!allowed)("W-1: real crashes at every protocol boundary", () => {
  let db: TestDb;
  beforeAll(async () => {
    db = await createTestDb({ seed: false }); await ownerWithSession(db);
    for (const p of [db.su, db.app]) p.on("error", () => { /* idle clients are dropped by the deliberate cluster restarts */ });
  });
  afterAll(async () => { await waitUp(db); await db?.drop(); });

  it("CRASH DURING PLAN (before the intent commits): no intent, and the target was never terminated", async () => {
    const v = await victim(db);
    await sleep(2500);
    const lock = await client({ ...superuserConfig(), database: db.name });
    await lock.query("BEGIN"); await lock.query("LOCK TABLE control.watchdog_intents IN ACCESS EXCLUSIVE MODE");
    const sp = await client({ ...sentinelConfig(), database: db.name });
    const spPid = (await sp.query("SELECT pg_backend_pid() AS p")).rows[0].p;
    void sp.query("SELECT control.watchdog_plan(2, 15)").catch(() => null);
    expect(await waitBlocked(db, spPid)).toBe(true);                                // PLAN is inside its transaction
    expect(await backendAlive(db, v.pid)).toBe(true);                               // nothing terminated yet
    crashBackend(spPid);
    await waitUp(db);
    expect((await q(db, "SELECT count(*)::int n FROM control.watchdog_intents WHERE target_pid = $1", [v.pid]))[0].n).toBe(0);
    expect((await q(db, "SELECT count(*)::int n FROM control.audit_events WHERE action = 'platform.watchdog_terminated'"))[0].n).toBe(0);
  }, 60_000);

  it("CRASH AFTER pg_terminate_backend, BEFORE COMMIT (the C1.2 W-1 window): evidence survives and is reconciled", async () => {
    const v = await victim(db);
    await sleep(2500);
    let sp = await client({ ...sentinelConfig(), database: db.name });
    const id = (await sp.query("SELECT control.watchdog_plan(2, 15) AS ids")).rows[0].ids[0];
    expect((await sp.query("SELECT control.watchdog_arm($1) AS a", [id])).rows[0].a).toBe(true);
    // hold the watchdog liveness row: EXECUTE locks its intent, kills, records the transition, then blocks on the
    // liveness update -- i.e. it is stuck AFTER the kill and BEFORE its transaction can commit (the C1.2 W-1 window)
    const lock = await client({ ...superuserConfig(), database: db.name });
    await lock.query("BEGIN"); await lock.query("SELECT 1 FROM control.sentinel_liveness WHERE component = 'watchdog' FOR UPDATE");
    const spPid = (await sp.query("SELECT pg_backend_pid() AS p")).rows[0].p;
    void sp.query("SELECT control.watchdog_execute($1)", [id]).catch(() => null);
    expect(await waitBlocked(db, spPid)).toBe(true);                                // terminated, now blocked before commit
    expect(await backendAlive(db, v.pid)).toBe(false);                              // the kill already happened
    crashBackend(spPid);                                                            // ... and the recording transaction dies
    await waitUp(db);
    const before = await q(db, "SELECT state FROM control.watchdog_intents WHERE id = $1", [id]);
    expect(before).toEqual([{ state: "armed" }]);                                   // durable pre-kill evidence
    expect((await q(db, "SELECT count(*)::int n FROM control.notify_outbox WHERE action = 'platform.watchdog_intent' AND target_id = $1", [String(id)]))[0].n).toBe(1);
    await q(db, "UPDATE control.watchdog_intents SET state_at = state_at - interval '1 minute' WHERE id = $1", [id]);
    sp = await client({ ...sentinelConfig(), database: db.name });
    await sp.query("SELECT control.watchdog_reconcile(10)");
    await sp.end();
    const after = await q(db, "SELECT state, audit_seq IS NOT NULL AS chained FROM control.watchdog_intents WHERE id = $1", [id]);
    expect(after).toEqual([{ state: "terminated_unconfirmed", chained: true }]);
    expect((await q(db, "SELECT count(*)::int n FROM control.notify_outbox WHERE action = 'platform.watchdog_terminated' AND target_id = $1", [String(id)]))[0].n).toBe(1);
    expect((await q(db, "SELECT ok FROM control.audit_verify()"))[0].ok).toBe(true);
  }, 60_000);

  it("CRASH DURING RECONCILE/FOLD: the resolved intent is folded by the next reconcile; the chain verifies", async () => {
    const v = await victim(db);
    await sleep(2500);
    let sp = await client({ ...sentinelConfig(), database: db.name });
    const id = (await sp.query("SELECT control.watchdog_plan(2, 15) AS ids")).rows[0].ids[0];
    await sp.query("SELECT control.watchdog_arm($1)", [id]);
    expect((await sp.query("SELECT control.watchdog_execute($1) AS r", [id])).rows[0].r).toBe("terminated");
    const lock = await client({ ...superuserConfig(), database: db.name });
    await lock.query("BEGIN"); await lock.query("SELECT 1 FROM control.audit_lock FOR UPDATE");
    const spPid = (await sp.query("SELECT pg_backend_pid() AS p")).rows[0].p;
    void sp.query("SELECT control.watchdog_reconcile(10)").catch(() => null);
    expect(await waitBlocked(db, spPid)).toBe(true);
    crashBackend(spPid);
    await waitUp(db);
    expect(await q(db, "SELECT state, audit_seq FROM control.watchdog_intents WHERE id = $1", [id])).toEqual([{ state: "terminated", audit_seq: null }]);
    sp = await client({ ...sentinelConfig(), database: db.name });
    await sp.query("SELECT control.watchdog_reconcile(10)");
    await sp.end();
    expect((await q(db, "SELECT audit_seq IS NOT NULL AS c FROM control.watchdog_intents WHERE id = $1", [id]))[0].c).toBe(true);
    expect((await q(db, "SELECT ok FROM control.audit_verify()"))[0].ok).toBe(true);
    void v;
  }, 60_000);

  it("SENTINEL PROCESS SIGKILL mid-pass: the intent is abandoned (never executed), and a restarted sentinel acts on a NEW intent", async () => {
    const v = await victim(db);
    await sleep(2500);
    const lock = await client({ ...superuserConfig(), database: db.name });
    await lock.query("BEGIN"); await lock.query("LOCK TABLE control.watchdog_intents IN ACCESS EXCLUSIVE MODE");
    const env = { ...process.env, ORVIX_DB_NAME: db.name };
    const start = (): ChildProcess => spawn(process.execPath, ["--import", "tsx", "scripts/sentinel.ts"], { env, stdio: "ignore", detached: true });
    const s1 = start();
    let blocked = false;
    for (let i = 0; i < 100 && !blocked; i++) {
      blocked = (await q(db, "SELECT 1 FROM pg_stat_activity WHERE application_name = 'orvix-sentinel-watchdog' AND wait_event_type = 'Lock'")).length > 0;
      await sleep(100);
    }
    expect(blocked).toBe(true);                                                      // the real sentinel is inside PLAN
    process.kill(-s1.pid!, "SIGKILL");                                               // the PROCESS dies (not the backend)
    await lock.query("ROLLBACK"); await lock.end();                                  // its backend finishes PLAN and commits
    await sleep(1000);
    // Either outcome is safe: the orphaned backend rolls PLAN back when it notices the lost client, or it commits a
    // 'planned' intent that nobody arms. Never armed, never terminated.
    const planned = await q(db, "SELECT id, state FROM control.watchdog_intents WHERE target_pid = $1 ORDER BY id", [v.pid]);
    expect(planned.every((r) => r.state === "planned")).toBe(true);
    expect(await backendAlive(db, v.pid)).toBe(true);
    if (planned.length) await q(db, "UPDATE control.watchdog_intents SET state_at = state_at - interval '1 minute' WHERE id = $1", [planned[0].id]);
    const s2 = start();
    try {
      let gone = false;
      for (let i = 0; i < 100 && !gone; i++) { gone = !(await backendAlive(db, v.pid)); await sleep(200); }
      expect(gone).toBe(true);
      await sleep(3000);
      const all = await q(db, "SELECT state, audit_seq IS NOT NULL AS chained FROM control.watchdog_intents WHERE target_pid = $1 ORDER BY id", [v.pid]);
      expect(all.at(-1)).toEqual({ state: "terminated", chained: true });                  // a NEW intent did the kill
      expect(all.slice(0, -1).every((r) => r.state === "abandoned" && r.chained)).toBe(true);
    } finally { process.kill(-s2.pid!, "SIGKILL"); }
  }, 90_000);
});
