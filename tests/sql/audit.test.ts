// Tamper-evident audit log: append-only by grant AND trigger, hash chain detects edits and deletions,
// anchors detect tail truncation; honest limits are asserted, not hidden.
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import pg from "pg";
import { appConfig } from "../../scripts/env";
import { createTestDb, lastAudit, ownerWithSession, signAnchor, type TestDb } from "../helpers/db";

async function code(p: Promise<unknown>) {
  return p.then(() => "OK", (e: { code?: string; message?: string }) => `${e.code}:${(e.message ?? "").split(":")[0]}`);
}

describe("append-only enforcement", () => {
  let db: TestDb;
  beforeAll(async () => {
    db = await createTestDb({ seed: false });
    await ownerWithSession(db);
  });
  afterAll(async () => { await db?.drop(); });

  it("starts from a genesis row and verifies", async () => {
    const { rows } = await db.su.query(`SELECT seq, action, encode(prev_hash,'hex') AS prev FROM control.audit_events WHERE seq = 0`);
    expect(rows[0]).toEqual({ seq: "0", action: "audit.genesis", prev: "0".repeat(64) });
    const v = await db.su.query(`SELECT * FROM control.audit_verify()`);
    expect(v.rows[0].ok).toBe(true);
  });

  it("control_app has no write path at all (privilege denied)", async () => {
    expect(await code(db.app.query(`INSERT INTO control.audit_events (seq) VALUES (999)`))).toMatch(/^42501/);
    expect(await code(db.app.query(`UPDATE control.audit_events SET outcome = 'success'`))).toMatch(/^42501/);
    expect(await code(db.app.query(`DELETE FROM control.audit_events`))).toMatch(/^42501/);
    expect(await code(db.app.query(`TRUNCATE control.audit_events`))).toMatch(/^42501/);
    expect(await code(db.app.query(`SELECT control.audit_append('system', NULL, 'x', 'audit.verified', 'success')`))).toMatch(/^42501/);
  });

  it("even the superuser is refused by triggers (UPDATE, DELETE, TRUNCATE, direct INSERT)", async () => {
    expect(await code(db.su.query(`UPDATE control.audit_events SET outcome = 'failed' WHERE seq = 1`))).toBe("42501:AUDIT_APPEND_ONLY");
    expect(await code(db.su.query(`DELETE FROM control.audit_events WHERE seq = 1`))).toBe("42501:AUDIT_APPEND_ONLY");
    expect(await code(db.su.query(`TRUNCATE control.audit_events CASCADE`))).toBe("42501:AUDIT_APPEND_ONLY");
    expect(await code(db.su.query(
      `INSERT INTO control.audit_events (seq, occurred_at, actor_type, action, outcome, prev_hash, row_hash)
       VALUES (100000, now(), 'system', 'audit.verified', 'success', decode(repeat('00',32),'hex'), decode(repeat('00',32),'hex'))`)))
      .toBe("42501:AUDIT_APPEND_ONLY");
  });

  it("a forged marker GUC does not allow a direct insert", async () => {
    const c = await db.su.connect();
    try {
      await c.query("BEGIN");
      await c.query(`SELECT set_config('control.audit_writer', 'on', true)`);
      const r = await code(c.query(
        `INSERT INTO control.audit_events (seq, occurred_at, actor_type, action, outcome, prev_hash, row_hash)
         VALUES (100001, now(), 'system', 'audit.verified', 'success', decode(repeat('00',32),'hex'), decode(repeat('00',32),'hex'))`));
      expect(r).toBe("42501:AUDIT_APPEND_ONLY");
    } finally {
      await c.query("ROLLBACK");
      c.release();
    }
  });

  it("concurrent appends stay gap-free and the chain stays valid (40 real appends)", async () => {
    // Each call burns a REAL, DB-issued challenge, so each one writes exactly one audit row (207+).
    const challenges: string[] = [];
    while (challenges.length < 40) {
      await db.su.query("DELETE FROM control.rate_limits");
      for (let i = 0; i < 15 && challenges.length < 40; i++) challenges.push((await db.api("api_login_begin", null)).challenge);
    }
    await db.su.query("DELETE FROM control.rate_limits");
    const before = Number((await db.su.query("SELECT max(seq) m FROM control.audit_events")).rows[0].m);
    const pools = Array.from({ length: 4 }, () => new pg.Pool({ ...appConfig(), database: db.name, max: 1 }));
    await Promise.all(challenges.map((ch, i) =>
      pools[i % 4]!.query("SELECT control.api_auth_failed('login', $1, 'cred-unknown-000000', 'SIGNATURE_INVALID')", [ch])));
    await Promise.all(pools.map((p) => p.end()));
    const { rows } = await db.su.query("SELECT count(*)::int n, max(seq)::int mx FROM control.audit_events");
    expect(rows[0].mx - before).toBe(40);
    expect(rows[0].n).toBe(rows[0].mx + 1);
    const v = await db.su.query("SELECT * FROM control.audit_verify()");
    expect(v.rows[0].ok).toBe(true);
  });
});

describe("tamper detection (superuser with all triggers disabled via session_replication_role, simulated)", () => {
  let db: TestDb;
  let owner: Awaited<ReturnType<typeof ownerWithSession>>;
  beforeAll(async () => {
    db = await createTestDb({ seed: true });
    owner = await ownerWithSession(db);
    for (let i = 0; i < 5; i++) await db.api("api_tenant_list", owner.token);
    await db.api("api_credential_add_begin", owner.token); // denied (no step-up) -> audited
  });
  afterAll(async () => { await db?.drop(); });

  const asTamperer = async (sql: string) => {
    const c = await db.su.connect();
    try {
      await c.query("SET session_replication_role = replica");
      await c.query(sql);
    } finally {
      await c.query("RESET session_replication_role");
      c.release();
    }
  };

  it("an edited middle row is reported at its exact seq", async () => {
    const { rows } = await db.su.query(`SELECT max(seq)::int mx FROM control.audit_events`);
    const target = Math.floor(rows[0].mx / 2);
    await asTamperer(`UPDATE control.audit_events SET detail = '{"edited":true}' WHERE seq = ${target}`);
    const v = (await db.api("api_audit_verify", owner.token));
    expect(v).toMatchObject({ ok: true, intact: false });
    expect(Number(v.first_bad_seq)).toBe(target);
    const [a] = await lastAudit(db);
    expect([a.action, a.outcome, a.reason_code]).toEqual(["audit.verified", "failed", "CHAIN_BROKEN"]);
  });

  it("a deleted middle row is detected", async () => {
    const db2 = await createTestDb({ seed: false });
    try {
      const o = await ownerWithSession(db2);
      await db2.api("api_session_get", o.token);
      const c = await db2.su.connect();
      await c.query("SET session_replication_role = replica");
      await c.query(`DELETE FROM control.audit_events WHERE seq = 2`);
      await c.query("RESET session_replication_role");
      c.release();
      const v = await db2.api("api_audit_verify", o.token);
      expect(v.intact).toBe(false);
      expect(Number(v.first_bad_seq)).toBe(3);
    } finally {
      await db2.drop();
    }
  });

  it("tail truncation is caught by an anchor, and NOT caught without one (honest limit)", async () => {
    const db3 = await createTestDb({ seed: false });
    try {
      const o = await ownerWithSession(db3);
      const truncateTail = async (fromSeq: number) => {
        const c = await db3.su.connect();
        await c.query("SET session_replication_role = replica");
        await c.query(`DELETE FROM control.audit_events WHERE seq >= ${fromSeq}`);
        await c.query("RESET session_replication_role");
        c.release();
      };
      // Without an anchor: deleting the newest rows leaves a valid shorter chain.
      const { rows: r1 } = await db3.su.query(`SELECT max(seq)::int mx FROM control.audit_events`);
      await truncateTail(r1[0].mx);
      expect((await db3.api("api_audit_verify", o.token)).intact).toBe(true);
      // With an anchor: deleting rows at or before the anchored head is detected.
      const anchor = await signAnchor(db3, o);
      expect(anchor.ok).toBe(true);
      await truncateTail(Number(anchor.seq));
      const v = await db3.api("api_audit_verify", o.token);
      expect(v.intact).toBe(false);
      expect(v.bad_anchor_id).not.toBeNull();
    } finally {
      await db3.drop();
    }
  });

  it("a full recompute of the chain by a superuser is NOT detected on-host (needs off-host anchors)", async () => {
    const db4 = await createTestDb({ seed: false });
    try {
      const o = await ownerWithSession(db4);
      // Rewrite a row and recompute every hash after it, exactly as an attacker with superuser would.
      const c = await db4.su.connect();
      await c.query("SET session_replication_role = replica");
      await c.query(`UPDATE control.audit_events SET detail = '{"rewritten":true}' WHERE seq = 1`);
      await c.query(`DO $$ DECLARE r record; prev bytea; BEGIN
        FOR r IN SELECT * FROM control.audit_events ORDER BY seq LOOP
          IF r.seq = 0 THEN prev := r.row_hash; CONTINUE; END IF;
          UPDATE control.audit_events SET prev_hash = prev,
            row_hash = control.audit_row_hash(prev, control.audit_canonical(r.seq, r.occurred_at, r.actor_type, r.actor_id,
              r.actor_label, r.action, r.outcome, r.target_type, r.target_id, r.request_id, r.reason_code, r.detail))
           WHERE seq = r.seq RETURNING row_hash INTO prev;
        END LOOP; END $$`);
      await c.query("RESET session_replication_role");
      c.release();
      expect((await db4.api("api_audit_verify", o.token)).intact).toBe(true);
    } finally {
      await db4.drop();
    }
  });
});

describe("audit read access", () => {
  let db: TestDb;
  beforeAll(async () => { db = await createTestDb({ seed: true }); });
  afterAll(async () => { await db?.drop(); });

  it("owner sees all events; a platform admin sees only their own; verify is owner-only (denial audited)", async () => {
    const { adminWithSession } = await import("../helpers/db");
    const owner = await ownerWithSession(db);
    const admin = await adminWithSession(db);
    await db.api("api_tenant_list", admin.token);
    const o = await db.api("api_audit_list", owner.token, 200, null);
    const a = await db.api("api_audit_list", admin.token, 200, null);
    expect(o.scope).toBe("all");
    expect(a.scope).toBe("own");
    expect(o.events.length).toBeGreaterThan(a.events.length);
    const { rows } = await db.su.query(`SELECT id FROM control.platform_identities WHERE role = 'admin'`);
    const adminSeqs = new Set((await db.su.query(`SELECT seq::text FROM control.audit_events WHERE actor_id = $1`, [rows[0].id])).rows.map((r) => Number(r.seq)));
    expect(a.events.every((e: { seq: number }) => adminSeqs.has(Number(e.seq)))).toBe(true);
    expect(await db.api("api_audit_verify", admin.token)).toEqual({ ok: false, error: "FORBIDDEN" });
    const [last] = await lastAudit(db);
    expect([last.action, last.reason_code, last.actor_id]).toEqual(["platform.access_denied", "FORBIDDEN", rows[0].id]);
  });

  it("audit rows never contain session tokens, enrolment tokens or public keys", async () => {
    const { rows } = await db.su.query(`SELECT detail::text || coalesce(target_id,'') AS t FROM control.audit_events`);
    const tokens = (await db.su.query(`SELECT encode(id_hash,'hex') h FROM control.sessions`)).rows.map((r) => r.h);
    for (const r of rows) {
      expect(r.t).not.toMatch(/[0-9a-f]{64}/);
      for (const h of tokens) expect(r.t).not.toContain(h);
    }
  });
});
