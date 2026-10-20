// Phase C1.2: out-of-band notifications (RM-1), scoped login limits (RM-2), transaction watchdog + shadow audit
// evidence (RM-3), operator invitations / multi-owner recovery (R-1), and the migration rollback drill.
import { createHash, createHmac, randomBytes } from "node:crypto";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import pg from "pg";
import { appConfig, sentinelConfig, superuserConfig } from "../../scripts/env";
import { migrate } from "../../scripts/migrator";
import { ackWebhook, deliverOnce, signWebhook, watchdogOnce } from "../../scripts/sentinel";
import { parseShadowLog, reconcile, shadowKey } from "../../scripts/audit-shadow";
import {
  addCredential, adminWithSession, assertionParts, backdateDeliveries, createTestDb, deliverAll, enrolWithToken, lastAudit, login,
  loginToken, operatorFixture, ownerWithSession, resetRateLimits, stepup, type Operator, type TestDb,
} from "../helpers/db";
import { SoftAuthenticator } from "../helpers/softAuthenticator";

const sha = (s: string) => createHash("sha256").update(s).digest("hex");
const sentinelPool = (db: TestDb) => new pg.Pool({ ...sentinelConfig(), database: db.name, max: 2 });
const errCode = (p: Promise<unknown>) => p.then(() => "OK", (e: { code?: string }) => e.code);

async function invite(db: TestDb, owner: Operator, email: string, role: "owner" | "admin", name = "Invitee") {
  const s = await stepup(db, owner.token, owner.auth, "operator_invite", `${role}:${sha(email.toLowerCase())}`);
  if (!s.ok) return s;
  return db.api("api_operator_invite", owner.token, email, name, role);
}
async function inviteAndActivate(db: TestDb, owner: Operator, email: string, role: "owner" | "admin") {
  const inv = await invite(db, owner, email, role);
  const auth = new SoftAuthenticator();
  const e = await enrolWithToken(db, inv.enrolment_token, auth);
  await deliverAll(db);
  const ap = (await db.su.query("SELECT control.host_approve_operator($1, $2) AS r", [email, e.fingerprint])).rows[0].r;
  if (!ap.ok) throw new Error(`approve: ${ap.error}`);
  return { identityId: ap.identity_id as string, auth, token: await loginToken(db, auth) } as Operator;
}

// =====================================================================================================================
describe("RM-1 out-of-band notifications", () => {
  let db: TestDb; let owner: Operator;
  beforeAll(async () => { db = await createTestDb({ seed: true }); owner = await ownerWithSession(db); });
  afterAll(async () => { await db?.drop(); });
  beforeEach(async () => { await resetRateLimits(db); });

  it("notices are enqueued by the database in the SAME transaction as the audited effect", async () => {
    const c = await db.su.connect();
    try {
      const before = Number((await c.query("SELECT count(*) n FROM control.notify_outbox")).rows[0].n);
      await c.query("BEGIN");
      await c.query("SELECT control.audit_append('cli', NULL, 'x', 'platform.recovery_requested', 'success')");
      expect(Number((await c.query("SELECT count(*) n FROM control.notify_outbox")).rows[0].n)).toBe(before + 1);
      await c.query("ROLLBACK");
      expect(Number((await c.query("SELECT count(*) n FROM control.notify_outbox")).rows[0].n)).toBe(before);
    } finally { c.release(); }
  });

  it("a compromised app credential cannot read, skip, edit or fake notices, channels or deliveries", async () => {
    for (const sql of ["SELECT * FROM control.notify_outbox", "SELECT * FROM control.notify_channels", "SELECT * FROM control.notify_deliveries",
      "DELETE FROM control.notify_outbox", "UPDATE control.notify_deliveries SET delivered_at = now()",
      "SELECT * FROM control.sentinel_claim(10, NULL)", "SELECT control.sentinel_ack(1, 1, gen_random_uuid(), true, NULL)",
      "SELECT control.host_add_notify_channel('host', NULL, 'file', '/tmp/x', NULL)", "SELECT control.host_disable_notify_channel(1)",
      "SELECT control.notification_delivered('a','b','c')"]) {
      expect(await errCode(db.app.query(sql)), sql).toBe("42501");
    }
  });

  it("the sentinel credential can only claim/ack and run the watchdog", async () => {
    const sp = sentinelPool(db);
    try {
      const { rows } = await db.su.query(
        `SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
          WHERE n.nspname = 'control' AND has_function_privilege('control_sentinel', p.oid, 'EXECUTE') ORDER BY 1`);
      expect(rows.map((r) => r.proname)).toEqual(["sentinel_ack", "sentinel_claim", "sentinel_pending_channels",
        "watchdog_arm", "watchdog_execute", "watchdog_plan", "watchdog_reconcile"]);
      for (const sql of ["SELECT * FROM control.sessions", "SELECT * FROM control.notify_channels", "SELECT control.api_login_begin(NULL)",
        "SELECT control.host_approve_operator('a@example.invalid', 'x')", "UPDATE control.notify_deliveries SET delivered_at = now()"]) {
        expect(await errCode(sp.query(sql)), sql).toBe("42501");
      }
    } finally { await sp.end(); }
  });

  it("the outbox is append-only even for its owner path (superuser UPDATE refused by trigger)", async () => {
    expect(await errCode(db.su.query("UPDATE control.notify_outbox SET action = 'x'"))).toBe("42501");
    expect(await errCode(db.su.query("DELETE FROM control.notify_deliveries"))).toBe("42501");
  });

  it("RELAY: a redirected credential_add step-up and the rogue passkey are announced, and the passkey stays unusable until delivery", async () => {
    const rogue = new SoftAuthenticator();
    const r = await addCredential(db, owner.token, owner.auth, rogue, owner.identityId, "rogue");
    expect(r.ok).toBe(true);
    const { rows } = await db.su.query("SELECT action, payload->'detail'->>'action' AS a FROM control.notify_outbox ORDER BY id DESC LIMIT 2");
    expect(rows.map((x) => x.action).sort()).toEqual(["platform.credential_added", "platform.stepup_succeeded"]);
    await db.su.query("UPDATE control.webauthn_credentials SET usable_after = now() WHERE credential_id = $1", [rogue.id]);
    expect((await login(db, rogue)).error).toBe("CREDENTIAL_PENDING");     // delay passed, notice NOT delivered
    await deliverAll(db);
    expect((await login(db, rogue)).error).toBe("CREDENTIAL_PENDING");     // delivered: the reaction window starts NOW (217)
    await backdateDeliveries(db);
    expect((await login(db, rogue)).ok).toBe(true);
  });

  it("with NO channel configured, gated actions stay blocked (fail closed) and the host status shows it", async () => {
    const d = await createTestDb({ seed: false, notify: false });
    try {
      const o = await ownerWithSession(d);
      const k = new SoftAuthenticator();
      expect((await addCredential(d, o.token, o.auth, k, o.identityId)).ok).toBe(true);
      await d.su.query("UPDATE control.webauthn_credentials SET usable_after = now()");
      expect(await deliverAll(d)).toBe(0);
      expect((await login(d, k)).error).toBe("CREDENTIAL_PENDING");
      const st = (await d.su.query("SELECT control.host_notify_status() AS r")).rows[0].r;
      expect(st.notices_without_recipients).toBeGreaterThan(0);
    } finally { await d.drop(); }
  });

  it("webhook delivery is HMAC-signed with the host-only secret; a failing receiver, or one without a valid ack, keeps the gate closed", async () => {
    const received: { body: string; sig: string; ts: string }[] = [];
    let mode: "fail" | "noack" | "ack" = "fail";
    let secretBuf = Buffer.alloc(0);
    const srv = http.createServer((req, res) => {
      let body = ""; req.on("data", (c) => (body += c)); req.on("end", () => {
        const ts = String(req.headers["x-orvix-timestamp"]);
        received.push({ body, sig: String(req.headers["x-orvix-signature"]), ts });
        if (mode === "ack") res.setHeader("x-orvix-ack", ackWebhook(secretBuf, String(JSON.parse(body).notice_id), ts));
        res.statusCode = mode === "fail" ? 500 : 204; res.end();       // "noack": an impostor that just answers 204
      });
    });
    await new Promise<void>((r) => srv.listen(0, "127.0.0.1", r));
    const port = (srv.address() as { port: number }).port;
    const d = await createTestDb({ seed: false, notify: false });
    const sp = sentinelPool(d);
    try {
      const secret = randomBytes(32).toString("hex");
      secretBuf = Buffer.from(secret, "hex");
      expect((await d.su.query("SELECT control.host_add_notify_channel('host', NULL, 'webhook', $1, $2) AS r",
        [`http://127.0.0.1:${port}/hook`, secret])).rows[0].r.ok).toBe(true);
      const o = await ownerWithSession(d);
      const k = new SoftAuthenticator();
      expect((await addCredential(d, o.token, o.auth, k, o.identityId)).ok).toBe(true);
      await d.su.query("UPDATE control.webauthn_credentials SET usable_after = now()");
      const r1 = await deliverOnce(sp);
      expect(r1.failed).toBeGreaterThan(0);
      expect((await login(d, k)).error).toBe("CREDENTIAL_PENDING");          // receiver failed -> still gated
      const last = received.at(-1)!;
      expect(signWebhook(Buffer.from(secret, "hex"), last.ts, last.body)).toBe(last.sig);
      mode = "noack";
      await d.su.query("UPDATE control.notify_deliveries SET last_attempt_at = now() - interval '1 hour', claimed_until = NULL WHERE delivered_at IS NULL");
      const rn = await deliverOnce(sp);
      expect(rn).toMatchObject({ delivered: 0 });
      expect((await d.su.query("SELECT DISTINCT last_error FROM control.notify_deliveries WHERE delivered_at IS NULL")).rows.map((x) => x.last_error)).toEqual(["missing or invalid ack"]);
      mode = "ack";
      await d.su.query("UPDATE control.notify_deliveries SET last_attempt_at = now() - interval '1 hour', claimed_until = NULL WHERE delivered_at IS NULL");
      const r2 = await deliverOnce(sp);
      expect(r2.delivered).toBeGreaterThan(0);
      await backdateDeliveries(d);
      await resetRateLimits(d);
      expect((await login(d, k)).ok).toBe(true);
      expect(received.some((x) => JSON.parse(x.body).action === "platform.credential_added")).toBe(true);
    } finally { await sp.end(); await d.drop(); srv.close(); }
  });

  it("file channel delivery appends one JSON line per notice", async () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "orvix-notify-"));
    const file = path.join(dir, "notices.jsonl");
    const d = await createTestDb({ seed: false, notify: false });
    const sp = sentinelPool(d);
    try {
      await d.su.query("SELECT control.host_add_notify_channel('host', NULL, 'file', $1, NULL)", [file]);
      await ownerWithSession(d);
      await d.su.query("SELECT control.host_recovery_request('owner@example.invalid', 'synthetic file channel test')");
      await deliverOnce(sp);
      const lines = readFileSync(file, "utf8").split("\n").filter((l) => l.length > 0).map((l) => JSON.parse(l));   // C1.3: "\n" + JSON + "\n"
      expect(lines.map((l) => l.action)).toEqual(expect.arrayContaining(["platform.owner_enrolled", "platform.recovery_requested"]));
    } finally { await sp.end(); await d.drop(); }
  });

  it("a recovery link cannot be redeemed before the approval notice is delivered (token not consumed)", async () => {
    const d = await createTestDb({ seed: false });
    try {
      await ownerWithSession(d, "a@example.invalid");
      const b = await operatorFixture(d, "owner", "b@example.invalid");
      await d.su.query("UPDATE control.webauthn_credentials SET last_used_at = now() - interval '1 day'");
      const rq = (await d.su.query("SELECT control.host_recovery_request('a@example.invalid', 'lost device synthetic') AS r")).rows[0].r;
      expect((await stepup(d, b.token, b.auth, "recovery_approve", rq.request_id)).ok).toBe(true);
      const ap = await d.api("api_recovery_approve", b.token, rq.request_id);
      expect(ap.ok).toBe(true);
      const fresh = new SoftAuthenticator();
      expect((await enrolWithToken(d, ap.enrolment_token, fresh, "x", { deliver: false })).error).toBe("NOTIFICATION_PENDING");
      expect((await enrolWithToken(d, ap.enrolment_token, fresh, "x")).ok).toBe(true);   // delivers first
    } finally { await d.drop(); }
  });
});

// =====================================================================================================================
describe("RM-2 scoped login limits", () => {
  let db: TestDb; let owner: Operator; let device: string;
  beforeAll(async () => {
    db = await createTestDb({ seed: false });
    owner = await ownerWithSession(db);
    await resetRateLimits(db);
    const r = await login(db, owner.auth);
    device = r.device_token;
  });
  afterAll(async () => { await db?.drop(); });
  beforeEach(async () => { await resetRateLimits(db); });

  it("a successful login issues an opaque device token (hash stored) that carries no authentication power", async () => {
    expect(device).toMatch(/^[0-9a-f]{64}$/);
    expect((await db.su.query("SELECT count(*)::int n FROM control.login_devices WHERE token_hash = sha256(convert_to($1,'UTF8'))", [device])).rows[0].n).toBe(1);
    expect((await db.api("api_session_get", device)).ok).toBe(false);
  });

  it("an anonymous flood exhausts only the anonymous bucket; a known device still signs in", async () => {
    const out: boolean[] = [];
    for (let i = 0; i < 25; i++) out.push((await db.api("api_login_begin", null)).ok);
    expect(out.filter(Boolean)).toHaveLength(20);
    const b = await db.api("api_login_begin", device);
    expect(b).toMatchObject({ ok: true, scope: "device" });
    const a = assertionParts(owner.auth.assert({ challenge: b.challenge }));
    expect((await db.api("api_login_complete", a.id, a.cdj, a.ad, a.sig, device)).ok).toBe(true);
  });

  it("a device bucket is itself limited, and forged/garbage device tokens fall back to anonymous", async () => {
    const out: boolean[] = [];
    for (let i = 0; i < 12; i++) out.push((await db.api("api_login_begin", device)).ok);
    expect(out.filter(Boolean)).toHaveLength(10);
    expect((await db.api("api_login_begin", "f".repeat(64))).scope).toBe("anonymous");
    expect((await db.api("api_login_begin", "not-a-token")).scope).toBe("anonymous");
  });

  it("a hard ceiling on outstanding login challenges bounds total creation across all buckets", async () => {
    await db.su.query("UPDATE control.settings SET value = '5' WHERE key = 'login_challenge_ceiling'");
    await db.su.query("UPDATE control.webauthn_challenges SET used_at = now() WHERE purpose = 'login' AND used_at IS NULL");
    try {
      for (let i = 0; i < 5; i++) expect((await db.api("api_login_begin", null)).ok).toBe(true);
      expect((await db.api("api_login_begin", null)).error).toBe("RATE_LIMITED");
      expect((await db.api("api_login_begin", device)).error).toBe("RATE_LIMITED");
    } finally {
      await db.su.query("UPDATE control.settings SET value = '500' WHERE key = 'login_challenge_ceiling'");
    }
  });

  it("devices of a revoked identity are not honoured", async () => {
    const d = await createTestDb({ seed: false });
    try {
      await ownerWithSession(d, "a@example.invalid");
      const b = await operatorFixture(d, "owner", "b@example.invalid");
      await resetRateLimits(d);
      const dev = (await login(d, b.auth)).device_token;
      expect((await d.api("api_login_begin", dev)).scope).toBe("device");
      await d.su.query("SELECT control.host_revoke_operator_credentials('b@example.invalid', 'device test revoke')");
      await d.su.query("UPDATE control.platform_identities SET state = 'revoked' WHERE email = 'b@example.invalid'");
      expect((await d.api("api_login_begin", dev)).scope).toBe("anonymous");
    } finally { await d.drop(); }
  });
});

// =====================================================================================================================
describe("RM-3 open transactions: watchdog and shadow audit evidence", () => {
  let db: TestDb; let owner: Operator;
  beforeAll(async () => { db = await createTestDb({ seed: false }); owner = await ownerWithSession(db); });
  afterAll(async () => { await db?.drop(); });

  it("the watchdog terminates a control_app session holding the audit lock open; audited calls then proceed", async () => {
    const holder = await db.app.connect();
    holder.on("error", () => {});
    const sp = sentinelPool(db);
    try {
      await holder.query("SET idle_in_transaction_session_timeout = 0; SET transaction_timeout = 0");   // attacker overrides defaults
      await holder.query("BEGIN");
      await holder.query("SELECT control.api_credential_add_begin($1)", [owner.token]);              // audited -> holds audit lock
      expect(await errCode(db.app.query("SELECT control.api_audit_verify($1)", [owner.token]))).toBe("55P03");
      await new Promise((r) => setTimeout(r, 2500));
      expect(await watchdogOnce(sp, 2, 15)).toBe(1);
      expect((await db.api("api_audit_verify", owner.token)).ok).toBe(true);
      const ev = (await lastAudit(db, 5)).find((e) => e.action === "platform.watchdog_terminated");
      expect(ev?.detail.state).toBe("terminated");
      // one intent per acted-on backend (the C1.3 successor sweep may add one for a queued backend); all resolved + chained
      expect((await db.su.query("SELECT count(*)::int n FROM control.notify_outbox WHERE action = 'platform.watchdog_intent'")).rows[0].n).toBeGreaterThanOrEqual(1);
      expect((await db.su.query("SELECT count(*)::int n FROM control.watchdog_intents WHERE state IN ('planned', 'armed') OR audit_seq IS NULL")).rows[0].n).toBe(0);
      expect((await db.su.query("SELECT count(*)::int n FROM control.notify_outbox WHERE action = 'platform.watchdog_terminated'")).rows[0].n).toBe(1);
    } finally { holder.release(true); await sp.end(); }
  }, 20_000);

  it("the watchdog never touches sessions of other roles", async () => {
    const su = await db.su.connect();
    const sp = sentinelPool(db);
    try {
      await su.query("BEGIN"); await su.query("SELECT 1");
      await new Promise((r) => setTimeout(r, 2500));
      expect(await watchdogOnce(sp, 2, 2)).toBe(0);
      await su.query("ROLLBACK");
    } finally { su.release(); await sp.end(); }
  }, 20_000);

  it("INHERENT: control_app can override its own timeout defaults (hence the watchdog), but not logging or another role's limits", async () => {
    const c = await db.app.connect();
    try {
      expect((await c.query("SHOW transaction_timeout")).rows[0].transaction_timeout).toBe("10s");
      await c.query("SET transaction_timeout = 0");
      expect((await c.query("SHOW transaction_timeout")).rows[0].transaction_timeout).toBe("0");
      expect(await errCode(c.query("SET log_min_messages = 'panic'"))).toBe("42501");
      expect(await errCode(c.query("SET temp_file_limit = -1"))).toBe("42501");
      expect(await errCode(c.query("SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE usename = 'control_sentinel'"))).not.toBe("XX000");
    } finally { c.release(); }
  });

  it("a refusal hidden by ROLLBACK is absent from the table but recorded in the server log, and reconciliation reports it", async () => {
    const since = new Date(Date.now() - 1000).toISOString();
    const c = await db.app.connect();
    try {
      await c.query("BEGIN");
      const r = (await c.query("SELECT control.api_credential_add_begin($1) AS r", [owner.token])).rows[0].r;
      expect(r.error).toBe("STEPUP_REQUIRED");
      await c.query("ROLLBACK");
    } finally { c.release(); }
    const count = (await db.su.query("SELECT count(*)::int n FROM control.audit_events WHERE action = 'platform.credential_add_failed'")).rows[0].n;
    expect(count).toBe(0);
    await new Promise((r) => setTimeout(r, 500));
    const log = spawnSync("docker", ["logs", "--since", since, "orvix-control-db"], { encoding: "utf8" });
    const shadows = parseShadowLog(`${log.stdout}\n${log.stderr}`, await shadowKey(db.su), db.name).lines
      .filter((s) => s.action === "platform.credential_add_failed" && s.actor_id === owner.identityId);
    expect(shadows.length).toBeGreaterThanOrEqual(1);
    const rec = await reconcile(db.su, shadows);
    expect(rec.rolledBack.map((s) => s.shadow_id)).toEqual(shadows.map((s) => s.shadow_id));
    expect(rec.rolledBack[0]!.session_user).toBe("control_app");
  });

  it("committed audit rows carry the shadow id found in the log", async () => {
    const since = new Date(Date.now() - 1000).toISOString();
    await db.api("api_audit_verify", owner.token);
    await new Promise((r) => setTimeout(r, 500));
    const log = spawnSync("docker", ["logs", "--since", since, "orvix-control-db"], { encoding: "utf8" });
    const shadows = parseShadowLog(`${log.stdout}\n${log.stderr}`, await shadowKey(db.su), db.name).lines
      .filter((s) => s.action === "audit.verified" && s.actor_id === owner.identityId);
    const rec = await reconcile(db.su, shadows);
    expect(rec.committed).toBe(shadows.length);
    expect(rec.rolledBack).toEqual([]);
  });
});

// =====================================================================================================================
describe("R-1 operator invitations and multi-owner recovery", () => {
  let db: TestDb; let a: Operator;
  beforeAll(async () => { db = await createTestDb({ seed: false }); a = await ownerWithSession(db, "a@example.invalid"); });
  afterAll(async () => { await db?.drop(); });
  beforeEach(async () => { await resetRateLimits(db); });

  it("only owners can invite, with a step-up bound to that role AND that email", async () => {
    const admin = await adminWithSession(db);
    expect((await invite(db, admin, "x@example.invalid", "owner")).error).toBe("FORBIDDEN");
    expect((await db.api("api_operator_invite", a.token, "x@example.invalid", "X", "owner")).error).toBe("STEPUP_REQUIRED");
    expect((await stepup(db, a.token, a.auth, "operator_invite", `admin:${sha("x@example.invalid")}`)).ok).toBe(true);
    expect((await db.api("api_operator_invite", a.token, "x@example.invalid", "X", "owner")).error).toBe("STEPUP_REQUIRED"); // role differs
    expect((await stepup(db, a.token, a.auth, "operator_invite", `owner:${sha("y@example.invalid")}`)).ok).toBe(true);
    expect((await db.api("api_operator_invite", a.token, "x@example.invalid", "X", "owner")).error).toBe("STEPUP_REQUIRED"); // email differs
  });

  it("an invited owner is NOT active until the host approves with the right fingerprint after delivery", async () => {
    const inv = await invite(db, a, "b@example.invalid", "owner");
    expect(inv.ok).toBe(true);
    const kb = new SoftAuthenticator();
    const e = await enrolWithToken(db, inv.enrolment_token, kb, "b-key", { deliver: false });
    expect(e).toMatchObject({ ok: true, purpose: "invite", awaiting_host_approval: true });
    expect((await login(db, kb)).error).toBe("IDENTITY_INACTIVE");
    const approve = async (fp: string) => (await db.su.query("SELECT control.host_approve_operator('b@example.invalid', $1) AS r", [fp])).rows[0].r;
    expect((await approve("xxxxxxxx")).error).toBe("FINGERPRINT_MISMATCH");
    expect((await approve(e.fingerprint)).error).toBe("NOTIFICATION_PENDING");
    await deliverAll(db);
    expect(await approve(e.fingerprint)).toMatchObject({ ok: true, role: "owner" });
    expect((await login(db, kb)).ok).toBe(true);
    const actions = (await db.su.query("SELECT action FROM control.notify_outbox ORDER BY id")).rows.map((r) => r.action);
    expect(actions).toEqual(expect.arrayContaining(["platform.operator_invited", "platform.operator_enrolled", "platform.operator_approved"]));
    expect(await errCode(db.app.query("SELECT control.host_approve_operator('b@example.invalid', 'x')"))).toBe("42501");
  });

  it("forged, replayed, expired and revoked invitation links are refused", async () => {
    expect((await enrolWithToken(db, randomBytes(32).toString("hex"), new SoftAuthenticator())).error).toBe("INVALID_TOKEN");
    const inv = await invite(db, a, "c@example.invalid", "admin");
    expect((await enrolWithToken(db, inv.enrolment_token, new SoftAuthenticator())).ok).toBe(true);
    expect((await enrolWithToken(db, inv.enrolment_token, new SoftAuthenticator())).error).toBe("INVALID_TOKEN");   // replay
    const inv2 = await invite(db, a, "d@example.invalid", "admin");
    await db.su.query("UPDATE control.operator_invitations SET expires_at = now() - interval '1 second' WHERE id = $1", [inv2.invitation_id]);
    expect((await enrolWithToken(db, inv2.enrolment_token, new SoftAuthenticator())).error).toBe("INVALID_TOKEN");  // expired
    const inv3 = await invite(db, a, "e@example.invalid", "admin");
    expect((await stepup(db, a.token, a.auth, "operator_invite", `revoke:${inv3.invitation_id}`)).ok).toBe(true);
    expect((await db.api("api_operator_invite_revoke", a.token, inv3.invitation_id)).ok).toBe(true);
    expect((await enrolWithToken(db, inv3.enrolment_token, new SoftAuthenticator())).error).toBe("INVALID_TOKEN");  // revoked
    expect((await db.su.query("SELECT state FROM control.platform_identities WHERE email = 'e@example.invalid'")).rows[0].state).toBe("revoked");
  });

  it("an admin invitation cannot become an owner; an invited admin cannot invite", async () => {
    const adm = await inviteAndActivate(db, a, "f@example.invalid", "admin");
    expect((await db.su.query("SELECT role FROM control.platform_identities WHERE id = $1", [adm.identityId])).rows[0].role).toBe("admin");
    expect((await invite(db, adm, "g@example.invalid", "owner")).error).toBe("FORBIDDEN");
  });

  it("concurrent redemption of one link: exactly one enrolment succeeds", async () => {
    const inv = await invite(db, a, "h@example.invalid", "admin");
    await deliverAll(db);
    const [k1, k2] = [new SoftAuthenticator(), new SoftAuthenticator()];
    const b1 = await db.api("api_enrol_begin", inv.enrolment_token);
    const b2 = await db.api("api_enrol_begin", inv.enrolment_token);
    const r1 = k1.register({ challenge: b1.challenge, user: { id: "eA" } });
    const r2 = k2.register({ challenge: b2.challenge, user: { id: "eA" } });
    const B = (s: string) => Buffer.from(s, "base64url");
    const pools = [0, 1].map(() => new pg.Pool({ ...appConfig(), database: db.name, max: 1 }));
    const res = await Promise.all([[r1, pools[0]!], [r2, pools[1]!]].map(([r, p]) => (p as pg.Pool).query(
      "SELECT control.api_enrol_complete($1, $2, $3, 'x') AS r",
      [inv.enrolment_token, B((r as typeof r1).response.attestationObject), B((r as typeof r1).response.clientDataJSON)]).then((q) => q.rows[0].r)));
    await Promise.all(pools.map((p) => p.end()));
    expect(res.filter((r) => r.ok)).toHaveLength(1);
    expect((await db.su.query("SELECT count(*)::int n FROM control.webauthn_credentials w JOIN control.platform_identities i ON i.id = w.identity_id WHERE i.email = 'h@example.invalid'")).rows[0].n).toBe(1);
  });

  it("concurrent invitations for the same email: exactly one succeeds", async () => {
    const email = "i@example.invalid";
    for (let n = 0; n < 2; n++) expect((await stepup(db, a.token, a.auth, "operator_invite", `admin:${sha(email)}`)).ok).toBe(true);
    const pools = [0, 1].map(() => new pg.Pool({ ...appConfig(), database: db.name, max: 1 }));
    const res = await Promise.all(pools.map((p) => p.query("SELECT control.api_operator_invite($1, $2, 'I', 'admin') AS r", [a.token, email]).then((q) => q.rows[0].r)));
    await Promise.all(pools.map((p) => p.end()));
    expect(res.filter((r) => r.ok)).toHaveLength(1);
    expect(res.find((r) => !r.ok)?.error).toBe("ALREADY_EXISTS");
  });

  it("the host cannot approve an invitee whose inviter is no longer an active owner", async () => {
    const d = await createTestDb({ seed: false });
    try {
      const o1 = await ownerWithSession(d, "o1@example.invalid");
      const o2 = await inviteAndActivate(d, o1, "o2@example.invalid", "owner");
      const inv = await invite(d, o2, "o3@example.invalid", "admin");
      const e = await enrolWithToken(d, inv.enrolment_token, new SoftAuthenticator());
      await deliverAll(d);
      await d.su.query("UPDATE control.platform_identities SET state = 'revoked' WHERE email = 'o2@example.invalid'");
      expect((await d.su.query("SELECT control.host_approve_operator('o3@example.invalid', $1) AS r", [e.fingerprint])).rows[0].r.error).toBe("INVITER_INACTIVE");
    } finally { await d.drop(); }
  });

  it("REAL HOST PATH: emergency-revoking the inviter voids its open invitations (link and pending activation) (217)", async () => {
    const d = await createTestDb({ seed: false });
    try {
      const o1 = await ownerWithSession(d, "o1@example.invalid");
      const o2 = await inviteAndActivate(d, o1, "o2@example.invalid", "owner");
      const enrolled = await invite(d, o2, "o3@example.invalid", "owner");
      const e = await enrolWithToken(d, enrolled.enrolment_token, new SoftAuthenticator());
      const unused = await invite(d, o2, "o4@example.invalid", "admin");
      await deliverAll(d);
      const rv = (await d.su.query("SELECT control.host_revoke_operator_credentials('o2@example.invalid', 'stolen device synthetic') AS r")).rows[0].r;
      expect(rv).toMatchObject({ ok: true, invitations_voided: 2 });
      expect((await d.su.query("SELECT control.host_approve_operator('o3@example.invalid', $1) AS r", [e.fingerprint])).rows[0].r.error).toBe("NOT_FOUND");
      expect((await enrolWithToken(d, unused.enrolment_token, new SoftAuthenticator())).error).toBe("INVALID_TOKEN");
      const ev = (await d.su.query("SELECT reason_code FROM control.audit_events WHERE action = 'platform.operator_invite_revoked'")).rows;
      expect(ev.map((x) => x.reason_code)).toEqual(["INVITER_REVOKED", "INVITER_REVOKED"]);
    } finally { await d.drop(); }
  });

  it("MULTI-OWNER RECOVERY: an owner whose passkey is unavailable is recovered by the invited second owner", async () => {
    const d = await createTestDb({ seed: false });
    try {
      const o1 = await ownerWithSession(d, "o1@example.invalid");
      const o2 = await inviteAndActivate(d, o1, "o2@example.invalid", "owner");
      // o1 loses the device: the host locks the old passkey out (stolen-device path) and files a request
      expect((await d.su.query("SELECT control.host_revoke_operator_credentials('o1@example.invalid', 'laptop stolen synthetic') AS r")).rows[0].r.ok).toBe(true);
      const rq = (await d.su.query("SELECT control.host_recovery_request('o1@example.invalid', 'laptop stolen synthetic') AS r")).rows[0].r;
      expect((await stepup(d, o2.token, o2.auth, "recovery_approve", rq.request_id)).ok).toBe(true);
      expect((await d.api("api_recovery_approve", o2.token, rq.request_id)).error).toBe("RECOVERY_CONTESTED");  // revoke => contested
      await d.su.query("UPDATE control.platform_identities SET emergency_revoked_at = emergency_revoked_at - interval '13 hours' WHERE email = 'o1@example.invalid'");
      await d.su.query("UPDATE control.recovery_requests SET requested_at = requested_at - interval '13 hours' WHERE id = $1", [rq.request_id]);
      await d.su.query("SELECT control.host_recovery_confirm($1)", [rq.request_id]);
      expect((await stepup(d, o2.token, o2.auth, "recovery_approve", rq.request_id)).ok).toBe(true);
      const ap = await d.api("api_recovery_approve", o2.token, rq.request_id);
      expect(ap.ok).toBe(true);
      const fresh = new SoftAuthenticator();
      expect((await enrolWithToken(d, ap.enrolment_token, fresh)).ok).toBe(true);
      await resetRateLimits(d);
      expect((await login(d, fresh)).ok).toBe(true);
    } finally { await d.drop(); }
  });

  it("LOCKOUT GUARDS: a pending (unapproved) owner does not count for LAST_OWNER; with both owners active, one can be revoked", async () => {
    const d = await createTestDb({ seed: false });
    try {
      const o1 = await ownerWithSession(d, "o1@example.invalid");
      const inv = await invite(d, o1, "o2@example.invalid", "owner");
      await enrolWithToken(d, inv.enrolment_token, new SoftAuthenticator());
      expect((await d.su.query("SELECT control.host_revoke_operator_credentials('o1@example.invalid', 'lockout guard test') AS r")).rows[0].r.error).toBe("LAST_OWNER");
      const e2 = (await d.su.query("SELECT control.credential_fingerprint(w.public_key) fp FROM control.webauthn_credentials w JOIN control.platform_identities i ON i.id = w.identity_id WHERE i.email = 'o2@example.invalid'")).rows[0].fp;
      await deliverAll(d);
      expect((await d.su.query("SELECT control.host_approve_operator('o2@example.invalid', $1) AS r", [e2])).rows[0].r.ok).toBe(true);
      expect((await d.su.query("SELECT control.host_revoke_operator_credentials('o1@example.invalid', 'lockout guard test') AS r")).rows[0].r.ok).toBe(true);
    } finally { await d.drop(); }
  });
});

// =====================================================================================================================
describe("migration upgrade and rollback drill (forward-only migrations + restore point)", () => {
  it("dump at 211 -> upgrade to 216 -> restore the dump: the 211 state and audit chain return intact; re-upgrade works", async () => {
    const d = await createTestDb({ seed: true, upTo: "211" });
    const restored = `orvix_control_test_${randomBytes(5).toString("hex")}`;
    const dir = mkdtempSync(path.join(os.tmpdir(), "orvix-dump-"));
    const dump = path.join(dir, "pre.dump");
    try {
      await d.su.query("SELECT control.host_bootstrap_owner('owner@example.invalid', 'Owner')");
      const head211 = (await d.su.query("SELECT seq::int s, encode(row_hash,'hex') h FROM control.audit_events ORDER BY seq DESC LIMIT 1")).rows[0];
      const out = execFileSync("docker", ["exec", "orvix-control-db", "pg_dump", "-U", "orvix_control_super", "-Fc", d.name], { maxBuffer: 64 << 20 });
      writeFileSync(dump, out);
      const c = new pg.Client({ ...superuserConfig(), database: d.name }); await c.connect();
      const { applied } = await migrate(c); await c.end();
      expect(applied).toEqual(["212_oob_notifications.sql", "213_scoped_login_limits.sql", "214_txn_watchdog_shadow_audit.sql",
        "215_operator_invitations.sql", "216_review_211_fixes.sql", "217_review_c1_2_fixes.sql",
        "218_watchdog_intents.sql", "219_recovery_auth_hardening.sql", "220_sentinel_delivery.sql", "221_privileges_tenant_contract.sql"]);
      // "rollback": restore the pre-upgrade dump into a fresh database
      const admin = new pg.Client({ ...superuserConfig(), database: "orvix_control" }); await admin.connect();
      await admin.query(`CREATE DATABASE ${restored}`); await admin.end();
      execFileSync("docker", ["exec", "-i", "orvix-control-db", "pg_restore", "-U", "orvix_control_super", "-d", restored],
        { input: readFileSync(dump) });
      const r = new pg.Client({ ...superuserConfig(), database: restored }); await r.connect();
      try {
        expect((await r.query("SELECT max(version) v FROM control_ledger.schema_migrations")).rows[0].v).toBe("211");
        expect((await r.query("SELECT to_regclass('control.notify_outbox') AS t")).rows[0].t).toBeNull();
        expect((await r.query("SELECT max(seq)::int s FROM control.audit_events")).rows[0].s).toBe(head211.s);
        expect((await r.query("SELECT * FROM control.audit_verify()")).rows[0].ok).toBe(true);
        const re = await migrate(r);
        expect(re.applied).toHaveLength(10);
        expect((await r.query("SELECT * FROM control.audit_verify()")).rows[0].ok).toBe(true);
      } finally { await r.end(); }
    } finally {
      const admin = new pg.Client({ ...superuserConfig(), database: "orvix_control" }); await admin.connect();
      await admin.query(`DROP DATABASE IF EXISTS ${restored} WITH (FORCE)`); await admin.end();
      await d.drop();
    }
  }, 60_000);
});

describe("211 review fixes (216)", () => {
  it("passkey ACTIVITY during an earlier request still contests a re-filed request", async () => {
    const d = await createTestDb({ seed: false });
    try {
      const s1 = await ownerWithSession(d, "s@example.invalid");
      const o = await operatorFixture(d, "owner", "o@example.invalid");
      const r1 = (await d.su.query("SELECT control.host_recovery_request('s@example.invalid', 'first synthetic request') AS r")).rows[0].r;
      await resetRateLimits(d);
      expect((await login(d, s1.auth)).ok).toBe(true);                       // activity during R1
      await d.su.query("SELECT control.host_recovery_cancel($1)", [r1.request_id]);
      const r2 = (await d.su.query("SELECT control.host_recovery_request('s@example.invalid', 'second synthetic request') AS r")).rows[0].r;
      expect((await stepup(d, o.token, o.auth, "recovery_approve", r2.request_id)).ok).toBe(true);
      expect((await d.api("api_recovery_approve", o.token, r2.request_id)).error).toBe("RECOVERY_CONTESTED");
    } finally { await d.drop(); }
  });

  it("owner-count guards refuse to run outside READ COMMITTED", async () => {
    const d = await createTestDb({ seed: false });
    try {
      await ownerWithSession(d, "a@example.invalid");
      await operatorFixture(d, "owner", "b@example.invalid");
      const c = await d.su.connect();
      try {
        await c.query("BEGIN ISOLATION LEVEL REPEATABLE READ");
        const e = await c.query("SELECT control.host_revoke_operator_credentials('a@example.invalid', 'isolation test x')").catch((x) => x);
        expect(e.message).toMatch(/READ_COMMITTED_REQUIRED/);
        await c.query("ROLLBACK");
      } finally { c.release(); }
    } finally { await d.drop(); }
  });
});

describe("C1.2 role invariants (sentinel + watchdog owner)", () => {
  let db: TestDb;
  beforeAll(async () => { db = await createTestDb({ seed: false }); });
  afterAll(async () => { await db?.drop(); });

  it("control_sentinel: LOGIN, NOINHERIT, no memberships, no superuser powers; control_watchdog_owner: NOLOGIN, exactly two built-in memberships", async () => {
    const { rows } = await db.su.query(`SELECT rolname, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolcanlogin, rolinherit, rolconnlimit
      FROM pg_roles WHERE rolname IN ('control_sentinel', 'control_watchdog_owner') ORDER BY 1`);
    expect(rows).toEqual([
      { rolname: "control_sentinel", rolsuper: false, rolbypassrls: false, rolcreaterole: false, rolcreatedb: false, rolcanlogin: true, rolinherit: false, rolconnlimit: 12 },
      { rolname: "control_watchdog_owner", rolsuper: false, rolbypassrls: false, rolcreaterole: false, rolcreatedb: false, rolcanlogin: false, rolinherit: true, rolconnlimit: -1 },
    ]);
    const m = await db.su.query(`SELECT r.rolname AS role, m.rolname AS member FROM pg_auth_members a
      JOIN pg_roles r ON r.oid = a.roleid JOIN pg_roles m ON m.oid = a.member
      WHERE m.rolname LIKE 'control_%' OR r.rolname LIKE 'control_%' ORDER BY 1, 2`);
    expect(m.rows).toEqual([
      { role: "pg_read_all_stats", member: "control_watchdog_owner" },
      { role: "pg_signal_backend", member: "control_watchdog_owner" },
    ]);
    const owned = await db.su.query(`SELECT p.proname FROM pg_proc p WHERE pg_get_userbyid(p.proowner) = 'control_watchdog_owner'`);
    expect(owned.rows.map((r) => r.proname).sort()).toEqual(["watchdog_arm", "watchdog_assert_own_transaction", "watchdog_execute", "watchdog_plan", "watchdog_reconcile"]);
  });

  it("no runtime role (incl. the sentinel) can execute an invoker-rights function owned by a different runtime role", async () => {
    const { rows } = await db.su.query(
      `SELECT r.rolname AS caller, p.proname, pg_get_userbyid(p.proowner) AS owner
         FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace CROSS JOIN pg_roles r
        WHERE n.nspname = 'control' AND NOT p.prosecdef
          AND r.rolname IN ('control_app', 'control_auth', 'control_definer', 'control_audit_owner', 'control_sentinel', 'control_watchdog_owner')
          AND has_function_privilege(r.oid, p.oid, 'EXECUTE')
          AND pg_get_userbyid(p.proowner) NOT IN (r.rolname, 'control_schema_owner')`);
    expect(rows).toEqual([]);
  });

  it("control_app cannot run the watchdog or any sentinel/host function, and no new role has CREATE anywhere", async () => {
    for (const fn of ["watchdog_execute", "watchdog_plan", "sentinel_claim", "sentinel_ack", "host_add_notify_channel", "host_approve_operator", "host_notify_status"]) {
      const { rows } = await db.su.query(`SELECT bool_or(has_function_privilege('control_app', p.oid, 'EXECUTE')) x
        FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname = 'control' AND p.proname = $1`, [fn]);
      expect(rows[0].x, fn).toBe(false);
    }
    const { rows } = await db.su.query(`SELECT r.rolname, n.nspname FROM pg_namespace n CROSS JOIN pg_roles r
      WHERE r.rolname IN ('control_sentinel', 'control_watchdog_owner') AND n.nspname NOT LIKE 'pg_%' AND n.nspname <> 'information_schema'
        AND has_schema_privilege(r.oid, n.oid, 'CREATE')`);
    expect(rows).toEqual([]);
  });
});

// =====================================================================================================================
describe("C1.2 review fixes (217)", () => {
  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

  it("H1: a queued control_app backend that inherits the audit lock cannot stall or crash the watchdog", async () => {
    const d = await createTestDb({ seed: false });
    const o = await ownerWithSession(d);
    const sp = sentinelPool(d);
    const [ca, cb] = [await d.app.connect(), await d.app.connect()];
    for (const c of [ca, cb]) c.on("error", () => {});
    try {
      for (const c of [ca, cb]) {
        await c.query("SET idle_in_transaction_session_timeout = 0; SET transaction_timeout = 0; SET lock_timeout = 0; SET statement_timeout = 0");
        await c.query("BEGIN");
      }
      await ca.query("SELECT control.api_credential_add_begin($1)", [o.token]);          // A holds the audit lock, idles
      const queued = cb.query("SELECT control.api_audit_verify($1)", [o.token]).catch(() => null); // B queues on the lock
      await sleep(2500);
      const t0 = Date.now();
      // C1.3 protocol: the kill is never stalled by the audit lock. B (queued behind A) is caught by the successor sweep
      // in the same pass, or as an idle-in-transaction holder by the next pass; every pass is bounded.
      let n = await watchdogOnce(sp, 2, 15);
      expect(Date.now() - t0).toBeLessThan(9000);
      await sleep(2500);
      const t1 = Date.now();
      n += await watchdogOnce(sp, 2, 15);
      expect(Date.now() - t1).toBeLessThan(9000);
      expect(n).toBeGreaterThanOrEqual(2);
      await queued;
      await watchdogOnce(sp, 2, 15);                    // fold anything left once the lock is free
      const evs = (await d.su.query("SELECT count(*)::int n FROM control.audit_events WHERE action = 'platform.watchdog_terminated'")).rows[0].n;
      expect(evs).toBeGreaterThanOrEqual(2);
      expect((await d.api("api_audit_verify", o.token)).ok).toBe(true);
    } finally { ca.release(true); cb.release(true); await sp.end(); await d.drop(); }
  }, 30_000);

  it("H1 (re-review, C1.3 protocol): the intent and its notice are written WITHOUT the audit lock and folded into the chain later", async () => {
    const d = await createTestDb({ seed: false });
    const sp = sentinelPool(d);
    const stale = await d.app.connect();
    stale.on("error", () => {});
    const lockHolder = await d.su.connect();       // stands in for any backend the watchdog does not kill holding the lock
    try {
      await stale.query("SET idle_in_transaction_session_timeout = 0; SET transaction_timeout = 0");
      await stale.query("BEGIN"); await stale.query("SELECT control.api_contract_version()");
      await lockHolder.query("BEGIN"); await lockHolder.query("SELECT 1 FROM control.audit_lock FOR UPDATE");
      await sleep(2500);
      expect(await watchdogOnce(sp, 2, 15)).toBe(1);
      const k = (await d.su.query("SELECT state, audit_seq FROM control.watchdog_intents")).rows;
      expect(k).toEqual([{ state: "terminated", audit_seq: null }]);
      const o = (await d.su.query("SELECT count(*)::int n FROM control.notify_outbox WHERE action = 'platform.watchdog_intent' AND audit_seq IS NULL")).rows[0].n;
      expect(o).toBe(1);                              // announced BEFORE the kill, even though the audit lock was held
      expect((await d.su.query("SELECT control.host_notify_status() AS r")).rows[0].r.watchdog.not_in_chain).toBe(1);
      await lockHolder.query("ROLLBACK");
      expect(await watchdogOnce(sp, 2, 15)).toBe(0);  // next pass folds the intent into the hash chain
      expect((await d.su.query("SELECT audit_seq FROM control.watchdog_intents")).rows[0].audit_seq).not.toBeNull();
      expect((await d.su.query("SELECT count(*)::int n FROM control.notify_outbox WHERE action = 'platform.watchdog_terminated'")).rows[0].n).toBe(1);
      expect((await d.su.query("SELECT * FROM control.audit_verify()")).rows[0].ok).toBe(true);
    } finally { stale.release(true); lockHolder.release(); await sp.end(); await d.drop(); }
  }, 30_000);

  it("H1: the watchdog only acts on control_app sessions of its own database", async () => {
    const [d1, d2] = [await createTestDb({ seed: false }), await createTestDb({ seed: false })];
    const sp = sentinelPool(d1);
    const other = await d2.app.connect();
    other.on("error", () => {});
    try {
      await other.query("SET idle_in_transaction_session_timeout = 0; SET transaction_timeout = 0");
      await other.query("BEGIN"); await other.query("SELECT control.api_contract_version()");
      await sleep(2500);
      expect(await watchdogOnce(sp, 2, 5)).toBe(0);
      expect((await other.query("SELECT 1 AS x")).rows[0].x).toBe(1);
      await other.query("ROLLBACK");
    } finally { other.release(true); await sp.end(); await d1.drop(); await d2.drop(); }
  }, 30_000);

  it("H2: control_app cannot run DO blocks; forged shadow lines are rejected and counted, genuine ones verify", async () => {
    const d = await createTestDb({ seed: false });
    try {
      const o = await ownerWithSession(d);
      expect(await errCode(d.app.query("DO $$ BEGIN RAISE LOG 'ORVIX_AUDIT_SHADOW x'; END $$"))).toBe("42501");
      const since = new Date(Date.now() - 1000).toISOString();
      const fakeId = "deadbeef-0000-4000-8000-00000000a001";
      const fake = JSON.stringify({ shadow_id: fakeId, db: d.name, xid: 1, at: "x", session_user: "control_sentinel", action: "platform.owner_enrolled" });
      // statement echo of a failing statement whose text carries a forged line
      await d.app.query(`SELECT 1/0 -- \nORVIX_AUDIT_SHADOW ${"a".repeat(64)} ${fake}`).catch(() => null);
      await d.api("api_audit_verify", o.token);
      await sleep(500);
      const log = spawnSync("docker", ["logs", "--since", since, "orvix-control-db"], { encoding: "utf8" });
      const key = await shadowKey(d.su);
      const p = parseShadowLog(`${log.stdout}\n${log.stderr}`, key, d.name);
      expect(p.forged).toBeGreaterThanOrEqual(1);
      expect(p.lines.some((s) => s.shadow_id === fakeId)).toBe(false);
      expect(p.lines.some((s) => s.action === "audit.verified" && s.actor_id === o.identityId)).toBe(true);
      // unit: a genuine-MAC line for another database is ignored as foreign, a bad MAC naming this database is forged
      const mk = (json: string, k: Buffer) => `x LOG:  ORVIX_AUDIT_SHADOW ${createHmacHex(k, json)} ${json}`;
      const other = JSON.stringify({ shadow_id: fakeId, db: "orvix_control_test_other00" });
      const t = [mk(other, randomBytes(32)), mk(JSON.stringify({ shadow_id: fakeId, db: d.name }), randomBytes(32)),
                 "ORVIX_AUDIT_SHADOW {\"shadow_id\":\"------------------------------------\"}"].join("\n");
      expect(parseShadowLog(t, key, d.name)).toEqual({ lines: [], forged: 1, foreign: 1, legacy: 1, malformed: 0 });
      expect(await errCode(d.app.query("SELECT * FROM control.audit_shadow_key"))).toBe("42501");
    } finally { await d.drop(); }
  });

  it("MED: the activation fingerprint is derived from the PUBLIC KEY; the credential-id prefix no longer matches", async () => {
    const d = await createTestDb({ seed: false });
    try {
      const o1 = await ownerWithSession(d, "o1@example.invalid");
      const inv = await invite(d, o1, "o2@example.invalid", "owner");
      const k = new SoftAuthenticator();
      const e = await enrolWithToken(d, inv.enrolment_token, k);
      expect(e.fingerprint).toMatch(/^[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}$/);
      expect(e.fingerprint).toBe(createHash("sha256").update(k.cosePublicKey).digest("hex").slice(0, 16).toUpperCase().match(/.{4}/g)!.join("-"));
      const approve = async (fp: string) => (await d.su.query("SELECT control.host_approve_operator('o2@example.invalid', $1) AS r", [fp])).rows[0].r;
      await deliverAll(d);
      expect((await approve(k.id.slice(0, 8))).error).toBe("FINGERPRINT_MISMATCH");
      expect(await approve(e.fingerprint.toLowerCase().replace(/-/g, " "))).toMatchObject({ ok: true });   // separators/case ignored
    } finally { await d.drop(); }
  });

  it("MED: a recovery link approved by an owner who is then emergency-revoked cannot be redeemed", async () => {
    const d = await createTestDb({ seed: false });
    try {
      await ownerWithSession(d, "a@example.invalid");
      const b = await operatorFixture(d, "owner", "b@example.invalid");
      await operatorFixture(d, "owner", "c@example.invalid");
      await d.su.query("UPDATE control.webauthn_credentials SET last_used_at = now() - interval '1 day'");
      const rq = (await d.su.query("SELECT control.host_recovery_request('a@example.invalid', 'lost device synthetic') AS r")).rows[0].r;
      expect((await stepup(d, b.token, b.auth, "recovery_approve", rq.request_id)).ok).toBe(true);
      const ap = await d.api("api_recovery_approve", b.token, rq.request_id);
      expect(ap.ok).toBe(true);
      const rv = (await d.su.query("SELECT control.host_revoke_operator_credentials('b@example.invalid', 'approver device stolen') AS r")).rows[0].r;
      expect(rv).toMatchObject({ ok: true, approved_links_voided: 1 });
      expect((await enrolWithToken(d, ap.enrolment_token, new SoftAuthenticator())).error).toBe("INVALID_TOKEN");
      expect((await d.su.query("SELECT state FROM control.recovery_requests WHERE id = $1", [rq.request_id])).rows[0].state).toBe("pending");
    } finally { await d.drop(); }
  });

  it("MED: an owner who is mid-recovery does not count as 'another usable owner' (no double lockout)", async () => {
    const d = await createTestDb({ seed: false });
    try {
      await ownerWithSession(d, "a@example.invalid");
      await operatorFixture(d, "owner", "b@example.invalid");
      expect((await d.su.query("SELECT control.host_recovery_request('b@example.invalid', 'b lost every passkey') AS r")).rows[0].r.ok).toBe(true);
      expect((await d.su.query("SELECT control.host_revoke_operator_credentials('a@example.invalid', 'a device stolen synthetic') AS r")).rows[0].r.error).toBe("LAST_OWNER");
    } finally { await d.drop(); }
  });

  it("LOW: a never-activated identity can be re-invited after revoke or expiry; the audit row records what it replaces", async () => {
    const d = await createTestDb({ seed: false });
    try {
      const a = await ownerWithSession(d, "a@example.invalid");
      const i1 = await invite(d, a, "x@example.invalid", "admin");
      expect((await stepup(d, a.token, a.auth, "operator_invite", `revoke:${i1.invitation_id}`)).ok).toBe(true);
      expect((await d.api("api_operator_invite_revoke", a.token, i1.invitation_id)).ok).toBe(true);
      const i2 = await invite(d, a, "x@example.invalid", "owner");
      expect(i2.ok).toBe(true);
      expect(i2.identity_id).toBe(i1.identity_id);
      const k = new SoftAuthenticator();
      expect((await enrolWithToken(d, i2.enrolment_token, k)).ok).toBe(true);
      await d.su.query("UPDATE control.operator_invitations SET expires_at = now() - interval '1 second' WHERE id = $1", [i2.invitation_id]);
      const i3 = await invite(d, a, "x@example.invalid", "admin");
      expect(i3.ok).toBe(true);
      const ev = (await d.su.query("SELECT detail FROM control.audit_events WHERE action = 'platform.operator_invited' ORDER BY seq")).rows.map((r) => r.detail);
      expect(ev.at(-1)).toMatchObject({ replaced_invitation: i2.invitation_id, previous_role: "owner", previous_state: "pending_approval" });
      expect(ev.at(-2)).toMatchObject({ replaced_invitation: i1.invitation_id, previous_state: "revoked" });
      expect((await d.su.query("SELECT count(*)::int n FROM control.webauthn_credentials WHERE credential_id = $1 AND disabled_at IS NULL", [k.id])).rows[0].n).toBe(0);
      const adm = await operatorFixture(d, "admin", "y@example.invalid");
      expect(adm).toBeTruthy();
      expect((await invite(d, a, "y@example.invalid", "admin")).error).toBe("ALREADY_EXISTS");          // active: never
    } finally { await d.drop(); }
  });

  it("LOW: device tokens are capped per identity; recovery redemption revokes the subject's devices", async () => {
    const d = await createTestDb({ seed: false });
    try {
      const a = await ownerWithSession(d, "a@example.invalid");
      const b = await operatorFixture(d, "owner", "b@example.invalid");
      for (let n = 0; n < 7; n++) { await resetRateLimits(d); expect((await login(d, a.auth)).ok).toBe(true); }
      const live = async () => (await d.su.query("SELECT count(*)::int n FROM control.login_devices WHERE identity_id = $1 AND revoked_at IS NULL", [a.identityId])).rows[0].n;
      expect(await live()).toBe(5);
      await d.su.query("UPDATE control.webauthn_credentials SET last_used_at = now() - interval '1 day'");
      const rq = (await d.su.query("SELECT control.host_recovery_request('a@example.invalid', 'lost device synthetic') AS r")).rows[0].r;
      expect((await stepup(d, b.token, b.auth, "recovery_approve", rq.request_id)).ok).toBe(true);
      const ap = await d.api("api_recovery_approve", b.token, rq.request_id);
      expect((await enrolWithToken(d, ap.enrolment_token, new SoftAuthenticator())).ok).toBe(true);
      expect(await live()).toBe(1);                      // all old devices revoked; C1.3 M2: the recovering browser gets a fresh one
      expect((await d.su.query("SELECT count(*)::int n FROM control.login_devices WHERE identity_id = $1 AND revoked_at IS NULL AND created_at < now() - interval '1 second'", [a.identityId])).rows[0].n).toBe(0);
    } finally { await d.drop(); }
  });

  it("MED: deliveries are retried beyond 20 attempts; host status reports stuck deliveries and the sentinel heartbeat", async () => {
    const d = await createTestDb({ seed: false });
    try {
      await ownerWithSession(d);
      await d.su.query("UPDATE control.notify_deliveries SET attempts = 25, last_attempt_at = now() - interval '1 hour' WHERE delivered_at IS NULL");
      expect((await d.su.query("SELECT control.host_notify_status() AS r")).rows[0].r.stuck).toBeGreaterThan(0);
      expect(await deliverAll(d)).toBeGreaterThan(0);
      const st = (await d.su.query("SELECT control.host_notify_status() AS r")).rows[0].r;
      expect(st).toMatchObject({ stuck: 0, undelivered: 0 });
      expect(st.sentinel_last_claim_at).toBeTruthy();
    } finally { await d.drop(); }
  });

  it("MED: webhook targets must be https or loopback http; file targets must be absolute", async () => {
    const d = await createTestDb({ seed: false, notify: false });
    try {
      const add = async (kind: string, target: string, secret: string | null) =>
        (await d.su.query("SELECT control.host_add_notify_channel('host', NULL, $1, $2, $3) AS r", [kind, target, secret])).rows[0].r;
      const sec = randomBytes(32).toString("hex");
      expect((await add("webhook", "http://example.com/hook", sec)).error).toBe("INVALID_INPUT");
      expect((await add("webhook", "http://127.0.0.1.example.com/hook", sec)).error).toBe("INVALID_INPUT");
      expect((await add("file", "relative/notices.jsonl", null)).error).toBe("INVALID_INPUT");
      expect((await add("webhook", "https://ntfy.example.com/hook", sec)).ok).toBe(true);
      expect((await add("webhook", "http://127.0.0.1:8080/hook", sec)).ok).toBe(true);
    } finally { await d.drop(); }
  });

  it("LOW: new-device sign-ins and host-confirmed recoveries are notices addressed to the subject", async () => {
    const d = await createTestDb({ seed: false });
    try {
      const a = await ownerWithSession(d, "a@example.invalid");
      await resetRateLimits(d);
      await login(d, a.auth);
      expect((await d.su.query("SELECT count(*)::int n FROM control.notify_outbox WHERE action = 'platform.login_succeeded' AND subject_id = $1", [a.identityId])).rows[0].n).toBeGreaterThan(0);
      const rq = (await d.su.query("SELECT control.host_recovery_request('a@example.invalid', 'synthetic subject test') AS r")).rows[0].r;
      await d.su.query("SELECT control.host_recovery_confirm($1)", [rq.request_id]);
      await d.su.query("SELECT control.host_recovery_cancel($1)", [rq.request_id]);
      const { rows } = await d.su.query("SELECT action, subject_id FROM control.notify_outbox WHERE action IN ('platform.recovery_host_confirmed', 'platform.recovery_cancelled')");
      expect(rows.map((r) => r.subject_id)).toEqual([a.identityId, a.identityId]);
    } finally { await d.drop(); }
  });

  it("LOW: a partially migrated test database never weakens control_app's cluster-wide settings", async () => {
    const d = await createTestDb({ seed: false, upTo: "203" });
    try {
      const { rows } = await d.su.query("SELECT rolconfig FROM pg_roles WHERE rolname = 'control_app'");
      expect([...rows[0].rolconfig].sort()).toEqual(["idle_in_transaction_session_timeout=10s", "lock_timeout=3s",
        "search_path=control, pg_catalog", "statement_timeout=5s", "temp_file_limit=256MB", "transaction_timeout=10s"]);
    } finally { await d.drop(); }
  });
});

function createHmacHex(key: Buffer, s: string) {
  return createHmac("sha256", key).update(s, "utf8").digest("hex");
}
