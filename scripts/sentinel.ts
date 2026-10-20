// Orvix Control sentinel: out-of-band security notifier + open-transaction watchdog (C1.2, hardened in C1.3).
//
// Runs as a SEPARATE process under the SEPARATE database login `control_sentinel`, whose password lives only in
// .env.sentinel. Its only database rights are EXECUTE on control.sentinel_* and control.watchdog_* functions. It never
// loads the superuser or app password, and it refuses to start if its role can reach a non-control database or the
// control database's ACL is open to PUBLIC (C1.3 M3/M4).
//
//   npx tsx scripts/sentinel.ts            # run (delivery workers per channel + watchdog loop)
//   npx tsx scripts/sentinel.ts --once     # one delivery pass over every channel + one watchdog pass, then exit
//
// DELIVERY (C1.3 M5/M6): one independent worker per channel claims at most 5 deliveries for that channel (40 s lease,
// claim token) and delivers them in order. A stalled channel only stalls its own worker.
//   file    : appends "\n" + JSON + "\n" with O_APPEND|O_NOFOLLOW|O_NONBLOCK to an absolute path whose parent is not a
//             symlink and which is a regular file with exactly one link; every byte is written (short writes are
//             continued), fsync'ed, then READ BACK and compared before the delivery is acknowledged.
//   webhook : POST with X-Orvix-Timestamp / X-Orvix-Signature = hex(HMAC-SHA256(secret, timestamp + "." + body)); the
//             receiver must answer 2xx with X-Orvix-Ack = hex(HMAC-SHA256(secret, "ack." + notice_id + "." + timestamp)).
// WATCHDOG (C1.3 W-1): PLAN -> ARM -> EXECUTE -> RECONCILE, each a separate transaction (db/migrations/218).
import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { constants } from "node:fs";
import { lstat, open, realpath, stat } from "node:fs/promises";
import path from "node:path";
import pg from "pg";
import { PRIVILEGE_CHECK_SQL, privilegeProblems, type PrivilegeRow } from "../src/server/db/privilegeCheck";
import { loadSentinelEnv, sentinelConfig } from "./env";

export type Claimed = { outbox_id: string; channel_id: string; claim_token: string; kind: string; target: string; secret: Buffer | null;
  payload: unknown; attempts: number; ack_verified_in_db: boolean; body?: string };

export function signWebhook(secret: Buffer, timestamp: string, body: string): string {
  return createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex");
}

// Legacy channels (no ack key): HMAC(signing secret, "ack.<id>.<ts>"), checked by the sentinel.
// Ack-key channels (C1.3): HMAC(ack key, "ack.<id>.<ts>.<hex sha256(body)>"), checked IN THE DATABASE.
export function ackWebhook(secret: Buffer, noticeId: string, timestamp: string, body?: string): string {
  const suffix = body === undefined ? "" : `.${createHash("sha256").update(body, "utf8").digest("hex")}`;
  return createHmac("sha256", secret).update(`ack.${noticeId}.${timestamp}${suffix}`).digest("hex");
}

function sameHex(a: string, b: string): boolean {
  const x = Buffer.from(a, "utf8"), y = Buffer.from(b, "utf8");
  return x.length === y.length && timingSafeEqual(x, y);
}

const LOOPBACK_HTTP = /^http:\/\/(127\.0\.0\.1|\[::1\]|localhost)(:[0-9]{1,5})?(\/|$)/;
const errText = (e: unknown) => {
  const x = e as { name?: string; code?: string | number; message?: string; cause?: { code?: string } };
  if (x?.name === "AbortError" || x?.name === "TimeoutError") return "timeout";
  return String(x?.cause?.code ?? x?.code ?? x?.name ?? "error").slice(0, 60);   // fetch failures carry the reason in .cause
};

// Durable, verified append (async: a slow or hung disk never blocks the event loop, the watchdog or other channels).
// Returns null on success, else the reason (the delivery is then NOT acknowledged).
export async function appendVerified(target: string, body: string): Promise<string | null> {
  if (!path.isAbsolute(target)) return "file target not absolute";
  const dir = path.dirname(target);
  try {
    if ((await realpath(dir)) !== dir) return "file target parent is a symlink";
    const ds = await stat(dir);
    if ((ds.mode & 0o022) !== 0) return "file target directory is group/world writable";
    if (ds.uid !== 0 && ds.uid !== process.getuid?.()) return "file target directory is owned by another user";
  } catch (e) { return errText(e); }
  let created = false;
  try {
    const st = await lstat(target);
    if (!st.isFile()) return "file target is not a regular file";
    if (st.nlink !== 1) return "file target has more than one link";
  } catch (e) { if ((e as NodeJS.ErrnoException).code !== "ENOENT") return errText(e); created = true; }
  const buf = Buffer.from(`\n${body}\n`, "utf8");      // leading newline: a torn earlier line never swallows this one
  let fh;
  try {
    fh = await open(target, constants.O_RDWR | constants.O_APPEND | constants.O_CREAT | constants.O_NOFOLLOW | constants.O_NONBLOCK, 0o600);
  } catch (e) { return errText(e); }
  try {
    const st = await fh.stat();
    if (!st.isFile()) return "file target is not a regular file";
    if (st.nlink !== 1) return "file target has more than one link";
    if ((st.mode & 0o022) !== 0) return "file target is group/world writable";
    const before = st.size;
    let off = 0;
    while (off < buf.length) {
      const { bytesWritten } = await fh.write(buf, off, buf.length - off);
      if (bytesWritten <= 0) return "short write";
      off += bytesWritten;
    }
    await fh.sync();
    if (created) { const d = await open(dir, constants.O_RDONLY); try { await d.sync(); } finally { await d.close(); } }
    // read back everything appended since `before` (other appenders may interleave) and find our exact bytes
    const end = (await fh.stat()).size;
    if (end - before < buf.length) return "file shrank";
    const region = Buffer.alloc(end - before);
    let got = 0;
    while (got < region.length) {
      const { bytesRead } = await fh.read(region, got, region.length - got, before + got);
      if (bytesRead <= 0) break;
      got += bytesRead;
    }
    if (region.subarray(0, got).indexOf(buf) < 0) return "read-back mismatch";
    // the path must still name the same single-link file we wrote (no rename/replace between checks and write)
    const now = await lstat(target); const fst = await fh.stat();
    if (now.dev !== fst.dev || now.ino !== fst.ino || fst.nlink !== 1) return "file target changed during delivery";
    return null;
  } catch (e) {
    return errText(e);
  } finally {
    await fh.close();
  }
}

type Outcome = { ok: boolean; error?: string; ackTs?: string; ack?: string };
async function deliver(c: Claimed): Promise<Outcome> {
  const body = c.body ?? JSON.stringify(c.payload);      // the database's canonical text (bound into database-verified acks)
  try {
    if (c.kind === "file") {
      const err = await appendVerified(c.target, body);
      return err ? { ok: false, error: err } : { ok: true };
    }
    if (c.kind === "webhook") {
      if (!c.secret) return { ok: false, error: "no secret" };
      if (!/^https:\/\//.test(c.target) && !LOOPBACK_HTTP.test(c.target)) return { ok: false, error: "webhook target must be https or loopback http" };
      const ts = String(Math.floor(Date.now() / 1000));
      const noticeId = String((c.payload as { notice_id?: unknown }).notice_id ?? "");
      const r = await fetch(c.target, {
        method: "POST", signal: AbortSignal.timeout(5000), redirect: "error",
        headers: { "content-type": "application/json", "x-orvix-timestamp": ts, "x-orvix-signature": signWebhook(c.secret, ts, body) },
        body,
      });
      void r.body?.cancel().catch(() => {});                    // never read (or hold) the response body
      if (r.status < 200 || r.status >= 300) return { ok: false, error: `HTTP ${r.status}` };
      const ack = r.headers.get("x-orvix-ack") ?? "";
      // C1.3: channels with a separate ack key are verified IN THE DATABASE (the sentinel never sees that key);
      // legacy channels (no ack key) are verified here with the signing secret.
      if (c.ack_verified_in_db) return { ok: /^[0-9a-f]{64}$/.test(ack), error: /^[0-9a-f]{64}$/.test(ack) ? undefined : "missing or invalid ack", ackTs: ts, ack };
      return sameHex(ack, ackWebhook(c.secret, noticeId, ts)) ? { ok: true } : { ok: false, error: "missing or invalid ack" };
    }
    return { ok: false, error: "unknown channel kind" };
  } catch (e) {
    return { ok: false, error: errText(e) };
  }
}

async function deliverClaimed(pool: pg.Pool, rows: Claimed[], log: (s: string) => void = () => {}) {
  let delivered = 0, failed = 0;
  for (const c of rows) {
    const r = await deliver(c);
    const { rows: a } = await pool.query("SELECT control.sentinel_ack($1, $2, $3, $4, $5, $6, $7) AS ok",
      [c.outbox_id, c.channel_id, c.claim_token, r.ok, r.error ?? null, r.ackTs ?? null, r.ack ?? null]);
    if (r.ok && a[0]?.ok === true) delivered++;
    else { failed++; if (r.ok) log(`channel=${c.channel_id} notice=${c.outbox_id} ack not accepted by the database`); }
  }
  return { delivered, failed };
}

// One pass over every channel (channels in PARALLEL, items within a channel in order). Used by --once and tests.
export async function deliverOnce(pool: pg.Pool, limit = 50): Promise<{ delivered: number; failed: number }> {
  const { rows } = await pool.query<Claimed>("SELECT * FROM control.sentinel_claim($1, NULL)", [limit]);
  const byChannel = new Map<string, Claimed[]>();
  for (const r of rows) byChannel.set(r.channel_id, [...(byChannel.get(r.channel_id) ?? []), r]);
  const parts = await Promise.all([...byChannel.values()].map((items) => deliverClaimed(pool, items)));
  return parts.reduce((a, b) => ({ delivered: a.delivered + b.delivered, failed: a.failed + b.failed }), { delivered: 0, failed: 0 });
}

// Long-running mode: one worker per channel with pending work.
export class DeliveryWorkers {
  private active = new Set<string>();
  constructor(private pool: pg.Pool, private log: (s: string) => void = () => {}) {}
  async tick() {
    const { rows } = await this.pool.query<{ channel_id: string }>("SELECT channel_id FROM control.sentinel_pending_channels()");
    for (const { channel_id } of rows) {
      if (this.active.has(channel_id)) continue;
      this.active.add(channel_id);
      void this.run(channel_id).finally(() => this.active.delete(channel_id));
    }
  }
  private async run(channel: string) {
    try {
      for (;;) {
        const { rows } = await this.pool.query<Claimed>("SELECT * FROM control.sentinel_claim(5, $1)", [channel]);
        if (rows.length === 0) return;
        const r = await deliverClaimed(this.pool, rows, this.log);
        if (r.delivered || r.failed) this.log(`channel=${channel} delivered=${r.delivered} failed=${r.failed}`);
        if (r.delivered === 0) await new Promise((res) => setTimeout(res, 1000));   // a failing channel backs off
      }
    } catch (e) {
      this.log(`channel=${channel} error: ${errText(e)} ${(e as Error).message?.slice(0, 160) ?? ""}`);
    }
  }
}

// One watchdog pass: PLAN -> (ARM -> EXECUTE) per intent -> RECONCILE. Each call is its own autocommit transaction
// (the database refuses ARM/EXECUTE inside a transaction that has already written). A backend that inherits a
// victim's locks becomes a stale holder itself and is handled by the next pass.
export async function watchdogOnce(pool: pg.Pool, idleSeconds = 5, xactSeconds = 15): Promise<number> {
  let terminated = 0;
  const { rows } = await pool.query<{ ids: string[] }>("SELECT control.watchdog_plan($1, $2) AS ids", [idleSeconds, xactSeconds]);
  for (const id of rows[0]?.ids ?? []) {
    const armed = (await pool.query("SELECT control.watchdog_arm($1) AS a", [id])).rows[0].a;
    if (!armed) continue;
    const r = (await pool.query("SELECT control.watchdog_execute($1) AS r", [id])).rows[0].r;
    if (r === "terminated" || r === "terminated_unconfirmed") terminated++;
  }
  await pool.query("SELECT control.watchdog_reconcile(10)");
  return terminated;
}

// Refuse to run with an exposed role or an open control-database ACL (C1.3 M3/M4); same checks as the web server.
export async function privilegeSelfCheck(pool: pg.Pool): Promise<string[]> {
  const { rows } = await pool.query<PrivilegeRow>(PRIVILEGE_CHECK_SQL);
  const out = privilegeProblems(rows[0]);
  // the sentinel's own role defaults must be exactly the canonical set (C1.3 review: the role could relax them)
  const { rows: c } = await pool.query(`SELECT (SELECT rolconfig FROM pg_roles WHERE rolname = current_user) AS rolconfig,
      (SELECT count(*) FROM pg_db_role_setting s JOIN pg_roles r ON r.oid = s.setrole WHERE r.rolname = current_user AND s.setdatabase <> 0)::int AS per_db,
      current_setting('statement_timeout') AS st, current_setting('idle_in_transaction_session_timeout') AS it`);
  const want = ["idle_in_transaction_session_timeout=10s", "search_path=control, pg_catalog", "statement_timeout=10s"];
  if (JSON.stringify([...(c[0]?.rolconfig ?? [])].sort()) !== JSON.stringify(want) || c[0]?.per_db !== 0 || c[0]?.st !== "10s" || c[0]?.it !== "10s") {
    out.push("sentinel role defaults are not the canonical set (run npm run db:migrate)");
  }
  return out;
}

async function loop(name: string, once: boolean, everyMs: number, pass: () => Promise<string | null>) {
  do {
    try {
      const msg = await pass();
      if (msg) console.log(`${new Date().toISOString()} ${name} ${msg}`);
    } catch (e) {
      console.error(`${new Date().toISOString()} ${name} error: ${errText(e)} ${(e as Error).message?.slice(0, 160) ?? ""}`);
    }
    if (!once) await new Promise((r) => setTimeout(r, everyMs));
  } while (!once);
}

async function main() {
  loadSentinelEnv();
  const once = process.argv.includes("--once");
  const deliveryPool = new pg.Pool({ ...sentinelConfig(), max: 4, application_name: "orvix-sentinel-delivery" });
  const watchdogPool = new pg.Pool({ ...sentinelConfig(), max: 1, application_name: "orvix-sentinel-watchdog" });
  for (const p of [deliveryPool, watchdogPool]) p.on("error", () => {});
  const problems = await privilegeSelfCheck(deliveryPool);
  if (problems.length) {
    console.error(`SENTINEL REFUSING TO START: ${problems.join("; ")}`);
    await deliveryPool.end(); await watchdogPool.end();
    process.exit(2);
  }
  // re-checked every 30 s: a database exposed (or a role setting changed) later stops the sentinel (fail closed)
  let recheckFailures = 0;
  const recheck = setInterval(() => {
    privilegeSelfCheck(deliveryPool).then((p) => {
      recheckFailures = 0;
      if (p.length) { console.error(`SENTINEL STOPPING: ${p.join("; ")}`); process.exit(2); }
    }, () => {
      // a transient error is retried; a check that keeps failing stops the sentinel (fail closed, never run unchecked)
      if (++recheckFailures >= 3) { console.error("SENTINEL STOPPING: privilege re-check failed 3 times"); process.exit(2); }
    });
  }, 30_000);
  recheck.unref();
  const workers = new DeliveryWorkers(deliveryPool, (s) => console.log(`${new Date().toISOString()} delivery ${s}`));
  try {
    await Promise.all([
      once ? loop("delivery", true, 0, async () => { const d = await deliverOnce(deliveryPool); return d.delivered || d.failed ? `delivered=${d.delivered} failed=${d.failed}` : null; })
           : loop("delivery", false, 1000, async () => { await workers.tick(); return null; }),
      loop("watchdog", once, 2000, async () => { const n = await watchdogOnce(watchdogPool); return n ? `terminated=${n}` : null; }),
    ]);
  } finally {
    await deliveryPool.end();
    await watchdogPool.end();
  }
}

if (process.argv[1]?.endsWith("sentinel.ts")) {
  main().catch((e) => { console.error(`SENTINEL FAIL: ${(e as Error).message}`); process.exit(1); });
}
