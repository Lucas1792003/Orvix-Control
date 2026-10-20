// Orvix Control sentinel: out-of-band security notifier + open-transaction watchdog (C1.2, RM-1/RM-3).
//
// Runs as a SEPARATE process under the SEPARATE database login `control_sentinel`, whose password lives only in
// .env.sentinel (the web server never loads it and refuses to start if it sees it). Its only database rights are
// EXECUTE on control.sentinel_claim / sentinel_ack / sentinel_watchdog. It never loads the superuser credential.
//
//   npx tsx scripts/sentinel.ts            # loop (delivery and watchdog run independently, every 2 s)
//   npx tsx scripts/sentinel.ts --once     # one pass of each, then exit
//
// Channels are configured by the host only (npm run host -- notify-add ...):
//   file    : appends one JSON line per notice to an absolute host path (symlinks refused; outside the web app's reach
//             in production)
//   webhook : POSTs the notice as JSON with headers X-Orvix-Timestamp and X-Orvix-Signature =
//             hex(HMAC-SHA256(secret, timestamp + "." + body)). The receiver MUST answer 2xx with header
//             X-Orvix-Ack = hex(HMAC-SHA256(secret, "ack." + notice_id + "." + timestamp)); without a valid ack the
//             delivery counts as failed (an impostor that merely answers 200 cannot open a gate).
import { createHmac, timingSafeEqual } from "node:crypto";
import { closeSync, constants, fstatSync, openSync, writeSync } from "node:fs";
import pg from "pg";
import { loadSentinelEnv, sentinelConfig } from "./env";

export type Claimed = { outbox_id: string; channel_id: string; kind: string; target: string; secret: Buffer | null; payload: unknown; attempts: number };

export function signWebhook(secret: Buffer, timestamp: string, body: string): string {
  return createHmac("sha256", secret).update(`${timestamp}.${body}`).digest("hex");
}

export function ackWebhook(secret: Buffer, noticeId: string, timestamp: string): string {
  return createHmac("sha256", secret).update(`ack.${noticeId}.${timestamp}`).digest("hex");
}

function sameHex(a: string, b: string): boolean {
  const x = Buffer.from(a, "utf8"), y = Buffer.from(b, "utf8");
  return x.length === y.length && timingSafeEqual(x, y);
}

async function deliver(c: Claimed): Promise<{ ok: boolean; error?: string }> {
  const body = JSON.stringify(c.payload);
  try {
    if (c.kind === "file") {
      if (!c.target.startsWith("/")) return { ok: false, error: "file target not absolute" };
      // O_NONBLOCK: a FIFO planted at the path must not freeze the process (open fails instead of waiting for a reader)
      const fd = openSync(c.target, constants.O_WRONLY | constants.O_APPEND | constants.O_CREAT | constants.O_NOFOLLOW | constants.O_NONBLOCK, 0o600);
      try {
        if (!fstatSync(fd).isFile()) return { ok: false, error: "file target is not a regular file" };
        writeSync(fd, body + "\n");
      } finally { closeSync(fd); }
      return { ok: true };
    }
    if (c.kind === "webhook") {
      if (!c.secret) return { ok: false, error: "no secret" };
      // also enforced by a table constraint (217); checked here for rows that predate it
      if (!/^https:\/\//.test(c.target) && !/^http:\/\/(127\.0\.0\.1|\[::1\]|localhost)(:[0-9]{1,5})?(\/|$)/.test(c.target)) {
        return { ok: false, error: "webhook target must be https or loopback http" };
      }
      const ts = String(Math.floor(Date.now() / 1000));
      const noticeId = String((c.payload as { notice_id?: unknown }).notice_id ?? "");
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), 5000);
      try {
        const r = await fetch(c.target, {
          method: "POST", signal: ctrl.signal, redirect: "error",
          headers: { "content-type": "application/json", "x-orvix-timestamp": ts, "x-orvix-signature": signWebhook(c.secret, ts, body) },
          body,
        });
        if (r.status < 200 || r.status >= 300) return { ok: false, error: `HTTP ${r.status}` };
        const ack = r.headers.get("x-orvix-ack") ?? "";
        return sameHex(ack, ackWebhook(c.secret, noticeId, ts)) ? { ok: true } : { ok: false, error: "missing or invalid ack" };
      } finally {
        clearTimeout(timer);
      }
    }
    return { ok: false, error: "unknown channel kind" };
  } catch (e) {
    return { ok: false, error: (e as NodeJS.ErrnoException).code ?? (e as Error).name };
  }
}

// One delivery pass. Returns counts. Failures are retried by the database's backoff (sentinel_claim).
export async function deliverOnce(pool: pg.Pool, limit = 50): Promise<{ delivered: number; failed: number }> {
  const { rows } = await pool.query<Claimed>("SELECT * FROM control.sentinel_claim($1)", [limit]);
  let delivered = 0, failed = 0;
  for (const c of rows) {
    const r = await deliver(c);
    await pool.query("SELECT control.sentinel_ack($1, $2, $3, $4)", [c.outbox_id, c.channel_id, r.ok, r.error ?? null]);
    if (r.ok) delivered++; else failed++;
  }
  return { delivered, failed };
}

export async function watchdogOnce(pool: pg.Pool, idleSeconds = 5, xactSeconds = 15): Promise<number> {
  const { rows } = await pool.query("SELECT control.sentinel_watchdog($1, $2) AS n", [idleSeconds, xactSeconds]);
  return Number(rows[0].n);
}

// A loop that survives errors: a stalled or failing pass is logged and retried; it never ends the process.
async function loop(name: string, once: boolean, pass: () => Promise<string | null>) {
  do {
    try {
      const msg = await pass();
      if (msg) console.log(`${new Date().toISOString()} ${name} ${msg}`);
    } catch (e) {
      console.error(`${new Date().toISOString()} ${name} error: ${(e as Error).name}`);
    }
    if (!once) await new Promise((r) => setTimeout(r, 2000));
  } while (!once);
}

async function main() {
  loadSentinelEnv();
  const once = process.argv.includes("--once");
  // separate pools: a watchdog pass waiting on a lock never delays delivery, and vice versa
  const deliveryPool = new pg.Pool({ ...sentinelConfig(), max: 1, application_name: "orvix-sentinel-delivery" });
  const watchdogPool = new pg.Pool({ ...sentinelConfig(), max: 1, application_name: "orvix-sentinel-watchdog" });
  for (const p of [deliveryPool, watchdogPool]) p.on("error", () => {});
  try {
    await Promise.all([
      loop("delivery", once, async () => {
        const d = await deliverOnce(deliveryPool);
        return d.delivered || d.failed ? `delivered=${d.delivered} failed=${d.failed}` : null;
      }),
      loop("watchdog", once, async () => {
        const n = await watchdogOnce(watchdogPool);
        return n ? `terminated=${n}` : null;
      }),
    ]);
  } finally {
    await deliveryPool.end();
    await watchdogPool.end();
  }
}

if (process.argv[1]?.endsWith("sentinel.ts")) {
  main().catch((e) => { console.error(`SENTINEL FAIL: ${(e as Error).message}`); process.exit(1); });
}
