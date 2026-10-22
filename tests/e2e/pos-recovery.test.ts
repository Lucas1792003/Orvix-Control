// Step 5 (222) / Step 6 (223) over HTTP: the POS recovery page and routes against `next start` on localhost:3410, backed by
// orvix_control_e2e, which reaches the POS Recovery V1 operator MOCK (db/dev/pos_recovery_mock.sql) in its own database
// over the network bridge. The real POS is exercised by the POS repository's Step 6 integration run.
import { spawn, type ChildProcess } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ROOT } from "../../scripts/env";
import { createTestDb, hostBootstrap, installPosRecoveryMock, type PosMock, type TestDb } from "../helpers/db";
import { configurePosBridge, removePosBridge } from "../../scripts/pos-bridge";
import { SoftAuthenticator } from "../helpers/softAuthenticator";

const BASE = "http://localhost:3410";
let db: TestDb;
let pos: PosMock;
let server: ChildProcess;
let serverLog = "";
const auth = new SoftAuthenticator();
let cookie: string;
let csrf: string;

type Res = { status: number; body: any; headers: Headers };
async function req(path: string, o: { method?: string; body?: unknown; csrf?: string; origin?: string | null; cookie?: string | null } = {}): Promise<Res> {
  const headers: Record<string, string> = {};
  if (o.body !== undefined) headers["content-type"] = "application/json";
  const c = o.cookie === undefined ? cookie : o.cookie;
  if (c) headers.cookie = c;
  if (o.csrf) headers["x-orvix-csrf"] = o.csrf;
  if (o.origin !== null) headers.origin = o.origin ?? BASE;
  const r = await fetch(BASE + path, { method: o.method ?? (o.body !== undefined ? "POST" : "GET"), headers,
    body: o.body !== undefined ? JSON.stringify(o.body) : undefined, redirect: "manual" });
  const text = await r.text();
  let body: any = text;
  try { body = JSON.parse(text); } catch { /* html */ }
  return { status: r.status, body, headers: r.headers };
}
async function stepUp(action: string, target: string) {
  const so = await req("/api/auth/stepup/options", { body: { action, target }, csrf });
  expect(so.status).toBe(200);
  expect((await req("/api/auth/stepup/verify", { body: { response: auth.assert(so.body.options) }, csrf })).status).toBe(200);
}

beforeAll(async () => {
  db = await createTestDb({ name: "orvix_control_e2e", seed: true });
  pos = await installPosRecoveryMock(db);
  server = spawn(process.execPath, [`${ROOT}/node_modules/next/dist/bin/next`, "start", "--hostname", "localhost", "--port", "3410"], {
    cwd: ROOT, detached: true,
    env: { ...Object.fromEntries(Object.entries(process.env).filter(([k]) => !/SUPERUSER|SENTINEL/.test(k))),
           ORVIX_DB_NAME: "orvix_control_e2e", NODE_ENV: "production" }, stdio: ["ignore", "pipe", "pipe"],
  });
  server.stdout!.on("data", (d) => { serverLog += d; });
  server.stderr!.on("data", (d) => { serverLog += d; });
  for (let i = 0; i < 120; i++) {
    try { if ((await fetch(`${BASE}/api/healthz`)).status === 200) break; } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 500));
  }
  // owner: bootstrap -> passkey enrolment -> login, all over HTTP
  const boot = await hostBootstrap(db, "owner@example.invalid", "E2E Owner");
  const eo = await req("/api/auth/enroll/options", { body: { token: boot.enrolment_token }, cookie: null });
  expect((await req("/api/auth/enroll/verify", { body: { token: boot.enrolment_token, response: auth.register(eo.body.options) }, cookie: null })).status).toBe(200);
  await db.su.query("DELETE FROM control.rate_limits");
  const lo = await req("/api/auth/login/options", { body: {}, cookie: null });
  const lv = await req("/api/auth/login/verify", { body: { response: auth.assert(lo.body.options) }, cookie: null });
  expect(lv.status).toBe(200);
  cookie = `__Host-orvix_sid=${(lv.headers.get("set-cookie") ?? "").match(/__Host-orvix_sid=([0-9a-f]{64})/)![1]}`;
  csrf = (await req("/api/auth/session")).body.csrf;
}, 180_000);

afterAll(async () => {
  if (server?.pid) { try { process.kill(-server.pid, "SIGTERM"); } catch { /* already gone */ } }
  await new Promise((r) => setTimeout(r, 500));
  await pos?.drop();
  await db?.drop();
});

describe("POS recovery over HTTP", () => {
  it("fails closed without a session", async () => {
    const p = await req("/pos-recovery", { origin: null, cookie: null });
    expect([307, 308]).toContain(p.status);
    expect((await req("/api/pos-recovery", { cookie: null })).status).toBe(401);
    expect((await req("/api/pos-recovery/submit", { body: {}, cookie: null })).status).toBe(401);
  });

  it("the page lists organizations and says BLOCKED where there is no owner authority; nothing offers ACTIVE", async () => {
    const page = await req("/pos-recovery?org=org-synthetic-b", { origin: null });
    expect(page.status).toBe(200);
    expect(page.body).toContain("org-synthetic-a");
    expect(page.body).toContain("BLOCKED: no owner authority");
    expect(page.body).not.toMatch(/Move to ACTIVE|Reopen now|Set ACTIVE/i);
    const api = await req("/api/pos-recovery");
    expect(api.body.organizations.map((o: { orgId: string }) => o.orgId)).toEqual(["org-synthetic-a", "org-synthetic-b"]);
  });

  it("containment: CSRF, then step-up bound to the state; ACTIVE is not even a valid input", async () => {
    const body = { to: "RECONCILING", reason: "synthetic incident (e2e)", evidenceReference: "INC-E2E-1", requestId: randomUUID() };
    expect((await req("/api/pos-recovery/orgs/org-synthetic-b/transition", { body })).status).toBe(403);   // no CSRF header
    const r1 = await req("/api/pos-recovery/orgs/org-synthetic-b/transition", { body, csrf });
    expect([r1.status, r1.body.error]).toEqual([403, "STEPUP_REQUIRED"]);
    expect((await req("/api/pos-recovery/orgs/org-synthetic-b/transition", { body: { ...body, to: "ACTIVE" }, csrf })).body.error).toBe("INVALID_INPUT");
    await stepUp("pos_recovery_transition", "org-synthetic-b:RECONCILING");
    const r2 = await req("/api/pos-recovery/orgs/org-synthetic-b/transition", { body, csrf });
    expect(r2.status).toBe(200);
    expect(r2.body).toMatchObject({ ok: true, state: "RECONCILING" });
    expect(r2.headers.get("x-request-id")).toBe(body.requestId);
  });

  it("report, then the page highlights the hard blocker", async () => {
    const r = await req("/api/pos-recovery/orgs/org-synthetic-b/report", { body: { requestId: randomUUID() }, csrf });
    expect(r.body).toMatchObject({ ok: true, hardBlockers: ["ledger_in_flight"] });
    const page = await req("/pos-recovery?org=org-synthetic-b", { origin: null });
    expect(page.body).toContain("ledger_in_flight");
    expect(page.body).toMatch(/HARD · (<!-- -->)?ledger_in_flight/);
  });

  it("submit carries the exact text; a refused signature is a generic code; no POS or database text leaks", async () => {
    const authorization = JSON.stringify({ protocol: "orvix-owner-authorization-v1", purpose: "enroll-device", scope: "org-synthetic-b",
      keyId: "owner-key-synthetic-1", requestId: "a2000000-0000-4000-8000-0000000000b2" });
    const target = `enroll-device:${createHash("sha256").update(authorization, "utf8").digest("hex")}`;
    expect((await req("/api/pos-recovery/submit", { body: { authorization, signature: "zz", requestId: randomUUID() }, csrf })).body.error).toBe("INVALID_INPUT");
    await stepUp("pos_recovery_submit", target);
    const r = await req("/api/pos-recovery/submit", { body: { authorization, signature: "abcd", requestId: randomUUID() }, csrf });
    expect([r.status, r.body]).toEqual([409, { ok: false, error: "POS_RECOVERY_REFUSED" }]);
    expect(JSON.stringify(r.body)).not.toMatch(/RECOVERY_V1|recovery_v1|SQLSTATE|control_/);
  });

  it("device containment over HTTP", async () => {
    const enr = "e1000000-0000-4000-8000-0000000000b1";
    const body = { action: "suspend", reason: "till reported missing (e2e)", requestId: randomUUID() };
    expect((await req(`/api/pos-recovery/orgs/org-synthetic-b/devices/${enr}/contain`, { body, csrf })).body.error).toBe("STEPUP_REQUIRED");
    await stepUp("pos_recovery_contain", `org-synthetic-b:${enr}:suspend`);
    expect((await req(`/api/pos-recovery/orgs/org-synthetic-b/devices/${enr}/contain`, { body, csrf })).body).toMatchObject({ ok: true, state: "SUSPENDED" });
  });

  it("without the network bridge the page says BLOCKED and the API is 503; a POS that is down is the same", async () => {
    const c = await db.su.connect();
    try {
      await removePosBridge(c);
      let api = await req("/api/pos-recovery");
      expect([api.status, api.body]).toEqual([503, { ok: false, error: "POS_RECOVERY_UNAVAILABLE" }]);
      const page = await req("/pos-recovery", { origin: null });
      expect(page.status).toBe(200);
      expect(page.body).toContain("BLOCKED: POS recovery interface unavailable");
      await configurePosBridge(c, { ...pos.settings, port: 1 });   // nothing listens there
      api = await req("/api/pos-recovery");
      expect([api.status, api.body]).toEqual([503, { ok: false, error: "POS_RECOVERY_UNAVAILABLE" }]);
    } finally {
      await configurePosBridge(c, pos.settings);
      c.release();
    }
    expect((await req("/api/pos-recovery")).status).toBe(200);
  });

  it("the audit chain verifies after the run", async () => {
    expect((await db.su.query("SELECT ok FROM control.audit_verify()")).rows[0].ok).toBe(true);
  });
});
