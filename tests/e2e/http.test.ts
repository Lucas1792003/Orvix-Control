// End-to-end over HTTP against `next start` on localhost:3410, backed by the orvix_control_e2e database.
// Uses a software authenticator, so @simplewebauthn/server verifies real signatures in the running server.
import { spawn, type ChildProcess } from "node:child_process";
import { randomUUID } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { ROOT } from "../../scripts/env";
import { createTestDb, hostBootstrap, type TestDb } from "../helpers/db";
import { verifyAnchorBundle, verifyChain } from "../../scripts/verify-audit";
import { createHash } from "node:crypto";
import { SoftAuthenticator } from "../helpers/softAuthenticator";

const BASE = "http://localhost:3410";
const ORIGIN = BASE;
let db: TestDb;
let server: ChildProcess;
let serverLog = "";

type Res = { status: number; body: any; headers: Headers };
async function req(path: string, o: { method?: string; body?: unknown; cookie?: string; csrf?: string; origin?: string | null } = {}): Promise<Res> {
  const headers: Record<string, string> = {};
  if (o.body !== undefined) headers["content-type"] = "application/json";
  if (o.cookie) headers.cookie = o.cookie;
  if (o.csrf) headers["x-orvix-csrf"] = o.csrf;
  if (o.origin !== null) headers.origin = o.origin ?? ORIGIN;
  const r = await fetch(BASE + path, {
    method: o.method ?? (o.body !== undefined ? "POST" : "GET"),
    headers, body: o.body !== undefined ? JSON.stringify(o.body) : undefined, redirect: "manual",
  });
  const text = await r.text();
  let body: any = text;
  try { body = JSON.parse(text); } catch { /* html */ }
  return { status: r.status, body, headers: r.headers };
}
const cookieFrom = (r: Res) => {
  const sc = r.headers.get("set-cookie") ?? "";
  const m = sc.match(/__Host-orvix_sid=([0-9a-f]{64})/);
  return m ? `__Host-orvix_sid=${m[1]}` : null;
};

async function loginWith(auth: SoftAuthenticator, assertOpts = {}) {
  const o = await req("/api/auth/login/options", { body: {} });
  expect(o.status).toBe(200);
  return req("/api/auth/login/verify", { body: { response: auth.assert(o.body.options, assertOpts) } });
}

beforeAll(async () => {
  db = await createTestDb({ name: "orvix_control_e2e", seed: true });
  server = spawn("npx", ["next", "start", "--hostname", "localhost", "--port", "3410"], {
    cwd: ROOT, env: { ...process.env, ORVIX_DB_NAME: "orvix_control_e2e", NODE_ENV: "production" }, stdio: ["ignore", "pipe", "pipe"],
  });
  server.stdout!.on("data", (d) => { serverLog += d; });
  server.stderr!.on("data", (d) => { serverLog += d; });
  for (let i = 0; i < 120; i++) {
    try {
      const r = await fetch(`${BASE}/api/healthz`);
      if (r.status === 200) return;
    } catch { /* not up yet */ }
    await new Promise((r) => setTimeout(r, 500));
  }
  throw new Error(`server did not start:\n${serverLog}`);
});

afterAll(async () => {
  server?.kill("SIGTERM");
  await new Promise((r) => setTimeout(r, 500));
  await db?.drop();
});

describe("unauthenticated surface fails closed", () => {
  it("console pages redirect to /login; session API is 401", async () => {
    for (const p of ["/", "/tenants", "/audit", "/health", `/tenants/${randomUUID()}`]) {
      const r = await req(p, { origin: null });
      expect([307, 308], p).toContain(r.status);
      expect(r.headers.get("location"), p).toMatch(/\/login$/);
    }
    expect((await req("/api/auth/session")).status).toBe(401);
  });

  it("a forged or garbage cookie is refused", async () => {
    expect((await req("/api/auth/session", { cookie: `__Host-orvix_sid=${"a".repeat(64)}` })).status).toBe(401);
    expect((await req("/", { cookie: "__Host-orvix_sid=../../etc", origin: null })).status).toBe(307);
  });

  it("security headers are present, CSP carries a nonce, no framing, no caching", async () => {
    const r = await req("/login", { origin: null });
    expect(r.status).toBe(200);
    const csp = r.headers.get("content-security-policy")!;
    expect(csp).toMatch(/script-src 'self' 'nonce-[A-Za-z0-9+/=]+' 'strict-dynamic'/);
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).not.toContain("unsafe-eval");
    expect(r.headers.get("x-frame-options")).toBe("DENY");
    expect(r.headers.get("referrer-policy")).toBe("no-referrer");
    expect(r.headers.get("cache-control")).toContain("no-store");
    expect(r.headers.get("x-powered-by")).toBeNull();
    const nonce = csp.match(/'nonce-([^']+)'/)![1];
    expect(r.body).toContain(`nonce="${nonce}"`);
  });

  it("state-changing endpoints refuse a foreign or missing Origin", async () => {
    expect((await req("/api/auth/login/options", { body: {}, origin: "https://evil.example" })).status).toBe(403);
    expect((await req("/api/auth/login/options", { body: {}, origin: null })).status).toBe(403);
    expect((await req("/api/auth/enroll/options", { body: { token: "a".repeat(64) }, origin: "http://127.0.0.1:3410" })).status).toBe(403);
  });
});

describe("passkey enrolment, login, step-up, logout", () => {
  const auth = new SoftAuthenticator();
  let cookie: string;
  let csrf: string;
  let enrolToken: string;

  it("bootstrap token -> passkey registration (real attestation verification)", async () => {
    const boot = await hostBootstrap(db, "owner@example.invalid", "E2E Owner");
    enrolToken = boot.enrolment_token;
    const bad = new SoftAuthenticator(); // wrong origin in clientDataJSON
    const o1 = await req("/api/auth/enroll/options", { body: { token: enrolToken } });
    const rBad = await req("/api/auth/enroll/verify", { body: { token: enrolToken, response: bad.register(o1.body.options, { origin: "https://evil.example" }) } });
    expect(rBad.status).toBe(400);
    const o2 = await req("/api/auth/enroll/options", { body: { token: enrolToken } });
    expect(o2.body.options.authenticatorSelection.userVerification).toBe("required");
    const noUv = await req("/api/auth/enroll/verify", { body: { token: enrolToken, response: new SoftAuthenticator().register(o2.body.options, { uv: false }) } });
    expect(noUv.status).toBe(400);
    const o3 = await req("/api/auth/enroll/options", { body: { token: enrolToken } });
    const ok = await req("/api/auth/enroll/verify", { body: { token: enrolToken, response: auth.register(o3.body.options) } });
    expect(ok.status).toBe(200);
    // single use
    expect((await req("/api/auth/enroll/options", { body: { token: enrolToken } })).status).toBe(400);
  });

  it("login rejects a bad signature, missing UV, wrong origin and wrong RP ID (each audited)", async () => {
    const before = Number((await db.su.query(`SELECT count(*) n FROM control.audit_events WHERE action = 'platform.login_failed'`)).rows[0].n);
    for (const opts of [{ tamper: true }, { uv: false }, { origin: "https://evil.example" }, { rpId: "evil.example" }, { type: "webauthn.create" }]) {
      const r = await loginWith(auth, opts);
      expect(r.status, JSON.stringify(opts)).toBe(401);
      expect(r.body).toEqual({ ok: false, error: "LOGIN_FAILED" });
      expect(cookieFrom(r)).toBeNull();
    }
    const after = Number((await db.su.query(`SELECT count(*) n FROM control.audit_events WHERE action = 'platform.login_failed'`)).rows[0].n);
    expect(after - before).toBe(5);
  });

  it("an unregistered authenticator cannot log in", async () => {
    expect((await loginWith(new SoftAuthenticator())).status).toBe(401);
  });

  it("login sets a __Host- HttpOnly, Secure, SameSite=Strict cookie and the console renders", async () => {
    await db.su.query("DELETE FROM control.rate_limits");
    const r = await loginWith(auth);
    expect(r.status).toBe(200);
    const sc = r.headers.get("set-cookie")!;
    expect(sc).toMatch(/^__Host-orvix_sid=[0-9a-f]{64}; /);
    expect(sc).toMatch(/HttpOnly/i);
    expect(sc).toMatch(/Secure/i);
    expect(sc).toMatch(/SameSite=Strict/i);
    expect(sc).toMatch(/Path=\//);
    expect(sc).not.toMatch(/Domain=/i);
    cookie = cookieFrom(r)!;
    const s = await req("/api/auth/session", { cookie });
    expect(s.body).toMatchObject({ ok: true, identity: { role: "owner" }, activeCredentials: 1 });
    csrf = s.body.csrf;
    const page = await req("/", { cookie, origin: null });
    expect(page.status).toBe(200);
    expect(page.body).toContain("Overview");
    expect(page.body).toContain("Synthetic Monsoon Mini"); // stuck in provisioning > 24 h
    const list = await req("/tenants", { cookie, origin: null });
    expect(list.body).toContain("Synthetic Golden Lotus Mart");
  });

  it("a replayed assertion is refused (challenge single-use)", async () => {
    const o = await req("/api/auth/login/options", { body: {} });
    const resp = auth.assert(o.body.options);
    expect((await req("/api/auth/login/verify", { body: { response: resp } })).status).toBe(200);
    expect((await req("/api/auth/login/verify", { body: { response: resp } })).status).toBe(401);
  });

  it("mutations need the CSRF header and a same-origin request", async () => {
    const t = (await db.su.query(`SELECT id FROM control.tenants WHERE slug = 'syn-golden-lotus'`)).rows[0].id;
    const body = { to: "past_due", reasonCode: "notice", note: "synthetic notice period", requestId: randomUUID() };
    expect((await req(`/api/tenants/${t}/transition`, { body, cookie })).status).toBe(403);
    expect((await req(`/api/tenants/${t}/transition`, { body, cookie, csrf: "0".repeat(64) })).status).toBe(403);
    expect((await req(`/api/tenants/${t}/transition`, { body, cookie, csrf, origin: "https://evil.example" })).status).toBe(403);
    const ok = await req(`/api/tenants/${t}/transition`, { body, cookie, csrf });
    expect(ok.status).toBe(200);
    expect(ok.headers.get("x-request-id")).toBe(body.requestId);
    const replay = await req(`/api/tenants/${t}/transition`, { body, cookie, csrf });
    expect(replay.body.replayed).toBe(true);
  });

  it("critical actions demand step-up; a real step-up assertion unlocks them", async () => {
    const t = (await db.su.query(`SELECT id FROM control.tenants WHERE slug = 'syn-river-bazaar'`)).rows[0].id;
    const body = { to: "suspended", reasonCode: "test", note: "synthetic suspension e2e", requestId: randomUUID() };
    const r1 = await req(`/api/tenants/${t}/transition`, { body, cookie, csrf });
    expect([r1.status, r1.body.error]).toEqual([403, "STEPUP_REQUIRED"]);
    const stepBody = { action: "tenant_transition", target: `${t}:suspended` };
    expect((await req("/api/auth/stepup/options", { body: {}, cookie, csrf })).status).toBe(400); // must name an action
    const so = await req("/api/auth/stepup/options", { body: stepBody, cookie, csrf });
    expect(so.body.options.allowCredentials.map((c: { id: string }) => c.id)).toEqual([auth.id]);
    const bad = await req("/api/auth/stepup/verify", { body: { response: auth.assert(so.body.options, { tamper: true }) }, cookie, csrf });
    expect(bad.status).toBe(403);
    const so2 = await req("/api/auth/stepup/options", { body: stepBody, cookie, csrf });
    expect((await req("/api/auth/stepup/verify", { body: { response: auth.assert(so2.body.options) }, cookie, csrf })).status).toBe(200);
    const r2 = await req(`/api/tenants/${t}/transition`, { body, cookie, csrf });
    expect(r2.status).toBe(200);
    expect(r2.body).toMatchObject({ ok: true, from: "active", to: "suspended" });
    // the grant was single-use
    await db.su.query("UPDATE control.tenants SET status = 'active' WHERE id = $1", [t]);
    const r3 = await req(`/api/tenants/${t}/transition`, { body: { ...body, requestId: randomUUID() }, cookie, csrf });
    expect(r3.body.error).toBe("STEPUP_REQUIRED");
  });

  const backup = new SoftAuthenticator();
  it("adds a second passkey over HTTP (step-up bound to credential_add), and it can sign in", async () => {
    const identityId = (await db.su.query("SELECT id FROM control.platform_identities")).rows[0].id;
    expect((await req("/api/credentials/add/options", { body: {}, cookie, csrf })).body.error).toBe("STEPUP_REQUIRED");
    const so = await req("/api/auth/stepup/options", { body: { action: "credential_add", target: identityId }, cookie, csrf });
    expect((await req("/api/auth/stepup/verify", { body: { response: auth.assert(so.body.options) }, cookie, csrf })).status).toBe(200);
    const ao = await req("/api/credentials/add/options", { body: {}, cookie, csrf });
    expect(ao.status).toBe(200);
    expect(ao.body.options.excludeCredentials.map((c: { id: string }) => c.id)).toEqual([auth.id]);
    expect(ao.body.options.pubKeyCredParams).toEqual([{ alg: -7, type: "public-key" }]);
    const av = await req("/api/credentials/add/verify", { body: { response: backup.register(ao.body.options), nickname: "backup" }, cookie, csrf });
    expect(av.status).toBe(200);
    const list = await req("/api/credentials", { cookie });
    expect(list.body.credentials).toHaveLength(2);
    await db.su.query("DELETE FROM control.rate_limits");
    expect((await loginWith(backup)).status).toBe(401); // pending for 15 minutes
    expect((await req("/api/auth/session", { cookie })).body.pendingCredentials).toBe(1);
    const page = await req("/", { cookie, origin: null });
    expect(page.body).toContain("still pending");
    await db.su.query("UPDATE control.webauthn_credentials SET usable_after = now() WHERE usable_after > now()");
    expect((await loginWith(backup)).status).toBe(200);
  });

  it("revokes the backup passkey over HTTP; the last one cannot be revoked", async () => {
    const list = (await req("/api/credentials", { cookie })).body.credentials as { id: string; nickname: string }[];
    const bk = list.find((c) => c.nickname === "backup")!; const primary = list.find((c) => c.nickname !== "backup")!;
    const so = await req("/api/auth/stepup/options", { body: { action: "credential_revoke", target: bk.id }, cookie, csrf });
    await req("/api/auth/stepup/verify", { body: { response: auth.assert(so.body.options) }, cookie, csrf });
    expect((await req(`/api/credentials/${bk.id}/revoke`, { body: {}, cookie, csrf })).status).toBe(200);
    expect((await loginWith(backup)).status).toBe(401);
    const so2 = await req("/api/auth/stepup/options", { body: { action: "credential_revoke", target: primary.id }, cookie, csrf });
    await req("/api/auth/stepup/verify", { body: { response: auth.assert(so2.body.options) }, cookie, csrf });
    const last = await req(`/api/credentials/${primary.id}/revoke`, { body: {}, cookie, csrf });
    expect([last.status, last.body.error]).toEqual([409, "LAST_CREDENTIAL"]);
  });

  it("signs an audit anchor with the passkey over HTTP; the exported bundle and events verify offline", async () => {
    const ao = await req("/api/audit/anchor/options", { body: {}, cookie, csrf });
    expect(ao.status).toBe(200);
    const av = await req("/api/audit/anchor/verify", { body: { response: auth.assert(ao.body.options), note: "e2e" }, cookie, csrf });
    expect(av.status).toBe(200);
    const bundle = (await req(`/api/audit/anchor/${av.body.anchor_id}/export`, { body: {}, cookie, csrf })).body.bundle;
    const events = (await req("/api/audit/export", { body: { from: 0, to: 4999 }, cookie, csrf })).body.events;
    const pin = createHash("sha256").update(auth.cosePublicKey).digest("hex");
    expect(verifyAnchorBundle(bundle, { pin, origin: "http://localhost:3410", rpId: "localhost" })).toEqual({ ok: true });
    const chain = verifyChain(events);
    expect(chain.ok && chain.rows[av.body.seq]!.row_hash).toBe(bundle.anchor.head_hash);
  });

  it("a chunked body without content-length is capped while streaming", async () => {
    const big = "x".repeat(64 * 1024);
    const stream = new ReadableStream({ start(c) { c.enqueue(new TextEncoder().encode(`{"response":"${big}"}`)); c.close(); } });
    const r = await fetch(`${BASE}/api/auth/login/verify`, {
      method: "POST", headers: { "content-type": "application/json", origin: ORIGIN }, body: stream, duplex: "half",
    } as RequestInit & { duplex: "half" });
    expect(await r.json()).toEqual({ ok: false, error: "INVALID_INPUT" });
  });

  it("errors are generic codes; no database text leaks", async () => {
    const r = await req(`/api/tenants/not-a-uuid/transition`, { body: { to: "x" }, cookie, csrf });
    expect(r.body).toEqual({ ok: false, error: "INVALID_INPUT" });
    const big = await req(`/api/auth/login/verify`, { body: { response: { id: "x".repeat(40_000) } } });
    expect(big.body).toEqual({ ok: false, error: "INVALID_INPUT" });
    for (const res of [r, big]) expect(JSON.stringify(res.body)).not.toMatch(/control_|postgres|SQLSTATE|relation|permission/i);
  });

  it("a replayed-out-of-order (cloned) authenticator is FLAGGED through the real app path (final review)", async () => {
    await db.su.query("DELETE FROM control.rate_limits");
    const o1 = await req("/api/auth/login/options", { body: {} });
    const o2 = await req("/api/auth/login/options", { body: {} });
    const a1 = auth.assert(o1.body.options);             // counter n
    const a2 = auth.assert(o2.body.options);             // counter n+1
    expect((await req("/api/auth/login/verify", { body: { response: a2 } })).status).toBe(200);
    expect((await req("/api/auth/login/verify", { body: { response: a1 } })).status).toBe(401);
    const { rows } = await db.su.query("SELECT counter_suspect_at FROM control.webauthn_credentials WHERE credential_id = $1", [auth.id]);
    expect(rows[0].counter_suspect_at).not.toBeNull();
    const ev = await db.su.query("SELECT count(*)::int n FROM control.audit_events WHERE action = 'platform.credential_counter_regression'");
    expect(ev.rows[0].n).toBe(1);
    await db.su.query("UPDATE control.webauthn_credentials SET counter_suspect_at = NULL");
  });

  it("an idle-expired session is refused by the server and audited", async () => {
    const r = await loginWith(auth);
    const c2 = cookieFrom(r)!;
    await db.su.query(`UPDATE control.sessions SET last_seen_at = now() - interval '16 minutes' WHERE id_hash = sha256(convert_to($1,'UTF8'))`, [c2.split("=")[1]]);
    expect((await req("/api/auth/session", { cookie: c2 })).status).toBe(401);
    expect((await req("/", { cookie: c2, origin: null })).status).toBe(307);
    const { rows } = await db.su.query(`SELECT reason_code FROM control.audit_events WHERE action = 'platform.session_expired' ORDER BY seq DESC LIMIT 1`);
    expect(rows[0].reason_code).toBe("idle_timeout");
  });

  it("logout clears the cookie and kills the session server-side", async () => {
    const r = await req("/api/auth/logout", { body: {}, cookie, csrf });
    expect(r.status).toBe(200);
    expect(r.headers.get("set-cookie")).toMatch(/__Host-orvix_sid=;.*Max-Age=0/i);
    expect((await req("/api/auth/session", { cookie })).status).toBe(401);
  });

  it("the full audit chain verifies after the e2e run", async () => {
    const { rows } = await db.su.query(`SELECT * FROM control.audit_verify()`);
    expect(rows[0].ok).toBe(true);
  });
});

describe("browser bundle contains no server secrets or DB code", () => {
  it("client JS chunks never include pg, control_app, the DB password or SQL", async () => {
    const { readdirSync, readFileSync, statSync } = await import("node:fs");
    const path = await import("node:path");
    const dir = path.join(ROOT, ".next", "static");
    const files: string[] = [];
    const walk = (d: string) => readdirSync(d).forEach((f) => { const p = path.join(d, f); statSync(p).isDirectory() ? walk(p) : files.push(p); });
    walk(dir);
    const pw = process.env.ORVIX_DB_APP_PASSWORD!;
    for (const f of files.filter((x) => x.endsWith(".js"))) {
      const s = readFileSync(f, "utf8");
      expect(s.includes(pw), f).toBe(false);
      expect(/control\.api_|ORVIX_DB_|SELECT control\.|pg-pool|scram/i.test(s), f).toBe(false);
    }
    expect(files.length).toBeGreaterThan(0);
  });
});
