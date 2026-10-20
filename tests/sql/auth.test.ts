// Authentication rules enforced by the database, driven with real WebAuthn evidence (software authenticator).
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import pg from "pg";
import { superuserConfig } from "../../scripts/env";
import {
  adminWithSession, assertionParts, createTestDb, enrolWithToken, hostBootstrap, lastAudit, login, loginToken,
  ownerWithSession, resetRateLimits, stepup, type TestDb,
} from "../helpers/db";
import { SoftAuthenticator } from "../helpers/softAuthenticator";

describe("owner bootstrap (host only)", () => {
  let db: TestDb;
  beforeAll(async () => { db = await createTestDb({ seed: false }); });
  afterAll(async () => { await db?.drop(); });

  it("control_app cannot bootstrap at all (no grant)", async () => {
    const err = await db.app.query("SELECT control.host_bootstrap_owner('x@example.invalid', 'X')").catch((e) => e);
    expect(err.code).toBe("42501");
    const { rows } = await db.su.query("SELECT count(*)::int n FROM control.platform_identities");
    expect(rows[0].n).toBe(0);
  });

  it("succeeds exactly once under a concurrent host race", async () => {
    const pools = Array.from({ length: 6 }, () => new pg.Pool({ ...superuserConfig(), database: db.name, max: 1 }));
    const results = await Promise.all(pools.map((p, i) =>
      p.query("SELECT control.host_bootstrap_owner($1, $2) AS r", [`owner${i}@example.invalid`, `Owner ${i}`]).then((x) => x.rows[0].r)));
    await Promise.all(pools.map((p) => p.end()));
    expect(results.filter((r) => r.ok)).toHaveLength(1);
    expect(results.filter((r) => !r.ok).every((r) => r.error === "ALREADY_BOOTSTRAPPED")).toBe(true);
    const { rows } = await db.su.query("SELECT count(*)::int n FROM control.platform_identities");
    expect(rows[0].n).toBe(1);
  });

  it("stores only the hash of the enrolment token", async () => {
    const { rows } = await db.su.query("SELECT length(token_hash) AS l FROM control.enrolment_tokens");
    expect(rows).toEqual([{ l: 32 }]);
  });

  it("rejects invalid input without creating an identity", async () => {
    const db2 = await createTestDb({ seed: false });
    try {
      expect(await hostBootstrap(db2, "not-an-email", "X")).toEqual({ ok: false, error: "INVALID_INPUT" });
    } finally {
      await db2.drop();
    }
  });
});

describe("enrolment by token", () => {
  let db: TestDb;
  let token: string;
  beforeAll(async () => { db = await createTestDb({ seed: false }); token = (await hostBootstrap(db)).enrolment_token; });
  afterAll(async () => { await db?.drop(); });

  it("refuses unknown and malformed tokens (audited)", async () => {
    expect((await db.api("api_enrol_begin", "f".repeat(64))).error).toBe("INVALID_TOKEN");
    expect((await db.api("api_enrol_begin", "'; DROP TABLE x; --")).error).toBe("INVALID_TOKEN");
    const [a] = await lastAudit(db);
    expect([a.action, a.outcome]).toEqual(["platform.enrol_failed", "denied"]);
  });

  it("refuses an attestation over a challenge the database did not issue", async () => {
    const auth = new SoftAuthenticator();
    const reg = auth.register({ challenge: Buffer.alloc(32, 7).toString("base64url"), user: { id: "eA" } });
    const r = await db.api("api_enrol_complete", token, Buffer.from(reg.response.attestationObject, "base64url"),
      Buffer.from(reg.response.clientDataJSON, "base64url"), "x");
    expect(r.error).toBe("INVALID_CHALLENGE");
  });

  it("refuses a login challenge used for registration, a wrong origin, a wrong RP ID and missing UV", async () => {
    const lb = await db.api("api_login_begin");
    const auth = new SoftAuthenticator();
    const reg = auth.register({ challenge: lb.challenge, user: { id: "eA" } });
    expect((await db.api("api_enrol_complete", token, Buffer.from(reg.response.attestationObject, "base64url"),
      Buffer.from(reg.response.clientDataJSON, "base64url"), "x")).error).toBe("INVALID_CHALLENGE");
    for (const [opts, code] of [[{ origin: "https://evil.example" }, "BAD_CLIENT_DATA"], [{ rpId: "evil.example" }, "RP_ID_MISMATCH"],
                                [{ uv: false }, "USER_NOT_VERIFIED"], [{ type: "webauthn.get" }, "BAD_CLIENT_DATA"]] as const) {
      const b = await db.api("api_enrol_begin", token);
      const rr = new SoftAuthenticator().register({ challenge: b.challenge, user: { id: "eA" } }, opts);
      const res = await db.api("api_enrol_complete", token, Buffer.from(rr.response.attestationObject, "base64url"),
        Buffer.from(rr.response.clientDataJSON, "base64url"), "x");
      expect(res.error, JSON.stringify(opts)).toBe(code);
    }
  });

  it("refuses a non-'none' attestation format", async () => {
    const b = await db.api("api_enrol_begin", token);
    const reg = new SoftAuthenticator().register({ challenge: b.challenge, user: { id: "eA" } });
    const att = Buffer.from(reg.response.attestationObject, "base64url");
    att.write("pack", 9, "latin1"); // "none" -> "pack"
    const r = await db.api("api_enrol_complete", token, att, Buffer.from(reg.response.clientDataJSON, "base64url"), "x");
    expect(r.error).toBe("UNSUPPORTED_ATTESTATION");
  });

  it("completes once, closes bootstrap, then refuses token reuse", async () => {
    const auth = new SoftAuthenticator();
    expect((await enrolWithToken(db, token, auth)).ok).toBe(true);
    expect((await db.api("api_enrol_begin", token)).error).toBe("INVALID_TOKEN");
    expect((await db.su.query("SELECT closed FROM control.bootstrap_state")).rows[0].closed).toBe(true);
    expect((await hostBootstrap(db, "x@example.invalid", "X")).error).toBe("ALREADY_BOOTSTRAPPED");
    const { rows } = await db.su.query("SELECT credential_id, sign_count, created_via FROM control.webauthn_credentials");
    expect(rows).toEqual([{ credential_id: auth.id, sign_count: "0", created_via: "bootstrap" }]);
  });

  it("refuses an expired token", async () => {
    const db2 = await createTestDb({ seed: false });
    try {
      const t = (await hostBootstrap(db2)).enrolment_token;
      await db2.su.query("UPDATE control.enrolment_tokens SET expires_at = now() - interval '1 second'");
      expect((await db2.api("api_enrol_begin", t)).error).toBe("INVALID_TOKEN");
    } finally {
      await db2.drop();
    }
  });
});

describe("login", () => {
  let db: TestDb;
  let owner: Awaited<ReturnType<typeof ownerWithSession>>;
  beforeAll(async () => { db = await createTestDb({ seed: false }); owner = await ownerWithSession(db); });
  afterAll(async () => { await db?.drop(); });
  beforeEach(async () => { await resetRateLimits(db); });

  it("issues an opaque 256-bit token and stores only its SHA-256", async () => {
    expect(owner.token).toMatch(/^[0-9a-f]{64}$/);
    const { rows } = await db.su.query("SELECT count(*)::int n FROM control.sessions WHERE id_hash = sha256(convert_to($1,'UTF8'))", [owner.token]);
    expect(rows[0].n).toBe(1);
  });

  it("the database generates challenges (32 random bytes, base64url)", async () => {
    const a = await db.api("api_login_begin");
    const b = await db.api("api_login_begin");
    expect(a.challenge).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(a.challenge).not.toBe(b.challenge);
  });

  it("a signed assertion is single-use (replay refused, audited)", async () => {
    const b = await db.api("api_login_begin");
    const a = assertionParts(owner.auth.assert({ challenge: b.challenge }));
    expect((await db.api("api_login_complete", a.id, a.cdj, a.ad, a.sig)).ok).toBe(true);
    expect(await db.api("api_login_complete", a.id, a.cdj, a.ad, a.sig)).toEqual({ ok: false, error: "INVALID_CHALLENGE" });
    const [e] = await lastAudit(db);
    expect([e.action, e.outcome, e.reason_code]).toEqual(["platform.login_failed", "denied", "INVALID_CHALLENGE"]);
  });

  it("refuses an expired challenge and a challenge issued for another purpose", async () => {
    const b = await db.api("api_login_begin");
    await db.su.query("UPDATE control.webauthn_challenges SET expires_at = now() - interval '1 second' WHERE challenge_hash = sha256(convert_to($1,'UTF8'))", [b.challenge]);
    const a = assertionParts(owner.auth.assert({ challenge: b.challenge }));
    expect((await db.api("api_login_complete", a.id, a.cdj, a.ad, a.sig)).error).toBe("INVALID_CHALLENGE");
    const s = await db.api("api_stepup_begin", owner.token, "credential_add", owner.identityId);
    const a2 = assertionParts(owner.auth.assert({ challenge: s.challenge }));
    expect((await db.api("api_login_complete", a2.id, a2.cdj, a2.ad, a2.sig)).error).toBe("INVALID_CHALLENGE");
  });

  it("a validly signed but stale counter is refused and FLAGGED, never auto-disabled (no last-passkey lockout)", async () => {
    const db2 = await createTestDb({ seed: false });
    try {
      const o = await ownerWithSession(db2);
      const stale = await login(db2, o.auth, { counter: 1 }); // counter already 1 from the first login
      expect(stale.error).toBe("COUNTER_REGRESSION");
      const { rows } = await db2.su.query("SELECT disabled_at, counter_suspect_at FROM control.webauthn_credentials");
      expect(rows[0].disabled_at).toBeNull();
      expect(rows[0].counter_suspect_at).not.toBeNull();
      expect((await db2.api("api_session_get", o.token))).toMatchObject({ ok: true, flagged_credentials: 1 });
      expect((await login(db2, o.auth)).ok).toBe(true); // a fresh, increasing counter still works
      const ev = (await lastAudit(db2, 5)).find((e) => e.action === "platform.credential_counter_regression");
      expect(ev?.detail).toEqual({ stored: 1, presented: 1 });
    } finally {
      await db2.drop();
    }
  });

  it("per-credential rate limit refuses the 6th attempt in a window", async () => {
    const results: string[] = [];
    const stranger = new SoftAuthenticator();
    for (let i = 0; i < 6; i++) results.push((await login(db, stranger)).error);
    expect(results.slice(0, 5).every((e) => e === "UNKNOWN_CREDENTIAL")).toBe(true);
    expect(results[5]).toBe("RATE_LIMITED");
  });

  it("global login rate limit applies to challenge issuance (audited)", async () => {
    const out: boolean[] = [];
    for (let i = 0; i < 21; i++) out.push((await db.api("api_login_begin")).ok);
    expect(out.filter(Boolean)).toHaveLength(20);
    expect(out[20]).toBe(false);
    const [e] = await lastAudit(db);
    expect([e.action, e.reason_code]).toEqual(["platform.rate_limited", "RATE_LIMITED"]);
  });
});

describe("sessions", () => {
  let db: TestDb;
  let owner: Awaited<ReturnType<typeof ownerWithSession>>;
  beforeAll(async () => { db = await createTestDb({ seed: false }); owner = await ownerWithSession(db); });
  afterAll(async () => { await db?.drop(); });
  beforeEach(async () => { await resetRateLimits(db); });

  const backdate = (token: string, set: string) =>
    db.su.query(`UPDATE control.sessions SET ${set} WHERE id_hash = sha256(convert_to($1,'UTF8'))`, [token]);

  it("resolves a live session", async () => {
    expect(await db.api("api_session_get", owner.token)).toMatchObject({ ok: true, role: "owner", active_credentials: 1 });
  });

  it("refuses malformed, unknown and empty tokens", async () => {
    for (const t of [null, "", "abc", "g".repeat(64), "0".repeat(64)]) {
      expect(await db.api("api_session_get", t)).toEqual({ ok: false, error: "UNAUTHENTICATED" });
    }
  });

  it("expires after 15 minutes idle, once, audited", async () => {
    const t = await loginToken(db, owner.auth);
    await backdate(t, "last_seen_at = now() - interval '15 minutes 1 second'");
    expect((await db.api("api_session_get", t)).ok).toBe(false);
    const [a] = await lastAudit(db);
    expect([a.action, a.reason_code]).toEqual(["platform.session_expired", "idle_timeout"]);
    await backdate(t, "last_seen_at = now()");
    expect((await db.api("api_session_get", t)).ok).toBe(false);
  });

  it("does not expire at 14 minutes idle", async () => {
    const t = await loginToken(db, owner.auth);
    await backdate(t, "last_seen_at = now() - interval '14 minutes'");
    expect((await db.api("api_session_get", t)).ok).toBe(true);
  });

  it("expires at the 8-hour absolute limit even while active", async () => {
    const t = await loginToken(db, owner.auth);
    const { rows } = await db.su.query("SELECT absolute_expires_at - created_at AS d FROM control.sessions WHERE id_hash = sha256(convert_to($1,'UTF8'))", [t]);
    expect(rows[0].d).toMatchObject({ hours: 8 });
    await backdate(t, "absolute_expires_at = now() - interval '1 second', last_seen_at = now()");
    expect((await db.api("api_session_get", t)).ok).toBe(false);
    expect((await lastAudit(db))[0].reason_code).toBe("absolute_timeout");
  });

  it("logout revokes the session and any unused step-up grants", async () => {
    const t = await loginToken(db, owner.auth);
    expect((await stepup(db, t, owner.auth, "credential_add", owner.identityId)).ok).toBe(true);
    expect(await db.api("api_session_revoke", t)).toEqual({ ok: true });
    expect((await db.api("api_session_get", t)).ok).toBe(false);
    const { rows } = await db.su.query("SELECT count(*)::int n FROM control.stepup_grants WHERE used_at IS NULL");
    expect(rows[0].n).toBe(0);
  });

  it("revoking the identity kills its live sessions and blocks login", async () => {
    const admin = await adminWithSession(db);
    await db.su.query("UPDATE control.platform_identities SET state = 'revoked', revoked_at = now() WHERE id = $1", [admin.identityId]);
    expect((await db.api("api_session_get", admin.token)).ok).toBe(false);
    expect((await lastAudit(db))[0].reason_code).toBe("identity_inactive");
    expect((await login(db, admin.auth)).error).toBe("IDENTITY_INACTIVE");
  });
});
