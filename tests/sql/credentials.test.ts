// Multiple passkeys per operator: authenticated enrolment with action-bound step-up, revocation, final-passkey
// protection, concurrency, and step-up replay.
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import pg from "pg";
import { appConfig } from "../../scripts/env";
import {
  activatePending, addCredential, adminWithSession, assertionParts, createTestDb, lastAudit, login, loginToken, ownerWithSession,
  resetRateLimits, stepup, type Operator, type TestDb,
} from "../helpers/db";
import { SoftAuthenticator } from "../helpers/softAuthenticator";

const B = (s: string) => Buffer.from(s, "base64url");
let db: TestDb;
beforeAll(async () => { db = await createTestDb({ seed: true }); });
afterAll(async () => { await db?.drop(); });
beforeEach(async () => { await resetRateLimits(db); });

const credIdFor = async (auth: SoftAuthenticator) =>
  (await db.su.query("SELECT id FROM control.webauthn_credentials WHERE credential_id = $1", [auth.id])).rows[0].id as string;
const activeCount = async (identity: string) =>
  Number((await db.su.query("SELECT count(*) n FROM control.webauthn_credentials WHERE identity_id = $1 AND disabled_at IS NULL", [identity])).rows[0].n);

describe("adding passkeys", () => {
  let owner: Operator;
  const backup = new SoftAuthenticator();
  beforeAll(async () => { owner = await ownerWithSession(db); });

  it("refuses without a session, and without a step-up (audited)", async () => {
    expect((await db.api("api_credential_add_begin", "0".repeat(64))).error).toBe("UNAUTHENTICATED");
    expect((await db.api("api_credential_add_begin", owner.token)).error).toBe("STEPUP_REQUIRED");
    const [a] = await lastAudit(db);
    expect([a.action, a.reason_code]).toEqual(["platform.credential_add_failed", "STEPUP_REQUIRED"]);
  });

  it("a step-up for a different action or target does not authorise enrolment", async () => {
    const t = (await db.su.query("SELECT id FROM control.tenants LIMIT 1")).rows[0].id;
    expect((await stepup(db, owner.token, owner.auth, "tenant_transition", `${t}:suspended`)).ok).toBe(true);
    expect((await stepup(db, owner.token, owner.auth, "credential_add", "00000000-0000-0000-0000-000000000000")).ok).toBe(true);
    expect((await db.api("api_credential_add_begin", owner.token)).error).toBe("STEPUP_REQUIRED");
  });

  it("adds a second passkey after a bound step-up; both sign in independently", async () => {
    const r = await addCredential(db, owner.token, owner.auth, backup, owner.identityId, "backup key");
    expect(r.ok).toBe(true);
    expect(await activeCount(owner.identityId)).toBe(2);
    // pending for 15 minutes: cannot sign in yet, visible to every session of the operator
    expect((await login(db, backup)).error).toBe("CREDENTIAL_PENDING");
    expect(await db.api("api_session_get", owner.token)).toMatchObject({ pending_credentials: 1, active_credentials: 1 });
    await activatePending(db);
    expect((await login(db, owner.auth)).ok).toBe(true);
    expect((await login(db, backup)).ok).toBe(true);
    const [a] = await lastAudit(db, 20).then((x) => x.filter((e) => e.action === "platform.credential_added"));
    expect(a?.target_id).toBe(r.credential);
    const list = await db.api("api_credential_list", owner.token);
    expect(list.credentials.map((c: { nickname: string }) => c.nickname)).toEqual(["primary", "backup key"]);
  });

  it("a registration challenge is bound to the session that started it", async () => {
    const other = await loginToken(db, owner.auth);
    expect((await stepup(db, owner.token, owner.auth, "credential_add", owner.identityId)).ok).toBe(true);
    const b = await db.api("api_credential_add_begin", owner.token);
    const reg = new SoftAuthenticator().register({ challenge: b.challenge, user: { id: "eA" } });
    expect((await db.api("api_credential_add_complete", other, B(reg.response.attestationObject), B(reg.response.clientDataJSON), "x")).error)
      .toBe("INVALID_CHALLENGE");
  });

  it("another operator cannot complete an enrolment started in the owner's session", async () => {
    const admin = await adminWithSession(db);
    expect((await stepup(db, owner.token, owner.auth, "credential_add", owner.identityId)).ok).toBe(true);
    const b = await db.api("api_credential_add_begin", owner.token);
    const reg = new SoftAuthenticator().register({ challenge: b.challenge, user: { id: "eA" } });
    expect((await db.api("api_credential_add_complete", admin.token, B(reg.response.attestationObject), B(reg.response.clientDataJSON), "x")).error)
      .toBe("INVALID_CHALLENGE");
  });

  it("an already-registered authenticator cannot be added again", async () => {
    const r = await addCredential(db, owner.token, owner.auth, backup, owner.identityId);
    expect(r.error).toBe("INVALID_CREDENTIAL");
  });

  it("concurrent completions cannot exceed the per-operator maximum", async () => {
    const db2 = await createTestDb({ seed: false });
    try {
      const o = await ownerWithSession(db2);
      await db2.su.query("UPDATE control.settings SET value = '3' WHERE key = 'max_credentials_per_identity'");
      // Prepare 4 enrolments (each with its own step-up), then complete all 4 at once.
      const prepared = [];
      for (let i = 0; i < 4; i++) {
        expect((await stepup(db2, o.token, o.auth, "credential_add", o.identityId)).ok).toBe(true);
        const b = await db2.api("api_credential_add_begin", o.token);
        expect(b.ok).toBe(true);
        prepared.push(new SoftAuthenticator().register({ challenge: b.challenge, user: { id: "eA" } }));
      }
      const pools = prepared.map(() => new pg.Pool({ ...appConfig(), database: db2.name, max: 1 }));
      const results = await Promise.all(prepared.map((reg, i) => pools[i]!.query(
        "SELECT control.api_credential_add_complete($1, $2, $3, $4) AS r",
        [o.token, B(reg.response.attestationObject), B(reg.response.clientDataJSON), `k${i}`]).then((x) => x.rows[0].r)));
      await Promise.all(pools.map((p) => p.end()));
      expect(results.filter((r) => r.ok)).toHaveLength(2);
      expect(results.filter((r) => !r.ok).every((r) => r.error === "TOO_MANY_CREDENTIALS")).toBe(true);
      expect(Number((await db2.su.query("SELECT count(*) n FROM control.webauthn_credentials WHERE disabled_at IS NULL")).rows[0].n)).toBe(3);
    } finally {
      await db2.drop();
    }
  });
});

describe("revoking passkeys", () => {
  let o: Operator; const k2 = new SoftAuthenticator(); const k3 = new SoftAuthenticator();
  let db3: TestDb;
  beforeAll(async () => {
    db3 = await createTestDb({ seed: false });
    o = await ownerWithSession(db3);
    expect((await addCredential(db3, o.token, o.auth, k2, o.identityId)).ok).toBe(true);
    expect((await addCredential(db3, o.token, o.auth, k3, o.identityId)).ok).toBe(true);
    await activatePending(db3);
  });
  afterAll(async () => { await db3?.drop(); });
  beforeEach(async () => { await resetRateLimits(db3); });
  const idOf = async (a: SoftAuthenticator) => (await db3.su.query("SELECT id FROM control.webauthn_credentials WHERE credential_id = $1", [a.id])).rows[0].id;

  it("needs a step-up bound to that exact credential", async () => {
    const id3 = await idOf(k3); const id2 = await idOf(k2);
    expect((await db3.api("api_credential_revoke", o.token, id3)).error).toBe("STEPUP_REQUIRED");
    expect((await stepup(db3, o.token, o.auth, "credential_revoke", id2)).ok).toBe(true);
    expect((await db3.api("api_credential_revoke", o.token, id3)).error).toBe("STEPUP_REQUIRED");
  });

  it("revokes, ends that passkey's sessions, refuses its future logins, and audits", async () => {
    const id3 = await idOf(k3);
    const k3Session = await loginToken(db3, k3);
    expect((await stepup(db3, o.token, o.auth, "credential_revoke", id3)).ok).toBe(true);
    const r = await db3.api("api_credential_revoke", o.token, id3);
    expect(r).toMatchObject({ ok: true, sessions_revoked: 1, current_session_ended: false });
    expect((await db3.api("api_session_get", k3Session)).ok).toBe(false);
    expect((await login(db3, k3)).error).toBe("UNKNOWN_CREDENTIAL");
    const ev = (await lastAudit(db3, 5)).find((e) => e.action === "platform.credential_revoked");
    expect(ev?.target_id).toBe(id3);
  });

  it("revoking the passkey that the current session used ends the current session", async () => {
    const k2Session = await loginToken(db3, k2);
    const id2 = await idOf(k2);
    expect((await stepup(db3, k2Session, k2, "credential_revoke", id2)).ok).toBe(true);
    expect(await db3.api("api_credential_revoke", k2Session, id2)).toMatchObject({ ok: true, current_session_ended: true });
    expect((await db3.api("api_session_get", k2Session)).ok).toBe(false);
  });

  it("the final usable passkey cannot be revoked, and the step-up grant is NOT consumed by the refusal", async () => {
    const id1 = await idOf(o.auth);
    expect((await stepup(db3, o.token, o.auth, "credential_revoke", id1)).ok).toBe(true);
    expect((await db3.api("api_credential_revoke", o.token, id1)).error).toBe("LAST_CREDENTIAL");
    const { rows } = await db3.su.query("SELECT count(*)::int n FROM control.stepup_grants WHERE action = 'credential_revoke' AND target = $1 AND used_at IS NULL", [id1]);
    expect(rows[0].n).toBe(1);
    expect((await login(db3, o.auth)).ok).toBe(true);
  });

  it("an operator cannot revoke another operator's passkey", async () => {
    const admin = await (async () => { const { operatorFixture } = await import("../helpers/db"); return operatorFixture(db3, "admin", "a2@example.invalid"); })();
    const id1 = await idOf(o.auth);
    expect((await stepup(db3, admin.token, admin.auth, "credential_revoke", id1)).ok).toBe(true);
    expect((await db3.api("api_credential_revoke", admin.token, id1)).error).toBe("NOT_FOUND");
  });
});

describe("concurrent revocation keeps one passkey", () => {
  it("session A (passkey A) revokes B while session B (passkey B) revokes A, simultaneously: one passkey survives", async () => {
    const db4 = await createTestDb({ seed: false });
    try {
      const o = await ownerWithSession(db4);
      const kB = new SoftAuthenticator();
      expect((await addCredential(db4, o.token, o.auth, kB, o.identityId)).ok).toBe(true);
      await activatePending(db4);
      const idA = (await db4.su.query("SELECT id FROM control.webauthn_credentials WHERE credential_id = $1", [o.auth.id])).rows[0].id;
      const idB = (await db4.su.query("SELECT id FROM control.webauthn_credentials WHERE credential_id = $1", [kB.id])).rows[0].id;
      const sA = o.token;
      const sB = await loginToken(db4, kB);
      expect((await stepup(db4, sA, o.auth, "credential_revoke", idB)).ok).toBe(true);
      expect((await stepup(db4, sB, kB, "credential_revoke", idA)).ok).toBe(true);
      const pools = [0, 1].map(() => new pg.Pool({ ...appConfig(), database: db4.name, max: 1 }));
      const results = await Promise.all([
        pools[0]!.query("SELECT control.api_credential_revoke($1, $2) AS r", [sA, idB]).then((x) => x.rows[0].r),
        pools[1]!.query("SELECT control.api_credential_revoke($1, $2) AS r", [sB, idA]).then((x) => x.rows[0].r),
      ]);
      await Promise.all(pools.map((p) => p.end()));
      expect(results.filter((r) => r.ok)).toHaveLength(1);
      // The loser either sees the last-passkey rule or finds its own session already ended by the winner.
      expect(["LAST_CREDENTIAL", "UNAUTHENTICATED"]).toContain(results.find((r) => !r.ok)?.error);
      expect(Number((await db4.su.query("SELECT count(*) n FROM control.webauthn_credentials WHERE disabled_at IS NULL")).rows[0].n)).toBe(1);
    } finally {
      await db4.drop();
    }
  });

  it("with three sessions on three passkeys, three concurrent cross-revocations leave at least one passkey", async () => {
    const db5 = await createTestDb({ seed: false });
    try {
      const o = await ownerWithSession(db5);
      const keys = [o.auth, new SoftAuthenticator(), new SoftAuthenticator()];
      for (const k of keys.slice(1)) expect((await addCredential(db5, o.token, o.auth, k, o.identityId)).ok).toBe(true);
      await activatePending(db5);
      const ids: string[] = [];
      for (const k of keys) ids.push((await db5.su.query("SELECT id FROM control.webauthn_credentials WHERE credential_id = $1", [k.id])).rows[0].id);
      const tokens = [o.token, await loginToken(db5, keys[1]!), await loginToken(db5, keys[2]!)];
      // session i revokes passkey (i+1) % 3
      for (let i = 0; i < 3; i++) expect((await stepup(db5, tokens[i]!, keys[i]!, "credential_revoke", ids[(i + 1) % 3]!)).ok).toBe(true);
      const pools = [0, 1, 2].map(() => new pg.Pool({ ...appConfig(), database: db5.name, max: 1 }));
      await Promise.all([0, 1, 2].map((i) => pools[i]!.query("SELECT control.api_credential_revoke($1, $2) AS r", [tokens[i], ids[(i + 1) % 3]])));
      await Promise.all(pools.map((p) => p.end()));
      expect(Number((await db5.su.query("SELECT count(*) n FROM control.webauthn_credentials WHERE disabled_at IS NULL")).rows[0].n)).toBeGreaterThanOrEqual(1);
    } finally {
      await db5.drop();
    }
  });
});

describe("step-up replay", () => {
  let o: Operator;
  let tenant: string;
  beforeAll(async () => {
    o = await (async () => { const { operatorFixture } = await import("../helpers/db"); return operatorFixture(db, "owner", "owner2@example.invalid"); })();
    tenant = (await db.su.query("SELECT id FROM control.tenants WHERE slug = 'syn-river-bazaar'")).rows[0].id;
  });
  const move = (to: string, reason: string | null, note: string | null) =>
    db.api("api_tenant_transition", o.token, tenant, to, reason, note, crypto.randomUUID());

  it("the same signed step-up assertion cannot be submitted twice", async () => {
    const b = await db.api("api_stepup_begin", o.token, "tenant_transition", `${tenant}:suspended`);
    const a = assertionParts(o.auth.assert({ challenge: b.challenge }));
    expect((await db.api("api_stepup_complete", o.token, a.id, a.cdj, a.ad, a.sig)).ok).toBe(true);
    expect((await db.api("api_stepup_complete", o.token, a.id, a.cdj, a.ad, a.sig)).error).toBe("INVALID_CHALLENGE");
    expect(Number((await db.su.query("SELECT count(*) n FROM control.stepup_grants WHERE target = $1", [`${tenant}:suspended`])).rows[0].n)).toBe(1);
  });

  it("one grant authorises exactly one action", async () => {
    expect((await move("suspended", "test", "synthetic replay check")).ok).toBe(true);
    await db.su.query("UPDATE control.tenants SET status = 'active' WHERE id = $1", [tenant]);
    expect((await move("suspended", "test", "synthetic replay check")).error).toBe("STEPUP_REQUIRED");
  });

  it("a grant expires after two minutes", async () => {
    expect((await stepup(db, o.token, o.auth, "tenant_transition", `${tenant}:suspended`)).ok).toBe(true);
    await db.su.query("UPDATE control.stepup_grants SET expires_at = now() - interval '1 second' WHERE used_at IS NULL");
    expect((await move("suspended", "test", "synthetic replay check")).error).toBe("STEPUP_REQUIRED");
  });

  it("a grant belongs to the session that earned it", async () => {
    const other = await loginToken(db, o.auth);
    expect((await stepup(db, other, o.auth, "tenant_transition", `${tenant}:suspended`)).ok).toBe(true);
    expect((await move("suspended", "test", "synthetic replay check")).error).toBe("STEPUP_REQUIRED");
  });

  it("a step-up challenge from one session cannot be completed in another", async () => {
    const other = await loginToken(db, o.auth);
    const b = await db.api("api_stepup_begin", other, "tenant_transition", `${tenant}:locked`);
    const a = assertionParts(o.auth.assert({ challenge: b.challenge }));
    expect((await db.api("api_stepup_complete", o.token, a.id, a.cdj, a.ad, a.sig)).error).toBe("INVALID_CHALLENGE");
  });

  it("step-up actions outside the allow-list are refused", async () => {
    expect((await db.api("api_stepup_begin", o.token, "anything", "x")).error).toBe("INVALID_INPUT");
    expect((await db.api("api_stepup_begin", o.token, "credential_add", "bad target with spaces")).error).toBe("INVALID_INPUT");
  });
});

describe("pending passkeys (relay mitigation, review F4/M-4)", () => {
  it("a just-added passkey cannot sign in or step up, can be revoked during the window, and does not count as usable", async () => {
    const d = await createTestDb({ seed: false });
    try {
      const o = await ownerWithSession(d);
      const rogue = new SoftAuthenticator();
      const r = await addCredential(d, o.token, o.auth, rogue, o.identityId, "rogue");
      expect(r.ok).toBe(true);
      expect(new Date(r.usable_after).getTime() - Date.now()).toBeGreaterThan(14 * 60_000);
      expect((await login(d, rogue)).error).toBe("CREDENTIAL_PENDING");
      const sb = await d.api("api_stepup_begin", o.token, "credential_add", o.identityId);
      expect(sb.credential_ids).toEqual([o.auth.id]); // pending key is not offered for step-up
      const id = (await d.su.query("SELECT id FROM control.webauthn_credentials WHERE credential_id = $1", [rogue.id])).rows[0].id;
      const list = await d.api("api_credential_list", o.token);
      expect(list.credentials.find((c: { id: string }) => c.id === id).pending_until).not.toBeNull();
      // the original passkey is still the last USABLE one, so it cannot be revoked while the other is pending
      const primary = (await d.su.query("SELECT id FROM control.webauthn_credentials WHERE credential_id = $1", [o.auth.id])).rows[0].id;
      expect((await stepup(d, o.token, o.auth, "credential_revoke", primary)).ok).toBe(true);
      expect((await d.api("api_credential_revoke", o.token, primary)).error).toBe("LAST_CREDENTIAL");
      // but the pending one can be revoked
      expect((await stepup(d, o.token, o.auth, "credential_revoke", id)).ok).toBe(true);
      expect((await d.api("api_credential_revoke", o.token, id)).ok).toBe(true);
    } finally {
      await d.drop();
    }
  });

  it("a step-up grant dies with the passkey that earned it", async () => {
    const d = await createTestDb({ seed: true });
    try {
      const o = await ownerWithSession(d);
      const k2 = new SoftAuthenticator();
      expect((await addCredential(d, o.token, o.auth, k2, o.identityId)).ok).toBe(true);
      await activatePending(d);
      const t = (await d.su.query("SELECT id FROM control.tenants WHERE slug = 'syn-river-bazaar'")).rows[0].id;
      expect((await stepup(d, o.token, k2, "tenant_transition", `${t}:suspended`)).ok).toBe(true);
      const id2 = (await d.su.query("SELECT id FROM control.webauthn_credentials WHERE credential_id = $1", [k2.id])).rows[0].id;
      expect((await stepup(d, o.token, o.auth, "credential_revoke", id2)).ok).toBe(true);
      expect((await d.api("api_credential_revoke", o.token, id2)).ok).toBe(true);
      const r = await d.api("api_tenant_transition", o.token, t, "suspended", "test", "grant from revoked key", crypto.randomUUID());
      expect(r.error).toBe("STEPUP_REQUIRED");
    } finally {
      await d.drop();
    }
  });
});
