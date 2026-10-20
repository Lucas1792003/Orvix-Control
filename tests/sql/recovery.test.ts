// Lost-device recovery: host request (superuser) + approval by a DIFFERENT owner with a bound step-up.
// No single identity can complete recovery for itself.
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import pg from "pg";
import { superuserConfig } from "../../scripts/env";
import {
  adminWithSession, createTestDb, enrolWithToken, hostBootstrap, lastAudit, login, loginToken, operatorFixture, ownerWithSession,
  resetRateLimits, stepup, type Operator, type TestDb,
} from "../helpers/db";
import { SoftAuthenticator } from "../helpers/softAuthenticator";

let db: TestDb;
let subject: Operator & { enrolmentToken: string };
let approver: Operator;
let admin: Operator;
const hostRequest = async (email: string, reason = "lost both passkeys in a fire (synthetic)") =>
  (await db.su.query("SELECT control.host_recovery_request($1, $2) AS r", [email, reason])).rows[0].r;

beforeAll(async () => {
  db = await createTestDb({ seed: false });
  subject = await ownerWithSession(db, "owner@example.invalid");
  approver = await operatorFixture(db, "owner", "owner-b@example.invalid");
  admin = await adminWithSession(db);
});
afterAll(async () => { await db?.drop(); });
beforeEach(async () => { await resetRateLimits(db); });

describe("request", () => {
  it("control_app cannot create a recovery request (host only)", async () => {
    const err = await db.app.query("SELECT control.host_recovery_request('owner@example.invalid', 'some reason here')").catch((e) => e);
    expect(err.code).toBe("42501");
  });

  it("the host request alone grants nothing and needs a reason", async () => {
    expect((await hostRequest("owner@example.invalid", "short")).error).toBe("REASON_REQUIRED");
    expect((await hostRequest("nobody@example.invalid")).error).toBe("NOT_FOUND");
    const r = await hostRequest("owner@example.invalid");
    expect(r.ok).toBe(true);
    expect((await hostRequest("owner@example.invalid")).error).toBe("ALREADY_OPEN");
    const { rows } = await db.su.query("SELECT count(*)::int n FROM control.enrolment_tokens WHERE purpose = 'recovery'");
    expect(rows[0].n).toBe(0);
    expect((await lastAudit(db))[0].action).toBe("platform.recovery_requested");
  });
});

describe("approval", () => {
  let requestId: string;
  beforeAll(async () => {
    requestId = (await db.su.query("SELECT id FROM control.recovery_requests WHERE state = 'pending'")).rows[0].id;
  });

  it("owners see all open requests; others see only their own", async () => {
    expect((await db.api("api_recovery_list", admin.token)).requests).toEqual([]);
    const l = await db.api("api_recovery_list", approver.token);
    expect(l.requests).toHaveLength(1);
    expect(l.requests[0].subject_is_you).toBe(false);
  });

  it("the subject cannot approve their own recovery", async () => {
    // (no step-up by the subject here: signing with their passkey would trip the SUBJECT_ACTIVE guard)
    expect((await db.api("api_recovery_approve", subject.token, requestId)).error).toBe("SELF_APPROVAL_FORBIDDEN");
    const [a] = await lastAudit(db);
    expect([a.action, a.reason_code]).toEqual(["platform.recovery_refused", "SELF_APPROVAL_FORBIDDEN"]);
  });

  it("a platform admin cannot approve", async () => {
    expect((await stepup(db, admin.token, admin.auth, "recovery_approve", requestId)).ok).toBe(true);
    expect((await db.api("api_recovery_approve", admin.token, requestId)).error).toBe("FORBIDDEN");
  });

  it("another owner needs a step-up bound to THIS request", async () => {
    expect((await db.api("api_recovery_approve", approver.token, requestId)).error).toBe("STEPUP_REQUIRED");
    expect((await stepup(db, approver.token, approver.auth, "recovery_approve", "00000000-0000-0000-0000-000000000000")).ok).toBe(true);
    expect((await db.api("api_recovery_approve", approver.token, requestId)).error).toBe("STEPUP_REQUIRED");
  });

  let recoveryToken: string;
  it("approval by a second owner issues a one-time token, once", async () => {
    expect((await stepup(db, approver.token, approver.auth, "recovery_approve", requestId)).ok).toBe(true);
    const r = await db.api("api_recovery_approve", approver.token, requestId);
    expect(r.ok).toBe(true);
    recoveryToken = r.enrolment_token;
    expect(recoveryToken).toMatch(/^[0-9a-f]{64}$/);
    expect((await stepup(db, approver.token, approver.auth, "recovery_approve", requestId)).ok).toBe(true);
    expect((await db.api("api_recovery_approve", approver.token, requestId)).error).toBe("NOT_FOUND");
  });

  it("redeeming the token disables every old passkey and ends every old session", async () => {
    await db.su.query("DELETE FROM control.rate_limits");
    const fresh = new SoftAuthenticator();
    const r = await enrolWithToken(db, recoveryToken, fresh, "replacement");
    expect(r.ok).toBe(true);
    expect((await db.api("api_session_get", subject.token)).ok).toBe(false);
    expect((await login(db, subject.auth)).error).toBe("UNKNOWN_CREDENTIAL");
    expect((await login(db, fresh)).ok).toBe(true);
    const { rows } = await db.su.query(
      "SELECT created_via, disabled_reason FROM control.webauthn_credentials WHERE identity_id = $1 ORDER BY created_at", [subject.identityId]);
    expect(rows).toEqual([{ created_via: "bootstrap", disabled_reason: "recovered" }, { created_via: "recovery", disabled_reason: null }]);
    expect((await db.su.query("SELECT state FROM control.recovery_requests WHERE id = $1", [requestId])).rows[0].state).toBe("redeemed");
    const done = (await lastAudit(db, 5)).find((e) => e.action === "platform.recovery_completed");
    expect(done?.detail).toMatchObject({ credentials_disabled: 1 });
  });

  it("the recovery token is single-use", async () => {
    expect((await enrolWithToken(db, recoveryToken, new SoftAuthenticator())).error).toBe("INVALID_TOKEN");
  });
});

describe("limits", () => {
  it("an expired request cannot be approved", async () => {
    const r = await hostRequest("admin@example.invalid", "synthetic: admin lost device");
    await db.su.query("UPDATE control.recovery_requests SET expires_at = now() - interval '1 second' WHERE id = $1", [r.request_id]);
    expect((await stepup(db, approver.token, approver.auth, "recovery_approve", r.request_id)).ok).toBe(true);
    expect((await db.api("api_recovery_approve", approver.token, r.request_id)).error).toBe("NOT_FOUND");
  });

  it("a single-owner install cannot recover its owner (documented owner decision, no bypass)", async () => {
    const solo = await createTestDb({ seed: false });
    try {
      const o = await ownerWithSession(solo);
      const r = (await solo.su.query("SELECT control.host_recovery_request('owner@example.invalid', 'synthetic: single owner lost key') AS r")).rows[0].r;
      expect(r.ok).toBe(true);
      // The only owner is the subject; nobody else can approve. C1.3: an owner under recovery cannot even step up for it.
      expect((await solo.api("api_stepup_begin", o.token, "recovery_approve", r.request_id)).error).toBe("IDENTITY_UNDER_RECOVERY");
      expect((await solo.api("api_recovery_approve", o.token, r.request_id)).error).toBe("SELF_APPROVAL_FORBIDDEN");
      const { rows } = await solo.su.query("SELECT count(*)::int n FROM control.platform_identities WHERE role = 'owner' AND state = 'active'");
      expect(rows[0].n).toBe(1);
    } finally {
      await solo.drop();
    }
  });
});

describe("request state binding and cancellation (review R-M2)", () => {
  let d: TestDb; let s1: Operator; let b: Operator;
  const req = async (reason = "synthetic: lost device") =>
    (await d.su.query("SELECT control.host_recovery_request('owner@example.invalid', $1) AS r", [reason])).rows[0].r;
  const approve = async (id: string) => {
    expect((await stepup(d, b.token, b.auth, "recovery_approve", id)).ok).toBe(true);
    return d.api("api_recovery_approve", b.token, id);
  };
  beforeAll(async () => {
    d = await createTestDb({ seed: false });
    s1 = await ownerWithSession(d);
    b = await operatorFixture(d, "owner", "owner-b@example.invalid");
  });
  afterAll(async () => { await d?.drop(); });

  it("a token from an expired, superseded request is dead", async () => {
    const r1 = await req();
    const t1 = (await approve(r1.request_id)).enrolment_token;
    await d.su.query("UPDATE control.recovery_requests SET expires_at = now() - interval '1 second' WHERE id = $1", [r1.request_id]);
    const r2 = await req();
    expect(r2.ok).toBe(true);
    expect((await d.su.query("SELECT state FROM control.recovery_requests WHERE id = $1", [r1.request_id])).rows[0].state).toBe("cancelled");
    expect((await enrolWithToken(d, t1, new SoftAuthenticator())).error).toBe("INVALID_TOKEN");
    expect((await d.su.query("SELECT control.host_recovery_cancel($1) AS r", [r2.request_id])).rows[0].r.ok).toBe(true);
  });

  it("an approved request can be cancelled by another owner (step-up), which kills its token", async () => {
    const r = await req();
    const tok = (await approve(r.request_id)).enrolment_token;
    expect((await d.api("api_recovery_cancel", b.token, r.request_id)).error).toBe("STEPUP_REQUIRED");
    expect((await stepup(d, b.token, b.auth, "recovery_cancel", r.request_id)).ok).toBe(true);
    expect((await d.api("api_recovery_cancel", b.token, r.request_id)).ok).toBe(true);
    expect((await enrolWithToken(d, tok, new SoftAuthenticator())).error).toBe("INVALID_TOKEN");
  });

  it("control_app cannot use the host cancel", async () => {
    const err = await d.app.query("SELECT control.host_recovery_cancel(gen_random_uuid())").catch((e) => e);
    expect(err.code).toBe("42501");
  });

  it("an active (or objecting) subject turns recovery into a DELAY plus host confirmation, never a veto", async () => {
    const r = await req();
    await d.su.query("DELETE FROM control.rate_limits");
    expect((await login(d, s1.auth)).ok).toBe(true); // a passkey of the subject was used after the request
    expect((await stepup(d, b.token, b.auth, "recovery_approve", r.request_id)).ok).toBe(true);
    expect((await d.api("api_recovery_approve", b.token, r.request_id)).error).toBe("RECOVERY_CONTESTED");
    // host confirms out of band; still refused until the 12 h delay has passed
    expect((await d.su.query("SELECT control.host_recovery_confirm($1) AS r", [r.request_id])).rows[0].r.ok).toBe(true);
    expect((await stepup(d, b.token, b.auth, "recovery_approve", r.request_id)).ok).toBe(true);
    expect((await d.api("api_recovery_approve", b.token, r.request_id)).error).toBe("RECOVERY_CONTESTED");
    await d.su.query("UPDATE control.recovery_requests SET requested_at = now() - interval '12 hours 1 minute' WHERE id = $1", [r.request_id]);
    const ok = await d.api("api_recovery_approve", b.token, r.request_id);
    expect(ok.ok).toBe(true);
    expect((await d.su.query("SELECT control.host_recovery_cancel($1) AS r", [r.request_id])).rows[0].r.ok).toBe(true);
  });

  it("the subject's own cancel only CONTESTS (a thief with the subject's passkey cannot end the request)", async () => {
    const r = await req();
    expect((await stepup(d, s1.token, s1.auth, "recovery_cancel", r.request_id)).ok).toBe(true);
    expect(await d.api("api_recovery_cancel", s1.token, r.request_id)).toEqual({ ok: true, contested: true, link_voided: false });
    const st = (await d.su.query("SELECT state, contested_at FROM control.recovery_requests WHERE id = $1", [r.request_id])).rows[0];
    expect(st.state).toBe("pending");
    expect(st.contested_at).not.toBeNull();
    expect((await d.su.query("SELECT control.host_recovery_cancel($1) AS r", [r.request_id])).rows[0].r.ok).toBe(true);
  });

  it("stolen-device path: host emergency revoke locks the thief out, then normal two-person recovery works", async () => {
    const x = await createTestDb({ seed: false });
    try {
      const victim = await ownerWithSession(x, "victim@example.invalid");
      const other = await operatorFixture(x, "owner", "other@example.invalid");
      const err = await x.app.query("SELECT control.host_revoke_operator_credentials('victim@example.invalid', 'stolen laptop and key')").catch((e) => e);
      expect(err.code).toBe("42501"); // host only
      const rv = (await x.su.query("SELECT control.host_revoke_operator_credentials('victim@example.invalid', 'stolen laptop and key') AS r")).rows[0].r;
      expect(rv).toMatchObject({ ok: true, credentials_disabled: 1 });
      expect((await x.api("api_session_get", victim.token)).ok).toBe(false);   // thief's session is gone
      expect((await login(x, victim.auth)).error).toBe("UNKNOWN_CREDENTIAL");   // and the stolen passkey is dead
      const rq = (await x.su.query("SELECT control.host_recovery_request('victim@example.invalid', 'stolen laptop and key') AS r")).rows[0].r;
      // NEW-B: after an emergency revoke the request is contested: host confirmation + 12 h are required
      expect((await stepup(x, other.token, other.auth, "recovery_approve", rq.request_id)).ok).toBe(true);
      expect((await x.api("api_recovery_approve", other.token, rq.request_id)).error).toBe("RECOVERY_CONTESTED");
      expect((await x.su.query("SELECT control.host_recovery_confirm($1) AS r", [rq.request_id])).rows[0].r.ok).toBe(true);
      await x.su.query("UPDATE control.recovery_requests SET requested_at = requested_at - interval '13 hours' WHERE id = $1", [rq.request_id]);
      await x.su.query("UPDATE control.platform_identities SET emergency_revoked_at = emergency_revoked_at - interval '13 hours' WHERE email = 'victim@example.invalid'");
      await x.su.query("UPDATE control.recovery_requests SET host_confirmed_at = now() WHERE id = $1", [rq.request_id]);
      const ap = await x.api("api_recovery_approve", other.token, rq.request_id);
      expect(ap.ok).toBe(true);
      expect((await enrolWithToken(x, ap.enrolment_token, new SoftAuthenticator())).ok).toBe(true);
    } finally {
      await x.drop();
    }
  });

  it("activity by a FLAGGED (possibly cloned) passkey does not contest a recovery", async () => {
    const x = await createTestDb({ seed: false });
    try {
      const victim = await ownerWithSession(x, "victim@example.invalid");
      const other = await operatorFixture(x, "owner", "other@example.invalid");
      const rq = (await x.su.query("SELECT control.host_recovery_request('victim@example.invalid', 'suspected cloned key') AS r")).rows[0].r;
      await x.su.query("UPDATE control.webauthn_credentials SET counter_suspect_at = now(), last_used_at = now() WHERE identity_id = $1", [victim.identityId]);
      expect((await stepup(x, other.token, other.auth, "recovery_approve", rq.request_id)).ok).toBe(true);
      expect((await x.api("api_recovery_approve", other.token, rq.request_id)).ok).toBe(true);
    } finally {
      await x.drop();
    }
  });

  it("a stranger cannot exhaust a valid enrolment link's rate limit with junk tokens", async () => {
    const fresh = await createTestDb({ seed: false });
    try {
      const boot = await hostBootstrap(fresh);
      for (let i = 0; i < 40; i++) await fresh.api("api_enrol_begin", "f".repeat(64));
      expect((await fresh.api("api_enrol_begin", boot.enrolment_token)).ok).toBe(true);
    } finally {
      await fresh.drop();
    }
  });

  it("an expired, unused bootstrap link can be re-issued by the host while the owner is still enrolling", async () => {
    const fresh = await createTestDb({ seed: false });
    try {
      const boot = await hostBootstrap(fresh);
      expect((await hostBootstrap(fresh)).error).toBe("ALREADY_BOOTSTRAPPED"); // still valid -> no re-issue
      await fresh.su.query("UPDATE control.enrolment_tokens SET expires_at = now() - interval '1 second'");
      const again = await hostBootstrap(fresh);
      expect(again).toMatchObject({ ok: true, reissued: true, identity_id: boot.identity_id });
      expect((await enrolWithToken(fresh, again.enrolment_token, new SoftAuthenticator())).ok).toBe(true);
      expect((await hostBootstrap(fresh)).error).toBe("ALREADY_BOOTSTRAPPED");
    } finally {
      await fresh.drop();
    }
  });
});

describe("contest semantics (round 3)", () => {
  it("NEW-A: a host confirmation made before the subject objects does not override the objection", async () => {
    const x = await createTestDb({ seed: false });
    try {
      const subj = await ownerWithSession(x, "subj@example.invalid");
      const other = await operatorFixture(x, "owner", "other@example.invalid");
      const rq = (await x.su.query("SELECT control.host_recovery_request('subj@example.invalid', 'reported lost device') AS r")).rows[0].r;
      expect((await x.su.query("SELECT control.host_recovery_confirm($1) AS r", [rq.request_id])).rows[0].r.ok).toBe(true);
      expect((await stepup(x, subj.token, subj.auth, "recovery_cancel", rq.request_id)).ok).toBe(true);
      expect((await x.api("api_recovery_cancel", subj.token, rq.request_id)).contested).toBe(true);
      await x.su.query("UPDATE control.recovery_requests SET requested_at = requested_at - interval '13 hours', contested_at = contested_at - interval '13 hours' WHERE id = $1", [rq.request_id]);
      await x.su.query("UPDATE control.webauthn_credentials SET last_used_at = now() - interval '14 hours'");
      expect((await stepup(x, other.token, other.auth, "recovery_approve", rq.request_id)).ok).toBe(true);
      expect((await x.api("api_recovery_approve", other.token, rq.request_id)).error).toBe("RECOVERY_CONTESTED");
      expect((await x.su.query("SELECT host_confirmed_at FROM control.recovery_requests WHERE id = $1", [rq.request_id])).rows[0].host_confirmed_at).toBeNull();
    } finally {
      await x.drop();
    }
  });

  it("NEW-B: an emergency revoke immediately followed by approval cannot skip the delay", async () => {
    const x = await createTestDb({ seed: false });
    try {
      await ownerWithSession(x, "subj@example.invalid");
      const other = await operatorFixture(x, "owner", "other@example.invalid");
      const rq = (await x.su.query("SELECT control.host_recovery_request('subj@example.invalid', 'reported lost device') AS r")).rows[0].r;
      await x.su.query("SELECT control.host_revoke_operator_credentials('subj@example.invalid', 'emergency lockout test')");
      await x.su.query("SELECT control.host_recovery_confirm($1)", [rq.request_id]);
      expect((await stepup(x, other.token, other.auth, "recovery_approve", rq.request_id)).ok).toBe(true);
      expect((await x.api("api_recovery_approve", other.token, rq.request_id)).error).toBe("RECOVERY_CONTESTED");
    } finally {
      await x.drop();
    }
  });
});

describe("final checkpoint review fixes", () => {
  const delayAgo = "interval '12 hours 1 minute'";
  async function setup() {
    const x = await createTestDb({ seed: false });
    const subj = await ownerWithSession(x, "subj@example.invalid");
    const other = await operatorFixture(x, "owner", "other@example.invalid");
    const rq = (await x.su.query("SELECT control.host_recovery_request('subj@example.invalid', 'reported lost device') AS r")).rows[0].r;
    return { x, subj, other, id: rq.request_id as string };
  }
  const object = async (x: TestDb, op: Operator, id: string) => {
    expect((await stepup(x, op.token, op.auth, "recovery_cancel", id)).ok).toBe(true);
    return x.api("api_recovery_cancel", op.token, id);
  };
  const approve = async (x: TestDb, op: Operator, id: string) => {
    expect((await stepup(x, op.token, op.auth, "recovery_approve", id)).ok).toBe(true);
    return x.api("api_recovery_approve", op.token, id);
  };

  it("repeated objections do not restart the delay, and contesting keeps the request alive long enough", async () => {
    const { x, subj, other, id } = await setup();
    try {
      await object(x, subj, id);
      await x.su.query(`UPDATE control.recovery_requests SET requested_at = requested_at - ${delayAgo}, contested_at = contested_at - ${delayAgo} WHERE id = $1`, [id]);
      await x.su.query("DELETE FROM control.rate_limits");
      await object(x, subj, id);                                   // late second objection
      const row = (await x.su.query("SELECT expires_at - clock_timestamp() AS left, contested_at < last_contested_at AS first_kept FROM control.recovery_requests WHERE id = $1", [id])).rows[0];
      expect(row.first_kept).toBe(true);
      expect(row.left.hours).toBeGreaterThanOrEqual(23);          // delay + window fit inside the lifetime
      // the subject keeps using the passkey -> host breaks the loop with revoke-operator, then confirms
      expect((await x.su.query("SELECT control.host_revoke_operator_credentials('subj@example.invalid', 'objection loop by thief') AS r")).rows[0].r.ok).toBe(true);
      await x.su.query("SELECT control.host_recovery_confirm($1)", [id]);
      expect((await approve(x, other, id)).error).toBe("RECOVERY_CONTESTED");   // delay now runs from the revoke
      await x.su.query(`UPDATE control.platform_identities SET emergency_revoked_at = emergency_revoked_at - ${delayAgo} WHERE email = 'subj@example.invalid'`);
      await x.su.query(`UPDATE control.recovery_requests SET last_contested_at = last_contested_at - ${delayAgo} WHERE id = $1`, [id]);
      await x.su.query("SELECT control.host_recovery_confirm($1)", [id]);
      expect((await approve(x, other, id)).ok).toBe(true);
    } finally { await x.drop(); }
  });

  it("an objection AFTER approval voids the link and returns the request to pending", async () => {
    const { x, subj, other, id } = await setup();
    try {
      await x.su.query("UPDATE control.webauthn_credentials SET last_used_at = now() - interval '1 day'");
      const ap = await approve(x, other, id);
      expect(ap.ok).toBe(true);
      await x.su.query("DELETE FROM control.rate_limits");
      expect(await object(x, subj, id)).toMatchObject({ ok: true, contested: true, link_voided: true });
      expect((await x.su.query("SELECT state FROM control.recovery_requests WHERE id = $1", [id])).rows[0].state).toBe("pending");
      expect((await enrolWithToken(x, ap.enrolment_token, new SoftAuthenticator())).error).toBe("INVALID_TOKEN");
    } finally { await x.drop(); }
  });

  it("an emergency revoke voids an already-approved link; revoking the LAST owner needs --force", async () => {
    const { x, other, id } = await setup();
    try {
      await x.su.query("UPDATE control.webauthn_credentials SET last_used_at = now() - interval '1 day'");
      const ap = await approve(x, other, id);
      expect(ap.ok).toBe(true);
      expect((await x.su.query("SELECT control.host_revoke_operator_credentials('subj@example.invalid', 'stolen approved link') AS r")).rows[0].r.ok).toBe(true);
      expect((await enrolWithToken(x, ap.enrolment_token, new SoftAuthenticator())).error).toBe("INVALID_TOKEN");
      const last = (await x.su.query("SELECT control.host_revoke_operator_credentials('other@example.invalid', 'testing last owner guard') AS r")).rows[0].r;
      expect(last.error).toBe("LAST_OWNER");
      const forced = (await x.su.query("SELECT control.host_revoke_operator_credentials('other@example.invalid', 'testing last owner guard', true) AS r")).rows[0].r;
      expect(forced.ok).toBe(true);
    } finally { await x.drop(); }
  });

  it("activity after a host confirmation requires a NEW confirmation", async () => {
    const { x, subj, other, id } = await setup();
    try {
      await x.su.query("SELECT control.host_recovery_confirm($1)", [id]);
      await x.su.query(`UPDATE control.recovery_requests SET requested_at = requested_at - ${delayAgo}, host_confirmed_at = host_confirmed_at - ${delayAgo} WHERE id = $1`, [id]);
      await x.su.query("DELETE FROM control.rate_limits");
      expect((await login(x, subj.auth)).ok).toBe(true);           // activity AFTER the confirmation
      expect((await approve(x, other, id)).error).toBe("RECOVERY_CONTESTED");
      await x.su.query("SELECT control.host_recovery_confirm($1)", [id]);
      expect((await approve(x, other, id)).ok).toBe(true);
    } finally { await x.drop(); }
  });

  it("a re-filed request inherits a recent objection", async () => {
    const { x, subj, id } = await setup();
    try {
      await object(x, subj, id);
      await x.su.query("SELECT control.host_recovery_cancel($1)", [id]);
      const again = (await x.su.query("SELECT control.host_recovery_request('subj@example.invalid', 'second request') AS r")).rows[0].r;
      expect(again).toMatchObject({ ok: true, contested: true });
    } finally { await x.drop(); }
  });
});

describe("final review follow-ups (recovery)", () => {
  it("two concurrent revoke-operator calls on the only two owners cannot both pass the LAST_OWNER guard", async () => {
    const x = await createTestDb({ seed: false });
    try {
      await ownerWithSession(x, "a@example.invalid");
      await operatorFixture(x, "owner", "b@example.invalid");
      const pools = [0, 1].map(() => new pg.Pool({ ...superuserConfig(), database: x.name, max: 1 }));
      const res = await Promise.all([
        pools[0]!.query("SELECT control.host_revoke_operator_credentials('a@example.invalid', 'concurrent revoke test') AS r").then((q) => q.rows[0].r),
        pools[1]!.query("SELECT control.host_revoke_operator_credentials('b@example.invalid', 'concurrent revoke test') AS r").then((q) => q.rows[0].r),
      ]);
      await Promise.all(pools.map((p) => p.end()));
      expect(res.filter((r) => r.ok)).toHaveLength(1);
      expect(res.find((r) => !r.ok)?.error).toBe("LAST_OWNER");
    } finally { await x.drop(); }
  });

  it("an objection is inherited by a request re-filed after the previous one EXPIRED", async () => {
    const x = await createTestDb({ seed: false });
    try {
      const subj = await ownerWithSession(x, "subj@example.invalid");
      await operatorFixture(x, "owner", "other@example.invalid");
      const rq = (await x.su.query("SELECT control.host_recovery_request('subj@example.invalid', 'reported lost device') AS r")).rows[0].r;
      expect((await stepup(x, subj.token, subj.auth, "recovery_cancel", rq.request_id)).ok).toBe(true);
      expect((await x.api("api_recovery_cancel", subj.token, rq.request_id)).contested).toBe(true);
      // the request expires on its own (objection 25 h ago, request expired an hour ago)
      await x.su.query("UPDATE control.recovery_requests SET last_contested_at = now() - interval '25 hours', contested_at = now() - interval '25 hours', expires_at = now() - interval '1 hour' WHERE id = $1", [rq.request_id]);
      const again = (await x.su.query("SELECT control.host_recovery_request('subj@example.invalid', 'second request') AS r")).rows[0].r;
      expect(again).toMatchObject({ ok: true, contested: true });
    } finally { await x.drop(); }
  });
});
