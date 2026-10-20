// Tenant lifecycle model (synthetic tenants only): state machine, role and step-up policy, reasons,
// idempotency, and one audit row per attempt in the same transaction as the change.
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { randomUUID } from "node:crypto";
import { adminWithSession, createTestDb, lastAudit, ownerWithSession, stepup, type TestDb } from "../helpers/db";

let db: TestDb;
let owner: Awaited<ReturnType<typeof ownerWithSession>>;
let admin: Awaited<ReturnType<typeof adminWithSession>>;
const tenant = async (slug: string) =>
  (await db.su.query(`SELECT id, status FROM control.tenants WHERE slug = $1`, [slug])).rows[0] as { id: string; status: string };
const move = (token: string, id: string, to: string, reason: string | null = null, note: string | null = null, rid = randomUUID()) =>
  db.api("api_tenant_transition", token, id, to, reason, note, rid);

beforeAll(async () => {
  db = await createTestDb({ seed: true });
  owner = await ownerWithSession(db);
  admin = await adminWithSession(db);
});
afterAll(async () => { await db?.drop(); });
beforeEach(async () => { await db.su.query("DELETE FROM control.rate_limits"); });

describe("reads", () => {
  it("lists synthetic tenants with metadata only", async () => {
    const r = await db.api("api_tenant_list", admin.token);
    expect(r.ok).toBe(true);
    expect(r.tenants.length).toBe(8);
    for (const t of r.tenants) {
      expect(t.is_synthetic).toBe(true);
      expect(Object.keys(t).sort()).toEqual(["admin_mfa_verified", "created_at", "display_name", "id", "is_synthetic",
        "shop_count", "slug", "status", "status_changed_at", "status_reason", "user_count"]);
    }
  });

  it("refuses without a session", async () => {
    expect(await db.api("api_tenant_list", null)).toEqual({ ok: false, error: "UNAUTHENTICATED" });
    expect(await db.api("api_tenant_get", "0".repeat(64), randomUUID())).toEqual({ ok: false, error: "UNAUTHENTICATED" });
  });

  it("shows only the transitions defined from the current state", async () => {
    const t = await tenant("syn-jade-corner"); // suspended
    const r = await db.api("api_tenant_get", owner.token, t.id);
    expect(r.transitions.map((x: { to: string }) => x.to).sort()).toEqual(["active", "archived", "locked"]);
  });
});

describe("policy", () => {
  it("refuses a transition not in the state machine (audited, no change)", async () => {
    const t = await tenant("syn-pagoda-pharm"); // draft
    expect(await move(owner.token, t.id, "active")).toEqual({ ok: false, error: "TRANSITION_NOT_ALLOWED" });
    expect((await tenant("syn-pagoda-pharm")).status).toBe("draft");
    const [a] = await lastAudit(db);
    expect([a.action, a.outcome, a.reason_code]).toEqual(["tenant.transition_refused", "denied", "TRANSITION_NOT_ALLOWED"]);
  });

  it("refuses POS-dependent steps in the foundation", async () => {
    const t = await tenant("syn-monsoon-mini"); // provisioning
    await stepup(db, owner.token, owner.auth, "tenant_transition", `${t.id}:invited`);
    expect((await move(owner.token, t.id, "invited")).error).toBe("NOT_AVAILABLE_IN_FOUNDATION");
  });

  it("suspension requires step-up, then a reason code and a note of >= 10 characters", async () => {
    const t = await tenant("syn-river-bazaar"); // active
    expect((await move(admin.token, t.id, "suspended", "test", "long enough note")).error).toBe("STEPUP_REQUIRED");
    await stepup(db, admin.token, admin.auth, "tenant_transition", `${t.id}:suspended`);
    // Reason is checked before the step-up grant is consumed, so these refusals do not burn the grant.
    expect((await move(admin.token, t.id, "suspended")).error).toBe("REASON_REQUIRED");
    expect((await move(admin.token, t.id, "suspended", "test", "short")).error).toBe("REASON_REQUIRED");
    expect((await move(admin.token, t.id, "suspended", "made_up", "long enough note")).error).toBe("REASON_REQUIRED");
    const ok = await move(admin.token, t.id, "suspended", "test", "synthetic suspension for tests");
    expect(ok).toMatchObject({ ok: true, from: "active", to: "suspended" });
  });

  it("a platform admin may suspend but only the owner may reactivate", async () => {
    const t = await tenant("syn-river-bazaar"); // now suspended
    await stepup(db, admin.token, admin.auth, "tenant_transition", `${t.id}:active`);
    expect((await move(admin.token, t.id, "active")).error).toBe("FORBIDDEN");
    const [a] = await lastAudit(db);
    expect([a.action, a.reason_code, a.actor_id]).toEqual(["tenant.transition_refused", "FORBIDDEN", admin.identityId]);
    await stepup(db, owner.token, owner.auth, "tenant_transition", `${t.id}:active`);
    expect((await move(owner.token, t.id, "active")).ok).toBe(true);
  });

  it("notice transitions need no step-up", async () => {
    const t = await tenant("syn-golden-lotus"); // active
    await db.su.query("UPDATE control.stepup_grants SET used_at = now() WHERE used_at IS NULL");
    expect((await move(admin.token, t.id, "past_due", "notice", "synthetic notice period")).ok).toBe(true);
    expect((await move(admin.token, t.id, "active")).ok).toBe(true);
  });
});

describe("audit coupling and idempotency", () => {
  it("each success writes exactly one audit row whose seq is recorded in the history", async () => {
    const t = await tenant("syn-pagoda-pharm"); // draft
    const before = (await db.su.query(`SELECT max(seq)::int mx FROM control.audit_events`)).rows[0].mx;
    const r = await move(owner.token, t.id, "provisioning");
    expect(r.ok).toBe(true);
    const after = (await db.su.query(`SELECT max(seq)::int mx FROM control.audit_events`)).rows[0].mx;
    expect(after - before).toBe(1);
    const h = (await db.su.query(`SELECT audit_seq::int s FROM control.tenant_status_history WHERE tenant_id = $1 ORDER BY id DESC LIMIT 1`, [t.id])).rows[0];
    expect(h.s).toBe(Number(r.audit_seq));
    const [a] = await lastAudit(db);
    expect(a.detail).toEqual({ from: "draft", to: "provisioning", synthetic: true });
  });

  it("the same request id replays the result with no second effect or audit row", async () => {
    const t = await tenant("syn-teak-house"); // past_due
    const rid = randomUUID();
    const first = await move(owner.token, t.id, "active", null, null, rid);
    const seq = (await db.su.query(`SELECT max(seq)::int mx FROM control.audit_events`)).rows[0].mx;
    const second = await move(owner.token, t.id, "active", null, null, rid);
    expect(second).toEqual({ ...first, replayed: true });
    expect((await db.su.query(`SELECT max(seq)::int mx FROM control.audit_events`)).rows[0].mx).toBe(seq);
    // Another identity cannot reuse that request id.
    expect((await move(admin.token, t.id, "past_due", "notice", "a different request", rid)).error).toBe("REQUEST_ID_CONFLICT");
  });

  it("a request id is mandatory", async () => {
    const t = await tenant("syn-golden-lotus");
    expect(await db.api("api_tenant_transition", owner.token, t.id, "past_due", "notice", "synthetic notice", null))
      .toEqual({ ok: false, error: "REQUEST_ID_REQUIRED" });
  });

  it("the chain verifies after all lifecycle activity", async () => {
    const v = await db.api("api_audit_verify", owner.token);
    expect(v).toMatchObject({ ok: true, intact: true });
  });
});
