// Audit continuity across the 203 -> 206 upgrade: events written under the old schema stay verifiable, the
// upgrade itself is audited, pre-upgrade sessions and non-ES256 credentials stop working, and the whole history
// (old + new) verifies offline against a passkey-signed anchor made after the upgrade.
import { createHash, randomBytes } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import pg from "pg";
import { superuserConfig } from "../../scripts/env";
import { migrate } from "../../scripts/migrator";
import { createTestDb, exportAll, operatorFixture, signAnchor, type TestDb } from "../helpers/db";
import { generateKeyPairSync } from "node:crypto";
import { ed25519Fingerprint, verifyAnchorBundle, verifyArchive } from "../../scripts/verify-audit";
import { signAnchor as signOffline } from "../../scripts/anchor-sign";

let db: TestDb;
let oldToken: string;
let preUpgradeHead: { seq: number; hash: string };

beforeAll(async () => {
  db = await createTestDb({ seed: true, upTo: "203" });
  // --- old (pre-205) flow, as it existed: control_app could bootstrap and "complete" logins with no signature.
  const q = async (sql: string, args: unknown[]) => (await db.app.query(sql, args)).rows[0].r;
  const boot = await q("SELECT control.api_bootstrap_owner($1, $2) AS r", ["old@example.invalid", "Old Owner"]);
  const cred = randomBytes(32).toString("base64url");
  const ch1 = randomBytes(32).toString("base64url");
  await q("SELECT control.api_enrol_begin($1, $2) AS r", [boot.enrolment_token, ch1]);
  await q("SELECT control.api_enrol_complete($1, $2, $3, $4, $5, $6) AS r", [boot.enrolment_token, ch1, cred, randomBytes(77), 0, ["internal"]]);
  const ch2 = randomBytes(32).toString("base64url");
  await q("SELECT control.api_login_begin($1) AS r", [ch2]);
  oldToken = (await q("SELECT control.api_login_complete($1, $2, $3) AS r", [ch2, cred, 0])).session_token;
  await q("SELECT control.api_tenant_list($1) AS r", [oldToken]);
  const h = (await db.su.query("SELECT seq::int, encode(row_hash,'hex') h FROM control.audit_events ORDER BY seq DESC LIMIT 1")).rows[0];
  preUpgradeHead = { seq: h.seq, hash: h.h };
  // --- upgrade
  const c = new pg.Client({ ...superuserConfig(), database: db.name });
  await c.connect();
  const { applied } = await migrate(c);
  await c.end();
  expect(applied).toEqual(["204_webauthn_crypto.sql", "205_auth_trust_boundary.sql", "206_signed_audit_anchors.sql", "207_review_hardening.sql", "208_review_round2.sql", "209_review_round3.sql", "210_final_review.sql", "211_final_review_followup.sql",
      "212_oob_notifications.sql", "213_scoped_login_limits.sql", "214_txn_watchdog_shadow_audit.sql", "215_operator_invitations.sql",
      "216_review_211_fixes.sql", "217_review_c1_2_fixes.sql", "218_watchdog_intents.sql", "219_recovery_auth_hardening.sql", "220_sentinel_delivery.sql", "221_privileges_tenant_contract.sql", "222_pos_recovery_bridge.sql"]);
});
afterAll(async () => { await db?.drop(); });

describe("upgrade 203 -> 222", () => {
  it("pre-upgrade events are untouched and the chain continues from them", async () => {
    const { rows } = await db.su.query("SELECT encode(row_hash,'hex') h FROM control.audit_events WHERE seq = $1", [preUpgradeHead.seq]);
    expect(rows[0].h).toBe(preUpgradeHead.hash);
    const next = (await db.su.query("SELECT action, encode(prev_hash,'hex') p FROM control.audit_events WHERE seq = $1", [preUpgradeHead.seq + 1])).rows[0];
    expect(next).toEqual({ action: "platform.sessions_revoked", p: preUpgradeHead.hash });
    expect((await db.su.query("SELECT * FROM control.audit_verify()")).rows[0].ok).toBe(true);
  });

  it("pre-upgrade sessions are dead and the unverifiable legacy credential is disabled", async () => {
    expect((await db.api("api_session_get", oldToken)).ok).toBe(false);
    const { rows } = await db.su.query("SELECT disabled_reason FROM control.webauthn_credentials");
    expect(rows).toEqual([{ disabled_reason: "unsupported_key_format" }]);
  });

  it("the legacy trust-me entry points are gone", async () => {
    for (const sql of ["SELECT control.api_bootstrap_owner('a@example.invalid','A')",
                       "SELECT control.api_login_complete('x', 'y', 0::bigint)"]) {
      const e = await db.app.query(sql).catch((x) => x);
      expect(["42883", "42501"]).toContain(e.code);
    }
  });

  it("the whole history (pre- and post-upgrade) verifies offline against a post-upgrade signed anchor", async () => {
    const owner = await operatorFixture(db, "owner", "new-owner@example.invalid");
    await db.api("api_tenant_list", owner.token);
    const s = await signAnchor(db, owner);
    expect(s.ok).toBe(true);
    const bundle = (await db.api("api_anchor_export", owner.token, s.anchor_id)).bundle;
    const events = await exportAll(db, owner);
    expect(events[0]!.action).toBe("audit.genesis");
    const pin = createHash("sha256").update(owner.auth.cosePublicKey).digest("hex");
    expect(verifyAnchorBundle(bundle, { pin, origin: "http://localhost:3410", rpId: "localhost" })).toEqual({ ok: true });
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const v2 = signOffline(events, [], privateKey.export({ type: "pkcs8", format: "pem" }).toString());
    expect(v2.ok).toBe(true);
    const fp = ed25519Fingerprint(Buffer.from(publicKey.export({ format: "jwk" }).x!, "base64url"));
    if (v2.ok) expect(verifyArchive(events, { v1: [bundle], v2: [v2.anchor] }, { anchorKey: fp, pin, origin: "http://localhost:3410", rpId: "localhost" }))
      .toMatchObject({ ok: true, unanchoredTail: 0 });
    expect(Number(s.seq)).toBeGreaterThan(preUpgradeHead.seq);
  });
});
