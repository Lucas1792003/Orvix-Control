// Per-test-file throwaway database inside the isolated orvix-control-db container, plus helpers that drive
// real WebAuthn ceremonies (software authenticator) through the database API exactly as the server does.
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import path from "node:path";
import pg from "pg";
import { appConfig, devDbTarget, loadDevEnv, ROOT, sentinelConfig, superuserConfig } from "../../scripts/env";
import { migrate, setAppPassword } from "../../scripts/migrator";
import { SoftAuthenticator } from "./softAuthenticator";

export type TestDb = {
  name: string;
  su: pg.Pool;   // superuser: host-only functions, fixtures, backdating, tamper simulation ONLY
  app: pg.Pool;  // control_app: everything the server would do
  api: (fn: string, ...args: unknown[]) => Promise<any>;
  drop: () => Promise<void>;
};

const B = (s: string) => Buffer.from(s, "base64url");

export async function createTestDb(opts: { name?: string; seed?: boolean; upTo?: string; notify?: boolean } = {}): Promise<TestDb> {
  loadDevEnv();
  devDbTarget();
  const name = opts.name ?? `orvix_control_test_${randomBytes(5).toString("hex")}`;
  const admin = new pg.Client({ ...superuserConfig(), database: "orvix_control" });
  await admin.connect();
  await admin.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
  await admin.query(`CREATE DATABASE ${name}`);
  await admin.end();

  const mig = new pg.Client({ ...superuserConfig(), database: name });
  await mig.connect();
  await migrate(mig, { upTo: opts.upTo });
  await setAppPassword(mig, process.env.ORVIX_DB_APP_PASSWORD!);
  if (opts.seed !== false) {
    for (const f of ["pos_mock.sql", "synthetic_tenants.sql"]) {
      await mig.query(readFileSync(path.join(ROOT, "db", "dev", f), "utf8"));
    }
  }
  // A host out-of-band channel, as an operator would configure (212). Without one, gated actions stay blocked.
  if (opts.notify !== false && (await mig.query("SELECT to_regproc('control.host_add_notify_channel') IS NOT NULL AS x")).rows[0].x) {
    await mig.query("SELECT control.host_add_notify_channel('host', NULL, 'file', '/dev/null', NULL)");
  }
  await mig.end();

  const su = new pg.Pool({ ...superuserConfig(), database: name, max: 4 });
  const app = new pg.Pool({ ...appConfig(), database: name, max: 6 });
  const api = async (fn: string, ...args: unknown[]) => {
    if (!/^api_[a-z_]+$/.test(fn)) throw new Error("bad fn");
    const ph = args.map((_, i) => `$${i + 1}`).join(", ");
    const { rows } = await app.query(`SELECT control.${fn}(${ph}) AS r`, args);
    return rows[0].r;
  };
  return {
    name, su, app, api,
    drop: async () => {
      await su.end();
      await app.end();
      const c = new pg.Client({ ...superuserConfig(), database: "orvix_control" });
      await c.connect();
      await c.query(`DROP DATABASE IF EXISTS ${name} WITH (FORCE)`);
      await c.end();
    },
  };
}

export async function lastAudit(db: TestDb, n = 1) {
  const { rows } = await db.su.query(`SELECT * FROM control.audit_events ORDER BY seq DESC LIMIT $1`, [n]);
  return rows;
}

export async function resetRateLimits(db: TestDb) {
  await db.su.query("DELETE FROM control.rate_limits");
}

// ------------------------------------------------------------ ceremonies through the DB API

export type Assertion = { id: string; cdj: Buffer; ad: Buffer; sig: Buffer };
export function assertionParts(r: ReturnType<SoftAuthenticator["assert"]>): Assertion {
  return { id: r.id, cdj: B(r.response.clientDataJSON), ad: B(r.response.authenticatorData), sig: B(r.response.signature) };
}

export async function hostBootstrap(db: TestDb, email = "owner@example.invalid", name = "Test Owner") {
  const { rows } = await db.su.query("SELECT control.host_bootstrap_owner($1, $2) AS r", [email, name]);
  return rows[0].r;
}

// Stands in for scripts/sentinel.ts: claims pending notices AS control_sentinel and acknowledges them delivered.
export async function deliverAll(db: TestDb): Promise<number> {
  if (!(await db.su.query("SELECT to_regproc('control.sentinel_claim') IS NOT NULL AS x")).rows[0].x) return 0;
  const sp = new pg.Pool({ ...sentinelConfig(), database: db.name, max: 1 });
  let n = 0;
  try {
    for (;;) {
      const { rows } = await sp.query("SELECT * FROM control.sentinel_claim(100, NULL)");
      if (rows.length === 0) break;
      for (const r of rows) { await sp.query("SELECT control.sentinel_ack($1, $2, $3, true, NULL)", [r.outbox_id, r.channel_id, r.claim_token]); n++; }
    }
  } finally {
    await sp.end();
  }
  return n;
}

export async function enrolWithToken(db: TestDb, token: string, auth: SoftAuthenticator, nickname = "primary",
                                     opts: { deliver?: boolean } = {}) {
  if (opts.deliver !== false) await deliverAll(db);
  const b = await db.api("api_enrol_begin", token);
  if (!b.ok) return b;
  const reg = auth.register({ challenge: b.challenge, user: { id: Buffer.from(b.identity_id).toString("base64url") } });
  return db.api("api_enrol_complete", token, B(reg.response.attestationObject), B(reg.response.clientDataJSON), nickname);
}

export async function login(db: TestDb, auth: SoftAuthenticator, opts: Parameters<SoftAuthenticator["assert"]>[1] = {},
                            deviceToken: string | null = null) {
  const b = await db.api("api_login_begin", deviceToken);
  if (!b.ok) return b;
  const a = assertionParts(auth.assert({ challenge: b.challenge }, opts));
  return db.api("api_login_complete", a.id, a.cdj, a.ad, a.sig, deviceToken);
}

export async function loginToken(db: TestDb, auth: SoftAuthenticator): Promise<string> {
  const r = await login(db, auth);
  if (!r.ok) throw new Error(`login: ${r.error}`);
  return r.session_token;
}

export async function stepup(db: TestDb, token: string, auth: SoftAuthenticator, action: string, target: string) {
  const b = await db.api("api_stepup_begin", token, action, target);
  if (!b.ok) return b;
  const a = assertionParts(auth.assert({ challenge: b.challenge }));
  return db.api("api_stepup_complete", token, a.id, a.cdj, a.ad, a.sig);
}

export async function addCredential(db: TestDb, token: string, existing: SoftAuthenticator, fresh: SoftAuthenticator,
                                    identityId: string, nickname = "backup") {
  const s = await stepup(db, token, existing, "credential_add", identityId);
  if (!s.ok) return s;
  const b = await db.api("api_credential_add_begin", token);
  if (!b.ok) return b;
  const reg = fresh.register({ challenge: b.challenge, user: { id: Buffer.from(identityId).toString("base64url") } });
  return db.api("api_credential_add_complete", token, B(reg.response.attestationObject), B(reg.response.clientDataJSON), nickname);
}

export type Operator = { identityId: string; auth: SoftAuthenticator; token: string };

// Host bootstrap + passkey enrolment + login, all through the real ceremonies.
export async function ownerWithSession(db: TestDb, email = "owner@example.invalid"): Promise<Operator & { enrolmentToken: string }> {
  const boot = await hostBootstrap(db, email);
  if (!boot.ok) throw new Error(`bootstrap: ${boot.error}`);
  const auth = new SoftAuthenticator();
  const e = await enrolWithToken(db, boot.enrolment_token, auth);
  if (!e.ok) throw new Error(`enrol: ${e.error}`);
  return { identityId: boot.identity_id, auth, token: await loginToken(db, auth), enrolmentToken: boot.enrolment_token };
}

// Fixture: an already-active operator (the invitation flow is not built), inserted by the superuser with a
// REAL public key so that it can sign in through the normal ceremony.
export async function operatorFixture(db: TestDb, role: "admin" | "owner", email: string): Promise<Operator> {
  const auth = new SoftAuthenticator();
  const { rows } = await db.su.query(
    `INSERT INTO control.platform_identities (email, display_name, role, state, activated_at)
     VALUES ($1, $2, $3, 'active', now()) RETURNING id`, [email, `Test ${role} ${email.split("@")[0]}`, role]);
  await db.su.query(
    `INSERT INTO control.webauthn_credentials (identity_id, credential_id, public_key, created_via) VALUES ($1, $2, $3, 'bootstrap')`,
    [rows[0].id, auth.id, auth.cosePublicKey]);
  return { identityId: rows[0].id, auth, token: await loginToken(db, auth) };
}

export const adminWithSession = (db: TestDb) => operatorFixture(db, "admin", "admin@example.invalid");

// Owner signs the current audit head with a passkey (206).
export async function signAnchor(db: TestDb, op: Operator, note = "test anchor") {
  const b = await db.api("api_anchor_begin", op.token);
  if (!b.ok) return b;
  const a = assertionParts(op.auth.assert({ challenge: b.challenge }));
  return db.api("api_anchor_complete", op.token, a.id, a.cdj, a.ad, a.sig, note);
}

export async function exportAll(db: TestDb, op: Operator) {
  const events: unknown[] = [];
  for (let from = 0; ; from += 5000) {
    const r = await db.api("api_audit_export", op.token, from, from + 4999);
    if (!r.ok) throw new Error(r.error);
    events.push(...r.events);
    if (r.events.length < 5000) break;
  }
  return events as import("../../scripts/verify-audit").ExportedEvent[];
}

export async function recomputeChainAsSuperuser(db: TestDb, editSql?: string) {
  const c = await db.su.connect();
  try {
    await c.query("SET session_replication_role = replica");
    if (editSql) await c.query(editSql);
    await c.query(`DO $$ DECLARE r record; prev bytea; BEGIN
      FOR r IN SELECT * FROM control.audit_events ORDER BY seq LOOP
        IF r.seq = 0 THEN prev := r.row_hash; CONTINUE; END IF;
        UPDATE control.audit_events SET prev_hash = prev,
          row_hash = control.audit_row_hash(prev, control.audit_canonical(r.seq, r.occurred_at, r.actor_type, r.actor_id,
            r.actor_label, r.action, r.outcome, r.target_type, r.target_id, r.request_id, r.reason_code, r.detail))
         WHERE seq = r.seq RETURNING row_hash INTO prev;
      END LOOP; END $$`);
  } finally {
    await c.query("RESET session_replication_role");
    c.release();
  }
}

// New in-session passkeys are pending for 15 minutes (207). Tests that need them immediately end the wait.
export async function activatePending(db: TestDb) {
  await deliverAll(db);
  await db.su.query("UPDATE control.webauthn_credentials SET usable_after = now() WHERE usable_after > now()");
  await backdateDeliveries(db);
}

// The reaction window for an added passkey counts from DELIVERY of its notice (217): tests end it by backdating.
export async function backdateDeliveries(db: TestDb) {
  await db.su.query("UPDATE control.notify_deliveries SET delivered_at = delivered_at - interval '1 day' WHERE delivered_at > now() - interval '1 day'");
}

// Step 5: the POS Recovery V1 operator-interface MOCK (db/dev/pos_recovery_mock.sql), loaded by the superuser. Its
// `GRANT orvix_recovery_operator TO control_definer` is a CLUSTER-WIDE role membership: create every other test
// database of the file BEFORE loading it (migration 207 refuses to run while a control role has memberships), and
// call revokePosRecoveryGrant when done (test files run one at a time).
export async function installPosRecoveryMock(db: TestDb) {
  await db.su.query(readFileSync(path.join(ROOT, "db", "dev", "pos_recovery_mock.sql"), "utf8"));
}

export async function revokePosRecoveryGrant(su: pg.Pool) {
  await su.query(`DO $$ BEGIN
    IF to_regrole('orvix_recovery_operator') IS NOT NULL THEN REVOKE orvix_recovery_operator FROM control_definer; END IF;
  END $$`);
}
