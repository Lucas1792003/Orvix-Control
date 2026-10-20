// Role privileges: control_app can do exactly one thing (EXECUTE control.api_*), and no control role can
// touch tenant tables. pos_mock is a synthetic stand-in for POS tenant tables.
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createTestDb, type TestDb } from "../helpers/db";

const EXPECTED_APP_FUNCTIONS = [
  "api_anchor_begin", "api_anchor_complete", "api_anchor_export", "api_anchor_list", "api_audit_export",
  "api_audit_list", "api_audit_verify", "api_auth_failed", "api_contract_version", "api_credential_add_begin",
  "api_credential_add_complete", "api_credential_list", "api_credential_lookup", "api_credential_revoke",
  "api_enrol_begin", "api_enrol_complete", "api_login_begin", "api_login_complete", "api_operator_invite", "api_operator_invite_revoke",
  "api_operator_list", "api_recovery_approve", "api_recovery_cancel", "api_recovery_list", "api_session_get", "api_session_revoke", "api_stepup_begin", "api_stepup_complete",
  "api_tenant_get", "api_tenant_list", "api_tenant_transition",
].sort();
// api_* functions and the role that must own each group.
const AUTH_OWNED = ["api_anchor_begin", "api_anchor_complete", "api_auth_failed", "api_credential_add_begin",
  "api_credential_add_complete", "api_credential_list", "api_credential_lookup", "api_credential_revoke", "api_enrol_begin",
  "api_enrol_complete", "api_login_begin", "api_login_complete", "api_operator_invite", "api_operator_invite_revoke",
  "api_operator_list", "api_recovery_approve", "api_recovery_cancel", "api_recovery_list",
  "api_session_get", "api_session_revoke", "api_stepup_begin", "api_stepup_complete"];
const AUDIT_OWNED = ["api_audit_list", "api_audit_verify", "api_anchor_list", "api_anchor_export", "api_audit_export"];
const CONTROL_ROLES = ["control_app", "control_definer", "control_audit_owner", "control_auth", "control_schema_owner"];

let db: TestDb;
beforeAll(async () => { db = await createTestDb(); });
afterAll(async () => { await db?.drop(); });

async function deniedAsApp(sql: string) {
  const err = await db.app.query(sql).then(() => null, (e: { code?: string }) => e);
  return err?.code;
}

describe("role attributes", () => {
  it("no control role is superuser, BYPASSRLS, CREATEROLE, CREATEDB or REPLICATION; only control_app logs in", async () => {
    const { rows } = await db.su.query(
      `SELECT rolname, rolsuper, rolbypassrls, rolcreaterole, rolcreatedb, rolreplication, rolcanlogin, rolinherit, rolconnlimit
         FROM pg_roles WHERE rolname = ANY($1) ORDER BY rolname`, [CONTROL_ROLES]);
    expect(rows).toHaveLength(5);
    for (const r of rows) {
      expect([r.rolsuper, r.rolbypassrls, r.rolcreaterole, r.rolcreatedb, r.rolreplication]).toEqual([false, false, false, false, false]);
      expect(r.rolinherit).toBe(false);
      expect(r.rolcanlogin).toBe(r.rolname === "control_app");
    }
    expect(rows.find((r) => r.rolname === "control_app")!.rolconnlimit).toBe(8);
  });

  it("control_app is not a member of any role (cannot SET ROLE to the definer)", async () => {
    const { rows } = await db.su.query(
      `SELECT count(*)::int AS n FROM pg_auth_members m JOIN pg_roles r ON r.oid = m.member WHERE r.rolname = 'control_app'`);
    expect(rows[0].n).toBe(0);
    expect(await deniedAsApp("SET ROLE control_definer")).toBe("42501");
  });

  it("control_app runs with statement and idle-in-transaction timeouts", async () => {
    const { rows } = await db.app.query(`SELECT current_setting('statement_timeout') AS st, current_setting('idle_in_transaction_session_timeout') AS it`);
    expect(rows[0]).toEqual({ st: "5s", it: "10s" });
  });
});

describe("no table privileges for control_app anywhere", () => {
  it("has no privilege on any table, view or sequence in any schema", async () => {
    const { rows } = await db.su.query(
      `SELECT n.nspname || '.' || c.relname AS rel
         FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE c.relkind IN ('r','v','m','p','f','S')
          AND n.nspname NOT IN ('pg_catalog','information_schema') AND n.nspname NOT LIKE 'pg_toast%'
          AND (CASE WHEN c.relkind = 'S' THEN has_sequence_privilege('control_app', c.oid, 'USAGE,SELECT,UPDATE')
                    ELSE has_table_privilege('control_app', c.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER') END)`);
    expect(rows).toEqual([]);
  });

  it("has USAGE on schema control only (not public, control_ext, control_ledger, pos_mock)", async () => {
    const { rows } = await db.su.query(
      `SELECT nspname FROM pg_namespace WHERE has_schema_privilege('control_app', oid, 'USAGE')
         AND nspname NOT IN ('pg_catalog','information_schema') AND nspname NOT LIKE 'pg_toast%' AND nspname NOT LIKE 'pg_temp%'
       ORDER BY 1`);
    expect(rows.map((r) => r.nspname)).toEqual(["control"]);
    const { rows: create } = await db.su.query(
      `SELECT nspname FROM pg_namespace WHERE has_schema_privilege('control_app', oid, 'CREATE')`);
    expect(create).toEqual([]);
  });

  it("is refused at runtime on tenant and control tables", async () => {
    expect(await deniedAsApp("SELECT * FROM pos_mock.sales")).toBe("42501");
    expect(await deniedAsApp("SELECT * FROM pos_mock.organizations")).toBe("42501");
    expect(await deniedAsApp("SELECT * FROM control.sessions")).toBe("42501");
    expect(await deniedAsApp("SELECT * FROM control.tenants")).toBe("42501");
    expect(await deniedAsApp("SELECT * FROM control.webauthn_credentials")).toBe("42501");
    expect(await deniedAsApp("SELECT * FROM control.audit_events")).toBe("42501");
    expect(await deniedAsApp("SELECT * FROM control_ledger.schema_migrations")).toBe("42501");
  });

  it("cannot create temporary tables or objects", async () => {
    expect(await deniedAsApp("CREATE TEMP TABLE x (a int)")).toBe("42501");
    expect(await deniedAsApp("CREATE TABLE control.x (a int)")).toBe("42501");
    expect(await deniedAsApp("CREATE FUNCTION control.f() RETURNS int LANGUAGE sql AS 'SELECT 1'")).toBe("42501");
  });
});

describe("function grants", () => {
  it("control_app can execute exactly the control.api_* allow-list", async () => {
    const { rows } = await db.su.query(
      `SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'control' AND has_function_privilege('control_app', p.oid, 'EXECUTE') ORDER BY 1`);
    expect(rows.map((r) => r.proname)).toEqual(EXPECTED_APP_FUNCTIONS);
  });

  it("no control function is executable by PUBLIC", async () => {
    const { rows } = await db.su.query(
      `SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'control'
          AND EXISTS (SELECT 1 FROM aclexplode(coalesce(p.proacl, acldefault('f', p.proowner))) a WHERE a.grantee = 0)`);
    expect(rows).toEqual([]);
  });

  it("every api_* is SECURITY DEFINER, owned by control_auth (authentication), control_audit_owner (audit reads) or control_definer (tenant model), with a pinned search_path", async () => {
    const { rows } = await db.su.query(
      `SELECT p.proname, p.prosecdef, pg_get_userbyid(p.proowner) AS owner, p.proconfig
         FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'control' AND p.proname LIKE 'api\\_%'`);
    expect(rows.length).toBe(EXPECTED_APP_FUNCTIONS.length);
    for (const r of rows) {
      expect(r.prosecdef, r.proname).toBe(true);
      expect(r.owner, r.proname).toBe(AUTH_OWNED.includes(r.proname) ? "control_auth"
        : AUDIT_OWNED.includes(r.proname) ? "control_audit_owner" : "control_definer");
      expect((r.proconfig ?? []).some((c: string) => c.startsWith("search_path=")), r.proname).toBe(true);
    }
  });

  it("every SECURITY DEFINER function in control pins search_path", async () => {
    const { rows } = await db.su.query(
      `SELECT p.proname FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
        WHERE n.nspname = 'control' AND p.prosecdef
          AND NOT coalesce(EXISTS (SELECT 1 FROM unnest(p.proconfig) c WHERE c LIKE 'search_path=%'), false)`);
    expect(rows).toEqual([]);
  });
});

describe("definer roles hold no tenant privileges", () => {
  it("control_definer, control_audit_owner and control_auth have no privilege on any pos_mock or public table", async () => {
    const { rows } = await db.su.query(
      `SELECT r.rolname, n.nspname || '.' || c.relname AS rel
         FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace CROSS JOIN pg_roles r
        WHERE r.rolname IN ('control_definer','control_audit_owner','control_auth') AND n.nspname IN ('pos_mock','public')
          AND c.relkind IN ('r','v','m','p')
          AND has_table_privilege(r.oid, c.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE')`);
    expect(rows).toEqual([]);
    const { rows: usage } = await db.su.query(
      `SELECT r.rolname, n.nspname FROM pg_namespace n CROSS JOIN pg_roles r
        WHERE r.rolname IN ('control_definer','control_audit_owner','control_auth','control_app') AND n.nspname IN ('pos_mock','public')
          AND has_schema_privilege(r.oid, n.oid, 'USAGE')`);
    expect(usage).toEqual([]);
  });

  it("no control role owns any object outside the control schemas", async () => {
    const { rows } = await db.su.query(
      `SELECT n.nspname, c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE pg_get_userbyid(c.relowner) = ANY($1) AND n.nspname NOT IN ('control', 'pg_toast')`, [CONTROL_ROLES]);
    expect(rows).toEqual([]);
  });

  it("a definer role that reads a control table it does not own has an RLS read policy (no silent empty reads)", async () => {
    const { rows } = await db.su.query(
      `SELECT r.rolname, c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace CROSS JOIN pg_roles r
        WHERE n.nspname = 'control' AND c.relkind = 'r' AND c.relrowsecurity
          AND r.rolname IN ('control_definer','control_audit_owner','control_auth') AND c.relowner <> r.oid
          AND has_table_privilege(r.oid, c.oid, 'SELECT')
          AND NOT EXISTS (SELECT 1 FROM pg_policy p WHERE p.polrelid = c.oid AND r.oid = ANY (p.polroles)
                            AND p.polcmd IN ('r', '*'))`);
    expect(rows).toEqual([]);
  });

  it("final review F1: no runtime role holds ANY privilege on a table owned by a different runtime role, and no cross-role policy exists", async () => {
    const { rows } = await db.su.query(
      `SELECT r.rolname, c.relname, pg_get_userbyid(c.relowner) AS owner
         FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace CROSS JOIN pg_roles r
        WHERE n.nspname = 'control' AND c.relkind IN ('r','v','m','p')
          AND r.rolname IN ('control_app','control_auth','control_definer','control_audit_owner')
          AND c.relowner <> r.oid
          AND has_table_privilege(r.oid, c.oid, 'SELECT,INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER')`);
    expect(rows).toEqual([]);
    const { rows: pol } = await db.su.query(
      `SELECT p.polname, c.relname FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'control'`);
    expect(pol).toEqual([]);
  });

  it("every control table has RLS enabled", async () => {
    const { rows } = await db.su.query(
      `SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
        WHERE n.nspname = 'control' AND c.relkind = 'r' AND NOT c.relrowsecurity`);
    expect(rows).toEqual([]);
  });
});

describe("synthetic-only tenant model", () => {
  it("refuses a non-synthetic tenant row even for the superuser", async () => {
    const err = await db.su.query(
      `INSERT INTO control.tenants (slug, display_name, is_synthetic) VALUES ('real-org', 'Real Org', false)`).catch((e) => e);
    expect(err.code).toBe("23514");
  });
});
