import "server-only";
import pg from "pg";
import { config } from "../config";
import { PRIVILEGE_CHECK_SQL, privilegeProblems, type PrivilegeRow } from "./privilegeCheck";

// The ONLY database access path in the app: control_app calling control.api_* functions.
// No table is ever queried directly; control_app has no table privileges anyway.

const globalForPool = globalThis as unknown as { __orvixPool?: pg.Pool; __orvixContractCheckedAt?: number };
const RECHECK_MS = 30_000;

function pool(): pg.Pool {
  if (!globalForPool.__orvixPool) {
    globalForPool.__orvixPool = new pg.Pool({
      ...config.db,
      max: 5,
      idleTimeoutMillis: 30_000,
      connectionTimeoutMillis: 3_000,
      statement_timeout: 5_000,
      application_name: "orvix-control",
    });
  }
  return globalForPool.__orvixPool;
}

// Allow-list of callable functions and their arity. Anything else is refused before reaching the DB.
const API = {
  api_contract_version: 0,
  api_enrol_begin: 1,
  api_enrol_complete: 4,
  api_login_begin: 1,
  api_credential_lookup: 1,
  api_login_complete: 5,
  api_auth_failed: 4,
  api_session_get: 1,
  api_session_revoke: 1,
  api_stepup_begin: 3,
  api_stepup_complete: 5,
  api_credential_list: 1,
  api_credential_add_begin: 1,
  api_credential_add_complete: 4,
  api_credential_revoke: 2,
  api_recovery_list: 1,
  api_recovery_approve: 2,
  api_recovery_cancel: 2,
  api_operator_invite: 4,
  api_operator_invite_revoke: 2,
  api_operator_list: 1,
  api_tenant_list: 1,
  api_tenant_get: 2,
  api_tenant_transition: 6,
  api_audit_list: 3,
  api_audit_verify: 1,
  api_audit_export: 3,
  api_anchor_begin: 1,
  api_anchor_complete: 6,
  api_anchor_list: 1,
  api_anchor_export: 2,
} as const;
export type ApiName = keyof typeof API;

export type ApiResult = { ok: true; [k: string]: unknown } | { ok: false; error: string };

async function ensureContract(): Promise<void> {
  if (globalForPool.__orvixContractCheckedAt && Date.now() - globalForPool.__orvixContractCheckedAt < RECHECK_MS) return;
  // Startup integrity checks (fail closed): expected contract and cluster; every SECURITY DEFINER function in
  // `control` pins a search_path ending in pg_temp; this role's defaults have not been altered; no prepared
  // transactions; (C1.3 M3/M4) the control database's ACL grants nothing to PUBLIC and no TEMP to this role, this role
  // cannot CONNECT to any non-control database, and the 217 built-in revocations are in place.
  const { rows } = await pool().query(`
    SELECT control.api_contract_version() AS v, current_setting('cluster_name') AS cluster,
           (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
             WHERE n.nspname = 'control' AND p.prosecdef
               AND NOT coalesce(EXISTS (SELECT 1 FROM unnest(p.proconfig) c WHERE c LIKE 'search_path=%pg_temp'), false))::int AS unpinned,
           (SELECT rolconfig FROM pg_roles WHERE rolname = current_user) AS rolconfig,
           (SELECT count(*) FROM pg_db_role_setting s JOIN pg_roles r ON r.oid = s.setrole
             WHERE r.rolname = current_user AND s.setdatabase <> 0)::int AS per_db,
           current_setting('statement_timeout') AS st, current_setting('lock_timeout') AS lt,
           current_setting('idle_in_transaction_session_timeout') AS it, current_setting('temp_file_limit') AS tfl,
           current_setting('transaction_timeout') AS tt, current_setting('max_prepared_transactions') AS mpt,
           current_setting('default_transaction_read_only') AS ro, current_setting('row_security') AS rs`);
  const priv = await pool().query<PrivilegeRow>(PRIVILEGE_CHECK_SQL);
  const cfg: string[] = rows[0]?.rolconfig ?? [];
  // the role's defaults must be EXACTLY this set (no extra or replaced entries)
  const expected = ["search_path=control, pg_catalog", "statement_timeout=5s", "idle_in_transaction_session_timeout=10s",
                    "lock_timeout=3s", "temp_file_limit=256MB", "transaction_timeout=10s"].sort();
  const r0 = rows[0] ?? {};
  if (r0.v !== config.contractVersion || r0.cluster !== "orvix-control-dev" || r0.unpinned !== 0
      || JSON.stringify([...cfg].sort()) !== JSON.stringify(expected) || r0.per_db !== 0
      || r0.lt !== "3s" || r0.it !== "10s" || r0.tfl !== "256MB" || r0.tt !== "10s" || r0.ro !== "off" || r0.rs !== "on"
      // prepared transactions would survive the watchdog and hold locks forever
      || r0.mpt !== "0"
      || privilegeProblems(priv.rows[0]).length > 0) {
    throw new Error("CONTRACT_MISMATCH");
  }
  globalForPool.__orvixContractCheckedAt = Date.now();   // re-checked every 30 s (fail closed on drift)
}

export async function callApi(name: ApiName, args: unknown[]): Promise<ApiResult> {
  if (!(name in API) || API[name] !== args.length) {
    return { ok: false, error: "INTERNAL" };
  }
  try {
    await ensureContract();
    const placeholders = args.map((_, i) => `$${i + 1}`).join(", ");
    const { rows } = await pool().query(`SELECT control.${name}(${placeholders}) AS r`, args);
    const r = rows[0]?.r;
    // Fail closed: anything that is not an explicit {ok:true} is a refusal.
    if (r && typeof r === "object" && (r as { ok?: unknown }).ok === true) return r as ApiResult;
    if (r && typeof r === "object" && typeof (r as { error?: unknown }).error === "string") {
      return { ok: false, error: (r as { error: string }).error };
    }
    return { ok: false, error: "INTERNAL" };
  } catch (e) {
    // Database text never leaves the server.
    console.error(`[orvix-control] ${name} failed: ${(e as Error).name}`);
    return { ok: false, error: "INTERNAL" };
  }
}

export async function contractVersion(): Promise<string | null> {
  try {
    const { rows } = await pool().query("SELECT control.api_contract_version() AS v");
    return rows[0]?.v ?? null;
  } catch {
    return null;
  }
}
