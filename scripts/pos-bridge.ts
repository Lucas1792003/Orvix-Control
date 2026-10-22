// HOST-ONLY (database superuser): configure the network bridge from Control to the POS recovery operator interface
// (migration 223). Creates the dblink foreign server `orvix_pos_recovery`, gives control_definer USAGE on it, and stores
// the POS login (a POS role that is a member of orvix_recovery_operator only, created by the POS owner) in a user mapping
// for control_definer. The web server never sees the POS credential: it is not in .env.local, and control_app cannot read
// user mappings or execute dblink (startup privilege check).
//   npx tsx scripts/pos-bridge.ts --configure   (reads .env.posbridge, mode 0600: ORVIX_POS_BRIDGE_HOST, _PORT, _DBNAME,
//                                                _USER, _PASSWORD, _SSLMODE=verify-full + _SSLROOTCERT=<absolute path>;
//                                                values are never printed)
// TLS: verify-full is required. ORVIX_POS_BRIDGE_INSECURE_DEV=1 allows any sslmode for a DISPOSABLE local stack only; the
// choice is recorded in control.pos_bridge_binding (tls_required=false) and visible in every call's audit context.
// The bridge is BOUND to the database it is configured in (system identifier, oid, name): a restore or copy of this
// database (a drill, staging) has no working bridge until the host configures it there deliberately.
//   npx tsx scripts/pos-bridge.ts --status | --remove
import { existsSync, lstatSync } from "node:fs";
import path from "node:path";
import pg from "pg";
import { loadDevEnv, ROOT, superuserConfig } from "./env";

export type BridgeSettings = { host: string; port: number; dbname: string; user: string; password: string; sslmode: string;
  sslrootcert?: string; insecureDev?: boolean };

const SSLMODES = new Set(["disable", "allow", "prefer", "require", "verify-ca", "verify-full"]);

export function bridgeSettingsFromEnv(env: NodeJS.ProcessEnv): BridgeSettings {
  const need = (k: string) => { const v = env[k]; if (!v) throw new Error(`missing ${k}`); return v; };
  const s: BridgeSettings = {
    host: need("ORVIX_POS_BRIDGE_HOST"), port: Number(need("ORVIX_POS_BRIDGE_PORT")), dbname: need("ORVIX_POS_BRIDGE_DBNAME"),
    user: need("ORVIX_POS_BRIDGE_USER"), password: need("ORVIX_POS_BRIDGE_PASSWORD"), sslmode: env.ORVIX_POS_BRIDGE_SSLMODE ?? "verify-full",
    sslrootcert: env.ORVIX_POS_BRIDGE_SSLROOTCERT, insecureDev: env.ORVIX_POS_BRIDGE_INSECURE_DEV === "1",
  };
  if (!/^[A-Za-z0-9.-]{1,253}$/.test(s.host) || !Number.isInteger(s.port) || s.port < 1 || s.port > 65535
      || !/^[A-Za-z0-9_]{1,63}$/.test(s.dbname) || !/^[a-z0-9_]{1,63}$/.test(s.user) || !SSLMODES.has(s.sslmode)) {
    throw new Error("invalid bridge settings");
  }
  if (s.password.length < 24) throw new Error("bridge password too short (generate at least 24 random characters)");
  if (!s.insecureDev && (s.sslmode !== "verify-full" || !s.sslrootcert || !path.isAbsolute(s.sslrootcert))) {
    throw new Error("the bridge requires sslmode=verify-full and an absolute ORVIX_POS_BRIDGE_SSLROOTCERT (ORVIX_POS_BRIDGE_INSECURE_DEV=1 only for a disposable local stack)");
  }
  return s;
}

// Idempotent: replaces an existing server/mapping. Runs in one transaction on the given superuser client.
export async function configurePosBridge(c: pg.Client | pg.PoolClient, s: BridgeSettings): Promise<void> {
  const L = (v: string) => c.escapeLiteral(v);
  if (!s.insecureDev && (s.sslmode !== "verify-full" || !s.sslrootcert)) throw new Error("the bridge requires verify-full TLS");
  await c.query("BEGIN");
  try {
    // the user mapping statement carries the password: never logged, not even on error (as migrator.setAppPassword)
    await c.query("SET LOCAL log_statement = 'none'");
    await c.query("SET LOCAL log_min_error_statement = 'panic'");
    await c.query("SET LOCAL log_min_duration_statement = -1");
    await c.query("SET LOCAL log_min_duration_sample = -1");
    await c.query("DROP SERVER IF EXISTS orvix_pos_recovery CASCADE");
    // remote session limits are part of the bridge, not left to the POS role's defaults
    await c.query(`CREATE SERVER orvix_pos_recovery FOREIGN DATA WRAPPER dblink_fdw OPTIONS (host ${L(s.host)}, port ${L(String(s.port))},
      dbname ${L(s.dbname)}, sslmode ${L(s.sslmode)}${s.sslrootcert ? `, sslrootcert ${L(s.sslrootcert)}` : ""}, connect_timeout '3',
      application_name 'orvix-control-bridge',
      options '-c statement_timeout=4000 -c lock_timeout=3000 -c idle_in_transaction_session_timeout=15000')`);
    await c.query("GRANT USAGE ON FOREIGN SERVER orvix_pos_recovery TO control_definer");
    await c.query(`CREATE USER MAPPING FOR control_definer SERVER orvix_pos_recovery OPTIONS (user ${L(s.user)}, password ${L(s.password)})`);
    await c.query(`INSERT INTO control.pos_bridge_binding (id, system_identifier, database_oid, database_name, tls_required)
      SELECT 1, (SELECT system_identifier::text FROM pg_control_system()), d.oid, d.datname, $1 FROM pg_database d WHERE d.datname = current_database()
      ON CONFLICT (id) DO UPDATE SET system_identifier = EXCLUDED.system_identifier, database_oid = EXCLUDED.database_oid,
        database_name = EXCLUDED.database_name, tls_required = EXCLUDED.tls_required, configured_at = clock_timestamp()`, [!s.insecureDev]);
    await c.query("COMMIT");
  } catch (e) {
    await c.query("ROLLBACK");
    throw e;
  }
}

export async function removePosBridge(c: pg.Client | pg.PoolClient): Promise<void> {
  await c.query("DROP SERVER IF EXISTS orvix_pos_recovery CASCADE");
  await c.query("DELETE FROM control.pos_bridge_binding");
}

async function main() {
  loadDevEnv();
  const mode = process.argv[2];
  const client = new pg.Client(superuserConfig());
  await client.connect();
  try {
    if (mode === "--configure") {
      const f = path.join(ROOT, ".env.posbridge");
      if (!existsSync(f)) throw new Error(".env.posbridge missing");
      const st = lstatSync(f);
      if (!st.isFile() || st.isSymbolicLink() || (st.mode & 0o077) !== 0 || (process.getuid && st.uid !== process.getuid())) {
        throw new Error(".env.posbridge must be a regular file of this user, mode 0600");
      }
      const env = {} as NodeJS.ProcessEnv;
      process.loadEnvFile(f);   // into process.env, then moved out of it
      for (const k of Object.keys(process.env)) if (k.startsWith("ORVIX_POS_BRIDGE_")) { env[k] = process.env[k]; delete process.env[k]; }
      await configurePosBridge(client, bridgeSettingsFromEnv(env));
      console.log("POS bridge configured (server orvix_pos_recovery, user mapping for control_definer).");
    } else if (mode === "--remove") {
      await removePosBridge(client);
      console.log("POS bridge removed: every POS recovery API now answers POS_RECOVERY_UNAVAILABLE.");
    } else if (mode === "--status") {
      const { rows } = await client.query(`SELECT s.srvname, array_to_string(s.srvoptions, ' ') AS options,
          (SELECT count(*) FROM pg_user_mappings m WHERE m.srvid = s.oid)::int AS mappings,
          (SELECT tls_required FROM control.pos_bridge_binding) AS tls_required
        FROM pg_foreign_server s WHERE s.srvname = 'orvix_pos_recovery'`);
      console.log(rows.length ? `configured: ${rows[0].options}; user mappings: ${rows[0].mappings}; tls required: ${rows[0].tls_required}` : "not configured");
    } else {
      throw new Error("usage: pos-bridge.ts --configure | --status | --remove");
    }
  } finally {
    await client.end();
  }
}

if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(import.meta.filename)) {
  main().catch((e) => { console.error(`POS BRIDGE FAIL: ${(e as Error).message}`); process.exit(1); });
}
