// Migration core shared by the CLI (scripts/migrate.ts) and the test harness.
import { createHash } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";
import type pg from "pg";
import { ROOT } from "./env";

const DIR = path.join(ROOT, "db", "migrations");
const FILE_RE = /^(\d{3})_[a-z0-9_]+\.sql$/;
export const ALLOWED_DB = /^orvix_control(_e2e|_test_[a-z0-9]{6,16})?$/;

export async function migrate(client: pg.Client, opts: { statusOnly?: boolean; log?: (s: string) => void; upTo?: string } = {}) {
  const log = opts.log ?? (() => {});
  const guard = await client.query(
    `SELECT current_database() AS db, current_setting('cluster_name') AS cluster,
            EXISTS (SELECT 1 FROM pg_namespace WHERE nspname IN ('auth','storage','supabase_migrations')) AS looks_supabase`,
  );
  // The cluster name is set only by docker-compose.dev.yml: a tunnel or port-forward to any other server fails here.
  if (!ALLOWED_DB.test(guard.rows[0].db) || guard.rows[0].looks_supabase || guard.rows[0].cluster !== "orvix-control-dev") {
    throw new Error("refusing: connected database is not an isolated orvix_control dev/test database");
  }

  await client.query(`CREATE SCHEMA IF NOT EXISTS control_ledger`);
  await client.query(`REVOKE ALL ON SCHEMA control_ledger FROM PUBLIC`);
  await client.query(`CREATE TABLE IF NOT EXISTS control_ledger.schema_migrations (
      version    text PRIMARY KEY CHECK (version ~ '^[0-9]{3}$'),
      name       text NOT NULL,
      sha256     text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
      applied_at timestamptz NOT NULL DEFAULT now(),
      applied_by text NOT NULL DEFAULT current_user)`);

  const files = readdirSync(DIR).filter((f) => FILE_RE.test(f)).sort();
  const applied = new Map<string, { name: string; sha256: string }>(
    (await client.query(`SELECT version, name, sha256 FROM control_ledger.schema_migrations ORDER BY version`)).rows.map(
      (r) => [r.version, { name: r.name, sha256: r.sha256 }],
    ),
  );
  for (const [version, row] of applied) {
    const file = files.find((f) => f.startsWith(`${version}_`));
    if (!file) throw new Error(`ledger has ${version} (${row.name}) but the file is missing`);
    const sha = createHash("sha256").update(readFileSync(path.join(DIR, file))).digest("hex");
    if (sha !== row.sha256) throw new Error(`checksum changed for applied migration ${file}; refusing`);
  }
  const pending = files.filter((f) => !applied.has(f.slice(0, 3)) && (!opts.upTo || f.slice(0, 3) <= opts.upTo));
  const maxApplied = [...applied.keys()].sort().at(-1);
  for (const f of pending) {
    if (maxApplied && f.slice(0, 3) < maxApplied) {
      throw new Error(`out-of-order migration ${f} is older than applied ${maxApplied}; refusing`);
    }
  }
  if (opts.statusOnly) {
    for (const f of files) log(`${applied.has(f.slice(0, 3)) ? "applied" : "pending"}  ${f}`);
    return { applied: [] as string[] };
  }
  const done: string[] = [];
  for (const f of pending) {
    const sql = readFileSync(path.join(DIR, f), "utf8");
    const sha = createHash("sha256").update(sql).digest("hex");
    await client.query("BEGIN");
    try {
      await client.query(sql);
      await client.query(`INSERT INTO control_ledger.schema_migrations (version, name, sha256) VALUES ($1, $2, $3)`, [
        f.slice(0, 3), f, sha,
      ]);
      await client.query("COMMIT");
      done.push(f);
      log(`applied  ${f}`);
    } catch (e) {
      await client.query("ROLLBACK");
      throw new Error(`migration ${f} failed and was rolled back: ${(e as Error).message}`);
    }
  }
  if (applied.has("200") || done.some((f) => f.startsWith("200_"))) await enforceDatabaseAcl(client);
  return { applied: done };
}

// C1.3 M4: the control database's ACL is re-asserted on EVERY run (also when nothing is pending), so a restore into a
// plain CREATE DATABASE (PUBLIC default ACL: CONNECT + TEMP for every role) is corrected by the next migrate.
export async function enforceDatabaseAcl(client: pg.Client) {
  const { rows } = await client.query(
    `SELECT format('REVOKE ALL ON DATABASE %I FROM PUBLIC, ' || string_agg(quote_ident(rolname), ', '), current_database()) AS r,
            format('GRANT CONNECT ON DATABASE %I TO control_app', current_database()) AS a,
            CASE WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'control_sentinel')
                 THEN format('GRANT CONNECT ON DATABASE %I TO control_sentinel', current_database()) END AS s
       FROM pg_roles WHERE rolname IN ('control_app', 'control_sentinel')`);
  await client.query(rows[0].r);
  await client.query(rows[0].a);
  if (rows[0].s) await client.query(rows[0].s);
}

// C1.3 M3: cluster-wide exposure of the control roles. Database ACLs (what they may CONNECT to) and pg_hba, evaluated
// in order: for each control role and each probe database, the FIRST matching rule (TCP and local socket) must reject.
// Returned as findings for the host (scripts/harden-cluster.ts, db/cluster/pg_hba.conf); the app and the sentinel
// themselves REFUSE to run while their role can CONNECT to a non-control or unhardened database.
export async function clusterExposure(client: pg.Client): Promise<string[]> {
  const out: string[] = [];
  const dbs = await client.query(
    `SELECT r.rolname, d.datname FROM pg_database d CROSS JOIN pg_roles r
      WHERE r.rolname IN ('control_app', 'control_sentinel') AND d.datallowconn AND d.datname <> current_database()
        AND d.datname !~ '^orvix_control(_e2e|_test_[a-z0-9]{6,16})?$' AND has_database_privilege(r.oid, d.oid, 'CONNECT')
      ORDER BY 1, 2`);
  for (const r of dbs.rows) out.push(`${r.rolname} can CONNECT to non-control database ${r.datname}`);
  const rules = await client.query(
    `SELECT line_number, type, database, user_name, address, netmask, auth_method FROM pg_hba_file_rules WHERE error IS NULL ORDER BY line_number`)
    .catch(() => null);
  if (!rules) { out.push("pg_hba rules could not be read"); return out; }
  const matchDb = (list: string[], name: string) => list.some((d) =>
    d === "all" || d === name || (d.startsWith("/") && new RegExp(d.slice(1)).test(name)));
  // group (+role), file (@file) and samerole entries may include the role: treat them as matching
  const matchUser = (list: string[], role: string) => list.some((u) => u === "all" || u === role || u === "samerole" || u.startsWith("+") || u.startsWith("@"));
  // a reject only protects every client if it covers every address
  const coversAll = (r: { type: string; address: string | null; netmask: string | null }) =>
    r.type === "local" || r.address === "all" || ((r.address === "0.0.0.0" || r.address === "::") && (r.netmask === "0.0.0.0" || r.netmask === "::"));
  for (const role of ["control_app", "control_sentinel"]) {
    for (const db of ["postgres", "template1", "orvix_probe_noncontrol"]) {
      for (const kind of ["host", "local"]) {
        const first = rules.rows.find((r) => (kind === "local" ? r.type === "local" : r.type !== "local")
          && matchDb(r.database ?? [], db) && matchUser(r.user_name ?? [], role));
        if (first && first.auth_method !== "reject") {
          out.push(`pg_hba line ${first.line_number} lets ${role} reach ${db} over ${kind === "local" ? "the local socket" : "TCP"} (${first.auth_method})`);
        } else if (first && !coversAll(first)) {
          out.push(`pg_hba line ${first.line_number} rejects ${role} for ${db} only from some addresses`);
        }
      }
    }
  }
  return out;
}

// Out-of-band credential step: set control_app's password (dev/test only).
export async function setAppPassword(client: pg.Client, password: string) {
  // control_app can ALTER its own role defaults; every migrate run restores the canonical set (cluster-wide), in ONE
  // transaction so a failure part-way never leaves the role without timeouts. Role settings are cluster-wide, so the
  // FULL canonical set is always applied, whatever this database's ledger says (a partially migrated test database
  // must not weaken the role for every other database).
  await client.query("BEGIN");
  try {
  // Plaintext passwords must never reach the server log, even if a statement below fails.
  await client.query(`SET LOCAL log_statement = 'none'`);
  await client.query(`SET LOCAL log_min_error_statement = 'panic'`);
  await client.query(`SET LOCAL log_min_duration_statement = -1`);
  await client.query(`SET LOCAL log_min_duration_sample = -1`);
  const { rows } = await client.query(`SELECT format('ALTER ROLE control_app PASSWORD %L', $1::text) AS stmt`, [password]);
  await client.query(rows[0].stmt);
  await client.query(`ALTER ROLE control_app RESET ALL`);
  // per-database defaults override the role defaults and are invisible in pg_roles.rolconfig: clear them too
  const dbs = await client.query(
    `SELECT d.datname FROM pg_db_role_setting s JOIN pg_roles r ON r.oid = s.setrole JOIN pg_database d ON d.oid = s.setdatabase
      WHERE r.rolname = 'control_app'`);
  for (const row of dbs.rows) {
    const { rows: st } = await client.query(`SELECT format('ALTER ROLE control_app IN DATABASE %I RESET ALL', $1::text) AS s`, [row.datname]);
    await client.query(st[0].s);
  }
  await client.query(`ALTER ROLE control_app SET search_path = control, pg_catalog`);
  await client.query(`ALTER ROLE control_app SET statement_timeout = '5s'`);
  await client.query(`ALTER ROLE control_app SET idle_in_transaction_session_timeout = '10s'`);
  await client.query(`ALTER ROLE control_app SET lock_timeout = '3s'`);
  await client.query(`ALTER ROLE control_app SET temp_file_limit = '256MB'`);
  await client.query(`ALTER ROLE control_app SET transaction_timeout = '10s'`);
  // sentinel credential (separate file, separate process)
  const sentinel = await client.query(`SELECT 1 FROM pg_roles WHERE rolname = 'control_sentinel'`);
  if (sentinel.rowCount && process.env.ORVIX_DB_SENTINEL_PASSWORD) {
    const { rows: sp } = await client.query(`SELECT format('ALTER ROLE control_sentinel PASSWORD %L', $1::text) AS stmt`,
      [process.env.ORVIX_DB_SENTINEL_PASSWORD]);
    await client.query(sp[0].stmt);
  }
  if (sentinel.rowCount) {
    // C1.3 review: the sentinel role can also ALTER its own defaults; restore the canonical set (cluster-wide) every run
    await client.query(`ALTER ROLE control_sentinel RESET ALL`);
    const sdbs = await client.query(
      `SELECT d.datname FROM pg_db_role_setting s JOIN pg_roles r ON r.oid = s.setrole JOIN pg_database d ON d.oid = s.setdatabase
        WHERE r.rolname = 'control_sentinel'`);
    for (const row of sdbs.rows) {
      const { rows: st } = await client.query(`SELECT format('ALTER ROLE control_sentinel IN DATABASE %I RESET ALL', $1::text) AS s`, [row.datname]);
      await client.query(st[0].s);
    }
    await client.query(`ALTER ROLE control_sentinel SET search_path = control, pg_catalog`);
    await client.query(`ALTER ROLE control_sentinel SET statement_timeout = '10s'`);
    await client.query(`ALTER ROLE control_sentinel SET idle_in_transaction_session_timeout = '10s'`);
  }
  await client.query("COMMIT");
  } catch (e) {
    await client.query("ROLLBACK");
    throw e;
  }
}
