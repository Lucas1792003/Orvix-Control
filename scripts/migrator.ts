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
  return { applied: done };
}

// Out-of-band credential step: set control_app's password (dev/test only).
export async function setAppPassword(client: pg.Client, password: string) {
  const { rows } = await client.query(`SELECT format('ALTER ROLE control_app PASSWORD %L', $1::text) AS stmt`, [password]);
  await client.query(rows[0].stmt);
  // control_app can ALTER its own role defaults; every migrate run restores the canonical set (cluster-wide).
  const applied = await client.query(`SELECT 1 FROM control_ledger.schema_migrations WHERE version = '210'`);
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
  if (applied.rowCount) await client.query(`ALTER ROLE control_app SET temp_file_limit = '256MB'`);
}
