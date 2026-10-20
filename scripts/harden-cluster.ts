// HOST-ONLY, CLUSTER-WIDE (C1.3 M3). Revokes PUBLIC CONNECT/TEMP on the cluster's shared databases (postgres,
// template1), so the control roles cannot use a sibling database where the control-database hardening does not apply.
// This changes databases OTHER than the control database: run it only on a cluster dedicated to Orvix Control.
//
//   npx tsx scripts/harden-cluster.ts --check                      # report only (no changes)
//   npx tsx scripts/harden-cluster.ts --apply --i-understand-cluster-wide
//
// It also reports whether pg_hba restricts the control roles (db/cluster/pg_hba.conf) and the NOTIFY queue limit.
import { readdirSync } from "node:fs";
import path from "node:path";
import pg from "pg";
import { loadDevEnv, ROOT, superuserConfig } from "./env";
import { clusterExposure } from "./migrator";

async function main() {
  loadDevEnv();
  const apply = process.argv.includes("--apply");
  if (apply && !process.argv.includes("--i-understand-cluster-wide")) throw new Error("--apply also needs --i-understand-cluster-wide");
  const c = new pg.Client(superuserConfig());
  await c.connect();
  try {
    const g = (await c.query("SELECT current_setting('cluster_name') AS cluster, current_setting('max_notify_queue_pages', true) AS nq")).rows[0];
    if (!/^orvix-control-/.test(g.cluster)) throw new Error("refusing: not an Orvix Control cluster");
    if (apply) {
      for (const db of ["postgres", "template1"]) {
        await c.query(`REVOKE CONNECT, TEMPORARY ON DATABASE ${db} FROM PUBLIC`);
        console.log(`revoked PUBLIC CONNECT, TEMPORARY on ${db}`);
      }
    }
    const findings = await clusterExposure(c);
    // CREATE DATABASE copies template1: it must hold nothing beyond the stock catalog (C1.3 review)
    const t = new pg.Client({ ...superuserConfig(), database: "template1" });
    await t.connect();
    try {
      const x = (await t.query(`SELECT
          (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
            WHERE n.nspname NOT IN ('pg_catalog', 'information_schema', 'pg_toast'))::int AS relations,
          (SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = p.pronamespace
            WHERE n.nspname NOT IN ('pg_catalog', 'information_schema'))::int AS functions,
          (SELECT count(*) FROM pg_largeobject_metadata)::int AS large_objects`)).rows[0];
      if (x.relations || x.functions || x.large_objects) findings.push(`template1 is not empty: ${JSON.stringify(x)}`);
    } finally { await t.end(); }
    // control-named sibling databases are reachable by the control roles (pg_hba): each must be at the latest migration,
    // otherwise its weaker grants (e.g. advisory locks before 217) are usable cluster-wide
    const latest = readdirSync(path.join(ROOT, "db", "migrations")).filter((f) => /^\d{3}_.*\.sql$/.test(f)).sort().at(-1)!.slice(0, 3);
    const sibs = (await c.query(`SELECT datname FROM pg_database WHERE datallowconn AND datname ~ '^orvix_control(_e2e|_test_[a-z0-9]{6,16})?$'`)).rows;
    for (const { datname } of sibs) {
      const s = new pg.Client({ ...superuserConfig(), database: datname });
      await s.connect();
      try {
        const v = (await s.query("SELECT max(version) AS v FROM control_ledger.schema_migrations").catch(() => ({ rows: [{ v: null }] }))).rows[0].v;
        if (v !== latest) findings.push(`control database ${datname} is at migration ${v ?? "none"} (latest ${latest}): migrate or drop it`);
      } finally { await s.end(); }
    }
    console.log(JSON.stringify({ cluster: g.cluster, max_notify_queue_pages: g.nq, findings }, null, 1));
    if (findings.length) process.exitCode = 3;
  } finally {
    await c.end();
  }
}
main().catch((e) => { console.error(`HARDEN FAIL: ${(e as Error).message}`); process.exit(1); });
