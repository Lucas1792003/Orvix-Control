// Orvix Control migration runner with its own ledger (control_ledger.schema_migrations).
// - Applies db/migrations/NNN_*.sql in order, each in ONE transaction together with its ledger row.
// - Refuses if an applied file's checksum changed, an applied file is missing, or a file is out of order.
// - Refuses any target other than the isolated loopback dev database, and any database that looks like Supabase.
// - Sets the control_app password OUT OF BAND (never in a migration file).
import pg from "pg";
import { loadDevEnv, superuserConfig } from "./env";
import { clusterExposure, migrate, setAppPassword } from "./migrator";

async function main() {
  loadDevEnv();
  const statusOnly = process.argv.includes("--status");
  const client = new pg.Client(superuserConfig());
  await client.connect();
  try {
    const { applied } = await migrate(client, { statusOnly, log: console.log });
    if (statusOnly) return;
    if (applied.length === 0) console.log("no pending migrations");
    await setAppPassword(client, process.env.ORVIX_DB_APP_PASSWORD!);
    console.log("control_app password set (out of band)");
    const exposure = await clusterExposure(client);
    for (const w of exposure) console.log(`CLUSTER NOT HARDENED: ${w}`);
    if (exposure.length) {
      console.log("Migrations are applied, but the cluster is exposed (see docs/MIGRATIONS_C1_3.md). The app and the sentinel refuse to run while their role can reach a non-control or unhardened database.");
      process.exitCode = 3;
    }
  } finally {
    await client.end();
  }
}

main().catch((e) => {
  console.error(`MIGRATE FAIL: ${(e as Error).message}`);
  process.exit(1);
});
