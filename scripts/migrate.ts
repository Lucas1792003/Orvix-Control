// Orvix Control migration runner with its own ledger (control_ledger.schema_migrations).
// - Applies db/migrations/NNN_*.sql in order, each in ONE transaction together with its ledger row.
// - Refuses if an applied file's checksum changed, an applied file is missing, or a file is out of order.
// - Refuses any target other than the isolated loopback dev database, and any database that looks like Supabase.
// - Sets the control_app password OUT OF BAND (never in a migration file).
import pg from "pg";
import { loadDevEnv, superuserConfig } from "./env";
import { migrate, setAppPassword } from "./migrator";

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
  } finally {
    await client.end();
  }
}

main().catch((e) => {
  console.error(`MIGRATE FAIL: ${(e as Error).message}`);
  process.exit(1);
});
