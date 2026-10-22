// Seeds SYNTHETIC data into the isolated dev database only. Never point this anywhere else.
import { readFileSync } from "node:fs";
import path from "node:path";
import pg from "pg";
import { loadDevEnv, superuserConfig, ROOT } from "./env";

async function main() {
  loadDevEnv();
  const client = new pg.Client(superuserConfig());
  await client.connect();
  try {
    // --pos-recovery-mock: ALSO load the MOCK of the POS Recovery V1 operator interface (db/dev/pos_recovery_mock.sql).
    // It grants orvix_recovery_operator to control_definer CLUSTER-WIDE; never run it against a shared cluster.
    const files = ["pos_mock.sql", "synthetic_tenants.sql", ...(process.argv.includes("--pos-recovery-mock") ? ["pos_recovery_mock.sql"] : [])];
    for (const f of files) {
      await client.query(readFileSync(path.join(ROOT, "db", "dev", f), "utf8"));
      console.log(`seeded ${f}`);
    }
  } finally {
    await client.end();
  }
}
main().catch((e) => { console.error(`SEED FAIL: ${(e as Error).message}`); process.exit(1); });
