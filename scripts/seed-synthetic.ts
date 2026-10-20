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
    for (const f of ["pos_mock.sql", "synthetic_tenants.sql"]) {
      await client.query(readFileSync(path.join(ROOT, "db", "dev", f), "utf8"));
      console.log(`seeded ${f}`);
    }
  } finally {
    await client.end();
  }
}
main().catch((e) => { console.error(`SEED FAIL: ${(e as Error).message}`); process.exit(1); });
