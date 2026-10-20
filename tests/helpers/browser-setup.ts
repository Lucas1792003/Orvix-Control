// Manual browser check helper: fresh orvix_control_e2e DB + HOST bootstrap; writes the enrolment URL to argv[2].
import { writeFileSync } from "node:fs";
import { createTestDb, hostBootstrap } from "./db";

async function main() {
  const db = await createTestDb({ name: "orvix_control_e2e", seed: true });
  const r = await hostBootstrap(db, "owner@example.invalid", "Browser Owner");
  writeFileSync(process.argv[2]!, `http://localhost:3410/enroll/${r.enrolment_token}\n`, { mode: 0o600 });
  await db.su.end();
  await db.app.end();
}
main();
