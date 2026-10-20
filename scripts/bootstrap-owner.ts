// HOST-ONLY owner bootstrap. Calls control.host_bootstrap_owner as the database superuser (the infrastructure
// owner on the host); control_app has no grant on it, so the web application cannot bootstrap.
// Succeeds once per install. Prints the one-time enrolment URL to this terminal only.
//   npm run bootstrap-owner -- --email owner@example.invalid --name "Dev Owner"
import pg from "pg";
import { loadDevEnv, superuserConfig } from "./env";

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 ? process.argv[i + 1] : undefined;
}

async function main() {
  loadDevEnv();
  const email = arg("email");
  const name = arg("name");
  if (!email || !name) throw new Error('usage: npm run bootstrap-owner -- --email <email> --name "<display name>"');
  const client = new pg.Client(superuserConfig());
  await client.connect();
  try {
    const { rows } = await client.query("SELECT control.host_bootstrap_owner($1, $2) AS r", [email, name]);
    const r = rows[0].r;
    if (!r.ok) throw new Error(`refused: ${r.error}`);
    console.log(`Owner identity created (enrolling). Open within ${Math.round(r.expires_in_seconds / 60)} minutes, once:`);
    console.log(`  ${process.env.ORVIX_ORIGIN}/enroll/${r.enrolment_token}`);
    console.log("Then add a SECOND passkey (Security page) and, if possible, a second owner: recovery needs one.");
  } finally {
    await client.end();
  }
}
main().catch((e) => { console.error(`BOOTSTRAP FAIL: ${(e as Error).message}`); process.exit(1); });
