// HOST-ONLY operator actions (database superuser on the host). None of these is reachable from the web app.
//   npm run host -- recovery-request  --email <e> --reason "<10+ chars>"   (grants nothing by itself)
//   npm run host -- recovery-confirm  --request <uuid>                     (contested requests: after out-of-band check)
//   npm run host -- recovery-cancel   --request <uuid>
//   npm run host -- revoke-operator   --email <e> --reason "<10+ chars>" [--force]  (emergency: disable all passkeys
//                                    + sessions; --force needed for the LAST owner, which makes recovery impossible)
//   npm run host -- purge-expired
//   npm run host -- notify-add      --recipient host|identity [--email <operator>] --kind file|webhook --target <path|url>
//                                    (webhook: a 32-byte HMAC secret is generated and printed ONCE for the receiver)
//   npm run host -- notify-disable  --id <channel id>
//   npm run host -- notify-status
//   npm run host -- approve-operator --email <e> --fingerprint <XXXX-XXXX-XXXX-XXXX shown to the invitee at enrolment>
//                                    (derived from the passkey's public key; confirm it with the invitee by voice or
//                                     in person, not through the console)
// Always use this CLI (bind parameters) rather than psql with literal values: audited statements are echoed to the
// server log, so literals such as webhook secrets would land there.
import { randomBytes } from "node:crypto";
import pg from "pg";
import { loadDevEnv, superuserConfig } from "./env";

function arg(name: string): string | undefined {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 ? process.argv[i + 1] : undefined;
}

const COMMANDS: Record<string, [string, string[]]> = {
  "recovery-request": ["SELECT control.host_recovery_request($1, $2) AS r", ["email", "reason"]],
  "recovery-confirm": ["SELECT control.host_recovery_confirm($1::uuid) AS r", ["request"]],
  "recovery-cancel": ["SELECT control.host_recovery_cancel($1::uuid) AS r", ["request"]],
  "revoke-operator": ["SELECT control.host_revoke_operator_credentials($1, $2, $3::boolean) AS r", ["email", "reason", "force"]],
  "purge-expired": ["SELECT control.host_purge_expired() AS r", []],
  "notify-add": ["SELECT control.host_add_notify_channel($1, $2, $3, $4, $5) AS r", ["recipient", "email?", "kind", "target", "secret"]],
  "notify-disable": ["SELECT control.host_disable_notify_channel($1::bigint) AS r", ["id"]],
  "notify-status": ["SELECT control.host_notify_status() AS r", []],
  "approve-operator": ["SELECT control.host_approve_operator($1, $2) AS r", ["email", "fingerprint"]],
};

async function main() {
  loadDevEnv();
  const cmd = process.argv[2] ?? "";
  const spec = COMMANDS[cmd];
  if (!spec) throw new Error(`usage: npm run host -- <${Object.keys(COMMANDS).join("|")}> [options]`);
  // --force is a flag (revoke-operator on the LAST owner: permanent lockout of a single-owner install)
  let generatedSecret: string | null = null;
  const args = spec[1].map((n) => {
    if (n === "force") return process.argv.includes("--force") ? "true" : "false";
    if (n === "secret") {
      if (arg("kind") !== "webhook") return null;
      generatedSecret = randomBytes(32).toString("hex");
      return generatedSecret;
    }
    if (n.endsWith("?")) return arg(n.slice(0, -1)) ?? null;
    const v = arg(n); if (!v) throw new Error(`missing --${n}`); return v;
  });
  const client = new pg.Client(superuserConfig());
  await client.connect();
  try {
    const r = (await client.query(spec[0], args)).rows[0].r;
    if (!r.ok) throw new Error(`refused: ${r.error}`);
    console.log(JSON.stringify(r));
    if (generatedSecret) console.log(`webhook HMAC secret (shown once; configure it in the receiver): ${generatedSecret}`);
  } finally {
    await client.end();
  }
}
main().catch((e) => { console.error(`HOST FAIL: ${(e as Error).message}`); process.exit(1); });
