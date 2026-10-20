// Generates the OFFLINE audit-anchor key (Ed25519). Run on the owner's own machine, never on the server.
//   npx tsx scripts/anchor-keygen.ts --out <dir outside the repo>
// Writes anchor-key.pem (0600) and prints the public-key fingerprint to pin in verify-audit.ts --anchor-key.
import { generateKeyPairSync } from "node:crypto";
import { existsSync, writeFileSync } from "node:fs";
import path from "node:path";
import { ed25519Fingerprint } from "./verify-audit";

const i = process.argv.indexOf("--out");
const dir = i > 0 ? process.argv[i + 1] : undefined;
if (!dir) { console.error("usage: npx tsx scripts/anchor-keygen.ts --out <dir>"); process.exit(2); }
const file = path.join(dir, "anchor-key.pem");
if (existsSync(file)) { console.error(`refusing to overwrite ${file}`); process.exit(1); }
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
writeFileSync(file, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 });
const raw = Buffer.from(publicKey.export({ format: "jwk" }).x!, "base64url");
console.log(`private key written to ${file} (keep it OFF the server; back it up offline)`);
console.log(`anchor key fingerprint (pin this): ${ed25519Fingerprint(raw)}`);
