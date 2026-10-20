// Loads .env.local for CLI scripts and tests. Never prints values.
import { existsSync } from "node:fs";
import path from "node:path";

const ROOT = path.resolve(import.meta.dirname, "..");

export function loadDevEnv(): void {
  const file = path.join(ROOT, ".env.local");
  if (!existsSync(file)) {
    throw new Error(".env.local missing: run `npm run db:up` first");
  }
  process.loadEnvFile(file);
  // Host-side secrets live in separate files that the Next.js server never loads (it auto-loads only .env.local):
  // .env.host (database superuser: migrations, host CLI, tests) and .env.sentinel (out-of-band notifier/watchdog).
  for (const extra of [".env.host", ".env.sentinel"]) {
    const f = path.join(ROOT, extra);
    if (existsSync(f)) process.loadEnvFile(f);
  }
}

// The sentinel process gets the database target and ITS OWN credential only: never the superuser or app password.
export function loadSentinelEnv(): void {
  const file = path.join(ROOT, ".env.local");
  if (!existsSync(file)) throw new Error(".env.local missing: run `npm run db:up` first");
  process.loadEnvFile(file);
  for (const k of Object.keys(process.env)) {
    if (/SUPERUSER|APP_PASSWORD|SESSION_SECRET/.test(k)) delete process.env[k];
  }
  const f = path.join(ROOT, ".env.sentinel");
  if (!existsSync(f)) throw new Error(".env.sentinel missing: run `npm run db:up` first");
  process.loadEnvFile(f);
}

export function sentinelConfig() {
  return { ...devDbTarget(), user: "control_sentinel", password: need("ORVIX_DB_SENTINEL_PASSWORD") };
}

function need(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`missing env ${name}`);
  return v;
}

// Hard guard: this project only ever talks to the isolated loopback dev database.
export function devDbTarget() {
  const host = need("ORVIX_DB_HOST");
  const port = Number(need("ORVIX_DB_PORT"));
  const database = need("ORVIX_DB_NAME");
  if (host !== "127.0.0.1" || port !== 55440 || !/^orvix_control(_e2e|_test_[a-z0-9]{6,16})?$/.test(database)) {
    throw new Error("refusing: database target is not the isolated dev database 127.0.0.1:55440/orvix_control");
  }
  return { host, port, database };
}

export function superuserConfig() {
  return { ...devDbTarget(), user: need("ORVIX_DB_SUPERUSER"), password: need("ORVIX_DB_SUPERUSER_PASSWORD") };
}

export function appConfig() {
  return { ...devDbTarget(), user: need("ORVIX_DB_APP_USER"), password: need("ORVIX_DB_APP_PASSWORD") };
}

export { ROOT };
