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
