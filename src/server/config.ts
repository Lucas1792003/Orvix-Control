import "server-only";

// Fail closed: the server refuses to start with anything other than the isolated dev target.
function need(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`orvix-control: missing env ${name}`);
  return v;
}

export const config = (() => {
  const host = need("ORVIX_DB_HOST");
  const port = Number(need("ORVIX_DB_PORT"));
  const database = need("ORVIX_DB_NAME");
  const user = need("ORVIX_DB_APP_USER");
  // orvix_control = dev; orvix_control_e2e = the end-to-end test database (same container).
  if (host !== "127.0.0.1" || port !== 55440 || !/^orvix_control(_e2e)?$/.test(database)) {
    throw new Error("orvix-control: refusing non-dev database target");
  }
  if (user !== "control_app") {
    throw new Error("orvix-control: the server must connect as control_app only");
  }
  for (const k of Object.keys(process.env)) {
    if (/SERVICE_ROLE|SUPABASE/i.test(k)) {
      throw new Error(`orvix-control: refusing to run with ${k} in the environment`);
    }
  }
  const rpID = need("ORVIX_RP_ID");
  const origin = need("ORVIX_ORIGIN");
  if (rpID !== "localhost" || origin !== "http://localhost:3410") {
    throw new Error("orvix-control: RP ID/origin must be localhost:3410 in development");
  }
  return {
    db: { host, port, database, user, password: need("ORVIX_DB_APP_PASSWORD") },
    rpID,
    rpName: "Orvix Control (dev)",
    origin,
    contractVersion: "orvix-control/0.3",
  } as const;
})();
