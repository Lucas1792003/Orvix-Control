// Shadow-audit reconciliation (C1.2, RM-3). HOST tool (database superuser + access to the PostgreSQL server log).
//
// Every control.audit_append call first writes `ORVIX_AUDIT_SHADOW <mac> <json>` to the PostgreSQL server log. Log lines
// are written immediately and are NOT undone by ROLLBACK, and control_app cannot lower log_min_messages. <mac> is
// HMAC-SHA256 over the exact JSON text with a per-database key that only the audit owner and the superuser can read
// (control.audit_shadow_key), so lines forged by anyone else (RAISE from a DO block, a statement echo, another
// database) do not verify. This tool lists VERIFIED shadow lines of the selected database whose shadow_id has no row
// in control.audit_events: audit events that were written and then rolled back (for example a refusal hidden by a
// control_app transaction that ended in ROLLBACK, or a legitimate transaction that failed later).
//
//   docker logs orvix-control-db 2> /path/pg.log >/dev/null; npx tsx scripts/audit-shadow.ts --log /path/pg.log [--db <name>]
// Exit codes: 0 clean, 3 rolled-back events found, 4 forged shadow lines found (and none rolled back).
import { createHmac, timingSafeEqual } from "node:crypto";
import { readFileSync } from "node:fs";
import pg from "pg";
import { loadDevEnv, superuserConfig } from "./env";
import { ALLOWED_DB } from "./migrator";
import { safe } from "./verify-audit";

export type ShadowLine = { shadow_id: string; db: string; xid: number; at: string; session_user: string; action: string; outcome: string;
  actor_type: string; actor_id: string | null; target_type: string | null; target_id: string | null; reason_code: string | null };

const MARK = "ORVIX_AUDIT_SHADOW ";
const LINE = /ORVIX_AUDIT_SHADOW ([0-9a-f]{64}) (\{.*\})\s*$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

export type ParsedShadow = { lines: ShadowLine[]; forged: number; foreign: number };

// Only lines whose MAC verifies with this database's key AND that name this database are returned.
export function parseShadowLog(text: string, key: Buffer, database: string): ParsedShadow {
  const out: ShadowLine[] = [];
  let forged = 0, foreign = 0;
  for (const raw of text.split("\n")) {
    if (!raw.includes(MARK)) continue;
    const m = LINE.exec(raw);
    if (!m) { forged++; continue; }
    const mac = createHmac("sha256", key).update(m[2]!, "utf8").digest();
    const given = Buffer.from(m[1]!, "hex");
    let j: Partial<ShadowLine>;
    try { j = JSON.parse(m[2]!); } catch { forged++; continue; }
    if (!timingSafeEqual(mac, given)) {
      // a line from another database is expected noise; a line naming THIS database with a bad MAC is a forgery
      if (j.db !== database) foreign++; else forged++;
      continue;
    }
    if (j.db !== database || typeof j.shadow_id !== "string" || !UUID.test(j.shadow_id)) { forged++; continue; }
    out.push(j as ShadowLine);
  }
  return { lines: out, forged, foreign };
}

export async function shadowKey(client: pg.Client | pg.Pool): Promise<Buffer> {
  const { rows } = await client.query("SELECT key FROM control.audit_shadow_key WHERE id = 1");
  if (!rows[0]) throw new Error("no shadow key (migration 217 not applied)");
  return rows[0].key as Buffer;
}

export async function reconcile(client: pg.Client | pg.Pool, shadows: ShadowLine[]) {
  const ids = [...new Set(shadows.map((s) => s.shadow_id))].filter((s) => UUID.test(s));
  const { rows } = await client.query("SELECT shadow_id::text AS id FROM control.audit_events WHERE shadow_id = ANY($1::uuid[])", [ids]);
  const committed = new Set(rows.map((r) => r.id));
  const missing = shadows.filter((s) => !committed.has(s.shadow_id));
  return { checked: ids.length, committed: committed.size, rolledBack: missing };
}

async function main() {
  loadDevEnv();
  const i = process.argv.indexOf("--log");
  const d = process.argv.indexOf("--db");
  if (i < 0) { console.error("usage: npx tsx scripts/audit-shadow.ts --log <postgres server log> [--db <database>]"); process.exit(2); }
  const cfg = superuserConfig();
  const database = d > 0 ? process.argv[d + 1]! : cfg.database;
  if (!ALLOWED_DB.test(database)) throw new Error("refusing: --db is not an orvix_control dev/test database");
  const client = new pg.Client({ ...cfg, database });
  await client.connect();
  try {
    const parsed = parseShadowLog(readFileSync(process.argv[i + 1]!, "utf8"), await shadowKey(client), database);
    const r = await reconcile(client, parsed.lines);
    console.log(`database ${safe(database)}: verified shadow lines ${r.checked}; committed ${r.committed}; ` +
      `rolled back ${r.rolledBack.length}; forged ${parsed.forged}; other databases ${parsed.foreign}`);
    for (const s of r.rolledBack) {
      console.log(`  ROLLED BACK xid=${safe(String(s.xid))} at=${safe(String(s.at))} user=${safe(String(s.session_user))} ` +
        `action=${safe(String(s.action))} outcome=${safe(String(s.outcome))} reason=${safe(String(s.reason_code))} ` +
        `target=${safe(String(s.target_type))}:${safe(String(s.target_id))}`);
    }
    if (parsed.forged) console.log(`  WARNING: ${parsed.forged} line(s) carry the shadow marker but fail verification (forged or corrupted)`);
    if (r.rolledBack.length) process.exitCode = 3;
    else if (parsed.forged) process.exitCode = 4;
  } finally {
    await client.end();
  }
}

if (process.argv[1]?.endsWith("audit-shadow.ts")) {
  main().catch((e) => { console.error(`SHADOW FAIL: ${safe((e as Error).message)}`); process.exit(1); });
}
