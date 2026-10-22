import { callApi } from "@/src/server/db/api";
import { getSession } from "@/src/server/auth/session";
import { fail, json } from "@/src/server/http/respond";

// Step 5 (222): recovery overview of every POS organization, through recovery_v1.operator_overview (metadata only).
export async function GET() {
  const s = await getSession();
  if (!s) return fail("UNAUTHENTICATED");
  const r = await callApi("api_pos_recovery_overview", [s.token]);
  return r.ok ? json(r) : fail(r.error);
}
