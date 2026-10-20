import { callApi } from "@/src/server/db/api";
import { getSession } from "@/src/server/auth/session";
import { fail, json } from "@/src/server/http/respond";

export async function GET() {
  const s = await getSession();
  if (!s) return fail("UNAUTHENTICATED");
  const r = await callApi("api_operator_list", [s.token]);
  return r.ok ? json(r) : fail(r.error);
}
