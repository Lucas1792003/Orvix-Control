import { callApi } from "@/src/server/db/api";
import { getSession } from "@/src/server/auth/session";
import { fail, json } from "@/src/server/http/respond";
import { posOrgId } from "@/src/server/http/schemas";

export async function GET(_req: Request, ctx: { params: Promise<{ org: string }> }) {
  const s = await getSession();
  if (!s) return fail("UNAUTHENTICATED");
  const org = posOrgId.safeParse((await ctx.params).org);
  if (!org.success) return fail("INVALID_INPUT");
  const r = await callApi("api_pos_recovery_org", [s.token, org.data]);
  return r.ok ? json(r) : fail(r.error);
}
