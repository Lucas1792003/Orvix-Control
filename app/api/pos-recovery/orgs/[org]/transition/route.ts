import type { NextRequest } from "next/server";
import { callApi } from "@/src/server/db/api";
import { fail, json, readJson, requireMutation } from "@/src/server/http/respond";
import { posOrgId, posTransitionBody } from "@/src/server/http/schemas";

// Containment only (RESTRICTED / RECONCILING / QUARANTINED). Requires a step-up bound to
// ('pos_recovery_transition', '<org>:<state>'). ACTIVE is not accepted here or in the database.
export async function POST(req: NextRequest, ctx: { params: Promise<{ org: string }> }) {
  const g = await requireMutation(req);
  if ("error" in g) return g.error;
  const org = posOrgId.safeParse((await ctx.params).org);
  const body = posTransitionBody.safeParse(await readJson(req));
  if (!org.success || !body.success) return fail("INVALID_INPUT");
  const b = body.data;
  const r = await callApi("api_pos_recovery_transition", [g.session.token, org.data, b.to, b.reason, b.evidenceReference, b.requestId]);
  return r.ok ? json(r, 200, b.requestId) : fail(r.error, b.requestId);
}
