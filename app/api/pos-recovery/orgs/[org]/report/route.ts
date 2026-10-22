import type { NextRequest } from "next/server";
import { callApi } from "@/src/server/db/api";
import { fail, json, readJson, requireMutation } from "@/src/server/http/respond";
import { posOrgId, posReportBody } from "@/src/server/http/schemas";

// Records a reconciliation report in the POS (only while RECONCILING). The owner signs its digest offline.
export async function POST(req: NextRequest, ctx: { params: Promise<{ org: string }> }) {
  const g = await requireMutation(req);
  if ("error" in g) return g.error;
  const org = posOrgId.safeParse((await ctx.params).org);
  const body = posReportBody.safeParse(await readJson(req));
  if (!org.success || !body.success) return fail("INVALID_INPUT");
  const r = await callApi("api_pos_recovery_report", [g.session.token, org.data, body.data.requestId]);
  return r.ok ? json(r, 200, body.data.requestId) : fail(r.error, body.data.requestId);
}
