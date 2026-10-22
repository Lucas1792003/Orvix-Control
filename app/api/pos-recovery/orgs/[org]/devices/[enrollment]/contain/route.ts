import type { NextRequest } from "next/server";
import { z } from "zod";
import { callApi } from "@/src/server/db/api";
import { fail, json, readJson, requireMutation } from "@/src/server/http/respond";
import { posContainBody, posOrgId } from "@/src/server/http/schemas";

// Suspend or revoke one till enrollment. Requires a step-up bound to
// ('pos_recovery_contain', '<org>:<enrollment>:<suspend|revoke>'). Reinstating needs an owner-signed authorization.
export async function POST(req: NextRequest, ctx: { params: Promise<{ org: string; enrollment: string }> }) {
  const g = await requireMutation(req);
  if ("error" in g) return g.error;
  const p = await ctx.params;
  const org = posOrgId.safeParse(p.org);
  const enrollment = z.uuid().safeParse(p.enrollment);
  const body = posContainBody.safeParse(await readJson(req));
  if (!org.success || !enrollment.success || !body.success) return fail("INVALID_INPUT");
  const b = body.data;
  const r = await callApi("api_pos_recovery_contain_device", [g.session.token, org.data, enrollment.data, b.action, b.reason, b.requestId]);
  return r.ok ? json(r, 200, b.requestId) : fail(r.error, b.requestId);
}
