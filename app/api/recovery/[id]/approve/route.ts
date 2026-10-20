import type { NextRequest } from "next/server";
import { z } from "zod";
import { callApi } from "@/src/server/db/api";
import { fail, json, requireMutation } from "@/src/server/http/respond";

// Returns the one-time enrolment token ONCE, to the approving owner, who relays it out of band.
export async function POST(req: NextRequest, ctx: { params: Promise<{ id: string }> }) {
  const g = await requireMutation(req);
  if ("error" in g) return g.error;
  const id = z.uuid().safeParse((await ctx.params).id);
  if (!id.success) return fail("INVALID_INPUT");
  const r = await callApi("api_recovery_approve", [g.session.token, id.data]);
  return r.ok ? json({ ok: true, enrolment_token: r.enrolment_token, expires_in_seconds: r.expires_in_seconds }) : fail(r.error);
}
