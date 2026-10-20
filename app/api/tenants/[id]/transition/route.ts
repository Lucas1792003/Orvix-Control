import type { NextRequest } from "next/server";
import { z } from "zod";
import { callApi } from "@/src/server/db/api";
import { fail, json, readJson, requireMutation } from "@/src/server/http/respond";
import { transitionBody } from "@/src/server/http/schemas";

export async function POST(req: NextRequest, ctx: { params: Promise<{ id: string }> }) {
  const g = await requireMutation(req);
  if ("error" in g) return g.error;
  const id = z.uuid().safeParse((await ctx.params).id);
  const body = transitionBody.safeParse(await readJson(req));
  if (!id.success || !body.success) return fail("INVALID_INPUT");
  const b = body.data;
  const r = await callApi("api_tenant_transition", [g.session.token, id.data, b.to, b.reasonCode, b.note, b.requestId]);
  return r.ok ? json(r, 200, b.requestId) : fail(r.error, b.requestId);
}
