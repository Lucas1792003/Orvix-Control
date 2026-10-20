import type { NextRequest } from "next/server";
import { callApi } from "@/src/server/db/api";
import { fail, json, requireMutation } from "@/src/server/http/respond";

export async function POST(req: NextRequest, ctx: { params: Promise<{ id: string }> }) {
  const g = await requireMutation(req);
  if ("error" in g) return g.error;
  const id = Number((await ctx.params).id);
  if (!Number.isSafeInteger(id) || id < 1) return fail("INVALID_INPUT");
  const r = await callApi("api_anchor_export", [g.session.token, id]);
  return r.ok ? json({ ok: true, bundle: r.bundle }) : fail(r.error);
}
