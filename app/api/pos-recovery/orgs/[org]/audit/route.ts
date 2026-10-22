import type { NextRequest } from "next/server";
import { z } from "zod";
import { callApi } from "@/src/server/db/api";
import { getSession } from "@/src/server/auth/session";
import { fail, json } from "@/src/server/http/respond";
import { posOrgId } from "@/src/server/http/schemas";

export async function GET(req: NextRequest, ctx: { params: Promise<{ org: string }> }) {
  const s = await getSession();
  if (!s) return fail("UNAUTHENTICATED");
  const org = posOrgId.safeParse((await ctx.params).org);
  const limit = z.coerce.number().int().min(1).max(200).default(50).safeParse(req.nextUrl.searchParams.get("limit") ?? undefined);
  if (!org.success || !limit.success) return fail("INVALID_INPUT");
  const r = await callApi("api_pos_recovery_audit", [s.token, org.data, limit.data]);
  return r.ok ? json(r) : fail(r.error);
}
