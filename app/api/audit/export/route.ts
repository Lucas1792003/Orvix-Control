import type { NextRequest } from "next/server";
import { callApi } from "@/src/server/db/api";
import { fail, json, readJson, requireMutation } from "@/src/server/http/respond";

export async function POST(req: NextRequest) {
  const g = await requireMutation(req);
  if ("error" in g) return g.error;
  const body = (await readJson(req)) as { from?: unknown; to?: unknown } | null;
  const from = Number(body?.from ?? 0);
  const to = body?.to == null ? null : Number(body.to);
  if (!Number.isSafeInteger(from) || from < 0 || (to !== null && (!Number.isSafeInteger(to) || to < from))) return fail("INVALID_INPUT");
  const r = await callApi("api_audit_export", [g.session.token, from, to]);
  return r.ok ? json(r) : fail(r.error);
}
