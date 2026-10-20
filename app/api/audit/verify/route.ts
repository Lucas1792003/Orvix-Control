import type { NextRequest } from "next/server";
import { callApi } from "@/src/server/db/api";
import { fail, json, requireMutation } from "@/src/server/http/respond";

export async function POST(req: NextRequest) {
  const g = await requireMutation(req);
  if ("error" in g) return g.error;
  const r = await callApi("api_audit_verify", [g.session.token]);
  return r.ok ? json(r) : fail(r.error);
}
