import type { NextRequest } from "next/server";
import { callApi } from "@/src/server/db/api";
import { fail, json, readJson, requireMutation } from "@/src/server/http/respond";
import { posSubmitBody } from "@/src/server/http/schemas";

// Carries an OWNER-SIGNED authorization (enroll-device | device-reinstate | reopen-organization), produced offline by
// the owner, to the POS verifier. Control never creates or signs one. Requires a step-up bound to
// ('pos_recovery_submit', '<purpose>:<sha256 hex of the exact authorization text>'); a reopening needs the owner role.
export async function POST(req: NextRequest) {
  const g = await requireMutation(req);
  if ("error" in g) return g.error;
  const body = posSubmitBody.safeParse(await readJson(req, 80_000));
  if (!body.success) return fail("INVALID_INPUT");
  const b = body.data;
  const r = await callApi("api_pos_recovery_submit", [g.session.token, b.authorization, b.signature, b.requestId]);
  return r.ok ? json(r, 200, b.requestId) : fail(r.error, b.requestId);
}
