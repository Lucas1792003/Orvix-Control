import type { NextRequest } from "next/server";
import { callApi } from "@/src/server/db/api";
import { fail, json, readJson, requireMutation } from "@/src/server/http/respond";
import { inviteBody } from "@/src/server/http/schemas";

// Requires a step-up bound to ('operator_invite', '<role>:<sha256(lower(email))>') obtained just before (215).
// Returns the one-time enrolment link token ONCE; the owner relays it out of band. Activation is host-only.
export async function POST(req: NextRequest) {
  const g = await requireMutation(req);
  if ("error" in g) return g.error;
  const b = inviteBody.safeParse(await readJson(req));
  if (!b.success) return fail("INVALID_INPUT");
  const r = await callApi("api_operator_invite", [g.session.token, b.data.email, b.data.displayName, b.data.role]);
  return r.ok ? json({ ok: true, invitation_id: r.invitation_id, enrolment_token: r.enrolment_token, expires_in_seconds: r.expires_in_seconds })
              : fail(r.error);
}
