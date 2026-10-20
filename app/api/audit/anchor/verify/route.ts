import type { NextRequest } from "next/server";
import type { AuthenticationResponseJSON } from "@simplewebauthn/server";
import { anchorVerify } from "@/src/server/auth/webauthn";
import { fail, json, readJson, requireMutation } from "@/src/server/http/respond";
import { authenticationResponse } from "@/src/server/http/schemas";

export async function POST(req: NextRequest) {
  const g = await requireMutation(req);
  if ("error" in g) return g.error;
  const body = (await readJson(req)) as { response?: unknown; note?: unknown } | null;
  const resp = authenticationResponse.safeParse(body?.response);
  if (!resp.success) return fail("INVALID_INPUT");
  const note = typeof body?.note === "string" ? body.note.slice(0, 200) : null;
  const r = await anchorVerify(g.session.token, resp.data as unknown as AuthenticationResponseJSON, note);
  return r.ok ? json(r) : fail(r.error === "HEAD_CHANGED" ? "HEAD_CHANGED" : "ANCHOR_FAILED");
}
