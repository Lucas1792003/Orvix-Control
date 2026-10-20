import type { NextRequest } from "next/server";
import type { AuthenticationResponseJSON } from "@simplewebauthn/server";
import { stepupVerify } from "@/src/server/auth/webauthn";
import { fail, json, readJson, requireMutation } from "@/src/server/http/respond";
import { authenticationResponse } from "@/src/server/http/schemas";

export async function POST(req: NextRequest) {
  const g = await requireMutation(req);
  if ("error" in g) return g.error;
  const body = (await readJson(req)) as { response?: unknown } | null;
  const resp = authenticationResponse.safeParse(body?.response);
  if (!resp.success) return fail("INVALID_INPUT");
  const r = await stepupVerify(g.session.token, resp.data as unknown as AuthenticationResponseJSON);
  return r.ok ? json({ ok: true }) : json({ ok: false, error: r.error }, r.error === "UNAUTHENTICATED" ? 401 : 403);
}
