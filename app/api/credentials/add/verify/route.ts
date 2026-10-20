import type { NextRequest } from "next/server";
import type { RegistrationResponseJSON } from "@simplewebauthn/server";
import { credentialAddVerify } from "@/src/server/auth/webauthn";
import { fail, json, readJson, requireMutation } from "@/src/server/http/respond";
import { nickname, registrationResponse } from "@/src/server/http/schemas";

export async function POST(req: NextRequest) {
  const g = await requireMutation(req);
  if ("error" in g) return g.error;
  const body = (await readJson(req)) as { response?: unknown; nickname?: unknown } | null;
  const resp = registrationResponse.safeParse(body?.response);
  const nick = nickname.safeParse(body?.nickname ?? null);
  if (!resp.success || !nick.success) return fail("INVALID_INPUT");
  const r = await credentialAddVerify(g.session.token, resp.data as unknown as RegistrationResponseJSON, nick.data);
  return r.ok ? json({ ok: true, credential: r.credential }) : fail(r.error === "TOO_MANY_CREDENTIALS" ? r.error : "ENROLMENT_FAILED");
}
