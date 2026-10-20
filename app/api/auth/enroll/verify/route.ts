import type { NextRequest } from "next/server";
import type { RegistrationResponseJSON } from "@simplewebauthn/server";
import { enrolVerify } from "@/src/server/auth/webauthn";
import { fail, json, originOk, readJson } from "@/src/server/http/respond";
import { enrolToken, nickname, registrationResponse } from "@/src/server/http/schemas";

export async function POST(req: NextRequest) {
  if (!originOk(req)) return fail("BAD_ORIGIN");
  const body = (await readJson(req)) as { token?: unknown; response?: unknown; nickname?: unknown } | null;
  const token = enrolToken.safeParse(body?.token);
  const resp = registrationResponse.safeParse(body?.response);
  const nick = nickname.safeParse(body?.nickname ?? null);
  if (!token.success || !resp.success || !nick.success) return fail("INVALID_INPUT");
  const r = await enrolVerify(token.data, resp.data as unknown as RegistrationResponseJSON, nick.data);
  if (r.ok) return json({ ok: true, purpose: r.purpose, fingerprint: r.fingerprint, awaitingHostApproval: r.awaiting_host_approval === true });
  return fail(r.error === "NOTIFICATION_PENDING" ? "NOTIFICATION_PENDING" : "ENROLMENT_FAILED");
}
