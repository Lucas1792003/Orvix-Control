import type { NextRequest } from "next/server";
import type { RegistrationResponseJSON } from "@simplewebauthn/server";
import { enrolVerify } from "@/src/server/auth/webauthn";
import { DEVICE_COOKIE, sessionCookieOptions } from "@/src/server/auth/session";
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
  if (r.ok) {
    const res = json({ ok: true, purpose: r.purpose, fingerprint: r.fingerprint, awaitingHostApproval: r.awaiting_host_approval === true });
    // C1.3 M2: the enrolling browser gets its own login bucket, so a freshly recovered or activated owner never depends
    // on the shared anonymous bucket for the first sign-in.
    if (typeof r.device_token === "string" && /^[0-9a-f]{64}$/.test(r.device_token)) {
      res.cookies.set(DEVICE_COOKIE, r.device_token, sessionCookieOptions(Number(r.device_ttl_seconds) || 34_560_000));
    }
    return res;
  }
  if (r.error === "NOTIFICATION_PENDING" || r.error === "RECOVERY_CONTESTED") return fail(r.error);
  return fail("ENROLMENT_FAILED");
}
