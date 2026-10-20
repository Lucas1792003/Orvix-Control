import type { NextRequest } from "next/server";
import type { AuthenticationResponseJSON } from "@simplewebauthn/server";
import { loginVerify } from "@/src/server/auth/webauthn";
import { DEVICE_COOKIE, SESSION_COOKIE, readDeviceToken, sessionCookieOptions } from "@/src/server/auth/session";
import { fail, json, originOk, readJson } from "@/src/server/http/respond";
import { authenticationResponse } from "@/src/server/http/schemas";

export async function POST(req: NextRequest) {
  if (!originOk(req)) return fail("BAD_ORIGIN");
  const body = (await readJson(req)) as { response?: unknown } | null;
  const resp = authenticationResponse.safeParse(body?.response);
  if (!resp.success) return fail("INVALID_INPUT");
  const r = await loginVerify(resp.data as unknown as AuthenticationResponseJSON, await readDeviceToken());
  if (!r.ok) return r.error === "RATE_LIMITED" ? fail("RATE_LIMITED") : json({ ok: false, error: "LOGIN_FAILED" }, 401);
  const token = String(r.session_token);
  const absMs = new Date(String(r.absolute_expires_at)).getTime() - Date.now();
  const res = json({ ok: true });
  // A new session token on every login (no fixation). The cookie never outlives the absolute expiry.
  res.cookies.set(SESSION_COOKIE, token, sessionCookieOptions(Math.max(1, Math.floor(absMs / 1000))));
  if (typeof r.device_token === "string" && /^[0-9a-f]{64}$/.test(r.device_token)) {
    res.cookies.set(DEVICE_COOKIE, r.device_token, sessionCookieOptions(Number(r.device_ttl_seconds) || 34_560_000));
  }
  return res;
}
