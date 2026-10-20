import type { NextRequest } from "next/server";
import { loginOptions } from "@/src/server/auth/webauthn";
import { fail, json, originOk } from "@/src/server/http/respond";

export async function POST(req: NextRequest) {
  if (!originOk(req)) return fail("BAD_ORIGIN");
  const r = await loginOptions();
  return r.ok ? json({ ok: true, options: r.options }) : fail(r.error === "RATE_LIMITED" ? "RATE_LIMITED" : "INVALID_INPUT");
}
