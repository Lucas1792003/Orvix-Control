import type { NextRequest } from "next/server";
import { enrolOptions } from "@/src/server/auth/webauthn";
import { fail, json, originOk, readJson } from "@/src/server/http/respond";
import { enrolToken } from "@/src/server/http/schemas";

export async function POST(req: NextRequest) {
  if (!originOk(req)) return fail("BAD_ORIGIN");
  const body = (await readJson(req)) as { token?: unknown } | null;
  const token = enrolToken.safeParse(body?.token);
  if (!token.success) return fail("INVALID_INPUT");
  const r = await enrolOptions(token.data);
  return r.ok ? json({ ok: true, options: r.options, purpose: r.purpose, expiresInSeconds: r.expiresInSeconds }) : fail(r.error === "RATE_LIMITED" ? "RATE_LIMITED" : "INVALID_TOKEN");
}
