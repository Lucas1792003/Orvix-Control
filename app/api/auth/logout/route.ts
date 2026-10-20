import type { NextRequest } from "next/server";
import { callApi } from "@/src/server/db/api";
import { SESSION_COOKIE } from "@/src/server/auth/session";
import { json, requireMutation } from "@/src/server/http/respond";

export async function POST(req: NextRequest) {
  const g = await requireMutation(req);
  if ("error" in g) return g.error;
  await callApi("api_session_revoke", [g.session.token]);
  const res = json({ ok: true });
  res.cookies.set(SESSION_COOKIE, "", { httpOnly: true, secure: true, sameSite: "strict", path: "/", maxAge: 0 });
  return res;
}
