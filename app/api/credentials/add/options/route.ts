import type { NextRequest } from "next/server";
import { credentialAddOptions } from "@/src/server/auth/webauthn";
import { fail, json, requireMutation } from "@/src/server/http/respond";

export async function POST(req: NextRequest) {
  const g = await requireMutation(req);
  if ("error" in g) return g.error;
  const r = await credentialAddOptions(g.session.token);
  return r.ok ? json({ ok: true, options: r.options }) : fail(r.error);
}
