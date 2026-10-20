import type { NextRequest } from "next/server";
import { stepupOptions } from "@/src/server/auth/webauthn";
import { fail, json, readJson, requireMutation } from "@/src/server/http/respond";
import { stepupBody } from "@/src/server/http/schemas";

// A step-up is always for ONE named action on ONE target; the resulting grant is single-use (2 min).
export async function POST(req: NextRequest) {
  const g = await requireMutation(req);
  if ("error" in g) return g.error;
  const body = stepupBody.safeParse(await readJson(req));
  if (!body.success) return fail("INVALID_INPUT");
  const r = await stepupOptions(g.session.token, body.data.action, body.data.target);
  return r.ok ? json({ ok: true, options: r.options }) : fail(r.error === "UNAUTHENTICATED" ? "UNAUTHENTICATED" : "INVALID_INPUT");
}
