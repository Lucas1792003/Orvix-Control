import { csrfFor, getSession } from "@/src/server/auth/session";
import { fail, json } from "@/src/server/http/respond";

export async function GET() {
  const s = await getSession();
  if (!s) return fail("UNAUTHENTICATED");
  return json({
    ok: true,
    identity: { displayName: s.displayName, email: s.email, role: s.role },
    absoluteExpiresAt: s.absoluteExpiresAt,
    idleExpiresAt: s.idleExpiresAt,
    activeCredentials: s.activeCredentials,
    pendingCredentials: s.pendingCredentials,
    flaggedCredentials: s.flaggedCredentials,
    csrf: csrfFor(s.token),
  });
}
