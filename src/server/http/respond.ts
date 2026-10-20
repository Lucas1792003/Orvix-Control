import "server-only";
import { randomUUID } from "node:crypto";
import { NextResponse, type NextRequest } from "next/server";
import { config } from "../config";
import { csrfValid, getSession, type Session } from "../auth/session";

const NO_STORE = { "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff" };

// Generic, code-only errors. Internal text never reaches the client.
const STATUS: Record<string, number> = {
  UNAUTHENTICATED: 401,
  FORBIDDEN: 403,
  STEPUP_REQUIRED: 403,
  CSRF: 403,
  BAD_ORIGIN: 403,
  RATE_LIMITED: 429,
  NOT_FOUND: 404,
  INVALID_INPUT: 400,
  REQUEST_ID_REQUIRED: 400,
  REQUEST_ID_CONFLICT: 409,
  TRANSITION_NOT_ALLOWED: 409,
  NOT_AVAILABLE_IN_FOUNDATION: 409,
  REASON_REQUIRED: 400,
  LAST_CREDENTIAL: 409,
  TOO_MANY_CREDENTIALS: 409,
  SELF_APPROVAL_FORBIDDEN: 403,
  HEAD_CHANGED: 409,
  RECOVERY_CONTESTED: 409,
  NOTIFICATION_PENDING: 409,
  ALREADY_EXISTS: 409,
  CREDENTIAL_PENDING: 403,
};

export function json(body: Record<string, unknown>, status = 200, requestId: string = randomUUID()) {
  return NextResponse.json(body, { status, headers: { ...NO_STORE, "x-request-id": requestId } });
}

export function fail(code: string, requestId?: string) {
  return json({ ok: false, error: code }, STATUS[code] ?? 400, requestId);
}

// Exact Origin match for every state-changing request (SameSite=Strict is the first layer).
export function originOk(req: NextRequest): boolean {
  return req.headers.get("origin") === config.origin;
}

// Gate for authenticated mutations: Origin + session + CSRF header. Fails closed.
export async function requireMutation(req: NextRequest): Promise<{ session: Session } | { error: Response }> {
  if (!originOk(req)) return { error: fail("BAD_ORIGIN") };
  const session = await getSession();
  if (!session) return { error: fail("UNAUTHENTICATED") };
  if (!csrfValid(session.token, req.headers.get("x-orvix-csrf"))) return { error: fail("CSRF") };
  return { session };
}

// Streams the body with a hard byte cap (a missing or false content-length cannot force a full read).
export async function readJson(req: NextRequest, maxBytes = 16_384): Promise<unknown | null> {
  if (!(req.headers.get("content-type") ?? "").startsWith("application/json")) return null;
  const declared = Number(req.headers.get("content-length") ?? "0");
  if (declared > maxBytes || !req.body) return null;
  const reader = req.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel();
        return null;
      }
      chunks.push(value);
    }
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    return null;
  }
}
