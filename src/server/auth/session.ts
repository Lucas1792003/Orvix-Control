import "server-only";
import { createHmac, timingSafeEqual } from "node:crypto";
import { cookies } from "next/headers";
import { cache } from "react";
import { callApi } from "../db/api";

// __Host- prefix: Secure, Path=/, no Domain. Chrome and Firefox treat http://localhost as a secure
// context; Safari's handling is unverified (docs/SECURITY_FINDINGS.md).
export const SESSION_COOKIE = "__Host-orvix_sid";
// Device cookie (213): selects a per-device login rate-limit bucket. Grants nothing by itself.
export const DEVICE_COOKIE = "__Host-orvix_dev";

export async function readDeviceToken(): Promise<string | null> {
  const v = (await cookies()).get(DEVICE_COOKIE)?.value;
  return v && TOKEN_RE.test(v) ? v : null;
}
const TOKEN_RE = /^[0-9a-f]{64}$/;

export type Session = {
  identityId: string;
  email: string;
  displayName: string;
  role: "owner" | "admin";
  absoluteExpiresAt: string;
  idleExpiresAt: string;
  activeCredentials: number;
  pendingCredentials: number;
  flaggedCredentials: number;
  token: string;
};

export async function readSessionToken(): Promise<string | null> {
  const v = (await cookies()).get(SESSION_COOKIE)?.value;
  return v && TOKEN_RE.test(v) ? v : null;
}

// Resolved once per request (React cache). Every page and route handler goes through this; the database
// decides. Any doubt (missing cookie, DB error, unexpected shape) means "no session".
export const getSession = cache(async (): Promise<Session | null> => {
  const token = await readSessionToken();
  if (!token) return null;
  const r = await callApi("api_session_get", [token]);
  if (!r.ok) return null;
  const role = r.role;
  if (role !== "owner" && role !== "admin") return null;
  return {
    identityId: String(r.identity_id),
    email: String(r.email),
    displayName: String(r.display_name),
    role,
    absoluteExpiresAt: String(r.absolute_expires_at),
    idleExpiresAt: String(r.idle_expires_at),
    activeCredentials: Number(r.active_credentials ?? 0),
    pendingCredentials: Number(r.pending_credentials ?? 0),
    flaggedCredentials: Number(r.flagged_credentials ?? 0),
    token,
  };
});

export function sessionCookieOptions(maxAgeSeconds: number) {
  return {
    httpOnly: true,
    secure: true,
    sameSite: "strict" as const,
    path: "/",
    maxAge: maxAgeSeconds,
  };
}

// Synchronizer CSRF token derived from the secret session token (no extra state).
export function csrfFor(token: string): string {
  return createHmac("sha256", token).update("orvix-control/csrf/v1").digest("hex");
}

export function csrfValid(token: string, presented: string | null): boolean {
  if (!presented || !/^[0-9a-f]{64}$/.test(presented)) return false;
  const expected = Buffer.from(csrfFor(token), "hex");
  const got = Buffer.from(presented, "hex");
  return expected.length === got.length && timingSafeEqual(expected, got);
}
