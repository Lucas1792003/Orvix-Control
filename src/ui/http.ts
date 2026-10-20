// Browser-side helpers. Holds no secrets: the session cookie is HttpOnly; the CSRF token is per session.
import { startAuthentication } from "@simplewebauthn/browser";

export async function postJson(url: string, body: unknown, csrf?: string): Promise<{ ok: boolean; [k: string]: unknown }> {
  const res = await fetch(url, {
    method: "POST",
    credentials: "same-origin",
    headers: { "content-type": "application/json", ...(csrf ? { "x-orvix-csrf": csrf } : {}) },
    body: JSON.stringify(body ?? {}),
  });
  try {
    return await res.json();
  } catch {
    return { ok: false, error: "NETWORK" };
  }
}

// Step-up for ONE action on ONE target. The database turns a verified assertion into a single-use grant.
export async function stepUp(csrf: string, action: string, target: string): Promise<boolean> {
  const o = await postJson("/api/auth/stepup/options", { action, target }, csrf);
  if (!o.ok) return false;
  try {
    const response = await startAuthentication({ optionsJSON: o.options as never });
    const v = await postJson("/api/auth/stepup/verify", { response }, csrf);
    return v.ok === true;
  } catch {
    return false;
  }
}

export const ERROR_TEXT: Record<string, string> = {
  UNAUTHENTICATED: "Your session has ended. Sign in again.",
  FORBIDDEN: "Your role does not allow this action.",
  STEPUP_REQUIRED: "Confirm with your passkey first.",
  REASON_REQUIRED: "Choose a reason and write a note of at least 10 characters.",
  TRANSITION_NOT_ALLOWED: "That transition is not allowed from the current state.",
  NOT_AVAILABLE_IN_FOUNDATION: "This step needs POS integration and is not available yet.",
  RATE_LIMITED: "Too many attempts. Wait a few minutes.",
  CSRF: "The request was refused. Reload the page.",
  LOGIN_FAILED: "Sign-in was refused.",
  LAST_CREDENTIAL: "You cannot remove your last passkey. Add another one first.",
  TOO_MANY_CREDENTIALS: "You already have the maximum number of passkeys.",
  SELF_APPROVAL_FORBIDDEN: "You cannot approve your own recovery. Another owner must do it.",
  HEAD_CHANGED: "The audit log changed while signing. Investigate before anchoring again.",
  RECOVERY_CONTESTED: "This request is contested (the operator objected or used a passkey since). It needs host confirmation and a 12-hour wait.",
  CREDENTIAL_PENDING: "That passkey is still pending: it activates 15 minutes after its out-of-band notice was delivered.",
  NOTIFICATION_PENDING: "Waiting for the out-of-band security notice to be delivered. Try again in a minute; if it persists, the host must check the sentinel.",
  ALREADY_EXISTS: "An operator or open invitation already exists for that email.",
};

export function downloadJson(name: string, data: unknown) {
  const url = URL.createObjectURL(new Blob([JSON.stringify(data, null, 2)], { type: "application/json" }));
  const a = document.createElement("a");
  a.href = url; a.download = name; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
