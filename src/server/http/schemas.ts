import "server-only";
import { z } from "zod";

export const enrolToken = z.string().regex(/^[0-9a-f]{64}$/);

// Shape check only; cryptographic verification happens in @simplewebauthn/server.
const b64url = z.string().regex(/^[A-Za-z0-9_-]+$/).max(16_384);
export const registrationResponse = z.object({
  id: b64url,
  rawId: b64url,
  type: z.literal("public-key"),
  response: z.object({ clientDataJSON: b64url, attestationObject: b64url, transports: z.array(z.string()).optional() }).passthrough(),
  clientExtensionResults: z.record(z.string(), z.unknown()).default({}),
  authenticatorAttachment: z.string().optional(),
}).passthrough();

export const authenticationResponse = z.object({
  id: b64url,
  rawId: b64url,
  type: z.literal("public-key"),
  response: z.object({ clientDataJSON: b64url, authenticatorData: b64url, signature: b64url, userHandle: b64url.optional() }).passthrough(),
  clientExtensionResults: z.record(z.string(), z.unknown()).default({}),
  authenticatorAttachment: z.string().optional(),
}).passthrough();

export const transitionBody = z.object({
  to: z.enum(["draft", "provisioning", "invited", "pending_activation", "active", "past_due", "suspended", "locked", "abandoned", "archived"]),
  reasonCode: z.enum(["owner_request", "abuse", "security", "notice", "test", "other"]).nullable().default(null),
  note: z.string().max(500).nullable().default(null),
  requestId: z.uuid(),
});

export const stepupBody = z.object({
  action: z.enum(["tenant_transition", "credential_add", "credential_revoke", "recovery_approve", "recovery_cancel", "operator_invite",
                  "pos_recovery_transition", "pos_recovery_contain", "pos_recovery_submit"]),
  target: z.string().regex(/^[A-Za-z0-9:_-]{1,200}$/),
});

export const nickname = z.string().trim().min(1).max(60).nullable().default(null);

export const inviteBody = z.object({
  email: z.string().trim().toLowerCase().max(254).regex(/^[^@\s]+@[^@\s]+\.[^@\s]+$/),
  displayName: z.string().trim().min(1).max(80),
  role: z.enum(["owner", "admin"]),
});

// Step 5 (222): POS recovery bridge. Shape checks only; the database re-checks everything and the POS decides.
export const posOrgId = z.string().regex(/^[A-Za-z0-9_-]{1,100}$/);
// Containment only. There is deliberately no "ACTIVE": only an owner-signed reopening (submitted below) sets it.
export const posTransitionBody = z.object({
  to: z.enum(["RESTRICTED", "RECONCILING", "QUARANTINED"]),
  reason: z.string().trim().min(10).max(500),
  evidenceReference: z.string().trim().min(3).max(500),
  requestId: z.uuid(),
});
export const posContainBody = z.object({
  action: z.enum(["suspend", "revoke"]),
  reason: z.string().trim().min(10).max(300),
  requestId: z.uuid(),
});
export const posReportBody = z.object({ requestId: z.uuid() });
// The authorization text is carried byte for byte (never trimmed or re-serialized): the step-up target is its SHA-256.
export const posSubmitBody = z.object({
  authorization: z.string().min(2).max(65_536),
  signature: z.string().regex(/^[0-9a-fA-F]+$/).min(2).max(4096),
  requestId: z.uuid(),
});
