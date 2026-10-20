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
  action: z.enum(["tenant_transition", "credential_add", "credential_revoke", "recovery_approve", "recovery_cancel"]),
  target: z.string().regex(/^[A-Za-z0-9:_-]{1,200}$/),
});

export const nickname = z.string().trim().min(1).max(60).nullable().default(null);
