import "server-only";
import { notFound, redirect } from "next/navigation";
import { csrfFor, getSession, type Session } from "../auth/session";
import { callApi, type ApiName } from "../db/api";

export type Tenant = {
  id: string; slug: string; display_name: string; status: string; status_reason: string | null;
  status_changed_at: string; shop_count: number; user_count: number; admin_mfa_verified: boolean;
  created_at: string; is_synthetic: boolean;
};
export type AuditEvent = {
  seq: number; occurred_at: string; actor_type: string; actor_label: string | null; action: string;
  outcome: "success" | "denied" | "failed"; target_type: string | null; target_id: string | null;
  request_id: string | null; reason_code: string | null; detail: Record<string, unknown>; row_hash: string;
};
export type Transition = { to: string; allowed_roles: string[]; requires_stepup: boolean; requires_reason: boolean; available: boolean };

// Every console page calls this. No session (or any doubt) -> /login. Never trusts the layout alone.
export async function requirePage(): Promise<Session & { csrf: string }> {
  const s = await getSession();
  if (!s) redirect("/login");
  return { ...s, csrf: csrfFor(s.token) };
}

async function call(name: ApiName, s: Session, ...rest: unknown[]) {
  const r = await callApi(name, [s.token, ...rest]);
  if (!r.ok && r.error === "UNAUTHENTICATED") redirect("/login");
  return r;
}

export async function listTenants(s: Session): Promise<Tenant[]> {
  const r = await call("api_tenant_list", s);
  if (!r.ok) throw new Error(r.error);
  return r.tenants as Tenant[];
}

export async function getTenant(s: Session, id: string) {
  if (!/^[0-9a-f-]{36}$/.test(id)) notFound();
  const r = await call("api_tenant_get", s, id);
  if (!r.ok && r.error === "NOT_FOUND") notFound();
  if (!r.ok) throw new Error(r.error);
  return r as unknown as { tenant: Tenant; history: { from: string; to: string; reason_code: string | null; changed_at: string; audit_seq: number }[]; transitions: Transition[] };
}

export async function listAudit(s: Session, limit = 50, beforeSeq: number | null = null) {
  const r = await call("api_audit_list", s, limit, beforeSeq);
  if (!r.ok) throw new Error(r.error);
  return { scope: r.scope as "all" | "own", events: r.events as AuditEvent[] };
}

// ------------------------------------------------------------ Step 5 (222): POS recovery bridge (metadata only)
export type PosEnrollment = { enrollmentId: string; shopId: string; deviceId: string; keyFingerprint: string; state: string; notAfter: string | null; replaces: string | null;
  /** Step 6: the current suspension event (what an owner's device-reinstate authorization names); null unless SUSPENDED */
  suspensionEventId?: number | null };
export type PosDeviceRequest = { requestId: string; shopId: string; deviceId: string; keyFingerprint: string; shortCode: string; requestNonce: string;
  replaces: string | null; requestedAt: string; requestedBy: string };
export type PosOrg = {
  orgId: string; state: "ACTIVE" | "RESTRICTED" | "RECONCILING" | "QUARANTINED"; incidentId: string | null; recoveryEpoch: number | null;
  activation: string | null;
  reopening: { reopenId: string; decision: string; acceptedBlockers: string[]; uncertainties: string[]; byKey: string; at: string } | null;
  lastReport: { reportId: string; digest: string; blockers: string[]; hardBlockers: string[]; at: string; facts: Record<string, unknown> } | null;
  devices: { pendingRequests: number; enrollments: PosEnrollment[] };
  ownerAuthority: { keyId: string; fingerprint: string; scope: string }[];
  deviceRequests?: PosDeviceRequest[];
  reopenBlockedBy: string[];
};
export type PosAuditEvent = { id: number; kind: string; detail: Record<string, unknown>; actor: string | null; at: string };

// Errors are returned, not thrown: the page must say clearly when the POS hook is unavailable (BLOCKED).
export async function posRecoveryOverview(s: Session): Promise<{ ok: true; organizations: PosOrg[] } | { ok: false; error: string }> {
  const r = await call("api_pos_recovery_overview", s);
  return r.ok ? { ok: true, organizations: r.organizations as PosOrg[] } : { ok: false, error: r.error };
}

export async function posRecoveryOrg(s: Session, org: string): Promise<{ ok: true; organization: PosOrg } | { ok: false; error: string }> {
  if (!/^[A-Za-z0-9_-]{1,100}$/.test(org)) return { ok: false, error: "INVALID_INPUT" };
  const r = await call("api_pos_recovery_org", s, org);
  return r.ok ? { ok: true, organization: r.organization as PosOrg } : { ok: false, error: r.error };
}

export async function posRecoveryAudit(s: Session, org: string, limit = 50): Promise<{ ok: true; events: PosAuditEvent[] } | { ok: false; error: string }> {
  if (!/^[A-Za-z0-9_-]{1,100}$/.test(org)) return { ok: false, error: "INVALID_INPUT" };
  const r = await call("api_pos_recovery_audit", s, org, limit);
  return r.ok ? { ok: true, events: r.events as PosAuditEvent[] } : { ok: false, error: r.error };
}
