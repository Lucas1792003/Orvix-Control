import Link from "next/link";
import { posRecoveryAudit, posRecoveryOrg, posRecoveryOverview, requirePage, type PosOrg } from "@/src/server/services/console";
import { fmtTime } from "@/src/ui/Status";
import { ContainmentPanel, DeviceActions, SubmitAuthorizationPanel } from "./RecoveryActions";

const STATE_TONE: Record<string, string> = {
  ACTIVE: "text-ok border-ok/40",
  RESTRICTED: "text-warn border-warn/40",
  RECONCILING: "text-accent border-accent/40",
  QUARANTINED: "text-danger border-danger/40",
  SUSPENDED: "text-warn border-warn/40",
  REVOKED: "text-danger border-danger/40",
  EXPIRED: "text-muted border-line",
};
function StateBadge({ value }: { value: string }) {
  return <span className={`inline-flex rounded border px-1.5 py-0.5 text-xs font-medium ${STATE_TONE[value] ?? "text-muted border-line"}`}>{value}</span>;
}

const BLOCKED_TEXT: Record<string, string> = {
  no_owner_authority: "no owner authority (no trusted owner key covers this organization)",
  not_reconciling: "not RECONCILING",
  no_report: "no reconciliation report for this incident",
  hard_blockers: "hard blockers in the last report",
};

const REFUSAL_TEXT: Record<string, string> = {
  FORBIDDEN: "Your role does not allow this view.",
  NOT_FOUND: "The POS does not know this organization.",
  INVALID_INPUT: "Invalid organization id.",
  POS_RECOVERY_ERROR: "The POS recovery interface failed.",
};
const refusal = (code: string) => REFUSAL_TEXT[code] ?? `Refused (${code}).`;

function Blocked({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div role="alert" className="rounded-lg border border-danger/40 bg-danger/10 px-4 py-3 text-sm text-danger">
      <p className="font-semibold">{title}</p>
      <div className="mt-1">{children}</div>
    </div>
  );
}

export default async function PosRecoveryPage({ searchParams }: { searchParams: Promise<{ org?: string }> }) {
  const s = await requirePage();
  const selected = (await searchParams).org;
  const overview = await posRecoveryOverview(s);
  const detail = overview.ok && selected ? await posRecoveryOrg(s, selected) : null;
  const audit = detail?.ok && selected ? await posRecoveryAudit(s, selected, 50) : null;

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-semibold">POS recovery</h1>
        <p className="mt-1 text-sm text-muted">
          Recovery V1 state of each POS organization, read through the POS-owned operator interface (metadata and counts only).
          Control can contain (restrict, start reconciliation, quarantine, suspend or revoke a till) and can carry an
          owner-signed authorization to the POS verifier. It cannot create trust: <strong>no action here sets ACTIVE</strong>;
          only an owner-signed reopening, verified by the POS, does.
        </p>
      </div>

      {!overview.ok && overview.error === "POS_RECOVERY_UNAVAILABLE" && (
        <Blocked title="BLOCKED: POS recovery hook not installed">
          The <code>recovery_v1.operator_*</code> interface is missing, incomplete, or not granted to Control
          (<code>orvix_recovery_operator</code> → <code>control_definer</code> is a POS-owner decision). Every recovery
          transition, containment and submission is blocked. Control does not fall back to anything else.
        </Blocked>
      )}
      {!overview.ok && overview.error !== "POS_RECOVERY_UNAVAILABLE" && (
        <Blocked title="POS recovery unavailable">{refusal(overview.error)}</Blocked>
      )}

      {overview.ok && (
        <div className="overflow-x-auto rounded-lg border border-line bg-panel">
          <table className="w-full min-w-[760px] text-left text-sm">
            <thead className="border-b border-line text-xs text-muted">
              <tr>
                <th className="px-4 py-2 font-medium">Organization</th><th className="px-4 py-2 font-medium">State</th>
                <th className="px-4 py-2 font-medium">Incident / epoch</th><th className="px-4 py-2 font-medium">Activation</th>
                <th className="px-4 py-2 font-medium">Tills</th><th className="px-4 py-2 font-medium">Owner authority</th>
                <th className="px-4 py-2 font-medium">Reopening blocked by</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {overview.organizations.length === 0 && <tr><td colSpan={7} className="px-4 py-3 text-muted">No organizations.</td></tr>}
              {overview.organizations.map((o) => (
                <tr key={o.orgId} className={selected === o.orgId ? "bg-bg" : ""}>
                  <td className="px-4 py-2"><Link href={`/pos-recovery?org=${encodeURIComponent(o.orgId)}`} className="font-mono underline-offset-2 hover:underline">{o.orgId}</Link></td>
                  <td className="px-4 py-2"><StateBadge value={o.state} /></td>
                  <td className="px-4 py-2 font-mono text-xs">{o.incidentId ? `${o.incidentId.slice(0, 8)}… / ${o.recoveryEpoch}` : "—"}</td>
                  <td className="px-4 py-2 text-xs">{o.activation ?? "—"}</td>
                  <td className="px-4 py-2 tabular-nums">{o.devices.enrollments.length}{o.devices.pendingRequests > 0 && <span className="text-warn"> +{o.devices.pendingRequests} pending</span>}</td>
                  <td className="px-4 py-2">{o.ownerAuthority.length > 0 ? `${o.ownerAuthority.length} key(s)` : <span className="font-medium text-danger">none (BLOCKED)</span>}</td>
                  <td className="px-4 py-2 text-xs">{o.reopenBlockedBy.length === 0 ? "—" : o.reopenBlockedBy.map((b) => BLOCKED_TEXT[b] ?? b).join("; ")}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {detail && !detail.ok && <Blocked title="Organization unavailable">{refusal(detail.error)}</Blocked>}
      {detail?.ok && <OrgDetail org={detail.organization} role={s.role} csrf={s.csrf} audit={audit?.ok ? audit.events : null} />}
    </div>
  );
}

function OrgDetail({ org: o, role, csrf, audit }: { org: PosOrg; role: string; csrf: string; audit: { id: number; kind: string; detail: Record<string, unknown>; actor: string | null; at: string }[] | null }) {
  const rep = o.lastReport;
  return (
    <section className="space-y-6">
      <div className="flex flex-wrap items-center gap-3">
        <h2 className="font-mono text-lg font-semibold">{o.orgId}</h2>
        <StateBadge value={o.state} />
        {o.activation && <span className="text-xs text-muted">activation: {o.activation}</span>}
      </div>

      {o.ownerAuthority.length === 0 && (
        <Blocked title="BLOCKED: no owner authority">
          No trusted owner key covers this organization. Reopening and device enrollment/reinstatement are blocked until the
          owner enrolls a key in the POS (owner procedure). Containment remains available.
        </Blocked>
      )}

      <dl className="grid grid-cols-1 gap-4 rounded-lg border border-line bg-panel p-4 text-sm sm:grid-cols-3">
        <div><dt className="text-muted">Incident</dt><dd className="font-mono text-xs">{o.incidentId ?? "—"}</dd></div>
        <div><dt className="text-muted">Recovery epoch</dt><dd className="tabular-nums">{o.recoveryEpoch ?? "—"}</dd></div>
        <div><dt className="text-muted">Owner authority</dt><dd className="text-xs">{o.ownerAuthority.length === 0 ? "none" : o.ownerAuthority.map((k) => (
          <div key={k.keyId}><span className="font-mono">{k.keyId}</span> · scope {k.scope}<div className="font-mono text-muted">{k.fingerprint}</div></div>))}</dd></div>
        <div className="sm:col-span-3"><dt className="text-muted">Last reopening</dt><dd className="text-xs">{o.reopening
          ? <>{o.reopening.decision} by key <span className="font-mono">{o.reopening.byKey}</span> · {fmtTime(o.reopening.at)}
              {o.reopening.uncertainties.length > 0 && <> · uncertainties: {o.reopening.uncertainties.join("; ")}</>}</>
          : "—"}</dd></div>
      </dl>

      <div className="rounded-lg border border-line bg-panel p-4 text-sm">
        <h3 className="text-sm font-medium">Last reconciliation report</h3>
        {!rep && <p className="mt-1 text-muted">None for the current incident.</p>}
        {rep && (
          <div className="mt-2 space-y-2">
            <p className="text-xs text-muted">{fmtTime(rep.at)} · digest <span className="font-mono">{rep.digest}</span></p>
            <div className="flex flex-wrap gap-2">
              {rep.blockers.length === 0 && <span className="text-ok">no blockers</span>}
              {rep.blockers.map((b) => {
                const hard = rep.hardBlockers.includes(b);
                return <span key={b} title={hard ? "hard blocker: no owner decision can accept it" : "an owner may accept it in a limited reopening"}
                  className={`rounded border px-1.5 py-0.5 text-xs ${hard ? "border-danger bg-danger/10 font-semibold text-danger" : "border-warn/40 text-warn"}`}>
                  {hard ? "HARD · " : ""}{b}</span>;
              })}
            </div>
          </div>
        )}
        {o.reopenBlockedBy.length > 0 && o.state !== "ACTIVE" && (
          <p className="mt-3 text-xs text-danger">Reopening is blocked: {o.reopenBlockedBy.map((b) => BLOCKED_TEXT[b] ?? b).join("; ")}.</p>
        )}
      </div>

      <ContainmentPanel org={o.orgId} state={o.state} csrf={csrf} />

      <div className="rounded-lg border border-line bg-panel p-4 text-sm">
        <h3 className="text-sm font-medium">Tills</h3>
        <ul className="mt-2 divide-y divide-line">
          {o.devices.enrollments.length === 0 && <li className="py-2 text-muted">No enrollments.</li>}
          {o.devices.enrollments.map((e) => (
            <li key={e.enrollmentId} className="flex flex-wrap items-center gap-3 py-2">
              <span className="font-mono">{e.deviceId}</span><StateBadge value={e.state} />
              <span className="text-xs text-muted">shop {e.shopId} · key {e.keyFingerprint.slice(0, 16)}…{e.notAfter && ` · until ${fmtTime(e.notAfter)}`}</span>
              <span className="ml-auto"><DeviceActions org={o.orgId} enrollmentId={e.enrollmentId} state={e.state} csrf={csrf} /></span>
            </li>
          ))}
        </ul>
        <h3 className="mt-4 text-sm font-medium">Open device requests</h3>
        <ul className="mt-2 divide-y divide-line">
          {(o.deviceRequests ?? []).length === 0 && <li className="py-2 text-muted">None.</li>}
          {(o.deviceRequests ?? []).map((q) => (
            <li key={q.requestId} className="py-2 text-xs">
              <span className="font-mono text-sm">{q.deviceId}</span> · shop {q.shopId} · short code <span className="font-mono font-semibold">{q.shortCode}</span>
              <div className="text-muted">request <span className="font-mono">{q.requestId}</span> · nonce <span className="font-mono">{q.requestNonce}</span> · {q.requestedBy} · {fmtTime(q.requestedAt)}</div>
            </li>
          ))}
        </ul>
        <p className="mt-2 text-xs text-muted">Enrolling a till needs an owner-signed enroll-device authorization naming the request; compare the short code with the till.</p>
      </div>

      <SubmitAuthorizationPanel role={role} csrf={csrf} ownerAuthority={o.ownerAuthority.length > 0} />

      <div className="rounded-lg border border-line bg-panel p-4 text-sm">
        <h3 className="text-sm font-medium">POS recovery history</h3>
        {!audit && <p className="mt-1 text-muted">Unavailable.</p>}
        <ul className="mt-2 divide-y divide-line">
          {audit?.length === 0 && <li className="py-2 text-muted">No events.</li>}
          {audit?.map((a) => (
            <li key={a.id} className="py-2 text-xs">
              <span className="font-medium">{a.kind}</span> <span className="text-muted">· {a.actor ?? "—"} · {fmtTime(a.at)}</span>
              <pre className="mt-1 overflow-x-auto whitespace-pre-wrap break-all font-mono text-[11px] text-muted">{JSON.stringify(a.detail)}</pre>
            </li>
          ))}
        </ul>
      </div>
    </section>
  );
}
