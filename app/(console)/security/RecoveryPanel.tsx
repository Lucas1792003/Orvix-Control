"use client";
import { useState } from "react";
import { ERROR_TEXT, postJson, stepUp } from "@/src/ui/http";
import { fmtTime } from "@/src/ui/Status";

export type RecoveryRequest = {
  id: string; subject_display_name: string; subject_email: string; subject_id: string; subject_is_you: boolean; reason: string; state: string;
  requested_at: string; expires_at: string; contested_at: string | null; host_confirmed_at: string | null;
};

// Recovery needs two people: the host operator creates the request (superuser CLI), and a DIFFERENT owner
// approves here with a passkey. The one-time link is shown once and must be relayed out of band.
export function RecoveryPanel({ csrf, requests }: { csrf: string; requests: RecoveryRequest[] }) {
  const [link, setLink] = useState<string | null>(null);
  const [msg, setMsg] = useState<string | null>(null);

  async function approve(r: RecoveryRequest) {
    setMsg(null);
    if (!(await stepUp(csrf, "recovery_approve", r.id))) return setMsg(ERROR_TEXT.STEPUP_REQUIRED!);
    const res = await postJson(`/api/recovery/${r.id}/approve`, {}, csrf);
    if (!res.ok) return setMsg(ERROR_TEXT[String(res.error)] ?? "Approval was refused.");
    setLink(`${window.location.origin}/enroll/${res.enrolment_token}`);
  }

  async function cancel(r: RecoveryRequest) {
    setMsg(null);
    if (!(await stepUp(csrf, "recovery_cancel", r.id))) return setMsg(ERROR_TEXT.STEPUP_REQUIRED!);
    const res = await postJson(`/api/recovery/${r.id}/cancel`, {}, csrf);
    if (!res.ok) return setMsg(ERROR_TEXT[String(res.error)] ?? "Cancel was refused.");
    window.location.reload();
  }

  return (
    <section className="rounded-lg border border-line bg-panel p-4">
      <h2 className="text-sm font-medium">Operator recovery requests</h2>
      <p className="mt-1 text-xs text-muted">Created on the host only. Approving (a different owner) issues a one-time, 30-minute enrolment link: whoever holds it enrols, and all of the operator's old passkeys are disabled. Check the email and id. If the operator objects, or has used a passkey since the request, approval additionally needs host confirmation and a 12-hour wait.</p>
      <ul className="mt-3 divide-y divide-line text-sm">
        {requests.length === 0 && <li className="py-2 text-muted">No open requests.</li>}
        {requests.map((r) => (
          <li key={r.id} className="flex flex-wrap items-center gap-3 py-2">
            <span className="font-medium">{r.subject_display_name}</span>
            <span className="font-mono text-xs text-muted">{r.subject_email} · {r.subject_id.slice(0, 8)}</span>
            <span className="text-muted">{r.reason}</span>
            <span className="text-xs text-muted">{r.state} · expires {fmtTime(r.expires_at)}</span>
            {r.contested_at && <span className="text-xs text-warn">contested {fmtTime(r.contested_at)}{r.host_confirmed_at ? " · host confirmed" : " · needs host confirmation"}</span>}
            {r.state === "pending" && !r.subject_is_you && (
              <button onClick={() => approve(r)} className="ml-auto rounded border border-line px-2 py-0.5 text-xs">Approve 🔑</button>
            )}
            {r.subject_is_you && <span className="ml-auto text-xs text-muted">another owner must approve</span>}
            <button onClick={() => cancel(r)} className="rounded border border-line px-2 py-0.5 text-xs">{r.subject_is_you ? "Object 🔑" : "Cancel 🔑"}</button>
          </li>
        ))}
      </ul>
      {link && (
        <div className="mt-3 rounded border border-warn/50 p-3 text-sm">
          <p className="font-medium">One-time enrolment link (shown once, valid 30 minutes):</p>
          <code className="mt-1 block break-all text-xs">{link}</code>
        </div>
      )}
      {msg && <p role="alert" className="mt-3 text-sm text-danger">{msg}</p>}
    </section>
  );
}
