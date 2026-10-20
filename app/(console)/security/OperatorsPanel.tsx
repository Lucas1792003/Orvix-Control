"use client";
import { useState } from "react";
import { ERROR_TEXT, postJson, stepUp } from "@/src/ui/http";
import { fmtTime } from "@/src/ui/Status";

export type Operator = { id: string; email: string; display_name: string; role: string; state: string; you: boolean; usable_passkeys: number };
export type Invitation = { id: string; email: string; role: string; state: string; created_at: string; expires_at: string; fingerprint: string | null };

async function sha256Hex(s: string) {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// Invitations (215): owner + step-up bound to the role and email; activation is HOST-only after the invitee enrols
// and the out-of-band notice is delivered. The link is shown once.
export function OperatorsPanel({ csrf, operators, invitations }: { csrf: string; operators: Operator[]; invitations: Invitation[] }) {
  const [email, setEmail] = useState(""); const [name, setName] = useState(""); const [role, setRole] = useState<"owner" | "admin">("owner");
  const [link, setLink] = useState<string | null>(null); const [msg, setMsg] = useState<string | null>(null); const [busy, setBusy] = useState(false);

  async function invite() {
    setBusy(true); setMsg(null); setLink(null);
    const e = email.trim().toLowerCase();
    if (!(await stepUp(csrf, "operator_invite", `${role}:${await sha256Hex(e)}`))) { setBusy(false); return setMsg(ERROR_TEXT.STEPUP_REQUIRED!); }
    const r = await postJson("/api/operators/invite", { email: e, displayName: name, role }, csrf);
    setBusy(false);
    if (!r.ok) return setMsg(ERROR_TEXT[String(r.error)] ?? "The invitation was refused.");
    setLink(`${window.location.origin}/enroll/${r.enrolment_token}`);
  }

  async function revoke(inv: Invitation) {
    if (!window.confirm(`Revoke the invitation for ${inv.email}?`)) return;
    if (!(await stepUp(csrf, "operator_invite", `revoke:${inv.id}`))) return setMsg(ERROR_TEXT.STEPUP_REQUIRED!);
    const r = await postJson(`/api/operators/invitations/${inv.id}/revoke`, {}, csrf);
    if (r.ok) window.location.reload(); else setMsg(ERROR_TEXT[String(r.error)] ?? "Revocation was refused.");
  }

  return (
    <section className="rounded-lg border border-line bg-panel p-4">
      <h2 className="text-sm font-medium">Operators</h2>
      <ul className="mt-2 divide-y divide-line text-sm">
        {operators.map((o) => (
          <li key={o.id} className="flex flex-wrap gap-3 py-1.5">
            <span className="font-medium">{o.display_name}</span><span className="font-mono text-xs text-muted">{o.email}</span>
            <span className="text-xs">{o.role}</span><span className="text-xs text-muted">{o.state} · {o.usable_passkeys} usable passkey(s)</span>
            {o.you && <span className="text-xs text-accent">you</span>}
          </li>
        ))}
      </ul>
      {invitations.length > 0 && (
        <ul className="mt-3 divide-y divide-line text-sm">
          {invitations.map((v) => (
            <li key={v.id} className="flex flex-wrap items-center gap-3 py-1.5">
              <span className="font-mono text-xs">{v.email}</span><span className="text-xs">{v.role}</span>
              <span className="text-xs text-muted">{v.state} · expires {fmtTime(v.expires_at)}</span>
              {v.fingerprint && <span className="text-xs">passkey fingerprint <span className="font-mono">{v.fingerprint}</span> · awaiting host approval</span>}
              <button onClick={() => revoke(v)} className="ml-auto rounded border border-line px-2 py-0.5 text-xs">Revoke 🔑</button>
            </li>
          ))}
        </ul>
      )}
      <div className="mt-4 flex flex-wrap items-end gap-2 border-t border-line pt-4 text-sm">
        <label>Email<input value={email} onChange={(e) => setEmail(e.target.value)} className="mt-1 block rounded border border-line bg-bg px-2 py-1.5" /></label>
        <label>Name<input value={name} onChange={(e) => setName(e.target.value)} maxLength={80} className="mt-1 block rounded border border-line bg-bg px-2 py-1.5" /></label>
        <label>Role<select value={role} onChange={(e) => setRole(e.target.value as "owner" | "admin")} className="mt-1 block rounded border border-line bg-bg px-2 py-1.5">
          <option value="owner">owner</option><option value="admin">admin</option></select></label>
        <button onClick={invite} disabled={busy} className="rounded-md bg-accent px-3 py-1.5 font-medium text-white disabled:opacity-60 dark:text-black">Invite 🔑</button>
      </div>
      <p className="mt-2 text-xs text-muted">The invitee registers a passkey with the one-time link (48 h). The host then activates them with
        <code className="mx-1">npm run host -- approve-operator</code> after checking the fingerprint with them out of band. Every step is notified out of band.</p>
      {link && <div className="mt-3 rounded border border-warn/50 p-3 text-sm"><p className="font-medium">One-time enrolment link (shown once):</p><code className="mt-1 block break-all text-xs">{link}</code></div>}
      {msg && <p role="alert" className="mt-3 text-sm text-danger">{msg}</p>}
    </section>
  );
}
