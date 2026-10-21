"use client";
import { useState } from "react";
import { ERROR_TEXT, postJson, stepUp } from "@/src/ui/http";
import type { Transition as T } from "@/src/server/services/console";
const REASONS = ["owner_request", "abuse", "security", "notice", "test", "other"];

export function TransitionPanel({ tenantId, role, csrf, transitions }: { tenantId: string; role: string; csrf: string; transitions: T[] }) {
  const [sel, setSel] = useState<T | null>(null);
  const [reason, setReason] = useState("test");
  const [note, setNote] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit() {
    if (!sel) return;
    setBusy(true);
    setMsg(null);
    const requestId = crypto.randomUUID(); // one id per intent: a retry of this submit has no second effect
    const body = { to: sel.to, reasonCode: sel.requires_reason ? reason : null, note: sel.requires_reason ? note : null, requestId };
    let r = await postJson(`/api/tenants/${tenantId}/transition`, body, csrf);
    if (!r.ok && r.error === "STEPUP_REQUIRED") {
      if (await stepUp(csrf, "tenant_transition", `${tenantId}:${sel.to}`)) r = await postJson(`/api/tenants/${tenantId}/transition`, body, csrf);
    }
    setBusy(false);
    if (r.ok) window.location.reload();
    else setMsg(ERROR_TEXT[String(r.error)] ?? "The action was refused.");
  }

  return (
    <section className="rounded-lg border border-line bg-panel p-4">
      <h2 className="text-sm font-medium">Lifecycle actions</h2>
      <p className="mt-1 text-xs text-muted">Changes this synthetic record only. The database enforces role, step-up and reason rules and audits every attempt.</p>
      <div className="mt-3 flex flex-wrap gap-2">
        {transitions.length === 0 && <span className="text-sm text-muted">No transitions from this state.</span>}
        {transitions.map((t) => {
          const roleOk = t.allowed_roles.includes(role);
          return (
            <button
              key={t.to}
              onClick={() => { setSel(t); setMsg(null); }}
              disabled={!t.available || !roleOk}
              title={!t.available ? "Needs POS integration" : !roleOk ? `Requires ${t.allowed_roles.join(" or ")}` : ""}
              className={`rounded border px-2.5 py-1 text-sm disabled:opacity-40 ${sel?.to === t.to ? "border-ink" : "border-line"}`}
            >
              → {t.to.replace("_", " ")}{t.requires_stepup && " 🔑"}
            </button>
          );
        })}
      </div>
      {sel && (
        <div className="mt-4 space-y-3 border-t border-line pt-4">
          {sel.requires_reason && (
            <>
              <label className="block text-sm">Reason
                <select value={reason} onChange={(e) => setReason(e.target.value)} className="mt-1 block w-full rounded border border-line bg-bg px-2 py-1.5">
                  {REASONS.map((r) => <option key={r} value={r}>{r}</option>)}
                </select>
              </label>
              <label className="block text-sm">Note (at least 10 characters)
                <textarea value={note} onChange={(e) => setNote(e.target.value)} maxLength={500} rows={2} className="mt-1 block w-full rounded border border-line bg-bg px-2 py-1.5" />
              </label>
            </>
          )}
          <button onClick={submit} disabled={busy} className="rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-white disabled:opacity-60 dark:text-black">
            {busy ? "Working…" : `Move to ${sel.to.replace("_", " ")}`}
          </button>
          {sel.requires_stepup && <p className="text-xs text-muted">You will confirm this one action with your passkey.</p>}
        </div>
      )}
      {msg && <p role="alert" className="mt-3 text-sm text-danger">{msg}</p>}
    </section>
  );
}
