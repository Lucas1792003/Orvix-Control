"use client";
import { useState } from "react";
import { startRegistration } from "@simplewebauthn/browser";
import { ERROR_TEXT, postJson, stepUp } from "@/src/ui/http";
import { fmtTime } from "@/src/ui/Status";

export type Cred = {
  id: string; nickname: string | null; created_via: string; created_at: string; last_used_at: string | null;
  disabled_at: string | null; disabled_reason: string | null; fingerprint: string; current: boolean;
  pending_until: string | null; counter_suspect_at: string | null;
};

export function PasskeyPanel({ csrf, identityId, credentials }: { csrf: string; identityId: string; credentials: Cred[] }) {
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [nick, setNick] = useState("");
  const active = credentials.filter((c) => !c.disabled_at);
  const usable = active.filter((c) => !c.pending_until);

  async function add() {
    setBusy(true); setMsg(null);
    try {
      if (!(await stepUp(csrf, "credential_add", identityId))) throw new Error("STEPUP_REQUIRED");
      const o = await postJson("/api/credentials/add/options", {}, csrf);
      if (!o.ok) throw new Error(String(o.error));
      const response = await startRegistration({ optionsJSON: o.options as never });
      const v = await postJson("/api/credentials/add/verify", { response, nickname: nick || null }, csrf);
      if (!v.ok) throw new Error(String(v.error));
      window.location.reload();
    } catch (e) {
      setMsg(ERROR_TEXT[(e as Error).message] ?? "Adding the passkey was cancelled or refused.");
      setBusy(false);
    }
  }

  async function revoke(c: Cred) {
    if (!window.confirm(`Revoke passkey ${c.nickname ?? c.fingerprint}? Sessions signed in with it end immediately.`)) return;
    setBusy(true); setMsg(null);
    if (!(await stepUp(csrf, "credential_revoke", c.id))) { setBusy(false); setMsg(ERROR_TEXT.STEPUP_REQUIRED!); return; }
    const r = await postJson(`/api/credentials/${c.id}/revoke`, {}, csrf);
    if (r.ok) window.location.assign(r.current_session_ended ? "/login" : "/security");
    else { setBusy(false); setMsg(ERROR_TEXT[String(r.error)] ?? "Revocation was refused."); }
  }

  return (
    <section className="rounded-lg border border-line bg-panel p-4">
      <h2 className="text-sm font-medium">Passkeys ({usable.length} usable{active.length > usable.length ? `, ${active.length - usable.length} pending` : ""})</h2>
      <p className="mt-1 text-xs text-muted">A newly added passkey is pending for 15 minutes before it can be used; every session sees it and can revoke it.</p>
      <ul className="mt-3 divide-y divide-line text-sm">
        {credentials.map((c) => (
          <li key={c.id} className="flex flex-wrap items-center gap-x-4 gap-y-1 py-2">
            <span className="font-medium">{c.nickname ?? "Passkey"}</span>
            <span className="font-mono text-xs text-muted">{c.fingerprint}</span>
            {c.current && <span className="rounded bg-accent/10 px-1.5 text-xs text-accent">this session</span>}
            {c.pending_until && <span className="rounded bg-danger/10 px-1.5 text-xs text-danger">pending until {fmtTime(c.pending_until)}</span>}
            {c.counter_suspect_at && <span className="rounded bg-warn/10 px-1.5 text-xs text-warn">flagged {fmtTime(c.counter_suspect_at)}</span>}
            <span className="text-xs text-muted">added {fmtTime(c.created_at)} · {c.created_via}</span>
            {c.last_used_at && <span className="text-xs text-muted">used {fmtTime(c.last_used_at)}</span>}
            {c.disabled_at ? (
              <span className="ml-auto text-xs text-danger">disabled ({c.disabled_reason})</span>
            ) : (
              <button onClick={() => revoke(c)} disabled={busy || (!c.pending_until && usable.length < 2)}
                title={!c.pending_until && usable.length < 2 ? "You cannot remove your last usable passkey" : ""}
                className="ml-auto rounded border border-line px-2 py-0.5 text-xs disabled:opacity-40">Revoke 🔑</button>
            )}
          </li>
        ))}
      </ul>
      <div className="mt-4 flex flex-wrap items-end gap-2 border-t border-line pt-4">
        <label className="text-sm">Name for the new passkey
          <input value={nick} onChange={(e) => setNick(e.target.value)} maxLength={60}
            className="mt-1 block rounded border border-line bg-bg px-2 py-1.5" placeholder="e.g. YubiKey (safe)" />
        </label>
        <button onClick={add} disabled={busy} className="rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-white disabled:opacity-60 dark:text-black">
          {busy ? "Working…" : "Add passkey 🔑"}
        </button>
      </div>
      {msg && <p role="alert" className="mt-3 text-sm text-danger">{msg}</p>}
    </section>
  );
}
