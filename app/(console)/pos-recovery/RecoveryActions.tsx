"use client";
import { useState } from "react";
import { ERROR_TEXT, postJson, sha256Hex, stepUp } from "@/src/ui/http";

// Every action: one request id per intent (a retry has no second effect), then the database enforces role, step-up,
// input rules and audits the attempt; the POS decides. There is NO control for ACTIVE anywhere on this page.
const say = (r: { ok: boolean; error?: unknown }, fallback: string) => ERROR_TEXT[String(r.error)] ?? fallback;
const enc = encodeURIComponent;

// Step-up first only when the server asks for it (the grant is bound to this action and target, single use).
async function withStepUp(csrf: string, url: string, body: unknown, action: string, target: string) {
  let r = await postJson(url, body, csrf);
  if (!r.ok && r.error === "STEPUP_REQUIRED" && (await stepUp(csrf, action, target))) r = await postJson(url, body, csrf);
  return r;
}

const CONTAIN_STATES = [
  { to: "RECONCILING", label: "Start reconciliation", hint: "Freeze the incident and begin reconciliation (needed before any report or reopening)." },
  { to: "RESTRICTED", label: "Restrict", hint: "Restrict the organization while the incident is assessed." },
  { to: "QUARANTINED", label: "Quarantine", hint: "Quarantine the organization (strongest containment)." },
] as const;

export function ContainmentPanel({ org, state, csrf }: { org: string; state: string; csrf: string }) {
  const [to, setTo] = useState<(typeof CONTAIN_STATES)[number]["to"]>("RECONCILING");
  const [reason, setReason] = useState("");
  const [evidence, setEvidence] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function move() {
    setBusy(true); setMsg(null);
    const body = { to, reason, evidenceReference: evidence, requestId: crypto.randomUUID() };
    const r = await withStepUp(csrf, `/api/pos-recovery/orgs/${enc(org)}/transition`, body, "pos_recovery_transition", `${org}:${to}`);
    setBusy(false);
    if (r.ok) window.location.reload(); else setMsg(say(r, "The transition was refused."));
  }

  async function report() {
    setBusy(true); setMsg(null);
    const r = await postJson(`/api/pos-recovery/orgs/${enc(org)}/report`, { requestId: crypto.randomUUID() }, csrf);
    setBusy(false);
    if (r.ok) window.location.reload(); else setMsg(say(r, "The report was refused."));
  }

  return (
    <div className="rounded-lg border border-line bg-panel p-4 text-sm">
      <h3 className="text-sm font-medium">Containment and reconciliation</h3>
      <p className="mt-1 text-xs text-muted">Owner or admin, with a passkey step-up for this organization and state. Reopening (ACTIVE) is not available here: it needs an owner-signed authorization.</p>
      <div className="mt-3 flex flex-wrap gap-2">
        {CONTAIN_STATES.map((c) => (
          <button key={c.to} onClick={() => { setTo(c.to); setMsg(null); }} disabled={state === c.to} title={c.hint}
            className={`rounded border px-2.5 py-1 text-sm disabled:opacity-40 ${to === c.to ? "border-ink" : "border-line"}`}>
            {c.label} 🔑
          </button>
        ))}
      </div>
      <div className="mt-3 grid gap-3 sm:grid-cols-2">
        <label className="block">Reason (10–500 characters)
          <textarea value={reason} onChange={(e) => setReason(e.target.value)} maxLength={500} rows={2} className="mt-1 block w-full rounded border border-line bg-bg px-2 py-1.5" />
        </label>
        <label className="block">Evidence reference (incident ticket, evidence hash…)
          <input value={evidence} onChange={(e) => setEvidence(e.target.value)} maxLength={500} className="mt-1 block w-full rounded border border-line bg-bg px-2 py-1.5" />
        </label>
      </div>
      <div className="mt-3 flex flex-wrap gap-2">
        <button onClick={move} disabled={busy || state === to} className="rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-white disabled:opacity-60 dark:text-black">
          {busy ? "Working…" : `Move to ${to}`}
        </button>
        <button onClick={report} disabled={busy || state !== "RECONCILING"} title={state !== "RECONCILING" ? "Only while RECONCILING" : ""}
          className="rounded-md border border-line px-3 py-1.5 text-sm disabled:opacity-40">
          Record reconciliation report
        </button>
      </div>
      {msg && <p role="alert" className="mt-3 text-danger">{msg}</p>}
    </div>
  );
}

export function DeviceActions({ org, enrollmentId, state, csrf }: { org: string; enrollmentId: string; state: string; csrf: string }) {
  const [msg, setMsg] = useState<string | null>(null);
  async function act(action: "suspend" | "revoke") {
    const reason = window.prompt(`Reason to ${action} this till (10–300 characters):`);
    if (!reason) return;
    if (action === "revoke" && !window.confirm("Revoking is permanent for this key. Continue?")) return;
    setMsg(null);
    const r = await withStepUp(csrf, `/api/pos-recovery/orgs/${enc(org)}/devices/${enrollmentId}/contain`,
      { action, reason, requestId: crypto.randomUUID() }, "pos_recovery_contain", `${org}:${enrollmentId}:${action}`);
    if (r.ok) window.location.reload(); else setMsg(say(r, "Refused."));
  }
  return (
    <span className="inline-flex items-center gap-2">
      <button onClick={() => act("suspend")} disabled={state !== "ACTIVE"} className="rounded border border-line px-2 py-0.5 text-xs disabled:opacity-40">Suspend 🔑</button>
      <button onClick={() => act("revoke")} disabled={state === "REVOKED"} className="rounded border border-danger/40 px-2 py-0.5 text-xs text-danger disabled:opacity-40">Revoke 🔑</button>
      {msg && <span role="alert" className="text-xs text-danger">{msg}</span>}
    </span>
  );
}

// Transport only: the owner produced and signed this document offline. Control shows what it will carry, binds the
// step-up to the SHA-256 of the exact text, and forwards text + signature unchanged. The POS verifies the signature.
export function SubmitAuthorizationPanel({ role, csrf, ownerAuthority }: { role: string; csrf: string; ownerAuthority: boolean }) {
  const [auth, setAuth] = useState("");
  const [sig, setSig] = useState("");
  const [msg, setMsg] = useState<string | null>(null);
  const [done, setDone] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  let parsed: { purpose?: string; scope?: string } | null = null;
  try { const j = JSON.parse(auth); if (j && typeof j === "object") parsed = j; } catch { parsed = null; }
  const purpose = parsed?.purpose ?? null;
  const ownerOnly = purpose === "reopen-organization";

  async function submit() {
    if (!purpose) return setMsg("Paste the owner-signed authorization (JSON) exactly as produced.");
    setBusy(true); setMsg(null); setDone(null);
    const target = `${purpose}:${await sha256Hex(auth)}`;
    const r = await withStepUp(csrf, "/api/pos-recovery/submit", { authorization: auth, signature: sig.trim(), requestId: crypto.randomUUID() },
      "pos_recovery_submit", target);
    setBusy(false);
    if (r.ok) { setDone(`Accepted by the POS: ${String(r.outcome)}.`); setTimeout(() => window.location.reload(), 1200); }
    else setMsg(say(r, "The submission was refused."));
  }

  return (
    <div className="rounded-lg border border-line bg-panel p-4 text-sm">
      <h3 className="text-sm font-medium">Submit an owner-signed authorization</h3>
      <p className="mt-1 text-xs text-muted">
        enroll-device, device-reinstate or reopen-organization. Control never creates or signs these; it carries the text and
        hex signature to the POS verifier. A reopening (the only way back to ACTIVE) can be carried by an owner only.
      </p>
      {!ownerAuthority && <p className="mt-2 text-xs font-medium text-danger">BLOCKED for this organization: no owner authority. The POS will refuse any authorization for it.</p>}
      <label className="mt-3 block">Authorization (exact text)
        <textarea value={auth} onChange={(e) => setAuth(e.target.value)} rows={6} spellCheck={false} className="mt-1 block w-full rounded border border-line bg-bg px-2 py-1.5 font-mono text-xs" />
      </label>
      <label className="mt-2 block">Signature (hex)
        <input value={sig} onChange={(e) => setSig(e.target.value)} spellCheck={false} className="mt-1 block w-full rounded border border-line bg-bg px-2 py-1.5 font-mono text-xs" />
      </label>
      {auth && <p className="mt-2 text-xs text-muted">Purpose: <span className="font-mono">{purpose ?? "unreadable"}</span> · organization: <span className="font-mono">{parsed?.scope ?? "—"}</span></p>}
      {ownerOnly && role !== "owner" && <p className="mt-2 text-xs text-danger">Only an owner may carry a reopening.</p>}
      <button onClick={submit} disabled={busy || !auth || !sig || (ownerOnly && role !== "owner")}
        className="mt-3 rounded-md bg-accent px-3 py-1.5 text-sm font-medium text-white disabled:opacity-60 dark:text-black">
        {busy ? "Working…" : "Confirm with passkey and submit 🔑"}
      </button>
      {done && <p className="mt-3 text-ok">{done}</p>}
      {msg && <p role="alert" className="mt-3 text-danger">{msg}</p>}
    </div>
  );
}
