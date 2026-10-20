"use client";
import { useState } from "react";
import { startAuthentication } from "@simplewebauthn/browser";
import { ERROR_TEXT, downloadJson, postJson } from "@/src/ui/http";

export type Anchor = { id: number; seq: number; head_fingerprint: string; created_at: string; signed: boolean; signer: string | null };

export function AuditTools({ csrf, anchors }: { csrf: string; anchors: Anchor[] }) {
  const [msg, setMsg] = useState<{ tone: "ok" | "bad"; text: string } | null>(null);

  async function verify() {
    const r = await postJson("/api/audit/verify", {}, csrf);
    if (!r.ok) return setMsg({ tone: "bad", text: ERROR_TEXT[String(r.error)] ?? "Refused." });
    setMsg(r.intact
      ? { tone: "ok", text: `Chain intact: ${r.checked} events checked. Head #${r.head_seq} · ${r.head_fingerprint}` }
      : { tone: "bad", text: `CHAIN BROKEN at seq ${r.first_bad_seq ?? "?"}${r.bad_anchor_id ? `, anchor ${r.bad_anchor_id} mismatch` : ""}` });
  }

  // The passkey signs a challenge derived from (seq, head hash, nonce): the anchor is signed by the owner's key.
  async function sign() {
    try {
      const o = await postJson("/api/audit/anchor/options", {}, csrf);
      if (!o.ok) throw new Error(String(o.error));
      const response = await startAuthentication({ optionsJSON: o.options as never });
      const r = await postJson("/api/audit/anchor/verify", { response, note: "manual anchor" }, csrf);
      if (!r.ok) throw new Error(String(r.error));
      window.location.reload();
    } catch (e) {
      setMsg({ tone: "bad", text: ERROR_TEXT[(e as Error).message] ?? "Signing was cancelled or refused." });
    }
  }

  async function exportAnchor(a: Anchor) {
    const r = await postJson(`/api/audit/anchor/${a.id}/export`, {}, csrf);
    if (!r.ok) return setMsg({ tone: "bad", text: "Export refused." });
    downloadJson(`orvix-anchor-${a.id}-seq${a.seq}.json`, r.bundle);
    setMsg({ tone: "ok", text: "Store this file OFF this machine. Verify later with scripts/verify-audit.ts --pin <your key fingerprint>." });
  }

  async function exportEvents() {
    const all: unknown[] = [];
    for (let from = 0; ; from += 5000) {
      const r = await postJson("/api/audit/export", { from, to: from + 4999 }, csrf);
      if (!r.ok) return setMsg({ tone: "bad", text: "Export refused." });
      all.push(...(r.events as unknown[]));
      if ((r.events as unknown[]).length < 5000) break;
    }
    downloadJson(`orvix-audit-events-0-${all.length - 1}.json`, { format: "orvix-control/audit-events/v1", events: all });
  }

  return (
    <div className="space-y-3 rounded-lg border border-line bg-panel p-4">
      <div className="flex flex-wrap items-center gap-3">
        <button onClick={verify} className="rounded border border-line px-3 py-1.5 text-sm hover:border-ink">Verify chain</button>
        <button onClick={sign} className="rounded border border-line px-3 py-1.5 text-sm hover:border-ink">Sign anchor with passkey 🔑</button>
        <button onClick={exportEvents} className="rounded border border-line px-3 py-1.5 text-sm hover:border-ink">Export events</button>
      </div>
      {anchors.length > 0 && (
        <ul className="divide-y divide-line text-sm">
          {anchors.slice(0, 5).map((a) => (
            <li key={a.id} className="flex flex-wrap items-center gap-3 py-1.5">
              <span className="font-mono text-xs">anchor {a.id} · seq {a.seq} · {a.head_fingerprint}</span>
              <span className="text-xs text-muted">{a.signed ? `signed by ${a.signer}` : "unsigned (legacy)"}</span>
              {a.signed && <button onClick={() => exportAnchor(a)} className="ml-auto rounded border border-line px-2 py-0.5 text-xs">Export bundle</button>}
            </li>
          ))}
        </ul>
      )}
      {msg && <p className={`text-sm ${msg.tone === "ok" ? "text-ok" : "text-danger"}`}>{msg.text}</p>}
    </div>
  );
}
