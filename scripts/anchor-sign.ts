// OFFLINE audit anchoring (review HIGH-1). Run on the owner's own machine with an events export downloaded from
// the console (Audit -> Export events). It signs the current head ONLY IF the export is a valid chain from genesis
// that agrees with EVERY anchor already in the archive, so a compromised server cannot get rewritten history
// signed. The private key never touches the server.
//   npx tsx scripts/anchor-sign.ts --events events.json --archive <dir> --key anchor-key.pem
import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { anchorV2Message, ed25519Fingerprint, loadArchive, parseStrict, safe, verifyAnchorV2, verifyChain, type AnchorV2, type ExportedEvent } from "./verify-audit";

export function signAnchor(events: ExportedEvent[], archive: AnchorV2[], keyPem: string, signedAt = new Date().toISOString()):
  { ok: true; anchor: AnchorV2 } | { ok: false; reason: string } {
  const chain = verifyChain(events);
  if (!chain.ok) return chain;
  const priv = createPrivateKey(keyPem);
  const raw = Buffer.from(createPublicKey(priv).export({ format: "jwk" }).x!, "base64url");
  const fp = ed25519Fingerprint(raw);
  for (const a of archive) {
    const v = verifyAnchorV2(a, fp);
    if (!v.ok) return { ok: false, reason: `ARCHIVE_SEQ_${a.seq}_${v.reason}` };
    const row = chain.rows[a.seq];
    if (!row) return { ok: false, reason: `TRUNCATED_BELOW_ANCHOR_${a.seq}` };
    if (row.row_hash !== a.head_hash) return { ok: false, reason: `HISTORY_REWRITTEN_AT_${a.seq}` };
  }
  const head = chain.rows.at(-1);
  if (!head) return { ok: false, reason: "EMPTY_EXPORT" };
  const anchor: AnchorV2 = {
    format: "orvix-control/anchor/v2", seq: head.seq, head_hash: head.row_hash, signed_at: signedAt,
    public_key: raw.toString("base64url"),
    signature: sign(null, anchorV2Message(head.seq, head.row_hash, signedAt), priv).toString("base64url"),
  };
  return { ok: true, anchor };
}

// What the owner is about to vouch for: everything after the newest archived anchor (final review, audit M1).
// A compromised server can rewrite or drop UNANCHORED events before they are exported; the signer cannot detect
// that, so the owner must read this summary and confirm the head explicitly.
// Anything the server controls is printed escaped (shared printable-ASCII escaping, final review + 211 review).
export { safe } from "./verify-audit";

export function summarizeTail(events: ExportedEvent[], archive: AnchorV2[]) {
  const from = archive.length ? Math.max(...archive.map((a) => a.seq)) + 1 : 0;
  const tail = [...events].filter((e) => e.seq >= from).sort((a, b) => a.seq - b.seq);
  const sensitive = tail.filter((e) => e.outcome !== "success" || /credential|recovery|stepup|owner|operator|anchor|bootstrap|suppressed|watchdog|notify/.test(String(e.action)));
  const counts: Record<string, number> = {};
  for (const e of tail) counts[safe(e.action)] = (counts[safe(e.action)] ?? 0) + 1;
  return {
    from, to: tail.at(-1)?.seq ?? from - 1, head: String(tail.at(-1)?.row_hash ?? "").slice(0, 12), count: tail.length, counts,
    firstAt: tail[0] ? new Date(tail[0].occurred_at_us / 1000).toISOString() : null,
    lastAt: tail.at(-1) ? new Date(tail.at(-1)!.occurred_at_us / 1000).toISOString() : null,
    sensitive: sensitive.map((e) => `#${e.seq} ${safe(e.action)} ${safe(e.outcome)}${e.reason_code ? " " + safe(e.reason_code) : ""} by ${safe(e.actor_label ?? e.actor_type)}`),
  };
}

function arg(name: string) {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 ? process.argv[i + 1] : undefined;
}

if (process.argv[1]?.endsWith("anchor-sign.ts")) {
  try {
    const eventsFile = arg("events"); const dir = arg("archive"); const keyFile = arg("key"); const confirm = arg("confirm-head");
    if (!eventsFile || !dir || !keyFile) {
      console.error("usage: npx tsx scripts/anchor-sign.ts --events events.json --archive <dir> --key anchor-key.pem [--init] [--confirm-head <seq>:<hash prefix>]");
      process.exit(2);
    }
    const exported = parseStrict(readFileSync(eventsFile, "utf8")) as Record<string, any>;
    const events = (exported.events ?? exported) as ExportedEvent[];
    const archive = loadArchive(dir).v2;
    const keyPem = readFileSync(keyFile, "utf8");
    const fp = ed25519Fingerprint(Buffer.from(createPublicKey(createPrivateKey(keyPem)).export({ format: "jwk" }).x!, "base64url"));
    console.log(`anchor key fingerprint: ${fp}`);
    if (archive.length === 0 && !process.argv.includes("--init")) {
      console.error("REFUSED: the archive has no v2 anchor. The first anchor is trust-on-first-use: re-run with --init only if this is a fresh install and the export is from before any exposure.");
      process.exit(3);
    }
    const sum = summarizeTail(events, archive);
    console.log(`events since the newest anchor: #${sum.from}..#${sum.to} (${sum.count}), ${sum.firstAt ?? "-"} .. ${sum.lastAt ?? "-"}; head ${safe(sum.head)}`);
    for (const [k, n] of Object.entries(sum.counts).sort()) console.log(`  ${String(n).padStart(5)}  ${k}`);
    if (sum.sensitive.length) { console.log("sensitive events in this range:"); for (const l of sum.sensitive) console.log(`  ${l}`); }
    // binds the reviewed head: sequence number AND hash prefix (an export swapped between runs is not signed)
    if (confirm === undefined || confirm !== `${sum.to}:${sum.head}`) {
      console.error(`NOT SIGNED: review the summary above against what you know happened, then re-run with --confirm-head ${sum.to}:${safe(sum.head)}`);
      process.exit(3);
    }
    const r = signAnchor(events, archive, keyPem);
    if (!r.ok) { console.error(`REFUSED: ${safe(r.reason)}`); process.exit(1); }
    const out = path.join(dir, `anchor-v2-seq${String(r.anchor.seq).padStart(9, "0")}.json`);
    writeFileSync(out, JSON.stringify(r.anchor, null, 2), { flag: "wx" });
    console.log(`signed seq ${r.anchor.seq} (${r.anchor.head_hash.slice(0, 16)}); wrote ${out}. Keep the archive off the server.`);
  } catch (e) {
    console.error(`REFUSED: ${safe((e as Error).message)}`);
    process.exit(1);
  }
}
