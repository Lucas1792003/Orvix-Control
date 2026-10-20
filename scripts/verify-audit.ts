// Offline verifier for Orvix Control audit evidence. No network, no database: Node/OpenSSL only.
//
//   npx tsx scripts/verify-audit.ts --events events.json --archive <dir> --anchor-key <fingerprint>
//        [--allow-unanchored-tail] [--pin <passkey fp> --origin <origin> --rp-id <rp>]   (v1 bundles only)
//
// TRUST MODEL (review HIGH-1). Two kinds of anchor bundle exist:
//  * v2 (AUTHORITATIVE): Ed25519 signature made OFFLINE by scripts/anchor-sign.ts with a key that never touches
//    the server. anchor-sign refuses to sign unless the export is continuous with EVERY bundle already in the
//    archive, so a compromised server cannot obtain a signature over rewritten history.
//  * v1 (passkey-signed, 206): convenience only. Any WebAuthn prompt can be turned into an anchor signature by a
//    compromised server, so a v1 bundle proves nothing about history written after a compromise. v1 bundles are
//    checked (if pins are given) but never make a run pass on their own.
// A run passes when: the export is a contiguous, internally consistent chain from genesis; EVERY bundle in the
// archive verifies and matches the export at its seq; at least one v2 bundle exists; and (unless
// --allow-unanchored-tail) no event follows the newest v2 anchor. Values shown come from the hashed canonical
// text; numbers that cannot be represented exactly are rejected.
import { createHash, createPublicKey, createVerify, verify as edVerify } from "node:crypto";
import { readdirSync, readFileSync } from "node:fs";
import path from "node:path";

export type AnchorBundle = {
  format: string;
  anchor: { id: number; seq: number; head_hash: string; nonce: string; created_at: string };
  signer: { identity_id: string; label: string; credential_id: string; public_key_cose: string; public_key_fingerprint: string };
  webauthn: { rp_id: string; origin: string; client_data_json: string; authenticator_data: string; signature: string };
};
export type AnchorV2 = {
  format: "orvix-control/anchor/v2";
  seq: number; head_hash: string; signed_at: string;
  public_key: string;      // raw 32-byte Ed25519 public key, base64url
  signature: string;       // Ed25519 over anchorV2Message(...), base64url
};
export type ExportedEvent = {
  seq: number; occurred_at_us: number; actor_type: string; actor_id: string | null; actor_label: string | null;
  action: string; outcome: string; target_type: string | null; target_id: string | null; request_id: string | null;
  reason_code: string | null; detail: unknown; prev_hash: string; row_hash: string; canonical: string;
};
export type VerifyResult =
  | { ok: true; checked: number; anchoredThrough: number; unanchoredTail: number; v1Checked: number; v2Checked: number }
  | { ok: false; reason: string };

const sha256 = (b: Buffer | string) => createHash("sha256").update(b).digest();
const b64u = (s: string) => Buffer.from(s, "base64url");

export const anchorV2Message = (seq: number, headHex: string, signedAt: string) =>
  Buffer.from(`orvix-control/anchor/v2|${seq}|${headHex}|${signedAt}`, "utf8");
export const ed25519Fingerprint = (rawPub: Buffer) => sha256(rawPub).toString("hex");

function stable(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(stable).join(",")}]`;
  if (v && typeof v === "object") {
    return `{${Object.keys(v as object).sort().map((k) => `${JSON.stringify(k)}:${stable((v as Record<string, unknown>)[k])}`).join(",")}}`;
  }
  return JSON.stringify(v);
}

// Parses the canonical text and REJECTS any number whose source text does not round-trip exactly (precision
// loss, 1.50 vs 1.5, exponents): what a reader sees must be exactly what was hashed.
function parseCanonical(text: string): unknown[] {
  let bad: string | null = null;
  let noSource = false;
  const v = JSON.parse(text, function (this: unknown, _k: string, value: unknown, ctx?: { source?: string }) {
    if (typeof value === "number") {
      if (ctx?.source === undefined) noSource = true;          // runtime lacks JSON source access: fail closed
      else if (String(value) !== ctx.source) bad = ctx.source;
    }
    return value;
  } as never);
  if (noSource) throw new Error("RUNTIME_LACKS_JSON_SOURCE_ACCESS (use Node >= 22)");
  if (bad !== null) throw new Error(`UNSAFE_NUMBER ${bad}`);
  if (!Array.isArray(v) || v.length !== 12) throw new Error("CANONICAL_SHAPE");
  return v;
}

// Re-serialises a value exactly as PostgreSQL renders jsonb as text: ", " and ": " separators, object keys ordered by
// UTF-8 byte length then bytes (duplicates impossible), and only " \ \b \f \n \r \t and other control
// characters escaped (\u00xx). The canonical text must be byte-identical to this: that rules out duplicate keys,
// alternative escapes, lone surrogates and alternative number forms (final review, audit L2/L3).
function pgString(str: string): string {
  let out = '"';
  for (const ch of str) {
    const c = ch.codePointAt(0)!;
    if (c >= 0xd800 && c <= 0xdfff) throw new Error("LONE_SURROGATE");
    if (ch === '"') out += '\\"';
    else if (ch === "\\") out += "\\\\";
    else if (ch === "\b") out += "\\b";
    else if (ch === "\f") out += "\\f";
    else if (ch === "\n") out += "\\n";
    else if (ch === "\r") out += "\\r";
    else if (ch === "\t") out += "\\t";
    else if (c < 0x20) out += "\\u" + c.toString(16).padStart(4, "0");
    else out += ch;
  }
  return out + '"';
}
export function pgJsonText(v: unknown): string {
  if (v === null) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") return String(v);
  if (typeof v === "string") return pgString(v);
  if (Array.isArray(v)) return `[${v.map(pgJsonText).join(", ")}]`;
  const keys = Object.keys(v as object).sort((a, b) => {
    const ba = Buffer.from(a, "utf8"), bb = Buffer.from(b, "utf8");
    return ba.length !== bb.length ? ba.length - bb.length : Buffer.compare(ba, bb);
  });
  return `{${keys.map((k) => `${pgString(k)}: ${pgJsonText((v as Record<string, unknown>)[k])}`).join(", ")}}`;
}

// Rejects any object with a duplicate key anywhere in a JSON text (JSON.parse silently keeps the last one, so a
// human reading the raw file could see a different value than the one verified). Minimal scanner over valid JSON.
export function assertNoDuplicateKeys(text: string): void {
  const stack: (Set<string> | null)[] = [];
  let i = 0;
  const expectKey: boolean[] = [];
  while (i < text.length) {
    const ch = text[i]!;
    if (ch === '"') {
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === "\\" ? 2 : 1;
      const raw = text.slice(i, j + 1);
      const top = stack.length - 1;
      if (top >= 0 && stack[top] && expectKey[top]) {
        const key = JSON.parse(raw) as string;
        if (stack[top]!.has(key)) throw new Error(`DUPLICATE_KEY ${JSON.stringify(key)}`);
        stack[top]!.add(key);
        expectKey[top] = false;
      }
      i = j + 1;
      continue;
    }
    if (ch === "{") { stack.push(new Set()); expectKey.push(true); }
    else if (ch === "[") { stack.push(null); expectKey.push(false); }
    else if (ch === "}" || ch === "]") { stack.pop(); expectKey.pop(); }
    else if (ch === "," && stack.length && stack[stack.length - 1]) expectKey[stack.length - 1] = true;
    i++;
  }
}

// Strict JSON parse for whole files: no duplicate keys, every number must round-trip exactly (fails closed without
// source access).
export function parseStrict(text: string): unknown {
  assertNoDuplicateKeys(text);
  let bad: string | null = null; let noSource = false;
  const v = JSON.parse(text, function (this: unknown, _k: string, value: unknown, ctx?: { source?: string }) {
    if (typeof value === "number") {
      if (ctx?.source === undefined) noSource = true;
      else if (String(value) !== ctx.source) bad = ctx.source;
    }
    return value;
  } as never);
  if (noSource) throw new Error("RUNTIME_LACKS_JSON_SOURCE_ACCESS (use Node >= 22)");
  if (bad !== null) throw new Error(`UNSAFE_NUMBER ${bad}`);
  return v;
}

// Terminal-safe text: everything outside printable ASCII is shown as \uXXXX (covers C0/C1, ESC, bidi controls,
// zero-width and line/paragraph separators, BOM, soft hyphen, tag characters). Used for every printed value.
export function safe(v: unknown): string {
  return Array.from(String(v ?? "")).map((ch) => {
    const c = ch.codePointAt(0)!;
    if (c >= 0x20 && c <= 0x7e && ch !== "\\") return ch;
    if (ch === "\\") return "\\\\";
    return c > 0xffff ? `\\u{${c.toString(16)}}` : `\\u${c.toString(16).padStart(4, "0")}`;
  }).join("");
}

export function anchorChallenge(seq: number, headHex: string, nonceHex: string): string {
  return sha256(`orvix-control/anchor/v1|${seq}|${headHex}|${nonceHex}`).toString("base64url");
}

function coseToKey(cose: Buffer) {
  if (cose.length !== 77 || !cose.subarray(0, 10).equals(Buffer.from("a5010203262001215820", "hex"))
      || !cose.subarray(42, 45).equals(Buffer.from("225820", "hex"))) throw new Error("public key is not canonical COSE ES256");
  return createPublicKey({ key: { kty: "EC", crv: "P-256", x: cose.subarray(10, 42).toString("base64url"), y: cose.subarray(45, 77).toString("base64url") }, format: "jwk" });
}

// v1: passkey-signed (206). Requires explicit pins for key, origin and RP ID. Unsigned metadata (id, created_at,
// signer label/identity) is NOT authenticated and is ignored.
export function verifyAnchorBundle(b: AnchorBundle, pins: { pin?: string; origin?: string; rpId?: string } = {}):
  { ok: true } | { ok: false; reason: string } {
  try {
    if (b.format !== "orvix-control/anchor-bundle/v1") return { ok: false, reason: "UNKNOWN_FORMAT" };
    if (!pins.pin || !pins.origin || !pins.rpId) return { ok: false, reason: "V1_REQUIRES_PIN_ORIGIN_RPID" };
    if (!/^[0-9a-f]{64}$/.test(b.anchor.head_hash) || !/^[0-9a-f]{32}$/.test(b.anchor.nonce)) return { ok: false, reason: "BAD_ANCHOR_FIELDS" };
    const cose = b64u(b.signer.public_key_cose);
    if (sha256(cose).toString("hex") !== pins.pin.toLowerCase()) return { ok: false, reason: "PINNED_KEY_MISMATCH" };
    const cdjRaw = b64u(b.webauthn.client_data_json);
    const cdj = JSON.parse(cdjRaw.toString("utf8"));
    if (cdj.type !== "webauthn.get") return { ok: false, reason: "BAD_CLIENT_DATA_TYPE" };
    if (cdj.origin !== pins.origin) return { ok: false, reason: "ORIGIN_MISMATCH" };
    if (cdj.crossOrigin !== undefined && cdj.crossOrigin !== false) return { ok: false, reason: "CROSS_ORIGIN" };
    if ("topOrigin" in cdj) return { ok: false, reason: "TOP_ORIGIN" };
    if (cdj.challenge !== anchorChallenge(b.anchor.seq, b.anchor.head_hash, b.anchor.nonce)) return { ok: false, reason: "CHALLENGE_NOT_BOUND_TO_ANCHOR" };
    const ad = b64u(b.webauthn.authenticator_data);
    if (ad.length < 37 || !ad.subarray(0, 32).equals(sha256(pins.rpId))) return { ok: false, reason: "RP_ID_MISMATCH" };
    if ((ad[32]! & 0x05) !== 0x05) return { ok: false, reason: "USER_NOT_VERIFIED" };
    if (!createVerify("SHA256").update(Buffer.concat([ad, sha256(cdjRaw)])).verify(coseToKey(cose), b64u(b.webauthn.signature))) {
      return { ok: false, reason: "SIGNATURE_INVALID" };
    }
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: `MALFORMED: ${(e as Error).message}` };
  }
}

// v2: offline Ed25519.
export function verifyAnchorV2(a: AnchorV2, anchorKeyFingerprint: string): { ok: true } | { ok: false; reason: string } {
  try {
    if (a.format !== "orvix-control/anchor/v2") return { ok: false, reason: "UNKNOWN_FORMAT" };
    if (!Number.isSafeInteger(a.seq) || a.seq < 0 || !/^[0-9a-f]{64}$/.test(a.head_hash)) return { ok: false, reason: "BAD_ANCHOR_FIELDS" };
    const raw = b64u(a.public_key);
    if (raw.length !== 32) return { ok: false, reason: "BAD_PUBLIC_KEY" };
    if (ed25519Fingerprint(raw) !== anchorKeyFingerprint.toLowerCase()) return { ok: false, reason: "PINNED_KEY_MISMATCH" };
    const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: a.public_key }, format: "jwk" });
    if (!edVerify(null, anchorV2Message(a.seq, a.head_hash, a.signed_at), key, b64u(a.signature))) return { ok: false, reason: "SIGNATURE_INVALID" };
    return { ok: true };
  } catch (e) {
    return { ok: false, reason: `MALFORMED: ${(e as Error).message}` };
  }
}

// Chain check from genesis. Returns the rows (ordered) or a failure.
export function verifyChain(events: ExportedEvent[]): { ok: true; rows: ExportedEvent[] } | { ok: false; reason: string } {
  try {
    const rows = [...events].sort((a, b) => a.seq - b.seq);
    let prev = Buffer.alloc(32);
    for (let i = 0; i < rows.length; i++) {
      const r = rows[i]!;
      if (r.seq !== i) return { ok: false, reason: `GAP_OR_START_AT_${i}` };
      const c = parseCanonical(r.canonical);
      if (pgJsonText(c) !== r.canonical) return { ok: false, reason: `NONCANONICAL_TEXT_AT_${r.seq}` };
      const expected = [r.seq, r.occurred_at_us, r.actor_type, r.actor_id, r.actor_label, r.action, r.outcome,
                        r.target_type, r.target_id, r.request_id, r.reason_code, r.detail ?? {}];
      if (stable(c) !== stable(expected)) return { ok: false, reason: `CANONICAL_MISMATCH_AT_${r.seq}` };
      if (r.prev_hash !== prev.toString("hex")) return { ok: false, reason: `PREV_HASH_MISMATCH_AT_${r.seq}` };
      const h = sha256(Buffer.concat([prev, Buffer.from(r.canonical, "utf8")]));
      if (h.toString("hex") !== r.row_hash) return { ok: false, reason: `ROW_HASH_MISMATCH_AT_${r.seq}` };
      prev = h;
    }
    return { ok: true, rows };
  } catch (e) {
    return { ok: false, reason: `MALFORMED: ${(e as Error).message}` };
  }
}

export type Archive = { v1: AnchorBundle[]; v2: AnchorV2[] };

export function verifyArchive(events: ExportedEvent[], archive: Archive,
  opts: { anchorKey: string; pin?: string; origin?: string; rpId?: string; allowUnanchoredTail?: boolean }): VerifyResult {
  const chain = verifyChain(events);
  if (!chain.ok) return chain;
  const rows = chain.rows;
  if (archive.v2.length === 0) return { ok: false, reason: "NO_V2_ANCHOR" };
  for (const a of archive.v2) {
    const v = verifyAnchorV2(a, opts.anchorKey);
    if (!v.ok) return { ok: false, reason: `V2_SEQ_${a.seq}_${v.reason}` };
    if (!rows[a.seq]) return { ok: false, reason: `ANCHORED_SEQ_MISSING_${a.seq}` };
    if (rows[a.seq]!.row_hash !== a.head_hash) return { ok: false, reason: `ANCHORED_HEAD_MISMATCH_${a.seq}` };
  }
  for (const b of archive.v1) {
    const v = verifyAnchorBundle(b, opts);
    if (!v.ok) return { ok: false, reason: `V1_SEQ_${b.anchor.seq}_${v.reason}` };
    if (!rows[b.anchor.seq] || rows[b.anchor.seq]!.row_hash !== b.anchor.head_hash) return { ok: false, reason: `V1_ANCHORED_HEAD_MISMATCH_${b.anchor.seq}` };
  }
  const anchoredThrough = Math.max(...archive.v2.map((a) => a.seq));
  const tail = rows.length - 1 - anchoredThrough;
  if (tail > 0 && !opts.allowUnanchoredTail) return { ok: false, reason: `UNANCHORED_TAIL_${tail}` };
  return { ok: true, checked: anchoredThrough + 1, anchoredThrough, unanchoredTail: Math.max(0, tail), v1Checked: archive.v1.length, v2Checked: archive.v2.length };
}

export function loadArchive(dir: string): Archive {
  const out: Archive = { v1: [], v2: [] };
  const seen = new Set<number>();
  for (const f of readdirSync(dir).filter((x) => !x.startsWith(".")).sort()) {
    if (!/^[A-Za-z0-9._-]+\.json$/.test(f)) throw new Error(`unexpected file in archive: ${f}`);
    const j = parseStrict(readFileSync(path.join(dir, f), "utf8")) as Record<string, any>;
    const b = j.bundle ?? j;
    if (b.format === "orvix-control/anchor/v2") {
      if (seen.has(b.seq)) throw new Error(`duplicate v2 anchor for seq ${b.seq}: ${f}`);
      seen.add(b.seq);
      out.v2.push(b);
    }
    else if (b.format === "orvix-control/anchor-bundle/v1") out.v1.push(b);
    else throw new Error(`unknown file in archive: ${f}`);
  }
  return out;
}

function arg(name: string) {
  const i = process.argv.indexOf(`--${name}`);
  return i > 0 ? process.argv[i + 1] : undefined;
}

if (process.argv[1]?.endsWith("verify-audit.ts")) {
  const eventsFile = arg("events"); const dir = arg("archive"); const anchorKey = arg("anchor-key");
  if (!eventsFile || !dir || !anchorKey) {
    console.error("usage: npx tsx scripts/verify-audit.ts --events events.json --archive <dir> --anchor-key <fingerprint> [--allow-unanchored-tail] [--pin <fp> --origin <o> --rp-id <rp>]");
    process.exit(2);
  }
  try {
    const exported = parseStrict(readFileSync(eventsFile, "utf8")) as Record<string, any>;
    const r = verifyArchive(exported.events ?? exported, loadArchive(dir), {
      anchorKey, pin: arg("pin"), origin: arg("origin"), rpId: arg("rp-id"), allowUnanchoredTail: process.argv.includes("--allow-unanchored-tail"),
    });
    if (r.ok) {
      console.log(`OK: events 0..${r.anchoredThrough} verified against ${r.v2Checked} offline anchor(s)` +
        (r.v1Checked ? ` and ${r.v1Checked} passkey bundle(s)` : "") +
        (r.unanchoredTail ? `; WARNING ${r.unanchoredTail} later event(s) are chain-consistent but NOT anchored` : "") + ".");
    } else {
      console.error(`FAIL: ${safe(r.reason)}`);
      process.exit(1);
    }
  } catch (e) {
    console.error(`FAIL: ${safe((e as Error).message)}`);
    process.exit(1);
  }
}
