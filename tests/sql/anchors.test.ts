// Passkey-signed audit anchors and offline verification (scripts/verify-audit.ts, Node/OpenSSL only).
import { createHash } from "node:crypto";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  adminWithSession, assertionParts, createTestDb, exportAll, lastAudit, ownerWithSession, recomputeChainAsSuperuser,
  resetRateLimits, signAnchor, type Operator, type TestDb,
} from "../helpers/db";
import { SoftAuthenticator } from "../helpers/softAuthenticator";
import { generateKeyPairSync } from "node:crypto";
import {
  anchorChallenge, ed25519Fingerprint, verifyAnchorBundle, verifyArchive, verifyChain, type AnchorBundle, type AnchorV2,
} from "../../scripts/verify-audit";
import { safe, signAnchor as signOffline, summarizeTail } from "../../scripts/anchor-sign";
import { loadArchive, parseStrict, pgJsonText } from "../../scripts/verify-audit";
import { mkdtempSync, writeFileSync } from "node:fs";
import os from "node:os";
import path from "node:path";

const pinOf = (op: Operator) => createHash("sha256").update(op.auth.cosePublicKey).digest("hex");

describe("signing", () => {
  let db: TestDb; let owner: Operator; let admin: Operator;
  beforeAll(async () => { db = await createTestDb({ seed: true }); owner = await ownerWithSession(db); admin = await adminWithSession(db); });
  afterAll(async () => { await db?.drop(); });
  beforeEach(async () => { await resetRateLimits(db); });

  it("only an owner can sign anchors (refusal audited)", async () => {
    expect((await db.api("api_anchor_begin", admin.token)).error).toBe("FORBIDDEN");
    expect((await lastAudit(db))[0].action).toBe("audit.anchor_refused");
  });

  it("the challenge commits to (seq, head, nonce) and the anchor stores the full WebAuthn evidence", async () => {
    const b = await db.api("api_anchor_begin", owner.token);
    const expected = createHash("sha256").update(`orvix-control/anchor/v1|${b.seq}|${b.head_hash}|${b.nonce}`).digest("base64url");
    expect(b.challenge).toBe(expected);
    const a = assertionParts(owner.auth.assert({ challenge: b.challenge }));
    const r = await db.api("api_anchor_complete", owner.token, a.id, a.cdj, a.ad, a.sig, "first");
    expect(r).toMatchObject({ ok: true, seq: b.seq, head_hash: b.head_hash });
    const { rows } = await db.su.query("SELECT signature IS NOT NULL s, public_key IS NOT NULL k FROM control.audit_anchors WHERE id = $1", [r.anchor_id]);
    expect(rows[0]).toEqual({ s: true, k: true });
    // replaying the same assertion fails (single-use challenge)
    expect((await db.api("api_anchor_complete", owner.token, a.id, a.cdj, a.ad, a.sig, "again")).error).toBe("INVALID_CHALLENGE");
  });

  it("an anchor cannot be signed by a key that is not the owner's, nor via a login challenge", async () => {
    const b = await db.api("api_anchor_begin", owner.token);
    const forged = assertionParts(new SoftAuthenticator().assert({ challenge: b.challenge }));
    expect((await db.api("api_anchor_complete", owner.token, owner.auth.id, forged.cdj, forged.ad, forged.sig, "x")).error).toBe("SIGNATURE_INVALID");
    const lb = await db.api("api_login_begin");
    const l = assertionParts(owner.auth.assert({ challenge: lb.challenge }));
    expect((await db.api("api_anchor_complete", owner.token, l.id, l.cdj, l.ad, l.sig, "x")).error).toBe("INVALID_CHALLENGE");
  });

  it("the audit-owner insert path re-verifies the signature itself (defence in depth)", async () => {
    const b = await db.api("api_anchor_begin", owner.token);
    const a = assertionParts(owner.auth.assert({ challenge: b.challenge }));
    const err = await db.su.query(
      "SELECT control.audit_anchor_insert_signed($1, decode($2,'hex'), decode($3,'hex'), $4, 'x', $5, $6, $7, $8, $9, 'x')",
      [b.seq, b.head_hash, b.nonce, owner.identityId, a.id, owner.auth.cosePublicKey, a.cdj, a.ad, Buffer.from(a.sig).fill(1, 10, 12)]).catch((e) => e);
    expect(err.message).toMatch(/ANCHOR_SIGNATURE_INVALID/);
  });

  it("a change to the anchored row between begin and complete is caught (HEAD_CHANGED)", async () => {
    const b = await db.api("api_anchor_begin", owner.token);
    await recomputeChainAsSuperuser(db, `UPDATE control.audit_events SET detail = '{"x":1}' WHERE seq = ${b.seq}`);
    const a = assertionParts(owner.auth.assert({ challenge: b.challenge }));
    expect((await db.api("api_anchor_complete", owner.token, a.id, a.cdj, a.ad, a.sig, "x")).error).toBe("HEAD_CHANGED");
  });
});

// Offline Ed25519 anchor key held by the owner (never on the server).
function anchorKey() {
  const { privateKey, publicKey } = generateKeyPairSync("ed25519");
  const pem = privateKey.export({ type: "pkcs8", format: "pem" }).toString();
  const fp = ed25519Fingerprint(Buffer.from(publicKey.export({ format: "jwk" }).x!, "base64url"));
  return { pem, fp };
}
const V1 = (op: Operator) => ({ pin: pinOf(op), origin: "http://localhost:3410", rpId: "localhost" });

describe("offline anchors (v2, Ed25519, continuity-checked) and verification", () => {
  let db: TestDb; let owner: Operator; const key = anchorKey(); const archive: AnchorV2[] = [];
  beforeAll(async () => {
    db = await createTestDb({ seed: true });
    owner = await ownerWithSession(db);
    for (let i = 0; i < 4; i++) await db.api("api_tenant_list", owner.token);
    const s = signOffline(await exportAll(db, owner), archive, key.pem);
    expect(s.ok).toBe(true);
    if (s.ok) archive.push(s.anchor);
  });
  afterAll(async () => { await db?.drop(); });

  it("a genuine export verifies against the archive with the anchor key pinned", async () => {
    const events = await exportAll(db, owner);
    const r = verifyArchive(events, { v1: [], v2: archive }, { anchorKey: key.fp, allowUnanchoredTail: true });
    expect(r).toMatchObject({ ok: true, anchoredThrough: archive[0]!.seq });
  });

  it("events after the newest anchor fail by default and are never counted as verified", async () => {
    const events = await exportAll(db, owner);
    const strict = verifyArchive(events, { v1: [], v2: archive }, { anchorKey: key.fp });
    expect(strict.ok).toBe(false);
    if (!strict.ok) expect(strict.reason).toMatch(/^UNANCHORED_TAIL_\d+$/);
    const lax = verifyArchive(events, { v1: [], v2: archive }, { anchorKey: key.fp, allowUnanchoredTail: true });
    expect(lax.ok && lax.checked).toBe(archive[0]!.seq + 1);
    expect(lax.ok && lax.unanchoredTail).toBeGreaterThan(0);
  });

  it("the signer refuses to anchor rewritten history (continuity with every archived anchor)", async () => {
    const d = await createTestDb({ seed: true });
    try {
      const o = await ownerWithSession(d);
      const k = anchorKey(); const arch: AnchorV2[] = [];
      for (let i = 0; i < 3; i++) await d.api("api_tenant_list", o.token);
      const first = signOffline(await exportAll(d, o), arch, k.pem); expect(first.ok).toBe(true); if (first.ok) arch.push(first.anchor);
      await recomputeChainAsSuperuser(d, `UPDATE control.audit_events SET actor_label = 'rewritten' WHERE seq = 2`);
      await recomputeChainAsSuperuser(d, `DELETE FROM control.audit_anchors`);
      expect((await d.api("api_audit_verify", o.token)).intact).toBe(true);            // on-host check is blind
      const second = signOffline(await exportAll(d, o), arch, k.pem);                    // owner tries to anchor again
      expect(second).toEqual({ ok: false, reason: `HISTORY_REWRITTEN_AT_${arch[0]!.seq}` });
      const v = verifyArchive(await exportAll(d, o), { v1: [], v2: arch }, { anchorKey: k.fp, allowUnanchoredTail: true });
      expect(v).toEqual({ ok: false, reason: `ANCHORED_HEAD_MISMATCH_${arch[0]!.seq}` });
    } finally {
      await d.drop();
    }
  });

  it("truncation below an anchor is refused by the signer and the verifier", async () => {
    const events = (await exportAll(db, owner)).filter((e) => e.seq < archive[0]!.seq);
    expect(signOffline(events, archive, key.pem)).toEqual({ ok: false, reason: `TRUNCATED_BELOW_ANCHOR_${archive[0]!.seq}` });
    expect(verifyArchive(events, { v1: [], v2: archive }, { anchorKey: key.fp }).ok).toBe(false);
  });

  it("a v2 anchor signed by any other key, or altered, fails", async () => {
    const other = anchorKey();
    const forged = signOffline(await exportAll(db, owner), [], other.pem);
    expect(forged.ok).toBe(true);
    if (forged.ok) {
      expect(verifyArchive(await exportAll(db, owner), { v1: [], v2: [forged.anchor] }, { anchorKey: key.fp, allowUnanchoredTail: true }))
        .toMatchObject({ ok: false });
    }
    const altered = { ...archive[0]!, head_hash: "0".repeat(64) };
    expect(verifyArchive(await exportAll(db, owner), { v1: [], v2: [altered] }, { anchorKey: key.fp, allowUnanchoredTail: true }).ok).toBe(false);
  });

  it("an edited export field, and a number that cannot round-trip, are rejected", async () => {
    const events = await exportAll(db, owner);
    const e = events.find((x) => x.seq === 2)!; e.actor_label = "someone else";
    expect(verifyChain(events)).toEqual({ ok: false, reason: "CANONICAL_MISMATCH_AT_2" });
    // NEW-1: the database stores numbers that cannot round-trip as STRINGS, so a poisoned value cannot break the chain.
    const d = await createTestDb({ seed: false });
    try {
      const o = await ownerWithSession(d);
      await d.su.query(`SELECT control.audit_append('system', NULL, 'x', 'audit.verified', 'success', NULL, NULL, NULL, NULL,
                        '{"amount": 12345678901234567891, "ratio": 1.50, "ok": 42, "nested": [9007199254745989]}'::jsonb)`);
      const { rows } = await d.su.query("SELECT detail FROM control.audit_events ORDER BY seq DESC LIMIT 1");
      expect(rows[0].detail).toEqual({ amount: "12345678901234567891", ratio: "1.50", ok: 42, nested: ["9007199254745989"] });
      const events = await exportAll(d, o);
      expect(verifyChain(events).ok).toBe(true);
      // ...and the verifier itself still refuses canonical text whose numbers would not round-trip
      const forged = structuredClone(events);
      const last = forged.at(-1)!;
      last.canonical = last.canonical.replace('"amount": "12345678901234567891"', '"amount": 12345678901234567891');
      const r = verifyChain(forged);
      expect(r.ok).toBe(false);
      if (!r.ok) expect(r.reason).toMatch(/UNSAFE_NUMBER/);
    } finally {
      await d.drop();
    }
  });

  it("NEW-1: an export request with a huge range is clamped and cannot poison the chain", async () => {
    const r = await db.api("api_audit_export", owner.token, "9007199254740990", null);
    expect(r.ok).toBe(true);
    const ev = await exportAll(db, owner);
    expect(verifyChain(ev).ok).toBe(true);
    const row = (await db.su.query("SELECT detail FROM control.audit_events WHERE action = 'audit.exported' ORDER BY seq DESC LIMIT 1 OFFSET 1")).rows[0];
    expect(Number(row.detail.to)).toBeLessThan(1_000_000);
  });

  it("an archive with no offline (v2) anchor never passes, even with a valid passkey (v1) bundle", async () => {
    const s = await signAnchor(db, owner);
    const bundle = (await db.api("api_anchor_export", owner.token, s.anchor_id)).bundle as AnchorBundle;
    const events = await exportAll(db, owner);
    expect(verifyArchive(events, { v1: [bundle], v2: [] }, { anchorKey: key.fp, ...V1(owner), allowUnanchoredTail: true }))
      .toEqual({ ok: false, reason: "NO_V2_ANCHOR" });
    expect(verifyArchive(events, { v1: [bundle], v2: archive }, { anchorKey: key.fp, ...V1(owner), allowUnanchoredTail: true }))
      .toMatchObject({ ok: true, v1Checked: 1 });
  });

  it("HIGH-1 reproduced: a passkey assertion obtained through an ordinary prompt yields a valid v1 bundle over a FABRICATED head", async () => {
    // A compromised server serves anchor_challenge(seq, X, nonce) as a login challenge; the owner signs it.
    const fakeHead = "ab".repeat(32); const nonce = "cd".repeat(16);
    const a = owner.auth.assert({ challenge: anchorChallenge(5, fakeHead, nonce) });
    const forged: AnchorBundle = {
      format: "orvix-control/anchor-bundle/v1",
      anchor: { id: 99, seq: 5, head_hash: fakeHead, nonce, created_at: new Date().toISOString() },
      signer: { identity_id: owner.identityId, label: "x", credential_id: owner.auth.id,
                public_key_cose: owner.auth.cosePublicKey.toString("base64url"), public_key_fingerprint: pinOf(owner) },
      webauthn: { rp_id: "localhost", origin: "http://localhost:3410", client_data_json: a.response.clientDataJSON,
                  authenticator_data: a.response.authenticatorData, signature: a.response.signature },
    };
    expect(verifyAnchorBundle(forged, V1(owner))).toEqual({ ok: true });                  // v1 alone is forgeable...
    expect(verifyArchive(await exportAll(db, owner), { v1: [forged], v2: archive }, { anchorKey: key.fp, ...V1(owner), allowUnanchoredTail: true }).ok)
      .toBe(false);                                                                          // ...and is rejected against the real chain
  });

  it("v1 bundles require explicit pins for key, origin and RP ID", async () => {
    const s = await signAnchor(db, owner);
    const b = (await db.api("api_anchor_export", owner.token, s.anchor_id)).bundle as AnchorBundle;
    expect(verifyAnchorBundle(b)).toEqual({ ok: false, reason: "V1_REQUIRES_PIN_ORIGIN_RPID" });
    expect(verifyAnchorBundle(b, { ...V1(owner), origin: "https://evil.example" })).toEqual({ ok: false, reason: "ORIGIN_MISMATCH" });
    expect(verifyAnchorBundle(b, { ...V1(owner), rpId: "evil.example" })).toEqual({ ok: false, reason: "RP_ID_MISMATCH" });
    expect(verifyAnchorBundle(b, V1(owner))).toEqual({ ok: true });
  });

  it("export and anchor export are owner-only and audited", async () => {
    const admin = await adminWithSession(db);
    expect((await db.api("api_audit_export", admin.token, 0, 10)).error).toBe("FORBIDDEN");
    expect((await db.api("api_anchor_export", admin.token, 1)).error).toBe("FORBIDDEN");
    await db.api("api_audit_export", owner.token, 0, 1);
    expect((await lastAudit(db))[0].action).toBe("audit.exported");
  });
});

describe("final review: strict canonical text, archive loading, signer tail summary", () => {
  let d: TestDb; let o: Operator;
  beforeAll(async () => {
    d = await createTestDb({ seed: false });
    o = await ownerWithSession(d);
    await d.su.query(`SELECT control.audit_append('system', NULL, E'quote" back\\\\ tab\t', 'audit.verified', 'success', NULL, NULL, NULL, NULL,
      jsonb_build_object('bb', 1, 'a', E'\x01ctl', 'é', 'ü€😀', 'z', '/', 'n', jsonb_build_array(true, null, -5)))`);
  });
  afterAll(async () => { await d?.drop(); });

  it("the verifier's re-serialisation is byte-identical to PostgreSQL's canonical text for every row", async () => {
    const events = await exportAll(d, o);
    for (const e of events) expect(pgJsonText(JSON.parse(e.canonical)), `seq ${e.seq}`).toBe(e.canonical);
    expect(verifyChain(events).ok).toBe(true);
  });

  it("canonical text with a duplicate key, an alternative escape or an alternative number form is rejected", async () => {
    const events = await exportAll(d, o);
    const idx = events.findIndex((e) => (e.actor_label ?? "").startsWith("quote"));
    const last = events[idx]!;
    expect(last.canonical).toContain('"a": ');
    const variants = [
      last.canonical.replace('{"a": ', '{"a": "x", "a": '),          // duplicate key (last wins in JSON.parse)
      last.canonical.replace('"z": "/"', '"z": "\\/"'),              // \/ instead of /
      last.canonical.replace('-5', '-5.0'),                           // number form
    ];
    for (const v of variants) {
      expect(v).not.toBe(last.canonical);
      const r = verifyChain(events.map((e, i) => (i === idx ? { ...e, canonical: v } : e)));
      expect(r.ok, v).toBe(false);
    }
  });

  it("the archive loader rejects stray files and duplicate anchors, and ignores dotfiles", async () => {
    const dir = mkdtempSync(path.join(os.tmpdir(), "orvix-arch-"));
    const k = anchorKey();
    const s = signOffline(await exportAll(d, o), [], k.pem);
    expect(s.ok).toBe(true);
    if (!s.ok) return;
    writeFileSync(path.join(dir, "a.json"), JSON.stringify(s.anchor));
    writeFileSync(path.join(dir, ".DS_Store"), "x");
    expect(loadArchive(dir).v2).toHaveLength(1);
    writeFileSync(path.join(dir, "b.json"), JSON.stringify(s.anchor));
    expect(() => loadArchive(dir)).toThrow(/duplicate v2 anchor/);
    writeFileSync(path.join(dir, "b.json.bak"), "{}");
    expect(() => loadArchive(dir)).toThrow(/unexpected file|duplicate/);
  });

  it("the signer's tail summary lists everything since the newest anchor, with sensitive events called out", async () => {
    const events = await exportAll(d, o);
    const sum = summarizeTail(events, []);
    expect(sum.from).toBe(0);
    expect(sum.to).toBe(events.at(-1)!.seq);
    expect(sum.sensitive.some((l) => /owner_enrolled|bootstrap/.test(l))).toBe(true);
  });
});

describe("final review follow-ups (offline tools)", () => {
  it("export/archive files with a duplicate key anywhere are rejected", () => {
    expect(() => parseStrict('{"events":[{"detail":{"amount":999,"amount":1}}]}')).toThrow(/DUPLICATE_KEY/);
    expect(() => parseStrict('{"a":1,"a":2}')).toThrow(/DUPLICATE_KEY/);
    expect(() => parseStrict('{"a":{"x":1},"b":{"x":1},"s":"a\\"b","t":[{"k":1},{"k":2}]}')).not.toThrow();
  });

  it("the signer escapes control characters, ANSI sequences and bidi overrides before printing", () => {
    expect(safe("x\u001b[2K\r")).toBe("x\\u001b[2K\\r");
    expect(safe("a\u202eb")).toBe("a\\u202eb");
    expect(safe("plain owner")).toBe("plain owner");
  });
});
