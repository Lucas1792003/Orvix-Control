// Differential tests: the in-database ES256 verifier (204) must agree with Node/OpenSSL.
import { createSign, createVerify, generateKeyPairSync, randomBytes, type KeyObject } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { isoCBOR } from "@simplewebauthn/server/helpers";
import { createTestDb, type TestDb } from "../helpers/db";

const N = BigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551");
let db: TestDb;
beforeAll(async () => { db = await createTestDb({ seed: false }); });
afterAll(async () => { await db?.drop(); });

function keypair() {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" });
  const cose = Buffer.from(isoCBOR.encode(new Map<number, number | Uint8Array>([
    [1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x!, "base64url")], [-3, Buffer.from(jwk.y!, "base64url")],
  ])));
  return { privateKey, publicKey, cose };
}
const sign = (k: KeyObject, msg: Buffer) => createSign("SHA256").update(msg).sign(k);
const nodeVerify = (k: KeyObject, msg: Buffer, sig: Buffer) => {
  try { return createVerify("SHA256").update(msg).verify(k, sig); } catch { return false; }
};
const dbVerify = async (cose: Buffer, msg: Buffer, sig: Buffer) =>
  (await db.su.query("SELECT control.es256_verify($1, $2, $3) AS v", [cose, msg, sig])).rows[0].v as boolean;

function derInt(v: bigint) {
  let h = v.toString(16); if (h.length % 2) h = "0" + h;
  let b = Buffer.from(h, "hex"); if (b[0]! & 0x80) b = Buffer.concat([Buffer.from([0]), b]);
  return Buffer.concat([Buffer.from([2, b.length]), b]);
}
const der = (r: bigint, s: bigint) => { const body = Buffer.concat([derInt(r), derInt(s)]); return Buffer.concat([Buffer.from([0x30, body.length]), body]); };
function parseDer(sig: Buffer) {
  const rl = sig[3]!; const r = BigInt("0x" + sig.subarray(4, 4 + rl).toString("hex"));
  const sl = sig[5 + rl]!; const s = BigInt("0x" + sig.subarray(6 + rl, 6 + rl + sl).toString("hex"));
  return { r, s };
}

describe("ES256 verifier agrees with OpenSSL", () => {
  it("accepts 40 random valid signatures (different keys, messages)", async () => {
    for (let i = 0; i < 40; i++) {
      const k = keypair(); const msg = randomBytes(1 + (i * 37) % 300); const sig = sign(k.privateKey, msg);
      expect(nodeVerify(k.publicKey, msg, sig)).toBe(true);
      expect(await dbVerify(k.cose, msg, sig), `vector ${i}`).toBe(true);
    }
  }, 120_000);

  it("rejects tampered message, signature bits, wrong key", async () => {
    const k = keypair(); const k2 = keypair(); const msg = randomBytes(64); const sig = sign(k.privateKey, msg);
    const msg2 = Buffer.from(msg); msg2[5]! ^= 1;
    expect(await dbVerify(k.cose, msg2, sig)).toBe(false);
    expect(await dbVerify(k2.cose, msg, sig)).toBe(false);
    const { r, s } = parseDer(sig);
    for (const [rr, ss] of [[r + 1n, s], [r, s + 1n], [r ^ 1n, s], [s, r]] as const) {
      if (rr >= N || ss >= N) continue;
      const forged = der(rr, ss);
      expect(await dbVerify(k.cose, msg, forged)).toBe(nodeVerify(k.publicKey, msg, forged));
      expect(await dbVerify(k.cose, msg, forged)).toBe(false);
    }
  }, 60_000);

  it("agrees on the malleable high-S twin (both accept; replay is stopped by single-use challenges)", async () => {
    const k = keypair(); const msg = randomBytes(32); const { r, s } = parseDer(sign(k.privateKey, msg));
    const twin = der(r, N - s);
    expect(nodeVerify(k.publicKey, msg, twin)).toBe(true);
    expect(await dbVerify(k.cose, msg, twin)).toBe(true);
  });

  it("rejects out-of-range scalars r,s in {0, n, n+1} and malformed DER", async () => {
    const k = keypair(); const msg = randomBytes(32); const sig = sign(k.privateKey, msg); const { r, s } = parseDer(sig);
    for (const [rr, ss] of [[0n, s], [r, 0n], [N, s], [r, N], [r + N, s], [r, s + N]] as const) {
      expect(await dbVerify(k.cose, msg, der(rr, ss))).toBe(false);
    }
    const bad: Buffer[] = [
      Buffer.alloc(0), Buffer.from([0x30, 0]), Buffer.concat([sig, Buffer.from([0])]),       // empty, trailing byte
      Buffer.from(sig).fill(0x31, 0, 1),                                                     // wrong tag
      (() => { const b = Buffer.from(sig); b[1] = b[1]! + 1; return b; })(),                 // wrong length
      Buffer.concat([Buffer.from([0x30, sig.length + 1 - 2 + 1]), Buffer.from([2, sig[3]! + 1, 0]), sig.subarray(4)]), // non-minimal
    ];
    for (const b of bad) expect(await dbVerify(k.cose, msg, b)).toBe(false);
  });

  it("rejects non-canonical, wrong-algorithm and off-curve COSE keys", async () => {
    const k = keypair(); const msg = randomBytes(32); const sig = sign(k.privateKey, msg);
    const offCurve = Buffer.from(k.cose); offCurve[76]! ^= 1;
    const rs256 = Buffer.from(k.cose); rs256[4] = 0x39; // alg -> not -7
    const reordered = Buffer.from(isoCBOR.encode(new Map<number, number | Uint8Array>([
      [3, -7], [1, 2], [-1, 1], [-2, k.cose.subarray(10, 42)], [-3, k.cose.subarray(45, 77)],
    ])));
    for (const c of [offCurve, rs256, reordered, k.cose.subarray(0, 76), Buffer.concat([k.cose, Buffer.from([0])])]) {
      expect(await dbVerify(Buffer.from(c), msg, sig)).toBe(false);
    }
  });

  it("verification time is bounded (records the cost)", async () => {
    const k = keypair(); const msg = randomBytes(200); const sig = sign(k.privateKey, msg);
    const t0 = performance.now();
    for (let i = 0; i < 5; i++) await dbVerify(k.cose, msg, sig);
    const ms = (performance.now() - t0) / 5;
    console.log(`in-DB ES256 verify: ${ms.toFixed(1)} ms/op`);
    expect(ms).toBeLessThan(2000);
  });

  it("base64url helpers round-trip and reject non-base64url", async () => {
    for (let i = 0; i < 20; i++) {
      const b = randomBytes(i * 3 + 1);
      const { rows } = await db.su.query("SELECT control.b64url_encode($1) e, control.b64url_decode(control.b64url_encode($1)) d", [b]);
      expect(rows[0].e).toBe(b.toString("base64url"));
      expect(Buffer.compare(rows[0].d, b)).toBe(0);
    }
    for (const bad of ["a+b", "ab/c", "abc=", "a"]) {
      expect((await db.su.query("SELECT control.b64url_decode($1) d", [bad])).rows[0].d).toBeNull();
    }
  });
});
