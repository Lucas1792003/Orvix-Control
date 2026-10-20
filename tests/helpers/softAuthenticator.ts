// Software WebAuthn authenticator for tests: real P-256 keys, real CBOR attestation ("none"), real ECDSA
// assertions. Lets the e2e suite drive the actual @simplewebauthn verification in the running server.
import { createHash, createSign, generateKeyPairSync, randomBytes, type KeyObject } from "node:crypto";
import { isoCBOR } from "@simplewebauthn/server/helpers";

const b64u = (b: Uint8Array | Buffer) => Buffer.from(b).toString("base64url");
const sha256 = (b: Uint8Array | Buffer) => createHash("sha256").update(b).digest();

export type AssertOpts = { origin?: string; rpId?: string; uv?: boolean; counter?: number; tamper?: boolean; type?: string };

export class SoftAuthenticator {
  readonly credentialId = randomBytes(32);
  private readonly privateKey: KeyObject;
  private readonly cose: Uint8Array;
  counter = 0;
  userHandle: string | undefined;

  constructor(readonly origin = "http://localhost:3410", readonly rpId = "localhost") {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    this.privateKey = privateKey;
    const jwk = publicKey.export({ format: "jwk" });
    const cose = new Map<number, number | Uint8Array>([
      [1, 2], [3, -7], [-1, 1],
      [-2, new Uint8Array(Buffer.from(jwk.x!, "base64url"))],
      [-3, new Uint8Array(Buffer.from(jwk.y!, "base64url"))],
    ]);
    this.cose = isoCBOR.encode(cose);
  }

  get id() {
    return b64u(this.credentialId);
  }

  // The COSE public key exactly as the authenticator reports it (CTAP2 canonical ES256).
  get cosePublicKey(): Buffer {
    return Buffer.from(this.cose);
  }

  private authData(flags: number, counter: number, attested: boolean, rpId: string) {
    const parts: Buffer[] = [sha256(Buffer.from(rpId)), Buffer.from([flags])];
    const c = Buffer.alloc(4);
    c.writeUInt32BE(counter);
    parts.push(c);
    if (attested) {
      const len = Buffer.alloc(2);
      len.writeUInt16BE(this.credentialId.length);
      parts.push(Buffer.alloc(16), len, this.credentialId, Buffer.from(this.cose));
    }
    return Buffer.concat(parts);
  }

  // options: PublicKeyCredentialCreationOptionsJSON
  register(options: { challenge: string; user: { id: string } }, o: AssertOpts = {}) {
    this.userHandle = options.user.id;
    const clientData = Buffer.from(JSON.stringify({
      type: o.type ?? "webauthn.create", challenge: options.challenge, origin: o.origin ?? this.origin, crossOrigin: false,
    }));
    const flags = 0x01 | (o.uv === false ? 0 : 0x04) | 0x40;
    const authData = this.authData(flags, 0, true, o.rpId ?? this.rpId);
    const attObj = isoCBOR.encode(new Map<string, unknown>([["fmt", "none"], ["attStmt", new Map()], ["authData", new Uint8Array(authData)]]) as never);
    return {
      id: this.id, rawId: this.id, type: "public-key",
      response: { clientDataJSON: b64u(clientData), attestationObject: b64u(attObj), transports: ["internal"] },
      clientExtensionResults: {},
    };
  }

  // options: PublicKeyCredentialRequestOptionsJSON
  assert(options: { challenge: string }, o: AssertOpts = {}) {
    const counter = o.counter ?? ++this.counter;
    const clientData = Buffer.from(JSON.stringify({
      type: o.type ?? "webauthn.get", challenge: options.challenge, origin: o.origin ?? this.origin, crossOrigin: false,
    }));
    const flags = 0x01 | (o.uv === false ? 0 : 0x04);
    const authData = this.authData(flags, counter, false, o.rpId ?? this.rpId);
    const signer = createSign("SHA256");
    signer.update(Buffer.concat([authData, sha256(clientData)]));
    const sig = signer.sign(this.privateKey);
    if (o.tamper) sig.writeUInt8(sig.readUInt8(sig.length - 1) ^ 0xff, sig.length - 1);
    return {
      id: this.id, rawId: this.id, type: "public-key",
      response: {
        clientDataJSON: b64u(clientData), authenticatorData: b64u(authData), signature: b64u(sig),
        ...(this.userHandle ? { userHandle: this.userHandle } : {}),
      },
      clientExtensionResults: {},
    };
  }
}
