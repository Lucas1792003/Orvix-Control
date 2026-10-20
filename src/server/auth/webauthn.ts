import "server-only";
import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
  type AuthenticationResponseJSON,
  type RegistrationResponseJSON,
} from "@simplewebauthn/server";
import { decodeClientDataJSON } from "@simplewebauthn/server/helpers";
import { config } from "../config";
import { callApi, type ApiName, type ApiResult } from "../db/api";

// Trust model (migration 205):
//  - The DATABASE issues every challenge and is the ONLY verifier whose answer counts. It receives the raw
//    evidence (clientDataJSON, authenticatorData / attestationObject, signature) and checks challenge, origin,
//    RP ID, UP+UV, counter and the ES256 signature itself.
//  - This server runs @simplewebauthn/server first as a NON-authoritative pre-check (early rejection, parity).
//    Nothing it decides can create a session: it never sends a "verified" flag or a counter.
// ES256 only (COSE -7): the database verifier supports P-256 keys only.

const ES256 = [-7];
const bytes = (b64url: string) => new Uint8Array(Buffer.from(b64url, "base64url"));

function challengeOf(resp: { response?: { clientDataJSON?: unknown } }): string | null {
  try {
    const raw = resp.response?.clientDataJSON;
    if (typeof raw !== "string") return null;
    const c = decodeClientDataJSON(raw).challenge;
    return /^[A-Za-z0-9_-]{32,128}$/.test(c) ? c : null;
  } catch {
    return null;
  }
}

// ------------------------------------------------------------ registration (enrolment token, or add-passkey)

async function registrationOptions(r: ApiResult & { ok: true }) {
  return generateRegistrationOptions({
    rpName: config.rpName,
    rpID: config.rpID,
    challenge: bytes(String(r.challenge)), // bytes, so options.challenge === the DB challenge
    userID: new TextEncoder().encode(String(r.identity_id)),
    userName: String(r.email),
    userDisplayName: String(r.display_name),
    attestationType: "none",
    authenticatorSelection: { userVerification: "required", residentKey: "required" },
    excludeCredentials: ((r.exclude_credential_ids as string[]) ?? []).map((id) => ({ id })),
    supportedAlgorithmIDs: ES256,
    timeout: 120_000,
  });
}

async function precheckRegistration(response: RegistrationResponseJSON, challenge: string) {
  try {
    const v = await verifyRegistrationResponse({
      response,
      expectedChallenge: challenge,
      expectedOrigin: config.origin,
      expectedRPID: config.rpID,
      requireUserVerification: true,
      supportedAlgorithmIDs: ES256,
    });
    return v.verified && v.registrationInfo.fmt === "none";
  } catch {
    return false;
  }
}

async function completeRegistration(purpose: "register" | "register_add", response: RegistrationResponseJSON,
                                    finish: (att: Buffer, cdj: Buffer) => Promise<ApiResult>): Promise<ApiResult> {
  const challenge = challengeOf(response);
  if (!challenge) return { ok: false, error: "INVALID_INPUT" };
  if (!(await precheckRegistration(response, challenge))) {
    await callApi("api_auth_failed", [purpose, challenge, String(response.id ?? ""), "ATTESTATION_INVALID"]);
    return { ok: false, error: "VERIFICATION_FAILED" };
  }
  return finish(Buffer.from(response.response.attestationObject, "base64url"),
                Buffer.from(response.response.clientDataJSON, "base64url"));
}

export async function enrolOptions(token: string): Promise<ApiResult> {
  const r = await callApi("api_enrol_begin", [token]);
  if (!r.ok) return r;
  return { ok: true, options: await registrationOptions(r), purpose: r.purpose, expiresInSeconds: r.expires_in_seconds };
}

export async function enrolVerify(token: string, response: RegistrationResponseJSON, nickname: string | null) {
  return completeRegistration("register", response, (att, cdj) => callApi("api_enrol_complete", [token, att, cdj, nickname]));
}

export async function credentialAddOptions(sessionToken: string): Promise<ApiResult> {
  const r = await callApi("api_credential_add_begin", [sessionToken]);
  if (!r.ok) return r;
  return { ok: true, options: await registrationOptions(r) };
}

export async function credentialAddVerify(sessionToken: string, response: RegistrationResponseJSON, nickname: string | null) {
  return completeRegistration("register_add", response,
    (att, cdj) => callApi("api_credential_add_complete", [sessionToken, att, cdj, nickname]));
}

// ------------------------------------------------------------ assertions (login, step-up, anchor signing)

async function assertionOptions(challenge: string, allow?: string[]) {
  return generateAuthenticationOptions({
    rpID: config.rpID,
    challenge: bytes(challenge),
    userVerification: "required",
    timeout: 120_000,
    ...(allow ? { allowCredentials: allow.map((id) => ({ id })) } : {}),
  });
}

async function precheckAssertion(response: AuthenticationResponseJSON, challenge: string): Promise<string | null> {
  const lookup = await callApi("api_credential_lookup", [String(response.id ?? "")]);
  if (!lookup.ok) return "UNKNOWN_CREDENTIAL";
  try {
    const v = await verifyAuthenticationResponse({
      response,
      expectedChallenge: challenge,
      expectedOrigin: config.origin,
      expectedRPID: config.rpID,
      requireUserVerification: true,
      credential: {
        id: String(lookup.credential_id),
        publicKey: new Uint8Array(Buffer.from(String(lookup.public_key), "base64")),
        // Counter is judged ONLY by the database (it refuses AND flags a regression). Passing the stored value here
        // made @simplewebauthn throw first, so the database never saw cloned-authenticator evidence (final review).
        counter: 0,
      },
    });
    return v.verified && v.authenticationInfo.userVerified ? null : "SIGNATURE_INVALID";
  } catch {
    return "SIGNATURE_INVALID";
  }
}

// Evidence goes to the database verbatim. Returns the DB result (fail closed on anything else).
async function completeAssertion(purpose: "login" | "stepup" | "anchor", response: AuthenticationResponseJSON,
                                 fn: ApiName, leading: unknown[], trailing: unknown[] = []): Promise<ApiResult> {
  const challenge = challengeOf(response);
  if (!challenge) return { ok: false, error: "INVALID_INPUT" };
  const pre = await precheckAssertion(response, challenge);
  if (pre) {
    await callApi("api_auth_failed", [purpose, challenge, String(response.id ?? ""), pre]);
    return { ok: false, error: "VERIFICATION_FAILED" };
  }
  return callApi(fn, [...leading, response.id,
    Buffer.from(response.response.clientDataJSON, "base64url"),
    Buffer.from(response.response.authenticatorData, "base64url"),
    Buffer.from(response.response.signature, "base64url"), ...trailing]);
}

// deviceToken: opaque rate-limit scope from a previous sign-in on this browser (213); no authentication power.
export async function loginOptions(deviceToken: string | null): Promise<ApiResult> {
  const r = await callApi("api_login_begin", [deviceToken]);
  if (!r.ok) return r;
  return { ok: true, options: await assertionOptions(String(r.challenge)) };
}

export async function loginVerify(response: AuthenticationResponseJSON, deviceToken: string | null): Promise<ApiResult> {
  const r = await completeAssertion("login", response, "api_login_complete", [], [deviceToken]);
  return r.ok ? r : { ok: false, error: r.error === "RATE_LIMITED" ? "RATE_LIMITED" : "LOGIN_FAILED" };
}

export async function stepupOptions(sessionToken: string, action: string, target: string): Promise<ApiResult> {
  const r = await callApi("api_stepup_begin", [sessionToken, action, target]);
  if (!r.ok) return r;
  return { ok: true, options: await assertionOptions(String(r.challenge), r.credential_ids as string[]) };
}

export async function stepupVerify(sessionToken: string, response: AuthenticationResponseJSON): Promise<ApiResult> {
  const r = await completeAssertion("stepup", response, "api_stepup_complete", [sessionToken]);
  return r.ok ? r : { ok: false, error: r.error === "UNAUTHENTICATED" ? "UNAUTHENTICATED" : "STEPUP_FAILED" };
}

export async function anchorOptions(sessionToken: string): Promise<ApiResult> {
  const r = await callApi("api_anchor_begin", [sessionToken]);
  if (!r.ok) return r;
  return { ok: true, options: await assertionOptions(String(r.challenge), r.credential_ids as string[]), seq: r.seq };
}

export async function anchorVerify(sessionToken: string, response: AuthenticationResponseJSON, note: string | null) {
  return completeAssertion("anchor", response, "api_anchor_complete", [sessionToken], [note]);
}
