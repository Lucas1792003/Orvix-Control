# Authentication trust boundary (Phases C1.1–C1.2, migrations 204–217)

## 1. What `control_app` could do before (≤ 203)

The Next.js server connects as `control_app`, whose only rights are EXECUTE on `control.api_*`. Before 205 the database trusted the server's claim that a passkey had been verified. Anyone holding the `control_app` password could:

| # | Capability | How |
|---|---|---|
| A1 | **Mint a session for any operator, with no passkey** | `api_login_begin(any challenge)` then `api_login_complete(challenge, credential_id, counter)`. Credential IDs are not secret. |
| A2 | Satisfy any step-up | `api_stepup_begin` / `api_stepup_complete(token, challenge, credential_id, counter)`, same pattern. |
| A3 | Claim the owner identity before enrolment | `api_bootstrap_owner` was granted to `control_app`. |
| A4 | Disable a real passkey | Send a lower counter to `api_login_complete`. |
| A5 | Burn challenges and write misleading failure rows | `api_auth_failed`. |

`control_app` could not read or write tables directly, touch tenant (POS) tables, write the audit log directly, or change settings.

## 2. What it can do now (205+)

| # | Capability | Status |
|---|---|---|
| A1 | Mint a session without a passkey | **Closed.** `api_login_complete(credential_id, clientDataJSON, authenticatorData, signature)` verifies the raw evidence **inside Postgres**: DB-issued, single-use, purpose-bound challenge; origin and type from clientDataJSON; RP ID hash; UP and UV flags; ES256 signature with the stored key; strictly increasing counter. There is no parameter for "verified" or "counter". |
| A2 | Satisfy a step-up | **Closed**, same evidence check. A grant is single-use, bound to (session, action, target) and expires after 2 min. |
| A3 | Bootstrap | **Closed.** `host_bootstrap_owner` has no grant to any login role; only the database superuser (host) can call it. |
| A4 | Disable a passkey by counter poisoning | **Closed** (205, 207, 210). The counter is parsed from signed authenticatorData, so a forged assertion never reaches the counter check. A genuine assertion that was held back and replayed out of order is refused and the passkey is **flagged**. It is never disabled automatically, because that could remove an operator's last passkey (review F1/R-M1). Since 210 the app's `@simplewebauthn` pre-check ignores the counter, so this evidence actually reaches the database (an e2e test covers it). |
| A5 | Burn challenges and add failure rows | **Reduced** (207). A row is written only for a challenge that existed, is attributed to `anonymous` (the claimed credential is kept in `detail`), and is rate-limited. |
| A6 | **Relay a live operator's ceremony** | **Remains (inherent) — MEDIUM.** A compromised app server or XSS sits between the operator's browser and the database. Authenticators do not display challenges, so **any** prompt the operator answers can be used for **any** step-up action of the attacker's choosing (not just "the same type"). Examples: `credential_add` followed by an attestation the attacker forges (format `none` is unsigned), or `recovery_approve`, whose enrolment link the server then holds. Mitigations (207): grants are single-use, bound to a target and valid for 2 min; passkeys added in-session stay **pending for 15 minutes** (they cannot sign in or step up, are shown to every session with a banner, and can be revoked); a recovery approval for a subject who objected, used a passkey or was emergency-revoked needs a later host confirmation plus a 12 h delay; every step is audited. Not mitigated in C1.1: an operator who does not look at the banner during the window. **C1.2 (212–217):** independent out-of-band notices with delivery gating — the pending window now starts only when the notice has been delivered (ack-verified) to every recipient including a host channel; recovery redemption and operator activation are gated the same way; new-device sign-ins are announced. The capability itself remains (inherent); see [RESIDUAL_RISKS_C1_2.md](RESIDUAL_RISKS_C1_2.md). |

## 3. Separation of duties

| Layer | Holds | Can | Cannot |
|---|---|---|---|
| Browser | session cookie (HttpOnly), CSRF token | run WebAuthn ceremonies | see any DB secret |
| Next.js (`control_app`) | DB password | relay evidence; pre-check it with @simplewebauthn (non-authoritative) | create sessions, grants or credentials without valid evidence; read any table |
| `control_auth` (NOLOGIN, owner) | identities, credentials, challenges, sessions, step-up grants, tokens, recovery requests, **settings, rate limits** | verify evidence; issue sessions and grants | read or write tenants, the tenant-model tables or the audit table (append only via `audit_append`) |
| `control_definer` (NOLOGIN, owner) | tenant model, request results | tenant API (the audit-read API moved to `control_audit_owner` in 210) | read any auth table; change settings; it may only call `session_resolve()` and `stepup_consume_token()` (which needs the session **token**, not a context it could forge) |
| `control_audit_owner` (NOLOGIN, owner) | audit events, anchors, the audit lock row, the audit read/export API | append; verify; store passkey anchors after re-verifying the signature (NULL-safe), with the signer's key obtained from the `control_auth` function `anchor_signer` | anything else. Since 210, no runtime role holds a privilege on another runtime role's table, and no RLS policy exists: a table owner can no longer run policy code as the reader. |
| `control_schema_owner` (NOLOGIN, inert) | schema `control`; the shared invoker-rights helpers (crypto, `sha`, `new_secret`, `err`, base64url, canonical form) | nothing at runtime: it owns no SECURITY DEFINER function, so no code ever runs as it | — |
| `control_sentinel` (LOGIN, C1.2) | its own password (`.env.sentinel`); reads webhook secrets through `sentinel_claim` | claim and acknowledge notice deliveries; run the watchdog | read or write any table; call any `api_*` or host function |
| `control_watchdog_owner` (NOLOGIN, C1.2) | member of `pg_signal_backend` and `pg_read_all_stats` | own `sentinel_watchdog`, which terminates **only `control_app`** backends **of its own database** | signal superuser backends; anything else |
| Superuser (host) | everything; `.env.host` | bootstrap; recovery requests; channel setup; operator approval; tamper (detectable offline against signed anchors) | — (infrastructure trust) |

**Why the schema owner exists (review P-F1, HIGH, fixed in 207).** Before 207, `control_definer` owned schema `control` and the invoker-rights helpers that `control_auth` and `control_audit_owner` execute. By rewriting `es256_verify` or `new_secret`, it could run code **as** those roles: it could mint sessions or rewrite the audit chain. It could also shadow `make_interval` (schema owners can create objects), and it owned the settings holding the WebAuthn origin. Now no runtime role has CREATE on any schema. Shared helpers belong to the inert `control_schema_owner`, and the settings belong to `control_auth`. A test enforces that no runtime role can execute an invoker-rights function owned by a *different* runtime role, and the reviewer's exploit steps run as `control_definer` are all refused.

No new network service was added. The privileged verifier is a role inside Postgres, so there is no extra process, port or credential to protect.

**Advisory locks.** Until 217 these were callable by every role, including `control_app`. 207 replaced the audit and bootstrap advisory locks with row locks on owner-only tables. 217 revoked every advisory-lock function from PUBLIC (transaction-scoped variants are granted only to the owner roles), and `plpgsql` USAGE (no `DO` blocks for `control_app`). A `control_app` **transaction held open** after an audited call still holds the audit row lock: residual RM-3 in [RESIDUAL_RISKS_C1_1.md](RESIDUAL_RISKS_C1_1.md). Since 210, auth entry points refuse a transaction more than 5 s old (`STALE_TRANSACTION`), so expiry cannot be outlived inside one. One advisory lock remains, per request id in `api_tenant_transition` (negligible).

**Startup integrity check (210, 211, C1.2).** The server refuses to serve (`CONTRACT_MISMATCH`) unless all of these hold, checked at start and again every 30 s:
- contract `orvix-control/0.4`;
- cluster `orvix-control-dev`;
- every SECURITY DEFINER function in `control` pins `search_path`;
- `control_app`'s role defaults are exactly the expected set, with no per-database overrides;
- the session's effective `statement_timeout`, `lock_timeout`, `idle_in_transaction_session_timeout`, `temp_file_limit`, `transaction_timeout`, `default_transaction_read_only` and `row_security` have their expected values;
- `max_prepared_transactions` is 0 (prepared transactions would survive the watchdog);
- no `SUPERUSER` or `SENTINEL` variable is in the server's environment (`src/server/config.ts`).

`npm run db:migrate` restores the full canonical defaults (whatever the database's ledger says), including clearing per-database overrides. A change made while the server is running is caught within 30 s.

**Note on migration 200's header:** it says `control_definer` owns every table and API function. That was true at 200; 205, 207 and 210 changed ownership as described above. Applied migrations are not edited, because their checksums are in the ledger.

## 4. In-database ES256 verification (204)

- Pure PL/pgSQL over `numeric`: P-256 Jacobian arithmetic (`dbl-2001-b`, `add-2007-bl` with explicit exceptional cases), Shamir double-scalar multiplication, a Fermat inverse, strict DER, and strict CTAP2-canonical COSE (`{1:2,3:-7,-1:1,-2:x,-3:y}`, 77 bytes, point on curve).
- Verify-only: all inputs are public, so constant time is not required.
- About 60 ms per verification. Login is rate-limited **before** verification, and a challenge is consumed before the signature is checked. Under normal (autocommit) use, verification work is therefore bounded by the number of challenges issued. Someone holding the `control_app` password can roll back and undo both the rate-limit count and the challenge consumption, so verification work is **not** bounded for them. That is CPU only and grants nothing (RM-3 in [RESIDUAL_RISKS_C1_1.md](RESIDUAL_RISKS_C1_1.md)).
- Differentially tested against OpenSSL: 40 random keys and messages, plus tampered message, signature bits, wrong key, r and s in {0, n, n+1}, the high-S twin (both accept), malformed DER, and non-canonical, wrong-algorithm and off-curve keys (`tests/sql/crypto.test.ts`).
- **Limit:** ES256 only. Authenticators that offer only RS256 or EdDSA cannot enrol; the request is refused, failing closed.
- Attestation: format `none` only, in CTAP2 canonical map order. Real Chrome's attestation and assertions were verified end to end in a browser run on 2026-10-19.

## 5. Settings that the boundary depends on

`webauthn_rp_id = localhost` and `webauthn_origin = http://localhost:3410` live in `control.settings`, which has been owned by `control_auth` since 207 (it was `control_definer` before). No granted function writes settings (asserted by a test), so `control_app` cannot repoint the origin, and `control_definer` has no privilege on the table.

## 6. Residual risks that remain by design

| Risk | Severity | Why accepted for now |
|---|---|---|
| A6 relay of a live ceremony (see above) | LOW with a watched host channel; MEDIUM without (C1.2) | Inherent to server-mediated WebAuthn. Mitigated by single-use bound grants, delivery-gated passkeys, recovery links and activations, and out-of-band notices. |
| First sign-in on a new device shares the anonymous login bucket | LOW (availability, C1.2) | Known devices have their own buckets (213, capped at 5 per identity in 217); a hard ceiling bounds total challenges. |
| `control_app` can ROLLBACK an explicit transaction around `api_*` calls, which suppresses **refusal** and **read/export** audit rows | LOW–MEDIUM (C1.2) | Effects are always atomic with their audit row. Rolled-back rows are now **detected** through MAC-verified shadow lines in the server log (214, 217); held transactions are terminated by the watchdog. |
| `control_app` can change its own session timeouts and role settings and password | LOW | PostgreSQL lets every role change its own settings. It is a DoS or lock-out risk only. Monitor it, and reset it on deploy. |
| Postgres superuser on the host | — | Infrastructure trust. Detection relies on **offline** v2 anchors (`docs/AUDIT_EVIDENCE.md`). |
