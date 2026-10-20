# Orvix Control

Platform Admin Console for Orvix: a **local development foundation**. It is separate from the Orvix POS (ShwePhaLa) repository and has no Git remote.

> Synthetic tenants and mock health data only. No POS connection, no production credentials, no real tenant administration, no recovery-release authority, no billing.

## Isolated resources

| Resource | Value |
|---|---|
| PostgreSQL | `orvix-control-db` (postgres:17), `127.0.0.1:55440`, database `orvix_control` |
| Volume / network | `orvix-control-pgdata` / `orvix-control-net` |
| Next.js | `http://localhost:3410` (must be `localhost`: it is the WebAuthn RP ID) |
| Test databases | `orvix_control_test_*`, `orvix_control_e2e`, created and dropped inside the same container |

`npm run db:preflight` checks that the ports are free (or already ours) and that no unexpected `orvix-control-*` Docker object exists. Scripts refuse any database target that is not `127.0.0.1:55440/orvix_control*`, and any database that looks like Supabase.

## Quick start

```bash
npm install
npm run db:up          # preflight, generate .env.local (0600, dev-only random passwords), start Postgres
npm run db:migrate     # apply db/migrations/2xx (own ledger: control_ledger.schema_migrations)
npm run db:seed        # synthetic tenants + pos_mock stand-in tenant tables
npm run bootstrap-owner -- --email you@example.invalid --name "Your Name"   # HOST ONLY (superuser): one-time enrolment URL
npm run dev            # http://localhost:3410 → open the enrolment URL, register a passkey, then sign in
```

## Tests

```bash
npm test               # 177 DB tests: crypto (vs OpenSSL), trust boundary, privileges, auth/sessions, passkeys,
                       # recovery, audit integrity, anchors/offline verification, upgrade continuity, guards
npm run test:e2e       # builds, starts `next start` on :3410 against orvix_control_e2e, 21 HTTP tests

# host / owner tools
npm run host -- recovery-request|recovery-confirm|recovery-cancel|revoke-operator|purge-expired …   # HOST ONLY (superuser)
npm run audit:keygen -- --out <private dir>             # owner machine: offline anchor key
npm run audit:sign -- --events e.json --archive <dir> --key anchor-key.pem [--init] --confirm-head <seq>
npm run audit:verify -- --events e.json --archive <dir> --anchor-key <fingerprint>
```

The e2e suite uses a software authenticator (`tests/helpers/softAuthenticator.ts`): real P-256 keys, real CBOR attestation and real ECDSA assertions, so the server's `@simplewebauthn/server` verification is exercised for real.

## Architecture

```
Browser ──(passkey, __Host- cookie, CSRF header)──▶ Next.js (route handlers, server components)
                                                     │  pg as control_app ONLY
                                                     ▼
                                   control.api_*  (SECURITY DEFINER, owner control_definer)
                                     ├─ session resolve (idle 15 min / absolute 8 h)
                                     ├─ role + step-up check (5 min)
                                     ├─ action
                                     └─ control.audit_append → hash-chained audit (owner control_audit_owner)
```

- `control_app` holds USAGE on schema `control` and EXECUTE on 28 `api_*` functions. It has no table privileges anywhere.
- **The database verifies WebAuthn evidence itself** (ES256 in PL/pgSQL, DB-issued challenges). The app's password alone cannot create a session, a step-up grant or a passkey. See `docs/AUTH_TRUST_BOUNDARY.md`.
- Owner roles: `control_auth` (authentication), `control_definer` (tenant model), `control_audit_owner` (audit log and its read API), plus an inert `control_schema_owner`. No runtime role can run code as another one, or holds a privilege on another's table.
- Every `api_*` returns `{ok:true,…}` or `{ok:false,error}`. Every effect is audited atomically with it; refusals are audited unless the caller rolls back (a documented residual). The app treats anything else as a refusal (fail closed).
- Migrations: `200` foundation and roles · `201` audit log · `202` identities, sessions · `203` lifecycle model and audit API · `204` ES256 verifier · `205` trust boundary, multiple passkeys, step-up grants, recovery · `206` passkey anchors and export · `207` review hardening · `208` review round 2 · `209` review round 3 · `210` final checkpoint review · `211` final follow-ups.

## Docs

- [docs/POS_INTEGRATION_REQUIREMENTS.md](docs/POS_INTEGRATION_REQUIREMENTS.md): what the POS must provide, and the boundaries.
- [docs/SECURITY_FINDINGS.md](docs/SECURITY_FINDINGS.md): fixed and unresolved findings, plus verified properties.
- [docs/AUTH_TRUST_BOUNDARY.md](docs/AUTH_TRUST_BOUNDARY.md), [docs/RECOVERY.md](docs/RECOVERY.md), [docs/AUDIT_EVIDENCE.md](docs/AUDIT_EVIDENCE.md), [docs/REVIEW_C1_1.md](docs/REVIEW_C1_1.md).
- Design source (read-only, in the POS repo): `docs/plans/orvix-platform-control-plane-architecture.md` and `reconciliation-v2-claude4-control-plane.md`.

## Teardown

```bash
npm run db:down                          # stop and remove the container (keeps the volume)
docker volume rm orvix-control-pgdata    # delete all local data
```
