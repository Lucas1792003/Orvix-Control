# C1.1 residual MEDIUM risks: impact, assumptions and checkpoint status

These three risks are **not resolved**. Each was re-observed live on 2026-10-19 against migrations 200–211 (throwaway database; probe output quoted under each risk). Tests passing does not change that: the tests only show that the mitigations behave as described. "Local checkpoint" here means one local git commit in a repository with no remote, nothing deployed, synthetic data only, and the server reachable only on loopback.

---

## RM-1: Relayed passkey ceremonies (MEDIUM)

**What exactly can happen.** An attacker who controls the code the operator's browser runs on `http://localhost:3410` can do the following. That means a compromised Next.js server, a malicious dependency, or XSS.

- Show the operator a normal-looking passkey prompt (login, step-up, anchor signing), backed by a challenge the attacker requested for a **different** purpose or action.
  - Authenticators do not display challenges, so the operator cannot tell.
  - The database accepts the resulting assertion, because it is genuine.
- With that single ceremony the attacker can obtain:
  - a session, or a one-time step-up grant for **any** allowed action (`tenant_transition`, `credential_add`, `credential_revoke`, `recovery_approve`, `recovery_cancel`), with a target of its choice;
  - a forged attestation for a passkey of its own. Format `none` is unsigned, so after a relayed `credential_add` step-up it can register its own key.
  - When the victim is an owner and a recovery request is pending, an approval whose one-time enrolment link the attacker can read.

**Observed:** `relayed credential_add grant: true | rogue passkey added: true | rogue login now: CREDENTIAL_PENDING | owner sees pending: 1`, and after the 15-minute window `rogue login: true`.

**What limits it (verified by tests; mitigations, not fixes).**
- **Grants are narrow:** single-use, bound to one session, one action and one target, valid for 2 minutes.
- **New passkeys wait:** a passkey added in-session is **pending for 15 minutes**. It cannot sign in or step up, every session of the operator shows a red banner, and any session can revoke it.
- **Contested recovery waits:** a contested recovery needs a host confirmation dated after the objection, plus 12 hours.
- **Everything is audited**, under the operator's identity.

**What does not limit it.**
- The banner and the revoke button are served by the same compromised app.
- After 15 minutes the attacker's passkey works normally.
- No out-of-band notification channel exists.

**Threat assumptions.**
- The attacker controls server code or script execution on the console origin.
- The operator completes one passkey ceremony while it does.
- Passkeys themselves are not broken.

**Blocks a LOCAL checkpoint?** **No.**
- There is no deployment, no operator account in the dev database, and no real tenant.
- The risk is inherent to server-mediated WebAuthn and is documented.
- It **does** block production or any shared use until there is out-of-band notice of new credentials and recovery approvals, or a confirmation step outside this origin.

---

## RM-2: Global login-challenge exhaustion (MEDIUM, availability)

**What exactly can happen.**
- `api_login_begin` counts calls in one global bucket: 20 per 15-minute window (setting `login_global_limit`).
- Anyone who can send `POST /api/auth/login/options` with the expected `Origin` header can use up the bucket, for example with a non-browser client.
- For the rest of the window, **every** operator's sign-in fails with `RATE_LIMITED`. Existing sessions keep working, and enrolment links are not affected (per-token limits since 207).
- Sustained, it is an indefinite sign-in denial of service.

**Observed:** `challenges issued: 20 | next call: RATE_LIMITED | existing session still works: true`.

**Threat assumptions.**
- The attacker can reach the console's HTTP port.
- In the intended deployment that means loopback on the host plus an SSH tunnel, so the attacker already has host or tunnel access.
- Through the tunnel every client is `127.0.0.1`, so per-IP limits cannot tell clients apart.
- It grants no access and no information.

**Blocks a LOCAL checkpoint?** **No.** Nothing is exposed, and it is an availability issue only. It blocks any deployment where the port is reachable by anyone other than the operators. Before then the fix needs a per-client identity (for example mTLS or a tunnel-side credential), or a pre-authentication proof such as a host-side secret.

---

## RM-3: Open-transaction and audit-lock abuse (MEDIUM; requires the `control_app` password)

**What exactly can happen.** Someone holding the `control_app` database password can:
1. **Lock out audited actions.**
   - Open a transaction, call any audited `api_*` function, and keep the transaction open.
   - That holds the single audit row lock, and possibly identity or session row locks.
   - `control_app` can raise its own `idle_in_transaction_session_timeout` and `statement_timeout` to 0.
   - Every other audited call (logins, step-ups, transitions, refusals) then fails with a lock timeout until the transaction ends.
   - It fails closed, so nothing is accepted without being audited.
2. **Suppress audit rows by rolling back.**
   - Wrap calls in `BEGIN … ROLLBACK`.
   - Refusal rows, reads and exports leave **no audit trace**.
   - Effects cannot be hidden: every change commits atomically with its audit row, so a rolled-back change did not happen.

3. **Undo rate-limit counts and challenge consumption** by rolling back. Login attempts then cost about 60 ms of signature verification each, with no limit, for the duration. It is CPU only and grants no authentication: the evidence must still verify.

**Observed:** `other audited call while lock held: 55P03 after 3012 ms` and `refusal inside txn: STEPUP_REQUIRED | audit rows added after ROLLBACK: 0`. What 210 did close: a call inside a transaction older than 5 s is refused (`STALE_TRANSACTION`), so a held transaction can no longer outlive session, grant, token or request expiry.

**Why it is not fixed.**
- PostgreSQL offers no reliable test for "inside an explicit transaction block".
- A `statement_timestamp() <> transaction_timestamp()` guard was implemented in 208 and **rejected**: under the extended query protocol it refused legitimate autocommit calls.
- A role cannot be prevented from changing its own session settings.

**Threat assumptions.**
- The attacker has the `control_app` password, which is held only by the server process (a dev value in `.env.local`, mode 0600, git-ignored).
- That is equivalent to a compromised server, which RM-1 already covers.
- It gives the attacker no session, no grant and no audit rewrite.

**Blocks a LOCAL checkpoint?** **No.** The database is a local loopback dev instance and the password is a generated dev value that is not tracked. Before production it needs:
- connection-level controls: a pooler that resets session settings and forbids transactions for this role, or `pgbouncer` in statement mode;
- monitoring of long-running transactions;
- or an autonomous audit sink.
