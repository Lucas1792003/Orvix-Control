# C1.3 security hardening: design review, threat model and plan

Baseline: C1.2 checkpoint `8c5618f`. Input: the C1.2 runtime-validation report (W-1 reproduced, 7 MEDIUM, about 16 LOW).
Provisional migrations: `218`–`221`. Contract `orvix-control/0.5`.

## 1. Threat model (what C1.3 must hold against)

| Actor | Capability assumed | Must NOT be able to |
|---|---|---|
| Compromised console (origin, Next.js process, `control_app` password) | call any `api_*`; open raw `control_app` connections; hold transactions; change own session settings | suppress or forge security evidence; open a notification gate; activate an operator or redeem a recovery alone; reach other databases' unhardened surface; stall the watchdog into silence |
| Thief holding one owner's passkey (until recovery) | everything that owner can do via ceremonies | have its invitations or recovery approvals take effect while the owner is under recovery, or survive the recovery; keep a cloned passkey's sessions; use step-up while that owner is under recovery |
| Unauthenticated network client | call the login, enrolment and health endpoints | lock out a recovered owner, or a newly activated owner, from signing in |
| Failing infrastructure (crash, full disk, dead receiver) | process or backend crashes at any instant; short writes; black-holed sockets | erase the evidence of a watchdog termination; make a half-written notice count as delivered; let one bad channel delay the others without limit |
| `control_sentinel` credential holder | `sentinel_*` / `watchdog_*` functions | terminate sessions outside the protocol (non-`control_app`, other databases, without a committed intent, in the same transaction as the evidence); mark a webhook delivery with an **ack key** delivered. **Can** still mark file-channel and legacy (no ack key) webhook deliveries delivered on its own word: sentinel trust, documented. |
| Host / superuser | everything | out of scope (infrastructure trust); detected only by offline anchors |

Design rules applied to every fix:
- **Deadlocks:** every new path that touches identities, invitations, recovery requests or tokens takes `bootstrap_state` first, then follows the existing order: identity, sessions, credentials, grants; tokens before requests.
- **Audit gaps:** every new state change writes an audit row in the same transaction. A path that cannot take the audit lock writes durable evidence that is folded into the chain later.
- **Unauthorized recovery:** new checks only **add** refusals to recovery and activation. None relaxes an existing guard.
- **Notification bypass:** the gate stays "newest notice delivered to every recipient in its snapshot, at least one a host channel". The only relaxation is for a channel the **host** disabled (audited), and at least one enabled host channel must still have delivered.
- **Privilege escalation:** no new grant to `control_app`. The sentinel gains only `sentinel_*` functions. The watchdog still signals only `control_app` backends of its own database.
- **Owner lockout:** new refusals (identity under recovery, flagged passkey) block privileged actions, never sign-in. Recovery stays possible through another owner.

## 2. Finding → code path → fix

| ID | Finding | Code path (C1.2) | C1.3 fix | Migration / file |
|---|---|---|---|---|
| **W-1** | Kill evidence lost if the transaction dies after `pg_terminate_backend` | `sentinel_watchdog` (217): kill, then insert in the same transaction | Intent protocol (section 3) | 218, `scripts/sentinel.ts` |
| M1 | Recovery leaves the thief's invitations and approvals valid | `api_enrol_complete` recovery branch (217) | On redemption: void invitations the subject issued, reopen requests the subject approved, void grants, stamp `recovered_at`. Approval and redemption also refuse an inviter or approver recovered after acting. | 219 |
| M2 | The anonymous login bucket locks out recovered and new owners | `api_login_begin` (217); recovery revokes devices | Every enrolment ceremony (bootstrap, invite, recovery) issues a **device token** to that browser, so its first sign-in never uses the anonymous bucket. The anonymous bucket remains only for never-enrolled browsers (documented). | 219, enrol route |
| M3 | App and sentinel can use other databases (`postgres`, `template1`) | DB-level ACL is per database; pg_hba allows all | (a) `db/cluster/pg_hba.conf` restricts the control roles to control databases; (b) `scripts/harden-cluster.ts` revokes PUBLIC CONNECT/TEMP on `postgres` and `template1`; (c) the app, sentinel and migrator **refuse** when the role can connect to a non-control database | 221, scripts, `api.ts` |
| M4 | A restore leaves the database ACL at PUBLIC | `pg_restore` into a plain `CREATE DATABASE`; migrations re-run nothing | The migrator re-applies the database ACL on **every** run. The startup check refuses PUBLIC CONNECT/TEMP, app TEMP, and missing 217 built-in revocations. The rollback drill asserts all of it. | migrator, `api.ts` |
| M5 | A torn file notice counts as delivered | `sentinel.ts` `writeSync` return ignored | Write a leading newline + body + newline fully (loop), `fsync`, then **read back** the written bytes and compare before acknowledging. Refuse hard links (`nlink > 1`), non-regular files and symlinked parents. | `sentinel.ts` |
| M6 | One stalled webhook delays every channel | sequential pass, lease `limit × 7 s` | One independent worker **per channel**; `sentinel_claim(limit, channel)`; at most 5 items per claim (lease 40 s); claim token | 220, `sentinel.ts` |
| M7 | Host status misleads | `host_notify_status` (217), one heartbeat | Per-component liveness (delivery and watchdog, with a "busy" signal) and per-channel state `healthy` / `busy` / `delayed` / `failing` / `disabled`, from age and last error; the overall state is the worst one | 220 |
| L | Emergency revoke stops contesting after 24 h | `api_recovery_approve` (216) | Contested if the revoke happened after the subject's last recovery | 219 |
| L | Activity after approval does not void the link | `api_enrol_complete` (217) | Redemption refuses and reopens the request as contested if the subject used a passkey after the approval | 219 |
| L | Mid-recovery owner keeps owner powers | approve / cancel-other / invite | Every step-up action is paused (`IDENTITY_UNDER_RECOVERY`), except the protective ones: revoking a passkey, revoking an invitation, contesting one's own request. Anchors are paused too. Invitations and recovery links the identity issued are frozen while it is under recovery (`INVITER_UNDER_RECOVERY`, `APPROVER_UNDER_RECOVERY`). | 219 |
| L | Expired requests cancelled without audit | `host_recovery_request` (211) | One `recovery_cancelled` / `EXPIRED` row with subject per expired request | 219 |
| L | Revoked owner's channel keeps blocking | `active_owner_ids`, `notification_delivered` (212) | Suspended owners leave `active_owner_ids`; deliveries to host-disabled channels stop counting | 219, 220 |
| L | `audit-shadow` false "forged" after an upgrade | `audit-shadow.ts` | Separate `legacy` (pre-217 format) and `malformed` counts. Only a bad MAC on a line naming this database is forged. Missing rows are labelled "rolled back or deleted". Fold attempts take the audit lock **before** the shadow line, so a lock timeout leaves none. | `audit-shadow.ts`, 218 |
| L | Multiple sentinels (connection limit 3) | role limit 3, 2 connections each | Limit 12. Watchdog intents are unique per target session, so concurrent watchdogs cannot double-act. Errors log their SQLSTATE. | 220 |
| L | Stale ack clears another lease | `sentinel_ack` (212) | `claim_token`; ack must present it | 220 |
| L | Hard-linked file target | `sentinel.ts` | `nlink` check (with M5) | `sentinel.ts` |
| L | Flagged (possibly cloned) passkey keeps sessions | `wa_assertion` (212) | On regression, revoke that passkey's sessions and grants. Step-up and anchors refuse a flagged passkey (`CREDENTIAL_FLAGGED`); sign-in still works (lockout safety). | 219 |
| L | Revoked owners appear active | `api_operator_list` (217) | Effective state `suspended` (revoked after the last recovery); excluded from owner recipients | 219 |
| L | `NOTIFY` bypasses the `pg_notify` revoke | PostgreSQL has no `NOTIFY` privilege | Not fixable by grants. The cluster config lowers `max_notify_queue_pages`, the watchdog kills idle-in-transaction listeners, M3 removes cross-database use, and host status shows queue usage. Residual documented. | cluster config, 220 |
| L | Cross-tenant request-id response | `api_tenant_transition` (207) | A replay must match the tenant (and target state), else `REQUEST_ID_CONFLICT` | 221 |
| L | Orphaned Next.js test processes | e2e `afterAll` kills `npx` | Start `next` directly in its own process group; kill the group | `tests/e2e` |
| L | Excessive claim lease | `limit × 7` with limit 50 | Per-channel claims of at most 5, lease 40 s (with M6) | 220 |

Out of scope for C1.3 (unchanged): R-1…R-12 policy decisions, POS integration, separate OS users (deployment), log shipping.

## 3. W-1 crash-consistency protocol (designed before implementation)

Goal: a backend is terminated **only** if durable evidence of the intent already exists, and every intent reaches a terminal state that is eventually in the hash chain and announced.

Each step below is its own transaction, called by the sentinel as a separate autocommit statement.

| Step | Function (owner) | Effect | Commits before the next step? |
|---|---|---|---|
| 1. PLAN | `watchdog_plan(idle, xact)` (watchdog owner → audit owner) | For each qualifying `control_app` backend of this database: insert an intent `(pid, backend_start, xact_start, reason, state='planned')`, unique on `(pid, backend_start, xact_start)`, and enqueue an out-of-band **intent notice**. Returns intent ids. | yes |
| 2. ARM | `watchdog_arm(id)` | `planned` → `armed` (only if the target still matches). Durable proof that a kill **may** follow. | yes |
| 3. EXECUTE | `watchdog_execute(id)` | Only an `armed` intent, **locked** (`FOR UPDATE`) and re-read. Re-reads `pg_stat_activity` (fresh snapshot): same pid **and** `backend_start` **and** `xact_start`, still `control_app`, this database, still qualifying (idle in that transaction, or the transaction is older than 5 s). Then `pg_terminate_backend(pid, 250)` → `terminated` (confirmed gone within 250 ms) or `terminated_unconfirmed`; or → `skipped` (target changed or gone). | yes |
| 4. RECONCILE | `watchdog_reconcile()` | Resolves leftovers (below), then **folds** resolved intents into the audit chain (lock taken with a 1 s timeout **before** writing the shadow line) and enqueues the resolution notice. | yes |

Crash at each boundary and how reconciliation resolves it (an intent stuck in a non-terminal state for more than 10 s is "interrupted"):

| Crash point | Durable state left | Reconcile resolution | Terminal state |
|---|---|---|---|
| During PLAN | nothing (rolled back); **no kill happened** (requirement 8) | — | — |
| After PLAN, before ARM | `planned` + intent notice | target gone → `abandoned_target_gone`; target present → `abandoned` (never killed) | yes |
| After ARM, before or inside EXECUTE (incl. after the kill, before commit: the old W-1 window) | `armed` + intent notice | target (pid + backend_start) gone → `terminated_unconfirmed` (a kill may have happened; evidence kept); target present → `abandoned_armed` (never retried silently: a new pass makes a **new** intent) | yes |
| After EXECUTE | `terminated` / `skipped` | fold into the chain | yes |
| During RECONCILE / fold | resolved but `audit_seq` NULL | next reconcile folds it; host status shows `not_in_chain` | eventually |

Properties:
1. **Pre-kill intent:** EXECUTE refuses unless a committed `armed` row exists.
2. **Terminal states:** `terminated`, `terminated_unconfirmed`, `skipped`, `abandoned`, `abandoned_target_gone`, `abandoned_armed`.
3. **A crash after the kill keeps the evidence:** the `armed` row and the intent notice were committed before the kill.
4. **Interrupted operations are detected:** by age and state, in RECONCILE and host status.
5. **Notifications:** the intent notice is enqueued at PLAN (pending until delivered); the resolution notice at fold.
6. **The chain:** fold writes the audit row and sets `audit_seq`.
7. **No unrelated sessions:** identity is `(pid, backend_start, xact_start)`; an interrupted intent is never re-executed.
8. **Persistence failure prevents termination:** no committed `armed` row means no `pg_terminate_backend`.

The `control_sentinel` credential can call these functions, but EXECUTE still terminates only qualifying `control_app` backends of this database that match an armed intent.

**Enforced by the database, not the client (independent review, H-1/H-2/M-1/L-1/L-3):**
- **Own transaction:** ARM and EXECUTE refuse to run in a transaction that has already written (`pg_current_xact_id_if_assigned()`). The committed intent can therefore never be rolled back together with the kill.
- **Durable commits:** PLAN, ARM, EXECUTE and RECONCILE force `synchronous_commit=on`.
- **No lost race:** EXECUTE holds the intent row lock from its re-read through the kill and the transition; RECONCILE uses `SKIP LOCKED` and counts only transitions that succeed.
- **No successor sweep:** there is no caller-chosen target class; a backend that inherits a victim's lock is a stale holder on the next pass.
- **Any database name:** RECONCILE resolves open intents of any database name (e.g. after a rename or restore) as "target gone".
- **Remaining window:** a microsecond check-then-act window between the `pg_stat_activity` match and the signal is inherent to PostgreSQL (pid reuse inside it is practically impossible); see RESIDUAL_RISKS_C1_3.

## 4. Test plan
All tests run in a disposable cluster (`orvix-c13-*`, `--network none`, hardened `pg_hba`):
- clean 200→221;
- 217→221 upgrade, then dump → restore → re-upgrade, with ACL assertions;
- watchdog crash injection: a real SIGKILL of the sentinel process **and** of its postgres backend, at each boundary, using locks to hold the protocol at the boundary;
- recovery and authentication races; notification outages and slow acks; tenant isolation; privilege escalation attempts, including cross-database;
- the full TypeScript, SQL and e2e suites; runtime drivers for the application.
