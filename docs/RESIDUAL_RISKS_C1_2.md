# C1.2 status of the C1.1 MEDIUM risks: mitigations vs inherent limits

"Mitigation" means implemented and tested here. "Inherent" means it cannot be removed while the stated precondition holds. Nothing below is claimed resolved just because tests pass.

## RM-1: Relayed passkey ceremonies

| | |
|---|---|
| **Mitigations (212, 215)** | Independent out-of-band notices (`docs/OOB_NOTIFICATIONS.md`). They are written in the same transaction as the effect, delivered by a separate process under a separate credential to host-configured channels, and the app cannot suppress or forge them. **Delivery gating:** a rogue passkey stays unusable until its notice is delivered (ack-verified, 217), plus 15 minutes **counted from delivery**; a recovery link stays unredeemable until its approval is announced; an invited operator needs a delivered notice **and** host approval with a **public-key** fingerprint check (217). New-device sign-ins are notices too. |
| **Inherent** | A compromised origin can still obtain **one** grant per operator ceremony, for an action of its choice (authenticators do not display intent). It can also keep any session it is given. During an invitation it can swap in its own key **and** show the invitee the matching fingerprint (RECOVERY.md, R-11). The mitigations make the outcome **visible and time-boxed**, not impossible. |
| **Residual severity** | LOW for a local checkpoint, provided a host channel is configured and read. MEDIUM if no one watches the channel. |

## RM-2: Global login-challenge exhaustion

| | |
|---|---|
| **Mitigations (213)** | A per-device bucket for any browser that has signed in before. It uses an opaque device token with no authentication power. An anonymous flood cannot drain it. A hard ceiling on outstanding challenges bounds total creation. Expired challenges and dead device rows are purged opportunistically. Devices of revoked identities are not honoured, and emergency revoke and recovery redemption revoke an identity's devices. **At most 5 live devices per identity** (217), so one passkey holder can no longer mint enough buckets to reach the ceiling. |
| **Inherent** | First sign-in on a **new** device (or after cookies are cleared) still shares the anonymous bucket, so a flood can delay it. The ceiling, once reached, also blocks devices; it is sized at 500 open challenges against an anonymous rate of 20 per 15 minutes. A stolen device cookie grants only that device's bucket; whoever holds it can drain that bucket, and an exhausted device bucket does not fall back to the anonymous one. Reaching the ceiling still needs many operators acting together (≈ 10 identities × 5 devices × 10). |
| **Residual severity** | LOW (availability only; loopback plus SSH tunnel exposure). |

## RM-3: Open-transaction and audit-lock abuse (requires the `control_app` password)

| | |
|---|---|
| **Mitigations (210, 214, 217)** | **Default limits:** `transaction_timeout = 10s` is a role default, applied cluster-wide on every migrate run whatever the ledger says (217). **Watchdog** (enforced, independent of client settings): the sentinel terminates `control_app` sessions **of its own database** idle in a transaction for more than 5 s, or with a transaction older than 15 s. The kill is audited and announced (except after a sentinel crash at the wrong moment: W-1 below). Backends queued behind a victim are terminated too. Each kill is recorded **without the audit lock** (`watchdog_kills` and an immediate out-of-band notice), so `control_app` cannot suppress it, and it is folded into the hash chain when the lock is next free (217). **Advisory locks:** `control_app` can no longer take any advisory lock (session locks would survive the transaction checks) and can no longer run `DO` blocks (217). **Prepared transactions:** the server refuses to start unless `max_prepared_transactions = 0` (217). **Stale transactions:** auth entry points refuse a transaction more than 5 s old. **Shadow audit evidence:** each audit row is first written to the PostgreSQL **server log** (`RAISE LOG`). That is not undone by ROLLBACK, and `control_app` cannot lower `log_min_messages`. Each line carries the database name and an **HMAC** keyed by a secret only the audit owner and the superuser can read (217), so forged lines (statement echoes, other databases) are rejected and counted. `scripts/audit-shadow.ts` lists rolled-back audit events of one database, with xid and session user, and escapes every printed field. **Startup and 30-second re-check** of the exact role defaults, plus an atomic reset on every migrate run. **Secret separation (C1.2):** the web server no longer has the superuser password in its environment (`.env.host` split). |
| **Inherent** | Anyone holding the `control_app` password can open transactions and change their own session settings, because PostgreSQL allows every role to. An attacker with reconnecting connections can keep re-taking the audit lock between watchdog passes (≤ ~2 s poll + 5 s idle threshold each time). Audited calls stall and fail closed after a 3 s lock wait, and folding kill records into the hash chain is postponed. Each kill is still announced at once, and `host notify-status` shows `watchdog_kills_not_in_chain`. This availability attack needs the app credential and is inherent. `control_app` can also make the shadow tool report "forged" lines on demand (alarm fatigue; it cannot create a line that verifies). Rolled-back events are **detected**, not **prevented**. Rate-limit counts can still be undone by rollback; that costs CPU only, because evidence must still verify. A superuser can disable the watchdog, logging or triggers. |
| **Residual severity** | LOW–MEDIUM. The precondition (app credential theft) is equivalent to app compromise. Detection and bounded DoS are now in place. |

## New C1.2 limitations to know

- The sentinel is now a **liveness dependency** for gated actions: if it stops, new passkeys, recovery redemptions and operator activations wait. This is fail-closed by design; monitor it.
- In local development the sentinel, the app and the host tools share one OS user, so separation there is by credential only.
- The shadow log depends on PostgreSQL logging being retained. A production log pipeline (rotation, retention, off-host copy) is an infrastructure task.
- Every audited statement is echoed to the server log (`RAISE LOG` counts for `log_min_error_statement`). API calls use bind parameters, so values are not logged; host actions must go through `npm run host` (bind parameters), never psql with literals. The migrator suppresses statement logging while it sets passwords (217).
- Same OS user in development: any code execution in the web server can read `.env.host` and `.env.sentinel` (mode 0600 but the same user), and the container's `POSTGRES_PASSWORD` is the superuser password. In production these must be separate OS users or hosts.
- The web server re-checks role settings every 30 s, so altered settings can apply to new connections for up to 30 s before it refuses to serve.

## Watchdog evidence gaps (found during checkpoint preparation, 2026-10-20)

These were found by testing the watchdog directly, not inferred from the reconnecting-worker tests. Security code and migrations were **not** changed for them in C1.2.

### W-1: a crash between termination and recording leaves a kill with no record (LOW; production blocker)

**What:** `sentinel_watchdog` terminates backends with `pg_terminate_backend`, which takes effect immediately and cannot be rolled back. It then writes the `watchdog_kills` row and its out-of-band notice in the **same transaction**. If the sentinel process, its connection or the database host dies after the kill but before that transaction commits, the backend stays terminated but nothing is kept: no kill record, no notice, no audit row. The only trace is PostgreSQL's generic `FATAL: terminating connection due to administrator command` line for the victim in the server log. That line has no MAC, does not name the watchdog, and no tool reconciles it.

**Who can trigger it:** not `control_app`. It needs a process or host crash, or someone with OS or superuser access. In local development the app and the sentinel share an OS user, so code execution in the web server could kill the sentinel at that moment (see "Same OS user" above).

**Reproduction** (throwaway database, kept under the session scratch directory as `wdcrash.mts`):
1. A `control_app` session opens a transaction and goes idle.
2. A superuser session holds `LOCK TABLE control.watchdog_kills IN ACCESS EXCLUSIVE MODE`, standing in for "the commit never happens".
3. After the idle threshold, `sentinel_watchdog(2, 15)` runs. It terminates the victim (confirmed gone from `pg_stat_activity`), then blocks on the insert.
4. The sentinel backend is terminated, simulating the crash: the pass ends with `57P01`.

Result: `watchdog_kills` = 0, `watchdog_terminated` notices = 0, audit rows = 0. Only the generic `FATAL` line is in the server log.

**Required before production:**
- **Durable pre-kill intent:** before each `pg_terminate_backend`, write evidence that survives a rollback or crash. For example, a MAC-protected `RAISE LOG` intent line (pid, database, reason, pass id), in the same format as the shadow lines, or an intent row committed in its own transaction before the kill.
- **Reconciliation:** extend `scripts/audit-shadow.ts`, or add a host check, to match every intent line to a `watchdog_kills` row and its notice. Report intents with no record, and generic `terminating connection` lines with no matching intent.

### W-2: `watchdog_kills` blocks deletes but not updates (INFO)

The table has `BEFORE DELETE` and `BEFORE TRUNCATE` triggers but no `BEFORE UPDATE` trigger: `watchdog_fold` legitimately sets `audit_seq`. No runtime role (`control_app`, `control_sentinel`, `control_watchdog_owner`, `control_auth`, `control_definer`) has **any** privilege on it (verified with `has_table_privilege`). Only SECURITY DEFINER functions owned by `control_audit_owner`, or the superuser, can change a row. Folded rows are protected by the hash chain (the audit row repeats `terminated`, `pids`, the record id and `recorded_at`). An unfolded row can be altered only by the superuser, which is infrastructure trust. A later migration could restrict updates to setting `audit_seq` once.

### W-3: a kill record is outside the hash chain until folded (INFO)

The kill record and its notice are written without the audit lock (that is what defeats the reconnecting-worker attack). Until `watchdog_fold` succeeds, the record is not in the hash chain or in offline anchors. During that window the independent evidence is the **out-of-band notice**, which carries `"seq": null`. The notice is sent at once and does not depend on the fold. `npm run host -- notify-status` shows `watchdog_kills_not_in_chain`. A superuser could delete an unfolded record by disabling its trigger; the notice already delivered would still show the kill.

### W-4: false "rolled back" watchdog events from `audit-shadow` (LOW, alarm fatigue)

**Why it happens:** `watchdog_fold` calls `audit_append`, which writes its shadow line **before** taking the audit lock. When the lock is held (for example by an attacker's open transaction), the fold hits its 1 s `lock_timeout` and rolls back. The shadow line stays, so `audit-shadow` reports a ROLLED BACK `platform.watchdog_terminated` event (exit code 3). A later pass folds the same record successfully under a new shadow id. Reproduced: two shadow lines for one kill, one committed and one reported as rolled back.

**How to tell it apart from real evidence loss:** a fold attempt's shadow line has `target_type = "watchdog_kill"` and `target_id` = the kill record id. For each such ROLLED BACK line, look the record up:

```sql
SELECT id, recorded_at, audit_seq FROM control.watchdog_kills WHERE id = <target_id>;
```

| Outcome | Meaning |
|---|---|
| Row exists, `audit_seq` set | **Benign.** It was folded on a later attempt; the chain has it. |
| Row exists, `audit_seq` NULL | **Benign but pending.** It is still waiting for the lock; check `notify-status` (`watchdog_kills_not_in_chain`) and that its notice was delivered. |
| No row | **Not benign.** The record is gone (possible only through the superuser). Investigate. |

A rolled-back line for any **other** action, or a watchdog line whose `target_type` is not `watchdog_kill`, is genuine evidence of a rolled-back audit event. W-1 kills never appear here, because the kill record is not written through `audit_append`.

## Side effects of testing on the local cluster

Test runs create and drop throwaway databases on the same PostgreSQL server as the development database. Roles and role settings are **cluster-wide**, so testing changed the server, not just the throwaway databases:

- The roles `control_sentinel` (LOGIN) and `control_watchdog_owner` (NOLOGIN; member of `pg_signal_backend` and `pg_read_all_stats`) now exist on the server. Neither has CONNECT on, or any object in, the development database.
- `control_app`'s cluster-wide defaults now include `transaction_timeout=10s`; every test run re-applies the full canonical set. The C1.1 server code at commit `810d570` checks for the exact C1.1 set, so it would refuse to start against this cluster until the role is reset or the development database is migrated.
- The development database `orvix_control` itself was **not** migrated: its ledger is at 211 (12 rows, checksums match the committed files), it contains no 212+ objects, the contract is `orvix-control/0.3`, it has 0 operators, and its chain verifies.
