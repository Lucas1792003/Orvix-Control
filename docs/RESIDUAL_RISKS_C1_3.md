# C1.3 residual risks (after migrations 218–221)

"Fixed" means implemented **and** tested in a disposable cluster, including real process crashes where relevant. "Inherent" means it cannot be removed while the stated precondition holds.

## W-1 watchdog durability: FIXED (protocol), with documented limits

- **Fixed:**
  - A backend is terminated only after a committed `armed` intent exists, and the intent notice is enqueued at PLAN.
  - The C1.2 window (kill, then crash before the record) now leaves `armed` + notice, which RECONCILE resolves to `terminated_unconfirmed` and folds into the chain.
  - Tested with real SIGKILLs at four points: the database backend during PLAN, after the kill, and during the fold; and the sentinel process mid-PLAN.
- **Limits:**
  - **Asynchronous ARM commit (LOW, sentinel credential only):** every step forces `synchronous_commit=on` for its own transaction. A caller holding the sentinel credential can still run `SET LOCAL synchronous_commit = off` after ARM returns and before its COMMIT, making that commit asynchronous. The intent is lost only if the database crashes inside the WAL writer's sub-second window between that commit and the kill, and the credential holder cannot cause that crash (an attempt in review did not lose the intent). A bounded "wait for WAL flush" in EXECUTE was tried and removed: SQL cannot see the commit LSN of ARM, so the guard skipped honest kills.
  - **Unconfirmed SIGTERM:** if `pg_terminate_backend(pid, 250)` times out and the caller rolls the EXECUTE transaction back while the target is still exiting, RECONCILE can record `abandoned_armed` although a SIGTERM was sent. The intent and its notice still exist.
  - **Kill threshold:** the sentinel credential can have any `control_app` transaction older than 5 s (or idle in a transaction for 2 s) terminated, by design.
  - `terminated_unconfirmed` means a kill *may* have happened: the target was gone, but the cause (the kill, or the crash itself) is unknown. The evidence is the intent and its notice, not proof of the kill.
  - Interrupted intents are resolved after 10 s of staleness. In between, they show as `open_intents`, then `interrupted_intents` after 30 s.
  - A superuser can still disable triggers or delete rows (infrastructure trust).

## C1.2 runtime MEDIUM findings

| # | Status | Residual |
|---|---|---|
| M1 recovery leaves the thief's invitations/approvals | **Fixed** (frozen while the owner is under recovery, voided at redemption) | Other actions the stolen credential already completed (tenant transitions, passkey revocations, cancelling others' recoveries) are audited and announced, not reversed. |
| M2 anonymous bucket locks out recovered/new owners | **Fixed for enrolled browsers**: every enrolment ceremony issues a device token | A **never-enrolled** browser (e.g. a new laptop without recovery) still uses the shared anonymous bucket and can be delayed by a flood. Removing that needs a trusted client identity (per-IP behind a trusted proxy): **owner decision R-13**. |
| M3 other databases undo the hardening | **Fixed with cluster prerequisites**: `pg_hba` reject rules (TCP and local socket), `harden-cluster`, startup refusal | Requires the cluster to be dedicated to Orvix Control (the hardening changes `postgres`/`template1`). The startup check sees database ACLs, not `pg_hba`; the migrator evaluates `pg_hba` in rule order and exits 3 when exposed. A **control-named** sibling database that is hardened but behind on migrations is reachable (by name) and keeps its older grants: `harden-cluster --check` reports it. In production, list the single control database by exact name in `pg_hba`. |
| M4 restore leaves PUBLIC ACL | **Fixed**: migrate re-asserts every run (also stripping extra per-role grants), startup refuses until then; a `--no-owner`/`-x` restore (by any role) is refused at startup | Between a restore and the next migrate, the database is open to other cluster roles (connect/temp); the app and sentinel refuse to run in that state. |
| M5 torn file notice counted as delivered | **Fixed**: full write loop, fsync, read-back compare, newline framing, link/FIFO/symlink checks | Two sentinels appending to the same file can interleave; the read-back then fails and the delivery is retried (duplicates possible; receivers dedupe on `notice_id`). A hung filesystem still blocks that worker's event-loop turn (synchronous I/O). |
| M6 one stalled webhook delays all channels | **Fixed**: one worker per channel, 5 items per claim, 40 s lease | A stalled channel still delays **its own** later notices (in-order delivery per channel). |
| M7 host status misleads | **Fixed** (heartbeat on every idle tick; overall state includes `watchdog_down` and `no_host_channel`): per-channel `healthy` / `busy` / `retrying` / `delayed` / `failing` / `disabled` / `disabled_pending` (informational: a host-disabled channel no longer blocks the gate); overall `sentinel_down`; watchdog liveness and intent health; NOTIFY queue usage | States are threshold-based (60 s for delayed/failing, 30 s for the sentinel heartbeat). |

## Sentinel trust (independent review)
- **Webhooks with an ack key:** a webhook channel with an **ack key** (`host_set_notify_ack_key`; `npm run host -- notify-add` sets one in the same transaction) is verified **in the database**. The ack binds the notice id, the timestamp and the SHA-256 of the exact canonical body that the database hands the sentinel. The sentinel never reads the ack key, so its credential alone can neither mark such a delivery delivered nor get a forged body acknowledged under a real notice id.
- **File channels and legacy webhooks:** file channels, and webhook channels without an ack key, still depend on the sentinel's honesty. A compromised sentinel credential can open their gates.
- **Unlimited WAL / transaction IDs:** `pg_logical_emit_message`, `txid_current` and `pg_current_xact_id` are revoked from PUBLIC. Ordinary writes still consume transaction IDs (rate-limited by the API).

## C1.2 runtime LOW findings

| Finding | Status |
|---|---|
| Emergency-revoke contest window (24 h) | Fixed: any revoke after the subject's last recovery contests |
| Activity after approval | Fixed: redemption refuses `RECOVERY_CONTESTED` and reopens the request (link voided) |
| Mid-recovery owner privileges | Fixed. Every step-up action and anchor signing are paused (`IDENTITY_UNDER_RECOVERY`), except revoking a passkey, revoking an invitation and contesting one's own request. The identity's invitations and approved recovery links are frozen until its recovery completes (then voided). **Limits:** a contest by the subject does **not** end the pause (only the host or another owner cancelling the request does); tenant transitions that need no step-up (e.g. `past_due`) and a passkey add already begun before the request are not paused (the new passkey is pending and disabled at redemption). |
| Expired requests unaudited | Fixed: `recovery_cancelled` / `EXPIRED` |
| Disabled owner channels block | Fixed: host-disabled channels stop counting, and suspended owners are no longer recipients |
| `audit-shadow` upgrade false positives | Fixed: `legacy` / `malformed` / `foreign` counted separately; folds no longer leave rolled-back lines; missing rows are labelled "rolled back or deleted" |
| Multiple sentinels | Fixed: connection limit 12, unique open intent per target, claim tokens |
| Stale ack lease race | Fixed: claim token |
| Hard-linked file targets | Fixed (`nlink` check, plus FIFO/symlinked-parent refusal) |
| Cloned passkey keeps sessions | Fixed: sessions and grants end; step-up and anchors refuse; a flagged passkey no longer counts as "usable" for `LAST_OWNER` / `LAST_CREDENTIAL`. Sign-in stays allowed so the owner is not locked out. **Limits:** whichever copy (genuine or clone) is behind on the counter is refused at sign-in; the one that is ahead can sign in again, so "loses its sessions" holds only until its next sign-in. |
| Revoked owners appear active | Fixed: `suspended` state |
| NOTIFY privilege bypass | **Mitigated, inherent:** PostgreSQL has no `NOTIFY` privilege. A small `max_notify_queue_pages`, the `pg_hba` cross-database reject, the watchdog (kills idle-in-transaction listeners) and the status `notify_queue_usage` bound it. A listener that is idle *outside* a transaction can still hold the queue tail until the queue limit is reached (NOTIFY then fails cluster-wide; the app does not use NOTIFY). |
| Cross-tenant request-id response | Fixed: `REQUEST_ID_CONFLICT` |
| Orphaned Next.js test processes | Fixed: the e2e suite starts `next` in its own process group and kills the group |
| Excessive claim lease (349 s) | Fixed: 40 s |

## New in C1.3 testing
- **PID-1 orphan reaping:** with the postmaster as PID 1, an orphaned process that dies by a signal (e.g. an interrupted `docker exec … pg_dump | …` pipeline) is treated as a crashed backend and the **whole cluster restarts**. Fixed in the compose file (`init: true`) and the test runner (`--init`). **Applies to the existing development container until it is recreated.**
- **Flagged passkey and step-up:** an owner whose only passkey is flagged can sign in but cannot step up, so cannot add a new passkey. They need recovery through another owner (by design; see R-3/R-7).

## Unchanged from C1.2 (still inherent or owner decisions)
- **Relayed ceremonies:** one grant per ceremony, and the activation key swap (R-11).
- **App credential holders** can stall audited calls between watchdog passes. That is detected and bounded, not prevented.
- **Shared OS user in development;** separate OS users are required in production.
- **Log pipeline:** retention and an off-host copy are required (shadow evidence).
- **Every owner losing every passkey** can only be recovered by a restore.
