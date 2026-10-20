# C1.3 independent reviews

Four fresh, read-only reviews ran in disposable clusters (`orvix-c13-runner`, and `orvix-c13-crash` for crash experiments). They were followed by two verification reviews of the fixes. **V** marks a finding the reviewer verified by experiment; **R** marks one established by reasoning.

## Round 1: four reviews of the first C1.3 implementation

### 1. Watchdog crash consistency and audit durability
Result: **2 HIGH**, 1 MEDIUM, 5 LOW. Properties 1, 7 and 8 failed.

| # | Sev | V/R | Finding | Resolution |
|---|---|---|---|---|
| H-1 | **HIGH** | V | The sentinel credential could run PLAN, ARM and EXECUTE in one transaction, then roll back: the kill happened and no evidence survived. | ARM and EXECUTE refuse when the transaction has already written (`watchdog_assert_own_transaction`). |
| H-2 | **HIGH** | V | RECONCILE raced EXECUTE and recorded a real kill as "abandoned_armed". | EXECUTE locks and re-reads the intent row; RECONCILE uses `FOR UPDATE SKIP LOCKED` and counts only successful transitions; a failed transition raises. |
| M-1 | MEDIUM | V | The caller-controlled successor sweep killed unrelated, legitimate sessions. | Removed; EXECUTE re-checks that the target still qualifies. |
| L-1 | LOW-MED | V | With `synchronous_commit=off`, an intent was lost in a crash. | Forced on in all four steps. |
| L-2 | LOW | V | Intents resolved without a kill were not announced. | `watchdog_intent_resolved` added to the notice list. |
| L-3 | LOW | V | An intent stayed open forever after a database rename. | RECONCILE resolves intents of any database name. |
| L-4 | LOW | V | A fold timeout after the shadow line left a false "missing" entry. | The audit lock is taken (with a timeout) before any append; appends then run without a timeout. |
| L-5 | LOW | R | "terminated" did not mean confirmed. | `pg_terminate_backend(pid, 250)` gives `terminated`, or `terminated_unconfirmed`. |

### 2. Authentication and recovery
Result: **0 CRITICAL/HIGH**, 1 MEDIUM, 4 LOW.

| # | Sev | V/R | Finding | Resolution |
|---|---|---|---|---|
| M-1 | MEDIUM | V | `LAST_OWNER` counted an owner whose only passkey is flagged, enabling a permanent loss of owner powers. | Flagged passkeys no longer count for `LAST_OWNER` or `LAST_CREDENTIAL`. |
| L1 | LOW | V | Deadlock between recovery redemption and a concurrent cancel. | The void helpers lock every affected token and request (ordered) before any audit write. Verified: 0 deadlocks in 3 runs. |
| L2 | LOW | V | M1 did not cover the window while the compromised owner was under recovery. | `INVITER_UNDER_RECOVERY` and `APPROVER_UNDER_RECOVERY`. |
| L3 | LOW | V | `IDENTITY_UNDER_RECOVERY` paused less than documented. | Every step-up action except the protective ones, and anchors, are paused (begin and use). |
| L4 | LOW | V | Host revoke did not audit the subject's own reopened requests. | One `recovery_link_voided` / `SUBJECT_REVOKED` row each. |

### 3. PostgreSQL privileges and restore safety
Result: **0 CRITICAL/HIGH**, 3 MEDIUM, 5 LOW.

| # | Sev | V/R | Finding | Resolution |
|---|---|---|---|---|
| F1 | MEDIUM | V | An unhardened, control-named sibling database was invisible to the check. | Counted as exposed unless hardened. `harden-cluster` reports control-named siblings behind the latest migration (round 2). |
| F2 | MEDIUM | V | A `--no-owner` restore made the superuser own everything, unnoticed. | Refused when any `control` object is owned outside the five owner roles. |
| F3 | MEDIUM | V | `control_app` could write unbounded WAL (`pg_logical_emit_message`) and burn transaction IDs. | Revoked from PUBLIC, and checked. |
| F4 | LOW | V | The sentinel role could relax its own defaults. | Reset on every migrate; the sentinel checks its role and per-database settings and live values, and re-checks every 30 s. |
| F5 | LOW | V | Extra per-role database grants survived a migrate. | Every migrate strips all, then grants CONNECT; CREATE is detected. |
| F6 | LOW | R | The sentinel only checked privileges at startup. | It now re-checks every 30 s. |
| F7 | LOW | V | Local-socket `trust` bypassed the pg_hba reject. | `local … control_app,control_sentinel reject`. |
| F8 | LOW | R | The pg_hba report was weak, and the migrator only warned. | Rule-order evaluation (groups, addresses), and migrate exits 3 when exposed. |
| F9–F12 | INFO | — | Compose wiring; check breadth; doc drift; `CONNECTION LIMIT`. | Compose wires `hba_file` and the NOTIFY limit. Check broadened and template1 emptiness reported. Docs corrected. |

### 4. Sentinel delivery, monitoring and operations
Result: **0 CRITICAL/HIGH**, 2 MEDIUM, 9 LOW.

| # | Sev | V/R | Finding | Resolution |
|---|---|---|---|---|
| M-1 | MEDIUM | V | The sentinel credential could open any gate without delivering. | Webhook channels carry a database-verified **ack key** that the sentinel never reads (`host notify-add` sets one). File and legacy webhook channels remain sentinel-trusted (documented). |
| M-2 | MEDIUM | V | Status said `sentinel_down` for a live sentinel and `healthy` for a dead one. | Heartbeat on every idle tick; `watchdog_down` and `no_host_channel` added; the state is derived from the heartbeat alone. |
| L-1 | LOW | V | The waiver counted a host channel that had since been disabled. | Requires an **enabled** host channel that delivered. |
| L-2 | LOW | V | The waiver skipped the 15-minute window. | The window counts from the disable time. |
| L-3 | LOW | V | Unread error bodies held sockets (EMFILE). | The body is cancelled on every path; a failing channel backs off 1 s. |
| L-4 | LOW | R | Synchronous file I/O could freeze the sentinel. | File I/O is now async (libuv thread pool). |
| L-5 | LOW | V | Concurrent appenders failed 98 % of read-backs. | The read-back searches the region appended since the write began. |
| L-6 | LOW | R | The file could be replaced between the checks and the write; the directory was not fsynced. | The path is re-checked to be the same inode with one link; the directory is fsynced on create; group/world-writable targets are refused. |
| L-7 | LOW | V | Non-kill resolutions were unannounced. | Same fix as watchdog L-2. |
| L-8 | LOW | — | The busy flag was unreliable. | Derived from in-flight claims only. |
| L-9 | LOW | — | "blocked" was misleading after the waiver. | Renamed to `disabled_pending` (informational). |

## Round 2: verification of the fixes (fresh reviewers)

**Authentication and privileges verifier:** all HIGH and MEDIUM fixes in scope **CLOSED**. Its new LOW findings and their resolution:
- **Per-database sentinel drift:** fixed (checked).
- **Hardened but older control-named sibling:** reported by `harden-cluster`, plus production `pg_hba` with the exact database name.
- **pg_hba evaluator** ignored addresses and groups: fixed.
- **The subject's own contest does not end the pause:** documented.
- **Paused-action gaps:** anchors now paused; a passkey add already in progress and tenant transitions needing no step-up are documented.
- **Non-superuser `--no-owner` restore:** refused (owner must be one of the five roles).

**Watchdog and sentinel verifier:** **H-1 and H-2 CLOSED.**
- **H-1:** a savepoint, `arm; execute` in one transaction, EXECUTE in `BEGIN … ROLLBACK`, and an uncommitted ARM on another connection were all refused or recorded. No sequence terminated a backend without a committed armed intent.
- **H-2:** a locked row was skipped by RECONCILE and executed afterwards.
- **Closed** (each re-checked): watchdog M-1, L-2 to L-5; sentinel M-2 and L-1 to L-8.

| # | Sev | V/R | Finding | Resolution |
|---|---|---|---|---|
| V-1 | MEDIUM | R | The database-verified ack covered only the notice id, not the body: a sentinel credential could post a forged body under a real id and get it acknowledged. | The ack now binds `hex(sha256(body))` of the canonical body the database gives the sentinel (`sentinel_claim.body`), recomputed in SQL. Regression test: a forged body acked by the real receiver is rejected. |
| V-2 | LOW | V | A caller can `SET LOCAL synchronous_commit=off` after ARM. | **Residual (documented).** A bounded WAL-flush wait in EXECUTE was tried and removed, because SQL cannot see ARM's commit LSN and the guard skipped honest kills. Exploiting it needs a crash in a sub-second window that the credential holder cannot cause. |
| V-3 | LOW | R | `notify-add` set the ack key in a second statement. | Channel and ack key are now created in one transaction. |
| INFO | — | — | Unconfirmed SIGTERM can resolve as `abandoned_armed`; silent re-check failures; directory owner; kill threshold. | Re-check stops the sentinel after 3 failures; the target directory must be owned by the sentinel user or root; the others are documented in RESIDUAL_RISKS_C1_3. |

## Final verification (disposable clusters, final code)
- **Type check:** `tsc` clean.
- **SQL suite:** 264/264 (13 files), 0 unexpected crash-recoveries.
- **Crash suite:** 4/4 with real SIGKILLs: the backend during PLAN, after the kill, and during the fold; and the sentinel process mid-PLAN.
- **e2e:** 23/23, no orphan processes.
- **Upgrade 217 → 221:** byte-identical to a fresh install (`bdbfd22e37f0aa4a`); restore and re-upgrade rehearsal passes.
- **Cluster exposure:** `harden-cluster --check` reports no findings.
