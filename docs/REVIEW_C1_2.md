# C1.2 independent reviews

## Part A: independent review of migration 211 and its tooling (C1.2 Step 1)

Scope: `db/migrations/211_*.sql`, `scripts/verify-audit.ts`, `scripts/anchor-sign.ts`, `scripts/migrator.ts`, `src/server/db/api.ts` startup checks.

**Result: no CRITICAL, no HIGH.**

| # | Severity | Finding | Resolution |
|---|---|---|---|
| A-1 | LOW | CLI error output echoed untrusted text (identifiers, jsonb) without escaping control or invisible characters | Shared `safe()` in `verify-audit.ts`: printable ASCII only, all else `\uXXXX` / `\u{…}`; used by `anchor-sign` `REFUSED` messages and summaries |
| A-2 | LOW | `safe()` was incomplete (CR, bidi and zero-width characters passed through) | Fixed by A-1; tests in `anchors.test.ts` |
| A-3 | LOW | The startup role-config check could be bypassed by per-database settings or by settings drift after startup | Exact sorted `rolconfig` match, no per-database settings, effective-value checks, re-check every 30 s (`src/server/db/api.ts`) |
| A-4 | LOW | `setAppPassword` reset and re-applied role settings in separate statements (non-atomic window) | Runs in one `BEGIN … COMMIT` with `RESET ALL` plus per-database resets (`scripts/migrator.ts`) |
| A-5 | LOW | Passkey activity was not inherited by a re-filed recovery request (objections were since 211) | Migration 216: activity measured from the earliest request for the subject within `recovery_max_lifetime_seconds` |
| A-6 | INFO | The `LAST_OWNER` guard in `host_revoke_operator_credentials` relies on READ COMMITTED | Migration 216: `assert_read_committed()` |
| A-7 | INFO | `--confirm-head` confirmed only the sequence number, not the hash | Now `<seq>:<12-hex hash prefix>` and must match exactly |
| A-8 | INFO | One concurrency test is timing-based | Accepted; it asserts outcomes, not timing |
| A-9 | INFO | A reopen deadlock is theoretically possible but practically unreachable under the documented lock order | Accepted, documented |
| A-10 | INFO | The 7-day inheritance window is a policy value | Listed as an owner decision (see `RECOVERY.md`) |

## Part B: C1.2 independent reviews (Step 5)

Four independent reviewers worked in parallel. Each saw the code for the first time, worked read-only, and used throwaway `orvix_control_test_*` databases only. Columns: **Rv** is the reviewer (1 authentication and WebAuthn, 2 PostgreSQL privileges and transactions, 3 recovery and multi-owner, 4 audit evidence and out-of-band notifications). **V** is verified by a reviewer's proof of concept; **R** is reasoned.

| # | Sev | Rv | V/R | Finding | Resolution (migration 217 unless stated) |
|---|---|---|---|---|---|
| B-1 | **HIGH** | 2, 4 | V | `control_app` could crash the sentinel. After the watchdog killed a lock holder, a queued backend inherited the audit lock, and the watchdog's audit write hit its 10 s timeout. The process exited, stopping delivery and the watchdog. | Each kill is recorded **without the audit lock** (`watchdog_kills` plus an immediate out-of-band notice to host channels and owners) and folded into the hash chain later, when the lock is free (1 s try per pass). Backends queued behind a victim are terminated too, after a fresh `pg_stat_activity` snapshot. The watchdog filters on its own database. `sentinel.ts`: delivery and the watchdog are independent loops on separate pools, errors never end the process, and there is a heartbeat. (A first version with a retry loop was found incomplete by the re-review: C-1.) |
| B-2 | **HIGH** (Rv 4) / MEDIUM (Rv 2) | 2, 4 | V | Forged shadow lines: `control_app` could write `ORVIX_AUDIT_SHADOW` lines (DO block, statement echo). These crashed `audit-shadow.ts`, flooded it with fake rolled-back events, and injected terminal escapes; lines from other databases were mixed in. | Each line carries an HMAC-SHA256 over the exact JSON text, keyed by `control.audit_shadow_key` (audit owner and superuser only), plus the database name. The parser verifies MAC, database and UUID, counts forged lines (exit 4), and prints through `safe()`. `plpgsql` USAGE is revoked from PUBLIC. `--db` is name-checked. |
| B-3 | MEDIUM | 1, 3 | V | The activation fingerprint was 8 characters of the authenticator-chosen credential id, so an attacker could match the invitee's. | 64 bits of SHA-256 over the **public key** (`credential_fingerprint`). Host comparison ignores case and separators. The residual compromised-origin key swap is documented (RECOVERY.md, R-11). |
| B-4 | MEDIUM (Rv 3) / LOW (Rv 1) | 1, 3 | V | The inviter check passed after the inviter's emergency revoke, and open invitations stayed usable. | Host revoke voids invitations the identity issued or is the subject of (audited `INVITER_REVOKED`). Approval refuses an inviter emergency-revoked after inviting. The test now uses the real host path. |
| B-5 | MEDIUM | 3 | V | A recovery link approved by an owner who was later revoked still worked. | Host revoke reopens requests the identity **approved**. Redemption refuses if the approver was emergency-revoked after approving. |
| B-6 | MEDIUM | 3 | V | `LAST_OWNER` counted an owner who was mid-recovery, allowing a double lockout. | Owners with an open recovery request as subject are excluded. "All owners lose all passkeys requires a restore" is documented. |
| B-7 | MEDIUM | 4 | R | The 15-minute passkey window counted from creation, so delayed delivery could consume it. | The window counts from **delivery** (`notification_delivered_at`). |
| B-8 | MEDIUM | 4 | V | Deliveries gave up after 20 attempts with no requeue. | Retries never stop (backoff capped at 300 s, overflow guarded). Host status shows `stuck`, `blocked_by_disabled_channel` and `sentinel_last_claim_at`. |
| B-9 | MEDIUM | 4 | V | Any 2xx counted as delivered, so an impostor receiver could open a gate. | The receiver must return `X-Orvix-Ack = HMAC(secret, "ack.<notice_id>.<ts>")` (constant-time check). Webhooks must be https or loopback http; file targets must be absolute and are opened with `O_NOFOLLOW`. |
| B-10 | MEDIUM | 2 | V (part) | Session advisory locks were invisible to the watchdog and could fill the lock table. | All advisory-lock functions are revoked from PUBLIC; transaction-scoped variants are granted to owner roles only. |
| B-11 | MEDIUM | 4 | — | The docs overstated the guarantees (watchdog bound, reaction window, lost notices, forgeable shadow, unauthenticated ack, replay window). | Rewritten: OOB_NOTIFICATIONS.md (receiver contract: 300 s skew, dedupe on `notice_id`, ack), RESIDUAL_RISKS_C1_2.md, RECOVERY.md. |
| B-12 | LOW | 1, 3 | V | Expired-but-enrolled or revoked invitee emails could never be re-invited. | A never-activated identity can be re-invited; old link and passkey voided. Recorded as R-10. |
| B-13 | LOW | 3 | V | A re-invite silently closed the old invitation and could change the role. | The audit detail carries `replaced_invitation`, `previous_role` and `previous_state`. |
| B-14 | LOW | 1 | V | Unlimited device tokens per operator let an insider reach the challenge ceiling. | At most 5 live devices per identity (least recently used revoked); dead rows purged. R-12. |
| B-15 | LOW/INFO | 1 | V | Recovery redemption did not revoke the subject's device tokens. | Revoked on redemption (and on host revoke). |
| B-16 | LOW | 2 | V | Literal SQL values (e.g. secrets) are echoed to the server log by audited statements; the migrator sent plaintext passwords. | The migrator sets passwords with `log_statement=none` and `log_min_error_statement=panic` (transaction-local). The host CLI uses bind parameters, and the rule is documented. |
| B-17 | LOW | 2 | R | The watchdog was cluster-wide. | Own-database filter (in B-1); test with a second database. |
| B-18 | LOW | 2 | V | A partially migrated test database weakened `control_app`'s cluster-wide settings. | The migrator always applies the full canonical set; tested. |
| B-19 | LOW | 2 | R | The sentinel loaded the superuser password. | `loadSentinelEnv()`: target plus own credential only (superuser and app passwords removed). |
| B-20 | LOW | 4 | R | `recovery_host_confirmed` and owner-cancelled recovery notices did not reach the subject. | `subject` added to the detail; tested. |
| B-21 | LOW | 4 | — | The 30 s claim lease was shorter than a delivery pass. | Lease is at least `limit × 7 s` (duplicates are still possible after a restart; receivers dedupe). |
| B-22 | LOW | 4 | — | A disabled channel blocks pending gated items. | Documented (R-9); status shows the count. |
| B-23 | LOW | 4 | — | The file channel followed symlinks. | `O_NOFOLLOW`; absolute paths only. |
| B-24 | LOW | 3 | — | R-4 did not cover invitations. | R-4 reworded. |
| B-25 | LOW | 3 | — | The enrol page gave the wrong expiry for invitations. | Text fixed. |
| B-26 | INFO | 2, 4 | — | `max_prepared_transactions` must stay 0. | Startup and 30 s re-check. |
| B-27 | INFO | 3 | — | `host_approve_operator` did not assert READ COMMITTED. | Asserted. |
| B-28 | INFO | 1 | — | New-device sign-ins were not announced. | They are now notices. |
| B-29 | INFO | 1 | R | An exhausted device bucket does not fall back to anonymous (a planted cookie could block one browser). | Accepted; documented in RESIDUAL_RISKS_C1_2 RM-2. |
| B-30 | INFO | 3 | R | Possible self-deadlock: inviting one's own email while revoking one's own passkey. | Accepted: Postgres aborts one; no security effect. |
| B-31 | INFO | 2 | — | Same OS user: the web server can read `.env.host` and `.env.sentinel`, and the container env holds the superuser password. | Documented as a development limitation; production must separate users. |
| B-32 | INFO | 2 | — | 30 s re-check window; `control_app` can terminate its own role's backends; theoretical pid reuse. | Documented / accepted. |
| B-33 | INFO | 4 | — | The sentinel can read webhook secrets (a compromised sentinel can forge receiver notices). | Documented (OOB_NOTIFICATIONS.md limits). |
| B-34 | INFO | 1 | — | `platform.login_device_issued` is registered but unused. | Accepted (the information is in `login_succeeded.new_device`). |

**Sound by all four reviewers:**
- No session, step-up grant or anchor without a valid passkey signature verified in the database.
- Pending or undelivered passkeys are refused everywhere (login, step-up, anchor, last-credential rule).
- `pending_approval` and `enrolling` identities cannot sign in.
- Token purposes are not confused.
- `control_app` and `control_sentinel` cannot reach another role's tables or functions.
- Notices are atomic with their effect and cannot be edited, deleted or forged by the app.
- The audit chain is unaffected by `shadow_id`.
- All migrations' `SECURITY DEFINER` functions pin `search_path`.

### Verification after fixes

- `npm test`: **224/224** passed (12 files), including 13 new regression tests for 217 and updated tests for changed behaviour.
- `npm run test:e2e`: **23/23** passed.
- `npx tsc --noEmit`: clean.

### Re-review of the fixes (independent, fifth reviewer)

**Result:** H2 and every MEDIUM/LOW fix **closed**; owners and ACLs of all 17 replaced functions are identical before and after 217; lock order is OK. H1 was **partially closed** in the first version. Its findings:

| # | Sev | V/R | Finding | Resolution |
|---|---|---|---|---|
| C-1 | MEDIUM | V | Reconnecting `control_app` workers (6–7) kept re-taking the audit lock, so all 4 audit retries failed. The kill went unaudited and unannounced, and the fallback log line had no reader. Causes: `pg_stat_activity` is cached per transaction; fresh active holders were not targeted. | Redesigned (above, B-1): the lock-free kill record and notice. The reviewer's own harness, rerun against the new code in idle, active and mixed modes with 7 workers, gives one kill record and one notice per kill pass, with a pass time of about 1.8 s. Folding into the chain waits while the attack lasts; `host notify-status` shows `watchdog_kills_not_in_chain`. New regression test: kill recorded and announced while another backend holds the audit lock, then folded on the next pass, with the chain still verifying. |
| C-2 | LOW | R | Catching `query_canceled` swallowed the statement timeout. | That handler is gone: the only catch is `lock_not_available` around the fold. |
| C-3 | LOW | V | `control_app` can raise "forged" alarms on demand (statement echoes of marker text) and replay genuine lines (deduplicated). | Accepted: alarm fatigue only; it cannot create a line that verifies. Documented. Attribution via `log_line_prefix` or jsonlog is future work. |
| C-4 | LOW | R | A FIFO at a file-channel path could freeze the sentinel. | `O_NONBLOCK` and an `fstat` regular-file check. |
| C-5 | LOW | V | The https/loopback constraint is `NOT VALID`, so rows from before 217 are not checked. | The sentinel checks the scheme itself before every webhook delivery. (The dev database has no channels.) |
| C-6 | LOW | R | A black-holed receiver's backlog could delay fresh notices. | Claims are ordered by fewest attempts first. |
| C-7 | LOW | V (not exploitable today) | Password log suppression missed `log_min_duration_*`. | Also set transaction-locally. |
| C-8 | INFO | — | The sentinel still reads `.env.local` (it drops the app password in-process). | Documented; production should give the sentinel its own target file. |
| C-9 | INFO | — | 18 leftover test databases. | They came from an early failing test run of 217 in this session; dropped (test-name pattern, no connections). |

### Final verification

- `npm test`: **225/225** passed (12 files).
- `npm run test:e2e`: **23/23** passed.
- `npx tsc --noEmit`: clean.
- The development database `orvix_control` was not migrated: ledger at **211**, 12 rows, unchanged.
