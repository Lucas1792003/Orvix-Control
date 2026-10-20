# Phase C1.1 independent review log (2026-10-19)

**Reviewers.** Four reviewers, each a separate agent run in a read-only mode against throwaway `orvix_control_test_*` databases only:
1. WebAuthn and sessions
2. PostgreSQL privileges
3. Recovery and operator lifecycle
4. Audit integrity and app integration

**Method.** Three rounds:
- **Round 1:** a full review of migrations 204–206 and the app.
- **Round 2:** each reviewer re-ran its own exploits against the fixes in 207.
- **Round 3:** reviewers 3 and 4 checked the issues that *my* 207 fixes had introduced, against 208. Reviewer 3's round-3 LOWs are fixed in 209 and covered by tests, but **were not re-reviewed**.

## Round 1 → fix

| Reviewer | Severity | Finding | Fix | Re-verified |
|---|---|---|---|---|
| Privileges | **HIGH** | F1: `control_definer` owned schema `control` and the invoker-rights helpers run by `control_auth` / `control_audit_owner`; it could shadow pg_catalog functions and owned the WebAuthn settings | 207: inert `control_schema_owner` owns the schema and the shared helpers; settings move to `control_auth`; no runtime CREATE; invariant test | **FIXED** (round 2) |
| Audit | **HIGH** | HIGH-1: passkey anchors form a signing oracle (any prompt can sign a forged head) | Offline Ed25519 v2 anchors, signed only after a continuity check against the whole archive; v1 never sufficient alone | **FIXED** (round 2) |
| WebAuthn, Recovery | MEDIUM | Counter regression auto-disable could remove the last passkey | 207: refuse + flag | FIXED |
| Recovery, WebAuthn | MEDIUM | Recovery token not bound to request state; no cancel | 207/208 | FIXED |
| Recovery, WebAuthn | MEDIUM | Global enrolment/login rate-limit lockout | 207: per-token enrolment limit. **Login: accepted residual** | Enrolment FIXED; login residual |
| WebAuthn, Privileges, Audit | MEDIUM | Unthrottled, identity-attributed failure audit rows | 207/208 | FIXED (round 3) |
| WebAuthn, Audit | MEDIUM | A relayed ceremony becomes a durable passkey; A6 wording wrong | 207: pending 15 min + banner; docs corrected | **PARTIAL (inherent)** |
| Privileges, Audit | MEDIUM | `control_app` advisory-lock DoS | 207: row locks | FIXED for advisory locks; open-transaction variant is a residual |
| Audit | MEDIUM | Verifier counted an unanchored tail as verified | Verifier rewrite | FIXED |
| Audit | MEDIUM | `control_app` ROLLBACK suppresses refusal/export rows | Not fixable without an autonomous transaction; a guard was tried in 208 and rejected (it broke the extended protocol) | **Residual** |
| All | LOW | Deadlocks, grants outliving their passkey, attestation bounds, anchor re-check, body cap, unique keys, default privileges, large objects, runner guard, bootstrap re-issue, doc drift | 207/208 | FIXED |

## Round 2 (issues introduced by 207) → fix

| Reviewer | Severity | Finding | Fix | Re-verified |
|---|---|---|---|---|
| Recovery | MEDIUM | N1: SUBJECT_ACTIVE and subject-cancel let a passkey thief **veto** recovery | 208: delay + host confirmation instead of veto; host emergency revoke; flagged passkeys ignored | **FIXED** (round 3) |
| Audit | MEDIUM | NEW-1: one export with a range beyond 2^53 permanently broke offline verification and anchoring | 208: `audit_safe_detail` stores such numbers as strings; export range clamped | **FIXED** (round 3) |
| Recovery | LOW | N3: cancel vs redeem deadlock | 208: lock order tokens → request | FIXED (round 3) |
| WebAuthn | LOW | `api_login_complete` attributed pre-signature failures to the claimed operator | 208 | FIXED (round 3) |
| Privileges | LOW | `control_schema_owner` not attribute-checked | 208 | Not re-reviewed (test passes) |

## Round 3 → fix

| Reviewer | Severity | Finding | Fix |
|---|---|---|---|
| Recovery | LOW | NEW-A: a host confirmation given before an objection pre-authorised overriding it | 209: an objection clears the confirmation; the confirmation must post-date the objection |
| Recovery | LOW | NEW-B: an emergency revoke let approval skip the contest delay | 209: the revoke marks open requests as contested; `emergency_revoked_at` forces the delay |
| Audit | LOW | The shared failure-audit cap can hide a later genuine failure for the rest of the window | **Residual** (documented) |
| Audit | LOW | The concurrent-append test had become vacuous | Fixed (40 real concurrent appends) |
| Audit, Recovery | INFO | Harness flakiness when several suites migrate concurrently (cluster-wide `ALTER ROLE`, connection limit 8) | Not a product defect; the repo's runs are sequential |

## Final checkpoint review (five fresh reviewers, then re-verification)

**Reviewers:** recovery authorization (209), role separation, WebAuthn and sessions, audit-anchor continuity, multi-passkey and recovery.

**Result:** no CRITICAL or HIGH in any area. The rows below list each finding, its fix, and its status after re-verification by the reviewer who found it (210). The follow-ups fixed in 211 are LOW/INFO and covered by tests, but were **not re-reviewed**.

| Area | Class | Finding | Fix | Status |
|---|---|---|---|---|
| Recovery 209 / Multi-passkey | MEDIUM | Repeated or late objection acted as a veto (delay restarted and outlived the request) | 210: delay from the first objection; confirmation must post-date the latest objection, activity or revoke; contest extends the lifetime (≤ 7 d) | FIXED (both reviewers) |
| Recovery 209 / Multi-passkey | MEDIUM | Objection after approval accepted but ignored | 210: voids the link, back to pending; redemption re-checks | FIXED |
| WebAuthn / Multi-passkey | MEDIUM | Clone flag never set through the app (`@simplewebauthn` counter check ran first) | 210: pre-check counter 0, the DB decides; e2e test | FIXED |
| Audit | MEDIUM | Offline signer signed a rewritten unanchored tail | Signer prints a sanitised tail summary and requires `--confirm-head`; `--init` for the first anchor; doc corrected (inherent residual) | FIXED / mitigated (residual documented) |
| Recovery 209 / Multi-passkey | LOW | Emergency revoke ignored approved requests | 210 | FIXED |
| Recovery 209 | LOW | Host confirmation before activity counted | 210 | FIXED |
| Recovery 209 / WebAuthn | LOW | Expiry judged by transaction start time | 210: `assert_fresh_transaction` + `clock_timestamp()` | FIXED |
| Audit | LOW | Exported field number text; duplicate keys in canonical text; silent first use | Byte-identical PostgreSQL re-serialisation; strict parsing; `--init` | FIXED |
| Roles | LOW | A table owner could run RLS policy code as a reader (cross-role SELECT policies) | 210: all policies dropped; audit read API owned by the audit owner; `anchor_signer` function | FIXED |
| Roles | LOW | `control_app` resource abuse (`pg_notify`, temp files, `row_security`) | 210: revoked; superuser-set `temp_file_limit`; startup check; migrator restores defaults | PARTIALLY FIXED (`statement_timeout` and `work_mem` stay with RM-3) |
| Roles | LOW | Helpers searched `control` before `pg_catalog` | 210 | FIXED |
| Roles | LOW | Open transaction holds the audit lock; ROLLBACK undoes rate limits | Documented residual RM-3 (re-observed live) | NOT FIXED (accepted for a local checkpoint) |
| Multi-passkey | LOW (new, from 210) | Concurrent revoke-operator on both owners bypassed LAST_OWNER | 211: serialised; test | Fixed, not re-reviewed |
| Recovery 209 | LOW (new, from 210) | An objection on an *expired* request was not inherited | 211: inherit window = maximum lifetime; test | Fixed, not re-reviewed |
| Audit | LOW (new, from fixes) | Signer printed server strings raw (ANSI could hide rows) | 211-era tooling: escaped output; test | Fixed, not re-reviewed |
| Audit | LOW (new, from fixes) | Duplicate keys in export files accepted | Duplicate-key rejection in `parseStrict`; test | Fixed, not re-reviewed |
| Roles | LOW (new, from 210) | Per-database role settings got past the startup check and the migrator | Startup check on effective values plus `pg_db_role_setting`; migrator clears per-database settings | Fixed, not re-reviewed |
| Various | INFO | Token void ordering, mixed clocks, stale clock after locks, CLI stack traces, loader dotfile, deep nesting, `contested: null`, duplicate JSON keys in clientDataJSON (browsers never produce them), `authorize` dependency, owners can unpin their own functions (startup check covers it) | Fixed in 210/211 or accepted as INFO | — |

**Reviewer side effects:**
- Two reviewers changed state outside the read-only brief. One briefly wrote scratch files into the repo root, then removed them. One altered `control_app` role settings, then restored them.
- Both were verified clean afterwards, and every later migrate run restores the canonical role settings.
