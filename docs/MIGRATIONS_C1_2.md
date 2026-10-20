# C1.2 migrations: compatibility and rollback

| File | Adds | Compatibility |
|---|---|---|
| `212_oob_notifications.sql` | Role `control_sentinel` (LOGIN); outbox, deliveries and channels (audit owner); an enqueue trigger on `audit_events`; `notification_delivered`, `credential_usable`; host channel functions; delivery gating in `wa_assertion`, revocation, the anchor signer and recovery redemption | **Gating applies only to items created after 212** (`notify_gate_since`): existing passkeys and approvals are not locked out on upgrade. After upgrade a host channel and a running sentinel are required for **new** passkeys, recovery redemptions and operator activations (fail closed). |
| `213_scoped_login_limits.sql` | `login_devices`; per-device and anonymous buckets; outstanding-challenge ceiling | **API change:** `api_login_begin(p_device_token)` and `api_login_complete(…, p_device_token)` replace the 0- and 4-argument versions. The app and contract move together (`orvix-control/0.4`). Existing sessions are unaffected. |
| `214_txn_watchdog_shadow_audit.sql` | `transaction_timeout=10s` role default; `audit_events.shadow_id` (not hashed; old rows NULL); RAISE LOG shadow lines; role `control_watchdog_owner` (NOLOGIN, member of `pg_signal_backend` and `pg_read_all_stats`); `sentinel_watchdog` | The audit hash chain is unchanged (`shadow_id` is not part of the canonical form), and the continuity tests verify the chain across the upgrade. `control_watchdog_owner` is the **only** control role with built-in role memberships; tests assert exactly those two. |
| `215_operator_invitations.sql` | Identity state `pending_approval`; credential source `invite`; token purpose `invite`; `operator_invitations`; invite, revoke and list APIs; `host_approve_operator`; the step-up allow-list gains `operator_invite`; contract `0.4` | Additive. Existing identities are unchanged. |
| `216_review_211_fixes.sql` | Activity-based contest inheritance; `assert_read_committed` in the host owner-count guard | Behavioural tightening only. |
| `217_review_c1_2_fixes.sql` | Fixes from the four C1.2 reviews: HMAC-keyed shadow lines (`audit_shadow_key`) with database name; lock-free watchdog kill records (`watchdog_kills`, `notify_outbox.audit_seq` now nullable) and own-database filter; public-key activation fingerprint; host revoke voids invitations and approved links; mid-recovery owners excluded from `LAST_OWNER`; passkey delay from delivery (`notification_delivered_at`); uncapped retries, heartbeat and richer `host_notify_status`; webhook target constraint (`NOT VALID`: existing rows are not re-checked); device cap and purge; re-invite of never-activated identities; advisory locks and `plpgsql` USAGE revoked from PUBLIC | **Behaviour changes:** (1) webhook receivers must return `X-Orvix-Ack` (sentinel change, not SQL), or deliveries fail and gates stay closed; (2) the activation fingerprint format changes to `XXXX-XXXX-XXXX-XXXX` (an invitee enrolled before 217 shows the old 8-character value; the host must use the new one from `api_operator_list` or the notice); (3) a passkey added and delivered before 217 may become usable later than before (window now starts at delivery); (4) `control_app` loses advisory locks and `DO` blocks (it used neither); (5) the shadow-line format gains a MAC field, so `audit-shadow.ts` from before 217 cannot parse new lines and new lines cannot be verified for events written before 217. API signatures and the contract version (`0.4`) are unchanged. |

**Secret layout change (not a migration):** `.env.local` (web server) no longer contains the superuser password. That moved to `.env.host`. The sentinel password is in `.env.sentinel`. All three files are mode 0600 and git-ignored. The server refuses to start if it sees `SUPERUSER` or `SENTINEL` variables.

## Rollback

The migrations are **forward-only**: each file runs in one transaction with its ledger row, and a failure leaves nothing applied. Rollback is **restore from the pre-upgrade recovery point**, which is tested in `tests/sql/c12.test.ts` ("migration upgrade and rollback drill"):

1. Run `pg_dump -Fc` at 211.
2. Upgrade to 217.
3. Restore the dump into a fresh database.
4. Check that the ledger shows 211, the 212+ objects are absent, the audit head is identical and the chain verifies.
5. Re-upgrade to 217, and check that the chain still verifies.

Writing down-migrations by hand for the function replacements in 212–217 was rejected. Each one would have to restate the previous body of more than ten functions, which is the riskier path.

Roles are cluster-wide and survive a database restore (`control_sentinel`, `control_watchdog_owner`). Privileges on built-in objects (the advisory-lock functions and `plpgsql`, revoked in 217) are per database and are restored with it. That is harmless: they own nothing in a restored 211 database, and the next upgrade reuses them after the attribute check.
