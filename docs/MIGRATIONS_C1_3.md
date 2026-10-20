# C1.3 migrations (provisional): compatibility, upgrade and rollback

| File | Adds / changes | Compatibility |
|---|---|---|
| `218_watchdog_intents.sql` | `watchdog_intents` (append-only, forward-only state machine); `sentinel_liveness`; protocol functions `watchdog_plan` / `watchdog_arm` / `watchdog_execute` / `watchdog_reconcile`; intent notices; fold that takes the audit lock **before** the shadow line. **Drops `sentinel_watchdog`.** | The sentinel must be the C1.3 `scripts/sentinel.ts`: the C1.2 sentinel's watchdog calls fail (function gone) and it no longer terminates anything. Unfolded 217 `watchdog_kills` rows are still folded. |
| `219_recovery_auth_hardening.sql` | `platform_identities.recovered_at`; `sessions.revoke_reason` adds `credential_flagged`. Recovery redemption voids the subject's issued invitations and approved links, issues a device token, and refuses if the subject was active after approval. `IDENTITY_UNDER_RECOVERY`; emergency revoke always contests; flagged passkeys lose sessions, step-up and anchors; suspended owners. | Behaviour tightening only. Contract and app move together (`enroll/verify` sets the device cookie). |
| `220_sentinel_delivery.sql` | `notify_deliveries.claim_token`; `notify_channels.ack_secret` (database-verified webhook ack) and `disabled_at`; `host_set_notify_ack_key`; claim index. **New signatures** `sentinel_claim(limit, channel)` and `sentinel_ack(outbox, channel, token, ok, error)` (old ones dropped). `sentinel_pending_channels()`. Lease 40 s, at most 5 per channel per claim. Disabled-channel gate waiver. New `host_notify_status`. `control_sentinel CONNECTION LIMIT 12` (cluster-wide role attribute). | Needs the C1.3 sentinel. Deliveries claimed by a 217 sentinel (no token) become claimable again once their lease expires (tested). |
| `221_privileges_tenant_contract.sql` | Re-asserts the control database ACL (PUBLIC nothing; CONNECT for `control_app`, `control_sentinel`); tenant replay must match tenant and target state; contract `orvix-control/0.5`. | App and contract move together. |

Outside migrations (also C1.3):
- **`scripts/migrator.ts`:** re-asserts the database ACL on **every** run and reports cluster exposure.
- **`src/server/db/privilegeCheck.ts`:** the startup and 30 s re-check used by the web server and the sentinel. It **refuses** when:
  - PUBLIC has privileges on the control database;
  - the role has TEMP or CREATE there;
  - the role can CONNECT to a non-control database or to an unhardened control-named one;
  - any revoked built-in is executable (advisory locks, large objects, `pg_notify`, `pg_sleep`, WAL/xid functions);
  - `plpgsql` USAGE is present;
  - any `control` object is owned outside the five owner roles (a `--no-owner`/`-x` restore).

  The sentinel additionally checks its own role settings (role-level and per-database) and live timeouts.
- **`db/cluster/pg_hba.conf`** and **`scripts/harden-cluster.ts`:** the cluster-level M3 controls (below).
- **`docker-compose.dev.yml`:** `init: true`.

## Cluster prerequisites (new in C1.3; required for the app and sentinel to start)

1. **`pg_hba`:** use `db/cluster/pg_hba.conf`, or equivalent rules: the control roles may reach only control databases, and are rejected everywhere else.
2. **Shared databases:** run `npm run harden-cluster -- --apply --i-understand-cluster-wide`, which revokes PUBLIC CONNECT/TEMP on `postgres` and `template1`. **This changes databases other than the control database**: run it only on a cluster dedicated to Orvix Control.
3. **NOTIFY queue:** a low `max_notify_queue_pages` (the test cluster uses 1024 pages = 8 MB). PostgreSQL has no privilege for `NOTIFY` (see RESIDUAL_RISKS_C1_3).
4. **Init process:** `init: true` (Docker) or another init as PID 1. With the postmaster as PID 1, an orphaned process that dies by a signal makes PostgreSQL restart the whole cluster (found in C1.3 testing).

**The existing development cluster was NOT changed by C1.3 work.** Applying C1.3 there requires steps 1–4 and `npm run db:migrate`, which is an owner decision. Until then a C1.3 server refuses to start against it, by design.

## Verified (disposable cluster `orvix-c13-*`, `--network none`)
- **Fresh install:** 200→221 applies in order; the ledger matches the files.
- **Upgrade 217 → 221 with state:** the chain verifies; the pre-217 head is unchanged; legacy kill records fold; 217-era claims become re-claimable.
- **Schema equivalence:** a fresh 221 schema and an upgraded 221 schema are byte-identical (`pg_dump -s` hash `bdbfd22e37f0aa4a`).
- **Rollback by restore:** a 217 dump restored → ledger 217, no 218+ objects, chain verifies. Re-upgrade applies 4 migrations, the chain verifies, and the ACL is re-asserted (the startup check passes).
- **Restore without migrate:** PUBLIC CONNECT/TEMP left by a plain restore is **detected** (the startup check refuses), and fixed by the next `db:migrate`, even when no migration is pending.
