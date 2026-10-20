# Orvix Control ↔ Orvix POS: integration requirements

| | |
|---|---|
| Status | Requirements for **future** work. Nothing here is implemented in the POS. No POS file was changed. |
| Date | 2026-10-19 |
| Sources | ShwePhaLa `docs/plans/orvix-platform-control-plane-architecture.md` (**CP**) and `docs/plans/reconciliation-v2-claude4-control-plane.md` (**R2**), both read-only; owner decisions register v2 (**D-20/21/22/24**). Where this document and those disagree, R2 wins over CP, and owner decisions win over both. |
| This repo provides | Control schema 200–203 with its own ledger, `control_app` role, passkey sessions, audit chain, and a lifecycle **model** over synthetic tenants. |

## 1. Hard boundaries (do not relax)

1. **No service-role key, and no Supabase client, in Orvix Control.** The app holds one DB credential (`control_app`) whose only right is EXECUTE on `control.api_*`.
2. **No direct tenant-table grants** to `control_app`, `control_definer` or `control_audit_owner`. All tenant access goes through **POS-owned interface functions** granted to a POS-owned role `platform_hooks`. `control_definer` gets only `GRANT platform_hooks TO control_definer` (R2 SB-3).
3. **Metadata only.** Platform roles never read sales, prices, costs, payments, stock, customers or tenant audit content. Interface functions return names, statuses, counts, timestamps and MFA flags.
4. **Platform identities never live in GoTrue**, and tenant identities never in `control.platform_identities`. No control function accepts a GoTrue JWT.
5. **Not internet-facing.** Loopback bind on `lucashome`, reached by SSH tunnel at `http://localhost:<port>`. The passkey RP ID is `localhost`; changing the hostname later means re-enrolling every passkey (OD-C8 / D-22).
6. **No recovery-release authority.** Orvix Control never opens a POS recovery hold (migration 087/088 `recovery.*`). That stays with the infrastructure owner's superuser procedure.
7. **No billing activation.** `past_due` is a manual notice state only.

## 2. Migration numbering and ledger

| Item | Requirement |
|---|---|
| Sequences | POS hooks take **POS numbers** (reserved 100–102). Control objects take **200–299** (reserved 200–204) (R2 §3.2, D-20). |
| Dependency direction | Control files may depend on POS objects and must assert them at the top. POS files never reference `control` or `control_*`. |
| Ledger | This repo's `control_ledger.schema_migrations` is a **development ledger**. In production there is one database and one ledger. Before the first real apply, the 200-series files move into `ShwePhaLa/supabase/migrations` and run through `deploy/lucashome/apply-migrations.sh` in their own invocation (`--from 200 --to 20x`), never in the same range as POS files (R2 R5). The checksum guard in `scripts/migrator.ts` should be ported to that script. |
| Adaptation needed | `200` revokes `public` usage from PUBLIC and database CONNECT from PUBLIC. That is correct for the isolated DB here, **wrong for Supabase**. Remove both before porting. `control_ext.pgcrypto` should use the existing `extensions.pgcrypto`. |
| Tooling first | Phase-d skip list, security-audit ledger synthesis from applied files, and a block-aware apply guard (R2 R7) must exist before any 100+/200+ file merges. |

## 3. POS hooks the control plane needs (owned by the POS team)

All are SECURITY DEFINER functions owned by `platform_hooks_definer` (NOLOGIN), with EXECUTE granted only to `platform_hooks`. Each is generated from the bodies as they stand at its number (R2 R4).

### Hook A: POS `100` (lifecycle columns, roles)

- `organizations`: `slug`, `status` (CHECK against the 10 states in §5), `status_reason`, `status_note`, `status_changed_at`, `status_changed_by`, `activated_at`, `suspended_at`, `provisioning_kind`, `timezone`, `locale`. Trigger keeps `is_active = status IN ('active','past_due')`.
- Shwe Pha Lar adopted in place as `active` / `shwe-pha-lar` / `adopted`, with digest asserts that no business row changed.
- Roles `platform_hooks`, `platform_hooks_definer`. A settings row `suspension_enforcement=false` in **public**, so the POS never reads `control`.

### Hook B: POS `101` (provisioning interface)

| Function | Returns / does | Notes |
|---|---|---|
| `platform_org_metadata(p_org_id text)` / `platform_org_list()` | name, slug, status, shop count, user counts by role, ADMIN email, ADMIN TOTP verified, created/activated timestamps | Replaces the synthetic `shop_count`/`user_count`/`admin_mfa_verified` columns in `control.tenants` |
| `platform_create_org(p_name, p_slug, p_request_id)` | org id, status `draft` | Fires the existing seed triggers (business_profile, price levels) |
| `platform_add_shop(p_org_id, p_name)` | shop id | Optional: tenant ADMINs can already create shops (R2 F-12) |
| `platform_seed_defaults(p_org_id)` | counts | Price levels (077) + unit types (M 086) |
| `platform_link_first_admin(p_org_id, p_invitation_id, p_auth_id)` | users row | Only via `org-invite`; re-checks every 082 link rule |
| `platform_set_org_status(p_org_id, p_to, p_reason, p_note, p_actor_label)` | prior/new status | The **only** writer of `organizations.status`; writes a tenant `audit_logs` row (metadata only) |
| Guard bypass | `guard_user_privilege_columns` and `guard_admin_continuity` trust `current_user = 'platform_hooks_definer'` **plus** a transaction-local GUC set only inside `platform_link_first_admin` | A client-set GUC must be ignored (`current_user` differs) |

### Hook C: POS `102` (suspension enforcement, after M 096)

- `app_pre_request()` configured as `PGRST_DB_PRE_REQUEST`. For authenticated callers of a suspended, locked or archived org it raises SQLSTATE **`PT503`**, HTTP **503**, with a message that starts `ORG_SUSPENDED:` **and** contains `service unavailable`. It is flag-gated (default off). Anonymous callers pass.
- `app_org_status()` (tenant, own org) and `app_org_operational(org)` (service_role, for Edge Functions). Allow-list `rpc/app_backend_info` and `rpc/app_org_status` through the pre-request.
- Identity-helper amendment (E2) is enabled **only** while E1 is active.
- **Never** use 401, 403, 400, `42501`, `P0001` or an empty-200 for suspension. Each would turn queued offline sales into permanent conflicts or renew the offline window forever (R2 §5.3).

## 4. Control-side work that follows (this repo, after hooks exist)

| Control file | Content | Replaces in this foundation |
|---|---|---|
| 203 rewrite | `control.api_tenant_*` read through `platform_org_list/metadata` | `control.tenants` synthetic table becomes a cache or is dropped; `is_synthetic` CHECK removed only then |
| 204 | Provisioning API + `control.org_invitations` + `invite_redeem_begin/finish` (EXECUTE to service_role for the `org-invite` Edge Function) | `available=false` rows for invite / redeem / activate |
| 205 | Suspend / lock / reactivate call `platform_set_org_status`; lock revokes GoTrue sessions (U-4 spike first) | Status changes that today touch only the synthetic table |

The transition table (`control.tenant_transitions`), role and step-up policy, reason rules, idempotency (`request_results`) and audit coupling carry over unchanged. Every `api_*` must still write its audit row in the same transaction as the POS hook call.

## 5. Lifecycle contract (shared vocabulary)

States: `draft → provisioning → invited → pending_activation → active ↔ past_due → suspended → archived`, plus `locked` and `abandoned` (CP G.1). Policy as modelled in `203`:

| Transition | Who | Step-up | Reason + note ≥ 10 |
|---|---|---|---|
| active/past_due → suspended | owner or admin | yes | yes |
| suspended → active | **owner only** | yes | no |
| live → locked | owner or admin | yes | yes |
| locked → active/suspended | **owner only** | yes | yes |
| suspended → archived | **owner only** | yes | yes |
| pending_activation → active | owner or admin | yes | — (blocked until ADMIN TOTP is verified, POS-side check) |

## 6. POS client (desktop app) requirements

From R2 §5.4 (C-1…C-8). None of this needs Orvix Control to exist; it is gate **G-SUS-1** for 1.0.17.

1. `ORG_SUSPENDED` (503 + `PT503` or the message prefix, or `app_org_status()` not operational) is **transient for replay**. It is never `conflict`, never deletes a queued row, and never renews the offline write window.
2. A response with a PostgREST error body is never "in-doubt" (it did not commit).
3. Once suspension is known, show a suspension screen; block new sales (D-24); keep the Sync page, pending list, export and sign-out.
4. `locked` at sign-in shows "organization locked: contact Orvix", not "No staff profile is linked".
5. Tolerate `organizations.status` being absent (1.0.17 ships before hook A).
6. Remove `/console`, `/console/login` and `platformAuthStore` from POS builds; undeploy `platform-console` (G0 / G-PC-1).

## 7. Infrastructure requirements (lucashome)

- Container `orvix-control` on loopback only, ≤ 512 MB / 0.5 CPU (S-15), joined to the Supabase compose network; Postgres stays unpublished.
- One `pg_hba.conf` line for `control_app` from the compose subnet with scram-sha-256. The password is set out of band and stored in `/srv/orvix-control/.env` (0600), which joins the age-encrypted secrets bundle.
- `control` is **never** added to `PGRST_DB_SCHEMAS`.
- Never exposed through the tenant API tunnel, Funnel or Cloudflare.
- Off-host anchoring channel (encrypted weekly email manifest) before audit is relied on (SECURITY_FINDINGS S-4).

## 8. Acceptance tests to port into `tools/security-audit` (CP §N)

| Suite | Port from this repo |
|---|---|
| N-1 control inventory | `tests/sql/privileges.test.ts` (exact grant set, definer + search_path, no PUBLIC EXECUTE, RLS read-policy guard) |
| N-2 control auth | `tests/sql/auth.test.ts` + `tests/e2e/http.test.ts` (software authenticator) |
| N-4 no business data | `privileges.test.ts` "definer roles hold no tenant privileges", re-pointed from `pos_mock` to the real tenant tables, generated from the table inventory |
| N-8 audit integrity | `tests/sql/audit.test.ts`, including the two **honest-limit** assertions (full recompute and un-anchored tail truncation are NOT detected on-host) |
| N-9 lifecycle / N-10 idempotency | `tests/sql/lifecycle.test.ts` |

## 9. Open decisions blocking integration

| ID | Decision | Default recommended in the plans |
|---|---|---|
| D-20 | Numbering scheme (POS hooks 100–102, control 200–204) | Yes |
| D-21 | Suspension: hold only; admin suspends with reason; owner reactivates; paying second org needs suspension first | As stated |
| D-22 | Schema `control`, `localhost` via SSH, no business activity visible | As stated |
| S-1 (this repo) | Accept that `control_app` is owner-equivalent for authentication, or fund a separate verifier | Accept + offline re-verification of stored assertions |
| CP S-10 | Invitation delivery: manual one-time links | Manual until email exists |
