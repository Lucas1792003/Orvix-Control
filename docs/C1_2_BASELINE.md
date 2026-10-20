# Phase C1.2 baseline (recorded before any C1.2 change)

| | |
|---|---|
| Date | 2026-10-20 |
| HEAD | `810d5701ee6a2a2fe468aad7a4ada133cc73dbfd` (C1.1 checkpoint), branch `main`, clean tree, no remote |
| Dev database | `orvix_control`, migrations 200–211 applied (ledger checksums match), 0 operators, 8 synthetic tenants |
| Platform | PostgreSQL 17.11 (`transaction_timeout` available), contrib extensions present, container pg_hba `local all all trust` |

## Unresolved at baseline

| ID | Severity | Item | Source |
|---|---|---|---|
| RM-1 | MEDIUM | Relayed passkey ceremonies: any prompt can be redirected to any step-up action; an attacker passkey activates after 15 min. The only "notice" is a same-origin banner served by the compromised app. | RESIDUAL_RISKS_C1_1.md |
| RM-2 | MEDIUM | Global login-challenge exhaustion: one anonymous bucket (20 per 15 min) shared by every client. | RESIDUAL_RISKS_C1_1.md |
| RM-3 | MEDIUM | With the `control_app` password: an open transaction holds the audit row lock (DoS); ROLLBACK suppresses refusal and read audit rows and undoes rate limits; `control_app` can change its own timeouts. | RESIDUAL_RISKS_C1_1.md |
| R-1 | Owner decision / gap | No way to create a second owner, so a single-owner install cannot recover its owner. | RECOVERY.md |
| R-2…R-8 | Owner decisions | Break-glass; ≥ 2 passkeys; host ≠ approver; TTLs; off-boarding; different-passkey revocation; repeated cancels. | RECOVERY.md |
| REV-211 | Process | Migration 211 and its tooling were tested but never independently reviewed. | REVIEW_C1_1.md |
| LOW set | LOW | `control_app` session timeouts and `work_mem`; unanchored audit tail; failure-audit cap window; Safari cookie; CSP `style-src 'unsafe-inline'`; ES256 only; first offline anchor is trust-on-first-use. | SECURITY_FINDINGS.md |
| DOC | INFO | `POS_INTEGRATION_REQUIREMENTS.md` is stale since C1. | — |

The results of the independent review of 211 are appended to `docs/REVIEW_C1_2.md` when available.
