# Orvix Control: security findings (as of Phase C1.1 final checkpoint, migrations 200–211, 2026-10-19)

Scope: this local repository only. No production system was touched. The review history and fix mapping are in [REVIEW_C1_1.md](REVIEW_C1_1.md).

## The two HIGH findings carried into C1.1

| ID | Finding | Status |
|---|---|---|
| S-1 | The app was trusted for passkey verification: `control_app` alone could mint any operator session | **Fixed (205).** The database verifies raw WebAuthn evidence (ES256 in PL/pgSQL; DB-issued, single-use challenges; origin, RP ID, UP/UV and counter from the signed data). Forged-session tests: `tests/sql/trust-boundary.test.ts`. |
| S-2 | Single passkey, no recovery | **Fixed within scope (205, 207, 208).** Up to 10 passkeys; add/revoke behind action-bound step-up; the last usable passkey is protected under concurrency; two-person recovery with cancel/contest; host emergency revoke. Policy decisions still open: [RECOVERY.md](RECOVERY.md) R-1…R-8. |

## Findings raised by the independent reviews (C1.1)

| Severity | Finding | Status |
|---|---|---|
| HIGH | P-F1: `control_definer` could act as `control_auth` / `control_audit_owner` (schema and helper ownership) | **Fixed (207)**; confirmed by the reviewer |
| HIGH | A-HIGH-1: passkey anchors are a signing oracle (any prompt can sign a forged head) | **Fixed by design change (offline Ed25519 v2 anchors, continuity-checked)**; v1 kept as convenience only and never sufficient alone; confirmed by the reviewer |
| MEDIUM | Counter regression auto-disable could lock out the last passkey | Fixed (207): refuse + flag |
| MEDIUM | Recovery tokens not bound to request state; no cancel | Fixed (207/208) |
| MEDIUM | Global enrolment rate limit lockout | Fixed (207): per token |
| MEDIUM | Unthrottled, identity-attributed failure audit rows | Fixed (207/208): anonymous, rate-limited, one summary row |
| MEDIUM | A relayed ceremony gives a malicious app a durable passkey | **Partially mitigated** (pending 15 min, banner, contest rules). Residual: see below |
| MEDIUM | Advisory-lock DoS by `control_app` | Fixed for session-level locks (207, row locks). Residual: open transaction (below) |
| MEDIUM | Verifier counted an unanchored tail as verified | Fixed |
| MEDIUM | NEW (round 2): an unsafe number in `detail` breaks all future verification | Fixed (208) |
| MEDIUM | NEW (round 2): a stolen passkey could veto recovery (SUBJECT_ACTIVE) | Fixed (208): delay plus host confirmation, never a veto; host emergency revoke |
| LOW | Lock-order deadlocks (revoke vs step-up; cancel vs redeem) | Fixed (207/208) |
| LOW | Round 3: a host confirmation before the objection overrode it; an emergency revoke skipped the contest delay | Fixed (209); covered by tests, not re-reviewed |
| LOW | Grants outlive their passkey; anchor re-check not NULL-safe; malformed attestation exception; body read before cap; default privileges; large objects; non-unique public keys; bootstrap re-issue; runner guard; pg_sleep | Fixed (207/208) |

| MEDIUM ×4 | Final checkpoint review: contest veto, objection after approval, clone flag never set in the app, signer signing a rewritten tail | Fixed (210) and re-verified; the signer-tail item is an inherent residual, mitigated by the summary and `--confirm-head` |
| LOW | Final checkpoint follow-ups (concurrent revoke-operator, expired-request inheritance, signer output escaping, duplicate keys in export files, per-database role settings) | Fixed (211 + tooling); covered by tests, not re-reviewed |

## Remaining risks (unresolved, accepted for a local foundation, not for production)

Full impact and assumptions, with live observations: [RESIDUAL_RISKS_C1_1.md](RESIDUAL_RISKS_C1_1.md).

| ID | Severity | Risk | Note |
|---|---|---|---|
| R-A6 | MEDIUM | A compromised app server or XSS relaying a live operator's ceremony can use any step-up it obtains for any allowed action. A passkey added this way is pending for 15 min and shown in a banner, but the banner is served by the same compromised app. | Needs an out-of-band notice (email or host) or a confirmation outside this origin. Future work. |
| R-DOS-LOGIN | MEDIUM (availability) | The global login-challenge limit can be exhausted by anyone who can reach the server. | Exposure is loopback plus SSH tunnel only. |
| R-TX | MEDIUM | With the `control_app` password: hold audit or identity row locks through an open transaction (DoS); ROLLBACK to suppress refusal or read audit rows, or to undo rate-limit counts and challenge consumption (CPU-only verification flood). Effects are always atomic with their audit row. A transaction older than 5 s is refused (210). | Postgres has no reliable "explicit transaction" test (a guard was tried and rejected; see 208 header). |
| R-AUDCAP | LOW | The per-purpose failure-audit cap (60 per 15 min, then one summary row) lets an attacker hide a later genuine failure for the rest of that window. | Accepted trade-off against log flooding. Next step: a separate small budget for failures that name a known credential. |
| R-ROLE | LOW | `control_app` can change its own session timeouts and `work_mem`, and its role password. Role and per-database defaults are checked at server start and restored by every migrate run. | PostgreSQL design. |
| R-TAIL | LOW (inherent) | Events after the newest offline anchor are only as trustworthy as the exporting server. | The signer shows the tail and requires `--confirm-head`; anchor after sensitive events. |
| R-SAFARI | LOW | The `__Host-` cookie over http://localhost is unverified in Safari. | Chrome is verified with a real browser. |
| R-CSP | LOW | `style-src 'unsafe-inline'`. | |
| R-ES256 | LOW | Only ES256 authenticators can enrol. | Fails closed. |
| R-1…R-8 | — | Recovery and lifecycle policy decisions. | [RECOVERY.md](RECOVERY.md) |
| R-SU | — | The Postgres superuser on the host can rewrite anything. | Detected only through offline v2 anchors ([AUDIT_EVIDENCE.md](AUDIT_EVIDENCE.md)), and the first anchor is trust-on-first-use. |
