# Operator lifecycle and lost-device recovery

## Implemented (independently safe)

| Situation | Procedure | Who |
|---|---|---|
| First owner | `npm run bootstrap-owner` on the host (superuser), which issues a one-time 15-min enrolment link. Works once per install. | Infrastructure owner |
| Add a passkey | Security page → step-up with an existing passkey (grant bound to `credential_add` + own identity) → register the new authenticator (ES256, UV, attestation `none`). Max 10 per operator. **The new passkey is pending for 15 minutes**: it cannot sign in or step up, every session shows a red banner, and it can be revoked during the window. This limits the damage of a relayed ceremony (AUTH_TRUST_BOUNDARY A6). | The operator |
| Lose **one** of ≥ 2 passkeys | Sign in with another; Security page → step-up bound to that credential → Revoke. Sessions signed in with it end immediately. | The operator |
| Remove the last **usable** passkey | **Refused** (`LAST_CREDENTIAL`). A pending passkey does not count as usable. Add and revoke are serialised by an identity row lock (lock order identity → sessions → credentials → grants), so concurrent revocations cannot remove the last two. | — |
| Possible cloned authenticator | A validly signed assertion with a non-increasing counter is **refused**, and the passkey is **flagged** (banner; audited `platform.credential_counter_regression`). Before 210 the app's own pre-check hid this from the database; it now works end to end. It is never disabled automatically, because that could remove the last passkey and lock out a single-owner install (review F1). The operator decides whether to revoke it. | Automatic flag, operator decision |
| Lose **all** passkeys | 1. Host: `npm run host -- recovery-request --email … --reason …` (grants nothing; expires in 24 h). 2. A **different active owner** checks the subject's email and id, then approves on the Security page with a step-up bound to that request. If the subject **objects** (their cancel only contests, and also voids an already-issued link), or a non-flagged passkey of theirs was used after the request, or they were emergency-revoked, the request is **contested**. Approval then also needs `npm run host -- recovery-confirm`, made **after** the latest objection, activity or revoke, **and** a 12-hour wait. The wait counts from the **first** objection (or the request, or the revoke) and never restarts; contesting extends the request so the wait always fits (at most 7 days). A request re-filed within 7 days of an objection inherits it, whether the earlier request was cancelled or simply expired (211). If the subject keeps objecting or using the passkey, which suggests a thief, the host runs `revoke-operator`, which ends that. So it is a delay, never a veto (210). 3. The approver relays the link out of band. **Whoever holds the link enrols**, so treat it like a password. 4. Redeeming it requires the request to still be `approved` and unexpired; all previous passkeys are then disabled and all sessions end. Every step is audited. | Host operator **and** a second owner |
| Withdraw a recovery | Host: `npm run host -- recovery-cancel --request …`, or in the console another owner (step-up bound to the request). Cancelling voids any outstanding token. Expired requests are cancelled, with their tokens, when a new request is filed. The subject cannot cancel, only contest. | Host or another owner |
| Stolen device or account under attack | Host emergency action: `npm run host -- revoke-operator --email … --reason …` disables every passkey, session and grant of that operator, and voids any recovery link already issued (grants nothing). Recovery then needs host confirmation plus 12 h. For the **last** owner it is refused unless `--force` is given, because a single-owner install could then never recover. Concurrent revokes are serialised, so revoking two owners at once cannot get past this guard (211). | Host |
| First-owner link expired unused | Run `npm run bootstrap-owner` again with the same email. The link is re-issued while the owner is still enrolling (audited `owner_bootstrap_reissued`). | Infrastructure owner |

**No single-person bypass at the application layer.** (A database superuser on the host can write any table directly; that is infrastructure trust, detected only through offline audit anchors: `AUDIT_EVIDENCE.md`.)
- The subject cannot approve their own request (also a table CHECK).
- Platform admins cannot approve.
- The host request alone issues nothing.
- The approval alone needs a host request to exist.

There is no recovery code, emergency key or unrestricted break-glass.

## Blocked: owner decisions required

| ID | Decision | Why it blocks | Recommendation |
|---|---|---|---|
| R-1 | **How is a second owner created?** There is no invitation or owner-approval flow yet (CP E.3). | Recovery needs a second owner. A **single-owner install cannot recover its owner** (asserted by a test). Until R-1 is answered, the only path is a database-level restore or reinstall by the infrastructure owner. | Build invitations with owner approval next. Require ≥ 2 owners before production use, or accept R-2. |
| R-2 | Break-glass for single-owner installs (sealed offline secret + host access, CP E.7). | This **is** a single-person path (host plus the secret are held by one person), so it was deliberately not implemented. | Decide explicitly. If accepted: sealed secret stored apart from backups, an immediate signed anchor, and a permanent banner until acknowledged. |
| R-3 | Must every operator hold ≥ 2 passkeys (one a hardware key)? | Today it is warned in the UI (banner), not enforced. | Enforce before production: refuse privileged actions while only one passkey is registered. |
| R-4 | Is the host operator allowed to be the same person as the approving owner? | If yes, recovery is effectively one person with two roles. | Require different people (organisational control; the software cannot tell). |
| R-5 | Recovery TTLs (request 24 h, token 30 min), and whether the subject's sessions should end at request time rather than at redemption. | Policy. | Keep the defaults; consider ending sessions at approval. |
| R-6 | **Operator off-boarding.** The host `revoke-operator` disables credentials but leaves the identity active; there is no API to retire an operator (`state = 'revoked'` only by superuser SQL). | Lifecycle gap. | Build retire-operator (owner, step-up, last-owner protection) together with R-1. |
| R-7 | A thief holding one unlocked passkey can step up, revoke the others and add their own (pending 15 min). The host can stop this with `revoke-operator`. | The authenticator is the factor. | Consider requiring a *different* passkey for revocations, plus out-of-band notification. |
| R-8 | Another owner can repeatedly cancel recovery requests (audited). | A colluding or compromised owner is a two-owner problem. | Alert on repeated cancels; the host re-files. |
