# Operator lifecycle and lost-device recovery

## Implemented (independently safe)

| Situation | Procedure | Who |
|---|---|---|
| First owner | `npm run bootstrap-owner` on the host (superuser), which issues a one-time 15-min enrolment link. Works once per install. | Infrastructure owner |
| Add a passkey | Security page → step-up with an existing passkey (grant bound to `credential_add` + own identity) → register the new authenticator (ES256, UV, attestation `none`). Max 10 per operator. **The new passkey is pending**: it needs its out-of-band notice delivered (212) and then **15 minutes counted from that delivery** (217). Until then it cannot sign in or step up, every session shows a red banner, and it can be revoked during the window. This limits the damage of a relayed ceremony (AUTH_TRUST_BOUNDARY A6). | The operator |
| Lose **one** of ≥ 2 passkeys | Sign in with another; Security page → step-up bound to that credential → Revoke. Sessions signed in with it end immediately. | The operator |
| Remove the last **usable** passkey | **Refused** (`LAST_CREDENTIAL`). A pending passkey does not count as usable. Add and revoke are serialised by an identity row lock (lock order identity → sessions → credentials → grants), so concurrent revocations cannot remove the last two. | — |
| Possible cloned authenticator | A validly signed assertion with a non-increasing counter is **refused**, and the passkey is **flagged** (banner; audited `platform.credential_counter_regression`). Before 210 the app's own pre-check hid this from the database; it now works end to end. It is never disabled automatically, because that could remove the last passkey and lock out a single-owner install (review F1). The operator decides whether to revoke it. | Automatic flag, operator decision |
| Lose **all** passkeys | 1. Host: `npm run host -- recovery-request --email … --reason …` (grants nothing; expires in 24 h). 2. A **different active owner** checks the subject's email and id, then approves on the Security page with a step-up bound to that request. If the subject **objects** (their cancel only contests, and also voids an already-issued link), or a non-flagged passkey of theirs was used after the request, or they were emergency-revoked, the request is **contested**. Approval then also needs `npm run host -- recovery-confirm`, made **after** the latest objection, activity or revoke, **and** a 12-hour wait. The wait counts from the **first** objection (or the request, or the revoke) and never restarts; contesting extends the request so the wait always fits (at most 7 days). A request re-filed within 7 days of an objection inherits it, whether the earlier request was cancelled or simply expired (211). If the subject keeps objecting or using the passkey, which suggests a thief, the host runs `revoke-operator`, which ends that. So it is a delay, never a veto (210). 3. The approver relays the link out of band. **Whoever holds the link enrols**, so treat it like a password. 4. Redeeming it requires the request to still be `approved` and unexpired; all previous passkeys are then disabled and all sessions end. Every step is audited. | Host operator **and** a second owner |
| Withdraw a recovery | Host: `npm run host -- recovery-cancel --request …`, or in the console another owner (step-up bound to the request). Cancelling voids any outstanding token. Expired requests are cancelled, with their tokens, when a new request is filed. The subject cannot cancel, only contest. | Host or another owner |
| Stolen device or account under attack | Host emergency action: `npm run host -- revoke-operator --email … --reason …` disables every passkey, session, grant and device token of that operator. It also voids recovery links issued **for** that operator, recovery links that operator **approved** for someone else, and every open invitation that operator **issued** or is the subject of (217). It grants nothing. Recovery then needs host confirmation plus 12 h. For the **last** owner it is refused unless `--force` is given, because a single-owner install could then never recover. An owner who is **mid-recovery** (open request as subject) does not count as another usable owner (217). Concurrent revokes are serialised, so revoking two owners at once cannot get past this guard (211). | Host |
| First-owner link expired unused | Run `npm run bootstrap-owner` again with the same email. The link is re-issued while the owner is still enrolling (audited `owner_bootstrap_reissued`). | Infrastructure owner |

**No single-person bypass at the application layer.** (A database superuser on the host can write any table directly; that is infrastructure trust, detected only through offline audit anchors: `AUDIT_EVIDENCE.md`.)
- The subject cannot approve their own request (also a table CHECK).
- Platform admins cannot approve.
- The host request alone issues nothing.
- The approval alone needs a host request to exist.

There is no recovery code, emergency key or unrestricted break-glass.

## Multi-owner setup (C1.2, migration 215)

| Step | Who | Guarantee |
|---|---|---|
| Invite | An active **owner**, with a step-up bound to `operator_invite` and `<role>:<sha256(email)>` | The role is fixed by the invitation. Admins cannot invite. Out-of-band notice to all owners and the host. |
| Enrol | The invitee, with the one-time link (48 h) and a passkey (verified in the database) | Single-use; concurrent redemption gives exactly one; replay, expiry and revocation all give `INVALID_TOKEN`. The identity becomes `pending_approval` and **cannot sign in**. The notice carries the passkey fingerprint. |
| Activate | The **host**: `npm run host -- approve-operator --email … --fingerprint XXXX-XXXX-XXXX-XXXX` after reading the fingerprint back with the invitee out of band (voice or in person, **not** through the console) | The fingerprint is 64 bits of SHA-256 over the passkey's **public key** (217); an attacker cannot choose it. Refused on a mismatch, before the enrolment notice is delivered, if the invitation expired, or if the inviter is no longer an active owner or was emergency-revoked after inviting (217). |
| Re-invite | An owner, as for an invite | Allowed only for an identity that was **never activated** (its invitation expired or was revoked); the old invitation, link and passkey are voided and the audit row names the replaced invitation, previous role and previous state (217). An active or once-active identity can never be re-invited. |

With two active owners, the existing two-person recovery covers the loss of one owner's passkeys. This is tested end to end, including the stolen-device path. A pending owner does not count toward the last-owner guard.

**Limits of the activation check (be precise).** Against a compromised console origin, the invitee sees only what the console shows them. The public-key fingerprint stops an attacker who **intercepted the link** (their key gives a different fingerprint from the one the real invitee reads out, and the link is single-use, so the real invitee's own enrolment fails and they notice). It does **not** stop a compromised origin that swaps its own key into the invitee's ceremony **and** shows the invitee the attacker's fingerprint. In that case the host and the invitee agree on the attacker's key. That case is detected only when the real invitee's first sign-in fails, after activation. See R-11.

**C1.3 recovery rules.**
- Redeeming a recovery **voids** every open invitation the subject issued and every recovery link the subject approved. Each is audited (`INVITER_RECOVERED`, `APPROVER_RECOVERED`) and announced.
- Host activation and recovery redemption refuse an inviter or approver who was recovered **after** acting.
- Any emergency revoke after the subject's last recovery contests the request; there is no 24 h window any more.
- If the subject uses a passkey **after** the approval, redemption is refused (`RECOVERY_CONTESTED`) and the request returns to pending.
- While an owner has an open recovery request:
  - every step-up action and anchor signing is paused (`IDENTITY_UNDER_RECOVERY`); revoking a passkey, revoking an invitation and contesting their own request still work;
  - invitations they issued cannot be activated (`INVITER_UNDER_RECOVERY`), and recovery links they approved cannot be redeemed (`APPROVER_UNDER_RECOVERY`);
  - the subject's own contest does **not** end the pause: the host or another owner must cancel the request.
- A passkey flagged as possibly cloned loses its sessions and cannot be used for step-up or anchors, and it does not count as usable for `LAST_OWNER` or `LAST_CREDENTIAL`. Sign-in still works.

**If every owner loses every passkey**, nobody can approve a recovery. The only remedy is a database restore or reinstall by the infrastructure owner. Keep two owners with two passkeys each (R-3).

## Owner decisions (C1.2 review; nothing below is decided by this implementation)

| ID | Decision | What is implemented now (a default, not a decision) | Alternatives for the owner |
|---|---|---|---|
| R-1 | Who activates a new operator? | **Host approval** with a fingerprint check, after the out-of-band notice is delivered (two parties: inviting owner + host) | (a) A **different existing owner** approves in the console (no host step; needs two owners first); (b) host **plus** a waiting period; (c) host plus re-confirmation by the inviting owner. |
| R-2 | Break-glass for single-owner installs | Not implemented (it would be a single-person path) | Sealed offline secret + host access + immediate anchor + permanent banner; or "always keep two owners" (R-1 makes that possible). |
| R-3 | Require ≥ 2 usable passkeys per operator? | Warned (banner), not enforced | Enforce for privileged actions; or require one hardware key. |
| R-4 | Must the host operator differ from the approving owner **and from the inviting owner**? | Not enforceable in software. If the host is also the inviting owner, one person can create an active owner; only the out-of-band notices remain as a check. The same applies to recovery. | An organisational rule; or require a different owner (R-1 a) instead of the host. |
| R-5 | Recovery and invitation TTLs, session timing | Request 24 h (extended by contest, ≤ 7 d); recovery link 30 min; **invitation 48 h**; contest delay 12 h; sessions end at redemption. A recovery link is redeemable as soon as its approval notice is delivered (no extra reaction window). | Shorter or longer; end sessions at approval; add a reaction window after the approval notice. |
| R-6 | Operator off-boarding | Host `revoke-operator` disables credentials; owners can revoke **invitations**; no API retires an active operator | Owner "retire operator" with step-up, a notice and last-owner protection. |
| R-7 | Revocation with a stolen passkey | One passkey can step up to revoke the others; new passkeys wait 15 min **and** for a delivered notice | Require a *different* passkey for revocations; or make revocations notice-gated too. |
| R-8 | Repeated cancels or objections | Audited and announced out of band | Rate-limit them, or escalate to the host after N. |
| R-9 (new) | Notification channels | At least one **host** channel is required for gated actions (fail closed). Every recipient channel in a notice's snapshot must succeed, so **one permanently failing or disabled channel blocks every gated action** until it recovers (a disabled channel never recovers: redo the action). Deliveries are retried forever with backoff capped at 300 s. | Require a per-owner channel as well; exclude emergency-revoked owners' channels from the snapshot; let the host waive a delivery; choose a webhook target (self-hosted ntfy, Matrix or SMTP relay); retention for the file channel. |
| R-10 (new) | Admin invitations and re-invitation | Same two-party flow as owners. A never-activated identity can be re-invited (217); an active or once-active one cannot. | Lighter flow for admins (owner-only approval), since admins cannot recover or invite; forbid re-invitation of revoked emails. |
| R-11 (new) | Strength of operator activation against a compromised console | Public-key fingerprint read back between host and invitee (217); detection on first failed sign-in | Require the new operator's first successful sign-in, confirmed through **their own** out-of-band channel, before any privileged action; or require a different owner to approve on a separate device (R-1 a). |
| R-13 (C1.3) | First sign-in from a never-enrolled browser | Shared anonymous login bucket (20 per 15 min) for browsers that never completed an enrolment; every enrolment (bootstrap, invite, recovery) now gives that browser its own bucket | Per-client-IP limits behind a **trusted** reverse proxy; a higher anonymous limit with proof-of-work; accept the residual. |
| R-12 (new) | Device tokens | At most 5 live device tokens per identity (least recently used revoked); 400-day TTL; the anonymous bucket is shared | Larger or smaller cap; per-scope ceiling reservations. |

## Historical: C1.1 blocked decisions (superseded by the table above)

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
