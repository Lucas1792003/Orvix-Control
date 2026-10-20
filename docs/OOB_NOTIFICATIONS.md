# Out-of-band security notifications (C1.2, migration 212)

## Why

A compromised console origin (server code, a malicious dependency or XSS) can turn one genuine passkey prompt into any step-up action. For example, it can add its own passkey, approve a recovery, or invite an operator. The C1.1 "pending passkey" banner was served by that same origin, so it was **not** independent.

## What makes it independent of the console

| Property | How |
|---|---|
| Cannot be skipped | The notice is enqueued by an `AFTER INSERT` trigger on `control.audit_events`, in the **same transaction** as the audited effect. No effect commits without its notice. |
| Cannot be edited, deleted or faked by the app | The outbox, deliveries and channels are owned by `control_audit_owner`. `control_app` has no privilege on them and cannot call `sentinel_*` or `host_*`. The outbox is append-only by trigger. |
| Delivered by someone else | `scripts/sentinel.ts` runs as a **separate process** under the **separate login** `control_sentinel`, whose only rights are `sentinel_claim`, `sentinel_ack` and `sentinel_watchdog`. Its password is in `.env.sentinel`. The web server never loads that file and refuses to start if it sees a sentinel or superuser variable; the sentinel in turn never loads the superuser or app password (217). Delivery and the watchdog run as independent loops on separate connections, and an error in one pass is logged and retried, never fatal (217). |
| Destinations set by the host only | `npm run host -- notify-add …` (superuser), with two kinds of channel. **file**: append-only JSONL at an **absolute** host path, opened with `O_NOFOLLOW` (a planted symlink is refused). **webhook**: an HTTP POST signed with HMAC-SHA256 over `timestamp.body`, using a per-channel 32-byte secret the app cannot read; the target must be `https://`, or `http://` on loopback only (217). |
| Delivery is proven | A webhook delivery counts only if the receiver answers 2xx **with** `X-Orvix-Ack = hex(HMAC-SHA256(secret, "ack." + notice_id + "." + timestamp))`. An impostor that binds the port and answers 200 cannot open a gate (217). |
| Gates the dangerous outcomes | A passkey added in-session becomes usable only after its `credential_added` notice was delivered to **every** recipient channel, at least one of them a host channel, **and** 15 minutes have passed **since that delivery** (217; before, the window counted from creation and could be consumed while delivery was held off). A recovery link can be redeemed only after the `recovery_approved` notice was delivered. An invited operator can be activated only after the `operator_enrolled` notice was delivered. |
| Fails closed | With no channel configured, or while any recipient's delivery fails, the gated outcomes stay blocked. Deliveries are retried forever (backoff capped at 300 s). `host -- notify-status` shows undelivered, failing (≥ 3 attempts) and **stuck** (≥ 20 attempts) deliveries, deliveries blocked by a **disabled** channel, notices without recipients, and the sentinel's **last claim time** (a stale value means the sentinel is down). |

**Notices:** owner enrolment; passkey added, revoked or flagged; recovery requested, approved, contested, cancelled, completed or host-confirmed; emergency revoke; operator invited, enrolled, approved or invite-revoked; step-ups for `credential_add`, `credential_revoke`, `recovery_approve`, `recovery_cancel` and `operator_invite`; sign-ins from a **new device** (217); suppressed failure-audit rows; watchdog terminations (written without the audit lock and announced at once, then folded into the hash chain; such notices carry `"seq": null` until folded); channel changes. **Recipients:** every enabled host channel, every active owner's channels, and the subject's channels.

**Payload:** sequence number, action, outcome, actor label, target, reason, time, `row_hash` (which links to the audit chain), and the audit detail. No tokens, keys or secrets.

## Free channels that work without a paid service

- A **file** channel on a host disk that the web app's OS user cannot write. Watch it with any log tool.
- A **webhook** to something the owner runs: a self-hosted ntfy or Gotify instance, a Matrix bot, an SMTP relay they already have, or a tiny receiver on another machine. Any webhook receiver must:
  1. verify `X-Orvix-Signature` with the channel secret (constant-time compare);
  2. reject an `X-Orvix-Timestamp` more than 300 s from its own clock;
  3. de-duplicate on `notice_id` (a retry re-sends the same body with a new timestamp, and a sentinel restart can deliver twice);
  4. answer 2xx with `X-Orvix-Ack` as above, and only after the notice is safely stored or shown.

## Limits (be precise)

- **Independent of a compromised app, not of a compromised host.** A superuser can disable the trigger, the sentinel or the channels. A host compromise is infrastructure trust.
- **A channel the attacker also reads defeats the purpose.** Route notices to a device or account separate from the console session.
- **Notification is not prevention.** It gives the owner the 15-minute window (passkeys), the redemption gate (recovery) and the host approval (operators) in which to react. Someone has to read the channel.
- **Local development** runs the sentinel as the same OS user as the app, so the separation there is credential-only. In production it must be a different OS user or container with its own secret file.
- Webhook deliveries retry with exponential backoff, capped at 300 s, without a limit. A permanently failing receiver, or a channel the host disabled, keeps the gated items in that snapshot blocked, by design (R-9).
- **The sentinel can read every webhook secret** (it signs with them). A compromised sentinel can therefore forge notices to receivers and acknowledge its own deliveries. It still cannot change the database's audit chain or open a gate without the ack-verified delivery of a real notice, but it is a trusted component: run it as its own OS user (production).
- A recovery link is redeemable as soon as its approval notice is delivered; there is no extra reaction window (R-5). Operator activation always has one: the host's manual approval.
