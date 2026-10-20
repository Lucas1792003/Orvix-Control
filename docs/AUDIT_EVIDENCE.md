# Audit evidence: chain, anchors and offline verification

## Layers

| Layer | Where | Detects | Does not detect |
|---|---|---|---|
| Append-only grants and triggers | 201, 207 | writes by any role other than the superuser | a superuser who disables triggers |
| Hash chain (`audit_verify`) | 201 | any edited or deleted row in the middle of the chain | a superuser who recomputes the chain |
| On-host anchors | `control.audit_anchors` | tail truncation, while the anchor rows survive | a superuser who also deletes them (tested) |
| Passkey anchors **v1** (206) | DB + exported bundle | changes made after a bundle that was copied off-host **before** the compromise | **anything once the server or app is compromised.** Any WebAuthn prompt can be turned into a v1 signature over a head the attacker chooses (review HIGH-1, reproduced in `tests/sql/anchors.test.ts`). v1 is a convenience only. |
| **Offline anchors v2 (authoritative)** | files on the owner's machine | any change, deletion or truncation at or before an anchored seq, including a full chain recompute by a superuser | events after the newest v2 anchor (reported as an unanchored tail and treated as a failure by default) |

## v2 procedure (no external service)

1. **Once**, on the owner's own machine (not the server): `npm run audit:keygen -- --out <private dir>`. This writes `anchor-key.pem` (0600) and prints its fingerprint. Record the fingerprint in at least two places (for example a password manager and paper).
2. **Periodically, and after sensitive events:** in the console, Audit → *Export events*, then download the JSON to the owner's machine.
3. `npm run audit:sign -- --events events.json --archive <archive dir> --key anchor-key.pem`
   - The tool prints the key fingerprint and a **summary of every event since the newest anchor**: counts per action, the time range, and the sensitive rows (refusals, failures, credentials, recovery, step-ups). It then stops.
   - Compare the summary with what you know happened. Then re-run with `--confirm-head <seq>:<hash prefix>`.
   - With an empty archive it also requires `--init` (trust on first use).
   - It **refuses** unless the export is a valid chain from genesis and agrees with **every** anchor already in the archive (`HISTORY_REWRITTEN_AT_n`, `TRUNCATED_BELOW_ANCHOR_n`).
   - On success it writes `anchor-v2-seq<n>.json` (Ed25519 over `orvix-control/anchor/v2|seq|head|signed_at`). The file is never overwritten.
4. **To verify at any time:** `npm run audit:verify -- --events events.json --archive <archive dir> --anchor-key <fingerprint>`
   - Add `--allow-unanchored-tail` to accept events after the newest anchor; they are reported, never counted as verified.
   - v1 bundles in the archive need `--pin <passkey key fingerprint> --origin http://localhost:3410 --rp-id localhost`.
   - A run never passes on v1 bundles alone.

## Trust assumptions (precise)

- **Key custody:** the anchor private key and the archive are kept off the server, and the archive is append-only in the owner's custody.
- **The unanchored tail is only as trustworthy as the server that exported it.** Anchored history cannot be rewritten without detection. Events **after** the newest anchor, however, can be altered, dropped or invented by a compromised server before export, and the signer cannot tell (final review, audit M1). That is why it shows the tail and demands `--confirm-head`. Anchor **soon after every sensitive event** to keep that window short. An earlier version of this document wrongly said such a head "only adds events".
- **Canonical form:** the canonical text of each row must be **byte-identical** to the verifier's own re-serialisation in PostgreSQL's jsonb text format. That rules out duplicate keys, alternative escapes, lone surrogates and alternative number forms. Export and archive files are parsed strictly (numbers must round-trip). The archive loader rejects unexpected files and duplicate anchors, and ignores dotfiles.
- **Field values:** the verifier checks that the exported per-row fields match the hashed canonical text. Numbers that cannot round-trip exactly (precision loss, `1.50`, exponents) are rejected (`UNSAFE_NUMBER`). The database prevents such numbers from being written at all: since 208, `audit_append` stores them as strings, so one bad row cannot block all future verification and anchoring. The verifier fails closed on runtimes without JSON source access (Node < 22).
- **First anchor is trust-on-first-use:** with an empty archive, the signer accepts any valid chain from genesis. Make the first v2 anchor before the server is exposed to anyone else.
- **Unsigned bundle metadata:** for v1, the anchor id, creation time and signer label are not covered by the signature and are ignored.
- **No outside service:** nothing here contacts an external service. Off-host *storage* of the archive is an owner action (out of scope: no destinations are configured).
