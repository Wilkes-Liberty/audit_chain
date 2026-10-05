# Checkpoint witnesses

Audit Chain's ledger remains the local hash chain. A witness is a separate
receipt for one persisted checkpoint digest. The digest already commits to the
checkpoint manifest, including its Merkle root and chain head. Witnesses do
not receive audit rows, and witness operations do not append audit-chain rows.

## What a witness shows

A verified receipt shows that this digest was accepted by that witness under
the stated check. It does not show who created the rows, that a person
accepted work, or that a payment may be released. Bitcoin block time and an
XRPL ledger close time are properties of those ledgers. They are not the
Drupal submission clock and they are not legal time.

An application can associate a versioned agreement or statement with a witness
only through the audit log. The application writes that versioned digest as a
normal audit row. A later checkpoint commits to the row. Each witness receipt
commits to the checkpoint digest. The receipt stores no agreement id, invoice
id, or actor. A correction is a new audit-log version. Business acceptance
and settlement rules stay outside this module. A timestamp does not authorize
them.

## Backends

`witness_backend` empty selects the `null` backend. It stores a pending
receipt and verification returns `backend_not_configured`. It makes no network
request.

`opentimestamps` and `xrpl` are independent. Each digest can have one receipt
per backend. A failure of one does not remove the other. Status lists every
receipt and does not add their results together. `XRPL confirmed` beside
`Bitcoin pending` is one confirmation and one pending receipt.

OpenTimestamps submission sends the 32 raw digest bytes. The stored token is
a detached proof. Confirmation requires a Bitcoin attestation whose evaluated
message matches the block header's merkle root in internal byte order, whose
header hash matches the header source, and whose block is in the best chain at
the configured depth (default 6). The header source is trusted for best-chain
membership. This module does not validate chainwork. Litecoin and unknown
attestations do not confirm. A complete Bitcoin proof is checked without
contacting a calendar. A pending proof stays pending until an upgrade returns
a proof that passes that check. If every calendar request fails, the stored
proof bytes stay as they were.

The XRPL client sends the digest and a request id to the configured relay.
The relay credential lives in `settings.php` as
`audit_chain_witness_xrpl_token`. It is not an XRPL seed, and this module
does not sign. The expected transaction is a payment of 1 drop to the
configured witness sink, with one memo whose data is the digest. The witness
account and the sink are not customer payment accounts. Mainnet relay and
read URLs are refused. A receipt is confirmed only when a separate read shows
the transaction validated, `tesSUCCESS`, and the same template. A timeout
keeps the request id and does not by itself prove that nothing was submitted.
This module does not measure how long confirmation takes.

## Operator gate

`drush audit-chain:witness-submit` submits only when `--confirm-digest` is the
persisted digest and `--confirm-backends` is the same backend list. The
default is to do nothing. Drush `--yes` is not approval. Configuration
import, cron, hooks, routes, and the MCP tools do not submit. Repeat submit
reuses a pending or confirmed receipt for that backend and digest.
`--new-attempt` stores another receipt. Upgrading a receipt that is still
pending is a successful command. Verification exits non-zero when the fresh
verdict is not valid. A stored `confirmed` status is checked again and is not
trusted on its own.

`witness-export` writes the detached proof bytes or the XRPL receipt JSON.
Those bytes can be inspected without Drupal. `witness-status --require`
exits successfully only when each named backend has a fresh valid verdict.
`--require=all` means both. The default is to print every receipt.

## Limits

No wallet, fee payer, or settlement authority is included. Choosing a witness
does not prune, retain, or delete audit rows. Receipts are not a second
ledger.
