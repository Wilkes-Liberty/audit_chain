# Witness demo runbook

This is a controlled-environment walk of the OpenTimestamps and XRPL
clients that already ship in Audit Chain. It is not a production
activation. Shipped `witness_backend` stays empty. Nothing here signs an
XRPL transaction.

The XRPL client posts a digest and a request id to a relay and then
reads the ledger. The injected signer that builds the one-drop payment
lives in the separate `moneta` service (DEV-850). Point this demo at
that relay. Do not put a family seed in Drupal config or in this
repository.

## Before a live demo: lead time

OpenTimestamps will not be Bitcoin-confirmed when you submit. Plan for
that. Do not start a live walk hoping the calendar finishes during the
talk.

1. The evening before, or 12–24 hours ahead, run `prepare`,
   `checkpoint`, and `submit` on the demo site. That posts the digest to
   the public calendars. Leave the receipt in place. Do not `reset`.
2. Before the audience arrives, run `drush audit-chain:witness-demo
   status` and `drush audit-chain:witness-demo upgrade`. The
   OpenTimestamps line must be `confirmed` (Bitcoin attestation in the
   proof). If it is still `pending`, wait or use the fallback below.
   `upgrade` does not wait inside the command.
3. Keep a pre-confirmed receipt as fallback: a digest you already
   upgraded to Bitcoin, plus its receipt id. If the live checkpoint is
   still pending, show verify and tamper against that older receipt
   (`drush audit-chain:witness-verify --receipt=… --digest=…` and the
   demo `tamper` step with `--digest`). Do not claim a pending proof is
   confirmed.

XRPL testnet usually confirms in seconds once the relay submits. Testnet
resets can wipe funded accounts. Fund the witness and sink from
`https://faucet.altnet.rippletest.net/accounts` the same day as the
demo. Do not rely on balances from an earlier week.

The shipped `witness_backend` setting stays empty. This lead time is
only for the controlled demo site.

## What the demo shows

1. A persisted archive checkpoint.
2. Submit to both backends. Each stores its own pending receipt.
3. Upgrade. OpenTimestamps usually stays pending for hours, until a
   calendar returns a Bitcoin attestation. XRPL moves to confirmed once
   the relay's transaction is validated on testnet.
4. Verify. A complete receipt passes. A still-pending receipt fails
   closed and says so.
5. Tamper. Verify against a flipped digest fails. The existing rewind
   detector (`RewindDetector`) is asked about each backend without
   turning on scheduled verification.

Bitcoin confirmation is slow. The demo prints a pending OpenTimestamps
receipt honestly. Do not wait inside a command.

## Timing

| Step | Typical wait |
| --- | --- |
| `prepare` | Immediate. |
| `checkpoint` | Immediate. The chain must already have at least one row. |
| `submit` | Seconds. OpenTimestamps talks to the public calendars. XRPL talks to the relay. |
| `status` | Immediate. No network. |
| `upgrade` (OTS) | Seconds for the calendar read. The receipt stays `pending` until Bitcoin is in the proof, often several hours. |
| `upgrade` (XRPL) | Seconds to a few minutes after the relay submits, once testnet validates the payment. |
| `verify` | Seconds. A pending OTS proof is `invalid` / `receipt_not_final` or `receipt_not_confirmed`. |
| `tamper` | Seconds. The chain is not rewritten. |
| `reset` | Immediate. Removes demo receipts only. |

## One-time settings

Add this to the demo site's `settings.php`. Keep it out of production
and out of exported config.

```php
$settings['audit_chain_witness_demo'] = TRUE;
$settings['audit_chain_instance_id'] = 'demo-instance-id';

// Bearer token for the moneta (or other) witness relay. Not an XRPL seed.
$settings['audit_chain_witness_xrpl_token'] = getenv('AUDIT_CHAIN_XRPL_TOKEN');
$settings['audit_chain_witness_xrpl_relay_url'] = getenv('AUDIT_CHAIN_XRPL_RELAY_URL');
$settings['audit_chain_witness_xrpl_read_url'] = getenv('AUDIT_CHAIN_XRPL_READ_URL');
$settings['audit_chain_witness_xrpl_witness_account'] = getenv('AUDIT_CHAIN_XRPL_ACCOUNT');
$settings['audit_chain_witness_xrpl_sink_address'] = getenv('AUDIT_CHAIN_XRPL_SINK');
```

`prepare` copies the four non-secret XRPL values into site config and
forces `network: xrpl:testnet`. It refuses mainnet hostnames. The token
stays in settings. `witness_backend` is not written.

OpenTimestamps uses the install-default public calendars
(`a.pool.opentimestamps.org`, `b.pool.opentimestamps.org`) and the
default header source. Those URLs are inactive until a command names
the `opentimestamps` backend.

## Point the demo at the moneta relay

1. Run the moneta checkpoint-witness HTTP handler in a testnet/devnet
   only process. Its listen binding is not part of this module. If that
   handler is not yet wired to `listen`, that work belongs in a moneta
   draft PR, not here.
2. Export `AUDIT_CHAIN_XRPL_RELAY_URL` as the handler's HTTPS URL
   (port 443; this module refuses non-HTTPS and private destinations).
3. Export `AUDIT_CHAIN_XRPL_READ_URL` as the read service that returns
   `GET {read}/transactions/{hash}` and
   `GET {read}/accounts/{account}/transactions` in the shapes
   documented in [WITNESS.md](WITNESS.md).
4. Export `AUDIT_CHAIN_XRPL_TOKEN` as the relay bearer token. Generate
   it in the demo environment. Do not commit it.
5. Fund two Testnet accounts from the faucet at
   `https://faucet.altnet.rippletest.net/accounts`. The witness account
   is the one moneta signs from. The sink is a different funded
   account. One drop moves from witness to sink. Put the classic
   addresses in `AUDIT_CHAIN_XRPL_ACCOUNT` and `AUDIT_CHAIN_XRPL_SINK`.
   The family seed stays in moneta's environment, never in Drupal.

The relay request body is only `{"digest":"…","request_id":"…"}`.

## Commands

The site must already have at least one audit-chain row and a unique
`audit_chain_instance_id`. Append a real row from whatever consumer you
are demonstrating. The demo does not invent chain entries.

```text
# Refuse unless the settings switch is on.
drush audit-chain:witness-demo prepare

# Close a checkpoint over the live chain.
drush audit-chain:witness-demo checkpoint
# expected: digest=<64 hex> from_id=1 through_id=N

# Submit to OpenTimestamps and XRPL. Approval is the demo switch, not
# the production --confirm-digest gate.
drush audit-chain:witness-demo submit
# expected: two lines, both status pending (XRPL may confirm immediately
# if the relay already saw a validated read)

drush audit-chain:witness-demo status
# expected: receipt-id backend status, no combined confirmation count

drush audit-chain:witness-demo upgrade
# expected: opentimestamps pending for hours; xrpl confirmed once
# testnet validates the one-drop payment

drush audit-chain:witness-demo verify
# expected: xrpl valid confirmed after a validated read;
# opentimestamps invalid until the Bitcoin proof is complete

drush audit-chain:witness-demo tamper
# expected: each receipt invalid checkpoint_digest_mismatch against a
# flipped digest; rewind_scheduled not_configured (selector still empty);
# rewind_xrpl matches once the ledger lists the payment;
# rewind_opentimestamps absent or unchecked until Bitcoin confirms

# Same walk as the steps above.
drush audit-chain:witness-demo run
```

Existing operator commands still work if you want the production gate:

```text
drush audit-chain:witness-submit --digest=DIGEST --backends=opentimestamps,xrpl \
  --confirm-digest=DIGEST --confirm-backends=opentimestamps,xrpl
drush audit-chain:witness-upgrade --receipt=RECEIPT
drush audit-chain:witness-verify --receipt=RECEIPT --digest=DIGEST
drush audit-chain:witness-status --digest=DIGEST
```

## Reset

```text
drush audit-chain:witness-demo reset
```

This deletes witness receipts for the last demo digest, clears the XRPL
site-config overlay, and forgets the demo session. It does not delete
audit-chain rows, checkpoints, or `settings.php`. `witness_backend`
stays whatever it was (empty on a site that never changed it).

To disable the switch, remove `$settings['audit_chain_witness_demo']`
and the XRPL settings keys. `reset` still runs after the switch is off
so a leftover overlay can be cleared.

## Tests

Kernel and unit tests mock calendars, the relay, and the ledger. They
never open a live socket.

An optional live smoke test hits the public OpenTimestamps calendars
and, when the XRPL env vars above are set, the configured testnet
relay. It is skipped unless `AUDIT_CHAIN_LIVE_WITNESS=1`.
