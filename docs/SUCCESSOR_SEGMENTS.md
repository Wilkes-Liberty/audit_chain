# Successor segments: implementation contract

Available in Audit Chain 1.8.0. Public tracking:
https://www.drupal.org/project/audit_chain/issues/3623864.

## What a successor proves

A successor records an operator's decision to continue after an investigated
historical failure. It does not recover lost chronology, repair a fork, or
make old verification failures pass. Existing rows, hashes and seals remain
unchanged.

The existing whole-history verifier remains authoritative for whole-history
claims. A separate verifier reports successor health with an explicit
historical exception. Existing evidence export remains blocked by a failed
whole-history verdict until an explicit segment-aware export contract exists.

## Storage and signing

Use a dedicated append-only recovery-record table. Each record holds a segment
UUID, a versioned canonical manifest and its HMAC. Do not store keys.
The manifest binds:

- A runtime instance identity that is not exported with site configuration.
- The original verification verdict and existing seal fingerprint.
- A digest of the retained historical records, their count and highest ID.
- Every retained branch tip and the selected predecessor head.
- Incident reference, operator identity, approval time and reason.
- Reviewed backup digest, segment UUID and signing-key identifier.

The first new record in the log identifies the segment and manifest digest.
Its normal keyed hash links to the selected historical head. This is a logical
segment boundary, not an undocumented reset of prev_hash. The signed recovery
manifest discloses other retained branch tips.

## Preparation and activation

Provide separate privileged Drush preparation and activation commands.
Preparation is read-only and returns a reviewable snapshot digest. Activation
requires that exact digest, a segment UUID, the recovery context and explicit
confirmation. Do not expose activation through anonymous routes or MCP.

Activation takes the same transaction-scoped mutex as appends, reads a current
snapshot, refuses stale approval, requires an available active signing key,
and atomically writes the recovery record and first successor receipt.
Retries with identical inputs return the existing record. Reusing an identifier
with different inputs fails. A caller rollback removes both new records.

Quiesce and replace pre-mutex workers before activation. A patched writer
cannot serialize an older writer that does not take the mutex.

## Verification and monitoring

Before reporting successor health, authenticate the recovery record using an
active or explicitly retained verification key. Check its runtime instance
identity, recompute the retained historical digest, and verify the receipt and
every successor row with the normal canonical hashing rules.

Return separate historical and successor results. A missing checkpoint,
changed history, changed seal, missing key or missing receipt fails closed.
Copying a database does not authorize its recovery manifest for a different
runtime instance.

The historical digest binds logical row content as well as stored hashes,
predecessors and row IDs. It reuses the normal verifier's canonical encoding,
and also binds stored metadata, key identifiers and encryption-profile hints.
This preserves the evidence bytes even where historical metadata could not
be interpreted. Bulk re-encryption and resealing are refused once a recovery
record exists. Retain the historical decryption keys; future archival and
re-encryption need their own reviewed evidence-preservation protocol.

Scheduled monitoring continues to report the historical exception and reports
new successor defects separately. The dashboard never collapses the combined
result to a green whole-history badge.

## Retention prerequisite

Until an archival protocol preserves verification, refuse destructive pruning.
Report the refusal and its storage consequences. Do not replace it with a
silent no-op, an unverified archive, a direct SQL delete, or a new prefix seal.

## Required tests

- Authentic synthetic fork; unchanged historical failure after activation.
- Cross-channel and legacy-channel retention, including sealed evidence.
- Concurrent activation and append on PostgreSQL and MySQL.
- Caller rollback, lock failure, stale snapshot and idempotent retry.
- Wrong, missing and retired signing keys; altered recovery context.
- Deleted or changed history, seal, recovery record or receipt.
- Cross-instance copied record refusal.
- Export and dashboard disclosure; no whole-history success substitution.
- Supported Drupal-version matrix and migration from the previous schema.

## Operator procedure

1. Preserve a backup, verify an isolated restore and record its SHA-256 digest.
   Keep the original verifier output. Quiesce writers and exporters during preparation and
   activation so that the reviewed snapshot remains current.
2. Install the new code and run database updates. Replace every older worker.
   Updates create storage only; they do not activate recovery or rewrite history.
3. Set a stable, unique runtime identity in settings.php:
   `$settings['audit_chain_instance_id'] = 'your-deployment-identity';`
   This is a non-secret identifier. Override it separately for staging and
   production, and when cloning a database. Do not export it as site config.
4. Run `drush audit-chain:recovery-prepare`. Review the snapshot, original
   verdict, retained branch tips and selected head. Preserve that output.
5. Run `drush audit-chain:recovery-activate` with `--segment` (a new UUID),
   `--snapshot` (the exact reviewed digest), `--incident`, `--reason`,
   `--approved-by` and `--backup-digest`. Confirm the historical exception.
   The operator name is an approval assertion, authenticated by the site's
   recovery signature; it is not a separate personal digital signature.
6. Run `drush audit-chain:recovery-verify SEGMENT_UUID`. Exit zero means only
   that the successor and retained anchor verify. The JSON still reports
   `historical_ok: false`. Run ordinary `audit-chain:verify` separately and
   confirm the original failure remains.
7. Run `drush audit-chain:recovery-export SEGMENT_UUID` and preserve the signed
   record with the incident evidence. This exports the recovery record, not
   raw audit rows or key values. Ordinary evidence export remains blocked.
8. Run scheduled verification and confirm the dashboard distinguishes the
   failed original history from successor health. Resume writers and verify
   again after new work has appended.

Only one recovery segment is supported in this first implementation. Another
failure is a new incident requiring review, not permission to roll over again.
The recovery API is not exposed through web routes or MCP. Drush access is
privileged host access; secure it accordingly.

An in-database chain cannot, on its own, prove that an attacker did not remove
its entire uncheckpointed tail. Preserve independently held evidence and
backups; the successor is not a replacement for those controls.
