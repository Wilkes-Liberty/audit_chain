# Archival boundary and witness contract

Audit Chain 1.10 defines a checkpoint and an offline archive-bundle format. It
does not delete audit rows. `prune()` remains a no-op, including when eligible
rows exist and when retention is set to zero.

The format is a prerequisite for a later archival-boundary decision, not that
decision itself. Before deletion can be considered, an operator still needs a
durable archive, an independently checked bundle, an explicit retention policy,
and a later release that defines the deletion ceremony. A checkpoint or witness
receipt alone does not authorize pruning.

## Existing NDJSON export

The ordinary NDJSON export is deliberately data-minimized. It omits metadata,
IP addresses, user agents, and entity labels. Because `row_hash` covers those
omitted values, an off-system NDJSON consumer cannot recompute `row_hash` from
the exported record. Whole-row chain verification remains an on-system duty.

The archive bundle is a separate contract. It does not change the NDJSON shape,
delivery checkpoint, replay behavior, or verification gate.

## Closed global window

`ArchiveBundleExporter::create($fromId, $throughId)` closes one global window
under the same transaction-scoped mutex used by append, seal, and successor
operations. There is no channel argument. Both bounds must name stored rows.
Serial gaps are allowed because a rolled-back insert can consume a database
sequence value without creating a row.

The bundle row projection contains exactly four members in this order:

1. `contract_version` — integer `1`;
2. `id` — integer global row id;
3. `prev_hash` — lowercase stored hex or `null`;
4. `row_hash` — lowercase stored hex or `null`.

It contains no metadata, IP address, user agent, entity label, channel,
operation, actor id, entity identifier, or key identifier. This projection can
prove the bundle's internal commitment and chain-hash continuity. It still
cannot recompute the live row hash from omitted row content.

## Canonicalization and Merkle tree

Contract v1 uses UTF-8 JSON with unescaped slashes and Unicode, no insignificant
whitespace, and the member order shown by the schema and lists below. Numbers
are JSON integers. `null` remains JSON `null`. PHP array insertion order, not a
database collation or JSON-object sorting function, defines the order.

Each leaf is lowercase hex:

```text
SHA-256("audit_chain.archive.leaf.v1\n" || canonical_row_json)
```

Each parent is lowercase hex:

```text
SHA-256("audit_chain.archive.node.v1\n" || left_hex || right_hex)
```

If a level has an odd number of nodes, its last node is duplicated as the right
node. A one-row window uses its leaf hash as the Merkle root. The bundle carries
every leaf hash and a left/right sibling path for every row.

The checkpoint manifest has this fixed member order:

1. `contract`;
2. `contract_version`;
3. `instance_id`;
4. `window` (`from_id`, `through_id`, `row_count`);
5. `hash_algorithm`;
6. `merkle_algorithm`;
7. `merkle_root`;
8. `chain_head`;
9. `seal`;
10. `successor`.

`instance_id` is the runtime `audit_chain_instance_id` already required by
successor segments. `chain_head` is the stored `row_hash` at `through_id`.

When a prefix seal exists, the manifest records its row bounds and prefix
digest plus a SHA-256 commitment to the complete stored seal. The human reason,
actor id, key id, and seal MAC are not exported separately. When a successor
record exists, the manifest records its segment id, manifest digest, and a
SHA-256 commitment to the complete stored record. Recovery context stays local.

The checkpoint digest is:

```text
SHA-256("audit_chain.checkpoint.v1\n" || canonical_manifest_without_digest)
```

The returned manifest appends `digest` after that computation. Creation time is
stored beside the manifest in Drupal's checkpoint table and is not part of the
digest. Repeating the same window against unchanged rows, seal, successor, and
instance identity therefore produces the same hex digest on every supported
database engine.

Any change to row projection, member order, domain separators, odd-node rule,
manifest fields, or digest algorithm requires a new contract version. It must
not silently alter v1.

The machine-readable schema is
[`archive-bundle-v1.schema.json`](archive-bundle-v1.schema.json).

## Offline verification recipe

An offline verifier does not need Drupal or a signing key to check the bundle's
internal commitment:

1. Reject a bundle whose shape differs from the v1 JSON Schema.
2. Encode each row exactly as specified and recompute its domain-separated leaf
   hash.
3. Recompute the Merkle root by pairing in row order and duplicating an
   unpaired right node.
4. Check every supplied inclusion path against that root.
5. Remove the manifest's final `digest` member, encode the remaining manifest
   in its specified order, and recompute the checkpoint digest.
6. Confirm that `chain_head` equals the last bundle row's stored `row_hash` and
   that adjacent non-null hash columns have the expected continuity.

This proves that the bundle is self-consistent and committed by its checkpoint
digest. It does not reconstruct the omitted row contents or independently prove
that a bundle came from a particular live database.

## Witness seam

`WitnessBackendInterface` has three operations:

```php
public function submit(string $digestHex, array $context): WitnessReceipt;
public function upgrade(WitnessReceipt $pending): WitnessReceipt;
public function verify(WitnessReceipt $receipt, string $digestHex): WitnessVerdict;
```

The manager passes only the digest and the public checkpoint contract name. It
never passes a row, metadata, channel name, actor, entity identifier, seal
context, recovery context, or key material. Receipts persist a bounded id,
backend id, `submitted` / `pending` / `confirmed` status, submission and update
times, checkpoint digest, and opaque token.

A backend registered with the manager implements
`IdentifiedWitnessBackendInterface`, which adds only a stable configuration id
to the three-operation witness contract. It is tagged
`audit_chain.witness_backend`; a future implementation's id can then be named
in `audit_chain.settings:witness_backend`.

The shipped `null` backend remains pending and always returns the fail-closed
`backend_not_configured` verdict. It performs no network request. Witness
submission, upgrade, and verification do not call `log()` or `logKeyed()` and
therefore do not add row-level witness events to the global chain.

A future witness can prove that a checkpoint digest existed before some time
recognized by the verifier. It does not prove authorship, legal time by itself,
or that the live Drupal table is the archive. A public chain, if a future
backend uses one, is a witness transport rather than the Audit Chain ledger.
No wallet belongs in this module.
