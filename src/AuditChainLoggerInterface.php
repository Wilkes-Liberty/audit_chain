<?php

declare(strict_types=1);

namespace Drupal\audit_chain;

/**
 * A tamper-evident, append-only audit log.
 *
 * Each row's hash covers the row's own content *and* the previous row's hash,
 * so any later insertion, deletion or edit breaks the chain and is detectable
 * by verify(). With an HMAC key configured, forging a repair requires the key.
 *
 * Consumers write through this interface and are identified by a channel — a
 * short machine name such as `mcp_sentinel` or `personnel` — so one chain can
 * carry several kinds of event while keeping them filterable and attributable.
 *
 * Two constraints every consumer has to respect:
 *
 * - **Do not log per access check.** A hook like `hook_entity_field_access()`
 *   fires per field, per entity, per render; writing a row each time produces a
 *   chain nobody can read and a write-amplified request. Dedupe per request and
 *   flush once, at `kernel.terminate`.
 * - **Rotating the encryption profile orphans prior rows until they are
 *   re-encrypted.** Metadata encrypted under profile A cannot be read after
 *   switching to profile B if A is gone. The chain covers the plaintext, so
 *   verification still needs that plaintext — `drush audit-chain:reencrypt`
 *   rewrites ciphertext in place without touching hashes. Each row records
 *   which profile produced its bytes; the status report WARNs when any
 *   differ from the configured profile.
 */
interface AuditChainLoggerInterface {

  /**
   * Appends an entry to the chain.
   *
   * @param string $channel
   *   The consumer's machine name, e.g. 'mcp_sentinel'. Bound into the row
   *   hash, so a row cannot be re-attributed to another channel undetected.
   * @param string $operation
   *   A short operation identifier, e.g. 'entity_save'. Truncated to 64 bytes.
   * @param array $metadata
   *   Optional context. The keys 'entity_type', 'bundle', 'id' and 'label' are
   *   promoted to their own columns so they can be indexed and filtered;
   *   everything else is serialised into the metadata column (encrypted when an
   *   encryption profile is configured). All of it is covered by the hash.
   */
  public function log(string $channel, string $operation, array $metadata = []): void;

  /**
   * Walks the chain in insertion order and verifies every link.
   *
   * Deliberately takes no channel argument. The chain is global — entries from
   * every consumer are interleaved in one sequence — so a single channel cannot
   * be verified in isolation without the entries between its own, and a
   * per-channel walk could not tell a deletion from a gap. A break anywhere is
   * a break.
   *
   * Two different failures are reported differently, because they call for
   * different responses. A row whose content or ordering no longer matches its
   * hash is tampering (`REASON_TAMPERED`, with `broken_at` naming the row). A
   * row that is internally consistent but was hashed without the configured
   * signing key is not (`REASON_WRITTEN_UNKEYED`) — that is a chain which ran
   * unsigned, usually because a Key entity did not resolve in the environment
   * those rows were written in. Both are failures; only one means someone
   * edited the log.
   *
   * @return array{
   *   ok: bool,
   *   broken_at: int|null,
   *   reason: string|null,
   *   unkeyed_rows: int,
   *   unkeyed_through: int|null,
   *   verified_from: int|null,
   *   sealed_through: int|null,
   *   seal_intact: bool|null
   * }
   *   Additive shape: read the keys you need. 'sealed_through' / 'seal_intact'
   *   describe an operator seal over a historical unverifiable prefix (#5).
   *   'verified_from' is the first post-seal row id that was content-checked,
   *   or NULL when the chain is empty / fully sealed.
   */
  public function verify(): array;

  /**
   * Seals an unverifiable prefix so it is not re-chained or silently repaired.
   *
   * Records a genesis anchor over the *stored* row_hash values of rows with
   * id <= $throughId. Sealing proves nothing about the past; it makes any
   * future change to that prefix detectable and lets post-seal verification
   * exit cleanly. May only cover rows that do not currently verify under the
   * site's signing keys — sealing a verifiable row would hide good history.
   *
   * Writes an audit entry (`channel=audit_chain`, `operation=prefix_sealed`).
   *
   * @param int $throughId
   *   Highest row id included in the seal (inclusive).
   * @param string $reason
   *   Operator reason (required, non-empty).
   *
   * @return array{sealed: bool, message: string, seal: array|null}
   *   Whether the seal was recorded, a human message, and the seal record.
   */
  public function sealPrefix(int $throughId, string $reason): array;

  /**
   * Returns the active prefix seal, if any.
   *
   * @return array{
   *   sealed_through_id: int,
   *   row_count: int,
   *   prefix_digest: string,
   *   seal_mac: string,
   *   timestamp: int,
   *   uid: int,
   *   reason: string,
   *   key_id: string
   * }|null
   *   The seal, or NULL when none is stored.
   */
  public function getSeal(): ?array;

  /**
   * Decodes a stored metadata value, decrypting it when necessary.
   *
   * @param string $stored
   *   The raw value from the metadata column.
   * @param string $encryptionProfile
   *   The profile that produced $stored (from the row's encryption_profile
   *   column). Tried first. Empty falls through to the currently configured
   *   profile, then plaintext JSON.
   *
   * @return array
   *   The decoded metadata, or an empty array when it cannot be read.
   */
  public function decodeMetadata(string $stored, string $encryptionProfile = ''): array;

  /**
   * Re-encrypts rows from one encryption profile to another.
   *
   * Updates only `metadata` and `encryption_profile`. Never touches `row_hash`
   * or any column covered by the hash — re-encryption is a storage transform,
   * not a rewrite of history. Rows already on $toProfile or plaintext are
   * skipped. Refuses to start when either profile cannot be loaded.
   *
   * @param string $fromProfile
   *   Source EncryptionProfile id (must match rows' encryption_profile).
   * @param string $toProfile
   *   Destination EncryptionProfile id.
   * @param int $limit
   *   Max rows to process this call (for resumable batches). Zero or less
   *   means no limit.
   *
   * @return array{updated: int, failed: int, remaining: int, refused: string|null}
   *   Counts and optional refusal reason when profiles will not load.
   */
  public function reencrypt(string $fromProfile, string $toProfile, int $limit = 0): array;

  /**
   * Deletes a channel's entries older than a retention period.
   *
   * Deleting rows necessarily breaks the chain at the boundary — that is
   * inherent to an append-only structure, not a defect — so verify() reports
   * the seam afterwards. Export before pruning if the history has to stay
   * provable.
   *
   * @param string $channel
   *   The channel to prune.
   * @param int $retentionDays
   *   Age in days beyond which entries are deleted. Zero or less is a no-op.
   *
   * @return int
   *   Rows deleted.
   */
  public function prune(string $channel, int $retentionDays): int;

}
