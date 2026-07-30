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
 * - **Rotating the encryption profile orphans prior rows.** Metadata encrypted
 *   under profile A cannot be read after switching to profile B; those rows
 *   then fail verification, because the chain is computed over the plaintext.
 *   Export or re-encrypt before rotating.
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
   * @return array{ok: bool, broken_at: int|null, reason: string|null, unkeyed_rows: int, unkeyed_through: int|null}
   *   'ok' is FALSE on either failure. 'reason' is an AuditChainLogger REASON_*
   *   constant, or NULL when ok. 'broken_at' is the offending row id for
   *   tampering and NULL otherwise. 'unkeyed_rows' counts rows that verified
   *   only without a key, and 'unkeyed_through' is the highest such row id.
   */
  public function verify(): array;

  /**
   * Decodes a stored metadata value, decrypting it when necessary.
   *
   * @param string $stored
   *   The raw value from the metadata column.
   *
   * @return array
   *   The decoded metadata, or an empty array when it cannot be read.
   */
  public function decodeMetadata(string $stored): array;

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
