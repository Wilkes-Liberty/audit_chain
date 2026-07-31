<?php

declare(strict_types=1);

namespace Drupal\audit_chain;

/**
 * Collects entries during a request and writes them once, deduplicated.
 *
 * Exists because the obvious integration is also the one that destroys the
 * chain's usefulness. A hook like `hook_entity_field_access()` fires per field,
 * per entity, per render, so a consumer that calls the logger directly from one
 * turns a single human action into dozens of rows. The result is a chain nobody
 * can read, and the damage is not reversible: you cannot un-flood a hash chain
 * without breaking it.
 *
 * Documentation saying "do not do the obvious thing" is weaker than an API
 * where the obvious thing is correct, so consumers that log per access check
 * should collect here and let the subscriber flush at `kernel.terminate`.
 *
 * Deduplication is by caller-supplied key. The first occurrence wins: its
 * metadata is kept and later ones are discarded rather than merged, because a
 * read that happened forty times is still one read of one field, and merging
 * would invent a record of something nobody did.
 *
 * Order is insertion order of first occurrence, so the flushed rows read in the
 * sequence the request actually did things.
 */
final class AuditChainCollector {

  /**
   * Pending entries, keyed by dedup key.
   *
   * @var array<string, array{channel: string, operation: string, metadata: array}>
   */
  private array $pending = [];

  /**
   * Constructs an AuditChainCollector.
   *
   * @param \Drupal\audit_chain\AuditChainLoggerInterface $chain
   *   The chain each collected entry is ultimately written to.
   */
  public function __construct(
    private readonly AuditChainLoggerInterface $chain,
  ) {}

  /**
   * Records an entry to be written at the end of the request.
   *
   * @param string $channel
   *   The consumer's machine name, e.g. 'personnel'.
   * @param string $operation
   *   A short operation identifier, e.g. 'field_read'.
   * @param array $metadata
   *   Context, same shape as AuditChainLoggerInterface::log().
   * @param string|null $dedupeKey
   *   What makes two calls "the same event". Defaults to the channel, the
   *   operation and the promoted entity keys — which is the right answer for
   *   per-field access checks, where the field name is what repeats. Pass an
   *   explicit key to widen or narrow that.
   */
  public function collect(string $channel, string $operation, array $metadata = [], ?string $dedupeKey = NULL): void {
    $key = $dedupeKey ?? implode(':', [
      $channel,
      $operation,
      (string) ($metadata['entity_type'] ?? ''),
      (string) ($metadata['id'] ?? ''),
    ]);

    // First occurrence wins; see the class docblock on why later ones are not
    // merged.
    if (!isset($this->pending[$key])) {
      $this->pending[$key] = [
        'channel' => $channel,
        'operation' => $operation,
        'metadata' => $metadata,
      ];
    }
  }

  /**
   * Writes every collected entry to the chain and empties the buffer.
   *
   * Safe to call more than once: the buffer is cleared before writing, so a
   * flush triggered twice in one request cannot double-write. Cleared first
   * rather than after, so an exception mid-write cannot leave entries queued to
   * be written a second time by a later flush.
   *
   * @return int
   *   How many entries were written.
   */
  public function flush(): int {
    if ($this->pending === []) {
      return 0;
    }

    $entries = $this->pending;
    $this->pending = [];

    foreach ($entries as $entry) {
      $this->chain->log($entry['channel'], $entry['operation'], $entry['metadata']);
    }

    return count($entries);
  }

  /**
   * Returns how many distinct entries are queued.
   *
   * @return int
   *   The pending count, after deduplication.
   */
  public function count(): int {
    return count($this->pending);
  }

}
