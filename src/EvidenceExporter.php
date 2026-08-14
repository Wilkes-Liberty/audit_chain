<?php

declare(strict_types=1);

namespace Drupal\audit_chain;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\State\StateInterface;
use GuzzleHttp\ClientInterface;
use GuzzleHttp\Exception\GuzzleException;
use Psr\Log\LoggerInterface;

/**
 * Pushes chain rows to an off-system evidence destination (d.o #3616535).
 *
 * Local-only evidence shares fate with the system it audits: an attacker (or
 * a failure) that reaches the database reaches the record of the reach. This
 * service moves the durable copy outside that trust boundary as versioned,
 * data-minimized NDJSON — one JSON object per row, each carrying
 * `contract_version` so a consumer can detect shape changes.
 *
 * Data minimization: exported rows carry identifiers and the hash-chain
 * columns, never content — `metadata`, `ip_address`, `user_agent`, and
 * `entity_label` stay on-system. The consequence is deliberate: the off-system
 * copy cannot re-derive `row_hash` (the canonical payload includes metadata),
 * so chain verification remains an on-system duty — which is why export is
 * gated on the scheduled verification: while the last recorded run is failing,
 * export refuses rather than presenting unverified rows as evidence.
 *
 * Delivery is at-least-once. The per-destination checkpoint (a state entry
 * keyed on the destination) advances only after a delivery succeeds, so an
 * outage leaves it in place and the next run retries the same rows; a
 * checkpoint that lags a delivery re-sends the overlap. Consumers must treat
 * the row `id` as the idempotency key. A checkpoint never moves backwards —
 * replays (`$fromId`) re-emit history without regressing it.
 */
final class EvidenceExporter {

  /**
   * Version stamped on every exported row; bump on any shape change.
   */
  public const CONTRACT_VERSION = 1;

  /**
   * State-key prefix for per-destination checkpoints.
   *
   * The full key is this prefix plus sha1 of the destination string.
   */
  public const CHECKPOINT_PREFIX = 'audit_chain.export_checkpoint.';

  /**
   * Refusal reason: the last scheduled verification did not pass.
   */
  public const REASON_VERIFICATION_FAILING = 'verification_failing';

  /**
   * Failure reason: the destination did not accept the batch.
   */
  public const REASON_DELIVERY_FAILED = 'delivery_failed';

  /**
   * Refusal reason: plain HTTP to a non-loopback host.
   */
  public const REASON_INSECURE_DESTINATION = 'insecure_destination';

  /**
   * Failure reason: a row could not be JSON-encoded.
   */
  public const REASON_ENCODING_FAILED = 'encoding_failed';

  public function __construct(
    private readonly Connection $database,
    private readonly StateInterface $state,
    private readonly TimeInterface $time,
    private readonly ClientInterface $httpClient,
    private readonly LoggerInterface $logger,
  ) {}

  /**
   * Exports chain rows beyond the destination's checkpoint.
   *
   * @param string $destination
   *   Where to deliver: an http(s):// URL (the batch is POSTed as one
   *   application/x-ndjson body) or a file:// URI / filesystem path (the
   *   batch is appended under an exclusive lock).
   * @param int|null $fromId
   *   Replay: re-emit history starting at this row id instead of the
   *   checkpoint. The checkpoint only ever advances — a replay of rows it
   *   already covers leaves it where it was.
   * @param string|null $channel
   *   Restrict the export to one channel partition (NULL/'' = all).
   * @param int|null $limit
   *   Cap the batch at this many rows; the checkpoint makes successive
   *   limited runs resumable. NULL/0 = unbounded.
   *
   * @return array
   *   Run record: 'ok' (bool), 'delivered' (int), 'last_id' (int|null, the
   *   highest row id delivered), 'remaining' (int, rows still beyond the
   *   checkpoint after this run), 'reason' (string|null on failure).
   */
  public function exportTo(string $destination, ?int $fromId = NULL, ?string $channel = NULL, ?int $limit = NULL): array {
    // Evidence must not travel plain HTTP off-host: refuse before reading a
    // single row. Loopback stays allowed for on-host collector sidecars.
    if (str_starts_with($destination, 'http://') && !$this->isLoopback($destination)) {
      $this->logger->warning('Evidence export to @destination refused: plain HTTP off-host would expose evidence in transit. Use https:// or a loopback collector.', [
        '@destination' => self::redactDestination($destination),
      ]);
      return [
        'ok' => FALSE,
        'delivered' => 0,
        'last_id' => NULL,
        'remaining' => $this->remainingAfter(0, $channel),
        'reason' => self::REASON_INSECURE_DESTINATION,
      ];
    }

    $verification = $this->state->get(ScheduledVerifier::STATE_KEY);
    if (\is_array($verification) && empty($verification['ok'])) {
      $this->logger->warning('Evidence export to @destination refused: the last scheduled verification did not pass. Resolve the integrity failure before exporting.', [
        '@destination' => self::redactDestination($destination),
      ]);
      return [
        'ok' => FALSE,
        'delivered' => 0,
        'last_id' => NULL,
        'remaining' => $this->remainingAfter(0, $channel),
        'reason' => self::REASON_VERIFICATION_FAILING,
      ];
    }

    $checkpointKey = self::CHECKPOINT_PREFIX . sha1($destination);
    $checkpoint = $this->state->get($checkpointKey);
    $checkpointId = (int) ($checkpoint['last_id'] ?? 0);
    $afterId = $fromId !== NULL ? $fromId - 1 : $checkpointId;

    $query = $this->database->select('audit_chain_log', 'a')
      ->fields('a', [
        'id',
        'channel',
        'timestamp',
        'uid',
        'operation',
        'entity_type',
        'bundle',
        'entity_id',
        'prev_hash',
        'row_hash',
        'key_id',
      ])
      ->condition('a.id', $afterId, '>')
      ->orderBy('a.id', 'ASC');
    if ($channel !== NULL && $channel !== '') {
      $query->condition('a.channel', $channel);
    }
    if ($limit !== NULL && $limit > 0) {
      $query->range(0, $limit);
    }

    $payload = '';
    $count = 0;
    $lastId = $afterId;
    foreach ($query->execute() as $record) {
      // The throw is defensive: exported columns are machine data, but a
      // storage backend that admits invalid UTF-8 could still poison one row,
      // and that must fail the run with a structured reason — not fatal cron.
      try {
        $payload .= json_encode([
          'contract_version' => self::CONTRACT_VERSION,
          'id' => (int) $record->id,
          'channel' => (string) $record->channel,
          'operation' => (string) $record->operation,
          'timestamp' => (int) $record->timestamp,
          'uid' => (int) $record->uid,
          'entity_type' => $record->entity_type,
          'bundle' => $record->bundle,
          'entity_id' => $record->entity_id,
          'prev_hash' => $record->prev_hash,
          'row_hash' => $record->row_hash,
          'key_id' => $record->key_id,
        ], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES) . "\n";
      }
      catch (\JsonException $e) {
        $this->logger->error('Evidence export aborted: row @id could not be JSON-encoded (@message). The checkpoint is unchanged.', [
          '@id' => (int) $record->id,
          '@message' => $e->getMessage(),
        ]);
        return [
          'ok' => FALSE,
          'delivered' => 0,
          'last_id' => NULL,
          'remaining' => $this->remainingAfter($checkpointId, $channel),
          'reason' => self::REASON_ENCODING_FAILED,
        ];
      }
      $lastId = (int) $record->id;
      $count++;
    }

    if ($count === 0) {
      return [
        'ok' => TRUE,
        'delivered' => 0,
        'last_id' => NULL,
        'remaining' => 0,
        'reason' => NULL,
      ];
    }

    if (!$this->deliver($destination, $payload)) {
      $this->logger->error('Evidence export to @destination failed to deliver @count rows. The checkpoint is unchanged; the next run retries the same rows.', [
        '@destination' => self::redactDestination($destination),
        '@count' => $count,
      ]);
      return [
        'ok' => FALSE,
        'delivered' => 0,
        'last_id' => NULL,
        'remaining' => $this->remainingAfter($checkpointId, $channel),
        'reason' => self::REASON_DELIVERY_FAILED,
      ];
    }

    // Advance-only: a replay of already-covered history must never pull the
    // checkpoint back behind rows that were delivered in normal runs.
    $newCheckpointId = max($lastId, $checkpointId);
    // The label is redacted: ingest URLs can embed credentials (userinfo or a
    // query-string token), and state rows outlive the secret's rotation. The
    // sha1 key already identifies the destination exactly.
    $this->state->set($checkpointKey, [
      'last_id' => $newCheckpointId,
      'time' => $this->time->getRequestTime(),
      'destination' => self::redactDestination($destination),
    ]);

    $remaining = $this->remainingAfter($newCheckpointId, $channel);
    $this->logger->info('Exported @count audit-chain rows (through id @last_id) to @destination; @remaining remaining.', [
      '@count' => $count,
      '@last_id' => $lastId,
      '@destination' => self::redactDestination($destination),
      '@remaining' => $remaining,
    ]);
    return [
      'ok' => TRUE,
      'delivered' => $count,
      'last_id' => $lastId,
      'remaining' => $remaining,
      'reason' => NULL,
    ];
  }

  /**
   * Counts rows still beyond a checkpoint, honoring the channel filter.
   */
  private function remainingAfter(int $afterId, ?string $channel): int {
    $query = $this->database->select('audit_chain_log', 'a')
      ->condition('a.id', $afterId, '>');
    if ($channel !== NULL && $channel !== '') {
      $query->condition('a.channel', $channel);
    }
    return (int) $query->countQuery()->execute()->fetchField();
  }

  /**
   * Whether an http(s) destination's host is a loopback address.
   */
  private function isLoopback(string $destination): bool {
    $host = parse_url($destination, PHP_URL_HOST);
    return \in_array($host, ['127.0.0.1', '::1', '[::1]', 'localhost'], TRUE);
  }

  /**
   * A destination label safe to log and persist.
   *
   * Ingest URLs can embed credentials — userinfo or a query-string token — so
   * only scheme, host, port and path survive. File paths pass through.
   */
  public static function redactDestination(string $destination): string {
    if (!str_starts_with($destination, 'http://') && !str_starts_with($destination, 'https://')) {
      return $destination;
    }
    $parts = parse_url($destination);
    if ($parts === FALSE || empty($parts['host'])) {
      return '(unparseable URL)';
    }
    return ($parts['scheme'] ?? 'https') . '://' . $parts['host']
      . (isset($parts['port']) ? ':' . $parts['port'] : '')
      . ($parts['path'] ?? '');
  }

  /**
   * Delivers one NDJSON batch; FALSE on any failure (nothing checkpointed).
   */
  private function deliver(string $destination, string $payload): bool {
    if (str_starts_with($destination, 'http://') || str_starts_with($destination, 'https://')) {
      try {
        $response = $this->httpClient->request('POST', $destination, [
          'headers' => ['Content-Type' => 'application/x-ndjson'],
          'body' => $payload,
          // Bounded so cron and drush cannot hang on a stalled collector; a
          // timeout is a delivery failure and retries from the checkpoint.
          'connect_timeout' => 10,
          'timeout' => 30,
        ]);
      }
      catch (GuzzleException) {
        return FALSE;
      }
      $status = $response->getStatusCode();
      return $status >= 200 && $status < 300;
    }

    $path = str_starts_with($destination, 'file://')
      ? substr($destination, 7)
      : $destination;
    $directory = \dirname($path);
    if (!is_dir($directory) || !is_writable($directory) || (file_exists($path) && !is_writable($path))) {
      return FALSE;
    }
    return file_put_contents($path, $payload, FILE_APPEND | LOCK_EX) !== FALSE;
  }

}
