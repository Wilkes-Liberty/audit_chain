<?php

declare(strict_types=1);

namespace Drupal\audit_chain;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\ImmutableConfig;
use Drupal\Core\Database\Connection;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Lock\LockBackendInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\encrypt\EncryptionProfileInterface;
use Drupal\encrypt\EncryptServiceInterface;
use Drupal\key\KeyRepositoryInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Hash-chained implementation of the audit chain.
 *
 * row_hash = HMAC-SHA256(prev_hash | canonical, key), or SHA-256 of the same
 * message when no Key entity is configured. The canonical form has a fixed key
 * order so the hash is reproducible regardless of insertion order, and includes
 * the forensic columns (label, IP, user agent) so editing those breaks the
 * chain too.
 *
 * Extracted from mcp_sentinel 1.13, which remains its first consumer. The
 * behaviour is deliberately unchanged from that implementation — the point of
 * the extraction was to stop "governed AI" being a prerequisite for "governed
 * anything", not to redesign the chain.
 */
final class AuditChainLogger implements AuditChainLoggerInterface {

  /**
   * Lock name serialising the read-latest-then-insert critical section.
   */
  private const CHAIN_LOCK = 'audit_chain_append';

  /**
   * Constructs an AuditChainLogger.
   *
   * @param \Drupal\Core\Database\Connection $database
   *   The database connection.
   * @param \Drupal\Core\Session\AccountProxyInterface $currentUser
   *   The current user proxy (attribution).
   * @param \Symfony\Component\HttpFoundation\RequestStack $requestStack
   *   The request stack (IP and User-Agent; absent on CLI).
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The config factory.
   * @param \Drupal\Component\Datetime\TimeInterface $time
   *   The time service.
   * @param \Drupal\key\KeyRepositoryInterface $keyRepository
   *   The Key repository, resolving the HMAC signing key.
   * @param \Drupal\Core\Lock\LockBackendInterface $lock
   *   The lock backend. Without it, two concurrent appends can read the same
   *   prev_hash and produce a fork that verification then reports as tampering.
   * @param \Psr\Log\LoggerInterface $logger
   *   The audit_chain logger channel.
   * @param \Drupal\encrypt\EncryptServiceInterface $encryptService
   *   The Encrypt service, for at-rest metadata encryption.
   * @param \Drupal\Core\Entity\EntityTypeManagerInterface $entityTypeManager
   *   The entity type manager, loading EncryptionProfile entities.
   */
  public function __construct(
    private readonly Connection $database,
    private readonly AccountProxyInterface $currentUser,
    private readonly RequestStack $requestStack,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly TimeInterface $time,
    private readonly KeyRepositoryInterface $keyRepository,
    private readonly LockBackendInterface $lock,
    private readonly LoggerInterface $logger,
    private readonly EncryptServiceInterface $encryptService,
    private readonly EntityTypeManagerInterface $entityTypeManager,
  ) {}

  /**
   * {@inheritdoc}
   */
  public function log(string $channel, string $operation, array $metadata = []): void {
    $config = $this->configFactory->get('audit_chain.settings');
    $request = $this->requestStack->getCurrentRequest();
    $timestamp = $this->time->getRequestTime();

    $row = [
      'channel' => substr($channel, 0, 64),
      'operation' => substr($operation, 0, 64),
      'entity_type' => $metadata['entity_type'] ?? NULL,
      'bundle' => $metadata['bundle'] ?? NULL,
      'entity_id' => (string) ($metadata['id'] ?? ''),
      'entity_label' => isset($metadata['label'])
        ? substr((string) $metadata['label'], 0, 255)
        : NULL,
      'ip_address' => $request?->getClientIp(),
      'user_agent' => $request
        ? substr((string) $request->headers->get('User-Agent', ''), 0, 512)
        : NULL,
      'timestamp' => $timestamp,
      'uid' => (int) $this->currentUser->id(),
    ];
    $extra = array_diff_key($metadata, array_flip(['entity_type', 'bundle', 'id', 'label']));

    $keyValue = $this->resolveHashKey($config->get('hash_key'));

    // Serialise read-latest-then-insert. If the lock cannot be taken the entry
    // is still written — never drop an audit record — but the ordering
    // guarantee is best-effort for that request.
    $locked = $this->lock->acquire(self::CHAIN_LOCK, 3.0);
    try {
      $canonical = $this->buildCanonical($row, $extra);
      $prevHash = $this->latestRowHash();
      $rowHash = $this->hashRow($prevHash ?? '', $canonical, $keyValue);

      $this->database->insert('audit_chain_log')
        ->fields($row + [
          'metadata' => $this->encodeMetadata($extra, $config),
          'prev_hash' => $prevHash,
          'row_hash' => $rowHash,
        ])
        ->execute();

      // A stable message template with the variable data in context, so log
      // aggregators can group by template and a SIEM can consume the fields.
      if ($config->get('stream_enabled')) {
        $this->logger->info('audit_chain_event', [
          'channel' => $row['channel'],
          'operation' => $row['operation'],
          'uid' => $row['uid'],
          'entity_type' => $row['entity_type'],
          'entity_id' => $row['entity_id'],
          'timestamp' => $row['timestamp'],
          'row_hash' => $rowHash,
        ]);
      }
    }
    finally {
      if ($locked) {
        $this->lock->release(self::CHAIN_LOCK);
      }
    }
  }

  /**
   * {@inheritdoc}
   */
  public function verify(?string $channel = NULL): array {
    $keyValue = $this->resolveHashKey(
      $this->configFactory->get('audit_chain.settings')->get('hash_key')
    );

    $result = $this->database->select('audit_chain_log', 'l')
      ->fields('l')
      ->orderBy('id', 'ASC')
      ->execute();

    $prevRowHash = '';
    foreach ($result as $record) {
      $record = (array) $record;

      // Rows with no hash predate chaining (or were written by a migration
      // that could not chain them). Skip, and reset so the next chained row can
      // start a fresh segment whose prev_hash is also empty.
      if ($record['row_hash'] === NULL || $record['row_hash'] === '') {
        $prevRowHash = '';
        continue;
      }

      $canonical = $this->buildCanonical([
        'channel' => (string) ($record['channel'] ?? ''),
        // Truncated to match the write path, so a future column-width change
        // cannot silently desync the hashes.
        'operation' => substr((string) $record['operation'], 0, 64),
        'entity_type' => $record['entity_type'],
        'bundle' => $record['bundle'],
        'entity_id' => (string) ($record['entity_id'] ?? ''),
        'entity_label' => isset($record['entity_label']) ? (string) $record['entity_label'] : NULL,
        'ip_address' => isset($record['ip_address']) ? (string) $record['ip_address'] : NULL,
        'user_agent' => isset($record['user_agent']) ? (string) $record['user_agent'] : NULL,
        'timestamp' => (int) $record['timestamp'],
        'uid' => (int) $record['uid'],
      ], $this->decodeMetadata((string) ($record['metadata'] ?? '')));

      $storedPrev = (string) ($record['prev_hash'] ?? '');

      // Continuity: this row must point at the previous chained row.
      if ($storedPrev !== $prevRowHash) {
        return ['ok' => FALSE, 'broken_at' => (int) $record['id']];
      }
      // Integrity: the stored hash must match a recomputation of the content.
      if ((string) $record['row_hash'] !== $this->hashRow($storedPrev, $canonical, $keyValue)) {
        return ['ok' => FALSE, 'broken_at' => (int) $record['id']];
      }

      $prevRowHash = (string) $record['row_hash'];
    }

    return ['ok' => TRUE, 'broken_at' => NULL];
  }

  /**
   * {@inheritdoc}
   */
  public function decodeMetadata(string $stored): array {
    if ($stored === '') {
      return [];
    }

    $profileId = (string) ($this->configFactory->get('audit_chain.settings')->get('encryption_profile') ?? '');
    if ($profileId !== '') {
      $profile = $this->loadEncryptionProfile($profileId);
      if ($profile !== NULL) {
        try {
          $decoded = json_decode($this->encryptService->decrypt($stored, $profile), TRUE);
          if (is_array($decoded)) {
            return $decoded;
          }
        }
        catch (\Throwable) {
          // Fall through: rows written before encryption was enabled, or under
          // a different profile, are still plain JSON (or unreadable, which
          // verification will surface rather than hide).
        }
      }
    }

    $decoded = json_decode($stored, TRUE);
    return is_array($decoded) ? $decoded : [];
  }

  /**
   * {@inheritdoc}
   */
  public function prune(string $channel, int $retentionDays): int {
    if ($retentionDays <= 0) {
      return 0;
    }
    $cutoff = $this->time->getRequestTime() - ($retentionDays * 86400);
    return (int) $this->database->delete('audit_chain_log')
      ->condition('channel', $channel)
      ->condition('timestamp', $cutoff, '<')
      ->execute();
  }

  /**
   * Returns the most recently inserted row's hash, or NULL when empty.
   *
   * Race-free only while CHAIN_LOCK is held.
   *
   * @return string|null
   *   The hex hash, or NULL.
   */
  private function latestRowHash(): ?string {
    $hash = $this->database->select('audit_chain_log', 'l')
      ->fields('l', ['row_hash'])
      ->orderBy('id', 'DESC')
      ->range(0, 1)
      ->execute()
      ->fetchField();

    return ($hash !== FALSE && $hash !== NULL && $hash !== '') ? (string) $hash : NULL;
  }

  /**
   * Computes a row hash, keyed when a signing key is available.
   *
   * @param string $prevHash
   *   The previous row's hash, or '' for the first row.
   * @param string $canonical
   *   The canonical JSON for this row.
   * @param string $keyValue
   *   The HMAC key, or '' to fall back to plain SHA-256.
   *
   * @return string
   *   Lowercase hex, 64 characters.
   */
  private function hashRow(string $prevHash, string $canonical, string $keyValue): string {
    $message = $prevHash . '|' . $canonical;
    return $keyValue !== ''
      ? hash_hmac('sha256', $message, $keyValue)
      : hash('sha256', $message);
  }

  /**
   * Resolves the HMAC key value from the configured Key entity.
   *
   * @param mixed $keyId
   *   The hash_key setting: a Key entity ID, or NULL.
   *
   * @return string
   *   The key value, or '' when unavailable — in which case the chain still
   *   works, unkeyed. An unkeyed chain detects accidental corruption and
   *   careless edits; it does not stop someone with database access from
   *   recomputing it.
   */
  private function resolveHashKey(mixed $keyId): string {
    $id = (string) ($keyId ?? '');
    if ($id === '') {
      return '';
    }
    $key = $this->keyRepository->getKey($id);
    return $key ? (string) $key->getKeyValue() : '';
  }

  /**
   * Builds the stable canonical JSON that the hash covers.
   *
   * The key order is fixed and the payload shape is frozen: changing either
   * invalidates every historical row, because verification recomputes old rows
   * with today's code.
   *
   * `channel` is omitted entirely when empty rather than emitted as "". That is
   * what lets rows migrated from mcp_sentinel's own table — written before this
   * module existed, with no channel in their canonical payload — keep verifying
   * against their original hashes instead of being re-chained. Re-chaining
   * would have been easy and wrong: hashes recomputed during a migration prove
   * only that the migration ran, and would paper over tampering that happened
   * beforehand.
   *
   * @param array $row
   *   The column values for this row.
   * @param array $metadata
   *   The extra metadata (plaintext — the chain always covers plaintext, so
   *   enabling encryption later does not invalidate earlier rows).
   *
   * @return string
   *   Canonical JSON.
   */
  private function buildCanonical(array $row, array $metadata): string {
    ksort($metadata);

    $payload = [
      'bundle' => $row['bundle'],
      'entity_id' => $row['entity_id'],
      'entity_label' => $row['entity_label'],
      'entity_type' => $row['entity_type'],
      'ip_address' => $row['ip_address'],
      'metadata' => $metadata,
      'operation' => $row['operation'],
      'timestamp' => $row['timestamp'],
      'uid' => $row['uid'],
      'user_agent' => $row['user_agent'],
    ];
    if (($row['channel'] ?? '') !== '') {
      $payload['channel'] = $row['channel'];
      ksort($payload);
    }

    return (string) json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
  }

  /**
   * Encodes metadata for storage, encrypting when a profile is configured.
   *
   * @param array $metadata
   *   The metadata array.
   * @param \Drupal\Core\Config\ImmutableConfig $config
   *   The audit_chain settings.
   *
   * @return string
   *   The encoded value.
   */
  private function encodeMetadata(array $metadata, ImmutableConfig $config): string {
    $json = (string) json_encode($metadata);

    $profileId = (string) ($config->get('encryption_profile') ?? '');
    if ($profileId === '') {
      return $json;
    }
    $profile = $this->loadEncryptionProfile($profileId);
    if ($profile === NULL) {
      return $json;
    }

    try {
      return $this->encryptService->encrypt($json, $profile);
    }
    catch (\Throwable $e) {
      // Storing plaintext beats dropping the entry: an unencrypted record of
      // what happened is still a record, and the warning names the failure.
      $this->logger->warning(
        'Audit metadata encryption failed; stored as plaintext for this row: @message',
        ['@message' => $e->getMessage()],
      );
      return $json;
    }
  }

  /**
   * Loads an EncryptionProfile by ID.
   *
   * @param string $profileId
   *   The profile entity ID.
   *
   * @return \Drupal\encrypt\EncryptionProfileInterface|null
   *   The profile, or NULL when it cannot be loaded.
   */
  private function loadEncryptionProfile(string $profileId): ?EncryptionProfileInterface {
    try {
      $profile = $this->entityTypeManager->getStorage('encryption_profile')->load($profileId);
    }
    catch (\Throwable) {
      return NULL;
    }
    return $profile instanceof EncryptionProfileInterface ? $profile : NULL;
  }

}
