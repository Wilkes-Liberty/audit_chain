<?php

declare(strict_types=1);

namespace Drupal\audit_chain;

use Drupal\audit_chain\Exception\AuditChainSigningUnavailableException;
use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\ImmutableConfig;
use Drupal\Core\Database\Connection;
use Drupal\Core\Entity\EntityTypeManagerInterface;
use Drupal\Core\Lock\LockBackendInterface;
use Drupal\Core\Session\AccountProxyInterface;
use Drupal\Core\State\StateInterface;
use Drupal\encrypt\EncryptionProfileInterface;
use Drupal\encrypt\EncryptServiceInterface;
use Drupal\key\KeyRepositoryInterface;
use Psr\Log\LoggerInterface;
use Symfony\Component\HttpFoundation\RequestStack;

/**
 * Hash-chained implementation of the audit chain.
 *
 * Each row's hash is HMAC-SHA256 over `prev_hash | canonical` with the
 * configured key, or SHA-256 of the same message when no Key entity is
 * configured. The canonical form has a fixed key
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
   * JSON flags for the canonical payload and the stored metadata.
   *
   * JSON_INVALID_UTF8_SUBSTITUTE is load-bearing, not tidiness. Without it
   * json_encode() returns FALSE on a single malformed byte, the `(string)` cast
   * turns that into '', and the row is hashed over an empty canonical — so it
   * can never verify again, and nothing anywhere says why. Five rows on a real
   * site were lost that way, all of them entity_save on nodes whose field
   * values carried a truncated multibyte character; they show up as
   * `metadata = ''` and verify under no key at all.
   *
   * Adding the flag is safe for existing rows: a payload that was already
   * valid UTF-8 encodes to exactly the same bytes with or without it, so no
   * historical hash changes. Only payloads that previously failed outright are
   * affected, and those did not verify to begin with.
   */
  private const JSON_FLAGS = JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE;

  /**
   * Verify() reason: a row's content or ordering no longer matches its hash.
   */
  public const REASON_TAMPERED = 'tampered';

  /**
   * Verify() reason: rows are intact but were hashed without the signing key.
   *
   * A distinct verdict because the remedy is distinct. Reporting this as
   * tampering — which is what this module did until now — sends an operator
   * hunting for an intruder when what actually happened is that a Key entity
   * did not resolve in the environment those rows were written in.
   */
  public const REASON_WRITTEN_UNKEYED = 'written_unkeyed';

  /**
   * Verify() reason: the sealed prefix digest no longer matches stored hashes.
   */
  public const REASON_SEAL_BROKEN = 'seal_broken';

  /**
   * Verify() reason: seal hashes match, but no local key authenticates its MAC.
   *
   * This is expected after refreshing a database into an environment that
   * deliberately has different signing keys. The copied seal remains
   * unverified, but unchanged prefix hashes are not evidence of tampering.
   */
  public const REASON_SEAL_FOREIGN = 'seal_foreign';

  /**
   * Internal seal status: digest and MAC both verify locally.
   */
  private const SEAL_INTACT = 'intact';

  /**
   * Internal seal status: digest matches, but its MAC is not verifiable here.
   */
  private const SEAL_FOREIGN = 'foreign';

  /**
   * Internal seal status: stored prefix hashes no longer match its digest.
   */
  private const SEAL_BROKEN = 'broken';

  /**
   * State key for the active prefix seal (site-local; not config export).
   */
  public const STATE_SEAL = 'audit_chain.seal';

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
   * @param \Drupal\Core\State\StateInterface $state
   *   State storage for the site-local prefix seal.
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
    private readonly StateInterface $state,
  ) {}

  /**
   * {@inheritdoc}
   */
  public function log(string $channel, string $operation, array $metadata = []): void {
    $this->append($channel, $operation, $metadata, FALSE);
  }

  /**
   * {@inheritdoc}
   */
  public function logKeyed(string $channel, string $operation, array $metadata = []): void {
    $this->append($channel, $operation, $metadata, TRUE);
  }

  /**
   * {@inheritdoc}
   */
  public function signingStatus(): array {
    $key = $this->resolveHashKey(
      $this->configFactory->get('audit_chain.settings')->get('hash_key'),
    );
    return [
      'keyed' => $key['value'] !== '',
      'key_id' => $key['id'],
    ];
  }

  /**
   * Shared append path for log() and logKeyed().
   *
   * @param string $channel
   *   Consumer machine name.
   * @param string $operation
   *   Operation identifier.
   * @param array $metadata
   *   Optional context.
   * @param bool $requireKeyed
   *   When TRUE, refuse (throw, write nothing) unless HMAC signing will apply.
   *
   * @throws \Drupal\audit_chain\Exception\AuditChainSigningUnavailableException
   *   When $requireKeyed is TRUE and no signing key value is available.
   */
  private function append(string $channel, string $operation, array $metadata, bool $requireKeyed): void {
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

    $key = $this->resolveHashKey($config->get('hash_key'));

    if ($requireKeyed && $key['value'] === '') {
      $this->throwSigningUnavailable($key);
    }

    // A configured key that will not resolve is not a reason to fall through to
    // an unkeyed hash quietly. The row is still written — dropping an audit
    // entry is its own failure, and worse than an unsigned one — but every such
    // write says so, and hook_requirements() reports it on the status report.
    // The alternative is what this module shipped until now: a site believing
    // it has a signed chain while every row goes in unsigned, with nothing
    // anywhere to notice it. logKeyed() never reaches here: it throws above.
    if ($key['unresolvable']) {
      $this->logger->error(
        "Audit chain signing key '@key' is configured but cannot be resolved; this entry was written with unkeyed SHA-256 and the chain is not signed. Fix the Key entity — entries written meanwhile cannot be signed retrospectively.",
        ['@key' => $key['id']],
      );
    }

    // Encoded outside the lock: encryption can be slow and holds nothing the
    // chain ordering depends on.
    $metadataStore = $this->encodeMetadata($extra, $config);

    // Serialise read-latest-then-insert. If the lock cannot be taken the entry
    // is still written — never drop an audit record — but the ordering
    // guarantee is best-effort for that request.
    $locked = $this->lock->acquire(self::CHAIN_LOCK, 3.0);
    try {
      // Re-resolve inside the lock so a key that vanished between the
      // precondition and the insert cannot produce an unkeyed row under
      // logKeyed(). Ordinary log() still prefers writing over dropping.
      if ($requireKeyed) {
        $key = $this->resolveHashKey($config->get('hash_key'));
        if ($key['value'] === '') {
          $this->throwSigningUnavailable($key);
        }
      }

      $canonical = $this->buildCanonical($row, $extra);
      $prevHash = $this->latestRowHash();
      $rowHash = $this->hashRow($prevHash ?? '', $canonical, $key['value']);

      $this->database->insert('audit_chain_log')
        ->fields($row + [
          'metadata' => $metadataStore['value'],
          'prev_hash' => $prevHash,
          'row_hash' => $rowHash,
          // Which key material actually produced this hash — empty when the row
          // was hashed unkeyed, including when a configured key was
          // unresolvable. Advisory only; see verify() on why it is never
          // trusted.
          'key_id' => $key['value'] !== '' ? $key['id'] : '',
          // Which encryption profile actually encrypted this row's metadata,
          // empty when it was stored as plaintext. Recorded so a later profile
          // rotation can be *detected* rather than discovered by an operator
          // finding old entries unreadable. Not covered by the hash — the chain
          // covers the plaintext, so encryption can be enabled or changed
          // without invalidating history.
          'encryption_profile' => $metadataStore['profile'],
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
          // Included because the implementation this was extracted from emitted
          // it, and a SIEM rule keyed on bundle would silently stop matching
          // otherwise. Dropping a field from a stream is a regression nobody
          // gets an error for.
          'bundle' => $row['bundle'],
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
  public function verify(): array {
    $keys = $this->verificationKeys();
    $seal = $this->getSeal();
    $sealedThrough = $seal !== NULL ? (int) $seal['sealed_through_id'] : NULL;
    $sealIntact = NULL;
    $verifiedFrom = NULL;

    if ($seal !== NULL) {
      $sealStatus = $this->sealStatus($seal);
      $sealIntact = $sealStatus === self::SEAL_INTACT;
      if (!$sealIntact) {
        return $this->verdict(
          FALSE,
          NULL,
          $sealStatus === self::SEAL_BROKEN
            ? self::REASON_SEAL_BROKEN
            : self::REASON_SEAL_FOREIGN,
          0,
          NULL,
          NULL,
          $sealedThrough,
          FALSE,
        );
      }
      // Accept stored hashes for the sealed prefix; content is not rechecked.
      $prevRowHash = $this->lastStoredHashThrough($sealedThrough) ?? '';
    }
    else {
      $prevRowHash = '';
    }

    $result = $this->database->select('audit_chain_log', 'l')
      ->fields('l')
      ->orderBy('id', 'ASC')
      ->execute();

    $unkeyedRows = 0;
    $unkeyedThrough = NULL;
    foreach ($result as $record) {
      $record = (array) $record;
      $id = (int) $record['id'];

      // Sealed prefix: skip content recompute (digest already checked).
      if ($sealedThrough !== NULL && $id <= $sealedThrough) {
        if ($record['row_hash'] !== NULL && $record['row_hash'] !== '') {
          $prevRowHash = (string) $record['row_hash'];
        }
        else {
          $prevRowHash = '';
        }
        continue;
      }

      // Rows with no hash predate chaining (or were written by a migration
      // that could not chain them). Skip, and reset so the next chained row can
      // start a fresh segment whose prev_hash is also empty.
      if ($record['row_hash'] === NULL || $record['row_hash'] === '') {
        $prevRowHash = '';
        continue;
      }

      if ($verifiedFrom === NULL) {
        $verifiedFrom = $id;
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
      ], $this->decodeMetadata(
        (string) ($record['metadata'] ?? ''),
        // Prefer the profile that produced this row's bytes — after a rotation
        // the configured profile is the wrong key for historical ciphertext.
        (string) ($record['encryption_profile'] ?? ''),
      ));

      $storedPrev = (string) ($record['prev_hash'] ?? '');

      // Continuity: this row must point at the previous chained row.
      if ($storedPrev !== $prevRowHash) {
        return $this->verdict(FALSE, $id, self::REASON_TAMPERED, $unkeyedRows, $unkeyedThrough, $verifiedFrom, $sealedThrough, $sealIntact);
      }

      // Integrity: the stored hash must match a recomputation of the content
      // under some key the site actually has.
      $stored = (string) $record['row_hash'];
      if ($this->matchesAnyKey($stored, $storedPrev, $canonical, $keys, (string) ($record['key_id'] ?? ''))) {
        $prevRowHash = $stored;
        continue;
      }

      // It matches with no key at all. When keys are configured that is not
      // tampering — it is a row written while the signing key was missing or
      // unresolvable, which is a completely different diagnosis and a
      // completely different remedy. Keep walking: the chain's continuity is
      // intact, it simply is not signed through here.
      if (hash_equals($this->hashRow($storedPrev, $canonical, ''), $stored)) {
        if ($keys === []) {
          // No key configured, so unkeyed *is* the configured mode.
          $prevRowHash = $stored;
          continue;
        }
        $unkeyedRows++;
        $unkeyedThrough = $id;
        $prevRowHash = $stored;
        continue;
      }

      return $this->verdict(FALSE, $id, self::REASON_TAMPERED, $unkeyedRows, $unkeyedThrough, $verifiedFrom, $sealedThrough, $sealIntact);
    }

    if ($unkeyedRows > 0) {
      return $this->verdict(FALSE, NULL, self::REASON_WRITTEN_UNKEYED, $unkeyedRows, $unkeyedThrough, $verifiedFrom, $sealedThrough, $sealIntact);
    }

    return $this->verdict(TRUE, NULL, NULL, 0, NULL, $verifiedFrom, $sealedThrough, $sealIntact);
  }

  /**
   * {@inheritdoc}
   */
  public function getSeal(): ?array {
    $seal = $this->state->get(self::STATE_SEAL);
    $required = ['sealed_through_id', 'row_count', 'prefix_digest', 'seal_mac', 'timestamp', 'uid', 'reason', 'key_id'];
    if (!is_array($seal)) {
      return NULL;
    }
    foreach ($required as $key) {
      if (!array_key_exists($key, $seal)) {
        return NULL;
      }
    }
    return $seal;
  }

  /**
   * {@inheritdoc}
   */
  public function sealPrefix(int $throughId, string $reason): array {
    $reason = trim($reason);
    if ($throughId < 1) {
      return ['sealed' => FALSE, 'message' => 'throughId must be a positive row id.', 'seal' => NULL];
    }
    if ($reason === '') {
      return ['sealed' => FALSE, 'message' => 'A non-empty reason is required.', 'seal' => NULL];
    }

    $maxId = (int) $this->database->select('audit_chain_log', 'l')
      ->orderBy('id', 'DESC')
      ->range(0, 1)
      ->fields('l', ['id'])
      ->execute()
      ->fetchField();
    if ($maxId < 1) {
      return ['sealed' => FALSE, 'message' => 'The chain is empty.', 'seal' => NULL];
    }
    if ($throughId > $maxId) {
      return [
        'sealed' => FALSE,
        'message' => sprintf('throughId %d is past the last row id %d.', $throughId, $maxId),
        'seal' => NULL,
      ];
    }

    // The active key must resolve before inspecting the prefix. Retired keys
    // are valid verification candidates, but they must never make an
    // unresolvable active key look sufficient to create a new seal.
    $keyId = (string) ($this->configFactory->get('audit_chain.settings')->get('hash_key') ?? '');
    if ($keyId === '') {
      return [
        'sealed' => FALSE,
        'message' => 'Refusing to seal: no signing key is configured. An unkeyed-by-design chain has nothing unverifiable to seal; configure a hash_key first if the history was written unsigned by accident.',
        'seal' => NULL,
      ];
    }
    $keyMaterial = $this->resolveHashKey($keyId);
    if ($keyMaterial['value'] === '') {
      return [
        'sealed' => FALSE,
        'message' => sprintf(
          "Refusing to seal: active signing key '%s' is configured but cannot be resolved. A seal must be authenticated with the active key; fix the Key entity before sealing.",
          $keyId,
        ),
        'seal' => NULL,
      ];
    }

    // May only seal rows that do not verify under the site's signing keys.
    // Reuse the exact active material that will sign the seal so a dynamic key
    // provider cannot change between the precondition and the write.
    $keys = [$keyId => $keyMaterial['value']] + $this->verificationKeys();
    $rows = $this->database->select('audit_chain_log', 'l')
      ->fields('l')
      ->condition('id', $throughId, '<=')
      ->orderBy('id', 'ASC')
      ->execute();
    $chained = 0;
    foreach ($rows as $record) {
      $record = (array) $record;
      if ($record['row_hash'] === NULL || $record['row_hash'] === '') {
        continue;
      }
      $chained++;
      $id = (int) $record['id'];
      $canonical = $this->buildCanonical([
        'channel' => (string) ($record['channel'] ?? ''),
        'operation' => substr((string) $record['operation'], 0, 64),
        'entity_type' => $record['entity_type'],
        'bundle' => $record['bundle'],
        'entity_id' => (string) ($record['entity_id'] ?? ''),
        'entity_label' => isset($record['entity_label']) ? (string) $record['entity_label'] : NULL,
        'ip_address' => isset($record['ip_address']) ? (string) $record['ip_address'] : NULL,
        'user_agent' => isset($record['user_agent']) ? (string) $record['user_agent'] : NULL,
        'timestamp' => (int) $record['timestamp'],
        'uid' => (int) $record['uid'],
      ], $this->decodeMetadata(
        (string) ($record['metadata'] ?? ''),
        (string) ($record['encryption_profile'] ?? ''),
      ));
      $storedPrev = (string) ($record['prev_hash'] ?? '');
      $stored = (string) $record['row_hash'];
      if ($this->matchesAnyKey($stored, $storedPrev, $canonical, $keys, (string) ($record['key_id'] ?? ''))) {
        return [
          'sealed' => FALSE,
          'message' => sprintf(
            'Refusing to seal: row %d still verifies under a configured signing key. Sealing would hide verifiable history.',
            $id,
          ),
          'seal' => NULL,
        ];
      }
    }
    if ($chained < 1) {
      return ['sealed' => FALSE, 'message' => 'No chained rows in the requested prefix.', 'seal' => NULL];
    }

    $prefixDigest = $this->computePrefixDigest($throughId);
    $uid = (int) $this->currentUser->id();
    $timestamp = $this->time->getRequestTime();
    $macPayload = $this->sealMacPayload($throughId, $chained, $prefixDigest, $timestamp, $uid, $reason, $keyId);
    $sealMac = hash_hmac('sha256', $macPayload, $keyMaterial['value']);

    $seal = [
      'sealed_through_id' => $throughId,
      'row_count' => $chained,
      'prefix_digest' => $prefixDigest,
      'seal_mac' => $sealMac,
      'timestamp' => $timestamp,
      'uid' => $uid,
      'reason' => $reason,
      'key_id' => $keyId,
    ];
    $this->state->set(self::STATE_SEAL, $seal);

    // Never invisible: the seal itself is an audit row.
    $this->log('audit_chain', 'prefix_sealed', [
      'id' => (string) $throughId,
      'sealed_through_id' => $throughId,
      'row_count' => $chained,
      'reason' => $reason,
      'prefix_digest' => $prefixDigest,
    ]);

    return [
      'sealed' => TRUE,
      'message' => sprintf(
        'Sealed rows through id %d (%d chained hashes). Post-seal verification starts after that id.',
        $throughId,
        $chained,
      ),
      'seal' => $seal,
    ];
  }

  /**
   * {@inheritdoc}
   */
  public function decodeMetadata(string $stored, string $encryptionProfile = ''): array {
    if ($stored === '') {
      return [];
    }

    // Try the profile that wrote the row first, then the currently configured
    // one (for rows written before encryption_profile was recorded).
    $candidates = array_values(array_unique(array_filter([
      $encryptionProfile,
      (string) ($this->configFactory->get('audit_chain.settings')->get('encryption_profile') ?? ''),
    ], static fn (string $id): bool => $id !== '')));

    foreach ($candidates as $profileId) {
      $profile = $this->loadEncryptionProfile($profileId);
      if ($profile === NULL) {
        continue;
      }
      try {
        $decoded = json_decode($this->encryptService->decrypt($stored, $profile), TRUE);
        if (is_array($decoded)) {
          return $decoded;
        }
      }
      catch (\Throwable) {
        // Wrong profile or corrupted ciphertext — try the next candidate.
      }
    }

    $decoded = json_decode($stored, TRUE);
    return is_array($decoded) ? $decoded : [];
  }

  /**
   * {@inheritdoc}
   */
  public function reencrypt(string $fromProfile, string $toProfile, int $limit = 0): array {
    $from = $this->loadEncryptionProfile($fromProfile);
    $to = $this->loadEncryptionProfile($toProfile);
    if ($from === NULL) {
      return [
        'updated' => 0,
        'failed' => 0,
        'remaining' => 0,
        'refused' => sprintf('Source encryption profile "%s" cannot be loaded.', $fromProfile),
      ];
    }
    if ($to === NULL) {
      return [
        'updated' => 0,
        'failed' => 0,
        'remaining' => 0,
        'refused' => sprintf('Destination encryption profile "%s" cannot be loaded.', $toProfile),
      ];
    }
    if ($fromProfile === $toProfile) {
      return [
        'updated' => 0,
        'failed' => 0,
        'remaining' => 0,
        'refused' => 'Source and destination profiles are the same.',
      ];
    }

    $query = $this->database->select('audit_chain_log', 'l')
      ->fields('l', ['id', 'metadata'])
      ->condition('encryption_profile', $fromProfile)
      ->orderBy('id', 'ASC');
    if ($limit > 0) {
      $query->range(0, $limit);
    }

    $updated = 0;
    $failed = 0;
    foreach ($query->execute() as $record) {
      $stored = (string) ($record->metadata ?? '');
      try {
        $plain = $this->encryptService->decrypt($stored, $from);
        // Round-trip through JSON to match encodeMetadata's stored shape.
        $decoded = json_decode($plain, TRUE);
        if (!is_array($decoded)) {
          throw new \RuntimeException('Decrypted metadata is not a JSON object.');
        }
        $json = json_encode($decoded, self::JSON_FLAGS);
        if ($json === FALSE) {
          throw new \RuntimeException(json_last_error_msg());
        }
        $cipher = $this->encryptService->encrypt($json, $to);
      }
      catch (\Throwable $e) {
        $failed++;
        $this->logger->error(
          'Re-encrypt failed for audit row @id (from @from to @to): @message',
          [
            '@id' => $record->id,
            '@from' => $fromProfile,
            '@to' => $toProfile,
            '@message' => $e->getMessage(),
          ],
        );
        continue;
      }

      // Only metadata storage columns — never the hash or prev_hash.
      $this->database->update('audit_chain_log')
        ->fields([
          'metadata' => $cipher,
          'encryption_profile' => $toProfile,
        ])
        ->condition('id', $record->id)
        ->execute();
      $updated++;
    }

    $remaining = (int) $this->database->select('audit_chain_log', 'l')
      ->condition('encryption_profile', $fromProfile)
      ->countQuery()
      ->execute()
      ->fetchField();

    return [
      'updated' => $updated,
      'failed' => $failed,
      'remaining' => $remaining,
      'refused' => NULL,
    ];
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
   * Builds the verify() return value in one place.
   *
   * @param bool $ok
   *   Whether the chain verifies under a key the site holds.
   * @param int|null $brokenAt
   *   The row id that failed, for REASON_TAMPERED only.
   * @param string|null $reason
   *   One of the REASON_* constants, or NULL when ok.
   * @param int $unkeyedRows
   *   How many post-seal rows verified only without a key.
   * @param int|null $unkeyedThrough
   *   The highest such row id.
   * @param int|null $verifiedFrom
   *   First post-seal row id content-checked, or NULL.
   * @param int|null $sealedThrough
   *   Active seal's sealed_through_id, or NULL.
   * @param bool|null $sealIntact
   *   Whether both the seal digest and MAC verify; NULL when no seal.
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
   *   }
   *   The verdict.
   */
  private function verdict(
    bool $ok,
    ?int $brokenAt,
    ?string $reason,
    int $unkeyedRows,
    ?int $unkeyedThrough,
    ?int $verifiedFrom = NULL,
    ?int $sealedThrough = NULL,
    ?bool $sealIntact = NULL,
  ): array {
    return [
      'ok' => $ok,
      'broken_at' => $brokenAt,
      'reason' => $reason,
      'unkeyed_rows' => $unkeyedRows,
      'unkeyed_through' => $unkeyedThrough,
      'verified_from' => $verifiedFrom,
      'sealed_through' => $sealedThrough,
      'seal_intact' => $sealIntact,
    ];
  }

  /**
   * Digest over stored row_hash values for ids 1..$throughId.
   *
   * Only chained rows (non-empty row_hash) contribute.
   */
  private function computePrefixDigest(int $throughId): string {
    $result = $this->database->select('audit_chain_log', 'l')
      ->fields('l', ['id', 'row_hash'])
      ->condition('id', $throughId, '<=')
      ->orderBy('id', 'ASC')
      ->execute();
    $parts = [];
    foreach ($result as $record) {
      if ($record->row_hash === NULL || $record->row_hash === '') {
        continue;
      }
      $parts[] = (int) $record->id . ':' . (string) $record->row_hash;
    }
    return hash('sha256', implode("\n", $parts));
  }

  /**
   * Canonical string MAC'd into the seal (fixed field order).
   */
  private function sealMacPayload(
    int $throughId,
    int $rowCount,
    string $prefixDigest,
    int $timestamp,
    int $uid,
    string $reason,
    string $keyId,
  ): string {
    $payload = [
      'key_id' => $keyId,
      'prefix_digest' => $prefixDigest,
      'reason' => $reason,
      'row_count' => $rowCount,
      'sealed_through_id' => $throughId,
      'timestamp' => $timestamp,
      'uid' => $uid,
    ];
    ksort($payload);
    $encoded = json_encode($payload, self::JSON_FLAGS);
    return $encoded !== FALSE ? $encoded : '';
  }

  /**
   * Classifies the stored seal's prefix digest and MAC independently.
   *
   * A matching digest with an unknown MAC is a foreign seal, which commonly
   * occurs after a database refresh across environments with separate keys.
   * It remains unverified, but is distinct from changed historical hashes.
   *
   * @return string
   *   One of the private SEAL_* status constants.
   */
  private function sealStatus(array $seal): string {
    $throughId = (int) $seal['sealed_through_id'];
    $expectedDigest = $this->computePrefixDigest($throughId);
    if (!hash_equals((string) $seal['prefix_digest'], $expectedDigest)) {
      return self::SEAL_BROKEN;
    }
    $macPayload = $this->sealMacPayload(
      $throughId,
      (int) $seal['row_count'],
      (string) $seal['prefix_digest'],
      (int) $seal['timestamp'],
      (int) $seal['uid'],
      (string) $seal['reason'],
      (string) ($seal['key_id'] ?? ''),
    );
    // A prefix can only be sealed while a signing key resolves, so accepting
    // an unkeyed digest here would let database access rewrite both the prefix
    // and the seal without knowing any trusted key.
    foreach ($this->verificationKeys() as $value) {
      $mac = hash_hmac('sha256', $macPayload, $value);
      if (hash_equals((string) $seal['seal_mac'], $mac)) {
        return self::SEAL_INTACT;
      }
    }
    return self::SEAL_FOREIGN;
  }

  /**
   * Last non-empty stored row_hash for ids <= $throughId.
   */
  private function lastStoredHashThrough(int $throughId): ?string {
    $hash = $this->database->select('audit_chain_log', 'l')
      ->fields('l', ['row_hash'])
      ->condition('id', $throughId, '<=')
      ->isNotNull('row_hash')
      ->condition('row_hash', '', '<>')
      ->orderBy('id', 'DESC')
      ->range(0, 1)
      ->execute()
      ->fetchField();
    return ($hash !== FALSE && $hash !== NULL && $hash !== '') ? (string) $hash : NULL;
  }

  /**
   * Tests a stored hash against every key the site actually holds.
   *
   * The row's own `key_id` only decides which key is *tried first*. It is
   * deliberately not treated as authority: the column is not covered by the row
   * hash — it could not be added to the canonical payload without invalidating
   * every row written before it existed — so a writer with database access
   * could otherwise blank it, recompute the row unkeyed, and have verification
   * accept the result. Trusting it would hand back exactly the forgery
   * resistance the HMAC is there to provide.
   *
   * @param string $stored
   *   The stored row hash.
   * @param string $storedPrev
   *   The stored prev_hash.
   * @param string $canonical
   *   The recomputed canonical payload.
   * @param array<string, string> $keys
   *   Resolvable key values, keyed by Key entity ID.
   * @param string $hint
   *   The row's recorded key_id, used only for ordering.
   *
   * @return bool
   *   TRUE when some configured key reproduces the stored hash.
   */
  private function matchesAnyKey(string $stored, string $storedPrev, string $canonical, array $keys, string $hint): bool {
    if ($hint !== '' && isset($keys[$hint])) {
      $keys = [$hint => $keys[$hint]] + $keys;
    }
    foreach ($keys as $value) {
      if (hash_equals($this->hashRow($storedPrev, $canonical, $value), $stored)) {
        return TRUE;
      }
    }
    return FALSE;
  }

  /**
   * Returns every signing key verification may accept, keyed by entity ID.
   *
   * The current key plus any retired ones listed in `previous_hash_keys`, so a
   * chain survives ordinary key rotation: rows written under the old key go on
   * verifying under it instead of becoming indistinguishable from tampering the
   * moment the key changes. Retired keys are trusted because they come from
   * configuration, which an attacker editing the log table does not control.
   *
   * Unresolvable IDs are skipped rather than treated as an empty key, so a
   * broken retired-key reference cannot silently turn into "accepts unkeyed".
   *
   * @return array<string, string>
   *   Key values by Key entity ID. Empty when the chain is unkeyed by design.
   */
  private function verificationKeys(): array {
    $config = $this->configFactory->get('audit_chain.settings');
    $ids = array_merge(
      [(string) ($config->get('hash_key') ?? '')],
      array_map('strval', (array) ($config->get('previous_hash_keys') ?? [])),
    );

    $keys = [];
    foreach (array_unique(array_filter($ids)) as $id) {
      $value = $this->resolveHashKey($id)['value'];
      if ($value !== '') {
        $keys[$id] = $value;
      }
    }
    return $keys;
  }

  /**
   * Refuse a keyed append when no signing key value is available.
   *
   * Shared by the pre-lock and in-lock checks so both failure sites keep the
   * same message if the wording ever changes.
   *
   * @param array{id: string, value: string, unresolvable: bool} $key
   *   Result of resolveHashKey().
   *
   * @throws \Drupal\audit_chain\Exception\AuditChainSigningUnavailableException
   */
  private function throwSigningUnavailable(array $key): never {
    $detail = $key['id'] === ''
      ? 'no signing key is configured'
      : sprintf("signing key '%s' is configured but cannot be resolved", $key['id']);
    throw new AuditChainSigningUnavailableException(
      "Keyed audit append refused: {$detail}.",
    );
  }

  /**
   * Resolves the HMAC key value from the configured Key entity.
   *
   * Distinguishes the two states the previous implementation collapsed into a
   * bare '': no key configured (unkeyed by design) and a configured key that
   * will not resolve (a fault). They produce the same hash and mean opposite
   * things, and merging them is what let a site run unsigned for 1,997 rows
   * without a single signal.
   *
   * @param mixed $keyId
   *   The hash_key setting: a Key entity ID, or NULL.
   *
   * @return array{id: string, value: string, unresolvable: bool}
   *   'value' is '' when hashing will be unkeyed. 'unresolvable' is TRUE only
   *   when an ID was configured and no key value came back from it.
   */
  private function resolveHashKey(mixed $keyId): array {
    $id = (string) ($keyId ?? '');
    if ($id === '') {
      return ['id' => '', 'value' => '', 'unresolvable' => FALSE];
    }
    $key = $this->keyRepository->getKey($id);
    $value = $key ? (string) $key->getKeyValue() : '';
    return ['id' => $id, 'value' => $value, 'unresolvable' => $value === ''];
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

    $encoded = json_encode($payload, self::JSON_FLAGS);
    if ($encoded === FALSE) {
      // Nothing left but recursion or INF/NAN, neither of which reaches here
      // from a column value. Return a deterministic marker rather than '': the
      // write and verify paths must agree, and '' is the value that silently
      // produced five permanently unverifiable rows.
      return '{"canonical_encoding_failed":' . json_last_error() . '}';
    }
    return $encoded;
  }

  /**
   * Encodes metadata for storage, encrypting when a profile is configured.
   *
   * @param array $metadata
   *   The metadata array.
   * @param \Drupal\Core\Config\ImmutableConfig $config
   *   The audit_chain settings.
   *
   * @return array{value: string, profile: string}
   *   'value' is what to store. 'profile' is the encryption profile that
   *   actually produced it, or '' when the value is plaintext — including when
   *   a profile is configured but could not be loaded or threw, so the recorded
   *   profile always describes the bytes rather than the intent.
   */
  private function encodeMetadata(array $metadata, ImmutableConfig $config): array {
    $encoded = json_encode($metadata, self::JSON_FLAGS);
    if ($encoded === FALSE) {
      $this->logger->error(
        'Audit metadata could not be JSON-encoded (@error); stored as an empty object. The entry is still recorded and still verifies, but its context is lost.',
        ['@error' => json_last_error_msg()],
      );
      $encoded = '{}';
    }
    $json = $encoded;

    $profileId = (string) ($config->get('encryption_profile') ?? '');
    if ($profileId === '') {
      return ['value' => $json, 'profile' => ''];
    }
    $profile = $this->loadEncryptionProfile($profileId);
    if ($profile === NULL) {
      return ['value' => $json, 'profile' => ''];
    }

    try {
      return ['value' => $this->encryptService->encrypt($json, $profile), 'profile' => $profileId];
    }
    catch (\Throwable $e) {
      // Storing plaintext beats dropping the entry: an unencrypted record of
      // what happened is still a record, and the warning names the failure.
      // Reported as plaintext, because that is what was actually stored — a row
      // labelled with a profile that did not encrypt it would send a later
      // re-encrypt pass looking for ciphertext that is not there.
      $this->logger->warning(
        'Audit metadata encryption failed; stored as plaintext for this row: @message',
        ['@message' => $e->getMessage()],
      );
      return ['value' => $json, 'profile' => ''];
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
