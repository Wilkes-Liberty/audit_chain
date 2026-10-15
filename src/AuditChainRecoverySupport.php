<?php

declare(strict_types=1);

namespace Drupal\audit_chain;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\State\StateInterface;

/**
 * Injected collaborator for recovery and lock helpers.
 *
 * Hash, mutex, and seal primitives remain on AuditChainLogger. Callers that
 * used the logger's @internal recovery methods receive this service instead.
 *
 * @internal
 */
final class AuditChainRecoverySupport {

  /**
   * Constructs the recovery collaborator.
   *
   * @param \Drupal\Core\Database\Connection $database
   *   The database connection.
   * @param \Drupal\Core\State\StateInterface $state
   *   State storage; reset under the mutex so seals are not stale.
   * @param \Drupal\Core\Config\ConfigFactoryInterface $configFactory
   *   The config factory, for the active signing key id.
   * @param \Closure $acquireAppendMutex
   *   Takes the singleton append mutex row lock.
   * @param \Closure $verificationKeys
   *   Returns resolvable signing key values keyed by Key entity ID.
   * @param \Closure $canonicalFromRecord
   *   Rebuilds canonical JSON from a stored audit row.
   * @param \Closure $matchesAnyKey
   *   Reports whether a stored hash verifies under any retained key.
   * @param \Closure $resolveHashKey
   *   Resolves a Key entity ID to its signing material.
   * @param \Closure $throwSigningUnavailable
   *   Refuses a keyed operation when no signing key value is available.
   *
   * @phpstan-param \Closure(): void $acquireAppendMutex
   * @phpstan-param \Closure(): array<string, string> $verificationKeys
   * @phpstan-param \Closure(array): string $canonicalFromRecord
   * @phpstan-param \Closure(string, string, string, array<string, string>, string): bool $matchesAnyKey
   * @phpstan-param \Closure(mixed): array{id: string, value: string, unresolvable: bool} $resolveHashKey
   * @phpstan-param \Closure(array{id: string, value: string, unresolvable: bool}): never $throwSigningUnavailable
   */
  public function __construct(
    private readonly Connection $database,
    private readonly StateInterface $state,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly \Closure $acquireAppendMutex,
    private readonly \Closure $verificationKeys,
    private readonly \Closure $canonicalFromRecord,
    private readonly \Closure $matchesAnyKey,
    private readonly \Closure $resolveHashKey,
    private readonly \Closure $throwSigningUnavailable,
  ) {}

  /**
   * Runs a chain operation under the same transaction lock as appends.
   *
   * Recovery callers must not perform network I/O inside this callback.
   *
   * @param callable $operation
   *   Callback executed while the mutex is held.
   *
   * @return mixed
   *   The callback's return value.
   */
  public function withChainLock(callable $operation): mixed {
    $transaction = $this->database->startTransaction();
    try {
      ($this->acquireAppendMutex)();
      // Recovery must not reuse a seal cached before another serialized
      // maintenance operation completed.
      $this->state->resetCache();
      $result = $operation();
    }
    catch (\Throwable $exception) {
      $transaction->rollBack();
      throw $exception;
    }
    unset($transaction);
    return $result;
  }

  /**
   * Creates an inspector using the normal verifier's canonical encoding.
   *
   * No plaintext metadata or signing material leaves this method.
   *
   * @return callable
   *   Returns a content digest and keyed authentication flag for a stored row.
   */
  public function recoveryRowInspector(): callable {
    $keys = ($this->verificationKeys)();
    $canonicalFromRecord = $this->canonicalFromRecord;
    $matchesAnyKey = $this->matchesAnyKey;
    return static function (array $row) use ($keys, $canonicalFromRecord, $matchesAnyKey): array {
      $canonical = $canonicalFromRecord($row);
      return [
        'content_digest' => hash('sha256', $canonical),
        'authenticated' => $matchesAnyKey(
          (string) ($row['row_hash'] ?? ''),
          (string) ($row['prev_hash'] ?? ''),
          $canonical,
          $keys,
          (string) ($row['key_id'] ?? ''),
        ),
      ];
    };
  }

  /**
   * Signs a recovery manifest with an available active key.
   *
   * @param string $manifest
   *   Canonical recovery payload.
   *
   * @return array
   *   Signing key identifier and domain-separated HMAC, never key material.
   */
  public function signRecoveryManifest(string $manifest): array {
    $key = ($this->resolveHashKey)($this->configFactory->get('audit_chain.settings')->get('hash_key'));
    if ($key['value'] === '') {
      ($this->throwSigningUnavailable)($key);
    }
    return [
      'key_id' => $key['id'],
      'mac' => hash_hmac('sha256', 'audit_chain.recovery.v1|' . $manifest, $key['value']),
    ];
  }

  /**
   * Authenticates a recovery manifest with active or retained signing keys.
   *
   * @param string $manifest
   *   Canonical recovery payload.
   * @param string $mac
   *   Stored domain-separated HMAC.
   *
   * @return bool
   *   TRUE when an active or retained key authenticates the MAC.
   */
  public function authenticateRecoveryManifest(string $manifest, string $mac): bool {
    foreach (($this->verificationKeys)() as $key) {
      if (hash_equals(hash_hmac('sha256', 'audit_chain.recovery.v1|' . $manifest, $key), $mac)) {
        return TRUE;
      }
    }
    return FALSE;
  }

}
