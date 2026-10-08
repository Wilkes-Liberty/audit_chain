<?php

declare(strict_types=1);

namespace Drupal\audit_chain;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Component\Uuid\Uuid;
use Drupal\Core\Database\Connection;
use Drupal\Core\Extension\ModuleExtensionList;
use Drupal\Core\Site\Settings;
use Drupal\Core\State\StateInterface;

/**
 * Records an explicit continuation without repairing historical verdicts.
 *
 * Only privileged command-line callers activate a segment. The shared append
 * mutex serializes snapshot approval, the signed record and its audit receipt.
 * Whole-history verification is deliberately not changed by this service.
 */
final class RecoverySegments {

  public function __construct(
    private readonly Connection $database,
    private readonly AuditChainLogger $chain,
    private readonly TimeInterface $time,
    private readonly StateInterface $state,
    private readonly ?ModuleExtensionList $modules = NULL,
  ) {}

  /**
   * Prepares a read-only snapshot for operator review.
   */
  public function prepare(): array {
    return $this->chain->withChainLock(function (): array {
      $snapshot = $this->snapshot();
      return [
        'snapshot' => $snapshot,
        'snapshot_digest' => hash('sha256', self::encode($snapshot)),
        'historical_verdict' => $snapshot['historical_verdict'],
      ];
    });
  }

  /**
   * Creates a signed segment after exact snapshot approval.
   *
   * @param string $segmentId
   *   Stable UUID for idempotent retries.
   * @param string $expectedSnapshot
   *   Digest returned by prepare().
   * @param array $context
   *   Incident reference, reason, approving actor and backup SHA-256 digest.
   *
   * @return array
   *   Signed recovery record. No signing material is returned.
   */
  public function activate(string $segmentId, string $expectedSnapshot, array $context): array {
    if (!Uuid::isValid($segmentId) || !preg_match('/^[a-f0-9]{64}$/D', $expectedSnapshot)) {
      throw new \InvalidArgumentException('A segment UUID and reviewed snapshot SHA-256 digest are required.');
    }
    $context = $this->validateContext($context);
    return $this->chain->withChainLock(function () use ($segmentId, $expectedSnapshot, $context): array {
      $existing = $this->record($segmentId);
      if ($existing !== NULL) {
        $manifest = $this->authenticatedManifest($existing);
        if ($manifest['snapshot_digest'] !== $expectedSnapshot || $manifest['context'] !== $context) {
          throw new \RuntimeException('The segment identifier already belongs to a different recovery request.');
        }
        if (!$this->verifyLocked($existing)['segment_ok']) {
          throw new \RuntimeException('The existing recovery segment does not verify.');
        }
        return $existing;
      }
      // A second recovery needs an explicit multi-segment protocol. Refuse
      // rather than silently hiding a failure of an already recovered segment.
      if ($this->database->select('audit_chain_recovery', 'r')
        ->fields('r', ['segment_id'])->range(0, 1)->forUpdate()->execute()->fetchField() !== FALSE) {
        throw new \RuntimeException('A recovery segment already exists.');
      }
      $snapshot = $this->snapshot();
      if (!hash_equals($expectedSnapshot, hash('sha256', self::encode($snapshot)))) {
        throw new \RuntimeException('The approved snapshot is stale. Prepare and review a fresh snapshot.');
      }
      $verdict = $snapshot['historical_verdict'];
      if ($verdict['ok'] || $snapshot['count'] === 0) {
        throw new \RuntimeException('Recovery requires a non-empty history with an explicit failed verdict.');
      }
      $manifest = [
        'version' => 1,
        'segment_id' => $segmentId,
        'instance_id' => $this->instanceId(),
        'approved_at' => $this->time->getCurrentTime(),
        'source_version' => $this->modules?->getExtensionInfo('audit_chain')['version'] ?? 'unversioned',
        'snapshot_digest' => $expectedSnapshot,
        'snapshot' => $snapshot,
        'historical_verdict' => $verdict,
        'historical_ok' => FALSE,
        'signing_key_id' => $this->chain->signingStatus()['key_id'],
        'context' => $context,
      ];
      $payload = self::encode($manifest);
      $signature = $this->chain->signRecoveryManifest($payload);
      if ($signature['key_id'] !== $manifest['signing_key_id']) {
        throw new \RuntimeException('The active signing key changed during recovery.');
      }
      $record = [
        'segment_id' => $segmentId,
        'manifest' => $payload,
        'key_id' => $signature['key_id'],
        'mac' => $signature['mac'],
      ];
      $this->database->insert('audit_chain_recovery')->fields($record)->execute();
      $this->chain->logKeyed('audit_chain', 'recovery_started', [
        'segment_id' => $segmentId,
        'manifest_digest' => hash('sha256', $payload),
      ]);
      // Invalidate any pre-incident cached success immediately. The next
      // scheduled run supplies independent successor health.
      $this->state->set(ScheduledVerifier::STATE_KEY, [
        'time' => $this->time->getCurrentTime(),
        'ok' => FALSE,
        'reason' => $verdict['reason'],
        'keyed' => TRUE,
        'verdict' => $verdict,
        'successor' => [
          'segment_ok' => FALSE,
          'historical_ok' => FALSE,
          'reason' => 'awaiting_verification',
          'segment_id' => $segmentId,
        ],
      ]);
      return $record;
    });
  }

  /**
   * Verifies a successor without returning a whole-history success.
   */
  public function verify(string $segmentId): array {
    return $this->chain->withChainLock(function () use ($segmentId): array {
      $record = $this->record($segmentId);
      if ($record === NULL) {
        return $this->failure('recovery_record_missing');
      }
      try {
        return $this->verifyLocked($record);
      }
      catch (\RuntimeException | \JsonException $exception) {
        return $this->failure('recovery_record_invalid');
      }
    });
  }

  /**
   * Requires the fork and the next row on the surviving chain.
   *
   * Historical rows may contain a fork. The surviving path is the ancestry
   * of the authenticated snapshot head, then the successor rows. The lowest
   * id after the fork can be the other branch.
   *
   * @param string $segmentId
   *   Recovery segment to authenticate.
   * @param int $forkId
   *   Row id the operator named as the fork.
   * @param string $forkHash
   *   The row_hash the operator named for that fork.
   * @param string $liveHash
   *   The row_hash the operator named for the next surviving row.
   *
   * @throws \RuntimeException
   *   When the segment does not verify, the fork is not on the surviving
   *   path, or the next surviving row is not the named live row.
   */
  public function assertSurvivingAnchor(string $segmentId, int $forkId, string $forkHash, string $liveHash): void {
    $this->chain->withChainLock(function () use ($segmentId, $forkId, $forkHash, $liveHash): void {
      $record = $this->record($segmentId);
      if ($record === NULL || empty($this->verifyLocked($record)['segment_ok'])) {
        throw new \RuntimeException('The recovery segment does not verify.');
      }
      $manifest = $this->authenticatedManifest($record);
      $snapshot = is_array($manifest['snapshot'] ?? NULL) ? $manifest['snapshot'] : [];
      $through = is_int($snapshot['through_id'] ?? NULL) ? $snapshot['through_id'] : 0;
      $head = is_string($snapshot['head_hash'] ?? NULL) ? $snapshot['head_hash'] : '';
      if ($through < 1 || preg_match('/^[a-f0-9]{64}$/D', $head) !== 1) {
        throw new \RuntimeException('The recovery segment does not verify.');
      }
      $byHash = [];
      $historical = $this->database->select('audit_chain_log', 'l')
        ->fields('l', ['id', 'prev_hash', 'row_hash'])
        ->condition('id', $through, '<=')
        ->orderBy('id')
        ->forUpdate()
        ->execute();
      foreach ($historical as $row) {
        $hash = (string) ($row->row_hash ?? '');
        if ($hash === '' || isset($byHash[$hash])) {
          throw new \RuntimeException('The fork row is not on the surviving chain.');
        }
        $byHash[$hash] = [
          'id' => (int) $row->id,
          'prev_hash' => $row->prev_hash === NULL ? '' : (string) $row->prev_hash,
          'row_hash' => $hash,
        ];
      }
      $path = [];
      $cursor = $head;
      $visited = [];
      while ($cursor !== '') {
        if (isset($visited[$cursor]) || !isset($byHash[$cursor])) {
          throw new \RuntimeException('The fork row is not on the surviving chain.');
        }
        $visited[$cursor] = TRUE;
        $path[] = $byHash[$cursor];
        $cursor = $byHash[$cursor]['prev_hash'];
      }
      $path = array_reverse($path);
      $successors = $this->database->select('audit_chain_log', 'l')
        ->fields('l', ['id', 'prev_hash', 'row_hash'])
        ->condition('id', $through, '>')
        ->orderBy('id')
        ->forUpdate()
        ->execute();
      foreach ($successors as $row) {
        $path[] = [
          'id' => (int) $row->id,
          'prev_hash' => $row->prev_hash === NULL ? '' : (string) $row->prev_hash,
          'row_hash' => (string) ($row->row_hash ?? ''),
        ];
      }
      $index = NULL;
      foreach ($path as $position => $row) {
        if ($row['id'] === $forkId
          && strlen($row['row_hash']) === strlen($forkHash)
          && hash_equals($forkHash, $row['row_hash'])) {
          $index = $position;
          break;
        }
      }
      $next = $index === NULL ? NULL : ($path[$index + 1] ?? NULL);
      if ($index === NULL) {
        throw new \RuntimeException('The fork row is not on the surviving chain.');
      }
      if (!is_array($next)
        || strlen($next['prev_hash']) !== strlen($forkHash)
        || strlen($next['row_hash']) !== strlen($liveHash)
        || !hash_equals($forkHash, $next['prev_hash'])
        || !hash_equals($liveHash, $next['row_hash'])) {
        throw new \RuntimeException('The first live row after the fork does not match.');
      }
    });
  }

  /**
   * Returns the separate successor verdict for scheduled monitoring.
   */
  public function currentStatus(): ?array {
    try {
      $id = $this->database->select('audit_chain_recovery', 'r')
        ->fields('r', ['segment_id'])->range(0, 1)->execute()->fetchField();
      return $id === FALSE ? NULL : $this->verify((string) $id);
    }
    catch (\Throwable $exception) {
      return $this->failure('recovery_status_unavailable');
    }
  }

  /**
   * Returns the signed record for explicit recovery evidence export.
   */
  public function record(string $segmentId): ?array {
    $record = $this->database->select('audit_chain_recovery', 'r')
      ->fields('r')
      ->condition('segment_id', $segmentId)
      ->forUpdate()
      ->execute()
      ->fetchAssoc();
    return $record === FALSE ? NULL : $record;
  }

  /**
   * Exports exactly the record that was verified under the shared mutex.
   */
  public function export(string $segmentId): array {
    return $this->chain->withChainLock(function () use ($segmentId): array {
      $record = $this->record($segmentId);
      if ($record === NULL) {
        return ['verification' => $this->failure('recovery_record_missing')];
      }
      try {
        $result = $this->verifyLocked($record);
      }
      catch (\RuntimeException | \JsonException $exception) {
        $result = $this->failure('recovery_record_invalid');
      }
      return [
        'contract' => 'audit_chain.recovery.v1',
        'whole_history_verified' => FALSE,
        'verification' => $result,
        'recovery_record' => $result['segment_ok'] ? $record : NULL,
      ];
    });
  }

  /**
   * Checks the anchor and every successor row while the mutex is held.
   */
  private function verifyLocked(array $record): array {
    $manifest = $this->authenticatedManifest($record);
    $snapshot = $manifest['snapshot'];
    $actual = $this->snapshot((int) $snapshot['through_id']);
    if (!hash_equals($manifest['snapshot_digest'], hash('sha256', self::encode($actual)))) {
      return $this->failure('historical_anchor_changed');
    }
    $inspect = $this->chain->recoveryRowInspector();
    $previous = $snapshot['head_hash'];
    $count = 0;
    $rows = $this->database->select('audit_chain_log', 'l')
      ->fields('l')
      ->condition('id', $snapshot['through_id'], '>')
      ->orderBy('id')
      ->forUpdate()
      ->execute();
    foreach ($rows as $row) {
      $row = (array) $row;
      if ($count === 0) {
        $metadata = $this->chain->decodeMetadata(
          (string) ($row['metadata'] ?? ''),
          (string) ($row['encryption_profile'] ?? ''),
        );
        if ($row['channel'] !== 'audit_chain' || $row['operation'] !== 'recovery_started'
          || ($metadata['segment_id'] ?? NULL) !== $record['segment_id']
          || ($metadata['manifest_digest'] ?? NULL) !== hash('sha256', $record['manifest'])) {
          return $this->failure('recovery_receipt_missing');
        }
      }
      if ((string) ($row['prev_hash'] ?? '') !== $previous || !$inspect($row)['authenticated']) {
        return $this->failure('successor_integrity_failed');
      }
      $previous = (string) $row['row_hash'];
      $count++;
    }
    if ($count === 0) {
      return $this->failure('recovery_receipt_missing');
    }
    return [
      'segment_ok' => TRUE,
      'historical_ok' => FALSE,
      'reason' => NULL,
      'segment_id' => $record['segment_id'],
      'incident' => $manifest['context']['incident'],
      'historical_verdict' => $manifest['historical_verdict'],
      'verified_rows' => $count,
    ];
  }

  /**
   * Captures logical contents, hashes, ordering, seals and branch tips.
   */
  private function snapshot(?int $through = NULL): array {
    $inspect = $this->chain->recoveryRowInspector();
    $query = $this->database->select('audit_chain_log', 'l')->fields('l')->orderBy('id')->forUpdate();
    if ($through !== NULL) {
      $query->condition('id', $through, '<=');
    }
    $digest = hash_init('sha256');
    $tips = [];
    $parents = [];
    $count = $highWater = 0;
    $head = '';
    foreach ($query->execute() as $row) {
      $row = (array) $row;
      $id = (int) $row['id'];
      $head = (string) ($row['row_hash'] ?? '');
      $previous = (string) ($row['prev_hash'] ?? '');
      $evidence = $inspect($row);
      hash_update($digest, self::encode([
        $id, $head, $previous, $evidence['content_digest'],
        hash('sha256', self::encode([
          $row['metadata'], $row['key_id'], $row['encryption_profile'],
        ])),
      ]) . "\n");
      if ($head !== '') {
        $tips[$id] = $head;
      }
      if ($previous !== '') {
        $parents[$previous] = TRUE;
      }
      $highWater = $id;
      $count++;
    }
    $tips = array_filter($tips, static fn (string $hash): bool => !isset($parents[$hash]));
    return [
      'instance_id' => $this->instanceId(),
      'count' => $count,
      'through_id' => $highWater,
      'head_hash' => $head,
      'content_digest' => hash_final($digest),
      'seal_digest' => hash('sha256', self::encode($this->chain->getSeal())),
      // unsigned_prefix is a status-report annotation. It is not part of the
      // recovery anchor. Leaving it in this array would change snapshot_digest
      // for every existing successor.
      'historical_verdict' => $this->recoveryVerdict(),
      'branch_tips' => $tips,
    ];
  }

  /**
   * Authenticates the complete stored manifest before interpreting it.
   */
  private function authenticatedManifest(array $record): array {
    if (!$this->chain->authenticateRecoveryManifest($record['manifest'], $record['mac'])) {
      throw new \RuntimeException('The recovery signature cannot be authenticated.');
    }
    $manifest = json_decode($record['manifest'], TRUE, 64, JSON_THROW_ON_ERROR);
    if (!is_array($manifest) || ($manifest['version'] ?? NULL) !== 1
      || ($manifest['instance_id'] ?? NULL) !== $this->instanceId()
      || ($manifest['segment_id'] ?? NULL) !== $record['segment_id']
      || ($manifest['signing_key_id'] ?? NULL) !== $record['key_id']
      || ($manifest['historical_ok'] ?? NULL) !== FALSE) {
      throw new \RuntimeException('The recovery manifest does not match this instance or segment.');
    }
    return $manifest;
  }

  /**
   * Requires a deployment identity kept outside exported configuration.
   */
  private function instanceId(): string {
    $identity = Settings::get('audit_chain_instance_id');
    if (!is_string($identity) || trim($identity) === '' || strlen($identity) > 255) {
      throw new \RuntimeException('Configure a unique runtime audit_chain_instance_id before recovery.');
    }
    return $identity;
  }

  /**
   * Accepts only the bounded, reviewed recovery context.
   */
  private function validateContext(array $context): array {
    $allowed = ['incident', 'reason', 'approved_by', 'backup_digest'];
    if (array_diff(array_keys($context), $allowed)) {
      throw new \InvalidArgumentException('Unknown recovery context field.');
    }
    $result = [];
    foreach ($allowed as $key) {
      if (!isset($context[$key]) || !is_string($context[$key])
        || trim($context[$key]) === '' || strlen($context[$key]) > 2000) {
        throw new \InvalidArgumentException('All recovery context fields must be non-empty bounded strings.');
      }
      $result[$key] = trim($context[$key]);
    }
    if (!preg_match('/^[a-f0-9]{64}$/D', $result['backup_digest'])) {
      throw new \InvalidArgumentException('The reviewed backup SHA-256 digest is required.');
    }
    return $result;
  }

  /**
   * Produces a stable failure shape without suppressing historical failure.
   */
  private function failure(string $reason): array {
    return ['segment_ok' => FALSE, 'historical_ok' => FALSE, 'reason' => $reason];
  }

  /**
   * Returns the whole-history verdict without status-report annotation.
   *
   * @return array
   *   The verify() verdict with unsigned_prefix removed.
   */
  private function recoveryVerdict(): array {
    $verdict = $this->chain->verify();
    unset($verdict['unsigned_prefix']);
    return $verdict;
  }

  /**
   * Encodes the ordered manifest and snapshot without lossy fallback.
   */
  private static function encode(mixed $value): string {
    return json_encode($value, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
  }

}
