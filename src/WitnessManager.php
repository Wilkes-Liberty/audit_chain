<?php

declare(strict_types=1);

namespace Drupal\audit_chain;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;

/**
 * Selects witness backends and persists opaque receipts off the audit chain.
 *
 * An empty witness_backend setting still selects the fail-closed null
 * backend. An explicit unknown id throws instead of falling through. Upgrade
 * compares the stored token and status so a stale result cannot overwrite a
 * newer receipt. Witness operations do not write audit-chain rows.
 */
final class WitnessManager {

  /**
   * Registered backends keyed by stable identifier.
   *
   * @var array<string, \Drupal\audit_chain\IdentifiedWitnessBackendInterface>
   */
  private array $backends = [];

  public function __construct(
    private readonly Connection $database,
    private readonly ConfigFactoryInterface $configFactory,
    private readonly TimeInterface $time,
  ) {}

  /**
   * Adds a backend through Drupal's service collector.
   */
  public function addBackend(IdentifiedWitnessBackendInterface $backend): void {
    $this->backends[$backend->id()] = $backend;
  }

  /**
   * Submits and persists one checkpoint receipt.
   *
   * An existing pending or confirmed receipt for the same backend and digest
   * is reused unless a new attempt is requested. The optional arguments keep
   * the original one-argument call valid.
   */
  public function submit(string $digestHex, ?string $backendId = NULL, bool $newAttempt = FALSE): WitnessReceipt {
    $this->validateDigest($digestHex);
    $this->assertCheckpoint($digestHex);
    $backend = $backendId === NULL ? $this->configuredBackend() : $this->backend($backendId);
    if (!$newAttempt) {
      $existing = $this->findReusable($digestHex, $backend->id());
      if ($existing !== NULL) {
        return $existing;
      }
    }
    if ($backend instanceof XrplWitnessBackend) {
      return $this->submitXrpl($digestHex, $backend);
    }
    $receipt = $backend->submit($digestHex, [
      'contract' => 'audit_chain.checkpoint.v1',
    ]);
    if ($receipt->backendId !== $backend->id()) {
      throw new \RuntimeException('Witness receipt backend does not match the selected backend.');
    }
    $this->insertReceipt($receipt, $digestHex);
    return $receipt;
  }

  /**
   * Submits to each named backend without rolling back the others.
   *
   * @param string $digestHex
   *   Persisted checkpoint digest.
   * @param list<string> $backendIds
   *   Backend ids, in the order the caller named them.
   * @param bool $newAttempt
   *   TRUE to store another receipt instead of reusing one.
   *
   * @return list<array{backend_id: string, receipt: \Drupal\audit_chain\WitnessReceipt|null, error: string|null}>
   *   One result per requested backend. A failure does not remove the others.
   */
  public function submitTo(string $digestHex, array $backendIds, bool $newAttempt = FALSE): array {
    $this->validateDigest($digestHex);
    $this->assertCheckpoint($digestHex);
    $results = [];
    foreach ($backendIds as $backendId) {
      try {
        $results[] = [
          'backend_id' => $backendId,
          'receipt' => $this->submit($digestHex, $backendId, $newAttempt),
          'error' => NULL,
        ];
      }
      catch (\Throwable $exception) {
        $results[] = [
          'backend_id' => $backendId,
          'receipt' => NULL,
          'error' => $exception->getMessage(),
        ];
      }
    }
    return $results;
  }

  /**
   * Loads a persisted receipt without exposing its checkpoint digest.
   */
  public function receipt(string $receiptId): ?WitnessReceipt {
    $record = $this->database->select('audit_chain_witness_receipt', 'w')
      ->fields('w', ['id', 'backend_id', 'status', 'opaque_token'])
      ->condition('id', $receiptId)
      ->execute()
      ->fetchAssoc();
    return $record === FALSE ? NULL : $this->receiptFromRecord($record);
  }

  /**
   * Lists receipts for one persisted checkpoint, oldest first.
   *
   * @return list<array{id: string, backend_id: string, status: string, submitted: int, updated: int, opaque_token: string}>
   *   Receipt rows for the digest, oldest first.
   */
  public function recordsForDigest(string $digestHex): array {
    $this->validateDigest($digestHex);
    $rows = $this->database->select('audit_chain_witness_receipt', 'w')
      ->fields('w', ['id', 'backend_id', 'status', 'submitted', 'updated', 'opaque_token'])
      ->condition('checkpoint_digest', $digestHex)
      ->orderBy('submitted')
      ->orderBy('id')
      ->execute()
      ->fetchAll();
    $records = [];
    foreach ($rows as $row) {
      $records[] = [
        'id' => (string) $row->id,
        'backend_id' => (string) $row->backend_id,
        'status' => (string) $row->status,
        'submitted' => (int) $row->submitted,
        'updated' => (int) $row->updated,
        'opaque_token' => (string) $row->opaque_token,
      ];
    }
    return $records;
  }

  /**
   * Attempts to advance a persisted pending receipt.
   */
  public function upgrade(string $receiptId): WitnessReceipt {
    $pending = $this->receipt($receiptId);
    if ($pending === NULL) {
      throw new \InvalidArgumentException('Witness receipt not found.');
    }
    $backend = $this->backend($pending->backendId);
    $upgraded = $backend->upgrade($pending);
    $this->assertSameIdentity($pending, $upgraded);
    return $this->storeUpgrade($pending, $upgraded);
  }

  /**
   * Verifies a persisted receipt against its original checkpoint digest.
   *
   * A stored confirmed status is not itself a successful verdict.
   */
  public function verify(string $receiptId, string $digestHex): WitnessVerdict {
    $this->validateDigest($digestHex);
    $record = $this->database->select('audit_chain_witness_receipt', 'w')
      ->fields('w')
      ->condition('id', $receiptId)
      ->execute()
      ->fetchAssoc();
    if ($record === FALSE) {
      return new WitnessVerdict(FALSE, 'receipt_missing');
    }
    if (!hash_equals((string) $record['checkpoint_digest'], $digestHex)) {
      return new WitnessVerdict(FALSE, 'checkpoint_digest_mismatch');
    }
    $receipt = $this->receiptFromRecord($record);
    try {
      $backend = $this->backend($receipt->backendId);
    }
    catch (\RuntimeException) {
      return new WitnessVerdict(FALSE, 'backend_not_configured');
    }
    $verdict = $backend->verify($receipt, $digestHex);
    if ($receipt->status !== WitnessReceipt::STATUS_CONFIRMED && $verdict->valid) {
      return new WitnessVerdict(FALSE, 'receipt_not_confirmed', $verdict->evidence);
    }
    return $verdict;
  }

  /**
   * Persists the XRPL request id before the relay is contacted.
   */
  private function submitXrpl(string $digestHex, XrplWitnessBackend $backend): WitnessReceipt {
    $reserved = $backend->reserve($digestHex);
    $this->insertReceipt($reserved, $digestHex);
    try {
      $final = $backend->dispatch($reserved);
    }
    catch (\Throwable) {
      $final = $backend->uncertain($reserved);
    }
    $this->assertSameIdentity($reserved, $final);
    return $this->storeUpgrade($reserved, $final);
  }

  /**
   * Inserts a receipt row. The caller has already checked the checkpoint.
   */
  private function insertReceipt(WitnessReceipt $receipt, string $digestHex): void {
    $now = $this->time->getCurrentTime();
    $this->database->insert('audit_chain_witness_receipt')->fields([
      'id' => $receipt->id,
      'checkpoint_digest' => $digestHex,
      'backend_id' => $receipt->backendId,
      'status' => $receipt->status,
      'submitted' => $now,
      'updated' => $now,
      'opaque_token' => $receipt->opaqueToken,
    ])->execute();
  }

  /**
   * Writes an upgrade only when the stored token and status are unchanged.
   */
  private function storeUpgrade(WitnessReceipt $prior, WitnessReceipt $upgraded): WitnessReceipt {
    if ($this->compareAndSwap($prior, $upgraded)) {
      return $upgraded;
    }
    $current = $this->receipt($prior->id);
    if ($current !== NULL && $current->opaqueToken === $upgraded->opaqueToken && $current->status === $upgraded->status) {
      return $current;
    }
    if ($current === NULL) {
      throw new \RuntimeException('witness_receipt_conflict');
    }
    $retried = $this->backend($current->backendId)->upgrade($current);
    $this->assertSameIdentity($current, $retried);
    if ($this->compareAndSwap($current, $retried)) {
      return $retried;
    }
    $again = $this->receipt($prior->id);
    if ($again !== NULL && $again->opaqueToken === $retried->opaqueToken && $again->status === $retried->status) {
      return $again;
    }
    throw new \RuntimeException('witness_receipt_conflict');
  }

  /**
   * Updates one receipt if its token and status still match.
   */
  private function compareAndSwap(WitnessReceipt $prior, WitnessReceipt $upgraded): bool {
    $updated = $this->database->update('audit_chain_witness_receipt')
      ->fields([
        'status' => $upgraded->status,
        'updated' => $this->time->getCurrentTime(),
        'opaque_token' => $upgraded->opaqueToken,
      ])
      ->condition('id', $prior->id)
      ->condition('opaque_token', $prior->opaqueToken)
      ->condition('status', $prior->status)
      ->execute();
    return (int) $updated > 0;
  }

  /**
   * Returns the earliest reusable receipt for a backend and digest.
   */
  private function findReusable(string $digestHex, string $backendId): ?WitnessReceipt {
    $record = $this->database->select('audit_chain_witness_receipt', 'w')
      ->fields('w', ['id', 'backend_id', 'status', 'opaque_token'])
      ->condition('checkpoint_digest', $digestHex)
      ->condition('backend_id', $backendId)
      ->condition('status', [
        WitnessReceipt::STATUS_PENDING,
        WitnessReceipt::STATUS_CONFIRMED,
      ], 'IN')
      ->orderBy('submitted')
      ->orderBy('id')
      ->range(0, 1)
      ->execute()
      ->fetchAssoc();
    return $record === FALSE ? NULL : $this->receiptFromRecord($record);
  }

  /**
   * Requires the digest to already be a persisted checkpoint.
   */
  private function assertCheckpoint(string $digestHex): void {
    $checkpoint = $this->database->select('audit_chain_checkpoint', 'c')
      ->fields('c', ['digest'])
      ->condition('digest', $digestHex)
      ->execute()
      ->fetchField();
    if ($checkpoint === FALSE) {
      throw new \InvalidArgumentException('A persisted archive checkpoint is required.');
    }
  }

  /**
   * Resolves the configured backend. An empty value stays on null.
   */
  private function configuredBackend(): IdentifiedWitnessBackendInterface {
    $id = $this->configFactory->get('audit_chain.settings')->get('witness_backend');
    $id = is_string($id) ? $id : '';
    return $this->backend($id === '' ? 'null' : $id);
  }

  /**
   * Resolves a registered backend. Missing ids do not fall through to null.
   */
  private function backend(string $id): IdentifiedWitnessBackendInterface {
    if ($id === '' || !isset($this->backends[$id])) {
      throw new \RuntimeException('Witness backend is not registered.');
    }
    return $this->backends[$id];
  }

  /**
   * Rebuilds the immutable value stored in the receipt table.
   *
   * @param array<string, mixed> $record
   *   One receipt-table row.
   *
   * @return \Drupal\audit_chain\WitnessReceipt
   *   Receipt value without the checkpoint digest.
   */
  private function receiptFromRecord(array $record): WitnessReceipt {
    return new WitnessReceipt(
      (string) $record['id'],
      (string) $record['backend_id'],
      (string) $record['status'],
      (string) $record['opaque_token'],
    );
  }

  /**
   * Requires a lowercase SHA-256 digest at the public boundary.
   */
  private function validateDigest(string $digestHex): void {
    if (preg_match('/^[a-f0-9]{64}$/D', $digestHex) !== 1) {
      throw new \InvalidArgumentException('A lowercase SHA-256 checkpoint digest is required.');
    }
  }

  /**
   * Rejects an upgrade that changes the receipt id or backend.
   */
  private function assertSameIdentity(WitnessReceipt $prior, WitnessReceipt $upgraded): void {
    if ($upgraded->id !== $prior->id || $upgraded->backendId !== $prior->backendId) {
      throw new \RuntimeException('A witness upgrade cannot replace the receipt identity or backend.');
    }
  }

}
