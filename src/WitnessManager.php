<?php

declare(strict_types=1);

namespace Drupal\audit_chain;

use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;

/**
 * Selects witness backends and persists opaque receipts off the audit chain.
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
   * Submits and persists a checkpoint receipt.
   */
  public function submit(string $digestHex): WitnessReceipt {
    $this->validateDigest($digestHex);
    $checkpoint = $this->database->select('audit_chain_checkpoint', 'c')
      ->fields('c', ['digest'])
      ->condition('digest', $digestHex)
      ->execute()
      ->fetchField();
    if ($checkpoint === FALSE) {
      throw new \InvalidArgumentException('A persisted archive checkpoint is required.');
    }
    $backend = $this->configuredBackend();
    $receipt = $backend->submit($digestHex, [
      'contract' => 'audit_chain.checkpoint.v1',
    ]);
    if ($receipt->backendId !== $backend->id()) {
      throw new \RuntimeException('Witness receipt backend does not match the selected backend.');
    }
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
    return $receipt;
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
   * Attempts to advance a persisted pending receipt.
   */
  public function upgrade(string $receiptId): WitnessReceipt {
    $pending = $this->receipt($receiptId);
    if ($pending === NULL) {
      throw new \InvalidArgumentException('Witness receipt not found.');
    }
    $backend = $this->backend($pending->backendId);
    $upgraded = $backend->upgrade($pending);
    if ($upgraded->id !== $pending->id || $upgraded->backendId !== $pending->backendId) {
      throw new \RuntimeException('A witness upgrade cannot replace the receipt identity or backend.');
    }
    $this->database->update('audit_chain_witness_receipt')->fields([
      'status' => $upgraded->status,
      'updated' => $this->time->getCurrentTime(),
      'opaque_token' => $upgraded->opaqueToken,
    ])->condition('id', $pending->id)->execute();
    return $upgraded;
  }

  /**
   * Verifies a persisted receipt against its original checkpoint digest.
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
    $verdict = $this->backend($receipt->backendId)->verify($receipt, $digestHex);
    if ($receipt->status !== WitnessReceipt::STATUS_CONFIRMED && $verdict->valid) {
      return new WitnessVerdict(FALSE, 'receipt_not_confirmed');
    }
    return $verdict;
  }

  /**
   * Resolves the configured backend, defaulting to the fail-closed backend.
   */
  private function configuredBackend(): IdentifiedWitnessBackendInterface {
    $id = (string) ($this->configFactory->get('audit_chain.settings')->get('witness_backend') ?? '');
    return $this->backend($id === '' ? 'null' : $id);
  }

  /**
   * Resolves a backend without treating missing configuration as success.
   */
  private function backend(string $id): IdentifiedWitnessBackendInterface {
    return $this->backends[$id] ?? $this->backends['null']
      ?? throw new \RuntimeException('The fail-closed witness backend is unavailable.');
  }

  /**
   * Rebuilds the immutable value stored in the receipt table.
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
    if (!preg_match('/^[a-f0-9]{64}$/D', $digestHex)) {
      throw new \InvalidArgumentException('A lowercase SHA-256 checkpoint digest is required.');
    }
  }

}
