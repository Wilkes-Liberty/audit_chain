<?php

declare(strict_types=1);

namespace Drupal\audit_chain;

/**
 * Human-gated witness operations for the command line.
 *
 * Approval is the exact persisted digest and the exact backend list. A
 * Drush affirmative flag is not accepted here. The operator does not write
 * audit-chain rows and does not treat one witness as confirmation of another.
 */
final class WitnessOperator {

  public function __construct(
    private readonly WitnessManager $manager,
  ) {}

  /**
   * Submits after the caller repeats the digest and backend list.
   */
  public function submit(string $digest, string $backends, string $confirmDigest, string $confirmBackends, bool $newAttempt): WitnessOperation {
    if (!$this->approved($digest, $backends, $confirmDigest, $confirmBackends)) {
      return new WitnessOperation(1, ['witness_approval_required']);
    }
    $ids = explode(',', $backends);
    try {
      $results = $this->manager->submitTo($digest, $ids, $newAttempt);
    }
    catch (\Throwable $exception) {
      return new WitnessOperation(1, [$exception->getMessage()]);
    }
    $lines = [];
    $failed = FALSE;
    foreach ($results as $result) {
      $receipt = $result['receipt'];
      if ($receipt instanceof WitnessReceipt) {
        $lines[] = $receipt->id . ' ' . $receipt->backendId . ' ' . $receipt->status;
      }
      else {
        $failed = TRUE;
        $lines[] = $result['backend_id'] . ' ' . (string) $result['error'];
      }
    }
    return new WitnessOperation($failed ? 1 : 0, $lines);
  }

  /**
   * Upgrades one receipt. A still-pending result is success.
   */
  public function upgrade(string $receiptId): WitnessOperation {
    try {
      $receipt = $this->manager->upgrade($receiptId);
    }
    catch (\Throwable $exception) {
      return new WitnessOperation(1, [$exception->getMessage()]);
    }
    return new WitnessOperation(0, [$receipt->id . ' ' . $receipt->status]);
  }

  /**
   * Verifies one receipt. A non-zero exit means the verdict is not valid.
   */
  public function verify(string $receiptId, string $digest): WitnessOperation {
    try {
      $verdict = $this->manager->verify($receiptId, $digest);
    }
    catch (\Throwable $exception) {
      return new WitnessOperation(1, [$exception->getMessage()]);
    }
    $line = ($verdict->valid ? 'valid' : 'invalid') . ' ' . $verdict->reason;
    return new WitnessOperation($verdict->valid ? 0 : 1, [$line], NULL, $verdict->evidence);
  }

  /**
   * Lists receipt ids for a checkpoint without making a combined claim.
   */
  public function receipts(string $digest): WitnessOperation {
    try {
      $records = $this->manager->recordsForDigest($digest);
    }
    catch (\Throwable $exception) {
      return new WitnessOperation(1, [$exception->getMessage()]);
    }
    $lines = [];
    foreach ($records as $record) {
      $lines[] = $record['id'] . ' ' . $record['backend_id'] . ' ' . $record['status'];
    }
    return new WitnessOperation(0, $lines);
  }

  /**
   * Prints each receipt and its own fresh verdict.
   *
   * The default exit does not require any witness. --require names one
   * backend, or all, and never counts a pending witness as confirmed.
   */
  public function status(string $digest, string $require): WitnessOperation {
    try {
      $records = $this->manager->recordsForDigest($digest);
    }
    catch (\Throwable $exception) {
      return new WitnessOperation(1, [$exception->getMessage()]);
    }
    $lines = [];
    $fresh = [];
    foreach ($records as $record) {
      $valid = FALSE;
      try {
        $verdict = $this->manager->verify($record['id'], $digest);
        $valid = $verdict->valid;
        $state = $valid ? 'valid' : 'invalid';
        $reason = $verdict->reason;
        $evidence = $verdict->evidence;
      }
      catch (\Throwable $exception) {
        $state = 'invalid';
        $reason = $exception->getMessage();
        $evidence = [];
      }
      $backendId = $record['backend_id'];
      $fresh[$backendId] = ($fresh[$backendId] ?? FALSE) || $valid;
      $lines[] = $record['id'] . ' ' . $backendId . ' ' . $record['status'] . ' ' . $state . ' ' . $reason;
      $lines[] = 'submitted=' . $record['submitted'] . ' ' . $this->evidenceText($evidence);
    }
    if ($require === '') {
      return new WitnessOperation(0, $lines);
    }
    $needed = $require === 'all' ? ['opentimestamps', 'xrpl'] : [$require];
    foreach ($needed as $backendId) {
      if (empty($fresh[$backendId])) {
        return new WitnessOperation(1, $lines);
      }
    }
    return new WitnessOperation(0, $lines);
  }

  /**
   * Returns portable proof bytes for one receipt.
   */
  public function export(string $receiptId): WitnessOperation {
    $receipt = $this->manager->receipt($receiptId);
    if ($receipt === NULL) {
      return new WitnessOperation(1, ['receipt_missing']);
    }
    if ($receipt->backendId === 'opentimestamps') {
      $bytes = base64_decode($receipt->opaqueToken, TRUE);
      if ($bytes === FALSE) {
        return new WitnessOperation(1, ['receipt_malformed']);
      }
      return new WitnessOperation(0, [$receipt->id . '.ots'], $bytes);
    }
    if ($receipt->backendId === 'xrpl') {
      return new WitnessOperation(0, [$receipt->id . '.json'], $receipt->opaqueToken);
    }
    return new WitnessOperation(1, ['receipt_not_exportable']);
  }

  /**
   * Whether the repeated digest and backend list match exactly.
   */
  private function approved(string $digest, string $backends, string $confirmDigest, string $confirmBackends): bool {
    if ($digest === '' || $backends === '' || $confirmDigest === '' || $confirmBackends === '') {
      return FALSE;
    }
    if (strlen($digest) !== strlen($confirmDigest) || strlen($backends) !== strlen($confirmBackends)) {
      return FALSE;
    }
    if (!hash_equals($digest, $confirmDigest) || !hash_equals($backends, $confirmBackends)) {
      return FALSE;
    }
    if (preg_match('/^[a-z0-9]+(,[a-z0-9]+)*$/', $backends) !== 1) {
      return FALSE;
    }
    return TRUE;
  }

  /**
   * Formats evidence for a status line.
   *
   * @param array<string, int|string|bool> $evidence
   *   Evidence copied from a fresh verdict.
   *
   * @return string
   *   One evidence clause, or evidence=none.
   */
  private function evidenceText(array $evidence): string {
    if ($evidence === []) {
      return 'evidence=none';
    }
    $parts = [];
    foreach ($evidence as $key => $value) {
      $parts[] = $key . '=' . (is_bool($value) ? ($value ? 'true' : 'false') : (string) $value);
    }
    return implode(' ', $parts);
  }

}
