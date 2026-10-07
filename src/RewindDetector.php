<?php

declare(strict_types=1);

namespace Drupal\audit_chain;

use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Database\Connection;

/**
 * Compares the live chain with the latest confirmed external witness.
 *
 * Receipt rows live in the database, so a restore removes them with the
 * chain. This check reads the witness. XRPL uses the read service's account
 * transaction list. OpenTimestamps can only fresh-verify a proof that is
 * still stored; Bitcoin does not list proofs, so a proof lost with the
 * database cannot be rediscovered. An empty witness setting does not run
 * the check.
 */
final class RewindDetector {

  /**
   * No witness is configured. The check did not run.
   */
  public const STATUS_NOT_CONFIGURED = 'not_configured';

  /**
   * The witness was read and has no confirmed checkpoint.
   */
  public const STATUS_ABSENT = 'absent';

  /**
   * The witness could not be read. This is not a rewind.
   */
  public const STATUS_UNCHECKED = 'unchecked';

  /**
   * The latest confirmed witness head is still the live row.
   */
  public const STATUS_MATCHES = 'matches';

  /**
   * The latest confirmed witness head is not in the live chain.
   */
  public const STATUS_REWOUND = 'rewound';

  /**
   * Scheduled-verification reason for a detected rewind.
   */
  public const REASON_REWOUND = 'chain_rewound';

  /**
   * Scheduled-verification reason when the witness could not be read.
   */
  public const REASON_UNREACHABLE = 'witness_unreachable';

  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly Connection $database,
    private readonly XrplWitnessBackend $xrpl,
    private readonly WitnessManager $witnesses,
  ) {}

  /**
   * Compares the live chain with the latest confirmed witness.
   *
   * @return array{status: string, reason: string, digest: string|null, through_id: int|null}
   *   status is one of the STATUS_* constants. digest and through_id are
   *   set when a confirmed checkpoint was identified.
   */
  public function assess(): array {
    $backend = $this->configFactory->get('audit_chain.settings')->get('witness_backend');
    $backend = is_string($backend) ? $backend : '';
    if ($backend === '' || $backend === 'null') {
      return $this->result(self::STATUS_NOT_CONFIGURED, 'witness_not_configured');
    }
    try {
      $digest = match ($backend) {
        'xrpl' => $this->xrplDigest(),
        'opentimestamps' => $this->openTimestampsDigest(),
        default => FALSE,
      };
    }
    catch (\Throwable) {
      return $this->result(self::STATUS_UNCHECKED, self::REASON_UNREACHABLE);
    }
    if ($digest === FALSE) {
      return $this->result(self::STATUS_UNCHECKED, self::REASON_UNREACHABLE);
    }
    if ($digest === NULL) {
      return $this->result(self::STATUS_ABSENT, 'witness_absent');
    }
    return $this->compare($digest);
  }

  /**
   * Returns the newest confirmed XRPL digest, or NULL when none exists.
   *
   * @return string|null
   *   Lowercase checkpoint digest.
   */
  private function xrplDigest(): ?string {
    $rows = $this->xrpl->confirmedDigests();
    $bestIndex = -1;
    $best = [];
    foreach ($rows as $row) {
      if ($row['ledger_index'] > $bestIndex) {
        $bestIndex = $row['ledger_index'];
        $best = [$row['digest']];
        continue;
      }
      if ($row['ledger_index'] === $bestIndex && !in_array($row['digest'], $best, TRUE)) {
        $best[] = $row['digest'];
      }
    }
    if (count($best) > 1) {
      throw new \RuntimeException('witness_ambiguous');
    }
    return $best[0] ?? NULL;
  }

  /**
   * Returns the newest fresh OpenTimestamps digest still stored here.
   *
   * @return string|null
   *   Lowercase checkpoint digest, or NULL when nothing is confirmed.
   */
  private function openTimestampsDigest(): ?string {
    if (!$this->database->schema()->tableExists('audit_chain_witness_receipt')) {
      return NULL;
    }
    $rows = $this->database->select('audit_chain_witness_receipt', 'w')
      ->fields('w', ['id', 'checkpoint_digest', 'status', 'updated'])
      ->condition('backend_id', 'opentimestamps')
      ->orderBy('updated', 'DESC')
      ->orderBy('id', 'DESC')
      ->execute();
    $confirmed = FALSE;
    foreach ($rows as $row) {
      if ((string) $row->status !== WitnessReceipt::STATUS_CONFIRMED) {
        continue;
      }
      $confirmed = TRUE;
      $verdict = $this->witnesses->verify((string) $row->id, (string) $row->checkpoint_digest);
      if ($verdict->reason === 'backend_unreachable') {
        throw new \RuntimeException('backend_unreachable');
      }
      if ($verdict->valid) {
        return strtolower((string) $row->checkpoint_digest);
      }
    }
    if (!$confirmed) {
      return NULL;
    }
    return NULL;
  }

  /**
   * Compares one confirmed digest with the live chain head it names.
   *
   * @param string $digest
   *   Lowercase checkpoint digest.
   *
   * @return array{status: string, reason: string, digest: string|null, through_id: int|null}
   *   A rewound or matching result.
   */
  private function compare(string $digest): array {
    $manifest = $this->checkpointManifest($digest);
    if ($manifest === NULL) {
      return $this->result(self::STATUS_REWOUND, self::REASON_REWOUND, $digest, NULL);
    }
    $through = $manifest['through_id'];
    $live = $this->database->select('audit_chain_log', 'l')
      ->fields('l', ['row_hash'])
      ->condition('id', $through)
      ->execute()
      ->fetchField();
    $max = $this->database->select('audit_chain_log', 'l')
      ->fields('l', ['id'])
      ->orderBy('id', 'DESC')
      ->range(0, 1)
      ->execute()
      ->fetchField();
    $headMovedBack = $max === FALSE || (int) $max < $through;
    $headMissing = !is_string($live) || !hash_equals($manifest['chain_head'], $live);
    if ($headMovedBack || $headMissing) {
      return $this->result(self::STATUS_REWOUND, self::REASON_REWOUND, $digest, $through);
    }
    return $this->result(self::STATUS_MATCHES, 'witness_matches', $digest, $through);
  }

  /**
   * Loads the head a persisted checkpoint commits to.
   *
   * @param string $digest
   *   Lowercase checkpoint digest.
   *
   * @return array{through_id: int, chain_head: string}|null
   *   NULL when this database has no such checkpoint.
   */
  private function checkpointManifest(string $digest): ?array {
    if (!$this->database->schema()->tableExists('audit_chain_checkpoint')) {
      return NULL;
    }
    $raw = $this->database->select('audit_chain_checkpoint', 'c')
      ->fields('c', ['manifest'])
      ->condition('digest', $digest)
      ->execute()
      ->fetchField();
    if ($raw === FALSE) {
      return NULL;
    }
    $manifest = json_decode((string) $raw, TRUE);
    $window = is_array($manifest) ? ($manifest['window'] ?? NULL) : NULL;
    $through = is_array($window) ? ($window['through_id'] ?? NULL) : NULL;
    $head = is_array($manifest) ? ($manifest['chain_head'] ?? NULL) : NULL;
    if (!is_int($through) || !is_string($head) || preg_match('/^[a-f0-9]{64}$/D', $head) !== 1) {
      throw new \RuntimeException('checkpoint_unreadable');
    }
    return [
      'through_id' => $through,
      'chain_head' => $head,
    ];
  }

  /**
   * Builds one assessment.
   *
   * @param string $status
   *   One of the STATUS_* constants.
   * @param string $reason
   *   Stable machine reason.
   * @param string|null $digest
   *   Confirmed checkpoint digest, when one was read.
   * @param int|null $throughId
   *   Witnessed head id, when the checkpoint names one.
   *
   * @return array{status: string, reason: string, digest: string|null, through_id: int|null}
   *   The assessment stored on the scheduled-verification run.
   */
  private function result(string $status, string $reason, ?string $digest = NULL, ?int $throughId = NULL): array {
    return [
      'status' => $status,
      'reason' => $reason,
      'digest' => $digest,
      'through_id' => $throughId,
    ];
  }

}
