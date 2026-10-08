<?php

declare(strict_types=1);

namespace Drupal\audit_chain;

/**
 * Classifies a scheduled-verification run against its interval.
 *
 * Status report and dashboard metrics share this tree so a new state cannot
 * land on one surface and be missed on the other.
 */
final class ScheduledVerificationIntegrity {

  /**
   * Classifies a stored run record.
   *
   * @param mixed $run
   *   The scheduled-verification state value, or NULL when none exists.
   * @param int $interval
   *   Configured verify_interval in seconds. Zero or less means unscheduled.
   * @param int $now
   *   Current unix time.
   *
   * @return array{status: string, reason: string, time: int|null}
   *   status is ok/warn/crit. reason is a stable machine key.
   */
  public static function classify(mixed $run, int $interval, int $now): array {
    $time = is_array($run) ? ((int) ($run['time'] ?? 0) ?: NULL) : NULL;

    if ($interval <= 0) {
      return [
        'status' => 'warn',
        'reason' => 'disabled',
        'time' => $time,
      ];
    }

    if (!is_array($run)) {
      return [
        'status' => 'warn',
        'reason' => 'pending',
        'time' => NULL,
      ];
    }

    $ok = (bool) ($run['ok'] ?? FALSE);
    $reason = (string) ($run['reason'] ?? '');
    $rewind = is_array($run['rewind'] ?? NULL) ? $run['rewind'] : [];

    // A restore can leave a chain that still verifies. The witness mismatch
    // is its own failure and is not softened into another warning.
    if (($rewind['status'] ?? '') === RewindDetector::STATUS_REWOUND) {
      return [
        'status' => 'crit',
        'reason' => RewindDetector::REASON_REWOUND,
        'time' => $time,
      ];
    }

    if (!$ok && $reason === AuditChainLogger::REASON_SEAL_FOREIGN) {
      return [
        'status' => 'warn',
        'reason' => 'seal_foreign',
        'time' => $time,
      ];
    }

    // A leading unsigned prefix is retained history. It is not a pass, and it
    // is not an unexplained integrity failure when a signed successor verifies.
    $verdict = is_array($run['verdict'] ?? NULL) ? $run['verdict'] : [];
    $unsignedPrefix = ($verdict['unsigned_prefix'] ?? FALSE) === TRUE;
    if (!$ok && $reason === AuditChainLogger::REASON_WRITTEN_UNKEYED && $unsignedPrefix) {
      return [
        'status' => 'warn',
        'reason' => 'unsigned_prefix',
        'time' => $time,
      ];
    }

    // A disclosed historical fork with a verifying successor is retained
    // evidence. It is not a pass, and it is not a new unexplained break.
    if (!$ok && self::isDocumentedHistoricalException($run)) {
      return [
        'status' => 'warn',
        'reason' => 'historical_exception',
        'time' => $time,
      ];
    }

    if (!$ok) {
      return [
        'status' => 'crit',
        'reason' => 'failed',
        'time' => $time,
      ];
    }

    if (($rewind['status'] ?? '') === RewindDetector::STATUS_UNCHECKED) {
      $rewindReason = (string) ($rewind['reason'] ?? '');
      return [
        'status' => 'warn',
        'reason' => $rewindReason === RewindDetector::REASON_AMBIGUOUS
          ? RewindDetector::REASON_AMBIGUOUS
          : RewindDetector::REASON_UNREACHABLE,
        'time' => $time,
      ];
    }

    if ($time !== NULL && $now > ($time + 2 * $interval)) {
      return [
        'status' => 'warn',
        'reason' => 'overdue',
        'time' => $time,
      ];
    }

    return [
      'status' => 'ok',
      'reason' => 'passing',
      'time' => $time,
    ];
  }

  /**
   * Whether a failing run is the disclosed historical fork, not a new break.
   *
   * Whole-history verification stays unsuccessful. A missing successor, a
   * successor that no longer verifies, or a broken_at that is not the
   * disclosed exception stays a critical failure.
   *
   * @param mixed $run
   *   The scheduled-verification state value.
   *
   * @return bool
   *   TRUE only when reason is tampered, the successor segment verifies,
   *   historical_ok is explicitly false, and broken_at matches the
   *   disclosed historical verdict.
   */
  public static function isDocumentedHistoricalException(mixed $run): bool {
    if (!is_array($run) || ($run['ok'] ?? TRUE) === TRUE) {
      return FALSE;
    }
    if (($run['reason'] ?? '') !== AuditChainLogger::REASON_TAMPERED) {
      return FALSE;
    }
    $successor = $run['successor'] ?? NULL;
    if (!is_array($successor)
      || ($successor['segment_ok'] ?? FALSE) !== TRUE
      || ($successor['historical_ok'] ?? TRUE) !== FALSE) {
      return FALSE;
    }
    $segmentId = $successor['segment_id'] ?? NULL;
    if (!is_string($segmentId) || $segmentId === '') {
      return FALSE;
    }
    $verdict = is_array($run['verdict'] ?? NULL) ? $run['verdict'] : [];
    $historical = is_array($successor['historical_verdict'] ?? NULL)
      ? $successor['historical_verdict']
      : [];
    if (($historical['reason'] ?? '') !== AuditChainLogger::REASON_TAMPERED) {
      return FALSE;
    }
    $brokenAt = $verdict['broken_at'] ?? NULL;
    $disclosedAt = $historical['broken_at'] ?? NULL;
    if (!is_numeric($brokenAt) || !is_numeric($disclosedAt)) {
      return FALSE;
    }
    return (int) $brokenAt === (int) $disclosedAt && (int) $brokenAt > 0;
  }

}
