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

    if (!$ok && $reason === AuditChainLogger::REASON_SEAL_FOREIGN) {
      return [
        'status' => 'warn',
        'reason' => 'seal_foreign',
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

}
