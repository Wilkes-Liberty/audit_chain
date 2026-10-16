<?php

declare(strict_types=1);

namespace Drupal\audit_chain;

use Drupal\Core\StringTranslation\TranslatableMarkup;

/**
 * Presents a ScheduledVerificationIntegrity reason on every operator surface.
 *
 * The classify() method remains the only classifier. This mapping turns a
 * reason key into copy, severity, log level, and whether the failure event
 * fires. An unknown reason is its own card: it must not throw and must not
 * reuse the pending-first-run presentation.
 */
final class ScheduledVerificationPresentation {

  /**
   * Maps a classified reason to operator-facing presentation.
   *
   * @param string $reason
   *   A ScheduledVerificationIntegrity reason key.
   * @param array $context
   *   Optional placeholders: rows, when, run_reason, require_keyed,
   *   broken_at, segment_id, historical_ok, segment_ok, rewind_through_id.
   *
   * @return array
   *   label, detail, severity, log_level, dispatch, omit, and uses_time.
   *
   * @phpstan-param array{
   *   rows?: int|string,
   *   when?: string|null,
   *   run_reason?: string,
   *   require_keyed?: bool,
   *   broken_at?: int|string|null,
   *   segment_id?: string|null,
   *   historical_ok?: mixed,
   *   segment_ok?: mixed,
   *   rewind_through_id?: int|string|null
   * } $context
   * @phpstan-return array{
   *   label: \Drupal\Core\StringTranslation\TranslatableMarkup,
   *   detail: \Drupal\Core\StringTranslation\TranslatableMarkup,
   *   severity: string,
   *   log_level: string|null,
   *   dispatch: bool,
   *   omit: bool,
   *   uses_time: bool
   * }
   */
  public static function forReason(string $reason, array $context = []): array {
    $rows = (int) ($context['rows'] ?? 0);
    $when = $context['when'] ?? NULL;
    $when = is_string($when) && $when !== '' ? $when : NULL;
    $runReason = (string) ($context['run_reason'] ?? '');
    $requireKeyed = (bool) ($context['require_keyed'] ?? FALSE);
    $brokenAt = $context['broken_at'] ?? NULL;
    $brokenAt = is_numeric($brokenAt) ? (int) $brokenAt : NULL;
    $segmentId = $context['segment_id'] ?? NULL;
    $segmentId = is_string($segmentId) && $segmentId !== '' ? $segmentId : NULL;
    $historicalOk = !empty($context['historical_ok']) ? 'true' : 'false';
    $segmentOk = !empty($context['segment_ok']) ? 'true' : 'false';
    $rewindThrough = $context['rewind_through_id'] ?? NULL;
    $rewindThrough = is_numeric($rewindThrough) ? (int) $rewindThrough : NULL;
    $unknown = new TranslatableMarkup('unknown');
    $placeholders = [
      '@n' => $rows,
      '@when' => $when ?? (string) $unknown,
      '@time' => $when ?? (string) $unknown,
      '@reason' => $runReason !== '' ? $runReason : (string) $unknown,
      '@broken_at' => $brokenAt ?? (string) $unknown,
      '@segment_id' => $segmentId ?? (string) $unknown,
      '@historical_ok' => $historicalOk,
      '@segment_ok' => $segmentOk,
      '@id' => $rewindThrough ?? (string) $unknown,
    ];

    return match ($reason) {
      'disabled' => [
        'label' => $requireKeyed
          ? new TranslatableMarkup('Assurance profile enabled, but no verification schedule')
          : new TranslatableMarkup('Not scheduled'),
        'detail' => $requireKeyed
          ? new TranslatableMarkup('verify_require_keyed is on while verify_interval is 0: keyed verification is required but never runs. Set a verification interval so integrity is proven on a cadence rather than on demand.')
          : new TranslatableMarkup('@n rows. Scheduled verification is off. Run drush audit-chain:verify, or set an interval under settings.', $placeholders),
        'severity' => 'warn',
        'log_level' => NULL,
        'dispatch' => FALSE,
        'omit' => !$requireKeyed,
        'uses_time' => FALSE,
      ],
      'pending' => [
        'label' => new TranslatableMarkup('Pending'),
        'detail' => new TranslatableMarkup('@n rows. No scheduled verification has run yet. The schedule is configured but cron has not executed a verification yet. Run cron, then re-check this report.', $placeholders),
        'severity' => 'warn',
        'log_level' => NULL,
        'dispatch' => FALSE,
        'omit' => FALSE,
        'uses_time' => FALSE,
      ],
      'seal_foreign' => [
        'label' => new TranslatableMarkup('Foreign seal'),
        'detail' => new TranslatableMarkup('The sealed prefix hashes are unchanged, but this environment cannot authenticate the copied seal with a current or retired signing key. No prefix-hash change was detected. Verification remains fail-closed and evidence export stays blocked. Verify on the source environment, or make its signing key available as a retired key only if your key-separation policy permits. Last scheduled verification @when.', $placeholders),
        'severity' => 'warn',
        'log_level' => 'warning',
        'dispatch' => FALSE,
        'omit' => FALSE,
        'uses_time' => TRUE,
      ],
      'unsigned_prefix' => [
        'label' => new TranslatableMarkup('Documented unsigned prefix'),
        'detail' => new TranslatableMarkup('A leading run of entries was hashed with unkeyed SHA-256. Those rows stay in the log. They are not cryptographically verifiable, and they are not re-signed or deleted. The signed rows after that prefix are the authoritative chain. An edited signed row, a missing signing key, or an unsigned row after the signed successor is still an error. Last scheduled verification @when.', $placeholders),
        'severity' => 'warn',
        'log_level' => 'warning',
        'dispatch' => FALSE,
        'omit' => FALSE,
        'uses_time' => TRUE,
      ],
      'historical_exception' => [
        'label' => new TranslatableMarkup('Historical exception'),
        'detail' => new TranslatableMarkup('Documented historical exception at row @broken_at. Audit Chain whole-history verification still reports the preserved failure at row @broken_at (historical_ok=@historical_ok). Successor segment @segment_id verifies independently (segment_ok=@segment_ok). This is a documented preserved failure, not a new break. Rows were not rewritten. A missing successor, or a successor that no longer verifies (segment_ok=false), is still a critical failure — investigate with drush audit-chain:verify and drush audit-chain:recovery-verify. Last scheduled verification @when.', $placeholders),
        'severity' => 'warn',
        'log_level' => 'warning',
        'dispatch' => FALSE,
        'omit' => FALSE,
        'uses_time' => TRUE,
      ],
      'failed' => [
        'label' => new TranslatableMarkup('Failed'),
        'detail' => new TranslatableMarkup('Last scheduled verification failed at @when (@reason). The chain was not modified by the check; investigate the reported reason with drush audit-chain:verify before trusting new entries.', $placeholders),
        'severity' => 'crit',
        'log_level' => 'error',
        'dispatch' => TRUE,
        'omit' => FALSE,
        'uses_time' => TRUE,
      ],
      'chain_rewound' => [
        'label' => new TranslatableMarkup('Chain rewound'),
        'detail' => $rewindThrough === NULL
          ? new TranslatableMarkup('A confirmed witness is not in this database. A database restore can rewind the chain without breaking its hashes. Last scheduled verification @when. The chain was not modified by the check. Investigate before trusting new entries.', $placeholders)
          : new TranslatableMarkup('The witnessed head at row @id is not the live row. A database restore can rewind the chain without breaking its hashes. Last scheduled verification @when. The chain was not modified by the check. Investigate before trusting new entries.', $placeholders),
        'severity' => 'crit',
        'log_level' => 'error',
        'dispatch' => TRUE,
        'omit' => FALSE,
        'uses_time' => TRUE,
      ],
      'witness_unreachable' => [
        'label' => new TranslatableMarkup('Rewind check unavailable'),
        'detail' => new TranslatableMarkup('The configured witness could not be read at @when, so this run does not show whether a database restore rewound the chain. The hash-chain result is recorded separately.', $placeholders),
        'severity' => 'warn',
        'log_level' => NULL,
        'dispatch' => FALSE,
        'omit' => FALSE,
        'uses_time' => TRUE,
      ],
      'witness_ambiguous' => [
        'label' => new TranslatableMarkup('Witness ambiguous'),
        'detail' => new TranslatableMarkup('Two confirmed witnesses name different checkpoints, so this run does not choose a chain head. Last scheduled verification @when. The chain was not modified by the check. The witness was read. The hash-chain result is recorded separately.', $placeholders),
        'severity' => 'warn',
        'log_level' => NULL,
        'dispatch' => FALSE,
        'omit' => FALSE,
        'uses_time' => TRUE,
      ],
      'overdue' => [
        'label' => new TranslatableMarkup('Overdue'),
        'detail' => new TranslatableMarkup('@n rows. Last successful verification @when is past twice the configured interval. Confirm cron is executing; an unverified chain is an unproven one.', $placeholders),
        'severity' => 'warn',
        'log_level' => NULL,
        'dispatch' => FALSE,
        'omit' => FALSE,
        'uses_time' => TRUE,
      ],
      'passing' => [
        'label' => new TranslatableMarkup('Verified'),
        'detail' => new TranslatableMarkup('@n rows. Last scheduled verification @when.', $placeholders),
        'severity' => 'ok',
        'log_level' => NULL,
        'dispatch' => FALSE,
        'omit' => FALSE,
        'uses_time' => TRUE,
      ],
      default => [
        'label' => new TranslatableMarkup('Unrecognized verification state'),
        'detail' => new TranslatableMarkup('Scheduled verification classified reason @reason, which this version does not present. This is not a pending first run. Investigate with drush audit-chain:verify before trusting new entries.', [
          '@reason' => $reason,
        ]),
        'severity' => 'warn',
        'log_level' => 'warning',
        'dispatch' => FALSE,
        'omit' => FALSE,
        'uses_time' => FALSE,
      ],
    };
  }

}
