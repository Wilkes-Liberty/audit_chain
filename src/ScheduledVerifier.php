<?php

declare(strict_types=1);

namespace Drupal\audit_chain;

use Drupal\audit_chain\Event\AuditChainVerificationFailedEvent;
use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Datetime\DateFormatterInterface;
use Drupal\Core\State\StateInterface;
use Psr\Log\LoggerInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

/**
 * Runs chain verification on a schedule and records its health durably.
 *
 * Keyed chain integrity is valuable only when verification is routinely
 * executed and a failure leaves the writer's trust boundary (d.o #3616535).
 * A foreign prefix seal remains a fail-closed, export-blocking result, but is
 * logged as an advisory and does not dispatch the tampering-oriented failure
 * event. Verification is strictly read-only: a failing chain is never
 * rewritten.
 *
 * The enterprise assurance profile (`verify_require_keyed`) refuses unkeyed
 * operation outright: with no signing key configured the run fails with a
 * stable reason instead of falling back to unkeyed SHA-256 verification, and
 * rows that were written unkeyed fail it too.
 */
final class ScheduledVerifier {

  /**
   * State key holding the latest run record.
   */
  public const STATE_KEY = 'audit_chain.scheduled_verification';

  /**
   * Failure reason when the assurance profile finds no signing key.
   */
  public const REASON_KEY_REQUIRED = 'keyed_verification_unavailable';

  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly AuditChainLoggerInterface $chain,
    private readonly StateInterface $state,
    private readonly TimeInterface $time,
    private readonly EventDispatcherInterface $eventDispatcher,
    private readonly LoggerInterface $logger,
    private readonly DateFormatterInterface $dates,
    private readonly ?RecoverySegments $recovery = NULL,
    private readonly ?RewindDetector $rewind = NULL,
  ) {}

  /**
   * Runs the verification when the configured interval says it is due.
   *
   * @return array|null
   *   The recorded run, or NULL when scheduling is disabled or not yet due.
   */
  public function runIfDue(): ?array {
    $interval = (int) $this->configFactory->get('audit_chain.settings')->get('verify_interval');
    if ($interval <= 0) {
      return NULL;
    }
    $last = $this->state->get(self::STATE_KEY);
    if (is_array($last) && $this->time->getRequestTime() < ((int) ($last['time'] ?? 0) + $interval)) {
      return NULL;
    }
    return $this->runNow();
  }

  /**
   * Runs the verification immediately and records the outcome.
   *
   * The verdict is written to state before presentation. The failure event
   * then dispatches, and successor-defect plus presentation logging run in
   * a finally block: a throwing logger cannot skip the event, and a throwing
   * subscriber cannot skip the watchdog log. Logger and subscriber exceptions
   * still propagate after the verdict is saved.
   *
   * @return array
   *   The recorded run: time, ok, reason, keyed, and (when the verification
   *   executed) the full verify() verdict under 'verdict'.
   */
  public function runNow(): array {
    $settings = $this->configFactory->get('audit_chain.settings');
    $requireKeyed = (bool) $settings->get('verify_require_keyed');
    // signingStatus() is the key-resolution owner: a hash_key naming a
    // missing or empty Key entity means writes fall back to unkeyed SHA-256,
    // and the assurance profile must treat that as unkeyed.
    $keyConfigured = $this->chain->signingStatus()['keyed'];

    if ($requireKeyed && !$keyConfigured) {
      // The assurance profile never falls back to unkeyed verification: an
      // unkeyed pass would claim integrity that anyone with database access
      // could forge by recomputing plain SHA-256 over an edited row.
      $run = [
        'time' => $this->time->getRequestTime(),
        'ok' => FALSE,
        'reason' => self::REASON_KEY_REQUIRED,
        'keyed' => FALSE,
        'verdict' => NULL,
      ];
    }
    else {
      $verdict = $this->chain->verify();
      $ok = (bool) $verdict['ok'];
      $reason = $verdict['reason'];
      if ($ok && $requireKeyed && (int) $verdict['unkeyed_rows'] > 0) {
        // Belt over verify()'s own unkeyed reporting: under the assurance
        // profile, unkeyed history can never amount to a pass.
        $ok = FALSE;
        $reason = AuditChainLogger::REASON_WRITTEN_UNKEYED;
      }
      $run = [
        'time' => $this->time->getRequestTime(),
        'ok' => $ok,
        'reason' => $reason,
        'keyed' => $keyConfigured,
        'verdict' => $verdict,
      ];
    }

    // Never substitute successor health for the whole-history verdict.
    $run['successor'] = $this->recovery?->currentStatus();
    // A confirmed witness lives outside the database. Compare it before the
    // run is recorded so a restore cannot look like a pass.
    $run['rewind'] = $this->assessRewind();
    if ($run['rewind']['status'] === RewindDetector::STATUS_REWOUND) {
      $run['ok'] = FALSE;
      $run['reason'] = RewindDetector::REASON_REWOUND;
    }
    $this->state->set(self::STATE_KEY, $run);
    $this->recordPresentation($run);

    return $run;
  }

  /**
   * Reads the configured witness without letting a transport failure escape.
   *
   * @return array{status: string, reason: string, digest: string|null, through_id: int|null}
   *   The rewind assessment. A missing detector is treated as not configured.
   */
  private function assessRewind(): array {
    if ($this->rewind === NULL) {
      return [
        'status' => RewindDetector::STATUS_NOT_CONFIGURED,
        'reason' => 'witness_not_configured',
        'digest' => NULL,
        'through_id' => NULL,
      ];
    }
    try {
      return $this->rewind->assess();
    }
    catch (\Throwable) {
      return [
        'status' => RewindDetector::STATUS_UNCHECKED,
        'reason' => RewindDetector::REASON_UNREACHABLE,
        'digest' => NULL,
        'through_id' => NULL,
      ];
    }
  }

  /**
   * Dispatches the failure event, then logs successor and presentation copy.
   *
   * The classify() method is the only classifier. Interval is forced above
   * zero and "now" is the run time so disabled/overdue/pending cannot mask
   * this run. Dispatch runs in try; successor-defect and presentation
   * logging run in finally so neither a throwing logger nor a throwing
   * subscriber can suppress the other. Those exceptions still propagate.
   *
   * @param array $run
   *   The recorded scheduled-verification run.
   */
  private function recordPresentation(array $run): void {
    $interval = (int) $this->configFactory->get('audit_chain.settings')->get('verify_interval');
    $now = (int) ($run['time'] ?? $this->time->getRequestTime());
    $classified = ScheduledVerificationIntegrity::classify(
      $run,
      max($interval, 1),
      $now,
    );
    $presented = ScheduledVerificationPresentation::forReason(
      $classified['reason'],
      ScheduledVerificationPresentation::contextFromRun($run, [
        // Type custom with DATE_ATOM does not load date-format config
        // entities. Type medium throws after persist when those are missing.
        'when' => $this->dates->format($now, 'custom', DATE_ATOM),
      ]),
    );
    try {
      if ($presented['dispatch']) {
        $this->eventDispatcher->dispatch(
          new AuditChainVerificationFailedEvent($run),
          AuditChainVerificationFailedEvent::EVENT_NAME,
        );
      }
    }
    finally {
      if ($run['successor'] !== NULL && !$run['successor']['segment_ok']) {
        $this->logger->error(
          'Audit successor verification FAILED: @reason. The historical exception remains unresolved.',
          ['@reason' => $run['successor']['reason']],
        );
      }
      if ($presented['log_level'] === 'error') {
        $this->logger->error((string) $presented['detail']);
      }
      elseif ($presented['log_level'] !== NULL) {
        $this->logger->warning((string) $presented['detail']);
      }
    }
  }

}
