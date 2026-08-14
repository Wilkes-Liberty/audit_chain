<?php

declare(strict_types=1);

namespace Drupal\audit_chain;

use Drupal\audit_chain\Event\AuditChainVerificationFailedEvent;
use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\State\StateInterface;
use Psr\Log\LoggerInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

/**
 * Runs chain verification on a schedule and records its health durably.
 *
 * Keyed chain integrity is valuable only when verification is routinely
 * executed and a failure leaves the writer's trust boundary (d.o #3616535).
 * Cron drives this service; each due run verifies the whole chain, stores the
 * verdict in state (the status report renders it as health), logs a failure
 * through the audit_chain channel (SIEM-forwardable), and dispatches
 * AuditChainVerificationFailedEvent so consumers can bind their own alerting.
 * Verification is strictly read-only: a failing chain is never rewritten.
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
    if (is_array($last) && $this->time->getRequestTime() < ((int) $last['time'] + $interval)) {
      return NULL;
    }
    return $this->runNow();
  }

  /**
   * Runs the verification immediately and records the outcome.
   *
   * @return array
   *   The recorded run: time, ok, reason, keyed, and (when the verification
   *   executed) the full verify() verdict under 'verdict'.
   */
  public function runNow(): array {
    $settings = $this->configFactory->get('audit_chain.settings');
    $requireKeyed = (bool) $settings->get('verify_require_keyed');
    $keyConfigured = (string) ($settings->get('hash_key') ?? '') !== '';

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

    $this->state->set(self::STATE_KEY, $run);

    if (!$run['ok']) {
      $this->logger->error(
        'Scheduled audit-chain verification FAILED: @reason. The chain was not modified; investigate before trusting new entries. See the status report for details.',
        ['@reason' => (string) $run['reason']]
      );
      $this->eventDispatcher->dispatch(
        new AuditChainVerificationFailedEvent($run),
        AuditChainVerificationFailedEvent::EVENT_NAME
      );
    }

    return $run;
  }

}
