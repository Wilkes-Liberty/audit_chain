<?php

declare(strict_types=1);

namespace Drupal\audit_chain\Event;

use Symfony\Contracts\EventDispatcher\Event;

/**
 * Dispatched when a scheduled chain verification fails.
 *
 * The alert contract for consumers (d.o #3616535): Audit Chain records the
 * durable failure state and logs the error itself; this event is how a
 * consumer binds its own alerting — webhooks, email, dashboards — to an
 * integrity failure without Audit Chain owning those channels. Dispatched
 * only on failure; a healthy run updates state silently.
 */
final class AuditChainVerificationFailedEvent extends Event {

  public const EVENT_NAME = 'audit_chain.verification_failed';

  /**
   * Constructs the event.
   *
   * @param array $run
   *   The recorded run: time, ok (FALSE here), reason, and — when the
   *   verification executed — the full verify() verdict under 'verdict'.
   */
  public function __construct(
    public readonly array $run,
  ) {}

}
