<?php

declare(strict_types=1);

namespace Drupal\audit_chain\EventSubscriber;

use Drupal\audit_chain\AuditChainCollector;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * Writes collected audit entries once the response has been sent.
 *
 * `kernel.terminate` rather than `kernel.response`: the entries describe what
 * the request did, so nothing downstream needs them, and writing after the
 * response keeps the chain lock off the user's critical path. The lock
 * serialises appends across the whole site, so holding it mid-request would
 * make concurrent requests wait on each other for work none of them needs.
 */
final class AuditChainFlushSubscriber implements EventSubscriberInterface {

  /**
   * Constructs an AuditChainFlushSubscriber.
   *
   * @param \Drupal\audit_chain\AuditChainCollector $collector
   *   The request-scoped collector to drain.
   */
  public function __construct(
    private readonly AuditChainCollector $collector,
  ) {}

  /**
   * Flushes anything collected during this request.
   */
  public function onTerminate(): void {
    $this->collector->flush();
  }

  /**
   * {@inheritdoc}
   */
  public static function getSubscribedEvents(): array {
    return [KernelEvents::TERMINATE => ['onTerminate', 0]];
  }

}
