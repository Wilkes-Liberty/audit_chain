<?php

declare(strict_types=1);

namespace Drupal\audit_chain;

use Drupal\Core\DependencyInjection\ContainerBuilder;
use Drupal\Core\DependencyInjection\ServiceProviderBase;
use Symfony\Component\DependencyInjection\Reference;

/**
 * Wires the SIEM stream to every logger backend except Database Logging.
 *
 * The stream_enabled setting used to call logger.channel.audit_chain, which
 * Drupal fans out to every service tagged `logger` — including
 * logger.dblog. That is why admin/reports/dblog filled with
 * audit_chain_event rows. The stream service is a narrow channel: same
 * message template and context a SIEM already keys on, but never the
 * dblog backend. Errors and warnings stay on logger.channel.audit_chain
 * so they remain visible in Recent log messages.
 */
final class AuditChainServiceProvider extends ServiceProviderBase {

  /**
   * Service id of Drupal's Database Logging backend.
   */
  private const DBLOG_SERVICE_ID = 'logger.dblog';

  /**
   * Class of Drupal's Database Logging backend.
   *
   * Matched by name so this pass does not autoload dblog when the module is
   * not installed.
   */
  private const DBLOG_CLASS = 'Drupal\dblog\Logger\DbLog';

  /**
   * {@inheritdoc}
   */
  public function alter(ContainerBuilder $container): void {
    if (!$container->hasDefinition('audit_chain.stream')) {
      return;
    }

    $stream = $container->getDefinition('audit_chain.stream');
    $attached = 0;
    foreach ($container->findTaggedServiceIds('logger') as $id => $tags) {
      if ($this->isDatabaseLogBackend($container, $id)) {
        // The whole point of this pass: high-volume appends must not land
        // in {watchdog}. Other backends (syslog, Monolog, …) stay attached
        // so existing SIEM rules keep matching.
        continue;
      }
      $priority = $tags[0]['priority'] ?? 0;
      $stream->addMethodCall('addLogger', [new Reference($id), $priority]);
      $attached++;
    }

    // A site with only dblog still has stream_enabled as a real switch, not
    // a silent no-op. PHP syslog is the fallback; it is not tagged `logger`
    // so it never fans out to every Drupal channel.
    if ($attached === 0 && $container->hasDefinition('audit_chain.stream_syslog')) {
      $stream->addMethodCall('addLogger', [new Reference('audit_chain.stream_syslog'), 0]);
    }
  }

  /**
   * Whether a tagged logger is Database Logging (by id or class).
   *
   * @param \Drupal\Core\DependencyInjection\ContainerBuilder $container
   *   The container being compiled.
   * @param string $id
   *   The tagged logger service id.
   *
   * @return bool
   *   TRUE when this backend writes to {watchdog}.
   */
  private function isDatabaseLogBackend(ContainerBuilder $container, string $id): bool {
    if ($id === self::DBLOG_SERVICE_ID) {
      return TRUE;
    }
    if (!$container->hasDefinition($id)) {
      return FALSE;
    }
    return $container->getDefinition($id)->getClass() === self::DBLOG_CLASS;
  }

}
