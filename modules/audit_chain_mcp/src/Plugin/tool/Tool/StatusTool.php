<?php

declare(strict_types=1);

namespace Drupal\audit_chain_mcp\Plugin\tool\Tool;

use Drupal\audit_chain\AuditChainLoggerInterface;
use Drupal\audit_chain\AuditChainMetrics;
use Drupal\audit_chain\ScheduledVerifier;
use Drupal\Core\State\StateInterface;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\tool\Attribute\Tool;
use Drupal\tool\Tool\ToolOperation;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Reports whether the audit chain is healthy.
 */
#[Tool(
  id: 'audit_chain_status',
  label: new TranslatableMarkup('Audit Chain status'),
  description: new TranslatableMarkup('Report chain health from stored state: how the last scheduled verification classifies (ok, warn or crit) and when it ran, the last verdict, whether new entries are signed, how far the prefix seal reaches, and the recovery successor status. Does not walk the chain. Returns no rows, metadata, hashes, seal MAC, prefix digest, key identifier or seal reason.'),
  operation: ToolOperation::Read,
  input_definitions: [],
)]
final class StatusTool extends AuditChainToolBase {

  /**
   * Dashboard metrics.
   */
  protected AuditChainMetrics $metrics;

  /**
   * Chain logger.
   */
  protected AuditChainLoggerInterface $chain;

  /**
   * State, for the last recorded run.
   */
  protected StateInterface $state;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->metrics = $container->get('audit_chain.metrics');
    $instance->chain = $container->get('audit_chain.logger');
    $instance->state = $container->get('state');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  protected function run(array $values): array {
    $integrity = $this->metrics->integrity();
    $seal = $this->chain->getSeal();
    return [
      'verification' => [
        'status' => (string) $integrity['status'],
        'reason' => (string) $integrity['reason'],
        'last_run_time' => $integrity['time'] === NULL ? NULL : (int) $integrity['time'],
        'rows' => (int) $integrity['rows'],
      ],
      'last_run' => $this->verdictFields($this->state->get(ScheduledVerifier::STATE_KEY)),
      // The key identifier stays out: it names the secret to go after.
      'signing' => ['keyed' => $this->chain->signingStatus()['keyed'] === TRUE],
      'seal' => $seal === NULL ? NULL : [
        'sealed_through_id' => (int) $seal['sealed_through_id'],
        'row_count' => (int) $seal['row_count'],
        'sealed_at' => (int) $seal['timestamp'],
      ],
      'recovery' => $this->successorFields($this->metrics->recoveryStatus()),
    ];
  }

}
