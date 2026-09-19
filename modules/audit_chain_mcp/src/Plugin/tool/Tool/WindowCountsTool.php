<?php

declare(strict_types=1);

namespace Drupal\audit_chain_mcp\Plugin\tool\Tool;

use Drupal\audit_chain\AuditChainMetrics;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\tool\Attribute\Tool;
use Drupal\tool\Tool\ToolOperation;
use Drupal\tool\TypedData\InputDefinition;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Counts keyed and unkeyed entries per window.
 */
#[Tool(
  id: 'audit_chain_window_counts',
  label: new TranslatableMarkup('Audit Chain window counts'),
  description: new TranslatableMarkup('Count chain entries written in the last 24 hours, 7 days or 30 days, split into keyed (HMAC-signed) and unkeyed. Unkeyed entries on a site with a signing key mean the key was missing when they were written. Omit the window to get all three. Counts only; no rows are read. The counts come from the dashboard metrics service, which logs a failed query and reports zero for it, so zero on a busy site is a reason to read the log.'),
  operation: ToolOperation::Read,
  input_definitions: [
    'window' => new InputDefinition(
      data_type: 'string',
      label: new TranslatableMarkup('Window'),
      description: new TranslatableMarkup('One of 24h, 7d or 30d. Omit for all three.'),
      required: FALSE,
      constraints: ['Choice' => ['choices' => ['24h', '7d', '30d']]],
    ),
  ],
)]
final class WindowCountsTool extends AuditChainToolBase {

  /**
   * Dashboard metrics.
   */
  protected AuditChainMetrics $metrics;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->metrics = $container->get('audit_chain.metrics');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  protected function run(array $values): array {
    $allowed = AuditChainMetrics::windows();
    $window = $values['window'] ?? NULL;
    // The metrics service maps an unknown window to 24h. Refuse instead, so a
    // caller never reads one window's counts under another window's name.
    if ($window !== NULL && !in_array($window, $allowed, TRUE)) {
      throw new \InvalidArgumentException('Unknown window.');
    }
    $windows = [];
    foreach ($window === NULL ? $allowed : [$window] as $key) {
      $counts = $this->metrics->windowCounts($key);
      $windows[$key] = [
        'total' => (int) $counts['total'],
        'keyed' => (int) $counts['keyed'],
        'unkeyed' => (int) $counts['unkeyed'],
      ];
    }
    return ['windows' => $windows];
  }

}
