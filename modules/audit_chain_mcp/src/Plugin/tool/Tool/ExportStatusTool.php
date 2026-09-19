<?php

declare(strict_types=1);

namespace Drupal\audit_chain_mcp\Plugin\tool\Tool;

use Drupal\audit_chain\EvidenceExporter;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\StringTranslation\TranslatableMarkup;
use Drupal\tool\Attribute\Tool;
use Drupal\tool\Tool\ToolOperation;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Reports whether the evidence export is behind.
 */
#[Tool(
  id: 'audit_chain_export_status',
  label: new TranslatableMarkup('Audit Chain export status'),
  description: new TranslatableMarkup('Report the configured off-system evidence export: whether cron export is enabled, the last row id delivered and when, and how many entries are waiting beyond that checkpoint. The destination is reported as its kind and, for a URL, its host only: no path, port, credentials or query string. Does not export anything and cannot change the destination.'),
  operation: ToolOperation::Read,
  input_definitions: [],
)]
final class ExportStatusTool extends AuditChainToolBase {

  /**
   * Evidence exporter.
   */
  protected EvidenceExporter $exporter;

  /**
   * Config factory.
   */
  protected ConfigFactoryInterface $configFactory;

  /**
   * {@inheritdoc}
   */
  public static function create(ContainerInterface $container, array $configuration, $plugin_id, $plugin_definition) {
    $instance = parent::create($container, $configuration, $plugin_id, $plugin_definition);
    $instance->exporter = $container->get('audit_chain.evidence_exporter');
    $instance->configFactory = $container->get('config.factory');
    return $instance;
  }

  /**
   * {@inheritdoc}
   */
  protected function run(array $values): array {
    $config = $this->configFactory->get('audit_chain.settings');
    $destination = (string) $config->get('export_destination');
    $channel = (string) $config->get('export_channel');
    $status = [
      'enabled' => (bool) $config->get('export_enabled'),
      'configured' => $destination !== '',
      'destination' => NULL,
      // A channel is a consumer's machine name. Anything else configured here
      // is reported as filtered without being repeated.
      'channel_filtered' => $channel !== '',
      'channel' => preg_match('/^[a-z0-9_]{1,64}$/D', $channel) ? $channel : NULL,
      'checkpoint' => NULL,
      'waiting' => NULL,
    ];
    if ($destination === '') {
      return $status;
    }
    $checkpoint = $this->exporter->checkpointStatus($destination, $channel === '' ? NULL : $channel);
    $status['destination'] = self::destinationLabel($destination);
    $status['checkpoint'] = [
      'last_id' => $checkpoint['last_id'],
      'time' => $checkpoint['time'],
    ];
    $status['waiting'] = $checkpoint['remaining'];
    return $status;
  }

  /**
   * Describes a destination by kind and host only.
   *
   * The module's own redaction runs first and drops userinfo and the query
   * string. Its output still carries the path and port, and ingest services
   * put tokens in paths, so only the scheme and host are kept. A file
   * destination is reported by kind: a filesystem path is not for a result.
   *
   * @return array{kind: string, host: string|null}
   *   The kind (https, http, file or unparseable) and, for a URL, the host.
   */
  private static function destinationLabel(string $destination): array {
    $redacted = EvidenceExporter::redactDestination($destination);
    foreach (['https', 'http'] as $scheme) {
      if (str_starts_with($redacted, $scheme . '://')) {
        $host = parse_url($redacted, PHP_URL_HOST);
        return is_string($host) && preg_match('/^[A-Za-z0-9.\-\[\]:]{1,253}$/D', $host)
          ? ['kind' => $scheme, 'host' => strtolower($host)]
          : ['kind' => 'unparseable', 'host' => NULL];
      }
    }
    return [
      'kind' => str_starts_with($destination, 'http') ? 'unparseable' : 'file',
      'host' => NULL,
    ];
  }

}
