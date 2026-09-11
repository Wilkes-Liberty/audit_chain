<?php

declare(strict_types=1);

namespace Drupal\Tests\audit_chain\Kernel;

use Drupal\audit_chain\AuditChainLogger;
use Drupal\audit_chain\AuditChainMetrics;
use Drupal\audit_chain\ScheduledVerifier;
use Drupal\KernelTests\KernelTestBase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Kernel tests for dashboard aggregates.
 *
 * @coversDefaultClass \Drupal\audit_chain\AuditChainMetrics
 *
 * @group audit_chain
 *
 * @runTestsInSeparateProcesses
 */
#[CoversClass(AuditChainMetrics::class)]
#[Group('audit_chain')]
#[RunTestsInSeparateProcesses]
final class AuditChainMetricsTest extends KernelTestBase {

  /**
   * {@inheritdoc}
   */
  protected static $modules = [
    'system',
    'user',
    'key',
    'encrypt',
    'encrypt_test',
    'audit_chain',
  ];

  /**
   * The metrics service.
   */
  private AuditChainMetrics $metrics;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installSchema('audit_chain', ['audit_chain_log']);
    $this->installConfig(['audit_chain']);
    $this->metrics = $this->container->get('audit_chain.metrics');
  }

  /**
   * Inserts a chain row with only the indexed columns the dashboard reads.
   *
   * @param array<string, mixed> $fields
   *   Overrides for channel, timestamp, uid, operation, or key_id.
   */
  private function insertRow(array $fields = []): void {
    $now = \Drupal::time()->getRequestTime();
    $this->container->get('database')->insert('audit_chain_log')->fields([
      'channel' => $fields['channel'] ?? 'personnel',
      'timestamp' => $fields['timestamp'] ?? ($now - 60),
      'uid' => $fields['uid'] ?? 1,
      'operation' => $fields['operation'] ?? 'field_read',
      'key_id' => array_key_exists('key_id', $fields) ? $fields['key_id'] : '',
    ])->execute();
  }

  /**
   * An unknown window key falls back to 24h.
   *
   * @covers ::normalizeWindow
   */
  public function testUnknownWindowFallsBackToDefault(): void {
    $this->assertSame('24h', $this->metrics->normalizeWindow('nope'));
    $this->assertSame('7d', $this->metrics->normalizeWindow('7d'));
  }

  /**
   * An empty table yields empty series and zero counts.
   *
   * @covers ::volumeTimeSeries
   * @covers ::windowCounts
   */
  public function testEmptyTableYieldsEmptySeries(): void {
    $this->assertSame([], $this->metrics->volumeTimeSeries('24h'));
    $this->assertSame([
      'total' => 0,
      'channels' => 0,
      'keyed' => 0,
      'unkeyed' => 0,
    ], $this->metrics->windowCounts('24h'));
  }

  /**
   * Volume, mix, and keyed split count only rows inside the window.
   *
   * @covers ::volumeTimeSeries
   * @covers ::channelMix
   * @covers ::operationMix
   * @covers ::keyedSplit
   * @covers ::windowCounts
   */
  public function testWindowBoundedAggregatesIgnoreOldRows(): void {
    $now = \Drupal::time()->getRequestTime();
    $this->insertRow([
      'channel' => 'personnel',
      'operation' => 'field_read',
      'timestamp' => $now - 60,
      'key_id' => 'hmac',
    ]);
    $this->insertRow([
      'channel' => 'personnel',
      'operation' => 'field_read',
      'timestamp' => $now - 90,
      'key_id' => '',
    ]);
    $this->insertRow([
      'channel' => 'mcp',
      'operation' => 'tool_call',
      'timestamp' => $now - 60,
      'key_id' => 'hmac',
    ]);
    // Outside the 24h window.
    $this->insertRow([
      'channel' => 'ancient',
      'operation' => 'field_read',
      'timestamp' => $now - 86400 * 40,
      'key_id' => 'hmac',
    ]);

    $counts = $this->metrics->windowCounts('24h');
    $this->assertSame(3, $counts['total']);
    $this->assertSame(2, $counts['channels']);
    $this->assertSame(2, $counts['keyed']);
    $this->assertSame(1, $counts['unkeyed']);

    $channels = $this->metrics->channelMix('24h');
    $this->assertSame(2, $channels['personnel']);
    $this->assertSame(1, $channels['mcp']);
    $this->assertArrayNotHasKey('ancient', $channels);

    $operations = $this->metrics->operationMix('24h');
    $this->assertSame(2, $operations['field_read']);
    $this->assertSame(1, $operations['tool_call']);

    $volume = $this->metrics->volumeTimeSeries('24h');
    $this->assertGreaterThan(0, array_sum($volume));
    $this->assertSame(3, array_sum($volume));
  }

  /**
   * Metadata, IP, and labels are not required for any aggregate.
   *
   * @covers ::channelMix
   */
  public function testAggregatesDoNotReadMetadata(): void {
    $this->insertRow(['channel' => 'personnel']);
    $mix = $this->metrics->channelMix('24h');
    $this->assertSame(['personnel' => 1], $mix);
  }

  /**
   * Integrity is "disabled" when no verification interval is configured.
   *
   * @covers ::integrity
   */
  public function testIntegrityDisabledWhenUnscheduled(): void {
    $this->insertRow();
    $disabled = $this->metrics->integrity();
    $this->assertSame('disabled', $disabled['reason']);
    $this->assertSame('warn', $disabled['status']);
    $this->assertSame(1, $disabled['rows']);
  }

  /**
   * A passing scheduled run is reported without walking the chain.
   *
   * @covers ::integrity
   */
  public function testIntegrityPassingWhenLastRunOk(): void {
    $this->insertRow();
    $this->config('audit_chain.settings')->set('verify_interval', 3600)->save();
    $this->container->get('state')->set(ScheduledVerifier::STATE_KEY, [
      'time' => \Drupal::time()->getRequestTime(),
      'ok' => TRUE,
      'reason' => NULL,
      'keyed' => TRUE,
      'verdict' => NULL,
    ]);
    $passing = $this->metrics->integrity();
    $this->assertSame('passing', $passing['reason']);
    $this->assertSame('ok', $passing['status']);
  }

  /**
   * A failed scheduled run surfaces as crit without walking the chain.
   *
   * @covers ::integrity
   */
  public function testIntegrityFailedRunIsCritical(): void {
    $this->config('audit_chain.settings')->set('verify_interval', 3600)->save();
    $this->container->get('state')->set(ScheduledVerifier::STATE_KEY, [
      'time' => \Drupal::time()->getRequestTime(),
      'ok' => FALSE,
      'reason' => AuditChainLogger::REASON_TAMPERED,
      'keyed' => TRUE,
      'verdict' => NULL,
    ]);
    $failed = $this->metrics->integrity();
    $this->assertSame('failed', $failed['reason']);
    $this->assertSame('crit', $failed['status']);
  }

}
