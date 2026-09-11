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
   * An empty table yields zero keyed/unkeyed counts.
   *
   * @covers ::windowCounts
   */
  public function testEmptyTableYieldsZeroCounts(): void {
    $this->assertSame([
      'total' => 0,
      'keyed' => 0,
      'unkeyed' => 0,
    ], $this->metrics->windowCounts('24h'));
  }

  /**
   * Keyed split counts only rows inside the window.
   *
   * @covers ::keyedSplit
   * @covers ::windowCounts
   */
  public function testWindowBoundedKeyedSplitIgnoresOldRows(): void {
    $now = \Drupal::time()->getRequestTime();
    $this->insertRow([
      'timestamp' => $now - 60,
      'key_id' => 'hmac',
    ]);
    $this->insertRow([
      'timestamp' => $now - 90,
      'key_id' => '',
    ]);
    $this->insertRow([
      'timestamp' => $now - 60,
      'key_id' => 'hmac',
    ]);
    // Outside the 24h window.
    $this->insertRow([
      'timestamp' => $now - 86400 * 40,
      'key_id' => 'hmac',
    ]);

    $counts = $this->metrics->windowCounts('24h');
    $this->assertSame(3, $counts['total']);
    $this->assertSame(2, $counts['keyed']);
    $this->assertSame(1, $counts['unkeyed']);
  }

  /**
   * Metadata, IP, and labels are not required for the keyed split.
   *
   * @covers ::keyedSplit
   */
  public function testAggregatesDoNotReadMetadata(): void {
    $this->insertRow(['key_id' => 'hmac']);
    $this->assertSame(['keyed' => 1, 'unkeyed' => 0], $this->metrics->keyedSplit('24h'));
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
