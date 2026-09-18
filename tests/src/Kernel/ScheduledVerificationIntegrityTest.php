<?php

declare(strict_types=1);

namespace Drupal\Tests\audit_chain\Kernel;

use Drupal\audit_chain\AuditChainLogger;
use Drupal\audit_chain\AuditChainMetrics;
use Drupal\audit_chain\ScheduledVerificationIntegrity;
use Drupal\audit_chain\ScheduledVerifier;
use Drupal\KernelTests\KernelTestBase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Shared scheduled-verification integrity classifier.
 *
 * @coversDefaultClass \Drupal\audit_chain\ScheduledVerificationIntegrity
 *
 * @group audit_chain
 *
 * @runTestsInSeparateProcesses
 */
#[CoversClass(ScheduledVerificationIntegrity::class)]
#[Group('audit_chain')]
#[RunTestsInSeparateProcesses]
final class ScheduledVerificationIntegrityTest extends KernelTestBase {

  use AuditChainSchemaTrait;

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
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installAuditChainTables();
    $this->installConfig(['system', 'audit_chain']);
  }

  /**
   * The six mirrored states live in one function.
   *
   * @covers ::classify
   */
  public function testClassifierStates(): void {
    $now = 1700000000;
    $passing = [
      'time' => $now - 60,
      'ok' => TRUE,
      'reason' => NULL,
    ];
    $cases = [
      [NULL, 0, 'disabled', 'warn'],
      [$passing, 0, 'disabled', 'warn'],
      [NULL, 3600, 'pending', 'warn'],
      [
        [
          'time' => $now,
          'ok' => FALSE,
          'reason' => AuditChainLogger::REASON_SEAL_FOREIGN,
        ],
        3600,
        'seal_foreign',
        'warn',
      ],
      [
        [
          'time' => $now,
          'ok' => FALSE,
          'reason' => AuditChainLogger::REASON_TAMPERED,
        ],
        3600,
        'failed',
        'crit',
      ],
      [
        [
          'time' => $now - 7300,
          'ok' => TRUE,
          'reason' => NULL,
        ],
        3600,
        'overdue',
        'warn',
      ],
      [$passing, 3600, 'passing', 'ok'],
    ];

    foreach ($cases as $case) {
      [$run, $interval, $reason, $status] = $case;
      $classified = ScheduledVerificationIntegrity::classify($run, $interval, $now);
      $this->assertSame($reason, $classified['reason']);
      $this->assertSame($status, $classified['status']);
    }
  }

  /**
   * Metrics and hook_requirements both consume the shared classifier.
   *
   * @covers ::classify
   */
  public function testSurfacesShareClassifier(): void {
    $now = \Drupal::time()->getRequestTime();
    $cases = [
      [
        'interval' => 0,
        'require_keyed' => FALSE,
        'run' => NULL,
      ],
      [
        'interval' => 0,
        'require_keyed' => TRUE,
        'run' => NULL,
      ],
      [
        'interval' => 3600,
        'require_keyed' => FALSE,
        'run' => NULL,
      ],
      [
        'interval' => 3600,
        'require_keyed' => FALSE,
        'run' => [
          'time' => $now,
          'ok' => FALSE,
          'reason' => AuditChainLogger::REASON_SEAL_FOREIGN,
        ],
      ],
      [
        'interval' => 3600,
        'require_keyed' => FALSE,
        'run' => [
          'time' => $now,
          'ok' => FALSE,
          'reason' => AuditChainLogger::REASON_TAMPERED,
        ],
      ],
      [
        'interval' => 3600,
        'require_keyed' => FALSE,
        'run' => [
          'time' => $now - 7300,
          'ok' => TRUE,
          'reason' => NULL,
        ],
      ],
      [
        'interval' => 3600,
        'require_keyed' => FALSE,
        'run' => [
          'time' => $now,
          'ok' => TRUE,
          'reason' => NULL,
        ],
      ],
    ];

    foreach ($cases as $index => $case) {
      $this->config('audit_chain.settings')
        ->set('verify_interval', $case['interval'])
        ->set('verify_require_keyed', $case['require_keyed'])
        ->save();
      if ($case['run'] === NULL) {
        $this->container->get('state')->delete(ScheduledVerifier::STATE_KEY);
      }
      else {
        $this->container->get('state')->set(ScheduledVerifier::STATE_KEY, $case['run']);
      }

      $classified = ScheduledVerificationIntegrity::classify(
        $case['run'],
        $case['interval'],
        $now,
      );
      // Fresh instance: AuditChainMetrics caches per request.
      $integrity = $this->freshMetrics()->integrity();
      $this->assertSame($classified['reason'], $integrity['reason'], "metrics reason case $index");
      $this->assertSame($classified['status'], $integrity['status'], "metrics status case $index");
      $this->assertSame($classified['time'], $integrity['time'], "metrics time case $index");

      \Drupal::moduleHandler()->loadInclude('audit_chain', 'install');
      $requirements = audit_chain_requirements('runtime');
      if ($classified['reason'] === 'disabled' && !$case['require_keyed']) {
        $this->assertArrayNotHasKey(
          'audit_chain_scheduled_verification',
          $requirements,
          "silent disabled case $index",
        );
        continue;
      }
      $expected = match ($classified['status']) {
        'ok' => REQUIREMENT_OK,
        'crit' => REQUIREMENT_ERROR,
        'warn' => REQUIREMENT_WARNING,
        default => throw new \InvalidArgumentException('Unknown integrity status: ' . $classified['status']),
      };
      $this->assertArrayHasKey('audit_chain_scheduled_verification', $requirements);
      $this->assertSame(
        $expected,
        $requirements['audit_chain_scheduled_verification']['severity'],
        "requirements case $index",
      );
    }
  }

  /**
   * Builds an uncached metrics service.
   */
  private function freshMetrics(): AuditChainMetrics {
    return new AuditChainMetrics(
      $this->container->get('database'),
      $this->container->get('datetime.time'),
      $this->container->get('state'),
      $this->container->get('config.factory'),
      $this->container->get('logger.channel.audit_chain'),
    );
  }

}
