<?php

declare(strict_types=1);

namespace Drupal\Tests\audit_chain\Kernel;

use Drupal\audit_chain\AuditChainLogger;
use Drupal\audit_chain\AuditChainMetrics;
use Drupal\audit_chain\RewindDetector;
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
   * Classifier states live in one function.
   *
   * @covers ::classify
   * @covers ::isDocumentedHistoricalException
   */
  public function testClassifierStates(): void {
    $now = 1700000000;
    $passing = [
      'time' => $now - 60,
      'ok' => TRUE,
      'reason' => NULL,
    ];
    $documented = $this->documentedExceptionRun($now);
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
        $documented,
        3600,
        'historical_exception',
        'warn',
      ],
      [
        $this->documentedExceptionRun($now, [
          'successor' => ['segment_ok' => FALSE],
        ]),
        3600,
        'failed',
        'crit',
      ],
      [
        $this->documentedExceptionRun($now, [
          'verdict' => ['broken_at' => 99],
        ]),
        3600,
        'failed',
        'crit',
      ],
      [
        $this->documentedExceptionRun($now, [
          'successor' => ['segment_id' => ''],
        ]),
        3600,
        'failed',
        'crit',
      ],
      [
        $this->documentedExceptionRun($now, [
          'successor' => ['historical_ok' => TRUE],
        ]),
        3600,
        'failed',
        'crit',
      ],
      [
        [
          'time' => $now,
          'ok' => FALSE,
          'reason' => AuditChainLogger::REASON_WRITTEN_UNKEYED,
          'verdict' => ['unsigned_prefix' => TRUE],
        ],
        3600,
        'unsigned_prefix',
        'warn',
      ],
      [
        [
          'time' => $now,
          'ok' => FALSE,
          'reason' => AuditChainLogger::REASON_WRITTEN_UNKEYED,
          'verdict' => ['unsigned_prefix' => FALSE],
        ],
        3600,
        'failed',
        'crit',
      ],
      [
        [
          'time' => $now,
          'ok' => FALSE,
          'reason' => ScheduledVerifier::REASON_KEY_REQUIRED,
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
      [
        [
          'time' => $now,
          'ok' => FALSE,
          'reason' => RewindDetector::REASON_REWOUND,
          'rewind' => ['status' => RewindDetector::STATUS_REWOUND],
        ],
        3600,
        'chain_rewound',
        'crit',
      ],
      [
        [
          'time' => $now - 60,
          'ok' => TRUE,
          'reason' => NULL,
          'rewind' => ['status' => RewindDetector::STATUS_UNCHECKED],
        ],
        3600,
        'witness_unreachable',
        'warn',
      ],
      [
        [
          'time' => $now - 60,
          'ok' => TRUE,
          'reason' => NULL,
          'rewind' => [
            'status' => RewindDetector::STATUS_UNCHECKED,
            'reason' => RewindDetector::REASON_AMBIGUOUS,
          ],
        ],
        3600,
        'witness_ambiguous',
        'warn',
      ],
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
   * @covers ::isDocumentedHistoricalException
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
        'run' => $this->documentedExceptionRun($now),
      ],
      [
        'interval' => 3600,
        'require_keyed' => FALSE,
        'run' => $this->documentedExceptionRun($now, [
          'successor' => ['segment_ok' => FALSE],
        ]),
      ],
      [
        'interval' => 3600,
        'require_keyed' => FALSE,
        'run' => [
          'time' => $now,
          'ok' => FALSE,
          'reason' => AuditChainLogger::REASON_WRITTEN_UNKEYED,
          'verdict' => ['unsigned_prefix' => TRUE],
        ],
      ],
      [
        'interval' => 3600,
        'require_keyed' => TRUE,
        'run' => [
          'time' => $now,
          'ok' => FALSE,
          'reason' => ScheduledVerifier::REASON_KEY_REQUIRED,
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
      [
        'interval' => 3600,
        'require_keyed' => FALSE,
        'run' => [
          'time' => $now,
          'ok' => FALSE,
          'reason' => RewindDetector::REASON_REWOUND,
          'rewind' => ['status' => RewindDetector::STATUS_REWOUND],
        ],
      ],
      [
        'interval' => 3600,
        'require_keyed' => FALSE,
        'run' => [
          'time' => $now,
          'ok' => TRUE,
          'reason' => NULL,
          'rewind' => ['status' => RewindDetector::STATUS_UNCHECKED],
        ],
      ],
      [
        'interval' => 3600,
        'require_keyed' => FALSE,
        'run' => [
          'time' => $now,
          'ok' => TRUE,
          'reason' => NULL,
          'rewind' => [
            'status' => RewindDetector::STATUS_UNCHECKED,
            'reason' => RewindDetector::REASON_AMBIGUOUS,
          ],
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
      if ($classified['reason'] === 'historical_exception') {
        $value = (string) $requirements['audit_chain_scheduled_verification']['value'];
        $description = (string) $requirements['audit_chain_scheduled_verification']['description'];
        $this->assertStringContainsString('Documented historical exception at row 11425', $value);
        $this->assertStringContainsString('Audit Chain', $description);
        $this->assertStringContainsString('11425', $description);
        $this->assertStringContainsString('957345ba-a0c8-42d5-9dcb-92ba4430a820', $description);
        $this->assertStringContainsString('historical_ok=false', $description);
        $this->assertStringContainsString('segment_ok=true', $description);
        $this->assertStringContainsString('documented preserved failure', $description);
        $this->assertStringContainsString('drush audit-chain:verify', $description);
        $this->assertStringContainsString('recovery-verify', $description);
      }
    }
  }

  /**
   * Builds a disclosed historical-exception run, with optional overlays.
   *
   * @param int $now
   *   Stored run time.
   * @param array $overrides
   *   Shallow replacements. Nested successor/verdict keys are merged.
   *
   * @return array
   *   A scheduled-verification run record.
   */
  private function documentedExceptionRun(int $now, array $overrides = []): array {
    $run = [
      'time' => $now,
      'ok' => FALSE,
      'reason' => AuditChainLogger::REASON_TAMPERED,
      'verdict' => [
        'ok' => FALSE,
        'reason' => AuditChainLogger::REASON_TAMPERED,
        'broken_at' => 11425,
      ],
      'successor' => [
        'segment_ok' => TRUE,
        'historical_ok' => FALSE,
        'reason' => NULL,
        'segment_id' => '957345ba-a0c8-42d5-9dcb-92ba4430a820',
        'historical_verdict' => [
          'ok' => FALSE,
          'reason' => AuditChainLogger::REASON_TAMPERED,
          'broken_at' => 11425,
        ],
      ],
    ];
    foreach (['verdict', 'successor'] as $key) {
      if (isset($overrides[$key]) && is_array($overrides[$key])) {
        $run[$key] = array_replace($run[$key], $overrides[$key]);
        unset($overrides[$key]);
      }
    }
    return array_replace($run, $overrides);
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
