<?php

declare(strict_types=1);

namespace Drupal\Tests\audit_chain\Kernel;

use Drupal\audit_chain\AuditChainLogger;
use Drupal\audit_chain\AuditChainMetrics;
use Drupal\audit_chain\Controller\AuditChainDashboardController;
use Drupal\audit_chain\RewindDetector;
use Drupal\audit_chain\ScheduledVerificationIntegrity;
use Drupal\audit_chain\ScheduledVerificationPresentation;
use Drupal\audit_chain\ScheduledVerifier;
use Drupal\KernelTests\KernelTestBase;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use Symfony\Component\HttpFoundation\Request;

/**
 * Shared scheduled-verification integrity classifier.
 *
 * @coversDefaultClass \Drupal\audit_chain\ScheduledVerificationIntegrity
 *
 * @group audit_chain
 */
#[CoversClass(ScheduledVerificationIntegrity::class)]
#[Group('audit_chain')]
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
   * Metrics snapshot, integrity(), and hook_requirements share classify().
   *
   * @covers ::classify
   * @covers ::isDocumentedHistoricalException
   * @covers \Drupal\audit_chain\ScheduledVerificationPresentation::snapshot
   * @covers \Drupal\audit_chain\AuditChainMetrics::snapshot
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
      $metrics = $this->freshMetrics();
      $snapshot = $metrics->snapshot();
      $integrity = $metrics->integrity();
      $this->assertSame($classified, $snapshot['classified'], "snapshot case $index");
      $this->assertSame($classified['reason'], $integrity['reason'], "metrics reason case $index");
      $this->assertSame($classified['status'], $integrity['status'], "metrics status case $index");
      $this->assertSame($classified['time'], $integrity['time'], "metrics time case $index");
      $this->assertSame($snapshot['rows'], $integrity['rows'], "integrity projects snapshot rows case $index");

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
        $this->assertStringContainsString('Historical exception', $value);
        $this->assertStringContainsString('Documented historical exception at row 11425', $description);
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
   * Pending and passing status-report copy use the live row count.
   *
   * @covers \Drupal\audit_chain\ScheduledVerificationPresentation::contextFromRun
   */
  public function testPendingAndPassingStatusReportUseLiveRowCount(): void {
    $now = \Drupal::time()->getRequestTime();
    for ($i = 0; $i < 3; $i++) {
      $this->container->get('database')->insert('audit_chain_log')->fields([
        'channel' => 'personnel',
        'timestamp' => $now - 60,
        'uid' => 1,
        'operation' => 'field_read',
        'key_id' => '',
      ])->execute();
    }
    $this->config('audit_chain.settings')->set('verify_interval', 3600)->save();

    $cases = [
      'pending' => NULL,
      'passing' => [
        'time' => $now,
        'ok' => TRUE,
        'reason' => NULL,
      ],
    ];
    foreach ($cases as $reason => $run) {
      if ($run === NULL) {
        $this->container->get('state')->delete(ScheduledVerifier::STATE_KEY);
      }
      else {
        $this->container->get('state')->set(ScheduledVerifier::STATE_KEY, $run);
      }
      // Fresh metrics: AuditChainMetrics caches per request.
      $this->container->set('audit_chain.metrics', $this->freshMetrics());

      $integrity = $this->freshMetrics()->integrity();
      $this->assertSame($reason, $integrity['reason'], $reason);
      $this->assertSame(3, $integrity['rows'], $reason);

      $request = Request::create('/admin/reports/audit-chain');
      $controller = AuditChainDashboardController::create($this->container);
      $build = $controller->dashboard($request);
      \Drupal::moduleHandler()->loadInclude('audit_chain', 'install');
      $requirements = audit_chain_requirements('runtime');

      $this->assertArrayHasKey('audit_chain_scheduled_verification', $requirements, $reason);
      $description = (string) $requirements['audit_chain_scheduled_verification']['description'];
      $this->assertStringContainsString('3 rows', $description, $reason);
      $this->assertSame($build['#chain']['detail'], $description, $reason);
    }
  }

  /**
   * An unknown reason is not pending and does not throw on the status report.
   *
   * @covers \Drupal\audit_chain\ScheduledVerificationPresentation::forReason
   */
  public function testUnknownReasonIsNotPendingAndDoesNotThrow(): void {
    $presented = ScheduledVerificationPresentation::forReason('mystery_future_reason', [
      'rows' => 3,
    ]);
    $this->assertSame('warn', $presented['severity']);
    $this->assertFalse($presented['omit']);
    $this->assertFalse($presented['dispatch']);
    $this->assertSame('warning', $presented['log_level']);
    $label = (string) $presented['label'];
    $detail = (string) $presented['detail'];
    $this->assertSame('Unrecognized verification state', $label);
    $this->assertStringNotContainsString('Pending', $label);
    $this->assertStringNotContainsString('No scheduled verification has run yet', $detail);
    $this->assertStringContainsString('mystery_future_reason', $detail);

    $pending = ScheduledVerificationPresentation::forReason('pending', ['rows' => 3]);
    $this->assertSame('Pending', (string) $pending['label']);
    $this->assertStringContainsString('No scheduled verification has run yet', (string) $pending['detail']);

    \Drupal::moduleHandler()->loadInclude('audit_chain', 'install');
    $requirement = _audit_chain_scheduled_verification_requirement([
      'presented' => $presented,
      'when' => NULL,
    ]);
    $this->assertIsArray($requirement);
    $this->assertSame(REQUIREMENT_WARNING, $requirement['severity']);
    $this->assertStringContainsString('Unrecognized verification state', (string) $requirement['value']);
    $this->assertStringNotContainsString('Pending', (string) $requirement['value']);
    $this->assertStringNotContainsString('No scheduled verification has run yet', (string) $requirement['description']);
    $this->assertStringNotContainsString('Enabled, but no run recorded yet', (string) $requirement['value']);
  }

  /**
   * Every classified reason has a named card, not the unknown fallback.
   *
   * @covers \Drupal\audit_chain\ScheduledVerificationPresentation::forReason
   */
  public function testClassifiedReasonsAreNotTheUnknownCard(): void {
    $reasons = [
      'disabled',
      'pending',
      'seal_foreign',
      'unsigned_prefix',
      'historical_exception',
      'failed',
      'chain_rewound',
      'witness_unreachable',
      'witness_ambiguous',
      'overdue',
      'passing',
    ];
    foreach ($reasons as $reason) {
      $presented = ScheduledVerificationPresentation::forReason($reason);
      $this->assertNotSame(
        'Unrecognized verification state',
        (string) $presented['label'],
        $reason,
      );
    }
  }

  /**
   * Run-context assembly unpacks successor, verdict, historical, and rewind.
   *
   * @covers \Drupal\audit_chain\ScheduledVerificationPresentation::contextFromRun
   */
  public function testContextFromRunAssemblesSuccessorVerdictAndRewind(): void {
    $run = $this->documentedExceptionRun(1700000000);
    $run['rewind'] = ['through_id' => 42];
    $context = ScheduledVerificationPresentation::contextFromRun($run, [
      'rows' => 9,
      'when' => 'formatted',
      'require_keyed' => TRUE,
    ]);

    $this->assertSame(AuditChainLogger::REASON_TAMPERED, $context['run_reason']);
    $this->assertSame(11425, $context['broken_at']);
    $this->assertSame('957345ba-a0c8-42d5-9dcb-92ba4430a820', $context['segment_id']);
    $this->assertFalse($context['historical_ok']);
    $this->assertTrue($context['segment_ok']);
    $this->assertSame(42, $context['rewind_through_id']);
    $this->assertSame(9, $context['rows']);
    $this->assertSame('formatted', $context['when']);
    $this->assertTrue($context['require_keyed']);

    $empty = ScheduledVerificationPresentation::contextFromRun([]);
    $this->assertSame('', $empty['run_reason']);
    $this->assertNull($empty['broken_at']);
    $this->assertNull($empty['segment_id']);
    $this->assertFalse($empty['historical_ok']);
    $this->assertFalse($empty['segment_ok']);
    $this->assertNull($empty['rewind_through_id']);

    $run['verdict']['broken_at'] = 7;
    $preferVerdict = ScheduledVerificationPresentation::contextFromRun($run);
    $this->assertSame(7, $preferVerdict['broken_at']);
  }

  /**
   * One snapshot feeds status report, dashboard, and DATE_ATOM verifier copy.
   *
   * @covers \Drupal\audit_chain\ScheduledVerificationPresentation::snapshot
   * @covers \Drupal\audit_chain\AuditChainMetrics::snapshot
   */
  public function testSnapshotAssemblesClassifiedRowsRunAndWhen(): void {
    $now = \Drupal::time()->getRequestTime();
    for ($i = 0; $i < 2; $i++) {
      $this->container->get('database')->insert('audit_chain_log')->fields([
        'channel' => 'personnel',
        'timestamp' => $now - 60,
        'uid' => 1,
        'operation' => 'field_read',
        'key_id' => '',
      ])->execute();
    }
    $this->config('audit_chain.settings')->set('verify_interval', 3600)->save();
    $run = [
      'time' => $now,
      'ok' => TRUE,
      'reason' => NULL,
    ];
    $this->container->get('state')->set(ScheduledVerifier::STATE_KEY, $run);

    $dates = $this->container->get('date.formatter');
    $when = $dates->format($now);
    $atom = $dates->format($now, 'custom', DATE_ATOM);
    $snapshot = $this->freshMetrics()->snapshot(
      fn (int $time): string => $dates->format($time),
    );
    $classified = ScheduledVerificationIntegrity::classify($run, 3600, $now);

    $this->assertSame($classified, $snapshot['classified']);
    $this->assertSame(2, $snapshot['rows']);
    $this->assertSame($run, $snapshot['run']);
    $this->assertSame($when, $snapshot['when']);
    $this->assertSame($when, $snapshot['context']['when']);
    $this->assertSame(
      (string) ScheduledVerificationPresentation::forReason(
        $classified['reason'],
        $snapshot['context'],
      )['detail'],
      (string) $snapshot['presented']['detail'],
    );

    $request = Request::create('/admin/reports/audit-chain');
    $controller = AuditChainDashboardController::create($this->container);
    $build = $controller->dashboard($request);
    $this->assertSame(
      (string) $snapshot['presented']['label'],
      $build['#chain']['label'],
    );
    $this->assertSame(
      (string) $snapshot['presented']['detail'],
      $build['#chain']['detail'],
    );
    $this->assertSame($snapshot['presented']['severity'], $build['#chain']['state']);

    \Drupal::moduleHandler()->loadInclude('audit_chain', 'install');
    $requirements = audit_chain_requirements('runtime');
    $this->assertSame(
      (string) $snapshot['presented']['detail'],
      (string) $requirements['audit_chain_scheduled_verification']['description'],
    );

    $verifierSnapshot = ScheduledVerificationPresentation::snapshot(
      $run,
      3600,
      $now,
      ['when' => $atom],
    );
    $this->assertSame($atom, $verifierSnapshot['when']);
    $this->assertStringContainsString(
      $atom,
      (string) $verifierSnapshot['presented']['detail'],
    );
    $this->assertStringNotContainsString(
      'unknown',
      (string) $verifierSnapshot['presented']['detail'],
    );
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
