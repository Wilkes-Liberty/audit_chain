<?php

declare(strict_types=1);

namespace Drupal\Tests\audit_chain\Kernel;

use Drupal\audit_chain\AuditChainLogger;
use Drupal\audit_chain\Event\AuditChainVerificationFailedEvent;
use Drupal\KernelTests\KernelTestBase;
use Drupal\key\Entity\Key;
use Psr\Log\AbstractLogger;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Kernel tests for scheduled keyed verification (d.o #3616535, part 1).
 *
 * Keyed chain integrity is valuable only when verification runs routinely and
 * a failure leaves the writer's trust boundary. The contract under test:
 * cron-scheduled verification honors its interval, the enterprise assurance
 * profile rejects unkeyed operation, an integrity failure records a durable
 * non-success health state, alerts through the logger channel, dispatches an
 * event for consumers — and never rewrites the chain it verified.
 *
 * @group audit_chain
 *
 * @runTestsInSeparateProcesses
 */
#[Group('audit_chain')]
#[RunTestsInSeparateProcesses]
final class AuditChainScheduledVerifierTest extends KernelTestBase {

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
    $this->installSchema('audit_chain', ['audit_chain_log']);
    // The system date formats back the date.formatter calls the status-report
    // requirement makes when rendering run times.
    $this->installConfig(['system', 'audit_chain']);
  }

  /**
   * Creates a config-provider Key entity holding an HMAC secret.
   */
  private function makeKey(string $id, string $value = 'test-secret-value'): void {
    Key::create([
      'id' => $id,
      'label' => $id,
      'key_type' => 'authentication',
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => $value],
    ])->save();
  }

  /**
   * Runs the module's cron hook the way core cron would.
   */
  private function runCron(): void {
    \Drupal::moduleHandler()->invoke('audit_chain', 'cron');
  }

  /**
   * The stored scheduled-verification run record, or NULL.
   */
  private function lastRun(): ?array {
    return \Drupal::state()->get('audit_chain.scheduled_verification');
  }

  /**
   * Returns runtime requirements keyed by requirement id.
   */
  private function runtimeRequirements(): array {
    \Drupal::moduleHandler()->loadInclude('audit_chain', 'install');
    return audit_chain_requirements('runtime');
  }

  /**
   * Replaces the audit_chain logger channel with a record-capturing spy.
   *
   * @return object
   *   The spy, exposing a public $records array.
   */
  private function spyChannel(): object {
    $spy = new class() extends AbstractLogger {

      /**
       * Captured log records.
       *
       * @var array<int, array{level: mixed, message: string}>
       */
      public array $records = [];

      /**
       * {@inheritdoc}
       */
      public function log($level, string|\Stringable $message, array $context = []): void {
        $this->records[] = ['level' => $level, 'message' => (string) $message];
      }

    };
    $this->container->set('logger.channel.audit_chain', $spy);
    $this->container->set('audit_chain.scheduled_verifier', NULL);
    return $spy;
  }

  /**
   * Snapshots the chain rows in a core-version-agnostic way.
   *
   * @return array<int, array{id: int, operation: string, row_hash: string}>
   *   The rows, keyed and ordered by id.
   */
  private function chainSnapshot(): array {
    $rows = [];
    $result = \Drupal::database()->select('audit_chain_log', 'l')
      ->fields('l', ['id', 'operation', 'row_hash'])
      ->orderBy('id')
      ->execute();
    foreach ($result as $record) {
      $record = (array) $record;
      $rows[(int) $record['id']] = $record;
    }
    return $rows;
  }

  /**
   * With no interval configured, cron runs nothing and records nothing.
   */
  public function testDisabledByDefaultCronRunsNothing(): void {
    $this->runCron();
    $this->assertNull($this->lastRun(),
      'Scheduled verification is opt-in: default configuration must record no run.');
  }

  /**
   * A due run records success; a second cron inside the interval skips.
   */
  public function testDueRunRecordsSuccessAndHonorsInterval(): void {
    $this->makeKey('chain_key');
    $this->config('audit_chain.settings')
      ->set('hash_key', 'chain_key')
      ->set('verify_interval', 3600)
      ->save();
    \Drupal::service('audit_chain.logger')->log('personnel', 'field_read', ['id' => '1']);

    $this->runCron();
    $run = $this->lastRun();
    $this->assertIsArray($run, 'A due cron must record a run.');
    $this->assertTrue($run['ok'], 'A healthy keyed chain must verify ok.');
    $firstTime = $run['time'];

    $this->runCron();
    $this->assertSame($firstTime, $this->lastRun()['time'],
      'A cron inside the interval must not re-run the verification.');
  }

  /**
   * The assurance profile refuses to verify unkeyed: no key, no pass.
   */
  public function testKeyedRequiredWithoutKeyFails(): void {
    $spy = $this->spyChannel();
    $this->config('audit_chain.settings')
      ->set('verify_interval', 3600)
      ->set('verify_require_keyed', TRUE)
      ->save();

    $this->runCron();
    $run = $this->lastRun();
    $this->assertIsArray($run);
    $this->assertFalse($run['ok'],
      'The assurance profile must fail, not fall back to unkeyed verification.');
    $this->assertSame('keyed_verification_unavailable', $run['reason']);

    $this->assertNotEmpty(
      array_filter($spy->records, fn (array $r): bool => $r['level'] === 'error'),
      'The failure must alert through the logger channel.'
    );

    $requirements = $this->runtimeRequirements();
    $this->assertArrayHasKey('audit_chain_scheduled_verification', $requirements);
    $this->assertSame(REQUIREMENT_ERROR, $requirements['audit_chain_scheduled_verification']['severity'],
      'A failed scheduled verification must be a non-success health state.');
  }

  /**
   * A tampered chain fails, alerts, dispatches the event, and is untouched.
   */
  public function testTamperFailureAlertsAndPreservesChain(): void {
    $spy = $this->spyChannel();
    $this->makeKey('chain_key');
    $this->config('audit_chain.settings')
      ->set('hash_key', 'chain_key')
      ->set('verify_interval', 3600)
      ->save();
    $logger = \Drupal::service('audit_chain.logger');
    $logger->log('personnel', 'field_read', ['id' => '1']);
    $logger->log('personnel', 'field_read', ['id' => '2']);

    // Tamper with the first row's operation, keeping its stored hash.
    $firstId = (int) \Drupal::database()->select('audit_chain_log', 'l')
      ->fields('l', ['id'])
      ->orderBy('id')
      ->range(0, 1)
      ->execute()->fetchField();
    \Drupal::database()->update('audit_chain_log')
      ->fields(['operation' => 'tampered_operation'])
      ->condition('id', $firstId)
      ->execute();
    $rowsBefore = $this->chainSnapshot();

    $captured = [];
    \Drupal::service('event_dispatcher')->addListener(
      AuditChainVerificationFailedEvent::EVENT_NAME,
      function (AuditChainVerificationFailedEvent $event) use (&$captured): void {
        $captured[] = $event->run;
      }
    );

    $this->runCron();
    $run = $this->lastRun();
    $this->assertFalse($run['ok'], 'A tampered chain must fail the scheduled run.');
    $this->assertSame('tampered', $run['reason']);

    $this->assertCount(1, $captured,
      'The failure must dispatch the verification-failed event for consumers.');
    $this->assertFalse($captured[0]['ok']);

    $this->assertNotEmpty(
      array_filter($spy->records, fn (array $r): bool => $r['level'] === 'error'),
      'The failure must alert through the logger channel.'
    );

    $rowsAfter = $this->chainSnapshot();
    $this->assertSame($rowsBefore, $rowsAfter,
      'Verification must never rewrite the chain it inspected — tampered rows included.');

    $requirements = $this->runtimeRequirements();
    $this->assertSame(REQUIREMENT_ERROR, $requirements['audit_chain_scheduled_verification']['severity']);
  }

  /**
   * A foreign seal stays fail-closed without raising a tampering incident.
   */
  public function testForeignSealWarnsWithoutDispatchingFailureEvent(): void {
    $logger = \Drupal::service('audit_chain.logger');
    $logger->log('personnel', 'field_read', ['id' => '1']);
    $logger->log('personnel', 'field_read', ['id' => '2']);
    $this->makeKey('production_key', 'production-secret');
    $this->config('audit_chain.settings')->set('hash_key', 'production_key')->save();
    $this->assertTrue($logger->sealPrefix(2, 'production prefix')['sealed']);

    // Model a database refresh into an environment that holds a different key.
    $this->makeKey('staging_key', 'staging-secret');
    $this->config('audit_chain.settings')
      ->set('hash_key', 'staging_key')
      ->set('previous_hash_keys', [])
      ->set('verify_interval', 3600)
      ->save();
    Key::load('production_key')?->delete();
    $rowsBefore = $this->chainSnapshot();
    $spy = $this->spyChannel();

    $captured = [];
    \Drupal::service('event_dispatcher')->addListener(
      AuditChainVerificationFailedEvent::EVENT_NAME,
      function (AuditChainVerificationFailedEvent $event) use (&$captured): void {
        $captured[] = $event->run;
      }
    );

    $this->runCron();
    $run = $this->lastRun();
    $this->assertFalse($run['ok'], 'A foreign seal must not be treated as verified.');
    $this->assertSame(AuditChainLogger::REASON_SEAL_FOREIGN, $run['reason']);
    $this->assertSame([], $captured, 'A foreign seal is not a tampering event.');
    $this->assertNotEmpty(
      array_filter($spy->records, fn (array $record): bool => $record['level'] === 'warning'),
      'The advisory must leave an operational signal.'
    );
    $this->assertEmpty(
      array_filter($spy->records, fn (array $record): bool => $record['level'] === 'error'),
      'An unchanged foreign prefix must not be logged as an integrity failure.'
    );
    $this->assertSame($rowsBefore, $this->chainSnapshot(), 'Verification must remain read-only.');

    $requirements = $this->runtimeRequirements();
    $this->assertSame(
      REQUIREMENT_WARNING,
      $requirements['audit_chain_scheduled_verification']['severity'],
      'The status report must distinguish an unauthenticated copy from tampering.'
    );
  }

  /**
   * An unresolvable signing key is not keyed operation: the profile fails.
   */
  public function testKeyedRequiredWithUnresolvableKeyFails(): void {
    // hash_key names a Key entity that does not exist: writes fall back to
    // unkeyed SHA-256, so the assurance profile must refuse — a config string
    // alone is not a key.
    $this->config('audit_chain.settings')
      ->set('hash_key', 'no_such_key')
      ->set('verify_interval', 3600)
      ->set('verify_require_keyed', TRUE)
      ->save();

    $this->runCron();
    $run = $this->lastRun();
    $this->assertIsArray($run);
    $this->assertFalse($run['ok'],
      'An unresolvable key must fail the assurance profile, not pass as keyed.');
    $this->assertSame('keyed_verification_unavailable', $run['reason']);
  }

  /**
   * Rows written unkeyed are rejected once the assurance profile is on.
   */
  public function testUnkeyedRowsRejectedUnderAssuranceProfile(): void {
    // History written with no key configured.
    \Drupal::service('audit_chain.logger')->log('personnel', 'field_read', ['id' => '1']);

    $this->makeKey('chain_key');
    $this->config('audit_chain.settings')
      ->set('hash_key', 'chain_key')
      ->set('verify_interval', 3600)
      ->set('verify_require_keyed', TRUE)
      ->save();

    $this->runCron();
    $run = $this->lastRun();
    $this->assertFalse($run['ok'],
      'Unkeyed history must not pass the assurance profile.');
    $this->assertSame('written_unkeyed', $run['reason']);
  }

  /**
   * Rotated keys keep old rows verifiable via previous_hash_keys.
   */
  public function testKeyRotationStillVerifies(): void {
    $this->makeKey('old_key', 'old-secret');
    $this->makeKey('new_key', 'new-secret');
    $this->config('audit_chain.settings')
      ->set('hash_key', 'old_key')
      ->set('verify_interval', 3600)
      ->set('verify_require_keyed', TRUE)
      ->save();
    $logger = \Drupal::service('audit_chain.logger');
    $logger->log('personnel', 'field_read', ['id' => '1']);

    $this->config('audit_chain.settings')
      ->set('hash_key', 'new_key')
      ->set('previous_hash_keys', ['old_key'])
      ->save();
    $logger->log('personnel', 'field_read', ['id' => '2']);

    $this->runCron();
    $run = $this->lastRun();
    $this->assertTrue($run['ok'],
      'Rows written under a rotated-out key must verify through previous_hash_keys.');
  }

  /**
   * An enabled schedule that has not run recently is an overdue warning.
   */
  public function testOverdueScheduleRaisesWarning(): void {
    $this->config('audit_chain.settings')->set('verify_interval', 3600)->save();
    \Drupal::state()->set('audit_chain.scheduled_verification', [
      'time' => \Drupal::time()->getRequestTime() - 7300,
      'ok' => TRUE,
      'reason' => NULL,
    ]);

    $requirements = $this->runtimeRequirements();
    $this->assertArrayHasKey('audit_chain_scheduled_verification', $requirements);
    $this->assertSame(REQUIREMENT_WARNING, $requirements['audit_chain_scheduled_verification']['severity'],
      'A run older than twice the interval must warn: silence is not health.');
  }

  /**
   * The assurance profile without a schedule is itself a warning.
   */
  public function testAssuranceProfileWithoutScheduleWarns(): void {
    $this->config('audit_chain.settings')
      ->set('verify_require_keyed', TRUE)
      ->set('verify_interval', 0)
      ->save();

    $requirements = $this->runtimeRequirements();
    $this->assertArrayHasKey('audit_chain_scheduled_verification', $requirements);
    $this->assertSame(REQUIREMENT_WARNING, $requirements['audit_chain_scheduled_verification']['severity'],
      'Requiring keyed verification while never scheduling it must warn.');
  }

}
