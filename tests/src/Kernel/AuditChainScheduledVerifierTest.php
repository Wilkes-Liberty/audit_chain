<?php

declare(strict_types=1);

namespace Drupal\Tests\audit_chain\Kernel;

use Drupal\audit_chain\AuditChainLogger;
use Drupal\audit_chain\Event\AuditChainVerificationFailedEvent;
use Drupal\audit_chain\ScheduledVerificationIntegrity;
use Drupal\KernelTests\KernelTestBase;
use Drupal\key\Entity\Key;
use Psr\Log\AbstractLogger;
use PHPUnit\Framework\Attributes\Group;

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
 */
#[Group('audit_chain')]
final class AuditChainScheduledVerifierTest extends KernelTestBase {

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

    $this->assertErrorCopyContainsFormattedTime($spy, $run);

    $requirements = $this->runtimeRequirements();
    $this->assertArrayHasKey('audit_chain_scheduled_verification', $requirements);
    $this->assertSame(REQUIREMENT_ERROR, $requirements['audit_chain_scheduled_verification']['severity'],
      'A failed scheduled verification must be a non-success health state.');
    $this->assertRequirementMatchesClassifier($requirements);
  }

  /**
   * A missing date-format config must not abort runNow() after persist.
   *
   * DateFormatter type medium loads core.date_format.medium, then fallback.
   * When those entities are gone, format() throws on getPattern(). That used
   * to abort runNow() after state->set() had already stored the verdict.
   */
  public function testRunNowCompletesWithoutDateFormatConfig(): void {
    $this->deleteDateFormatConfig();

    $spy = $this->spyChannel();
    $this->config('audit_chain.settings')
      ->set('verify_interval', 3600)
      ->set('verify_require_keyed', TRUE)
      ->save();

    $run = \Drupal::service('audit_chain.scheduled_verifier')->runNow();
    $stored = $this->lastRun();
    $this->assertIsArray(
      $stored,
      'The verdict must remain stored after presentation.',
    );
    $this->assertSame($run, $stored);
    $this->assertFalse($stored['ok']);
    $this->assertSame('keyed_verification_unavailable', $stored['reason']);
    $this->assertArrayHasKey('verdict', $stored);

    $errors = array_values(array_filter(
      $spy->records,
      fn (array $record): bool => $record['level'] === 'error',
    ));
    $this->assertCount(
      1,
      $errors,
      'Presentation must write one watchdog error.',
    );
    $this->assertTrue(
      (bool) preg_match(
        '/\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}[+\-]\d{2}:\d{2}/',
        $errors[0]['message'],
      ),
      'Presentation must show a sane ISO-8601 timestamp.',
    );
    $this->assertStringContainsString('keyed_verification_unavailable', $errors[0]['message']);
    $this->assertStringNotContainsString('unknown', $errors[0]['message']);
  }

  /**
   * A tampered chain still dispatches the failure event without date formats.
   */
  public function testTamperDispatchesWithoutDateFormatConfig(): void {
    $this->makeKey('chain_key');
    $this->config('audit_chain.settings')
      ->set('hash_key', 'chain_key')
      ->set('verify_interval', 3600)
      ->save();
    $logger = \Drupal::service('audit_chain.logger');
    $logger->log('personnel', 'field_read', ['id' => '1']);
    $logger->log('personnel', 'field_read', ['id' => '2']);

    $firstId = (int) \Drupal::database()->select('audit_chain_log', 'l')
      ->fields('l', ['id'])
      ->orderBy('id')
      ->range(0, 1)
      ->execute()->fetchField();
    \Drupal::database()->update('audit_chain_log')
      ->fields(['operation' => 'tampered_operation'])
      ->condition('id', $firstId)
      ->execute();

    $this->deleteDateFormatConfig();
    $captured = [];
    $this->listenForFailureEvents($captured);

    $run = \Drupal::service('audit_chain.scheduled_verifier')->runNow();
    $this->assertFalse($run['ok'], 'A tampered chain must fail the scheduled run.');
    $this->assertSame('tampered', $run['reason']);
    $this->assertCount(
      1,
      $captured,
      'A tamper failure must dispatch even without date-format config.',
    );
    $this->assertSame($run, $captured[0]);
    $this->assertSame($run, $this->lastRun());
  }

  /**
   * A throwing logger must not skip the verification-failed event.
   */
  public function testThrowingLoggerStillDispatchesFailureEvent(): void {
    $this->config('audit_chain.settings')
      ->set('verify_interval', 3600)
      ->set('verify_require_keyed', TRUE)
      ->save();

    $throwing = new class() extends AbstractLogger {

      /**
       * {@inheritdoc}
       */
      public function log($level, string|\Stringable $message, array $context = []): void {
        throw new \RuntimeException('scheduled-verifier logger failed');
      }

    };
    $this->container->set('logger.channel.audit_chain', $throwing);
    $this->container->set('audit_chain.scheduled_verifier', NULL);
    $captured = [];
    $this->listenForFailureEvents($captured);

    try {
      \Drupal::service('audit_chain.scheduled_verifier')->runNow();
      $this->fail('A throwing logger must surface from runNow().');
    }
    catch (\RuntimeException $exception) {
      $this->assertSame(
        'scheduled-verifier logger failed',
        $exception->getMessage(),
      );
    }

    $this->assertCount(
      1,
      $captured,
      'Dispatch must not depend on the logger succeeding.',
    );
    $stored = $this->lastRun();
    $this->assertIsArray($stored);
    $this->assertSame($stored, $captured[0]);
    $this->assertFalse($stored['ok']);
    $this->assertSame('keyed_verification_unavailable', $stored['reason']);
  }

  /**
   * A throwing subscriber must not skip the watchdog error.
   */
  public function testThrowingSubscriberStillLogsWatchdogError(): void {
    $spy = $this->spyChannel();
    $this->config('audit_chain.settings')
      ->set('verify_interval', 3600)
      ->set('verify_require_keyed', TRUE)
      ->save();

    $captured = [];
    \Drupal::service('event_dispatcher')->addListener(
      AuditChainVerificationFailedEvent::EVENT_NAME,
      function (AuditChainVerificationFailedEvent $event) use (&$captured): void {
        $captured[] = $event->run;
        throw new \RuntimeException('scheduled-verifier subscriber failed');
      },
    );

    try {
      \Drupal::service('audit_chain.scheduled_verifier')->runNow();
      $this->fail('A throwing subscriber must surface from runNow().');
    }
    catch (\RuntimeException $exception) {
      $this->assertSame(
        'scheduled-verifier subscriber failed',
        $exception->getMessage(),
      );
    }

    $this->assertCount(1, $captured, 'The failure event must dispatch once.');
    $stored = $this->lastRun();
    $this->assertIsArray($stored);
    $this->assertSame($stored, $captured[0]);
    $errors = array_values(array_filter(
      $spy->records,
      fn (array $record): bool => $record['level'] === 'error',
    ));
    $this->assertCount(
      1,
      $errors,
      'A throwing subscriber must not skip or duplicate the watchdog error.',
    );
    $this->assertStringContainsString(
      'keyed_verification_unavailable',
      $errors[0]['message'],
    );
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
    $this->listenForFailureEvents($captured);

    $this->runCron();
    $run = $this->lastRun();
    $this->assertFalse($run['ok'], 'A tampered chain must fail the scheduled run.');
    $this->assertSame('tampered', $run['reason']);

    $this->assertCount(1, $captured,
      'The failure must dispatch the verification-failed event for consumers.');
    $this->assertSame($run, $captured[0]);

    $this->assertErrorCopyContainsFormattedTime($spy, $run);

    $rowsAfter = $this->chainSnapshot();
    $this->assertSame($rowsBefore, $rowsAfter,
      'Verification must never rewrite the chain it inspected — tampered rows included.');

    $requirements = $this->runtimeRequirements();
    $this->assertSame(REQUIREMENT_ERROR, $requirements['audit_chain_scheduled_verification']['severity']);
    $this->assertRequirementMatchesClassifier($requirements);
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
    $this->assertRequirementMatchesClassifier($requirements);
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
    $this->assertFalse($run['verdict']['unsigned_prefix']);
    $requirements = $this->runtimeRequirements();
    $this->assertSame(REQUIREMENT_ERROR, $requirements['audit_chain_scheduled_verification']['severity'],
      'Unkeyed history with no signed successor stays an error under the assurance profile.');
  }

  /**
   * A leading unsigned prefix is annotated; a tampered signed row still fails.
   *
   * The prefix is not re-signed and is not deleted. Whole-history verification
   * stays unsuccessful. Editing a later signed row is still an integrity error.
   */
  public function testKnownUnsignedPrefixStaysAnnotatedAndTamperedSignedRowFails(): void {
    $chain = \Drupal::service('audit_chain.logger');
    $chain->log('personnel', 'field_read', ['id' => 'legacy']);

    $this->makeKey('chain_key');
    $this->config('audit_chain.settings')
      ->set('hash_key', 'chain_key')
      ->set('verify_interval', 3600)
      ->save();
    $chain->log('personnel', 'field_read', ['id' => 'successor']);
    $this->assertNull($chain->getSeal());

    $spy = $this->spyChannel();
    $captured = [];
    \Drupal::service('event_dispatcher')->addListener(
      AuditChainVerificationFailedEvent::EVENT_NAME,
      function (AuditChainVerificationFailedEvent $event) use (&$captured): void {
        $captured[] = $event->run;
      }
    );

    $before = $this->chainSnapshot();
    $this->runCron();
    $run = $this->lastRun();
    $this->assertIsArray($run);
    $this->assertFalse($run['ok'], 'A leading unsigned prefix is not a whole-history pass.');
    $this->assertSame(AuditChainLogger::REASON_WRITTEN_UNKEYED, $run['reason']);
    $this->assertTrue($run['verdict']['unsigned_prefix']);
    $this->assertSame($before, $this->chainSnapshot(), 'Annotation must not rewrite or delete rows.');
    $this->assertSame([], $captured, 'A documented prefix is not a tampering alert.');
    $this->assertEmpty(
      array_filter($spy->records, fn (array $record): bool => $record['level'] === 'error'),
      'A documented prefix must not be logged as an integrity failure.'
    );
    $this->assertNotEmpty(
      array_filter($spy->records, fn (array $record): bool => $record['level'] === 'warning'),
      'The prefix must stay visible as a warning.'
    );

    $requirements = $this->runtimeRequirements();
    $this->assertSame(REQUIREMENT_WARNING, $requirements['audit_chain_scheduled_verification']['severity']);
    $description = (string) $requirements['audit_chain_scheduled_verification']['description'];
    $this->assertStringContainsString('not re-signed', $description);
    $this->assertStringContainsString('authoritative chain', $description);
    $this->assertStringContainsString(
      'Documented unsigned prefix',
      (string) $requirements['audit_chain_scheduled_verification']['value'],
    );

    $signedId = (int) \Drupal::database()->select('audit_chain_log', 'l')
      ->fields('l', ['id'])
      ->orderBy('id', 'DESC')
      ->range(0, 1)
      ->execute()
      ->fetchField();
    \Drupal::database()->update('audit_chain_log')
      ->fields(['operation' => 'tampered_operation'])
      ->condition('id', $signedId)
      ->execute();

    \Drupal::service('audit_chain.scheduled_verifier')->runNow();
    $run = $this->lastRun();
    $this->assertFalse($run['ok']);
    $this->assertSame(AuditChainLogger::REASON_TAMPERED, $run['reason']);
    $this->assertSame($signedId, $run['verdict']['broken_at']);
    $requirements = $this->runtimeRequirements();
    $this->assertSame(
      REQUIREMENT_ERROR,
      $requirements['audit_chain_scheduled_verification']['severity'],
      'An edited signed row must still fail the status report.',
    );
    $this->assertNotEmpty($captured, 'Tampering must still dispatch the failure event.');
  }

  /**
   * An unsigned row written after the signed successor is not the known prefix.
   */
  public function testUnsignedRowAfterSignedSuccessorStaysAnError(): void {
    $this->makeKey('chain_key');
    $this->config('audit_chain.settings')
      ->set('hash_key', 'chain_key')
      ->set('verify_interval', 3600)
      ->save();
    $chain = \Drupal::service('audit_chain.logger');
    $chain->log('personnel', 'field_read', ['id' => 'signed']);

    $this->config('audit_chain.settings')->set('hash_key', '')->save();
    $chain->log('personnel', 'field_read', ['id' => 'later-unsigned']);
    $this->config('audit_chain.settings')->set('hash_key', 'chain_key')->save();

    $this->runCron();
    $run = $this->lastRun();
    $this->assertFalse($run['ok']);
    $this->assertSame(AuditChainLogger::REASON_WRITTEN_UNKEYED, $run['reason']);
    $this->assertFalse($run['verdict']['unsigned_prefix']);
    $requirements = $this->runtimeRequirements();
    $this->assertSame(REQUIREMENT_ERROR, $requirements['audit_chain_scheduled_verification']['severity']);
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
    $this->assertRequirementMatchesClassifier($requirements);
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
    $this->assertRequirementMatchesClassifier($requirements);
  }

  /**
   * Removes every system date-format config entity.
   */
  private function deleteDateFormatConfig(): void {
    $storage = $this->container->get('entity_type.manager')->getStorage('date_format');
    foreach ($storage->loadMultiple() as $format) {
      $format->delete();
    }
    $storage->resetCache();
    $this->assertNull($storage->load('medium'));
    $this->assertNull($storage->load('fallback'));
  }

  /**
   * Listens for verification-failed events and appends each run record.
   *
   * @param array $captured
   *   Captured run records, filled by the listener as events fire.
   */
  private function listenForFailureEvents(array &$captured): void {
    \Drupal::service('event_dispatcher')->addListener(
      AuditChainVerificationFailedEvent::EVENT_NAME,
      function (AuditChainVerificationFailedEvent $event) use (&$captured): void {
        $captured[] = $event->run;
      },
    );
  }

  /**
   * Asserts watchdog error copy uses the formatted run time, not "unknown".
   *
   * @param object $spy
   *   The logger spy returned by spyChannel().
   * @param array $run
   *   The recorded scheduled-verification run.
   */
  private function assertErrorCopyContainsFormattedTime(object $spy, array $run): void {
    $errors = array_values(array_filter(
      $spy->records,
      fn (array $r): bool => $r['level'] === 'error',
    ));
    $this->assertCount(
      1,
      $errors,
      'The failure must alert through the logger channel once.',
    );
    $when = \Drupal::service('date.formatter')->format(
      (int) $run['time'],
      'custom',
      DATE_ATOM,
    );
    $matched = array_filter(
      $errors,
      fn (array $r): bool => str_contains($r['message'], $when),
    );
    $this->assertNotEmpty(
      $matched,
      'Error copy must contain the formatted last-run time, not "unknown".',
    );
    foreach ($matched as $record) {
      $this->assertStringNotContainsString('unknown', $record['message']);
    }
  }

  /**
   * Asserts the status-report severity matches the shared classifier.
   *
   * @param array $requirements
   *   Runtime requirements keyed by id.
   */
  private function assertRequirementMatchesClassifier(array $requirements): void {
    $classified = ScheduledVerificationIntegrity::classify(
      $this->lastRun(),
      (int) $this->config('audit_chain.settings')->get('verify_interval'),
      \Drupal::time()->getRequestTime(),
    );
    $require_keyed = (bool) $this->config('audit_chain.settings')->get('verify_require_keyed');
    if ($classified['reason'] === 'disabled' && !$require_keyed) {
      $this->assertArrayNotHasKey('audit_chain_scheduled_verification', $requirements);
      return;
    }
    $expected = match ($classified['status']) {
      'ok' => REQUIREMENT_OK,
      'crit' => REQUIREMENT_ERROR,
      'warn' => REQUIREMENT_WARNING,
      default => throw new \InvalidArgumentException('Unknown integrity status: ' . $classified['status']),
    };
    $this->assertArrayHasKey('audit_chain_scheduled_verification', $requirements);
    $this->assertSame($expected, $requirements['audit_chain_scheduled_verification']['severity']);
  }

}
