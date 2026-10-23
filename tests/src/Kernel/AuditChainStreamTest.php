<?php

declare(strict_types=1);

namespace Drupal\Tests\audit_chain\Kernel;

use Drupal\audit_chain\AuditChainLogger;
use Drupal\audit_chain\AuditChainServiceProvider;
use Drupal\audit_chain\Exception\AuditChainSigningUnavailableException;
use Drupal\audit_chain\Logger\PhpSyslogStreamLogger;
use Drupal\Core\DependencyInjection\ContainerBuilder;
use Drupal\Core\Logger\LoggerChannel;
use Drupal\dblog\Logger\DbLog;
use Drupal\KernelTests\KernelTestBase;
use Drupal\syslog\Logger\SysLog;
use Psr\Log\AbstractLogger;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;

/**
 * SIEM stream routing for successful appends.
 *
 * @coversDefaultClass \Drupal\audit_chain\AuditChainLogger
 * @covers \Drupal\audit_chain\AuditChainServiceProvider
 * @group audit_chain
 */
#[CoversClass(AuditChainLogger::class)]
#[CoversClass(AuditChainServiceProvider::class)]
#[Group('audit_chain')]
final class AuditChainStreamTest extends KernelTestBase {

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
    $this->installEntitySchema('user');
    $this->installAuditChainTables();
    $this->installConfig(['audit_chain']);
  }

  /**
   * Successful stream_enabled appends reach logger.channel.audit_chain.
   *
   * 1.12.2 wrote that record there. That service is the SIEM sink
   * mcp_sentinel's McpSiemStreamingTest — and sites that already excluded
   * dblog from it — listen on. 1.13.0 moved the record onto
   * audit_chain.stream, so a successful append vanished from the channel
   * those collectors still consume.
   */
  public function testStreamEnabledWritesSuccessfulEventToAuditChainChannel(): void {
    // 1.12.2 config: stream_enabled only. No dedicated-sink opt-in.
    $this->config('audit_chain.settings')->set('stream_enabled', TRUE)->save();
    $spy = $this->installAuditChainChannelSpy();

    $this->container->get('audit_chain.logger')->log('personnel', 'field_read', [
      'entity_type' => 'node',
      'bundle' => 'person',
      'id' => '9',
    ]);

    $this->assertCount(1, $this->chainRows(), 'The append still lands in {audit_chain_log}.');
    $this->assertTrue($this->container->get('audit_chain.logger')->verify()['ok']);

    $events = $this->channelEvents($spy, 'audit_chain_event');
    $this->assertCount(1, $events, 'A successful append must emit audit_chain_event on logger.channel.audit_chain.');
    $this->assertSame('info', (string) $events[0]['level']);
    $ctx = $events[0]['context'];
    foreach (['channel', 'operation', 'uid', 'entity_type', 'bundle', 'entity_id', 'timestamp', 'row_hash'] as $key) {
      $this->assertArrayHasKey($key, $ctx, "Streamed context must carry '{$key}'.");
    }
    $this->assertSame('personnel', $ctx['channel']);
    $this->assertSame('field_read', $ctx['operation']);
    $this->assertSame('person', $ctx['bundle']);
    $this->assertSame('9', $ctx['entity_id']);
    $this->assertNotEmpty($ctx['row_hash']);
  }

  /**
   * Deny appends and signing faults still reach logger.channel.audit_chain.
   *
   * A deny is still a successful chain write. Dropping it from the SIEM
   * channel is fail-open for a collector that keys on that record. A
   * signing-key fault is an operational error and must stay on the same
   * channel. logKeyed() without a key still refuses and writes nothing.
   */
  public function testDenyAndFailureStillReachAuditChainChannel(): void {
    $this->config('audit_chain.settings')->set('stream_enabled', TRUE)->save();
    $spy = $this->installAuditChainChannelSpy();
    $chain = $this->container->get('audit_chain.logger');

    $chain->log('mcp_sentinel', 'access_denied', [
      'entity_type' => 'user',
      'id' => '4',
    ]);

    $denied = $this->channelEvents($spy, 'audit_chain_event');
    $this->assertCount(1, $denied, 'A deny append must still stream audit_chain_event.');
    $this->assertSame('access_denied', $denied[0]['context']['operation']);
    $this->assertSame('mcp_sentinel', $denied[0]['context']['channel']);
    $this->assertCount(1, $this->chainRows(), 'The deny is recorded; streaming must not drop it.');

    $this->config('audit_chain.settings')->set('hash_key', 'no_such_key')->save();
    $this->container->set('audit_chain.logger', NULL);
    $this->container->get('audit_chain.logger')->log('personnel', 'field_read', [
      'id' => '1',
    ]);

    $faults = array_values(array_filter(
      $spy->records,
      static fn (array $record): bool => str_contains($record['message'], 'cannot be resolved'),
    ));
    $this->assertNotEmpty($faults, 'An unresolvable signing key must still reach logger.channel.audit_chain.');
    $this->assertCount(2, $this->chainRows(), 'The unsigned row is still recorded.');

    try {
      $this->container->get('audit_chain.logger')->logKeyed('mcp_sentinel', 'access_denied');
      $this->fail('logKeyed() must refuse when the signing key cannot be resolved.');
    }
    catch (AuditChainSigningUnavailableException $exception) {
      $this->assertStringContainsString('cannot be resolved', $exception->getMessage());
    }
    $this->assertCount(2, $this->chainRows(), 'A refused keyed write must not leave a row.');
  }

  /**
   * With streaming on and dblog enabled, appends write no watchdog event rows.
   *
   * Would fail if append still called logger.channel.audit_chain->info():
   * that channel fans out to dblog and each write becomes a {watchdog} row.
   */
  public function testStreamedAppendDoesNotWriteWatchdogRows(): void {
    $this->enableDblog();
    $this->config('audit_chain.settings')
      ->set('stream_enabled', TRUE)
      ->set('stream_exclude_dblog', TRUE)
      ->save();

    $ops = $this->installOpsChannelSpy();
    $chain = $this->container->get('audit_chain.logger');
    $chain->log('personnel', 'field_read', [
      'entity_type' => 'node',
      'bundle' => 'person',
      'id' => '9',
    ]);
    $chain->log('personnel', 'field_read', [
      'entity_type' => 'node',
      'bundle' => 'person',
      'id' => '10',
    ]);
    $chain->log('personnel', 'field_read', [
      'entity_type' => 'node',
      'bundle' => 'person',
      'id' => '11',
    ]);

    $this->assertCount(3, $this->chainRows(), 'Appends still land in {audit_chain_log}.');
    $this->assertTrue($chain->verify()['ok'], 'The chain still verifies.');
    $this->assertCount(
      0,
      $this->watchdogContaining('audit_chain_event'),
      'Streaming must not write append events into dblog.',
    );
    $this->assertCount(
      0,
      $ops->records,
      'A successful append must not use the operational audit_chain channel.',
    );
  }

  /**
   * Verify-path / signing errors still reach dblog when streaming is on.
   */
  public function testUnresolvableKeyStillWritesWatchdogWhenStreaming(): void {
    $this->enableDblog();
    $this->config('audit_chain.settings')
      ->set('stream_enabled', TRUE)
      ->set('stream_exclude_dblog', TRUE)
      ->set('hash_key', 'no_such_key')
      ->save();

    $this->container->get('audit_chain.logger')->log('personnel', 'field_read', [
      'id' => '1',
    ]);

    $this->assertCount(1, $this->chainRows(), 'The unsigned row is still recorded.');
    $this->assertCount(
      0,
      $this->watchdogContaining('audit_chain_event'),
      'The append stream still must not appear in dblog.',
    );

    $errors = $this->watchdogContaining('cannot be resolved');
    $this->assertNotEmpty($errors, 'The signing-key fault must still reach dblog.');
    $this->assertSame('audit_chain', $errors[0]->type);
  }

  /**
   * A down SIEM sink must not roll back the evidence row.
   */
  public function testStreamFailureDoesNotRollBackAppend(): void {
    $this->config('audit_chain.settings')
      ->set('stream_enabled', TRUE)
      ->set('stream_exclude_dblog', TRUE)
      ->save();
    $throwing = new class() extends AbstractLogger {

      /**
       * {@inheritdoc}
       */
      public function log($level, string|\Stringable $message, array $context = []): void {
        throw new \RuntimeException('siem down');
      }

    };
    $this->container->set('audit_chain.stream', $throwing);
    $this->container->set('audit_chain.logger', NULL);

    $this->container->get('audit_chain.logger')->log('personnel', 'field_read', [
      'id' => '1',
    ]);
    $this->assertCount(1, $this->chainRows());
    $this->assertTrue($this->container->get('audit_chain.logger')->verify()['ok']);
  }

  /**
   * Update 10008 writes stream_exclude_dblog FALSE and does not overwrite TRUE.
   */
  public function testUpdate10008DefaultsExcludeDblogOffAndIsIdempotent(): void {
    $this->container->get('module_handler')->loadInclude('audit_chain', 'install');
    $this->config('audit_chain.settings')
      ->clear('stream_exclude_dblog')
      ->set('stream_enabled', TRUE)
      ->save();
    $before = $this->chainRows();

    audit_chain_update_10008();
    audit_chain_update_10008();
    $this->assertFalse($this->config('audit_chain.settings')->get('stream_exclude_dblog'));
    $this->assertTrue($this->config('audit_chain.settings')->get('stream_enabled'));
    $this->assertEquals($before, $this->chainRows());

    $this->config('audit_chain.settings')->set('stream_exclude_dblog', TRUE)->save();
    audit_chain_update_10008();
    $this->assertTrue(
      $this->config('audit_chain.settings')->get('stream_exclude_dblog'),
      'An operator-set TRUE is not overwritten.',
    );
  }

  /**
   * Syslog stays on the stream; dblog is excluded when both are enabled.
   */
  public function testStreamSinkExcludesDblogAndKeepsSyslog(): void {
    $this->enableModules(['dblog', 'syslog']);
    $foundSyslog = FALSE;
    foreach ($this->streamBackends() as $logger) {
      $this->assertNotInstanceOf(DbLog::class, $logger);
      $this->assertNotInstanceOf(PhpSyslogStreamLogger::class, $logger);
      if ($logger instanceof SysLog) {
        $foundSyslog = TRUE;
      }
    }
    $this->assertTrue($foundSyslog, 'Syslog must still receive the SIEM stream.');
  }

  /**
   * PHP syslog is attached only when every tagged logger is dblog.
   *
   * A kernel site often has DrupalConsoleLogger, so this asserts the
   * compiler pass in isolation rather than against whatever the test
   * kernel happened to tag.
   */
  public function testServiceProviderFallsBackWhenOnlyDblogIsTagged(): void {
    $container = $this->streamContainer();
    $container->register('logger.dblog', DbLog::class)->addTag('logger');

    (new AuditChainServiceProvider())->alter($container);

    $this->assertSame(
      ['audit_chain.stream_syslog'],
      $this->addedLoggerIds($container),
      'A dblog-only site must still emit the SIEM stream.',
    );
  }

  /**
   * Syslog stays; dblog and the PHP fallback do not share that stream.
   */
  public function testServiceProviderKeepsSyslogAndOmitsDblogAndFallback(): void {
    $container = $this->streamContainer();
    $container->register('logger.dblog', DbLog::class)->addTag('logger');
    $container->register('logger.syslog', SysLog::class)->addTag('logger');

    (new AuditChainServiceProvider())->alter($container);

    $ids = $this->addedLoggerIds($container);
    $this->assertContains('logger.syslog', $ids);
    $this->assertNotContains('logger.dblog', $ids);
    $this->assertNotContains('audit_chain.stream_syslog', $ids);
  }

  /**
   * Container with only the stream service and its PHP syslog fallback.
   */
  private function streamContainer(): ContainerBuilder {
    $container = new ContainerBuilder();
    $container->register('audit_chain.stream', LoggerChannel::class)
      ->addArgument('audit_chain');
    $container->register('audit_chain.stream_syslog', PhpSyslogStreamLogger::class);
    return $container;
  }

  /**
   * Service ids passed to audit_chain.stream addLogger() by the compiler pass.
   *
   * @param \Drupal\Core\DependencyInjection\ContainerBuilder $container
   *   A container the compiler pass has already altered.
   *
   * @return list<string>
   *   Logger service ids in attachment order.
   */
  private function addedLoggerIds(ContainerBuilder $container): array {
    $ids = [];
    foreach ($container->getDefinition('audit_chain.stream')->getMethodCalls() as $call) {
      if ($call[0] === 'addLogger') {
        $ids[] = (string) $call[1][0];
      }
    }
    return $ids;
  }

  /**
   * Logger backends attached to the SIEM stream (LoggerChannel::$loggers).
   *
   * LoggerChannel has no public getter in Drupal 10.6/11.3. The property is
   * the compiled result of AuditChainServiceProvider and is what we need
   * to prove dblog was excluded.
   *
   * @return list<\Psr\Log\LoggerInterface>
   *   Attached backends, flattened across priorities.
   */
  private function streamBackends(): array {
    $stream = $this->container->get('audit_chain.stream');
    $this->assertInstanceOf(LoggerChannel::class, $stream);
    $property = new \ReflectionProperty(LoggerChannel::class, 'loggers');
    $property->setAccessible(TRUE);
    $grouped = $property->getValue($stream);
    $this->assertIsArray($grouped);
    $flat = [];
    foreach ($grouped as $loggers) {
      foreach ($loggers as $logger) {
        $flat[] = $logger;
      }
    }
    return $flat;
  }

  /**
   * Enables dblog and installs {watchdog}.
   */
  private function enableDblog(): void {
    $this->enableModules(['dblog']);
    $this->installSchema('dblog', ['watchdog']);
  }

  /**
   * Replaces logger.channel.audit_chain and rebuilds the chain logger.
   *
   * @return object{records: array<int, array{level: mixed, message: string, context: array}>}
   *   The spy. Public $records is a list of captured log calls.
   */
  private function installAuditChainChannelSpy(): object {
    $spy = new class() extends AbstractLogger {

      /**
       * Captured channel records.
       *
       * @var array<int, array{level: mixed, message: string, context: array}>
       */
      public array $records = [];

      /**
       * {@inheritdoc}
       */
      public function log($level, string|\Stringable $message, array $context = []): void {
        $this->records[] = [
          'level' => $level,
          'message' => (string) $message,
          'context' => $context,
        ];
      }

    };
    $this->container->set('logger.channel.audit_chain', $spy);
    $this->container->set('audit_chain.logger', NULL);
    return $spy;
  }

  /**
   * Channel records whose message template equals a needle.
   *
   * @param object{records: array<int, array{level: mixed, message: string, context: array}>} $spy
   *   The spy installed by installAuditChainChannelSpy().
   * @param string $message
   *   Exact message template.
   *
   * @return list<array{level: mixed, message: string, context: array}>
   *   Matching records in capture order.
   */
  private function channelEvents(object $spy, string $message): array {
    return array_values(array_filter(
      $spy->records,
      static fn (array $record): bool => $record['message'] === $message,
    ));
  }

  /**
   * Replaces the operational channel so happy-path appends can be proven quiet.
   *
   * @return object{records: array<int, array{level: mixed, message: string}>}
   *   The spy. Public $records is a list of captured log calls.
   */
  private function installOpsChannelSpy(): object {
    $spy = new class() extends AbstractLogger {

      /**
       * Captured operational-channel records.
       *
       * @var array<int, array{level: mixed, message: string}>
       */
      public array $records = [];

      /**
       * {@inheritdoc}
       */
      public function log($level, string|\Stringable $message, array $context = []): void {
        $this->records[] = [
          'level' => $level,
          'message' => (string) $message,
        ];
      }

    };
    $this->container->set('logger.channel.audit_chain', $spy);
    $this->container->set('audit_chain.logger', NULL);
    return $spy;
  }

  /**
   * Stored chain rows in insert order.
   *
   * @return list<object>
   *   Row objects.
   */
  private function chainRows(): array {
    return $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l')
      ->orderBy('id', 'ASC')
      ->execute()
      ->fetchAll();
  }

  /**
   * Watchdog rows whose message template contains a needle.
   *
   * @param string $needle
   *   A substring of the stored message template.
   *
   * @return list<object>
   *   Matching {watchdog} rows.
   */
  private function watchdogContaining(string $needle): array {
    $rows = $this->container->get('database')
      ->select('watchdog', 'w')
      ->fields('w')
      ->execute()
      ->fetchAll();
    return array_values(array_filter(
      $rows,
      static fn (object $row): bool => str_contains((string) $row->message, $needle),
    ));
  }

}
