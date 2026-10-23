<?php

declare(strict_types=1);

namespace Drupal\Tests\audit_chain\Kernel;

use Drupal\audit_chain\AuditChainLogger;
use Drupal\audit_chain\AuditChainServiceProvider;
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
 * Streamed appends must not flood Database Logging.
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
   * With streaming on and dblog enabled, appends write no watchdog event rows.
   *
   * Would fail if append still called logger.channel.audit_chain->info():
   * that channel fans out to dblog and each write becomes a {watchdog} row.
   */
  public function testStreamedAppendDoesNotWriteWatchdogRows(): void {
    $this->enableDblog();
    $this->config('audit_chain.settings')->set('stream_enabled', TRUE)->save();

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
    $this->config('audit_chain.settings')->set('stream_enabled', TRUE)->save();
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
