<?php

declare(strict_types=1);

namespace Drupal\Tests\audit_chain\Kernel;

use Psr\Log\AbstractLogger;
use Drupal\audit_chain\AuditChainLogger;
use Drupal\audit_chain\AuditChainLoggerInterface;
use Drupal\audit_chain\Exception\AuditChainAppendException;
use Drupal\audit_chain\Exception\AuditChainSigningUnavailableException;
use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Database\Connection;
use Drupal\Core\Database\Database;
use Drupal\Core\Database\DatabaseExceptionWrapper;
use Drupal\encrypt\EncryptServiceInterface;
use Drupal\encrypt\Entity\EncryptionProfile;
use Drupal\KernelTests\KernelTestBase;
use Drupal\key\Entity\Key;
use Symfony\Component\Process\Process;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Kernel tests for the tamper-evident chain.
 *
 * @coversDefaultClass \Drupal\audit_chain\AuditChainLogger
 * @group audit_chain
 *
 * @runTestsInSeparateProcesses
 */
#[CoversClass(\Drupal\audit_chain\AuditChainLogger::class)]
#[Group('audit_chain')]
#[RunTestsInSeparateProcesses]
final class AuditChainLoggerTest extends KernelTestBase {

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
   * The logger under test.
   */
  private AuditChainLoggerInterface $chain;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installAuditChainTables();
    $this->installConfig(['audit_chain']);
    $this->chain = $this->container->get('audit_chain.logger');
  }

  /**
   * Missing mutex refuses ordinary log() and writes nothing.
   */
  public function testMissingMutexRefusesAppend(): void {
    $this->container->get('database')->delete('audit_chain_mutex')->execute();
    try {
      $this->chain->log('test', 'missing_mutex');
      $this->fail('log() must refuse a missing serialization row.');
    }
    catch (AuditChainAppendException $exception) {
      $this->assertStringContainsString('serialization row is missing', $exception->getMessage());
    }
    $this->assertCount(0, $this->rows());
  }

  /**
   * Keyed append also refuses a missing mutex and writes nothing (#3623694).
   */
  public function testKeyedAppendRefusesMissingMutex(): void {
    $this->makeKey('mutex_test_key', 'synthetic-test-key');
    $this->config('audit_chain.settings')->set('hash_key', 'mutex_test_key')->save();
    $this->container->get('database')->delete('audit_chain_mutex')->execute();
    try {
      $this->chain->logKeyed('mcp_sentinel', 'evidence_precommit', ['id' => '1']);
      $this->fail('logKeyed() must refuse a missing serialization row.');
    }
    catch (AuditChainAppendException $exception) {
      $this->assertStringContainsString('serialization row is missing', $exception->getMessage());
    }
    $this->assertCount(0, $this->rows());
  }

  /**
   * Caller rollback removes nested appends and permits the next write.
   */
  public function testCallerRollbackRemovesNestedAppends(): void {
    $transaction = $this->container->get('database')->startTransaction();
    $this->chain->log('test', 'first');
    $this->chain->log('test', 'second');
    $this->assertCount(2, $this->rows());
    $transaction->rollBack();
    unset($transaction);
    $this->assertCount(0, $this->rows());
    $this->chain->log('test', 'after_rollback');
    $this->assertCount(1, $this->rows());
    $this->assertNull($this->rows()[0]->prev_hash);
    $this->assertTrue($this->chain->verify()['ok']);
  }

  /**
   * A failed chain read rolls back and leaves the prior chain intact.
   */
  public function testReadFailureDoesNotLeaveTransactionOpen(): void {
    $database = $this->container->get('database');
    $this->chain->log('test', 'before_failure');
    $database->schema()->renameTable('audit_chain_log', 'audit_chain_log_saved');
    try {
      $this->chain->log('test', 'insert_failure');
      $this->fail('A missing audit table must refuse append.');
    }
    catch (DatabaseExceptionWrapper) {
      $this->assertFalse($database->inTransaction());
    }
    finally {
      $database->schema()->renameTable('audit_chain_log_saved', 'audit_chain_log');
    }
    $this->chain->log('test', 'after_failure');
    $this->assertCount(2, $this->rows());
    $this->assertTrue($this->chain->verify()['ok']);
  }

  /**
   * An uncommitted append holds the mutex against another connection.
   *
   * SQLite in-memory connections do not share a database, so this cannot
   * express the race there. MySQL/PostgreSQL kernel runs (d.o GitLab) do.
   */
  public function testUncommittedAppendBlocksSecondConnection(): void {
    $database = $this->container->get('database');
    if ($database->databaseType() === 'sqlite') {
      $this->markTestSkipped('SQLite in-memory cannot share a mutex across connections.');
    }

    $this->chain->log('test', 'committed_head');
    $transaction = $database->startTransaction();
    $this->chain->log('test', 'uncommitted');

    $info = Database::getConnectionInfo('default');
    Database::addConnectionInfo('audit_chain_other', 'default', $info['default']);
    $other = Database::getConnection('default', 'audit_chain_other');
    $this->setLockTimeout($other, 1);
    $otherLogger = $this->loggerForConnection($other);

    try {
      $otherLogger->log('test', 'competitor');
      $this->fail('Competing append must not proceed while the mutex is held.');
    }
    catch (DatabaseExceptionWrapper | AuditChainAppendException) {
      // Lock wait timeout or a wrapped refusal — either is fail-closed.
    }

    $otherCount = (int) $other->select('audit_chain_log', 'l')
      ->countQuery()
      ->execute()
      ->fetchField();
    $this->assertSame(1, $otherCount, 'Competitor must not insert a fork.');

    unset($transaction);

    $otherLogger->log('test', 'competitor');
    $this->assertTrue($this->chain->verify()['ok']);
    $rows = $this->rows();
    $this->assertCount(3, $rows);
    $this->assertSame($rows[1]->row_hash, $rows[2]->prev_hash);
  }

  /**
   * An unavailable serialization table refuses both append entrypoints.
   */
  public function testMissingMutexTableRefusesAppend(): void {
    $this->makeKey('mutex_table_key', 'synthetic-test-key');
    $this->config('audit_chain.settings')->set('hash_key', 'mutex_table_key')->save();
    $this->container->get('database')->schema()->dropTable('audit_chain_mutex');
    foreach (['log', 'logKeyed'] as $method) {
      try {
        $this->chain->{$method}('test', 'missing_mutex_table');
        $this->fail('Append must refuse a missing serialization table.');
      }
      catch (DatabaseExceptionWrapper) {
        $this->assertFalse($this->container->get('database')->inTransaction());
      }
      $this->assertCount(0, $this->rows());
    }
  }

  /**
   * The upgrade is repeatable and does not rewrite any existing audit record.
   */
  public function testSerializationUpdatePreservesHistory(): void {
    $this->chain->log('test', 'before_update');
    $before = $this->rows();
    $this->container->get('database')->schema()->dropTable('audit_chain_mutex');
    $this->container->get('module_handler')->loadInclude('audit_chain', 'install');
    audit_chain_update_10003();
    audit_chain_update_10003();
    $this->assertEquals($before, $this->rows());
    $this->chain->log('test', 'after_update');
    $this->assertCount(2, $this->rows());
    $this->assertTrue($this->chain->verify()['ok']);
  }

  /**
   * Separate processes stay serialized until the outer transaction commits.
   */
  public function testConcurrentOuterCommit(): void {
    $this->assertConcurrentAppend(FALSE);
  }

  /**
   * A waiting process continues from the committed head after caller rollback.
   */
  public function testConcurrentOuterRollback(): void {
    $this->assertConcurrentAppend(TRUE);
  }

  /**
   * Returns all stored rows in insertion order.
   *
   * @return array<int, object>
   *   The rows.
   */
  private function rows(): array {
    return $this->container->get('database')
      ->select('audit_chain_log', 'l')
      ->fields('l')
      ->orderBy('id')
      ->execute()
      ->fetchAll();
  }

  /**
   * An entry is stored with its channel, operation and promoted columns.
   */
  public function testEntryIsStoredWithPromotedColumns(): void {
    $this->chain->log('personnel', 'field_read', [
      'entity_type' => 'node',
      'bundle' => 'person',
      'id' => '42',
      'label' => 'A. Person',
      'field' => 'field_salary',
    ]);

    $rows = $this->rows();
    $this->assertCount(1, $rows);
    $this->assertSame('personnel', $rows[0]->channel);
    $this->assertSame('field_read', $rows[0]->operation);
    $this->assertSame('node', $rows[0]->entity_type);
    $this->assertSame('42', $rows[0]->entity_id);
    $this->assertSame('A. Person', $rows[0]->entity_label);
    $this->assertSame(
      ['field' => 'field_salary'],
      $this->chain->decodeMetadata((string) $rows[0]->metadata),
      'Unpromoted keys land in metadata.',
    );
  }

  /**
   * An untouched chain verifies, including across channels.
   */
  public function testIntactChainVerifies(): void {
    $this->chain->log('mcp_sentinel', 'entity_save', ['id' => '1']);
    $this->chain->log('personnel', 'field_read', ['id' => '2']);
    $this->chain->log('mcp_sentinel', 'entity_delete', ['id' => '3']);

    $result = $this->chain->verify();
    $this->assertTrue($result['ok']);
    $this->assertNull($result['broken_at']);
    $this->assertNull($result['reason']);
    $this->assertSame(0, $result['unkeyed_rows']);
  }

  /**
   * Editing a stored row is detected.
   */
  public function testEditedRowBreaksTheChain(): void {
    $this->chain->log('personnel', 'field_read', ['id' => '1']);
    $this->chain->log('personnel', 'field_read', ['id' => '2']);

    $this->container->get('database')->update('audit_chain_log')
      ->fields(['operation' => 'something_else'])
      ->condition('id', 1)
      ->execute();

    $result = $this->chain->verify();
    $this->assertFalse($result['ok']);
    $this->assertSame(1, $result['broken_at']);
  }

  /**
   * Deleting a row is detected at the seam it leaves.
   */
  public function testDeletedRowBreaksTheChain(): void {
    $this->chain->log('personnel', 'field_read', ['id' => '1']);
    $this->chain->log('personnel', 'field_read', ['id' => '2']);
    $this->chain->log('personnel', 'field_read', ['id' => '3']);

    $this->container->get('database')->delete('audit_chain_log')
      ->condition('id', 2)
      ->execute();

    $result = $this->chain->verify();
    $this->assertFalse($result['ok']);
    $this->assertSame(3, $result['broken_at'], 'The row after the gap no longer points at its predecessor.');
  }

  /**
   * Re-attributing a row to another channel is detected.
   *
   * The channel is bound into the hash precisely so a row cannot be moved
   * between consumers after the fact — otherwise an entry could be relabelled
   * out of the channel someone is auditing.
   */
  public function testChannelIsCoveredByTheHash(): void {
    $this->chain->log('personnel', 'field_read', ['id' => '1']);

    $this->container->get('database')->update('audit_chain_log')
      ->fields(['channel' => 'something_harmless'])
      ->condition('id', 1)
      ->execute();

    $this->assertFalse($this->chain->verify()['ok']);
  }

  /**
   * Forensic columns are covered too.
   */
  public function testForensicColumnsAreCoveredByTheHash(): void {
    $this->chain->log('personnel', 'field_read', ['id' => '1', 'label' => 'Original']);

    $this->container->get('database')->update('audit_chain_log')
      ->fields(['entity_label' => 'Rewritten'])
      ->condition('id', 1)
      ->execute();

    $this->assertFalse($this->chain->verify()['ok']);
  }

  /**
   * The chain is bound to the key material, not merely to the algorithm.
   *
   * Verifying under a different key must fail. That is what stops someone with
   * database access from editing a row and recomputing the chain over it: an
   * unkeyed chain can be rebuilt by anyone who can write to the table, a keyed
   * one cannot without the key.
   *
   * The check swaps the configured Key *entity* rather than mutating one key's
   * value, because the Key repository caches a resolved key for the request —
   * mutating it in-process leaves verification using the old value and the test
   * passes for the wrong reason.
   */
  public function testChainIsBoundToTheKeyMaterial(): void {
    foreach (['chain_key' => 'correct-horse-battery-staple', 'other_key' => 'a-different-secret'] as $id => $value) {
      Key::create([
        'id' => $id,
        'label' => $id,
        'key_type' => 'authentication',
        'key_provider' => 'config',
        'key_provider_settings' => ['key_value' => $value],
      ])->save();
    }

    $this->config('audit_chain.settings')->set('hash_key', 'chain_key')->save();
    $this->chain->log('personnel', 'field_read', ['id' => '1']);
    $this->assertTrue($this->chain->verify()['ok'], 'Verifies under the key it was written with.');

    $this->config('audit_chain.settings')->set('hash_key', 'other_key')->save();
    $this->assertFalse($this->chain->verify()['ok'], 'Does not verify under a different key.');

    $this->config('audit_chain.settings')->set('hash_key', '')->save();
    $this->assertFalse($this->chain->verify()['ok'], 'Does not verify unkeyed either.');
  }

  /**
   * Creates a Key entity.
   *
   * @param string $id
   *   The entity ID.
   * @param string $value
   *   The secret value.
   */
  private function makeKey(string $id, string $value): void {
    Key::create([
      'id' => $id,
      'label' => $id,
      'key_type' => 'authentication',
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => $value],
    ])->save();
  }

  /**
   * Builds a logger that writes through a second database connection.
   */
  private function loggerForConnection(Connection $connection): AuditChainLogger {
    return new AuditChainLogger(
      $connection,
      $this->container->get('current_user'),
      $this->container->get('request_stack'),
      $this->container->get('config.factory'),
      $this->container->get('datetime.time'),
      $this->container->get('key.repository'),
      $this->container->get('logger.channel.audit_chain'),
      $this->container->get('encryption'),
      $this->container->get('entity_type.manager'),
      $this->container->get('state'),
    );
  }

  /**
   * Caps lock-wait so a blocked second connection fails instead of hanging.
   */
  private function setLockTimeout(Connection $connection, int $seconds): void {
    switch ($connection->databaseType()) {
      case 'mysql':
        $connection->query('SET SESSION innodb_lock_wait_timeout = ' . $seconds);
        break;

      case 'pgsql':
        $connection->query("SET lock_timeout = '" . ($seconds * 1000) . "ms'");
        break;
    }
  }

  /**
   * Runs real database writers with independent process connections.
   */
  private function assertConcurrentAppend(bool $rollback): void {
    $database = $this->container->get('database');
    if (!in_array($database->driver(), ['pgsql', 'mysql'], TRUE)) {
      $this->markTestSkipped('Cross-process tests require PostgreSQL or MySQL.');
    }
    $this->makeKey('serialization_test', 'synthetic-serialization-key');
    $this->config('audit_chain.settings')->set('hash_key', 'serialization_test')->save();
    $prefix = sys_get_temp_dir() . '/audit-concurrency-' . bin2hex(random_bytes(8));
    $ready = $prefix . '-ready';
    $release = $prefix . '-release';
    $started = $prefix . '-started';
    $fixture = dirname(__DIR__, 2) . '/fixtures/append-worker.php';
    $vendor = $this->vendorDir();
    $first = new Process([PHP_BINARY, $fixture, $this->root, $vendor]);
    $second = new Process([PHP_BINARY, $fixture, $this->root, $vendor]);
    $first->setTimeout(30);
    $second->setTimeout(30);
    $namespaces = [
      'Drupal\\key\\' => dirname((new \ReflectionClass(Key::class))->getFileName(), 2),
      'Drupal\\encrypt\\' => dirname((new \ReflectionClass(EncryptServiceInterface::class))->getFileName()),
    ];
    $options = $database->getConnectionOptions();
    $first->setInput(json_encode([
      'namespaces' => $namespaces,
      'database' => $options,
      'operation' => 'first',
      'ready' => $ready,
      'release' => $release,
      'rollback' => $rollback,
    ], JSON_THROW_ON_ERROR));
    $second->setInput(json_encode([
      'namespaces' => $namespaces,
      'database' => $options,
      'operation' => 'second',
      'started' => $started,
    ], JSON_THROW_ON_ERROR));
    try {
      $first->start();
      $this->waitForWorker($first, $ready);
      $second->start();
      $this->waitForWorker($second, $started);
      // Outlast the old three-second external lease while the caller holds
      // its transaction. The second writer must still be waiting to append.
      usleep(3300000);
      $this->assertTrue($second->isRunning(), 'The second append returned before the caller transaction ended.');
    }
    finally {
      file_put_contents($release, 'release');
      if ($first->isStarted()) {
        $first->wait();
      }
      if ($second->isStarted()) {
        $second->wait();
      }
      foreach ([$ready, $release, $started] as $path) {
        if (is_file($path)) {
          unlink($path);
        }
      }
    }
    $this->assertSame(0, $first->getExitCode(), $first->getErrorOutput() . $first->getOutput());
    $this->assertSame(0, $second->getExitCode(), $second->getErrorOutput() . $second->getOutput());
    $rows = $this->rows();
    $this->assertCount($rollback ? 1 : 2, $rows);
    $this->assertSame('second', $rows[count($rows) - 1]->operation);
    $this->assertTrue($this->chain->verify()['ok']);
  }

  /**
   * Waits for a worker checkpoint without hiding an early process failure.
   */
  private function waitForWorker(Process $process, string $path): void {
    $deadline = microtime(TRUE) + 10;
    while (!is_file($path)) {
      if (!$process->isRunning() || microtime(TRUE) >= $deadline) {
        $this->fail('Worker did not reach its checkpoint: ' . $process->getErrorOutput() . $process->getOutput());
      }
      usleep(20000);
    }
  }

  /**
   * Locates vendor/autoload.php from the kernel Drupal root.
   */
  private function vendorDir(): string {
    foreach ([dirname($this->root) . '/vendor', $this->root . '/vendor'] as $dir) {
      if (is_file($dir . '/autoload.php')) {
        return $dir;
      }
    }
    throw new \RuntimeException('Could not locate vendor/autoload.php.');
  }

  /**
   * A configured key that will not resolve is reported, not silently dropped.
   *
   * The chain still records the entry — dropping an audit row is a worse
   * failure than an unsigned one — but it must say so. Until this fix the
   * fallback to unkeyed SHA-256 was completely silent, which is how a real
   * deployment wrote 1,997 unsigned rows while believing they were signed.
   */
  public function testUnresolvableKeyIsReportedAndRowIsWrittenUnkeyed(): void {
    $this->config('audit_chain.settings')->set('hash_key', 'no_such_key')->save();

    $spy = new class() extends AbstractLogger {
      /**
       * Captured log records.
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

    $this->container->get('audit_chain.logger')->log('personnel', 'field_read', ['id' => '1']);

    $rows = $this->rows();
    $this->assertCount(1, $rows, 'The entry is still recorded.');
    $this->assertSame('', (string) $rows[0]->key_id, 'The row records that it was hashed unkeyed.');

    $errors = array_filter($spy->records, static fn(array $r): bool => $r['level'] === 'error');
    $this->assertNotEmpty($errors, 'An unresolvable signing key must be logged as an error.');

    // Asserted on the template and its context separately, because that is what
    // Drupal actually stores: a stable message with the variable data beside
    // it, so aggregators can group by template.
    $error = reset($errors);
    $this->assertStringContainsString('cannot be resolved', $error['message']);
    $this->assertSame('no_such_key', $error['context']['@key'] ?? NULL);
  }

  /**
   * Rows written unkeyed are reported as unsigned, not as tampering.
   *
   * This is the diagnosis that sent someone hunting for an intruder: with the
   * key present, verification recomputed historical unkeyed rows under HMAC and
   * announced "BROKEN at row 1 — an entry has been inserted or edited".
   * Nothing had been edited.
   */
  public function testRowsWrittenUnkeyedAreNotReportedAsTampering(): void {
    // Two rows written with no key configured.
    $this->chain->log('personnel', 'field_read', ['id' => '1']);
    $this->chain->log('personnel', 'field_read', ['id' => '2']);

    // The key now resolves, as it would after the environment is fixed.
    $this->makeKey('chain_key', 'correct-horse-battery-staple');
    $this->config('audit_chain.settings')->set('hash_key', 'chain_key')->save();

    $result = $this->chain->verify();
    $this->assertFalse($result['ok'], 'An unsigned chain is still a finding.');
    $this->assertSame(AuditChainLogger::REASON_WRITTEN_UNKEYED, $result['reason']);
    $this->assertNull($result['broken_at'], 'Nothing was tampered with, so no row is named as broken.');
    $this->assertSame(2, $result['unkeyed_rows']);
    $this->assertSame(2, $result['unkeyed_through']);
  }

  /**
   * Editing a row is still tampering even when earlier rows are unsigned.
   *
   * The unkeyed diagnosis must not become a hiding place: a chain that contains
   * unsigned rows still has to report a genuine edit as an edit.
   */
  public function testTamperingIsStillDetectedAlongsideUnkeyedRows(): void {
    $this->chain->log('personnel', 'field_read', ['id' => '1']);
    $this->chain->log('personnel', 'field_read', ['id' => '2']);

    $this->makeKey('chain_key', 'correct-horse-battery-staple');
    $this->config('audit_chain.settings')->set('hash_key', 'chain_key')->save();

    $this->container->get('database')->update('audit_chain_log')
      ->fields(['operation' => 'something_else'])
      ->condition('id', 2)
      ->execute();

    $result = $this->chain->verify();
    $this->assertFalse($result['ok']);
    $this->assertSame(AuditChainLogger::REASON_TAMPERED, $result['reason']);
    $this->assertSame(2, $result['broken_at']);
  }

  /**
   * A retired key listed in configuration keeps its rows verifying.
   *
   * Without this, rotating the signing key — ordinary hygiene, and something a
   * compliance regime may mandate on a schedule — makes every previously
   * written row indistinguishable from tampering.
   */
  public function testRotatedKeyStillVerifiesEarlierRows(): void {
    $this->makeKey('old_key', 'the-first-secret');
    $this->makeKey('new_key', 'the-second-secret');

    $this->config('audit_chain.settings')->set('hash_key', 'old_key')->save();
    $this->chain->log('personnel', 'field_read', ['id' => '1']);

    // Rotate without recording the old key: the old row now looks tampered.
    $this->config('audit_chain.settings')->set('hash_key', 'new_key')->save();
    $this->chain->log('personnel', 'field_read', ['id' => '2']);
    $this->assertFalse($this->chain->verify()['ok'], 'A bare rotation orphans the earlier rows.');

    // Recording the retired key restores verification of its segment.
    $this->config('audit_chain.settings')->set('previous_hash_keys', ['old_key'])->save();
    $result = $this->chain->verify();
    $this->assertTrue($result['ok'], 'Each row verifies under the key that produced it.');
    $this->assertSame(0, $result['unkeyed_rows']);
  }

  /**
   * The recorded key_id is a hint, never authority.
   *
   * The key_id column cannot be covered by the row hash without invalidating
   * rows written before it existed, so it sits in the table unprotected. If
   * verification trusted it, anyone able to write to the log could blank it,
   * recompute the row with plain SHA-256, and have their edit accepted —
   * handing back precisely the forgery resistance the HMAC exists to provide.
   */
  public function testBlankingKeyIdCannotLaunderAnEditedRow(): void {
    $this->makeKey('chain_key', 'correct-horse-battery-staple');
    $this->config('audit_chain.settings')->set('hash_key', 'chain_key')->save();
    $this->chain->log('personnel', 'field_read', ['id' => '1']);
    $this->assertTrue($this->chain->verify()['ok']);

    $database = $this->container->get('database');

    // Forge exactly as an attacker with database access would: rewrite the
    // content, recompute the hash with plain SHA-256, and blank key_id so the
    // row claims it was never signed in the first place. The canonical payload
    // is rebuilt from the row's own stored columns so the forgery is a correct
    // one — a sloppy forgery would fail for the wrong reason and prove nothing.
    $database->update('audit_chain_log')
      ->fields(['operation' => 'something_else'])
      ->condition('id', 1)
      ->execute();

    $row = (array) $this->rows()[0];
    $canonical = [
      'bundle' => $row['bundle'],
      'entity_id' => (string) ($row['entity_id'] ?? ''),
      'entity_label' => $row['entity_label'],
      'entity_type' => $row['entity_type'],
      'ip_address' => $row['ip_address'],
      'metadata' => $this->chain->decodeMetadata((string) ($row['metadata'] ?? '')),
      'operation' => (string) $row['operation'],
      'timestamp' => (int) $row['timestamp'],
      'uid' => (int) $row['uid'],
      'user_agent' => $row['user_agent'],
      'channel' => (string) $row['channel'],
    ];
    ksort($canonical);
    $encoded = (string) json_encode($canonical, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

    $database->update('audit_chain_log')
      ->fields([
        'key_id' => '',
        'row_hash' => hash('sha256', '|' . $encoded),
      ])
      ->condition('id', 1)
      ->execute();

    $result = $this->chain->verify();
    $this->assertFalse($result['ok'], 'A forged row must never verify.');
    $this->assertSame(
      AuditChainLogger::REASON_WRITTEN_UNKEYED,
      $result['reason'],
      'It is reported as unsigned rather than accepted — the operator still gets a non-zero verdict.',
    );
  }

  /**
   * Metadata that is not valid UTF-8 still produces a verifiable row.
   *
   * Found on a real chain: five rows verified under no key at all while the
   * other 1,997 verified unkeyed, and every one of the five had an empty
   * metadata column. json_encode() returns FALSE on a single malformed byte,
   * the (string) cast turned that into '', and both the stored metadata and the
   * canonical payload became empty — so the row was hashed over nothing and
   * could never verify again. A truncated multibyte character in one field
   * value was enough, and nothing reported it.
   */
  public function testInvalidUtf8MetadataStillVerifies(): void {
    // A lone continuation byte: what a truncated multibyte value looks like.
    $this->chain->log('personnel', 'field_read', ['id' => '1', 'note' => "caf\xE9"]);
    $this->chain->log('personnel', 'field_read', ['id' => '2']);

    $rows = $this->rows();
    $this->assertNotSame(
      '',
      (string) $rows[0]->metadata,
      'Unencodable metadata must not collapse to an empty column.',
    );

    $result = $this->chain->verify();
    $this->assertTrue($result['ok'], 'A row carrying invalid UTF-8 must still verify.');
    $this->assertSame(0, $result['unkeyed_rows']);
  }

  /**
   * A retired encryption profile is reported, not left to be discovered.
   *
   * Rotating a profile is ordinary key hygiene and silently orphans everything
   * written under the previous one. Nothing looks broken — the rows are there
   * and the chain still verifies, because the chain covers the plaintext — so
   * the loss surfaces only when someone opens an old entry. Which is exactly
   * the moment an audit trail is supposed to work.
   */
  public function testRotatedEncryptionProfileIsReportedOnTheStatusReport(): void {
    $this->container->get('module_handler')->loadInclude('audit_chain', 'install');

    // Nothing written yet: no finding.
    $requirements = audit_chain_requirements('runtime');
    $this->assertArrayNotHasKey('audit_chain_encryption_rotated', $requirements);

    // A row written under no profile is plaintext, not a rotation.
    $this->chain->log('personnel', 'field_read', ['id' => '1', 'note' => 'plain']);
    $this->assertSame('', (string) $this->rows()[0]->encryption_profile);
    $requirements = audit_chain_requirements('runtime');
    $this->assertArrayNotHasKey(
      'audit_chain_encryption_rotated',
      $requirements,
      'Plaintext rows are not a retired profile.',
    );

    // Simulate a row written under a profile that is no longer configured.
    // Written directly rather than by configuring a real EncryptionProfile and
    // deleting it: the column is what the check reads, and this keeps the test
    // about the detection rather than about the encrypt module's fixtures.
    $this->container->get('database')->update('audit_chain_log')
      ->fields(['encryption_profile' => 'retired_profile'])
      ->condition('id', 1)
      ->execute();

    $requirements = audit_chain_requirements('runtime');
    $this->assertArrayHasKey('audit_chain_encryption_rotated', $requirements);
    $this->assertSame(
      REQUIREMENT_WARNING,
      $requirements['audit_chain_encryption_rotated']['severity'],
      'The entries are intact and the chain still verifies, so this is not an error.',
    );
    $this->assertStringContainsString(
      'retired_profile',
      (string) $requirements['audit_chain_encryption_rotated']['value'],
      'The finding must name the profile the operator has to restore.',
    );
  }

  /**
   * Creates a test encryption profile (encrypt_test method, 128-bit key).
   *
   * @param string $id
   *   Profile (and key) machine name prefix.
   *
   * @return string
   *   The encryption profile entity id.
   */
  private function createTestEncryptionProfile(string $id): string {
    // Distinct 16-byte keys per profile (encrypt_test method requires 128-bit).
    static $n = 0;
    $n++;
    $keyValue = sprintf('testkey%08d!!', $n);

    Key::create([
      'id' => $id . '_key',
      'label' => $id . ' key',
      'key_type' => 'encryption',
      'key_type_settings' => ['key_size' => '128'],
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => $keyValue],
    ])->save();

    EncryptionProfile::create([
      'id' => $id,
      'label' => $id,
      'encryption_method' => 'test_encryption_method',
      'encryption_key' => $id . '_key',
    ])->save();

    return $id;
  }

  /**
   * Re-encrypt rewrites ciphertext without invalidating the hash chain.
   *
   * @covers ::reencrypt
   * @covers ::decodeMetadata
   */
  public function testReencryptMovesRowsBetweenProfilesWithoutBreakingVerify(): void {
    $from = $this->createTestEncryptionProfile('ac_from');
    $to = $this->createTestEncryptionProfile('ac_to');

    $this->config('audit_chain.settings')->set('encryption_profile', $from)->save();
    $this->chain->log('personnel', 'field_read', [
      'id' => '7',
      'secret' => 'need-to-read-after-rotation',
    ]);

    $before = $this->rows()[0];
    $this->assertSame($from, (string) $before->encryption_profile);
    $cipherBefore = (string) $before->metadata;
    $hashBefore = (string) $before->row_hash;

    // Rotate config first (operator hygiene) then re-encrypt historical rows.
    $this->config('audit_chain.settings')->set('encryption_profile', $to)->save();

    $result = $this->chain->reencrypt($from, $to);
    $this->assertNull($result['refused']);
    $this->assertSame(1, $result['updated']);
    $this->assertSame(0, $result['failed']);
    $this->assertSame(0, $result['remaining']);

    $after = $this->rows()[0];
    $this->assertSame($to, (string) $after->encryption_profile);
    $this->assertNotSame($cipherBefore, (string) $after->metadata, 'Ciphertext must change.');
    $this->assertSame($hashBefore, (string) $after->row_hash, 'Hash must not be rewritten.');

    $meta = $this->chain->decodeMetadata((string) $after->metadata, (string) $after->encryption_profile);
    $this->assertSame('need-to-read-after-rotation', $meta['secret'] ?? NULL);

    $verify = $this->chain->verify();
    $this->assertTrue($verify['ok'], 'Chain must still verify after re-encrypt.');
  }

  /**
   * Re-encrypt refuses when a profile cannot be loaded.
   *
   * @covers ::reencrypt
   */
  public function testReencryptRefusesMissingProfile(): void {
    $result = $this->chain->reencrypt('missing_a', 'missing_b');
    $this->assertNotNull($result['refused']);
    $this->assertSame(0, $result['updated']);
  }

  /**
   * Sealing an unkeyed prefix lets verify exit cleanly without re-chaining.
   *
   * @covers ::sealPrefix
   * @covers ::verify
   * @covers ::getSeal
   */
  public function testSealUnkeyedPrefixThenPostSealRowsVerify(): void {
    // Historical segment written without a key.
    $this->chain->log('personnel', 'field_read', ['id' => '1']);
    $this->chain->log('personnel', 'field_read', ['id' => '2']);

    $this->makeKey('chain_key', 'correct-horse-battery-staple');
    $this->config('audit_chain.settings')->set('hash_key', 'chain_key')->save();

    $before = $this->chain->verify();
    $this->assertFalse($before['ok']);
    $this->assertSame(AuditChainLogger::REASON_WRITTEN_UNKEYED, $before['reason']);
    $this->assertSame(2, $before['unkeyed_through']);

    $seal = $this->chain->sealPrefix(2, 'pre-key production segment');
    $this->assertTrue($seal['sealed'], $seal['message']);
    $this->assertNotNull($this->chain->getSeal());

    // Seal writes its own audit row under the now-configured key.
    $this->chain->log('personnel', 'field_read', ['id' => '3']);

    $after = $this->chain->verify();
    $this->assertTrue($after['ok'], 'Sealed prefix + keyed post-seal must verify.');
    $this->assertTrue($after['seal_intact']);
    $this->assertSame(2, $after['sealed_through']);
    $this->assertNotNull($after['verified_from']);
    $this->assertGreaterThan(2, $after['verified_from']);
    $this->assertSame(0, $after['unkeyed_rows']);

    $this->container->get('module_handler')->loadInclude('audit_chain', 'install');
    $requirements = audit_chain_requirements('runtime');
    $this->assertArrayHasKey('audit_chain_prefix_seal', $requirements);
    $this->assertSame(REQUIREMENT_WARNING, $requirements['audit_chain_prefix_seal']['severity']);
  }

  /**
   * Editing a sealed row is detected as a broken seal, not re-chained away.
   *
   * @covers ::sealPrefix
   * @covers ::verify
   */
  public function testEditingSealedPrefixBreaksTheSeal(): void {
    $this->chain->log('personnel', 'field_read', ['id' => '1']);
    $this->chain->log('personnel', 'field_read', ['id' => '2']);
    $this->makeKey('chain_key', 'correct-horse-battery-staple');
    $this->config('audit_chain.settings')->set('hash_key', 'chain_key')->save();
    $this->assertTrue($this->chain->sealPrefix(2, 'freeze')['sealed']);

    $this->container->get('database')->update('audit_chain_log')
      ->fields(['row_hash' => str_repeat('a', 64)])
      ->condition('id', 1)
      ->execute();

    $result = $this->chain->verify();
    $this->assertFalse($result['ok']);
    $this->assertSame(AuditChainLogger::REASON_SEAL_BROKEN, $result['reason']);
    $this->assertFalse($result['seal_intact']);
  }

  /**
   * A copied seal signed by another environment is not reported as tampering.
   *
   * @covers ::sealPrefix
   * @covers ::verify
   */
  public function testForeignSealIsDistinctFromBrokenSeal(): void {
    // Model production history that was unsigned before a production-only key
    // was configured and used to seal it.
    $this->chain->log('personnel', 'field_read', ['id' => '1']);
    $this->chain->log('personnel', 'field_read', ['id' => '2']);
    $this->makeKey('production_key', 'production-secret');
    $this->config('audit_chain.settings')->set('hash_key', 'production_key')->save();
    $this->assertTrue($this->chain->sealPrefix(2, 'freeze')['sealed']);

    // A database refresh carries the stored rows and site-local seal, while
    // staging resolves only its own environment-specific signing key.
    $this->makeKey('staging_key', 'staging-secret');
    $this->config('audit_chain.settings')
      ->set('hash_key', 'staging_key')
      ->set('previous_hash_keys', ['production_key'])
      ->save();
    $this->assertTrue(
      $this->chain->verify()['ok'],
      'A source key explicitly retained for verification authenticates the copied seal.',
    );

    $this->config('audit_chain.settings')->set('previous_hash_keys', [])->save();
    Key::load('production_key')?->delete();
    $rowsBefore = $this->rows();

    $result = $this->chain->verify();
    $this->assertFalse($result['ok'], 'A seal that cannot be authenticated locally must remain fail-closed.');
    $this->assertSame(AuditChainLogger::REASON_SEAL_FOREIGN, $result['reason']);
    $this->assertNull($result['broken_at']);
    $this->assertFalse($result['seal_intact']);
    $this->assertSame(2, $result['sealed_through']);
    $this->assertEquals($rowsBefore, $this->rows(), 'Classifying a foreign seal must be read-only.');
  }

  /**
   * Replacing a keyed seal with an unsigned digest never authenticates it.
   *
   * @covers ::sealPrefix
   * @covers ::verify
   */
  public function testSealMacCannotBeReplacedWithUnkeyedDigest(): void {
    $this->chain->log('personnel', 'field_read', ['id' => '1']);
    $this->makeKey('chain_key', 'correct-horse-battery-staple');
    $this->config('audit_chain.settings')->set('hash_key', 'chain_key')->save();
    $this->assertTrue($this->chain->sealPrefix(1, 'freeze')['sealed']);

    // Model a database writer changing the prefix and replacing the seal with
    // a plain SHA-256 digest it can compute without the trusted signing key.
    $this->container->get('database')->update('audit_chain_log')
      ->fields(['row_hash' => str_repeat('a', 64)])
      ->condition('id', 1)
      ->execute();
    $seal = $this->chain->getSeal();
    $this->assertIsArray($seal);
    $seal['prefix_digest'] = hash('sha256', '1:' . str_repeat('a', 64));
    $payload = [
      'key_id' => $seal['key_id'],
      'prefix_digest' => $seal['prefix_digest'],
      'reason' => $seal['reason'],
      'row_count' => $seal['row_count'],
      'sealed_through_id' => $seal['sealed_through_id'],
      'timestamp' => $seal['timestamp'],
      'uid' => $seal['uid'],
    ];
    ksort($payload);
    $seal['seal_mac'] = hash('sha256', (string) json_encode(
      $payload,
      JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE,
    ));
    $this->container->get('state')->set(AuditChainLogger::STATE_SEAL, $seal);

    $result = $this->chain->verify();
    $this->assertFalse($result['ok']);
    $this->assertSame(AuditChainLogger::REASON_SEAL_FOREIGN, $result['reason']);
    $this->assertFalse($result['seal_intact']);
  }

  /**
   * Sealing a row that still verifies under a key is refused.
   *
   * @covers ::sealPrefix
   */
  public function testSealRefusesVerifiableRows(): void {
    $this->makeKey('chain_key', 'correct-horse-battery-staple');
    $this->config('audit_chain.settings')->set('hash_key', 'chain_key')->save();
    $this->chain->log('personnel', 'field_read', ['id' => '1']);

    $result = $this->chain->sealPrefix(1, 'should fail');
    $this->assertFalse($result['sealed']);
    $this->assertStringContainsString('still verifies', $result['message']);
  }

  /**
   * Sealing requires the active signing key, not merely a retired key.
   *
   * @covers ::sealPrefix
   */
  public function testSealRefusesUnresolvableActiveKeyWithRetiredKey(): void {
    $this->chain->log('personnel', 'field_read', ['id' => '1']);
    $this->makeKey('retired_key', 'retired-secret');
    $this->config('audit_chain.settings')
      ->set('hash_key', 'missing_active_key')
      ->set('previous_hash_keys', ['retired_key'])
      ->save();

    $result = $this->chain->sealPrefix(1, 'must not be unsigned');
    $this->assertFalse($result['sealed']);
    $this->assertNull($result['seal']);
    $this->assertStringContainsString('cannot be resolved', $result['message']);
    $this->assertNull($this->chain->getSeal());
  }

  /**
   * The streamed record carries every field a SIEM rule may key on.
   *
   * Asserted field by field rather than by shape: 1.0.0 shipped without
   * `bundle`, which the implementation this was extracted from had always
   * emitted. Nothing failed — a SIEM rule keyed on bundle would simply have
   * stopped matching, silently, which is the worst way for an audit stream to
   * regress.
   */
  public function testStreamedRecordCarriesEveryField(): void {
    $this->config('audit_chain.settings')->set('stream_enabled', TRUE)->save();

    $spy = new class() extends AbstractLogger {
      /**
       * Captured log records.
       *
       * @var array<int, array{message: string, context: array}>
       */
      public array $records = [];

      /**
       * {@inheritdoc}
       */
      public function log($level, string|\Stringable $message, array $context = []): void {
        $this->records[] = ['message' => (string) $message, 'context' => $context];
      }

    };
    $this->container->set('logger.channel.audit_chain', $spy);
    $this->container->set('audit_chain.logger', NULL);

    $this->container->get('audit_chain.logger')->log('personnel', 'field_read', [
      'entity_type' => 'node',
      'bundle' => 'person',
      'id' => '9',
      'label' => 'A. Person',
    ]);

    $this->assertCount(1, $spy->records);
    $this->assertSame('audit_chain_event', $spy->records[0]['message']);

    $ctx = $spy->records[0]['context'];
    foreach (['channel', 'operation', 'uid', 'entity_type', 'bundle', 'entity_id', 'timestamp', 'row_hash'] as $key) {
      $this->assertArrayHasKey($key, $ctx, "Streamed context must carry '{$key}'.");
    }
    $this->assertSame('personnel', $ctx['channel']);
    $this->assertSame('person', $ctx['bundle']);
    $this->assertNotEmpty($ctx['row_hash']);
  }

  /**
   * Retention preserves valid interleaved and legacy channel history.
   */
  public function testPrunePreservesSharedHistory(): void {
    $now = 1800000000;
    $time = $this->createMock(TimeInterface::class);
    $time->method('getRequestTime')->willReturnCallback(static function () use (&$now): int {
      return $now;
    });
    $this->container->set('datetime.time', $time);
    $this->container->set('audit_chain.logger', NULL);
    $this->chain = $this->container->get('audit_chain.logger');
    $this->makeKey('retention_key', 'synthetic-retention-key');
    $this->config('audit_chain.settings')->set('hash_key', 'retention_key')->save();
    $this->chain->logKeyed('', 'legacy');
    $this->chain->logKeyed('personnel', 'field_read');
    $this->chain->logKeyed('mcp_sentinel', 'entity_save');
    $original = $this->rows();
    $this->assertTrue($this->chain->verify()['ok']);

    // Advance the clock, never edit a timestamp covered by the signature.
    $now += 10 * 86400;
    $this->assertSame(0, $this->chain->prune('personnel', 0));
    $this->assertFalse($this->container->get('state')->get('audit_chain.retention_refused', FALSE));
    foreach (['', 'personnel', 'mcp_sentinel'] as $channel) {
      $this->assertSame(0, $this->chain->prune($channel, 5));
      $this->assertEquals($original, $this->rows());
      $this->assertTrue($this->chain->verify()['ok']);
    }
    $this->assertTrue($this->container->get('state')->get('audit_chain.retention_refused'));
    $this->chain->logKeyed('personnel', 'after_retention');
    $this->assertTrue($this->chain->verify()['ok']);
    $this->assertCount(4, $this->rows());
  }

  /**
   * Retention does not alter a prefix seal or hide an existing failure.
   */
  public function testPrunePreservesSealAndFailedVerdict(): void {
    $now = 1800000000;
    $time = $this->createMock(TimeInterface::class);
    $time->method('getRequestTime')->willReturnCallback(static function () use (&$now): int {
      return $now;
    });
    $this->container->set('datetime.time', $time);
    $this->container->set('audit_chain.logger', NULL);
    $this->chain = $this->container->get('audit_chain.logger');
    $this->chain->log('legacy', 'unsigned');
    $this->makeKey('retention_key', 'synthetic-retention-key');
    $this->config('audit_chain.settings')->set('hash_key', 'retention_key')->save();
    $this->assertTrue($this->chain->sealPrefix(1, 'synthetic unsigned prefix')['sealed']);
    $seal = $this->chain->getSeal();
    $this->chain->logKeyed('test', 'signed');
    $now += 10 * 86400;
    $this->assertTrue($this->chain->verify()['ok']);
    $this->assertSame(0, $this->chain->prune('legacy', 1));
    $this->assertSame($seal, $this->chain->getSeal());
    $this->assertTrue($this->chain->verify()['ok']);

    $this->container->get('database')->update('audit_chain_log')
      ->fields(['prev_hash' => str_repeat('f', 64)])
      ->condition('operation', 'signed')
      ->execute();
    $before = $this->chain->verify();
    $this->assertFalse($before['ok']);
    $original = $this->rows();
    $this->assertSame(0, $this->chain->prune('test', 1));
    $this->assertSame($before, $this->chain->verify());
    $this->assertEquals($original, $this->rows());
  }

  /**
   * A row written with no channel keeps the pre-extraction canonical form.
   *
   * This is what lets rows migrated from mcp_sentinel's own table — written
   * before this module existed, so hashed without any channel — go on
   * verifying against their original hashes. Re-chaining them during migration
   * would have been easy and wrong: hashes recomputed by a migration prove only
   * that the migration ran, and would paper over tampering from before it.
   */
  public function testChannellessRowsVerifyAgainstLegacyHashes(): void {
    $database = $this->container->get('database');
    $time = $this->container->get('datetime.time')->getRequestTime();

    // Exactly the canonical payload mcp_sentinel 1.13 hashed: fixed key order,
    // no channel key at all.
    $canonical = json_encode([
      'bundle' => NULL,
      'entity_id' => '7',
      'entity_label' => NULL,
      'entity_type' => 'node',
      'ip_address' => NULL,
      'metadata' => [],
      'operation' => 'entity_save',
      'timestamp' => $time,
      'uid' => 0,
      'user_agent' => NULL,
    ], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);

    $database->insert('audit_chain_log')->fields([
      'channel' => '',
      'timestamp' => $time,
      'uid' => 0,
      'operation' => 'entity_save',
      'entity_type' => 'node',
      'entity_id' => '7',
      'metadata' => '[]',
      'prev_hash' => NULL,
      'row_hash' => hash('sha256', '|' . $canonical),
    ])->execute();

    $this->assertTrue(
      $this->chain->verify()['ok'],
      'A legacy, channelless row verifies without being re-chained.',
    );

    // And the chain continues from it.
    $this->chain->log('mcp_sentinel', 'entity_save', ['id' => '8']);
    $this->assertTrue($this->chain->verify()['ok']);
  }

  /**
   * Signing status reports whether an append would be HMAC-signed (#25).
   */
  public function testSigningStatusReflectsKeyResolution(): void {
    $this->assertSame(
      ['keyed' => FALSE, 'key_id' => ''],
      $this->chain->signingStatus(),
    );

    $this->makeKey('chain_key', 'correct-horse-battery-staple');
    $this->config('audit_chain.settings')->set('hash_key', 'chain_key')->save();
    $this->assertSame(
      ['keyed' => TRUE, 'key_id' => 'chain_key'],
      $this->chain->signingStatus(),
    );

    $this->config('audit_chain.settings')->set('hash_key', 'missing_key')->save();
    $this->assertSame(
      ['keyed' => FALSE, 'key_id' => 'missing_key'],
      $this->chain->signingStatus(),
    );
  }

  /**
   * Keyed append refuses when unsigned (#25).
   */
  public function testKeyedAppendRequiresResolvableSigningKey(): void {
    $this->expectException(AuditChainSigningUnavailableException::class);
    $this->chain->logKeyed('mcp_sentinel', 'evidence_precommit', ['id' => '1']);
  }

  /**
   * Keyed append writes nothing when it refuses (#25).
   */
  public function testKeyedAppendWritesNothingWhenUnsigned(): void {
    try {
      $this->chain->logKeyed('mcp_sentinel', 'evidence_precommit', ['id' => '1']);
      $this->fail('Expected AuditChainSigningUnavailableException.');
    }
    catch (AuditChainSigningUnavailableException) {
      // Expected.
    }
    $this->assertCount(0, $this->rows());
  }

  /**
   * Keyed append writes a keyed row when the signing key resolves (#25).
   */
  public function testKeyedAppendWritesWhenSigningKeyResolves(): void {
    $this->makeKey('chain_key', 'correct-horse-battery-staple');
    $this->config('audit_chain.settings')->set('hash_key', 'chain_key')->save();

    $this->chain->logKeyed('mcp_sentinel', 'evidence_precommit', ['id' => '1']);

    $rows = $this->rows();
    $this->assertCount(1, $rows);
    $this->assertSame('chain_key', (string) $rows[0]->key_id);
    $this->assertTrue($this->chain->verify()['ok']);
  }

  /**
   * Keyed append refuses an unresolvable configured key without writing (#25).
   */
  public function testKeyedAppendRefusesUnresolvableConfiguredKey(): void {
    $this->config('audit_chain.settings')->set('hash_key', 'no_such_key')->save();
    try {
      $this->chain->logKeyed('mcp_sentinel', 'evidence_precommit', ['id' => '1']);
      $this->fail('Expected AuditChainSigningUnavailableException.');
    }
    catch (AuditChainSigningUnavailableException $e) {
      $this->assertStringContainsString('no_such_key', $e->getMessage());
    }
    $this->assertCount(0, $this->rows());
  }

}
