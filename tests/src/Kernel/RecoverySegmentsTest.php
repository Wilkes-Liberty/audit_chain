<?php

declare(strict_types=1);

namespace Drupal\Tests\audit_chain\Kernel;

use Composer\Autoload\ClassLoader;
use Drupal\audit_chain\Exception\AuditChainAppendException;
use Drupal\audit_chain\Exception\AuditChainSigningUnavailableException;
use Drupal\audit_chain\AuditChainLogger;
use Drupal\audit_chain\RecoverySegments;
use Drupal\Core\Site\Settings;
use Drupal\KernelTests\KernelTestBase;
use Drupal\key\Entity\Key;
use Drupal\encrypt\EncryptServiceInterface;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;
use Symfony\Component\Process\Process;

/**
 * Checks recovery without rewriting a synthetic authenticated fork.
 *
 * @group audit_chain
 * @runTestsInSeparateProcesses
 */
#[Group('audit_chain')]
#[RunTestsInSeparateProcesses]
final class RecoverySegmentsTest extends KernelTestBase {

  use AuditChainSchemaTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['system', 'user', 'key', 'encrypt', 'audit_chain'];

  private const SEGMENT = '957345ba-a0c8-42d5-9dcb-92ba4430a820';

  /**
   * The ordinary chain implementation.
   */
  private AuditChainLogger $chain;

  /**
   * The explicit successor workflow.
   */
  private RecoverySegments $recovery;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->installEntitySchema('user');
    $this->installAuditChainTables();
    $this->installConfig(['audit_chain']);
    new Settings(['audit_chain_instance_id' => 'synthetic-instance-a'] + Settings::getAll());
    Key::create([
      'id' => 'recovery_key',
      'label' => 'Synthetic recovery key',
      'key_type' => 'authentication',
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => 'synthetic-recovery-secret'],
    ])->save();
    $this->config('audit_chain.settings')->set('hash_key', 'recovery_key')->save();
    $this->chain = $this->container->get('audit_chain.logger');
    $this->recovery = $this->container->get('audit_chain.recovery');
    $this->makeFork();
  }

  /**
   * A successor verifies while the original failure and rows remain intact.
   */
  public function testSuccessorPreservesFailedHistory(): void {
    $original = $this->rows();
    $before = $this->chain->verify();
    $this->assertFalse($before['ok']);
    $prepared = $this->recovery->prepare();
    $this->assertCount(2, $prepared['snapshot']['branch_tips']);
    $this->assertSame($prepared['snapshot']['historical_verdict'], $prepared['historical_verdict']);
    $record = $this->recovery->activate(self::SEGMENT, $prepared['snapshot_digest'], $this->context());
    $manifest = json_decode($record['manifest'], TRUE, 64, JSON_THROW_ON_ERROR);
    $this->assertSame($prepared['snapshot']['historical_verdict'], $manifest['historical_verdict']);
    $this->assertSame($before, $this->chain->verify());
    $this->assertEquals($original, array_slice($this->rows(), 0, 3));
    $this->chain->logKeyed('test', 'new_work');
    $result = $this->recovery->verify(self::SEGMENT);
    $this->assertTrue($result['segment_ok']);
    $this->assertFalse($result['historical_ok']);
    $this->assertSame(2, $result['verified_rows']);
    $this->assertSame($record, $this->recovery->activate(self::SEGMENT, $prepared['snapshot_digest'], $this->context()));
    $this->assertCount(5, $this->rows(), 'Retry must not append another receipt.');
  }

  /**
   * Logical-content edits are detected even when stored hashes are untouched.
   */
  public function testHistoricalContentMutationFails(): void {
    $prepared = $this->recovery->prepare();
    $this->recovery->activate(self::SEGMENT, $prepared['snapshot_digest'], $this->context());
    $this->container->get('database')->update('audit_chain_log')
      ->fields(['entity_label' => 'changed after review'])
      ->condition('id', 1)->execute();
    $this->assertFalse($this->recovery->verify(self::SEGMENT)['segment_ok']);
  }

  /**
   * Other module maintenance APIs cannot change frozen recovery evidence.
   */
  public function testMaintenanceRefusesFrozenHistory(): void {
    $prepared = $this->recovery->prepare();
    $this->recovery->activate(self::SEGMENT, $prepared['snapshot_digest'], $this->context());
    $before = $this->rows();
    $this->assertFalse($this->chain->sealPrefix(3, 'must not hide the fork')['sealed']);
    $reencrypt = $this->chain->reencrypt('old_profile', 'new_profile');
    $this->assertSame(0, $reencrypt['updated']);
    $this->assertNotNull($reencrypt['refused']);
    $this->assertEquals($before, $this->rows());
    $this->assertTrue($this->recovery->verify(self::SEGMENT)['segment_ok']);
  }

  /**
   * Storage changes cannot hide behind a decoder's empty metadata fallback.
   */
  public function testHistoricalStorageMutationFails(): void {
    $prepared = $this->recovery->prepare();
    $this->recovery->activate(self::SEGMENT, $prepared['snapshot_digest'], $this->context());
    $this->container->get('database')->update('audit_chain_log')
      ->fields(['metadata' => 'not-json-or-decryptable'])
      ->condition('id', 1)->execute();
    $this->assertFalse($this->recovery->verify(self::SEGMENT)['segment_ok']);
  }

  /**
   * Approval of a previous head cannot activate a changed snapshot.
   */
  public function testStaleSnapshotRefused(): void {
    $prepared = $this->recovery->prepare();
    $this->chain->logKeyed('test', 'concurrent_append');
    try {
      $this->recovery->activate(self::SEGMENT, $prepared['snapshot_digest'], $this->context());
      $this->fail('Stale approval must be refused.');
    }
    catch (\RuntimeException $exception) {
      $this->assertStringContainsString('stale', $exception->getMessage());
    }
    $this->assertNull($this->recovery->record(self::SEGMENT));
    $this->assertCount(4, $this->rows());
  }

  /**
   * A database copy is not authority to recover a different runtime instance.
   */
  public function testForeignInstanceRefused(): void {
    $prepared = $this->recovery->prepare();
    $this->recovery->activate(self::SEGMENT, $prepared['snapshot_digest'], $this->context());
    new Settings(['audit_chain_instance_id' => 'synthetic-instance-b'] + Settings::getAll());
    $this->assertFalse($this->recovery->verify(self::SEGMENT)['segment_ok']);
  }

  /**
   * A caller rollback removes both the checkpoint and its log receipt.
   */
  public function testCallerRollback(): void {
    $prepared = $this->recovery->prepare();
    $transaction = $this->container->get('database')->startTransaction();
    $this->recovery->activate(self::SEGMENT, $prepared['snapshot_digest'], $this->context());
    $this->assertTrue($this->recovery->verify(self::SEGMENT)['segment_ok']);
    $transaction->rollBack();
    unset($transaction);
    $this->assertNull($this->recovery->record(self::SEGMENT));
    $this->assertCount(3, $this->rows());
  }

  /**
   * Missing and altered records or receipts never report segment success.
   */
  public function testMissingReceiptRefused(): void {
    $prepared = $this->recovery->prepare();
    $this->recovery->activate(self::SEGMENT, $prepared['snapshot_digest'], $this->context());
    $this->container->get('database')->delete('audit_chain_log')->condition('id', 4)->execute();
    $this->assertFalse($this->recovery->verify(self::SEGMENT)['segment_ok']);
  }

  /**
   * A missing or modified checkpoint cannot be exported as valid evidence.
   */
  public function testRecoveryExportRefusesTampering(): void {
    $prepared = $this->recovery->prepare();
    $this->recovery->activate(self::SEGMENT, $prepared['snapshot_digest'], $this->context());
    $export = $this->recovery->export(self::SEGMENT);
    $this->assertTrue($export['verification']['segment_ok']);
    $this->assertFalse($export['whole_history_verified']);
    $this->assertNotEmpty($export['recovery_record']['mac']);
    $this->container->get('database')->update('audit_chain_recovery')
      ->fields(['manifest' => '{}'])->condition('segment_id', self::SEGMENT)->execute();
    $export = $this->recovery->export(self::SEGMENT);
    $this->assertFalse($export['verification']['segment_ok']);
    $this->assertNull($export['recovery_record']);
    $this->container->get('database')->delete('audit_chain_recovery')->execute();
    $this->assertFalse($this->recovery->verify(self::SEGMENT)['segment_ok']);
  }

  /**
   * Retained keys permit rotation; losing them refuses verification.
   */
  public function testKeyRotationAndLoss(): void {
    $prepared = $this->recovery->prepare();
    $this->recovery->activate(self::SEGMENT, $prepared['snapshot_digest'], $this->context());
    Key::create([
      'id' => 'new_key',
      'label' => 'Synthetic new key',
      'key_type' => 'authentication',
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => 'synthetic-new-secret'],
    ])->save();
    $this->config('audit_chain.settings')
      ->set('hash_key', 'new_key')
      ->set('previous_hash_keys', ['recovery_key'])
      ->save();
    $this->chain->logKeyed('test', 'rotated');
    $this->assertTrue($this->recovery->verify(self::SEGMENT)['segment_ok']);
    $this->config('audit_chain.settings')->set('previous_hash_keys', [])->save();
    $this->assertFalse($this->recovery->verify(self::SEGMENT)['segment_ok']);
  }

  /**
   * Activation never falls back to an unsigned recovery record.
   */
  public function testMissingSigningKeyRefusesActivation(): void {
    $this->config('audit_chain.settings')->set('hash_key', 'missing')->save();
    $prepared = $this->recovery->prepare();
    try {
      $this->recovery->activate(self::SEGMENT, $prepared['snapshot_digest'], $this->context());
      $this->fail('An unavailable active signing key must refuse activation.');
    }
    catch (AuditChainSigningUnavailableException $exception) {
      $this->assertNull($this->recovery->record(self::SEGMENT));
      $this->assertCount(3, $this->rows());
    }
  }

  /**
   * A changed retry context cannot reuse an approved segment identifier.
   */
  public function testChangedRetryRefused(): void {
    $prepared = $this->recovery->prepare();
    $this->recovery->activate(self::SEGMENT, $prepared['snapshot_digest'], $this->context());
    $context = $this->context();
    $context['reason'] = 'different approval';
    $this->expectException(\RuntimeException::class);
    $this->recovery->activate(self::SEGMENT, $prepared['snapshot_digest'], $context);
  }

  /**
   * Failure to acquire serialization leaves no partial recovery.
   */
  public function testMissingMutexRefused(): void {
    $prepared = $this->recovery->prepare();
    $this->container->get('database')->delete('audit_chain_mutex')->execute();
    try {
      $this->recovery->activate(self::SEGMENT, $prepared['snapshot_digest'], $this->context());
      $this->fail('Missing mutex must refuse activation.');
    }
    catch (AuditChainAppendException $exception) {
      $this->assertNull($this->recovery->record(self::SEGMENT));
      $this->assertCount(3, $this->rows());
    }
  }

  /**
   * Monitoring and ordinary evidence export retain the historical failure.
   */
  public function testMonitoringNeverSubstitutesSuccessorHealth(): void {
    $this->config('audit_chain.settings')->set('verify_interval', 60)->save();
    $this->container->get('state')->set('audit_chain.scheduled_verification', ['ok' => TRUE]);
    $prepared = $this->recovery->prepare();
    $this->recovery->activate(self::SEGMENT, $prepared['snapshot_digest'], $this->context());
    $this->assertFalse($this->container->get('state')->get('audit_chain.scheduled_verification')['ok']);
    $run = $this->container->get('audit_chain.scheduled_verifier')->runNow();
    $this->assertFalse($run['ok']);
    $this->assertTrue($run['successor']['segment_ok']);
    $this->assertFalse($run['successor']['historical_ok']);
    $this->assertSame('failed', $this->container->get('audit_chain.metrics')->integrity()['reason']);
    $this->assertTrue($this->container->get('audit_chain.metrics')->recoveryStatus()['segment_ok']);
    $destination = sys_get_temp_dir() . '/audit-recovery-export-' . bin2hex(random_bytes(8));
    try {
      // Even stale success state must not override the explicit exception.
      $this->container->get('state')->set('audit_chain.scheduled_verification', ['ok' => TRUE]);
      $export = $this->container->get('audit_chain.evidence_exporter')->exportTo($destination);
      $this->assertFalse($export['ok']);
      $this->assertSame(0, $export['delivered']);
      $this->assertFileDoesNotExist($destination);
    }
    finally {
      if (is_file($destination)) {
        unlink($destination);
      }
    }
  }

  /**
   * Schema installation is repeatable and preserves the exact history.
   */
  public function testUpgradeDoesNotActivateOrRewrite(): void {
    $before = $this->rows();
    $this->container->get('database')->schema()->dropTable('audit_chain_recovery');
    $this->container->get('module_handler')->loadInclude('audit_chain', 'install');
    audit_chain_update_10004();
    audit_chain_update_10004();
    $this->assertEquals($before, $this->rows());
    $this->assertNull($this->recovery->currentStatus());
  }

  /**
   * A competing append waits for the recovery caller's outer commit.
   */
  public function testConcurrentRecoveryCommit(): void {
    $this->assertConcurrentRecovery(FALSE);
  }

  /**
   * A competing append continues without a receipt after recovery rollback.
   */
  public function testConcurrentRecoveryRollback(): void {
    $this->assertConcurrentRecovery(TRUE);
  }

  /**
   * Exercises the actual recovery and append paths in separate processes.
   */
  private function assertConcurrentRecovery(bool $rollback): void {
    $database = $this->container->get('database');
    if (!in_array($database->driver(), ['pgsql', 'mysql'], TRUE)) {
      $this->markTestSkipped('Cross-process recovery requires PostgreSQL or MySQL.');
    }
    $prepared = $this->recovery->prepare();
    $prefix = sys_get_temp_dir() . '/audit-recovery-concurrency-' . bin2hex(random_bytes(8));
    $ready = $prefix . '-ready';
    $release = $prefix . '-release';
    $started = $prefix . '-started';
    $vendor = dirname((new \ReflectionClass(ClassLoader::class))->getFileName(), 2);
    $fixture = dirname(__DIR__, 2) . '/fixtures/append-worker.php';
    $first = new Process([PHP_BINARY, $fixture, $this->root, $vendor]);
    $second = new Process([PHP_BINARY, $fixture, $this->root, $vendor]);
    $common = [
      'database' => $database->getConnectionOptions(),
      'recovery_fixture' => TRUE,
      'namespaces' => [
        'Drupal\\key\\' => dirname((new \ReflectionClass(Key::class))->getFileName(), 2),
        'Drupal\\encrypt\\' => dirname((new \ReflectionClass(EncryptServiceInterface::class))->getFileName()),
      ],
    ];
    $first->setInput(json_encode($common + [
      'activate_segment' => self::SEGMENT,
      'snapshot_digest' => $prepared['snapshot_digest'],
      'context' => $this->context(),
      'ready' => $ready,
      'release' => $release,
      'rollback' => $rollback,
    ], JSON_THROW_ON_ERROR));
    $second->setInput(json_encode($common + [
      'operation' => 'after_recovery',
      'started' => $started,
    ], JSON_THROW_ON_ERROR));
    $first->setTimeout(30);
    $second->setTimeout(30);
    $wait = function (Process $worker, string $path): void {
      $deadline = microtime(TRUE) + 10;
      while (!is_file($path)) {
        if (!$worker->isRunning() || microtime(TRUE) >= $deadline) {
          $this->fail('Recovery worker failed: ' . $worker->getErrorOutput() . $worker->getOutput());
        }
        usleep(20000);
      }
    };
    try {
      $first->start();
      $wait($first, $ready);
      $second->start();
      $wait($second, $started);
      usleep(3300000);
      $this->assertTrue($second->isRunning(), 'Append escaped recovery serialization before the outer transaction ended.');
    }
    finally {
      file_put_contents($release, 'release');
      foreach ([$first, $second] as $worker) {
        if ($worker->isStarted()) {
          $worker->wait();
        }
      }
      foreach ([$ready, $release, $started] as $path) {
        if (is_file($path)) {
          unlink($path);
        }
      }
    }
    foreach ([$first, $second] as $worker) {
      $this->assertSame(0, $worker->getExitCode(), $worker->getErrorOutput() . $worker->getOutput());
    }
    $this->assertCount($rollback ? 4 : 5, $this->rows());
    $this->assertSame(!$rollback, $this->recovery->verify(self::SEGMENT)['segment_ok']);
    $this->assertFalse($this->chain->verify()['ok']);
  }

  /**
   * Builds a fork whose two branches still have authentic HMACs.
   */
  private function makeFork(): void {
    foreach (['root', 'left', 'right'] as $operation) {
      $this->chain->logKeyed('test', $operation);
    }
    $rows = $this->rows();
    $right = (array) $rows[2];
    $right['prev_hash'] = $rows[0]->row_hash;
    // Test-only access avoids maintaining a second copy of the hash format.
    $canonical = new \ReflectionMethod(AuditChainLogger::class, 'canonicalFromRecord');
    $right['row_hash'] = hash_hmac(
      'sha256',
      $right['prev_hash'] . '|' . $canonical->invoke($this->chain, $right),
      'synthetic-recovery-secret',
    );
    $this->container->get('database')->update('audit_chain_log')
      ->fields(['prev_hash' => $right['prev_hash'], 'row_hash' => $right['row_hash']])
      ->condition('id', 3)->execute();
    $inspect = $this->chain->recoveryRowInspector();
    foreach ($this->rows() as $row) {
      $this->assertTrue($inspect((array) $row)['authenticated']);
    }
  }

  /**
   * Returns only synthetic recovery context.
   */
  private function context(): array {
    return [
      'incident' => 'synthetic-incident',
      'reason' => 'Preserve both authentic branches and their failed verdict.',
      'approved_by' => 'test operator',
      'backup_digest' => str_repeat('a', 64),
    ];
  }

  /**
   * Returns stored rows in chain order.
   */
  private function rows(): array {
    return $this->container->get('database')->select('audit_chain_log', 'l')
      ->fields('l')->orderBy('id')->execute()->fetchAll();
  }

}
