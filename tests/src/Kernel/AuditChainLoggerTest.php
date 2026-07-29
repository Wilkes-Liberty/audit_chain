<?php

declare(strict_types=1);

namespace Drupal\Tests\audit_chain\Kernel;

use Psr\Log\AbstractLogger;
use Drupal\audit_chain\AuditChainLoggerInterface;
use Drupal\KernelTests\KernelTestBase;
use Drupal\key\Entity\Key;
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

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['system', 'user', 'key', 'encrypt', 'audit_chain'];

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
    $this->installSchema('audit_chain', ['audit_chain_log']);
    $this->installConfig(['audit_chain']);
    $this->chain = $this->container->get('audit_chain.logger');
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

    $this->assertSame(['ok' => TRUE, 'broken_at' => NULL], $this->chain->verify());
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
   * Pruning removes only the named channel's aged rows.
   */
  public function testPruneIsScopedToItsChannelAndAge(): void {
    $this->chain->log('personnel', 'field_read', ['id' => '1']);
    $this->chain->log('mcp_sentinel', 'entity_save', ['id' => '2']);

    $this->assertSame(0, $this->chain->prune('personnel', 0), 'Retention of 0 is a no-op.');
    $this->assertCount(2, $this->rows());

    // Age the personnel row past the window.
    $this->container->get('database')->update('audit_chain_log')
      ->fields(['timestamp' => $this->container->get('datetime.time')->getRequestTime() - (10 * 86400)])
      ->condition('channel', 'personnel')
      ->execute();

    $this->assertSame(1, $this->chain->prune('personnel', 5));
    $rows = $this->rows();
    $this->assertCount(1, $rows);
    $this->assertSame('mcp_sentinel', $rows[0]->channel);
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

    $this->assertSame(
      ['ok' => TRUE, 'broken_at' => NULL],
      $this->chain->verify(),
      'A legacy, channelless row verifies without being re-chained.',
    );

    // And the chain continues from it.
    $this->chain->log('mcp_sentinel', 'entity_save', ['id' => '8']);
    $this->assertTrue($this->chain->verify()['ok']);
  }

}
