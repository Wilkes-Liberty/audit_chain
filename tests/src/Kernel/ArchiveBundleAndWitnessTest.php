<?php

declare(strict_types=1);

namespace Drupal\Tests\audit_chain\Kernel;

use Drupal\audit_chain\AuditChainLogger;
use Drupal\audit_chain\IdentifiedWitnessBackendInterface;
use Drupal\audit_chain\WitnessReceipt;
use Drupal\audit_chain\WitnessVerdict;
use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Site\Settings;
use Drupal\KernelTests\KernelTestBase;
use Drupal\key\Entity\Key;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Checks archival checkpoints, bundles, and the witness seam.
 *
 * @group audit_chain
 * @runTestsInSeparateProcesses
 */
#[Group('audit_chain')]
#[RunTestsInSeparateProcesses]
final class ArchiveBundleAndWitnessTest extends KernelTestBase {

  use AuditChainSchemaTrait;

  private const SEGMENT = '957345ba-a0c8-42d5-9dcb-92ba4430a820';

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['system', 'user', 'key', 'encrypt', 'audit_chain'];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $time = $this->createMock(TimeInterface::class);
    $time->method('getRequestTime')->willReturn(1790000000);
    $time->method('getCurrentTime')->willReturn(1790000000);
    $this->container->set('datetime.time', $time);
    $this->installEntitySchema('user');
    $this->installAuditChainTables();
    $this->installConfig(['audit_chain']);
    new Settings(['audit_chain_instance_id' => 'archive-test-instance'] + Settings::getAll());
    Key::create([
      'id' => 'archive_key',
      'label' => 'Archive test key',
      'key_type' => 'authentication',
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => 'archive-test-secret'],
    ])->save();
    $this->config('audit_chain.settings')->set('hash_key', 'archive_key')->save();
  }

  /**
   * The same closed window always produces the same digest and proof material.
   */
  public function testCheckpointDigestIsStable(): void {
    $chain = $this->container->get('audit_chain.logger');
    $chain->logKeyed('personnel', 'field_read', [
      'id' => 'person-1',
      'label' => 'Sensitive label',
      'secret_note' => 'metadata must stay local',
    ]);
    $chain->logKeyed('finance', 'export', ['id' => 'invoice-7']);

    $exporter = $this->container->get('audit_chain.archive_bundle_exporter');
    $first = $exporter->create(1, 2);
    $second = $exporter->create(1, 2);

    $this->assertSame($first['manifest']['digest'], $second['manifest']['digest']);
    $this->assertSame(
      '6d42fdce983e5f72a1f3fc8a73aa4486bebb5e3058f43f23f0d642e89f58562f',
      $first['manifest']['digest'],
    );
    $this->assertMatchesRegularExpression('/^[a-f0-9]{64}$/D', $first['manifest']['digest']);
    $this->assertSame($first['merkle'], $second['merkle']);
    $this->assertSame('audit_chain.archive.v1', $first['manifest']['contract']);
    $this->assertSame([
      'from_id' => 1,
      'through_id' => 2,
      'row_count' => 2,
    ], $first['manifest']['window']);
    $stored = $this->container->get('database')
      ->select('audit_chain_checkpoint', 'c')
      ->fields('c', ['manifest'])
      ->condition('digest', $first['manifest']['digest'])
      ->execute()
      ->fetchField();
    $this->assertSame($first['manifest'], json_decode($stored, TRUE, 32, JSON_THROW_ON_ERROR));
    foreach ($first['merkle']['proofs'] as $index => $proof) {
      $hash = $first['merkle']['leaves'][$index]['hash'];
      foreach ($proof['path'] as $sibling) {
        $left = $sibling['side'] === 'left' ? $sibling['hash'] : $hash;
        $right = $sibling['side'] === 'right' ? $sibling['hash'] : $hash;
        $hash = hash('sha256', "audit_chain.archive.node.v1\n" . $left . $right);
      }
      $this->assertSame($first['merkle']['root'], $hash);
    }
  }

  /**
   * The independent bundle exposes only row ids and hash-chain material.
   */
  public function testBundleContainsNoPiiFields(): void {
    $this->container->get('audit_chain.logger')->logKeyed('personnel', 'field_read', [
      'id' => 'person-1',
      'label' => 'Sensitive label',
      'secret_note' => 'metadata must stay local',
    ]);

    $bundle = $this->container->get('audit_chain.archive_bundle_exporter')->create(1, 1);
    $this->assertSame(
      ['contract_version', 'id', 'prev_hash', 'row_hash'],
      array_keys($bundle['rows'][0]),
    );
    $encoded = json_encode($bundle, JSON_THROW_ON_ERROR);
    foreach ([
      'metadata',
      'ip_address',
      'user_agent',
      'entity_label',
      'channel',
      'operation',
      'timestamp',
      'uid',
      'entity_type',
      'bundle',
      'entity_id',
      'key_id',
      'Sensitive label',
      'metadata must stay local',
      'archive-test-secret',
    ] as $forbidden) {
      $this->assertStringNotContainsString($forbidden, $encoded);
    }
  }

  /**
   * A broken chain cannot be turned into an apparently valid checkpoint.
   */
  public function testBrokenChainIsRefusedWithoutValidSuccessor(): void {
    $chain = $this->container->get('audit_chain.logger');
    $chain->logKeyed('test', 'before_tamper');
    $this->container->get('database')->update('audit_chain_log')
      ->fields(['row_hash' => str_repeat('f', 64)])
      ->condition('id', 1)
      ->execute();

    $this->expectException(\RuntimeException::class);
    $this->expectExceptionMessage('does not verify');
    $this->container->get('audit_chain.archive_bundle_exporter')->create(1, 1);
  }

  /**
   * An unconfigured witness persists pending state and never verifies.
   */
  public function testMissingWitnessBackendFailsClosedWithoutChainWrite(): void {
    $chain = $this->container->get('audit_chain.logger');
    $chain->logKeyed('test', 'before_witness');
    $bundle = $this->container->get('audit_chain.archive_bundle_exporter')->create(1, 1);
    $before = $this->chainRows();

    $witness = $this->container->get('audit_chain.witness_manager');
    $receipt = $witness->submit($bundle['manifest']['digest']);
    $this->assertSame('null', $receipt->backendId);
    $this->assertSame('pending', $receipt->status);
    $this->assertEquals($receipt, $witness->receipt($receipt->id));

    $upgraded = $witness->upgrade($receipt->id);
    $this->assertSame('pending', $upgraded->status);
    $verdict = $witness->verify($receipt->id, $bundle['manifest']['digest']);
    $this->assertFalse($verdict->valid);
    $this->assertSame('backend_not_configured', $verdict->reason);
    $this->assertEquals($before, $this->chainRows());
  }

  /**
   * A backend receives only the checkpoint digest and public contract name.
   */
  public function testWitnessBackendReceivesBoundedContext(): void {
    $chain = $this->container->get('audit_chain.logger');
    $chain->logKeyed('personnel', 'sensitive_operation', [
      'id' => 'person-1',
      'label' => 'Sensitive label',
    ]);
    $digest = $this->container->get('audit_chain.archive_bundle_exporter')
      ->create(1, 1)['manifest']['digest'];
    $before = $this->chainRows();
    $backend = new InMemoryWitnessBackend();
    $manager = $this->container->get('audit_chain.witness_manager');
    $manager->addBackend($backend);
    $this->config('audit_chain.settings')->set('witness_backend', 'memory')->save();

    $receipt = $manager->submit($digest);
    $this->assertSame($digest, $backend->submittedDigest);
    $this->assertSame([
      'contract' => 'audit_chain.checkpoint.v1',
    ], $backend->submittedContext);
    $this->assertFalse($manager->verify($receipt->id, $digest)->valid);
    $this->assertSame('confirmed', $manager->upgrade($receipt->id)->status);
    $this->assertTrue($manager->verify($receipt->id, $digest)->valid);
    $this->assertEquals($before, $this->chainRows());
  }

  /**
   * Seal context enters only through a bounded commitment.
   */
  public function testBundleCommitsExistingSealWithoutItsContext(): void {
    $this->config('audit_chain.settings')->set('hash_key', '')->save();
    $chain = $this->container->get('audit_chain.logger');
    $chain->log('legacy', 'unsigned');
    $this->config('audit_chain.settings')->set('hash_key', 'archive_key')->save();
    $this->assertTrue($chain->sealPrefix(1, 'sensitive seal reason')['sealed']);

    $bundle = $this->container->get('audit_chain.archive_bundle_exporter')->create(1, 2);

    $this->assertSame(1, $bundle['manifest']['seal']['sealed_through_id']);
    $this->assertNull($bundle['manifest']['successor']);
    $encoded = json_encode($bundle, JSON_THROW_ON_ERROR);
    $this->assertStringNotContainsString('sensitive seal reason', $encoded);
  }

  /**
   * A valid successor is committed without exposing its recovery context.
   */
  public function testBundleCommitsValidSuccessorWithoutItsContext(): void {
    $chain = $this->container->get('audit_chain.logger');
    $this->makeFork($chain);
    $recovery = $this->container->get('audit_chain.recovery');
    $prepared = $recovery->prepare();
    $recovery->activate(self::SEGMENT, $prepared['snapshot_digest'], [
      'incident' => 'sensitive incident reference',
      'reason' => 'sensitive recovery reason',
      'approved_by' => 'approved operator',
      'backup_digest' => str_repeat('a', 64),
    ]);

    $bundle = $this->container->get('audit_chain.archive_bundle_exporter')->create(1, 4);
    $this->assertSame(
      self::SEGMENT,
      $bundle['manifest']['successor']['segment_id'],
    );
    $encoded = json_encode($bundle, JSON_THROW_ON_ERROR);
    foreach (['sensitive incident reference', 'sensitive recovery reason', 'approved operator', 'archive_key'] as $forbidden) {
      $this->assertStringNotContainsString($forbidden, $encoded);
    }
  }

  /**
   * The shipped JSON Schema fixes the minimized bundle row surface.
   */
  public function testArchiveBundleSchemaMatchesMinimizedRows(): void {
    $path = dirname(__DIR__, 3) . '/docs/archive-bundle-v1.schema.json';
    $schema = json_decode((string) file_get_contents($path), TRUE, 64, JSON_THROW_ON_ERROR);
    $this->assertFalse($schema['additionalProperties']);
    $this->assertSame(
      ['contract_version', 'id', 'prev_hash', 'row_hash'],
      array_keys($schema['properties']['rows']['items']['properties']),
    );
  }

  /**
   * The update installs archival tables without rewriting the chain.
   */
  public function testArchivalSchemaUpdatePreservesRows(): void {
    $this->container->get('audit_chain.logger')->logKeyed('test', 'before_update');
    $before = $this->chainRows();
    $schema = $this->container->get('database')->schema();
    $schema->dropTable('audit_chain_checkpoint');
    $schema->dropTable('audit_chain_witness_receipt');

    $this->container->get('module_handler')->loadInclude('audit_chain', 'install');
    audit_chain_update_10005();
    audit_chain_update_10005();

    $this->assertTrue($schema->tableExists('audit_chain_checkpoint'));
    $this->assertTrue($schema->tableExists('audit_chain_witness_receipt'));
    $this->assertEquals($before, $this->chainRows());
  }

  /**
   * Returns the stored chain rows in global order.
   */
  private function chainRows(): array {
    return $this->container->get('database')->select('audit_chain_log', 'l')
      ->fields('l')->orderBy('id')->execute()->fetchAll();
  }

  /**
   * Builds a synthetic authenticated fork for the successor workflow.
   */
  private function makeFork(AuditChainLogger $chain): void {
    foreach (['root', 'left', 'right'] as $operation) {
      $chain->logKeyed('test', $operation);
    }
    $rows = $this->chainRows();
    $right = (array) $rows[2];
    $right['prev_hash'] = $rows[0]->row_hash;
    $canonical = new \ReflectionMethod(AuditChainLogger::class, 'canonicalFromRecord');
    $right['row_hash'] = hash_hmac(
      'sha256',
      $right['prev_hash'] . '|' . $canonical->invoke($chain, $right),
      'archive-test-secret',
    );
    $this->container->get('database')->update('audit_chain_log')
      ->fields([
        'prev_hash' => $right['prev_hash'],
        'row_hash' => $right['row_hash'],
      ])
      ->condition('id', 3)
      ->execute();
  }

}

/**
 * In-memory witness used to exercise the digest-only extension seam.
 */
final class InMemoryWitnessBackend implements IdentifiedWitnessBackendInterface {

  /**
   * Last submitted checkpoint digest.
   */
  public ?string $submittedDigest = NULL;

  /**
   * Last submitted bounded context.
   */
  public array $submittedContext = [];

  /**
   * {@inheritdoc}
   */
  public function id(): string {
    return 'memory';
  }

  /**
   * {@inheritdoc}
   */
  public function submit(string $digestHex, array $context): WitnessReceipt {
    $this->submittedDigest = $digestHex;
    $this->submittedContext = $context;
    return new WitnessReceipt(
      'memory-receipt',
      $this->id(),
      WitnessReceipt::STATUS_SUBMITTED,
      'opaque-test-token',
    );
  }

  /**
   * {@inheritdoc}
   */
  public function upgrade(WitnessReceipt $pending): WitnessReceipt {
    return new WitnessReceipt(
      $pending->id,
      $pending->backendId,
      WitnessReceipt::STATUS_CONFIRMED,
      $pending->opaqueToken,
    );
  }

  /**
   * {@inheritdoc}
   */
  public function verify(WitnessReceipt $receipt, string $digestHex): WitnessVerdict {
    $valid = $receipt->opaqueToken === 'opaque-test-token'
      && $digestHex === $this->submittedDigest;
    return new WitnessVerdict($valid, $valid ? 'confirmed' : 'invalid');
  }

}
