<?php

declare(strict_types=1);

namespace Drupal\Tests\audit_chain\Kernel;

use Drupal\audit_chain\AuditChainLogger;
use Drupal\audit_chain\EvidenceExporter;
use Drupal\audit_chain\ScheduledVerifier;
use Drupal\audit_chain\WitnessDemo;
use Drupal\KernelTests\KernelTestBase;
use PHPUnit\Framework\Attributes\Group;

/**
 * Kernel tests for uninstall clearing module-owned state.
 *
 * Schema tables drop on uninstall; state does not. A leftover prefix seal
 * makes the next install's empty-chain verify() return seal_broken. A
 * leftover demo digest can resolve against empty tables after reinstall.
 *
 * @group audit_chain
 */
#[Group('audit_chain')]
final class AuditChainUninstallTest extends KernelTestBase {

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
    $this->installSchema('user', ['users_data']);
    $this->installAuditChainTables();
    $this->installConfig(['system', 'user', 'audit_chain']);
  }

  /**
   * Uninstall deletes module-owned state so reinstall verifies an empty chain.
   */
  public function testUninstallClearsModuleOwnedState(): void {
    $sealKey = AuditChainLogger::STATE_SEAL;
    $verificationKey = ScheduledVerifier::STATE_KEY;
    $demoKey = WitnessDemo::STATE_KEY;
    $retentionKey = 'audit_chain.retention_refused';
    $checkpointKey = EvidenceExporter::CHECKPOINT_PREFIX . sha1('file:///tmp/audit-chain-uninstall-test.ndjson');

    $state = $this->container->get('state');
    $state->set($sealKey, [
      'sealed_through_id' => 1,
      'row_count' => 1,
      'prefix_digest' => str_repeat('a', 64),
      'seal_mac' => str_repeat('b', 64),
      'timestamp' => 1,
      'uid' => 0,
      'reason' => 'leftover-after-uninstall',
      'key_id' => 'gone',
    ]);
    $state->set($verificationKey, [
      'ok' => TRUE,
      'time' => 1,
      'reason' => NULL,
    ]);
    // Old sessions stored unused receipt_ids. Uninstall must drop the
    // whole key, not only the digest field.
    $state->set($demoKey, [
      'digest' => str_repeat('c', 64),
      'receipt_ids' => ['leftover-receipt'],
    ]);
    $state->set($retentionKey, TRUE);
    $state->set($checkpointKey, ['last_id' => 12]);

    $this->container->get('module_installer')->uninstall(['audit_chain']);

    $state = $this->container->get('state');
    $this->assertNull($state->get($sealKey));
    $this->assertNull($state->get($verificationKey));
    $this->assertNull($state->get($demoKey));
    $this->assertNull($state->get($retentionKey));
    $this->assertNull($state->get($checkpointKey));

    $this->container->get('module_installer')->install(['audit_chain']);

    $chain = $this->container->get('audit_chain.logger');
    $this->assertNull($chain->getSeal());
    $result = $chain->verify();
    $this->assertTrue($result['ok'], 'An empty chain after reinstall must verify.');
    $this->assertNull($result['reason']);
  }

}
