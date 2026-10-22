<?php

declare(strict_types=1);

namespace Drupal\Tests\audit_chain\Kernel;

use Drupal\Core\Site\Settings;
use Drupal\key\Entity\Key;
use Drupal\KernelTests\KernelTestBase;
use PHPUnit\Framework\Attributes\Group;

/**
 * Optional live smoke against public calendars and an XRPL testnet relay.
 *
 * Skipped unless AUDIT_CHAIN_LIVE_WITNESS=1. CI does not set that variable.
 *
 * @group audit_chain
 */
#[Group('audit_chain')]
final class WitnessLiveSmokeTest extends KernelTestBase {

  use AuditChainSchemaTrait;

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['system', 'user', 'key', 'encrypt', 'audit_chain'];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    if (getenv('AUDIT_CHAIN_LIVE_WITNESS') !== '1') {
      $this->markTestSkipped('Live witness smoke is opt-in via AUDIT_CHAIN_LIVE_WITNESS=1.');
    }
    $this->installEntitySchema('user');
    $this->installAuditChainTables();
    $this->installConfig(['audit_chain']);
    new Settings([
      'audit_chain_instance_id' => 'live-smoke-instance',
      'audit_chain_witness_xrpl_token' => (string) getenv('AUDIT_CHAIN_XRPL_TOKEN'),
    ] + Settings::getAll());
    Key::create([
      'id' => 'live_key',
      'label' => 'Live smoke key',
      'key_type' => 'authentication',
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => 'live-smoke-secret'],
    ])->save();
    $this->config('audit_chain.settings')->set('hash_key', 'live_key')->save();
    $this->container->get('audit_chain.logger')->logKeyed('test', 'live_smoke');
  }

  /**
   * Submits to public OpenTimestamps calendars and, if configured, XRPL.
   */
  public function testLiveCalendarsAndOptionalXrplRelay(): void {
    $digest = $this->container->get('audit_chain.archive_bundle_exporter')
      ->create()['manifest']['digest'];
    $manager = $this->container->get('audit_chain.witness_manager');
    $ots = $manager->submit($digest, 'opentimestamps');
    $this->assertSame('opentimestamps', $ots->backendId);
    $this->assertContains($ots->status, ['pending', 'confirmed']);
    $upgraded = $manager->upgrade($ots->id);
    $this->assertContains($upgraded->status, ['pending', 'confirmed']);
    $verdict = $manager->verify($ots->id, $digest);
    if ($upgraded->status === 'pending') {
      $this->assertFalse($verdict->valid);
    }

    $relay = (string) getenv('AUDIT_CHAIN_XRPL_RELAY_URL');
    $read = (string) getenv('AUDIT_CHAIN_XRPL_READ_URL');
    $account = (string) getenv('AUDIT_CHAIN_XRPL_ACCOUNT');
    $sink = (string) getenv('AUDIT_CHAIN_XRPL_SINK');
    $token = (string) getenv('AUDIT_CHAIN_XRPL_TOKEN');
    if ($relay === '' || $read === '' || $account === '' || $sink === '' || $token === '') {
      $this->markTestSkipped('XRPL live smoke needs AUDIT_CHAIN_XRPL_* relay settings.');
    }
    $this->config('audit_chain.settings')->set('witness_xrpl', [
      'relay_url' => $relay,
      'read_url' => $read,
      'network' => 'xrpl:testnet',
      'sink_address' => $sink,
      'witness_account' => $account,
    ])->save();
    $xrpl = $manager->submit($digest, 'xrpl');
    $this->assertSame('xrpl', $xrpl->backendId);
    $this->assertContains($xrpl->status, ['pending', 'confirmed']);
    $xrplUpgraded = $manager->upgrade($xrpl->id);
    $this->assertContains($xrplUpgraded->status, ['pending', 'confirmed']);
  }

}
