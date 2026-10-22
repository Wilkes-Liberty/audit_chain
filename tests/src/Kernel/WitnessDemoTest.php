<?php

declare(strict_types=1);

namespace Drupal\Tests\audit_chain\Kernel;

use Drupal\audit_chain\RewindDetector;
use Drupal\audit_chain\WitnessDemo;
use Drupal\Component\Datetime\TimeInterface;
use Drupal\Component\Serialization\Yaml;
use Drupal\Core\Site\Settings;
use Drupal\key\Entity\Key;
use Drupal\KernelTests\KernelTestBase;
use PHPUnit\Framework\Attributes\Group;

/**
 * Exercises the opt-in witness demo against scripted calendars and a relay.
 *
 * @group audit_chain
 */
#[Group('audit_chain')]
final class WitnessDemoTest extends KernelTestBase {

  use AuditChainSchemaTrait;

  private const HASH = 'CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC';

  /**
   * Scripted HTTP double.
   */
  private ScriptedWitnessTransport $transport;

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['system', 'user', 'key', 'encrypt', 'audit_chain'];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->transport = new ScriptedWitnessTransport();
    $this->container->set('audit_chain.witness_transport', $this->transport);
    $this->container->set('audit_chain.witness_dns', new MapWitnessDns([
      'calendar.example' => ['1.1.1.1'],
      'alice.example' => ['1.1.1.1'],
      'headers.example' => ['1.1.1.1'],
      'relay.example' => ['1.1.1.1'],
      'read.example' => ['1.1.1.1'],
    ]));
    $time = $this->createMock(TimeInterface::class);
    $time->method('getRequestTime')->willReturn(1790000000);
    $time->method('getCurrentTime')->willReturn(1790000000);
    $this->container->set('datetime.time', $time);
    $this->installEntitySchema('user');
    $this->installAuditChainTables();
    $this->installConfig(['audit_chain']);
    $this->enableDemoSettings();
    Key::create([
      'id' => 'demo_key',
      'label' => 'Demo key',
      'key_type' => 'authentication',
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => 'demo-test-secret'],
    ])->save();
    $this->config('audit_chain.settings')->set('hash_key', 'demo_key')->save();
    $this->config('audit_chain.settings')->set('witness_opentimestamps', [
      'calendars' => ['https://calendar.example'],
      'upgrade_allowlist' => [
        'https://calendar.example',
        'https://alice.example',
      ],
      'header_url' => 'https://headers.example/api',
      'min_depth' => 6,
    ])->save();
    $this->container->get('audit_chain.logger')->logKeyed('test', 'demo_row');
  }

  /**
   * Shipped install config leaves both witnesses off.
   */
  public function testShippedDefaultsLeaveWitnessesInactive(): void {
    $path = dirname(__DIR__, 3) . '/config/install/audit_chain.settings.yml';
    $yaml = Yaml::decode((string) file_get_contents($path));
    $this->assertIsArray($yaml);
    $this->assertSame('', $yaml['witness_backend']);
    $this->assertSame('', $yaml['witness_xrpl']['relay_url']);
    $this->assertSame('', $yaml['witness_xrpl']['read_url']);
    $this->assertSame('', $yaml['witness_xrpl']['network']);
    $this->assertSame('', $this->config('audit_chain.settings')->get('witness_backend'));
  }

  /**
   * The demo command does nothing without the settings switch.
   */
  public function testDemoRefusesWhenSwitchOff(): void {
    $all = Settings::getAll();
    unset($all['audit_chain_witness_demo']);
    new Settings($all);
    $refused = $this->rebuildDemo()->step('prepare');
    $this->assertSame(1, $refused->exitCode);
    $this->assertSame(['witness_demo_disabled'], $refused->lines);
    $this->assertSame('', $this->config('audit_chain.settings')->get('witness_xrpl.relay_url'));
    $this->assertSame([], $this->transport->calls);
  }

  /**
   * Prepare refuses a mainnet relay before writing site config.
   */
  public function testDemoPrepareRefusesMainnet(): void {
    $this->enableDemoSettings('https://s1.ripple.com');
    $demo = $this->rebuildDemo();
    $result = $demo->step('prepare');
    $this->assertSame(1, $result->exitCode);
    $this->assertSame(['witness_xrpl_mainnet_refused'], $result->lines);
    $this->assertSame('', $this->config('audit_chain.settings')->get('witness_xrpl.relay_url'));
  }

  /**
   * The demo walks submit, pending upgrade, verify, tamper, and reset.
   */
  public function testDemoWalksBothBackendsWithMockedNetwork(): void {
    $demo = $this->rebuildDemo();
    $prepared = $demo->step('prepare');
    $this->assertSame(0, $prepared->exitCode);
    $this->assertContains('demo=on', $prepared->lines);
    $this->assertContains('witness_backend=', $prepared->lines);
    $this->assertSame('', $this->config('audit_chain.settings')->get('witness_backend'));
    $this->assertSame('xrpl:testnet', $this->config('audit_chain.settings')->get('witness_xrpl.network'));

    $checkpoint = $demo->step('checkpoint');
    $this->assertSame(0, $checkpoint->exitCode);
    $digest = NULL;
    foreach ($checkpoint->lines as $line) {
      if (str_starts_with($line, 'digest=')) {
        $digest = substr($line, 7);
      }
    }
    $this->assertIsString($digest);
    $this->assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $digest);

    $this->transport->script[] = [
      'status' => 200,
      'body' => $this->pendingBody((string) hex2bin($digest), 'https://alice.example'),
      'match' => 'calendar.example',
    ];
    $this->transport->script[] = [
      'status' => 200,
      'body' => json_encode(['outcome' => 'pending', 'tx_hash' => self::HASH], JSON_THROW_ON_ERROR),
      'match' => 'relay.example',
    ];
    $submitted = $demo->step('submit', $digest);
    $this->assertSame(0, $submitted->exitCode, implode("\n", $submitted->lines));
    $this->assertStringContainsString('opentimestamps pending', implode("\n", $submitted->lines));
    $this->assertStringContainsString('xrpl pending', implode("\n", $submitted->lines));

    $status = $demo->step('status', $digest);
    $this->assertSame(0, $status->exitCode);
    $this->assertCount(2, $this->receipts($digest));

    // Queue the ledger read first so a UUID-oldest XRPL receipt cannot
    // consume the OpenTimestamps 404 and starve the calendar request.
    $this->transport->script[] = [
      'status' => 200,
      'body' => json_encode($this->xrplTransaction(TRUE, $digest), JSON_THROW_ON_ERROR),
      'match' => 'read.example/transactions',
    ];
    $this->transport->script[] = [
      'status' => 404,
      'body' => '',
      'match' => 'alice.example',
    ];
    $upgraded = $demo->step('upgrade', $digest);
    $this->assertSame(0, $upgraded->exitCode, implode("\n", $upgraded->lines));
    $this->assertStringContainsString('opentimestamps pending', implode("\n", $upgraded->lines));
    $this->assertStringContainsString('xrpl confirmed', implode("\n", $upgraded->lines));

    $this->transport->script[] = [
      'status' => 200,
      'body' => json_encode($this->xrplTransaction(TRUE, $digest), JSON_THROW_ON_ERROR),
      'match' => 'read.example/transactions',
    ];
    $verified = $demo->step('verify', $digest);
    $this->assertSame(0, $verified->exitCode, implode("\n", $verified->lines));
    $this->assertStringContainsString('xrpl confirmed valid confirmed', implode("\n", $verified->lines));

    $this->transport->script[] = [
      'status' => 200,
      'body' => json_encode([
        'transactions' => [$this->xrplTransaction(TRUE, $digest)],
      ], JSON_THROW_ON_ERROR),
      'match' => 'read.example/accounts',
    ];
    $tamper = $demo->step('tamper', $digest);
    $this->assertSame(0, $tamper->exitCode, implode("\n", $tamper->lines));
    $printed = implode("\n", $tamper->lines);
    $this->assertStringContainsString('checkpoint_digest_mismatch', $printed);
    $this->assertStringContainsString('rewind_scheduled not_configured', $printed);
    $this->assertStringContainsString('rewind_xrpl ' . RewindDetector::STATUS_MATCHES, $printed);

    $reset = $demo->step('reset');
    $this->assertSame(0, $reset->exitCode);
    $this->assertSame([], $this->receipts($digest));
    $this->assertSame('', $this->config('audit_chain.settings')->get('witness_xrpl.relay_url'));
    $this->assertSame('', $this->config('audit_chain.settings')->get('witness_backend'));
  }

  /**
   * Reset still clears an overlay after the demo switch is removed.
   */
  public function testDemoResetClearsOverlayAndReceipts(): void {
    $demo = $this->rebuildDemo();
    $this->assertSame(0, $demo->step('prepare')->exitCode);
    $this->assertSame('https://relay.example/witness', $this->config('audit_chain.settings')->get('witness_xrpl.relay_url'));
    new Settings(array_diff_key(Settings::getAll(), [
      'audit_chain_witness_demo' => TRUE,
    ]));
    $cleared = $this->rebuildDemo()->step('reset');
    $this->assertSame(0, $cleared->exitCode);
    $this->assertSame('', $this->config('audit_chain.settings')->get('witness_xrpl.relay_url'));
  }

  /**
   * Rebuilds the demo service after Settings changes.
   */
  private function rebuildDemo(): WitnessDemo {
    return new WitnessDemo(
      new Settings(Settings::getAll()),
      $this->container->get('config.factory'),
      $this->container->get('state'),
      $this->container->get('audit_chain.archive_bundle_exporter'),
      $this->container->get('audit_chain.witness_manager'),
      $this->container->get('audit_chain.rewind_detector'),
      $this->container->get('database'),
    );
  }

  /**
   * Turns on the demo switch and the relay overlay keys.
   */
  private function enableDemoSettings(string $relay = 'https://relay.example/witness'): void {
    new Settings([
      'audit_chain_instance_id' => 'demo-test-instance',
      'audit_chain_witness_demo' => TRUE,
      'audit_chain_witness_xrpl_token' => 'relay-test-token',
      'audit_chain_witness_xrpl_relay_url' => $relay,
      'audit_chain_witness_xrpl_read_url' => 'https://read.example',
      'audit_chain_witness_xrpl_witness_account' => 'rWitness11111111111111111111111',
      'audit_chain_witness_xrpl_sink_address' => 'rSink11111111111111111111111111',
    ] + Settings::getAll());
  }

  /**
   * Loads receipts for one digest.
   *
   * @return list<object>
   *   Receipt rows.
   */
  private function receipts(string $digest): array {
    return $this->container->get('database')->select('audit_chain_witness_receipt', 'w')
      ->fields('w')
      ->condition('checkpoint_digest', $digest)
      ->execute()
      ->fetchAll();
  }

  /**
   * Builds a one-attestation calendar body.
   */
  private function pendingBody(string $digest, string $uri): string {
    $this->assertSame(32, strlen($digest));
    $payload = chr(strlen($uri)) . $uri;
    $attestation = hex2bin('83dfe30d2ef90c8e') . chr(strlen($payload)) . $payload;
    return "\x00" . $attestation;
  }

  /**
   * Builds one ledger transaction fixture.
   *
   * @return array<string, mixed>
   *   Transaction body the read endpoint would return.
   */
  private function xrplTransaction(bool $validated, string $digest): array {
    return [
      'validated' => $validated,
      'ledger_index' => 42,
      'close_time' => 1700000100,
      'TransactionType' => 'Payment',
      'Account' => 'rWitness11111111111111111111111',
      'Destination' => 'rSink11111111111111111111111111',
      'Amount' => '1',
      'Fee' => '12',
      'hash' => self::HASH,
      'meta' => ['TransactionResult' => 'tesSUCCESS'],
      'Memos' => [[
        'Memo' => [
          'MemoType' => bin2hex('audit_chain.checkpoint.v1'),
          'MemoData' => bin2hex((string) hex2bin($digest)),
        ],
      ],
      ],
    ];
  }

}
