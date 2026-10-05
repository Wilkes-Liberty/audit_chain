<?php

declare(strict_types=1);

namespace Drupal\Tests\audit_chain\Kernel;

use Drupal\audit_chain\OpenTimestampsWitnessBackend;
use Drupal\audit_chain\IdentifiedWitnessBackendInterface;
use Drupal\audit_chain\Witness\OtsProof;
use Drupal\audit_chain\Witness\WitnessDnsResolverInterface;
use Drupal\audit_chain\Witness\WitnessTransportInterface;
use Drupal\audit_chain\WitnessOperator;
use Drupal\audit_chain\WitnessReceipt;
use Drupal\audit_chain\WitnessVerdict;
use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Site\Settings;
use Drupal\KernelTests\KernelTestBase;
use Drupal\key\Entity\Key;
use PHPUnit\Framework\Attributes\Group;
use PHPUnit\Framework\Attributes\RunTestsInSeparateProcesses;

/**
 * Exercises witness clients against offline protocol fixtures.
 *
 * @group audit_chain
 * @runTestsInSeparateProcesses
 */
#[Group('audit_chain')]
#[RunTestsInSeparateProcesses]
final class WitnessBackendsTest extends KernelTestBase {

  use AuditChainSchemaTrait;

  private const DIGEST = '1111111111111111111111111111111111111111111111111111111111111111';

  private const CHAIN_MSG = '6d76876234cb481bf9b63333970d4090e255965700ddd04b571ff1221daac77f';

  private const DISPLAY = 'a6f79bec9687877423e75f12d38be5ca406c37f1cd11b23d8ece359157acc72d';

  private const DISPLAY_CHAIN = '4e6b5a2fff8b628e4355b9680b51c3031a9da36cfd767ed0a6029302e80d5f6a';

  private const HEADER = '010000002222222222222222222222222222222222222222222222222222222222222222111111111111111111111111111111111111111111111111111111111111111100f15365ffff001d00000000';

  private const HEADER_CHAIN = '0100000022222222222222222222222222222222222222222222222222222222222222226d76876234cb481bf9b63333970d4090e255965700ddd04b571ff1221daac77f00f15365ffff001d00000000';

  private const CAL = '0083dfe30d2ef90c8e2e2d68747470733a2f2f616c6963652e6274632e63616c656e6461722e6f70656e74696d657374616d70732e6f7267';

  private const DETACHED_PENDING = '004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294010811111111111111111111111111111111111111111111111111111111111111110083dfe30d2ef90c8e2e2d68747470733a2f2f616c6963652e6274632e63616c656e6461722e6f70656e74696d657374616d70732e6f7267';

  private const DETACHED_BITCOIN = '004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e8929401081111111111111111111111111111111111111111111111111111111111111111000588960d73d7190103c0a233';

  private const DETACHED_BOTH = '004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e8929401081111111111111111111111111111111111111111111111111111111111111111ff000588960d73d7190103c0a2330083dfe30d2ef90c8e2e2d68747470733a2f2f616c6963652e6274632e63616c656e6461722e6f70656e74696d657374616d70732e6f7267';

  private const DETACHED_LITECOIN = '004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294010811111111111111111111111111111111111111111111111111111111111111110006869a0d73d71b45010a';

  private const DETACHED_UNKNOWN = '004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e892940108111111111111111111111111111111111111111111111111111111111111111100010101010101010100';

  private const DETACHED_CHAIN = '004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e8929401081111111111111111111111111111111111111111111111111111111111111111f002010208000588960d73d7190103c0a233';

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
    $this->container->set('audit_chain.witness_dns', new MapWitnessDns($this->publicDns()));
    $time = $this->createMock(TimeInterface::class);
    $time->method('getRequestTime')->willReturn(1790000000);
    $time->method('getCurrentTime')->willReturn(1790000000);
    $this->container->set('datetime.time', $time);
    $this->installEntitySchema('user');
    $this->installAuditChainTables();
    $this->installConfig(['audit_chain']);
    new Settings([
      'audit_chain_instance_id' => 'archive-test-instance',
      'audit_chain_witness_xrpl_token' => 'relay-test-token',
    ] + Settings::getAll());
    Key::create([
      'id' => 'archive_key',
      'label' => 'Archive test key',
      'key_type' => 'authentication',
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => 'archive-test-secret'],
    ])->save();
    $this->config('audit_chain.settings')->set('hash_key', 'archive_key')->save();
    $this->container->get('audit_chain.logger')->logKeyed('test', 'before_witness');
  }

  /**
   * Hand-built proofs round-trip and reject truncation or a deep tree.
   */
  public function testIndependentProofFixtures(): void {
    $header = hex2bin(self::HEADER);
    $this->assertNotFalse($header);
    $display = bin2hex(strrev(hash('sha256', hash('sha256', $header, TRUE), TRUE)));
    $this->assertSame(self::DISPLAY, $display);
    $this->assertSame(self::CHAIN_MSG, bin2hex(substr((string) hex2bin(self::HEADER_CHAIN), 36, 32)));

    foreach ([
      self::DETACHED_PENDING,
      self::DETACHED_BITCOIN,
      self::DETACHED_BOTH,
      self::DETACHED_LITECOIN,
      self::DETACHED_UNKNOWN,
      self::DETACHED_CHAIN,
    ] as $hex) {
      $bytes = hex2bin($hex);
      $this->assertNotFalse($bytes);
      $decoded = OtsProof::decodeDetached($bytes);
      $this->assertSame(self::DIGEST, bin2hex($decoded['digest']));
      $this->assertSame($bytes, OtsProof::encodeDetached($decoded['digest'], $decoded['proof']));
    }

    $bitcoin = OtsProof::decodeDetached((string) hex2bin(self::DETACHED_BITCOIN));
    $this->assertSame([[
      'height' => 840000,
      'message' => hex2bin(self::DIGEST),
    ],
    ], $bitcoin['proof']->bitcoinCandidates());
    $chain = OtsProof::decodeDetached((string) hex2bin(self::DETACHED_CHAIN));
    $this->assertSame(self::CHAIN_MSG, bin2hex($chain['proof']->bitcoinCandidates()[0]['message']));
    $this->assertNotSame($chain['proof']->message(), $chain['proof']->bitcoinCandidates()[0]['message']);

    $calendar = OtsProof::decodeTimestamp((string) hex2bin(self::CAL), (string) hex2bin(self::DIGEST));
    $this->assertSame(
      (string) hex2bin(self::DETACHED_PENDING),
      OtsProof::detachedFromCalendar((string) hex2bin(self::DIGEST), (string) hex2bin(self::CAL)),
    );
    $this->assertSame(
      'https://alice.btc.calendar.opentimestamps.org',
      $calendar->pendingNodes()[0]->attestations()[0]['uri'],
    );

    foreach ([
      self::DETACHED_BITCOIN . '00',
      '00' . self::DETACHED_BITCOIN,
    ] as $broken) {
      try {
        OtsProof::decodeDetached((string) hex2bin($broken));
        $this->fail('Malformed proof was accepted.');
      }
      catch (\RuntimeException $exception) {
        $this->assertSame('ots_malformed', $exception->getMessage());
      }
    }
    $nested = str_repeat("\x08", 40) . hex2bin(self::CAL);
    try {
      OtsProof::decodeTimestamp($nested, (string) hex2bin(self::DIGEST));
      $this->fail('A too-deep proof was accepted.');
    }
    catch (\RuntimeException $exception) {
      $this->assertSame('ots_malformed', $exception->getMessage());
    }
  }

  /**
   * Submit sends the raw digest or stores nothing.
   */
  public function testSubmitIsDigestOnlyAndFailClosed(): void {
    $before = $this->chainRows();
    $digest = $this->realDigest();
    $this->configureOpenTimestamps();
    $manager = $this->container->get('audit_chain.witness_manager');

    try {
      $manager->submit(str_repeat('2', 64));
      $this->fail('A digest that is not a checkpoint was submitted.');
    }
    catch (\InvalidArgumentException) {
      $this->assertSame([], $this->transport->calls);
    }

    $this->transport->script[] = ['status' => 200, 'body' => '<html></html>'];
    try {
      $manager->submit($digest, 'opentimestamps');
      $this->fail('An HTML calendar response was stored.');
    }
    catch (\RuntimeException $exception) {
      $this->assertSame('witness_submit_unusable', $exception->getMessage());
    }
    $this->assertSame([], $this->receiptCount());

    $this->transport->script[] = ['status' => 302, 'body' => ''];
    try {
      $manager->submit($digest, 'opentimestamps');
      $this->fail('A redirect was treated as a calendar proof.');
    }
    catch (\RuntimeException) {
    }
    $this->assertCount(2, $this->transport->calls);
    $this->assertSame('POST', $this->transport->calls[1]['method']);

    $this->transport->script[] = [
      'status' => 200,
      'body' => "\x00" . hex2bin('0101010101010101') . "\x00",
    ];
    try {
      $manager->submit($digest, 'opentimestamps');
      $this->fail('An unknown attestation was stored.');
    }
    catch (\RuntimeException) {
    }

    $this->transport->script[] = [
      'status' => 200,
      'body' => $this->pendingBody((string) hex2bin($digest), 'https://alice.example'),
    ];
    $receipt = $manager->submit($digest, 'opentimestamps');
    $call = $this->transport->calls[array_key_last($this->transport->calls)];
    $this->assertSame((string) hex2bin($digest), $call['body']);
    $this->assertSame(32, strlen($call['body']));
    $this->assertSame([
      'Accept' => 'application/vnd.opentimestamps.v1',
      'Content-Type' => 'application/octet-stream',
      'User-Agent' => 'audit_chain',
    ], $call['headers']);
    $this->assertStringNotContainsString($digest, $call['body']);
    $stored = base64_decode($receipt->opaqueToken, TRUE);
    $this->assertNotFalse($stored);
    $decoded = OtsProof::decodeDetached($stored);
    $this->assertSame($digest, bin2hex($decoded['digest']));
    $this->assertSame('pending', $receipt->status);
    $this->assertSame('https://alice.example', $decoded['proof']->pendingNodes()[0]->attestations()[0]['uri']);

    $again = $manager->submit($digest, 'opentimestamps');
    $this->assertSame($receipt->id, $again->id);
    $this->assertCount(4, $this->transport->calls);

    $this->container->set('audit_chain.witness_dns', new MapWitnessDns([
      'calendar.example' => ['10.1.2.3'],
    ]));
    $isolated = new OpenTimestampsWitnessBackend(
      $this->container->get('config.factory'),
      $this->transport,
      new MapWitnessDns(['calendar.example' => ['100.64.0.8']]),
      $this->container->get('uuid'),
    );
    $calls = count($this->transport->calls);
    try {
      $isolated->submit($digest, ['contract' => 'audit_chain.checkpoint.v1']);
      $this->fail('A carrier-grade NAT calendar was contacted.');
    }
    catch (\RuntimeException) {
    }
    $this->assertCount($calls, $this->transport->calls);
    $this->assertEquals($before, $this->chainRows());
  }

  /**
   * Bitcoin confirmation depends on the header, not the stored status.
   */
  public function testBitcoinHeaderPolicy(): void {
    $before = $this->chainRows();
    $this->configureOpenTimestamps();
    $this->checkpoint(self::DIGEST);
    $manager = $this->container->get('audit_chain.witness_manager');
    $token = base64_encode((string) hex2bin(self::DETACHED_CHAIN));
    $id = $this->insertReceipt($token, 'pending');

    $this->scriptHeader(self::DISPLAY_CHAIN, self::HEADER_CHAIN, '840005', '{"in_best_chain":true}');
    $verdict = $manager->verify($id, self::DIGEST);
    $this->assertFalse($verdict->valid);
    $this->assertSame('receipt_not_final', $verdict->reason);
    $this->assertCount(4, $this->transport->calls);
    foreach ($this->transport->calls as $call) {
      $this->assertStringNotContainsString('/timestamp/', $call['url']);
    }

    $this->transport->calls = [];
    $this->scriptHeader(self::DISPLAY_CHAIN, self::HEADER_CHAIN, '840005', '{"in_best_chain":true}');
    $upgraded = $manager->upgrade($id);
    $this->assertSame('pending', $upgraded->status);
    $this->scriptHeader(self::DISPLAY_CHAIN, self::HEADER_CHAIN, '840005', '{"in_best_chain":true}');
    $this->assertSame('receipt_not_final', $manager->verify($id, self::DIGEST)->reason);
    $this->assertCount(8, $this->transport->calls);

    $this->transport->calls = [];
    $this->scriptHeader(self::DISPLAY_CHAIN, self::HEADER_CHAIN, '840006', '{"in_best_chain":true}');
    $confirmed = $manager->upgrade($id);
    $this->assertSame('confirmed', $confirmed->status);
    $this->scriptHeader(self::DISPLAY_CHAIN, self::HEADER_CHAIN, '840006', '{"in_best_chain":true}');
    $valid = $manager->verify($id, self::DIGEST);
    $this->assertTrue($valid->valid);
    $this->assertSame(840000, $valid->evidence['bitcoin_height']);
    $this->assertSame(self::DISPLAY_CHAIN, $valid->evidence['bitcoin_block_hash']);
    $this->assertSame(1700000000, $valid->evidence['bitcoin_block_time']);
    $this->assertSame('header_provider', $valid->evidence['trust_mode']);
    $this->assertNotSame(1790000000, $valid->evidence['bitcoin_block_time']);
    foreach ($this->transport->calls as $call) {
      $this->assertStringNotContainsString('/timestamp/', $call['url']);
    }

    $this->transport->calls = [];
    $this->scriptHeader(self::DISPLAY_CHAIN, self::HEADER_CHAIN, '840006', '{"in_best_chain":false}');
    $orphan = $manager->verify($id, self::DIGEST);
    $this->assertFalse($orphan->valid);
    $this->assertSame('attestation_mismatch', $orphan->reason);

    $this->transport->calls = [];
    $this->transport->script[] = ['status' => 500, 'body' => ''];
    $down = $manager->verify($id, self::DIGEST);
    $this->assertSame('backend_unreachable', $down->reason);
    $this->assertSame($token, $this->storedToken($id));

    $litecoin = base64_encode((string) hex2bin(self::DETACHED_LITECOIN));
    $litecoinId = $this->insertReceipt($litecoin, 'confirmed');
    $this->assertSame('attestation_mismatch', $manager->verify($litecoinId, self::DIGEST)->reason);
    $this->assertEquals($before, $this->chainRows());
  }

  /**
   * Upgrade keeps a useful branch and does not let a stale write win.
   */
  public function testUpgradeRecoveryAndConflicts(): void {
    $digest = $this->realDigest();
    $this->configureOpenTimestamps();
    $manager = $this->container->get('audit_chain.witness_manager');
    $raw = (string) hex2bin($digest);
    $this->transport->script[] = [
      'status' => 200,
      'body' => $this->pendingBody($raw, 'https://alice.example'),
    ];
    $receipt = $manager->submit($digest, 'opentimestamps');
    $original = $receipt->opaqueToken;

    $this->transport->script[] = new \RuntimeException('backend_unreachable');
    try {
      $manager->upgrade($receipt->id);
      $this->fail('A calendar outage replaced the stored proof.');
    }
    catch (\RuntimeException) {
    }
    $this->assertSame($original, $this->storedToken($receipt->id));

    $this->transport->script[] = ['status' => 404, 'body' => ''];
    $still = $manager->upgrade($receipt->id);
    $this->assertSame('pending', $still->status);
    $this->assertSame($original, $still->opaqueToken);

    $height = 840000;
    $bitcoin = "\x00" . hex2bin('0588960d73d71901') . "\x03\xc0\xa2\x33";
    $this->assertSame(840000, $height);
    $this->transport->script[] = ['status' => 200, 'body' => $bitcoin];
    $this->scriptHeader(self::DISPLAY, self::HEADER, '840006', '{"in_best_chain":true}');
    try {
      $manager->upgrade($receipt->id);
      $this->fail('A Bitcoin branch for the wrong message was confirmed.');
    }
    catch (\RuntimeException $exception) {
      $this->assertSame('attestation_mismatch', $exception->getMessage());
    }
    $this->assertSame($original, $this->storedToken($receipt->id));

    $race = new RacingWitnessBackend();
    $manager->addBackend($race);
    $this->checkpoint(self::DIGEST);
    $raced = $manager->submit(self::DIGEST, 'race');
    $stored = $manager->upgrade($raced->id);
    $this->assertSame('token-confirmed', $stored->opaqueToken);
    $this->assertSame('confirmed', $stored->status);
    $this->assertSame(2, $race->calls);
    $this->assertSame('token-confirmed', $this->storedToken($raced->id));
  }

  /**
   * XRPL confirmation is a checked read, and a timeout keeps the request id.
   */
  public function testXrplIsNotConfirmationByItself(): void {
    $before = $this->chainRows();
    $digest = $this->realDigest();
    $this->configureXrpl();
    $manager = $this->container->get('audit_chain.witness_manager');
    $database = $this->container->get('database');
    $this->transport->script[] = static function () use ($database): \RuntimeException {
      $count = (int) $database->select('audit_chain_witness_receipt', 'w')
        ->countQuery()->execute()->fetchField();
      if ($count !== 1) {
        return new \RuntimeException('identity_not_durable');
      }
      return new \RuntimeException('relay_timeout');
    };
    $receipt = $manager->submit($digest, 'xrpl');
    $token = json_decode($receipt->opaqueToken, TRUE, 8, JSON_THROW_ON_ERROR);
    $this->assertSame('uncertain', $token['outcome']);
    $this->assertSame('pending', $receipt->status);
    $requestId = $token['request_id'];
    $body = $this->transport->calls[0]['body'];
    $this->assertSame(
      '{"digest":"' . $digest . '","request_id":"' . $requestId . '"}',
      $body,
    );
    $this->assertStringNotContainsString('rWitness', $body);
    $this->assertStringNotContainsString('contract', $body);
    $this->assertSame('Bearer relay-test-token', $this->transport->calls[0]['headers']['Authorization']);

    $reused = $manager->submit($digest, 'xrpl');
    $this->assertSame($receipt->id, $reused->id);
    $this->assertCount(1, $this->transport->calls);

    $hash = str_repeat('A', 64);
    $this->transport->script[] = [
      'status' => 200,
      'body' => json_encode(['outcome' => 'confirmed', 'tx_hash' => $hash], JSON_THROW_ON_ERROR),
    ];
    $this->transport->script[] = [
      'status' => 200,
      'body' => json_encode($this->xrplTransaction($hash, $digest, FALSE), JSON_THROW_ON_ERROR),
    ];
    $provisional = $manager->upgrade($receipt->id);
    $provisionalToken = json_decode($provisional->opaqueToken, TRUE, 8, JSON_THROW_ON_ERROR);
    $this->assertSame('pending', $provisional->status);
    $this->assertSame($requestId, $provisionalToken['request_id']);
    $this->assertNotSame('confirmed', $provisionalToken['outcome']);

    $this->transport->script[] = [
      'status' => 200,
      'body' => json_encode($this->xrplTransaction($hash, str_repeat('ab', 32), TRUE), JSON_THROW_ON_ERROR),
    ];
    $mismatch = $manager->verify($receipt->id, $digest);
    $this->assertSame('attestation_mismatch', $mismatch->reason);

    $this->transport->script[] = [
      'status' => 200,
      'body' => json_encode($this->xrplTransaction($hash, $digest, TRUE), JSON_THROW_ON_ERROR),
    ];
    $confirmed = $manager->upgrade($receipt->id);
    $this->assertSame('confirmed', $confirmed->status);
    $this->transport->script[] = [
      'status' => 200,
      'body' => json_encode($this->xrplTransaction($hash, $digest, TRUE), JSON_THROW_ON_ERROR),
    ];
    $valid = $manager->verify($receipt->id, $digest);
    $this->assertTrue($valid->valid);
    $this->assertSame('relay_and_read_url', $valid->evidence['trust_mode']);
    $this->assertSame(1700000100, $valid->evidence['close_time']);
    $this->assertNotSame(1790000000, $valid->evidence['close_time']);

    $calls = count($this->transport->calls);
    $this->configureXrpl('https://s1.ripple.com');
    try {
      $manager->submit($digest, 'xrpl', TRUE);
      $this->fail('A mainnet relay was accepted.');
    }
    catch (\RuntimeException $exception) {
      $this->assertSame('witness_xrpl_mainnet_refused', $exception->getMessage());
    }
    $this->assertCount($calls, $this->transport->calls);
    $this->assertEquals($before, $this->chainRows());
  }

  /**
   * The operator gate, partial success, and the surfaces that must not submit.
   */
  public function testOperatorGatePartialSuccessAndBoundaries(): void {
    $before = $this->chainRows();
    $digest = $this->realDigest();
    $this->configureOpenTimestamps();
    $manager = $this->container->get('audit_chain.witness_manager');
    $operator = $this->container->get('audit_chain.witness_operator');
    $this->assertInstanceOf(WitnessOperator::class, $operator);

    $refused = $operator->submit($digest, 'opentimestamps', $digest, 'xrpl', FALSE);
    $this->assertSame(1, $refused->exitCode);
    $this->assertSame(['witness_approval_required'], $refused->lines);
    $this->assertSame([], $this->transport->calls);
    $this->assertSame([], $this->receiptCount());

    $this->transport->script[] = [
      'status' => 200,
      'body' => $this->pendingBody((string) hex2bin($digest), 'https://alice.example'),
    ];
    $partial = $manager->submitTo($digest, ['opentimestamps', 'missing-backend']);
    $this->assertNotNull($partial[0]['receipt']);
    $this->assertNull($partial[1]['receipt']);
    $this->assertNotNull($partial[1]['error']);
    $this->assertSame('opentimestamps', $this->receiptCount()[0]->backend_id);

    try {
      $manager->submit($digest, 'not-a-backend');
      $this->fail('An unknown backend fell through to null.');
    }
    catch (\RuntimeException $exception) {
      $this->assertSame('Witness backend is not registered.', $exception->getMessage());
    }

    $this->config('audit_chain.settings')->set('witness_backend', '')->save();
    $nullReceipt = $manager->submit($digest);
    $this->assertSame('null', $nullReceipt->backendId);
    $this->assertSame('backend_not_configured', $manager->verify($nullReceipt->id, $digest)->reason);

    $this->configureXrpl();
    $hash = str_repeat('B', 64);
    $this->transport->script[] = [
      'status' => 200,
      'body' => json_encode(['outcome' => 'confirmed', 'tx_hash' => $hash], JSON_THROW_ON_ERROR),
    ];
    $this->transport->script[] = [
      'status' => 200,
      'body' => json_encode($this->xrplTransaction($hash, $digest, TRUE), JSON_THROW_ON_ERROR),
    ];
    $xrpl = $manager->submit($digest, 'xrpl');
    $this->assertSame('confirmed', $xrpl->status);
    $status = $operator->status($digest, '');
    $this->assertSame(0, $status->exitCode);
    $printed = implode("\n", $status->lines);
    $this->assertStringNotContainsString('confirmations', $printed);
    $this->assertStringContainsString('opentimestamps', $printed);
    $this->assertStringContainsString('xrpl', $printed);
    $this->assertStringContainsString('pending', $printed);
    $this->assertSame(1, $operator->status($digest, 'all')->exitCode);
    $this->transport->script[] = [
      'status' => 200,
      'body' => json_encode($this->xrplTransaction($hash, $digest, TRUE), JSON_THROW_ON_ERROR),
    ];
    $this->assertSame(0, $operator->status($digest, 'xrpl')->exitCode);

    $exported = $operator->export($partial[0]['receipt']->id);
    $this->assertSame(0, $exported->exitCode);
    $this->assertStringStartsWith(OtsProof::MAGIC, (string) $exported->bytes);
    $xrplExport = $operator->export($xrpl->id);
    $this->assertStringContainsString($hash, (string) $xrplExport->bytes);

    $this->container->get('module_handler')->loadInclude('audit_chain', 'install');
    $config = $this->config('audit_chain.settings');
    $config->clear('witness_opentimestamps')->clear('witness_xrpl')->set('witness_backend', 'null')->save();
    $calls = count($this->transport->calls);
    audit_chain_update_10006();
    audit_chain_update_10006();
    $reloaded = $this->config('audit_chain.settings');
    $this->assertSame('null', $reloaded->get('witness_backend'));
    $this->assertSame(6, $reloaded->get('witness_opentimestamps.min_depth'));
    $this->assertSame('', $reloaded->get('witness_xrpl.relay_url'));
    $this->assertCount($calls, $this->transport->calls);

    $form = file_get_contents(dirname(__DIR__, 3) . '/src/Form/AuditChainSettingsForm.php');
    $this->assertIsString($form);
    $this->assertStringNotContainsString('witness_', $form);
    $routing = file_get_contents(dirname(__DIR__, 3) . '/audit_chain.routing.yml');
    $this->assertIsString($routing);
    $this->assertStringNotContainsString('witness', $routing);
    $commands = file_get_contents(dirname(__DIR__, 3) . '/src/Drush/Commands/WitnessCommands.php');
    $this->assertIsString($commands);
    $this->assertStringNotContainsString('::affirmative', $commands);
    foreach (glob(dirname(__DIR__, 3) . '/modules/audit_chain_mcp/src/Plugin/tool/Tool/*.php') ?: [] as $tool) {
      $source = file_get_contents($tool);
      $this->assertIsString($source);
      $this->assertDoesNotMatchRegularExpression('/witness-submit|WitnessManager/', $source);
    }
    $this->assertEquals($before, $this->chainRows());
  }

  /**
   * Public DNS answers used unless a test replaces the resolver.
   *
   * @return array<string, list<string>>
   *   Fixture hosts mapped to one public address.
   */
  private function publicDns(): array {
    $hosts = [
      'calendar.example',
      'alice.example',
      'headers.example',
      'relay.example',
      'read.example',
    ];
    $map = [];
    foreach ($hosts as $host) {
      $map[$host] = ['1.1.1.1'];
    }
    return $map;
  }

  /**
   * Points OpenTimestamps at the fixture hosts.
   */
  private function configureOpenTimestamps(): void {
    $this->config('audit_chain.settings')->set('witness_opentimestamps', [
      'calendars' => ['https://calendar.example'],
      'upgrade_allowlist' => [
        'https://calendar.example',
        'https://alice.example',
      ],
      'header_url' => 'https://headers.example/api',
      'min_depth' => 6,
    ])->save();
  }

  /**
   * Points the XRPL client at the fixture relay.
   */
  private function configureXrpl(string $relay = 'https://relay.example/witness'): void {
    $this->config('audit_chain.settings')->set('witness_xrpl', [
      'relay_url' => $relay,
      'read_url' => 'https://read.example',
      'network' => 'xrpl:testnet',
      'sink_address' => 'rSink11111111111111111111111111',
      'witness_account' => 'rWitness11111111111111111111111',
    ])->save();
  }

  /**
   * Creates one real checkpoint and returns its digest.
   */
  private function realDigest(): string {
    $bundle = $this->container->get('audit_chain.archive_bundle_exporter')->create(1, 1);
    return $bundle['manifest']['digest'];
  }

  /**
   * Inserts a checkpoint row for a fixture digest.
   */
  private function checkpoint(string $digest): void {
    $this->container->get('database')->insert('audit_chain_checkpoint')->fields([
      'digest' => $digest,
      'contract_version' => 1,
      'from_id' => 1,
      'through_id' => 1,
      'row_count' => 1,
      'created' => 1700000000,
      'manifest' => '{}',
    ])->execute();
  }

  /**
   * Inserts one OpenTimestamps receipt for the fixture digest.
   */
  private function insertReceipt(string $token, string $status): string {
    $id = 'ots-' . $status . '-' . substr(hash('sha256', $token), 0, 12);
    $this->container->get('database')->insert('audit_chain_witness_receipt')->fields([
      'id' => $id,
      'checkpoint_digest' => self::DIGEST,
      'backend_id' => 'opentimestamps',
      'status' => $status,
      'submitted' => 1790000000,
      'updated' => 1790000000,
      'opaque_token' => $token,
    ])->execute();
    return $id;
  }

  /**
   * Queues one Esplora-style header read.
   */
  private function scriptHeader(string $display, string $header, string $tip, string $status): void {
    $this->transport->script[] = ['status' => 200, 'body' => $display];
    $this->transport->script[] = ['status' => 200, 'body' => $header];
    $this->transport->script[] = ['status' => 200, 'body' => $tip];
    $this->transport->script[] = ['status' => 200, 'body' => $status];
  }

  /**
   * Builds a one-attestation calendar body without the module encoder.
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
   * @param string $hash
   *   Transaction hash.
   * @param string $digest
   *   Lowercase checkpoint digest.
   * @param bool $validated
   *   Ledger validated flag.
   *
   * @return array<string, mixed>
   *   Transaction body the read endpoint would return.
   */
  private function xrplTransaction(string $hash, string $digest, bool $validated): array {
    return [
      'validated' => $validated,
      'ledger_index' => 42,
      'close_time' => 1700000100,
      'TransactionType' => 'Payment',
      'Account' => 'rWitness11111111111111111111111',
      'Destination' => 'rSink11111111111111111111111111',
      'Amount' => '1',
      'Fee' => '12',
      'hash' => $hash,
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

  /**
   * Loads every witness receipt row.
   *
   * @return list<object>
   *   Receipt rows in database order.
   */
  private function receiptCount(): array {
    return $this->container->get('database')->select('audit_chain_witness_receipt', 'w')
      ->fields('w')
      ->execute()
      ->fetchAll();
  }

  /**
   * Returns the stored opaque token.
   */
  private function storedToken(string $id): string {
    return (string) $this->container->get('database')->select('audit_chain_witness_receipt', 'w')
      ->fields('w', ['opaque_token'])
      ->condition('id', $id)
      ->execute()
      ->fetchField();
  }

  /**
   * Loads every audit-chain log row.
   *
   * @return list<object>
   *   Chain rows in id order.
   */
  private function chainRows(): array {
    return $this->container->get('database')->select('audit_chain_log', 'l')
      ->fields('l')
      ->orderBy('id')
      ->execute()
      ->fetchAll();
  }

}

/**
 * HTTP double that returns scripted results and records calls.
 */
final class ScriptedWitnessTransport implements WitnessTransportInterface {

  /**
   * Recorded requests.
   *
   * @var list<array{method: string, url: string, body: string, headers: array<string, string>}>
   */
  public array $calls = [];

  /**
   * Scripted results, exceptions, or closures.
   *
   * @var list<array{status: int, body: string}|\Throwable|\Closure>
   */
  public array $script = [];

  /**
   * {@inheritdoc}
   */
  public function request(string $method, string $url, string $body, array $headers, int $maxBytes = 10000): array {
    $this->calls[] = [
      'method' => $method,
      'url' => $url,
      'body' => $body,
      'headers' => $headers,
    ];
    if ($this->script === []) {
      throw new \RuntimeException('unexpected_witness_request');
    }
    $next = array_shift($this->script);
    if ($next instanceof \Closure) {
      $next = $next();
    }
    if ($next instanceof \Throwable) {
      throw $next;
    }
    if (strlen($next['body']) > $maxBytes) {
      throw new \RuntimeException('response_too_large');
    }
    return $next;
  }

}

/**
 * DNS double keyed by hostname.
 */
final class MapWitnessDns implements WitnessDnsResolverInterface {

  /**
   * Stores the hostname map.
   *
   * @param array<string, list<string>> $map
   *   Hostnames to the addresses a lookup would return.
   */
  public function __construct(
    private array $map,
  ) {}

  /**
   * {@inheritdoc}
   */
  public function resolve(string $host): array {
    if (!array_key_exists($host, $this->map)) {
      throw new \RuntimeException('dns_unmapped');
    }
    return $this->map[$host];
  }

}

/**
 * Backend whose first upgrade loses a compare-and-swap on purpose.
 */
final class RacingWitnessBackend implements IdentifiedWitnessBackendInterface {

  /**
   * Upgrade attempts.
   */
  public int $calls = 0;

  /**
   * {@inheritdoc}
   */
  public function id(): string {
    return 'race';
  }

  /**
   * {@inheritdoc}
   */
  public function submit(string $digestHex, array $context): WitnessReceipt {
    return new WitnessReceipt('race-receipt', $this->id(), WitnessReceipt::STATUS_PENDING, 'token-a');
  }

  /**
   * {@inheritdoc}
   */
  public function upgrade(WitnessReceipt $pending): WitnessReceipt {
    $this->calls++;
    if ($this->calls === 1) {
      \Drupal::database()->update('audit_chain_witness_receipt')
        ->fields([
          'status' => WitnessReceipt::STATUS_CONFIRMED,
          'opaque_token' => 'token-confirmed',
        ])
        ->condition('id', $pending->id)
        ->execute();
      return new WitnessReceipt($pending->id, $pending->backendId, WitnessReceipt::STATUS_PENDING, 'token-stale');
    }
    return $pending;
  }

  /**
   * {@inheritdoc}
   */
  public function verify(WitnessReceipt $receipt, string $digestHex): WitnessVerdict {
    return new WitnessVerdict(FALSE, 'invalid');
  }

}
