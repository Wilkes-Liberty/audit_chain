<?php

declare(strict_types=1);

namespace Drupal\Tests\audit_chain\Unit;

use Drupal\audit_chain\Witness\WitnessDnsResolverInterface;
use Drupal\audit_chain\WitnessReceipt;
use Drupal\audit_chain\XrplWitnessBackend;
use Drupal\Component\Uuid\UuidInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\ImmutableConfig;
use Drupal\Core\Site\Settings;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\Group;

/**
 * XRPL submit, upgrade, and verify against a scripted relay and ledger.
 *
 * The backend still holds no seed. These tests cover the relay contract.
 *
 * @group audit_chain
 * @coversDefaultClass \Drupal\audit_chain\XrplWitnessBackend
 */
#[Group('audit_chain')]
final class XrplWitnessBackendTest extends UnitTestCase {

  private const DIGEST = '1111111111111111111111111111111111111111111111111111111111111111';

  private const HASH = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';

  private const ACCOUNT = 'rWitness11111111111111111111111';

  private const SINK = 'rSink11111111111111111111111111';

  /**
   * Scripted HTTP double.
   */
  private UnitScriptedWitnessTransport $transport;

  /**
   * Backend under test.
   */
  private XrplWitnessBackend $backend;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    new Settings(['audit_chain_witness_xrpl_token' => 'relay-test-token']);
    $this->transport = new UnitScriptedWitnessTransport();
    $this->backend = $this->backend($this->xrplConfig());
  }

  /**
   * Submit records a pending receipt that carries the relay tx hash.
   */
  public function testSubmitStoresPendingReceiptWithTxHash(): void {
    $this->transport->script[] = [
      'status' => 200,
      'body' => json_encode(['outcome' => 'pending', 'tx_hash' => self::HASH], JSON_THROW_ON_ERROR),
    ];
    $receipt = $this->backend->submit(self::DIGEST, [
      'contract' => 'audit_chain.checkpoint.v1',
    ]);
    $this->assertSame('xrpl', $receipt->backendId);
    $this->assertSame(WitnessReceipt::STATUS_PENDING, $receipt->status);
    $token = json_decode($receipt->opaqueToken, TRUE, 8, JSON_THROW_ON_ERROR);
    $this->assertSame(self::HASH, $token['tx_hash']);
    $this->assertSame('pending', $token['outcome']);
    $this->assertSame(
      '{"digest":"' . self::DIGEST . '","request_id":"' . $token['request_id'] . '"}',
      $this->transport->calls[0]['body'],
    );
    $this->assertSame('Bearer relay-test-token', $this->transport->calls[0]['headers']['Authorization']);
  }

  /**
   * A relay outage throws before a caller can treat submit as success.
   */
  public function testSubmitTransportErrorDoesNotReturnReceipt(): void {
    $this->transport->script[] = new \RuntimeException('relay_timeout');
    try {
      $this->backend->submit(self::DIGEST, [
        'contract' => 'audit_chain.checkpoint.v1',
      ]);
      $this->fail('A relay outage returned a receipt.');
    }
    catch (\RuntimeException $exception) {
      $this->assertSame('relay_timeout', $exception->getMessage());
    }
  }

  /**
   * An unvalidated ledger read leaves the receipt pending.
   */
  public function testUpgradeWithoutValidatedTxLeavesPending(): void {
    $receipt = $this->pendingWithHash();
    $this->transport->script[] = [
      'status' => 200,
      'body' => json_encode($this->transaction(FALSE, self::DIGEST), JSON_THROW_ON_ERROR),
    ];
    $this->transport->script[] = [
      'status' => 200,
      'body' => json_encode(['outcome' => 'pending', 'tx_hash' => self::HASH], JSON_THROW_ON_ERROR),
    ];
    $still = $this->backend->upgrade($receipt);
    $this->assertSame(WitnessReceipt::STATUS_PENDING, $still->status);
    $token = json_decode($still->opaqueToken, TRUE, 8, JSON_THROW_ON_ERROR);
    $this->assertSame(self::HASH, $token['tx_hash']);
  }

  /**
   * A validated matching payment replaces pending with confirmed.
   */
  public function testUpgradeWithValidatedTxConfirms(): void {
    $receipt = $this->pendingWithHash();
    $this->transport->script[] = [
      'status' => 200,
      'body' => json_encode($this->transaction(TRUE, self::DIGEST), JSON_THROW_ON_ERROR),
    ];
    $confirmed = $this->backend->upgrade($receipt);
    $this->assertSame(WitnessReceipt::STATUS_CONFIRMED, $confirmed->status);
    $this->transport->script[] = [
      'status' => 200,
      'body' => json_encode($this->transaction(TRUE, self::DIGEST), JSON_THROW_ON_ERROR),
    ];
    $verdict = $this->backend->verify($confirmed, self::DIGEST);
    $this->assertTrue($verdict->valid);
    $this->assertSame('confirmed', $verdict->reason);
  }

  /**
   * A memo for a different digest fails closed.
   */
  public function testVerifyMismatchedMemoFailsClosed(): void {
    $receipt = $this->pendingWithHash();
    $this->transport->script[] = [
      'status' => 200,
      'body' => json_encode($this->transaction(TRUE, str_repeat('ab', 32)), JSON_THROW_ON_ERROR),
    ];
    $verdict = $this->backend->verify($receipt, self::DIGEST);
    $this->assertFalse($verdict->valid);
    $this->assertSame('attestation_mismatch', $verdict->reason);
  }

  /**
   * A read outage during upgrade throws and does not invent confirmation.
   */
  public function testUpgradeReadOutageFailsClosed(): void {
    $receipt = $this->pendingWithHash();
    $this->transport->script[] = new \RuntimeException('backend_unreachable');
    try {
      $this->backend->upgrade($receipt);
      $this->fail('A ledger outage confirmed the receipt.');
    }
    catch (\RuntimeException $exception) {
      $this->assertSame('backend_unreachable', $exception->getMessage());
    }
  }

  /**
   * Mainnet URLs are refused before any request.
   */
  public function testMainnetRelayIsRefused(): void {
    $backend = $this->backend([
      'relay_url' => 'https://s1.ripple.com',
      'read_url' => 'https://read.example',
      'network' => 'xrpl:testnet',
      'sink_address' => self::SINK,
      'witness_account' => self::ACCOUNT,
    ]);
    try {
      $backend->submit(self::DIGEST, [
        'contract' => 'audit_chain.checkpoint.v1',
      ]);
      $this->fail('A mainnet relay was accepted.');
    }
    catch (\RuntimeException $exception) {
      $this->assertSame('witness_xrpl_mainnet_refused', $exception->getMessage());
    }
    $this->assertSame([], $this->transport->calls);
  }

  /**
   * Empty XRPL config fails closed. That is the shipped default.
   */
  public function testEmptyConfigFailsClosed(): void {
    $backend = $this->backend([
      'relay_url' => '',
      'read_url' => '',
      'network' => '',
      'sink_address' => '',
      'witness_account' => '',
    ]);
    try {
      $backend->submit(self::DIGEST, [
        'contract' => 'audit_chain.checkpoint.v1',
      ]);
      $this->fail('An empty XRPL config submitted.');
    }
    catch (\RuntimeException $exception) {
      $this->assertSame('witness_xrpl_unconfigured', $exception->getMessage());
    }
  }

  /**
   * Builds the backend with a scripted transport.
   *
   * @param array<string, string> $xrpl
   *   Witness XRPL config values.
   */
  private function backend(array $xrpl): XrplWitnessBackend {
    $config = $this->createMock(ImmutableConfig::class);
    $config->method('get')->willReturnCallback(static function (string $key) use ($xrpl) {
      return $key === 'witness_xrpl' ? $xrpl : NULL;
    });
    $factory = $this->createMock(ConfigFactoryInterface::class);
    $factory->method('get')->with('audit_chain.settings')->willReturn($config);
    $dns = $this->createMock(WitnessDnsResolverInterface::class);
    $dns->method('resolve')->willReturn(['1.1.1.1']);
    $calls = 0;
    $uuid = $this->createMock(UuidInterface::class);
    $uuid->method('generate')->willReturnCallback(static function () use (&$calls): string {
      $calls++;
      return sprintf('11111111-1111-1111-1111-%012d', $calls);
    });
    return new XrplWitnessBackend($factory, $this->transport, $dns, $uuid, new Settings([
      'audit_chain_witness_xrpl_token' => 'relay-test-token',
    ] + Settings::getAll()));
  }

  /**
   * Testnet fixture config.
   *
   * @return array<string, string>
   *   witness_xrpl values.
   */
  private function xrplConfig(): array {
    return [
      'relay_url' => 'https://relay.example/witness',
      'read_url' => 'https://read.example',
      'network' => 'xrpl:testnet',
      'sink_address' => self::SINK,
      'witness_account' => self::ACCOUNT,
    ];
  }

  /**
   * Submits once so upgrade and verify have a pending hash.
   */
  private function pendingWithHash(): WitnessReceipt {
    $this->transport->script[] = [
      'status' => 200,
      'body' => json_encode(['outcome' => 'pending', 'tx_hash' => self::HASH], JSON_THROW_ON_ERROR),
    ];
    return $this->backend->submit(self::DIGEST, [
      'contract' => 'audit_chain.checkpoint.v1',
    ]);
  }

  /**
   * Builds one ledger transaction fixture.
   *
   * @return array<string, mixed>
   *   Transaction body the read endpoint would return.
   */
  private function transaction(bool $validated, string $digest): array {
    return [
      'validated' => $validated,
      'ledger_index' => 42,
      'close_time' => 1700000100,
      'TransactionType' => 'Payment',
      'Account' => self::ACCOUNT,
      'Destination' => self::SINK,
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
