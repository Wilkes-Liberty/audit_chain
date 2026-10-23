<?php

declare(strict_types=1);

namespace Drupal\Tests\audit_chain\Unit;

use Drupal\audit_chain\OpenTimestampsWitnessBackend;
use Drupal\audit_chain\Witness\OtsProof;
use Drupal\audit_chain\Witness\WitnessDnsResolverInterface;
use Drupal\audit_chain\Witness\WitnessTransportInterface;
use Drupal\audit_chain\WitnessReceipt;
use Drupal\Component\Uuid\UuidInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\Core\Config\ImmutableConfig;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\Group;

/**
 * OpenTimestamps submit, upgrade, and verify against scripted calendars.
 *
 * @group audit_chain
 * @coversDefaultClass \Drupal\audit_chain\OpenTimestampsWitnessBackend
 */
#[Group('audit_chain')]
final class OpenTimestampsWitnessBackendTest extends UnitTestCase {

  private const DIGEST = '1111111111111111111111111111111111111111111111111111111111111111';

  private const DISPLAY = 'a6f79bec9687877423e75f12d38be5ca406c37f1cd11b23d8ece359157acc72d';

  private const HEADER = '010000002222222222222222222222222222222222222222222222222222222222222222111111111111111111111111111111111111111111111111111111111111111100f15365ffff001d00000000';

  /**
   * Scripted HTTP double.
   */
  private UnitScriptedWitnessTransport $transport;

  /**
   * Backend under test.
   */
  private OpenTimestampsWitnessBackend $backend;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->transport = new UnitScriptedWitnessTransport();
    $this->backend = $this->backend($this->transport);
  }

  /**
   * Submit stores a pending detached proof and posts only the raw digest.
   */
  public function testSubmitStoresPendingReceipt(): void {
    $raw = (string) hex2bin(self::DIGEST);
    $this->transport->script[] = [
      'status' => 200,
      'body' => $this->pendingBody($raw, 'https://alice.example'),
    ];
    $receipt = $this->backend->submit(self::DIGEST, [
      'contract' => 'audit_chain.checkpoint.v1',
    ]);
    $this->assertSame('opentimestamps', $receipt->backendId);
    $this->assertSame(WitnessReceipt::STATUS_PENDING, $receipt->status);
    $this->assertSame((string) hex2bin(self::DIGEST), $this->transport->calls[0]['body']);
    $this->assertSame(32, strlen($this->transport->calls[0]['body']));
    $stored = base64_decode($receipt->opaqueToken, TRUE);
    $this->assertNotFalse($stored);
    $decoded = OtsProof::decodeDetached($stored);
    $this->assertSame(self::DIGEST, bin2hex($decoded['digest']));
    $this->assertSame(
      'https://alice.example',
      $decoded['proof']->pendingNodes()[0]->attestations()[0]['uri'],
    );
  }

  /**
   * A calendar that is down writes no receipt.
   */
  public function testSubmitTransportErrorWritesNoReceipt(): void {
    $this->transport->script[] = new \RuntimeException('backend_unreachable');
    try {
      $this->backend->submit(self::DIGEST, [
        'contract' => 'audit_chain.checkpoint.v1',
      ]);
      $this->fail('A calendar outage returned a receipt.');
    }
    catch (\RuntimeException $exception) {
      $this->assertSame('backend_unreachable', $exception->getMessage());
    }
  }

  /**
   * Upgrade without a new attestation leaves the pending receipt unchanged.
   */
  public function testUpgradeWithoutAttestationLeavesPending(): void {
    $receipt = $this->pendingReceipt();
    $this->transport->script[] = ['status' => 404, 'body' => ''];
    $same = $this->backend->upgrade($receipt);
    $this->assertSame(WitnessReceipt::STATUS_PENDING, $same->status);
    $this->assertSame($receipt->opaqueToken, $same->opaqueToken);
    $this->assertSame($receipt->id, $same->id);
  }

  /**
   * A Bitcoin attestation replaces the pending proof once the header checks.
   */
  public function testUpgradeWithBitcoinAttestationReplacesReceipt(): void {
    $receipt = $this->pendingReceipt();
    $this->transport->script[] = [
      'status' => 200,
      'body' => $this->bitcoinAttestation(),
    ];
    $this->scriptHeader(self::DISPLAY, self::HEADER, '840006', '{"in_best_chain":true}');
    $complete = $this->backend->upgrade($receipt);
    $this->assertSame(WitnessReceipt::STATUS_CONFIRMED, $complete->status);
    $this->assertSame($receipt->id, $complete->id);
    $this->assertNotSame($receipt->opaqueToken, $complete->opaqueToken);
    $decoded = OtsProof::decodeDetached((string) base64_decode($complete->opaqueToken, TRUE));
    $this->assertNotSame([], $decoded['proof']->bitcoinCandidates());

    $this->scriptHeader(self::DISPLAY, self::HEADER, '840006', '{"in_best_chain":true}');
    $verdict = $this->backend->verify($complete, self::DIGEST);
    $this->assertTrue($verdict->valid);
    $this->assertSame('confirmed', $verdict->reason);
  }

  /**
   * A header whose merkle root is not the digest is not stored.
   */
  public function testUpgradeMismatchedAttestationFailsClosed(): void {
    $receipt = $this->pendingReceipt();
    $this->transport->script[] = [
      'status' => 200,
      'body' => $this->bitcoinAttestation(),
    ];
    $wrongHeader = '010000002222222222222222222222222222222222222222222222222222222222222222aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa00f15365ffff001d00000000';
    $wrongDisplay = bin2hex(strrev(hash('sha256', hash('sha256', (string) hex2bin($wrongHeader), TRUE), TRUE)));
    $this->scriptHeader($wrongDisplay, $wrongHeader, '840006', '{"in_best_chain":true}');
    try {
      $this->backend->upgrade($receipt);
      $this->fail('A mismatched Bitcoin branch replaced the pending proof.');
    }
    catch (\RuntimeException $exception) {
      $this->assertSame('attestation_mismatch', $exception->getMessage());
    }
  }

  /**
   * Garbage calendar bytes do not replace the stored pending proof.
   */
  public function testUpgradeMalformedAttestationLeavesPending(): void {
    $receipt = $this->pendingReceipt();
    $this->transport->script[] = ['status' => 200, 'body' => 'not-a-proof'];
    $same = $this->backend->upgrade($receipt);
    $this->assertSame($receipt->opaqueToken, $same->opaqueToken);
    $this->assertSame(WitnessReceipt::STATUS_PENDING, $same->status);
  }

  /**
   * A calendar outage during upgrade throws and does not invent a token.
   */
  public function testUpgradeTransportErrorDoesNotReplaceReceipt(): void {
    $receipt = $this->pendingReceipt();
    $this->transport->script[] = new \RuntimeException('backend_unreachable');
    try {
      $this->backend->upgrade($receipt);
      $this->fail('A calendar outage returned an upgraded receipt.');
    }
    catch (\RuntimeException $exception) {
      $this->assertSame('backend_unreachable', $exception->getMessage());
    }
  }

  /**
   * Verify accepts a complete proof and rejects a flipped digest.
   */
  public function testVerifySucceedsOnCompleteReceiptAndFailsOnTamper(): void {
    $receipt = $this->pendingReceipt();
    $this->transport->script[] = [
      'status' => 200,
      'body' => $this->bitcoinAttestation(),
    ];
    $this->scriptHeader(self::DISPLAY, self::HEADER, '840006', '{"in_best_chain":true}');
    $complete = $this->backend->upgrade($receipt);

    $this->scriptHeader(self::DISPLAY, self::HEADER, '840006', '{"in_best_chain":true}');
    $this->assertTrue($this->backend->verify($complete, self::DIGEST)->valid);

    $tampered = $this->backend->verify($complete, str_repeat('ab', 32));
    $this->assertFalse($tampered->valid);
    $this->assertSame('receipt_malformed', $tampered->reason);

    $broken = new WitnessReceipt(
      $complete->id,
      $complete->backendId,
      $complete->status,
      '@@@@',
    );
    $malformed = $this->backend->verify($broken, self::DIGEST);
    $this->assertFalse($malformed->valid);
    $this->assertSame('receipt_malformed', $malformed->reason);
  }

  /**
   * Builds the backend with a scripted transport.
   */
  private function backend(WitnessTransportInterface $transport): OpenTimestampsWitnessBackend {
    $config = $this->createMock(ImmutableConfig::class);
    $config->method('get')->willReturnCallback(static function (string $key) {
      return $key === 'witness_opentimestamps' ? [
        'calendars' => ['https://calendar.example'],
        'upgrade_allowlist' => [
          'https://calendar.example',
          'https://alice.example',
        ],
        'header_url' => 'https://headers.example/api',
        'min_depth' => 6,
      ] : NULL;
    });
    $factory = $this->createMock(ConfigFactoryInterface::class);
    $factory->method('get')->with('audit_chain.settings')->willReturn($config);
    $dns = $this->createMock(WitnessDnsResolverInterface::class);
    $dns->method('resolve')->willReturn(['1.1.1.1']);
    $uuid = $this->createMock(UuidInterface::class);
    $uuid->method('generate')->willReturn('11111111-1111-1111-1111-111111111111');
    return new OpenTimestampsWitnessBackend($factory, $transport, $dns, $uuid);
  }

  /**
   * Returns a pending receipt for the fixture digest.
   */
  private function pendingReceipt(): WitnessReceipt {
    $raw = (string) hex2bin(self::DIGEST);
    $this->transport->script[] = [
      'status' => 200,
      'body' => $this->pendingBody($raw, 'https://alice.example'),
    ];
    return $this->backend->submit(self::DIGEST, [
      'contract' => 'audit_chain.checkpoint.v1',
    ]);
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
   * Builds a one-attestation calendar body.
   */
  private function pendingBody(string $digest, string $uri): string {
    if (strlen($digest) !== 32) {
      throw new \InvalidArgumentException('A 32-byte digest is required.');
    }
    $payload = chr(strlen($uri)) . $uri;
    $attestation = hex2bin('83dfe30d2ef90c8e') . chr(strlen($payload)) . $payload;
    return "\x00" . $attestation;
  }

  /**
   * Builds a Bitcoin attestation at height 840000.
   */
  private function bitcoinAttestation(): string {
    return "\x00" . hex2bin('0588960d73d71901') . "\x03\xc0\xa2\x33";
  }

}
