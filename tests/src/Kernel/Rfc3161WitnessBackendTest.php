<?php

declare(strict_types=1);

namespace Drupal\Tests\audit_chain\Kernel;

use Drupal\audit_chain\Witness\Rfc3161Asn1;
use Drupal\audit_chain\WitnessOperator;
use Drupal\audit_chain\WitnessReceipt;
use Drupal\Component\Datetime\TimeInterface;
use Drupal\Core\Site\Settings;
use Drupal\KernelTests\KernelTestBase;
use Drupal\key\Entity\Key;
use PHPUnit\Framework\Attributes\Group;

/**
 * Exercises the RFC 3161 witness against an offline fixture PKI.
 *
 * @group audit_chain
 */
#[Group('audit_chain')]
final class Rfc3161WitnessBackendTest extends KernelTestBase {

  use AuditChainSchemaTrait;

  /**
   * Scripted HTTP double shared with WitnessBackendsTest.
   */
  private ScriptedWitnessTransport $transport;

  /**
   * Good fixture PKI.
   */
  private Rfc3161FixtureFactory $pki;

  /**
   * Mocked Drupal clock, shared with the fixtures.
   *
   * OCSP freshness is checked against this clock, and the fixture
   * certificates are only valid from the moment they are minted, so the
   * mock takes the factory clock instead of a fixed date.
   */
  private int $now;

  /**
   * {@inheritdoc}
   */
  protected static $modules = ['system', 'user', 'key', 'encrypt', 'audit_chain'];

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    $this->pki = new Rfc3161FixtureFactory();
    $this->now = $this->pki->now;
    $this->transport = new ScriptedWitnessTransport();
    $this->container->set('audit_chain.witness_transport', $this->transport);
    $this->container->set('audit_chain.witness_dns', new MapWitnessDns([
      'tsa.example' => ['1.1.1.1'],
      'ocsp.example' => ['1.1.1.1'],
    ]));
    $time = $this->createMock(TimeInterface::class);
    $time->method('getRequestTime')->willReturn($this->now);
    $time->method('getCurrentTime')->willReturn($this->now);
    $this->container->set('datetime.time', $time);
    $this->installEntitySchema('user');
    $this->installAuditChainTables();
    $this->installConfig(['audit_chain']);
    new Settings([
      'audit_chain_instance_id' => 'archive-test-instance',
    ] + Settings::getAll());
    Key::create([
      'id' => 'archive_key',
      'label' => 'Archive test key',
      'key_type' => 'authentication',
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => 'archive-test-secret'],
    ])->save();
    $this->config('audit_chain.settings')->set('hash_key', 'archive_key')->save();
    $this->container->get('audit_chain.logger')->logKeyed('test', 'before_rfc3161');
  }

  /**
   * Granted submit stores a confirmed envelope and does not grow the log.
   */
  public function testGrantedSubmitStoresConfirmedEnvelope(): void {
    $before = $this->chainRows();
    $digest = $this->realDigest();
    $this->configureRfc3161();
    $this->scriptGranted();
    $manager = $this->container->get('audit_chain.witness_manager');
    $receipt = $manager->submit($digest, 'rfc3161');
    $this->assertSame('rfc3161', $receipt->backendId);
    $this->assertSame(WitnessReceipt::STATUS_CONFIRMED, $receipt->status);
    $this->assertNotSame('', $receipt->id);
    $raw = base64_decode($receipt->opaqueToken, TRUE);
    $this->assertNotFalse($raw);
    $envelope = Rfc3161Asn1::decodeEnvelope($raw);
    $this->assertNotSame('', $envelope['token']);
    $this->assertNotSame('', $envelope['ocsp']);
    $call = $this->transport->calls[0];
    $this->assertSame('POST', $call['method']);
    $this->assertSame('https://tsa.example/tsa', $call['url']);
    $req = Rfc3161Asn1::decodeTimeStampReq($call['body']);
    $this->assertSame(hex2bin($digest), $req['imprint']);
    $this->assertSame(Rfc3161FixtureFactory::POLICY, $req['policy']);
    $this->assertStringNotContainsString($digest, $call['body']);
    $this->assertStringNotContainsString('audit_chain.checkpoint.v1', $call['body']);
    $this->assertCount(1, $this->receiptRows());
    $this->assertEquals($before, $this->chainRows());
  }

  /**
   * Verify passes for a granted, fully checked receipt.
   */
  public function testVerifyPasses(): void {
    $digest = $this->realDigest();
    $this->configureRfc3161();
    $this->scriptGranted();
    $manager = $this->container->get('audit_chain.witness_manager');
    $receipt = $manager->submit($digest, 'rfc3161');
    $this->scriptOcsp('good');
    $verdict = $manager->verify($receipt->id, $digest);
    $this->assertTrue($verdict->valid);
    $this->assertSame('confirmed', $verdict->reason);
    $this->assertSame('rfc3161', $verdict->evidence['trust_mode']);
  }

  /**
   * Upgrade makes no network call and returns the confirmed receipt.
   */
  public function testUpgradeIsNoOp(): void {
    $digest = $this->realDigest();
    $this->configureRfc3161();
    $this->scriptGranted();
    $manager = $this->container->get('audit_chain.witness_manager');
    $receipt = $manager->submit($digest, 'rfc3161');
    $calls = count($this->transport->calls);
    $upgraded = $manager->upgrade($receipt->id);
    $this->assertSame($receipt->id, $upgraded->id);
    $this->assertSame($receipt->status, $upgraded->status);
    $this->assertSame($receipt->opaqueToken, $upgraded->opaqueToken);
    $this->assertCount($calls, $this->transport->calls);
  }

  /**
   * Verify fails when the imprint is not the expected digest.
   */
  public function testDigestMismatch(): void {
    $digest = $this->realDigest();
    $this->configureRfc3161();
    $this->scriptGranted();
    $manager = $this->container->get('audit_chain.witness_manager');
    $receipt = $manager->submit($digest, 'rfc3161');
    $other = str_repeat('2', 64);
    $backend = $this->container->get('audit_chain.witness_backend.rfc3161');
    $verdict = $backend->verify($receipt, $other);
    $this->assertFalse($verdict->valid);
    $this->assertSame('digest_mismatch', $verdict->reason);
  }

  /**
   * A flipped CMS byte is signature_invalid.
   */
  public function testTamperedSignature(): void {
    $digest = $this->realDigest();
    $this->configureRfc3161();
    $this->scriptGranted();
    $manager = $this->container->get('audit_chain.witness_manager');
    $receipt = $manager->submit($digest, 'rfc3161');
    $raw = base64_decode($receipt->opaqueToken, TRUE);
    $this->assertNotFalse($raw);
    $envelope = Rfc3161Asn1::decodeEnvelope($raw);
    $token = $envelope['token'];
    // Flip bytes at the end of the CMS, where the signature value lives,
    // so OpenSSL rejects the signature rather than a middle certificate.
    $end = strlen($token) - 1;
    $token[$end] = chr(ord($token[$end]) ^ 0xFF);
    $token[$end - 16] = chr(ord($token[$end - 16]) ^ 0xFF);
    $tampered = base64_encode(Rfc3161Asn1::encodeEnvelope($token, $envelope['ocsp']));
    $id = $this->insertReceipt($tampered, $digest);
    $verdict = $manager->verify($id, $digest);
    $this->assertFalse($verdict->valid);
    $this->assertSame('signature_invalid', $verdict->reason);
  }

  /**
   * A signer that does not chain to the configured anchors is untrusted.
   */
  public function testUntrustedSigner(): void {
    $digest = $this->realDigest();
    $this->configureRfc3161();
    $this->scriptGranted();
    $manager = $this->container->get('audit_chain.witness_manager');
    $receipt = $manager->submit($digest, 'rfc3161');
    $this->configureRfc3161($this->pki->otherRootPem);
    $verdict = $manager->verify($receipt->id, $digest);
    $this->assertFalse($verdict->valid);
    $this->assertSame('untrusted_tsa', $verdict->reason);
  }

  /**
   * A TSA certificate without timeStamping EKU is rejected on submit.
   */
  public function testMissingTimestampingEku(): void {
    $before = $this->receiptRows();
    $digest = $this->realDigest();
    $pki = new Rfc3161FixtureFactory('no_eku');
    $this->configureRfc3161($pki->trustBundle());
    $this->scriptGranted($pki);
    $manager = $this->container->get('audit_chain.witness_manager');
    try {
      $manager->submit($digest, 'rfc3161', TRUE);
      $this->fail('A signer without timeStamping EKU was accepted.');
    }
    catch (\RuntimeException $exception) {
      $this->assertSame('certificate_invalid', $exception->getMessage());
    }
    $this->assertSame($before, $this->receiptRows());
  }

  /**
   * A token that commits to another policy is policy_mismatch.
   */
  public function testPolicyMismatch(): void {
    $before = $this->receiptRows();
    $digest = $this->realDigest();
    $this->configureRfc3161();
    $this->transport->script[] = function (): array {
      $req = $this->transport->calls[array_key_last($this->transport->calls)]['body'];
      return [
        'status' => 200,
        'body' => $this->pki->grantedResponse($req, Rfc3161FixtureFactory::OTHER_POLICY),
      ];
    };
    $manager = $this->container->get('audit_chain.witness_manager');
    try {
      $manager->submit($digest, 'rfc3161', TRUE);
      $this->fail('A policy mismatch was stored.');
    }
    catch (\RuntimeException $exception) {
      $this->assertSame('policy_mismatch', $exception->getMessage());
    }
    $this->assertSame($before, $this->receiptRows());
  }

  /**
   * A SHA-1 TSA certificate is weak_algorithm.
   */
  public function testSha1SignerRejected(): void {
    $before = $this->receiptRows();
    $digest = $this->realDigest();
    $pki = new Rfc3161FixtureFactory('sha1');
    $this->configureRfc3161($pki->trustBundle());
    $this->scriptGranted($pki);
    $manager = $this->container->get('audit_chain.witness_manager');
    try {
      $manager->submit($digest, 'rfc3161', TRUE);
      $this->fail('A SHA-1 signer was accepted.');
    }
    catch (\RuntimeException $exception) {
      $this->assertSame('weak_algorithm', $exception->getMessage());
    }
    $this->assertSame($before, $this->receiptRows());
  }

  /**
   * A nonce that does not echo writes no receipt.
   */
  public function testNonceMismatchWritesNothing(): void {
    $before = $this->receiptRows();
    $digest = $this->realDigest();
    $this->configureRfc3161();
    $this->transport->script[] = function (): array {
      $req = $this->transport->calls[array_key_last($this->transport->calls)]['body'];
      return [
        'status' => 200,
        'body' => $this->pki->grantedResponse($req, NULL, '999'),
      ];
    };
    $manager = $this->container->get('audit_chain.witness_manager');
    try {
      $manager->submit($digest, 'rfc3161', TRUE);
      $this->fail('A nonce mismatch was stored.');
    }
    catch (\RuntimeException $exception) {
      $this->assertSame('nonce_mismatch', $exception->getMessage());
    }
    $this->assertSame($before, $this->receiptRows());
  }

  /**
   * A TSA outage writes no receipt.
   */
  public function testTsaDownWritesNothing(): void {
    $before = $this->receiptRows();
    $digest = $this->realDigest();
    $this->configureRfc3161();
    $this->transport->script[] = new \RuntimeException('backend_unreachable');
    $manager = $this->container->get('audit_chain.witness_manager');
    try {
      $manager->submit($digest, 'rfc3161', TRUE);
      $this->fail('A TSA outage stored a receipt.');
    }
    catch (\RuntimeException $exception) {
      $this->assertSame('backend_unreachable', $exception->getMessage());
    }
    $this->assertSame($before, $this->receiptRows());
  }

  /**
   * Revoked or unknown OCSP at submit writes no receipt.
   */
  public function testOcspRevokedOrUnknownAtSubmitWritesNothing(): void {
    $digest = $this->realDigest();
    $this->configureRfc3161();
    $manager = $this->container->get('audit_chain.witness_manager');
    foreach (['revoked', 'unknown'] as $status) {
      $before = $this->receiptRows();
      $this->scriptGrantedAndOcsp($this->pki, $status);
      try {
        $manager->submit($digest, 'rfc3161', TRUE);
        $this->fail("OCSP $status at submit stored a receipt.");
      }
      catch (\RuntimeException $exception) {
        $this->assertContains($exception->getMessage(), [
          'certificate_revoked',
          'certificate_invalid',
        ]);
      }
      $this->assertSame($before, $this->receiptRows());
    }
  }

  /**
   * A responder from another trusted root may not vouch for the TSA.
   *
   * Both roots are configured as anchors, so the stray responder chains
   * to a trust anchor. It still did not get authority from the CA that
   * issued the TSA certificate, so submit must refuse it.
   */
  public function testOcspFromUnauthorizedResponderWritesNothing(): void {
    $digest = $this->realDigest();
    $this->configureRfc3161($this->pki->trustBundle() . "\n" . $this->pki->otherRootPem);
    $manager = $this->container->get('audit_chain.witness_manager');
    $cases = [
      'other_root' => ['signer' => 'other_root'],
      'no_eku' => ['signer' => 'no_eku'],
    ];
    foreach ($cases as $label => $options) {
      $before = $this->receiptRows();
      $this->transport->script[] = function (): array {
        $req = $this->transport->calls[array_key_last($this->transport->calls)]['body'];
        return ['status' => 200, 'body' => $this->pki->grantedResponse($req)];
      };
      $this->transport->script[] = [
        'status' => 200,
        'body' => $this->pki->ocsp('good', $options),
      ];
      try {
        $manager->submit($digest, 'rfc3161', TRUE);
        $this->fail("OCSP signed by the $label responder stored a receipt.");
      }
      catch (\RuntimeException $exception) {
        $this->assertSame('untrusted_tsa', $exception->getMessage(), $label);
      }
      // Rows are stdClass objects, so compare by value, not identity.
      $this->assertEquals($before, $this->receiptRows(), $label);
    }
  }

  /**
   * A stale stored OCSP answer fails verify even if live OCSP is good.
   */
  public function testStaleStoredOcspFailsVerify(): void {
    $digest = $this->realDigest();
    $this->configureRfc3161();
    $this->transport->script[] = function (): array {
      $req = $this->transport->calls[array_key_last($this->transport->calls)]['body'];
      return ['status' => 200, 'body' => $this->pki->grantedResponse($req)];
    };
    $this->scriptOcsp('good');
    $manager = $this->container->get('audit_chain.witness_manager');
    $receipt = $manager->submit($digest, 'rfc3161');

    // Swap the stored answer for one whose nextUpdate ended an hour
    // before the token was issued. Signature, responder, CertID, and
    // producedAt are all fine, so only the freshness check can fail it.
    $envelope = Rfc3161Asn1::decodeEnvelope(base64_decode($receipt->opaqueToken, TRUE));
    $stale = $this->pki->ocsp('good', [
      'this_update' => $this->now - 7200,
      'next_update' => $this->now - 3600,
    ]);
    $this->container->get('database')->update('audit_chain_witness_receipt')
      ->fields(['opaque_token' => base64_encode(Rfc3161Asn1::encodeEnvelope($envelope['token'], $stale))])
      ->condition('id', $receipt->id)
      ->execute();
    $this->scriptOcsp('good');
    $verdict = $manager->verify($receipt->id, $digest);
    $this->assertFalse($verdict->valid);
    $this->assertSame('certificate_invalid', $verdict->reason);
  }

  /**
   * With ocsp_nonce on, the request carries a nonce that must be echoed.
   */
  public function testOcspNonceMustEcho(): void {
    $digest = $this->realDigest();
    $this->configureRfc3161();
    $this->config('audit_chain.settings')->set('witness_rfc3161.ocsp_nonce', TRUE)->save();
    $manager = $this->container->get('audit_chain.witness_manager');
    $grant = function (): array {
      $req = $this->transport->calls[array_key_last($this->transport->calls)]['body'];
      return ['status' => 200, 'body' => $this->pki->grantedResponse($req)];
    };

    // Echoed nonce: accepted.
    $this->transport->script[] = $grant;
    $this->transport->script[] = function (): array {
      $req = $this->transport->calls[array_key_last($this->transport->calls)]['body'];
      $nonce = Rfc3161Asn1::decodeOcspRequestNonce($req);
      $this->assertIsString($nonce);
      $this->assertSame(32, strlen($nonce));
      return ['status' => 200, 'body' => $this->pki->ocsp('good', ['nonce' => $nonce])];
    };
    $receipt = $manager->submit($digest, 'rfc3161', TRUE);
    $this->assertSame('confirmed', $receipt->status);

    // Missing or different nonce: refused, nothing stored.
    foreach (['missing' => NULL, 'different' => str_repeat("\x01", 32)] as $label => $nonce) {
      $before = $this->receiptRows();
      $this->transport->script[] = $grant;
      $this->transport->script[] = [
        'status' => 200,
        'body' => $this->pki->ocsp('good', $nonce === NULL ? [] : ['nonce' => $nonce]),
      ];
      try {
        $manager->submit($digest, 'rfc3161', TRUE);
        $this->fail("A $label OCSP nonce stored a receipt.");
      }
      catch (\RuntimeException $exception) {
        $this->assertSame('certificate_invalid', $exception->getMessage(), $label);
      }
      // Rows are stdClass objects, so compare by value, not identity.
      $this->assertEquals($before, $this->receiptRows(), $label);
    }
  }

  /**
   * Nonces stay off unless configured, so the request has none.
   */
  public function testOcspNonceOffByDefault(): void {
    $digest = $this->realDigest();
    $this->configureRfc3161();
    $this->scriptGranted();
    $this->container->get('audit_chain.witness_manager')->submit($digest, 'rfc3161', TRUE);
    $this->assertFalse($this->config('audit_chain.settings')->get('witness_rfc3161.ocsp_nonce'));
    $this->assertNull(Rfc3161Asn1::decodeOcspRequestNonce($this->transport->calls[1]['body']));
  }

  /**
   * Live OCSP revoked on an unexpired signer is certificate_revoked.
   */
  public function testOcspRevokedAtVerify(): void {
    $digest = $this->realDigest();
    $this->configureRfc3161();
    $this->scriptGranted();
    $manager = $this->container->get('audit_chain.witness_manager');
    $receipt = $manager->submit($digest, 'rfc3161');
    $this->scriptOcsp('revoked');
    $verdict = $manager->verify($receipt->id, $digest);
    $this->assertFalse($verdict->valid);
    $this->assertSame('certificate_revoked', $verdict->reason);
  }

  /**
   * An unreachable OCSP responder on an unexpired signer is not valid.
   */
  public function testOcspUnreachableAtVerify(): void {
    $digest = $this->realDigest();
    $this->configureRfc3161();
    $this->scriptGranted();
    $manager = $this->container->get('audit_chain.witness_manager');
    $receipt = $manager->submit($digest, 'rfc3161');
    $this->transport->script[] = new \RuntimeException('backend_unreachable');
    $verdict = $manager->verify($receipt->id, $digest);
    $this->assertFalse($verdict->valid);
    $this->assertSame('revocation_unreachable', $verdict->reason);
  }

  /**
   * Empty install defaults fail closed and submit nothing.
   */
  public function testEmptyDefaultsFailClosed(): void {
    $digest = $this->realDigest();
    $this->config('audit_chain.settings')->set('witness_backend', 'rfc3161')->save();
    $manager = $this->container->get('audit_chain.witness_manager');
    try {
      $manager->submit($digest, 'rfc3161', TRUE);
      $this->fail('An unconfigured RFC 3161 backend submitted.');
    }
    catch (\RuntimeException $exception) {
      $this->assertSame('witness_rfc3161_unconfigured', $exception->getMessage());
    }
    $this->assertSame([], $this->transport->calls);
    $this->assertSame([], $this->receiptRows());
  }

  /**
   * A Key-held credential is sent and never stored in config.
   */
  public function testCredentialKeyIsSent(): void {
    Key::create([
      'id' => 'tsa_secret',
      'label' => 'TSA secret',
      'key_type' => 'authentication',
      'key_provider' => 'config',
      'key_provider_settings' => ['key_value' => 'user:sekret'],
    ])->save();
    $digest = $this->realDigest();
    $this->configureRfc3161();
    $this->config('audit_chain.settings')->set('witness_rfc3161.credential_key', 'tsa_secret')->save();
    $this->scriptGranted();
    $this->container->get('audit_chain.witness_manager')->submit($digest, 'rfc3161', TRUE);
    $this->assertSame(
      'Basic ' . base64_encode('user:sekret'),
      $this->transport->calls[0]['headers']['Authorization'],
    );
    $exported = $this->config('audit_chain.settings')->get('witness_rfc3161');
    $this->assertSame('tsa_secret', $exported['credential_key']);
    $this->assertArrayNotHasKey('password', $exported);
  }

  /**
   * Operator export writes the envelope bytes. Update 10007 stays empty.
   */
  public function testOperatorExportAndUpdateHook(): void {
    $digest = $this->realDigest();
    $this->configureRfc3161();
    $this->scriptGranted();
    $manager = $this->container->get('audit_chain.witness_manager');
    $receipt = $manager->submit($digest, 'rfc3161');
    $operator = $this->container->get('audit_chain.witness_operator');
    $this->assertInstanceOf(WitnessOperator::class, $operator);
    $exported = $operator->export($receipt->id);
    $this->assertSame(0, $exported->exitCode);
    $this->assertSame($receipt->id . '.rfc3161', $exported->lines[0]);
    $this->assertSame(base64_decode($receipt->opaqueToken, TRUE), $exported->bytes);

    $this->container->get('module_handler')->loadInclude('audit_chain', 'install');
    $this->config('audit_chain.settings')->clear('witness_rfc3161')->save();
    audit_chain_update_10007();
    audit_chain_update_10007();
    $reloaded = $this->config('audit_chain.settings')->get('witness_rfc3161');
    $this->assertSame('', $reloaded['tsa_url']);
    $this->assertSame('', $reloaded['policy_oid']);
    $this->assertSame('', $reloaded['trust_anchors']);
    $this->assertFalse($reloaded['ocsp_nonce']);

    // Update 10009 adds ocsp_nonce (off) to sites that ran 10007 before
    // the key existed, and never flips an operator's TRUE back.
    $this->config('audit_chain.settings')->clear('witness_rfc3161.ocsp_nonce')->save();
    audit_chain_update_10009();
    $this->assertFalse($this->config('audit_chain.settings')->get('witness_rfc3161.ocsp_nonce'));
    $this->config('audit_chain.settings')->set('witness_rfc3161.ocsp_nonce', TRUE)->save();
    audit_chain_update_10009();
    $this->assertTrue($this->config('audit_chain.settings')->get('witness_rfc3161.ocsp_nonce'));
    $this->assertSame([], $this->container->get('database')->select('audit_chain_log', 'l')
      ->fields('l', ['operation'])
      ->condition('operation', 'before_rfc3161', '<>')
      ->execute()
      ->fetchCol());
  }

  /**
   * Points RFC 3161 at the fixture TSA.
   */
  private function configureRfc3161(?string $anchors = NULL): void {
    $this->config('audit_chain.settings')->set('witness_rfc3161', [
      'tsa_url' => 'https://tsa.example/tsa',
      'policy_oid' => Rfc3161FixtureFactory::POLICY,
      'trust_anchors' => $anchors ?? $this->pki->trustBundle(),
      'ocsp_override' => '',
      'credential_key' => '',
      'ocsp_nonce' => FALSE,
    ])->save();
  }

  /**
   * Scripts a granted TSA reply and a good OCSP reply.
   */
  private function scriptGranted(?Rfc3161FixtureFactory $pki = NULL): void {
    $this->scriptGrantedAndOcsp($pki ?? $this->pki, 'good');
  }

  /**
   * Scripts a granted TSA reply and one OCSP status.
   */
  private function scriptGrantedAndOcsp(Rfc3161FixtureFactory $pki, string $ocspStatus): void {
    $this->transport->script[] = function () use ($pki): array {
      $req = $this->transport->calls[array_key_last($this->transport->calls)]['body'];
      return ['status' => 200, 'body' => $pki->grantedResponse($req)];
    };
    $this->scriptOcsp($ocspStatus, $pki);
  }

  /**
   * Scripts one OCSP response.
   */
  private function scriptOcsp(string $status, ?Rfc3161FixtureFactory $pki = NULL): void {
    $factory = $pki ?? $this->pki;
    $this->transport->script[] = [
      'status' => 200,
      'body' => $factory->ocsp($status),
    ];
  }

  /**
   * Creates one real checkpoint and returns its digest.
   */
  private function realDigest(): string {
    $bundle = $this->container->get('audit_chain.archive_bundle_exporter')->create(1, 1);
    return $bundle['manifest']['digest'];
  }

  /**
   * Inserts one RFC 3161 receipt.
   */
  private function insertReceipt(string $token, string $digest): string {
    $id = 'rfc3161-' . substr(hash('sha256', $token), 0, 12);
    $this->container->get('database')->insert('audit_chain_witness_receipt')->fields([
      'id' => $id,
      'checkpoint_digest' => $digest,
      'backend_id' => 'rfc3161',
      'status' => WitnessReceipt::STATUS_CONFIRMED,
      'submitted' => 1790000000,
      'updated' => 1790000000,
      'opaque_token' => $token,
    ])->execute();
    return $id;
  }

  /**
   * Loads every witness receipt row.
   *
   * @return list<object>
   *   Receipt rows in database order.
   */
  private function receiptRows(): array {
    return $this->container->get('database')->select('audit_chain_witness_receipt', 'w')
      ->fields('w')
      ->execute()
      ->fetchAll();
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
