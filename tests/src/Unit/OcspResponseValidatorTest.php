<?php

declare(strict_types=1);

namespace Drupal\Tests\audit_chain\Unit;

use Drupal\audit_chain\Witness\OcspResponseValidator;
use Drupal\audit_chain\Witness\Rfc3161Asn1;
use Drupal\audit_chain\Witness\Rfc3161Crypto;
use Drupal\Tests\audit_chain\Kernel\Rfc3161FixtureFactory;
use Drupal\Tests\UnitTestCase;
use PHPUnit\Framework\Attributes\Group;

/**
 * One test per way an OCSP answer for the TSA signer must be refused.
 *
 * Every response is generated offline by Rfc3161FixtureFactory and signed
 * with real keys, so each case changes exactly one property of an
 * otherwise valid answer.
 *
 * @group audit_chain
 * @coversDefaultClass \Drupal\audit_chain\Witness\OcspResponseValidator
 *
 * @phpstan-import-type OcspBasicResponse from \Drupal\audit_chain\Witness\Rfc3161Asn1
 */
#[Group('audit_chain')]
final class OcspResponseValidatorTest extends UnitTestCase {

  /**
   * Shared PKI. Generating RSA keys is slow, so build it once per class.
   */
  private static ?Rfc3161FixtureFactory $sharedPki = NULL;

  /**
   * Fixture PKI for the current test.
   */
  private Rfc3161FixtureFactory $pki;

  /**
   * {@inheritdoc}
   */
  protected function setUp(): void {
    parent::setUp();
    self::$sharedPki ??= new Rfc3161FixtureFactory();
    $this->pki = self::$sharedPki;
  }

  /**
   * {@inheritdoc}
   */
  public static function tearDownAfterClass(): void {
    self::$sharedPki = NULL;
    parent::tearDownAfterClass();
  }

  /**
   * A delegated responder with OCSPSigning, named byName, is accepted.
   */
  public function testDelegatedResponderGoodPasses(): void {
    $this->assertAccepted($this->pki->ocsp('good'));
  }

  /**
   * The issuing CA may sign the answer itself, with no certs embedded.
   */
  public function testIssuerSignedGoodPasses(): void {
    $this->assertAccepted($this->pki->ocsp('good', ['signer' => 'issuer']));
  }

  /**
   * A byKey responderID identifies the responder as well as byName.
   */
  public function testByKeyResponderIdPasses(): void {
    $this->assertAccepted($this->pki->ocsp('good', ['responder_id' => 'key']));
    $this->assertAccepted($this->pki->ocsp('good', ['signer' => 'issuer', 'responder_id' => 'key']));
  }

  /**
   * The SingleResponse for our CertID is used, not simply the first one.
   */
  public function testPicksTheResponseForTheSigner(): void {
    $hashes = $this->signerHashes();
    $otherGood = [
      'name_hash' => $hashes['name_hash'],
      'key_hash' => $hashes['key_hash'],
      'serial_hex' => '7f7f',
      'status' => 'good',
    ];
    // Another certificate is good, ours is revoked: must report revoked.
    $this->assertRejected('certificate_revoked', $this->pki->ocsp('revoked', [
      'extra_responses' => [$otherGood],
    ]));
    // Another certificate is revoked, ours is good: must pass.
    $this->assertAccepted($this->pki->ocsp('good', [
      'extra_responses' => [['status' => 'revoked'] + $otherGood],
    ]));
  }

  /**
   * A good answer for a different serial does not cover the signer.
   */
  public function testWrongSerialRejected(): void {
    $this->assertRejected('certificate_invalid', $this->pki->ocsp('good', ['serial_hex' => '7f7f']));
  }

  /**
   * The issuer Name hash must match the signer's issuer.
   */
  public function testWrongIssuerNameHashRejected(): void {
    $this->assertRejected('certificate_invalid', $this->pki->ocsp('good', [
      'name_hash' => hash('sha1', 'some other issuer', TRUE),
    ]));
  }

  /**
   * The issuer key hash must match the issuing CA's key.
   */
  public function testWrongIssuerKeyHashRejected(): void {
    $otherRoot = Rfc3161Crypto::pemToDer($this->pki->otherRootPem);
    $this->assertRejected('certificate_invalid', $this->pki->ocsp('good', [
      'key_hash' => Rfc3161Asn1::publicKeyHash($otherRoot),
    ]));
  }

  /**
   * A responder the issuer signed, but without OCSPSigning, is refused.
   */
  public function testResponderWithoutOcspSigningEkuRejected(): void {
    $this->assertRejected('untrusted_tsa', $this->pki->ocsp('good', ['signer' => 'no_eku']));
  }

  /**
   * A responder with OCSPSigning from a different CA is refused.
   *
   * This is the case the old "chains to any trust anchor" check let
   * through when both CAs were configured as anchors.
   */
  public function testResponderFromAnotherCaRejected(): void {
    $this->assertRejected('untrusted_tsa', $this->pki->ocsp('good', ['signer' => 'other_root']));
  }

  /**
   * The TSA certificate cannot vouch for itself.
   */
  public function testTsaSignerAsResponderRejected(): void {
    $this->assertRejected('untrusted_tsa', $this->pki->ocsp('good', ['signer' => 'tsa']));
  }

  /**
   * A delegated responder must ship its certificate in the response.
   */
  public function testDelegatedResponderCertificateMissingRejected(): void {
    $this->assertRejected('untrusted_tsa', $this->pki->ocsp('good', ['certs' => []]));
  }

  /**
   * An embedded certificate that is not the named responder is ignored.
   */
  public function testEmbeddedCertificateNotMatchingResponderIdRejected(): void {
    $this->assertRejected('untrusted_tsa', $this->pki->ocsp('good', [
      'certs' => [$this->pki->ocspNoEkuPem],
    ]));
  }

  /**
   * Naming the issuer while signing with another key fails the signature.
   */
  public function testResponderIdNamesIssuerButOtherKeySignedRejected(): void {
    $parsed = Rfc3161Asn1::decodeOcspResponse($this->pki->ocsp('good'));
    $issuerSigned = Rfc3161Asn1::decodeOcspResponse($this->pki->ocsp('good', ['signer' => 'issuer']));
    // Keep the issuer-named TBS but swap in the delegated signature.
    $issuerSigned['signature'] = $parsed['signature'];
    $this->assertParsedRejected('signature_invalid', $issuerSigned);
  }

  /**
   * A flipped signature byte is signature_invalid.
   */
  public function testTamperedSignatureRejected(): void {
    $parsed = Rfc3161Asn1::decodeOcspResponse($this->pki->ocsp('good'));
    $parsed['signature'][10] = chr(ord($parsed['signature'][10]) ^ 0x01);
    $this->assertParsedRejected('signature_invalid', $parsed);
  }

  /**
   * A weak OCSP signature algorithm is refused before anything else.
   */
  public function testWeakSignatureAlgorithmRejected(): void {
    $parsed = Rfc3161Asn1::decodeOcspResponse($this->pki->ocsp('good'));
    // sha1WithRSAEncryption.
    $parsed['hash_alg'] = '1.2.840.113549.1.1.5';
    $this->assertParsedRejected('weak_algorithm', $parsed);
  }

  /**
   * ThisUpdate in the future, past the skew allowance, is refused.
   */
  public function testThisUpdateInTheFutureRejected(): void {
    $skew = OcspResponseValidator::CLOCK_SKEW;
    $this->assertAccepted($this->pki->ocsp('good', ['this_update' => $this->pki->now + $skew]));
    $this->assertRejected('certificate_invalid', $this->pki->ocsp('good', [
      'this_update' => $this->pki->now + $skew + 60,
    ]));
  }

  /**
   * ProducedAt in the future, past the skew allowance, is refused.
   */
  public function testProducedAtInTheFutureRejected(): void {
    $this->assertRejected('certificate_invalid', $this->pki->ocsp('good', [
      'produced_at' => $this->pki->now + OcspResponseValidator::CLOCK_SKEW + 60,
      'this_update' => $this->pki->now,
    ]));
  }

  /**
   * An answer whose nextUpdate has passed is stale.
   */
  public function testExpiredNextUpdateRejected(): void {
    $skew = OcspResponseValidator::CLOCK_SKEW;
    $this->assertAccepted($this->pki->ocsp('good', [
      'this_update' => $this->pki->now - 3600,
      'next_update' => $this->pki->now - $skew,
    ]));
    $this->assertRejected('certificate_invalid', $this->pki->ocsp('good', [
      'this_update' => $this->pki->now - 3600,
      'next_update' => $this->pki->now - $skew - 60,
    ]));
  }

  /**
   * A nextUpdate earlier than thisUpdate is nonsense and refused.
   */
  public function testNextUpdateBeforeThisUpdateRejected(): void {
    $this->assertRejected('certificate_invalid', $this->pki->ocsp('good', [
      'this_update' => $this->pki->now,
      'next_update' => $this->pki->now - 1,
    ]));
  }

  /**
   * Without nextUpdate, an old thisUpdate is refused.
   */
  public function testOldAnswerWithoutNextUpdateRejected(): void {
    $limit = OcspResponseValidator::MAX_AGE_WITHOUT_NEXT_UPDATE + OcspResponseValidator::CLOCK_SKEW;
    $this->assertAccepted($this->pki->ocsp('good', ['this_update' => $this->pki->now - $limit]));
    $this->assertRejected('certificate_invalid', $this->pki->ocsp('good', [
      'this_update' => $this->pki->now - $limit - 60,
    ]));
  }

  /**
   * The responder must not vouch for a time before the signer existed.
   */
  public function testProducedAtOutsideSignerValidityRejected(): void {
    // Issuer-signed, so the delegated responder's own validity window is
    // not what trips the check.
    $this->assertRejected('certificate_invalid', $this->pki->ocsp('good', [
      'signer' => 'issuer',
      'produced_at' => $this->pki->now - 86400,
      'this_update' => $this->pki->now,
    ]));
  }

  /**
   * A delegated responder must be valid when it signed the answer.
   */
  public function testDelegatedResponderOutsideItsValidityRejected(): void {
    $this->assertRejected('untrusted_tsa', $this->pki->ocsp('good', [
      'produced_at' => $this->pki->now - 86400,
      'this_update' => $this->pki->now,
    ]));
  }

  /**
   * A nonce we sent must come back unchanged.
   */
  public function testNonceMustEcho(): void {
    $nonce = random_bytes(32);
    $this->assertAccepted($this->pki->ocsp('good', ['nonce' => $nonce]), $nonce);
    $this->assertRejected('certificate_invalid', $this->pki->ocsp('good'), $nonce);
    $this->assertRejected('certificate_invalid', $this->pki->ocsp('good', ['nonce' => random_bytes(32)]), $nonce);
  }

  /**
   * A responder nonce we did not ask for is harmless.
   */
  public function testNonceWeDidNotSendIsIgnored(): void {
    $this->assertAccepted($this->pki->ocsp('good', ['nonce' => random_bytes(16)]));
  }

  /**
   * Revoked is certificate_revoked; unknown fails closed.
   */
  public function testRevokedAndUnknownRejected(): void {
    $this->assertRejected('certificate_revoked', $this->pki->ocsp('revoked'));
    $this->assertRejected('certificate_invalid', $this->pki->ocsp('unknown'));
  }

  /**
   * Revoked is only believed once the response is authenticated.
   */
  public function testUnauthenticatedRevokedIsNotReportedAsRevoked(): void {
    $this->assertRejected('untrusted_tsa', $this->pki->ocsp('revoked', ['signer' => 'other_root']));
  }

  /**
   * Asserts the response passes.
   */
  private function assertAccepted(string $der, ?string $nonce = NULL): void {
    $single = OcspResponseValidator::assertGood(
      Rfc3161Asn1::decodeOcspResponse($der),
      Rfc3161Crypto::pemToDer($this->pki->tsaPem),
      Rfc3161Crypto::pemToDer($this->pki->rootPem),
      $this->pki->now,
      $nonce,
    );
    $this->assertSame('good', $single['status']);
    $this->assertSame(
      Rfc3161Asn1::normalizeSerialHex($this->signerHashes()['serial_hex']),
      $single['serial_hex'],
    );
  }

  /**
   * Asserts the response fails with one reason.
   */
  private function assertRejected(string $reason, string $der, ?string $nonce = NULL): void {
    $this->assertParsedRejected($reason, Rfc3161Asn1::decodeOcspResponse($der), $nonce);
  }

  /**
   * Asserts an already parsed response fails with one reason.
   *
   * @param string $reason
   *   Expected witness reason code.
   * @param OcspBasicResponse $parsed
   *   Output of Rfc3161Asn1::decodeOcspResponse(), possibly edited.
   * @param string|null $nonce
   *   Nonce the request carried.
   */
  private function assertParsedRejected(string $reason, array $parsed, ?string $nonce = NULL): void {
    try {
      OcspResponseValidator::assertGood(
        $parsed,
        Rfc3161Crypto::pemToDer($this->pki->tsaPem),
        Rfc3161Crypto::pemToDer($this->pki->rootPem),
        $this->pki->now,
        $nonce,
      );
    }
    catch (\RuntimeException $exception) {
      $this->assertSame($reason, $exception->getMessage());
      return;
    }
    $this->fail("Expected $reason, but the OCSP response was accepted.");
  }

  /**
   * CertID hashes for the TSA signer.
   *
   * @return array{name_hash: string, key_hash: string, serial_hex: string, name: string}
   *   Issuer hashes and serial.
   */
  private function signerHashes(): array {
    return Rfc3161Asn1::ocspIssuerHashes(
      Rfc3161Crypto::pemToDer($this->pki->tsaPem),
      Rfc3161Crypto::pemToDer($this->pki->rootPem),
    );
  }

}
