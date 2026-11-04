<?php

declare(strict_types=1);

namespace Drupal\audit_chain\Witness;

/**
 * Decides whether a parsed OCSP response proves the TSA signer is good.
 *
 * A signature that verifies is not enough on its own. RFC 6960 also needs
 * the response to be about the right certificate, to come from a responder
 * the issuing CA authorized, and to be current. Each check below fails
 * closed with one of the documented witness reason codes:
 *
 * - CertID: a SingleResponse must name the TSA signer by serial, issuer
 *   Name hash, and issuer key hash. A "good" answer about some other
 *   certificate says nothing about ours (certificate_invalid).
 * - Responder: either the issuing CA itself, or a certificate the issuing
 *   CA signed directly that carries id-kp-OCSPSigning (RFC 6960 4.2.2.2).
 *   Any other certificate, even one that chains to a trust anchor, is
 *   untrusted_tsa.
 * - Freshness: thisUpdate and producedAt may not be in the future,
 *   thisUpdate may not be later than producedAt beyond the skew
 *   allowance, and nextUpdate may not have passed. Without nextUpdate
 *   the answer must be recent (certificate_invalid).
 * - Responder key rollover: a byName responderID can match more than one
 *   embedded certificate. Each authorized candidate is tried against the
 *   signature.
 * - Nonce: when the request carried one, the response must echo it, so a
 *   recorded "good" answer cannot be replayed (certificate_invalid).
 * - Status: only good passes. Revoked is certificate_revoked; unknown is
 *   certificate_invalid.
 *
 * The class is pure: it does no I/O and takes the reference time as an
 * argument, so every rejection path is unit-testable with fixtures.
 *
 * @phpstan-import-type OcspBasicResponse from Rfc3161Asn1
 * @phpstan-import-type OcspSingleResponse from Rfc3161Asn1
 */
final class OcspResponseValidator {

  /**
   * Allowed clock difference between us and the responder, in seconds.
   */
  public const CLOCK_SKEW = 300;

  /**
   * Oldest acceptable thisUpdate when the responder sends no nextUpdate.
   *
   * RFC 6960 says a missing nextUpdate means newer information is always
   * available, which is what on-demand responders do. An hour leaves room
   * for caching proxies without accepting a days-old answer.
   */
  public const MAX_AGE_WITHOUT_NEXT_UPDATE = 3600;

  /**
   * CertID hash algorithms we can recompute, by OID.
   */
  private const CERT_ID_HASHES = [
    Rfc3161Asn1::OID_SHA1 => 'sha1',
    Rfc3161Asn1::OID_SHA256 => 'sha256',
    Rfc3161Asn1::OID_SHA384 => 'sha384',
    Rfc3161Asn1::OID_SHA512 => 'sha512',
  ];

  /**
   * Throws unless the response proves the signer was good at $at.
   *
   * @param OcspBasicResponse $ocsp
   *   Output of Rfc3161Asn1::decodeOcspResponse().
   * @param string $signerDer
   *   TSA signer certificate the response must be about.
   * @param string $issuerDer
   *   Certificate of the CA that issued the TSA signer.
   * @param int $at
   *   Reference time: now for a live answer, the token genTime for the
   *   answer stored at submit.
   * @param string|null $expectedNonce
   *   Nonce sent in the request, or NULL when none was sent.
   *
   * @return OcspSingleResponse
   *   The SingleResponse that vouched for the signer (always "good").
   *
   * @throws \RuntimeException
   *   With a witness reason code as the message.
   */
  public static function assertGood(array $ocsp, string $signerDer, string $issuerDer, int $at, ?string $expectedNonce): array {
    if (Rfc3161Asn1::isWeakOid($ocsp['hash_alg'])) {
      throw new \RuntimeException('weak_algorithm');
    }

    // Authenticity first, so nothing below acts on an unsigned claim.
    $single = self::matchingResponse($ocsp['responses'], $signerDer, $issuerDer);
    self::assertResponderSignature($ocsp, $issuerDer);

    // The signer must have been inside its validity window when the
    // responder vouched for it.
    $validity = Rfc3161Crypto::validity(Rfc3161Crypto::derToPem($signerDer));
    if ($ocsp['produced_at'] < $validity['from'] || $ocsp['produced_at'] > $validity['to']) {
      throw new \RuntimeException('certificate_invalid');
    }

    self::assertFresh($ocsp['produced_at'], $single['this_update'], $single['next_update'], $at);

    if ($expectedNonce !== NULL && ($ocsp['nonce'] === NULL || !hash_equals($expectedNonce, $ocsp['nonce']))) {
      throw new \RuntimeException('certificate_invalid');
    }

    if ($single['status'] === 'revoked') {
      throw new \RuntimeException('certificate_revoked');
    }
    if ($single['status'] !== 'good') {
      throw new \RuntimeException('certificate_invalid');
    }
    return $single;
  }

  /**
   * Finds the SingleResponse whose CertID names the TSA signer.
   *
   * @param list<OcspSingleResponse> $responses
   *   Every SingleResponse in the reply.
   * @param string $signerDer
   *   TSA signer certificate.
   * @param string $issuerDer
   *   Issuing CA certificate.
   *
   * @return OcspSingleResponse
   *   The matching response.
   */
  private static function matchingResponse(array $responses, string $signerDer, string $issuerDer): array {
    $signer = Rfc3161Asn1::certIdMaterial($signerDer);
    $issuer = Rfc3161Asn1::certIdMaterial($issuerDer);
    $serial = Rfc3161Asn1::normalizeSerialHex($signer['serial_hex']);
    foreach ($responses as $single) {
      $algo = self::CERT_ID_HASHES[$single['hash_alg']] ?? NULL;
      if ($algo === NULL || $single['serial_hex'] !== $serial) {
        continue;
      }
      // issuerNameHash covers the signer's issuer Name; issuerKeyHash
      // covers the issuing CA's public key. Both must match, otherwise a
      // same-serial certificate from another CA would be accepted.
      if (hash_equals(hash($algo, $signer['name'], TRUE), $single['name_hash'])
        && hash_equals(hash($algo, $issuer['key'], TRUE), $single['key_hash'])) {
        return $single;
      }
    }
    throw new \RuntimeException('certificate_invalid');
  }

  /**
   * Checks that an authorized responder signed the response.
   *
   * A byName responderID names a subject, not a key. During a rollover
   * the reply can embed two still-valid certificates with that subject.
   * The signature is tried against each authorized one. Committing to the
   * first certificate rejects a response the next certificate verifies.
   *
   * @param OcspBasicResponse $ocsp
   *   Parsed basic response.
   * @param string $issuerDer
   *   Issuing CA certificate.
   */
  private static function assertResponderSignature(array $ocsp, string $issuerDer): void {
    $candidates = self::responderCandidates($ocsp['responder_id'], $ocsp['certs'], $ocsp['produced_at'], $issuerDer);
    foreach ($candidates as $pem) {
      if (Rfc3161Crypto::verifyOcspSignature($ocsp['tbs'], $ocsp['signature'], $pem, $ocsp['hash_alg'])) {
        return;
      }
    }
    throw new \RuntimeException('signature_invalid');
  }

  /**
   * PEMs of certificates allowed to sign this response.
   *
   * @param array{type: string, value: string} $responderId
   *   Parsed responderID.
   * @param list<string> $certs
   *   Certificates embedded in the response (DER).
   * @param int $producedAt
   *   Response producedAt.
   * @param string $issuerDer
   *   Issuing CA certificate.
   *
   * @return list<string>
   *   Authorized responder PEMs, issuer first when it signed directly.
   */
  private static function responderCandidates(array $responderId, array $certs, int $producedAt, string $issuerDer): array {
    $issuerSubject = Rfc3161Asn1::subjectNameDer($issuerDer);
    $issuerPem = Rfc3161Crypto::derToPem($issuerDer);

    // Case 1: the CA that issued the TSA certificate signed the answer.
    if (self::responderIdMatches($responderId, $issuerDer)) {
      return [$issuerPem];
    }

    // Case 2: a delegated responder. It has to be shipped in the response,
    // named by responderID, issued directly by the same CA, and marked for
    // OCSP signing. Chaining to some other anchor is not enough.
    $issuerKey = openssl_pkey_get_public($issuerPem);
    if ($issuerKey === FALSE) {
      throw new \RuntimeException('untrusted_tsa');
    }
    $found = [];
    foreach ($certs as $certDer) {
      if (!self::responderIdMatches($responderId, $certDer)) {
        continue;
      }
      $certPem = Rfc3161Crypto::derToPem($certDer);
      if (Rfc3161Asn1::certIdMaterial($certDer)['name'] !== $issuerSubject || openssl_x509_verify($certPem, $issuerKey) !== 1) {
        continue;
      }
      if (!Rfc3161Asn1::hasExtendedKeyUsage($certDer, Rfc3161Asn1::OID_OCSP_SIGNING)) {
        continue;
      }
      if (!Rfc3161Crypto::meetsAlgorithmFloor($certPem, [])) {
        throw new \RuntimeException('weak_algorithm');
      }
      $window = Rfc3161Crypto::validity($certPem);
      if ($producedAt + self::CLOCK_SKEW < $window['from'] || $producedAt - self::CLOCK_SKEW > $window['to']) {
        continue;
      }
      $found[] = $certPem;
    }
    if ($found === []) {
      throw new \RuntimeException('untrusted_tsa');
    }
    return $found;
  }

  /**
   * Whether responderID (byName or byKey) identifies the certificate.
   *
   * @param array{type: string, value: string} $responderId
   *   Parsed responderID.
   * @param string $certDer
   *   Candidate certificate.
   */
  private static function responderIdMatches(array $responderId, string $certDer): bool {
    try {
      if ($responderId['type'] === 'name') {
        return hash_equals(Rfc3161Asn1::subjectNameDer($certDer), $responderId['value']);
      }
      if ($responderId['type'] === 'key') {
        return hash_equals(Rfc3161Asn1::publicKeyHash($certDer), $responderId['value']);
      }
    }
    catch (\RuntimeException) {
      // An unparsable embedded certificate simply is not the responder.
    }
    return FALSE;
  }

  /**
   * Rejects answers from the future, past nextUpdate, or too old.
   *
   * The thisUpdate field is when the status was known. The producedAt
   * field is when the responder signed. A thisUpdate later than
   * producedAt, beyond skew, claims a status the signature does not
   * cover: a key that has since expired can backdate producedAt into its
   * validity window and still advertise a current status.
   */
  private static function assertFresh(int $producedAt, int $thisUpdate, ?int $nextUpdate, int $at): void {
    if ($thisUpdate > $at + self::CLOCK_SKEW || $producedAt > $at + self::CLOCK_SKEW) {
      throw new \RuntimeException('certificate_invalid');
    }
    if ($thisUpdate > $producedAt + self::CLOCK_SKEW) {
      throw new \RuntimeException('certificate_invalid');
    }
    if ($nextUpdate !== NULL) {
      if ($nextUpdate < $thisUpdate || $nextUpdate < $at - self::CLOCK_SKEW) {
        throw new \RuntimeException('certificate_invalid');
      }
      return;
    }
    if ($thisUpdate < $at - self::MAX_AGE_WITHOUT_NEXT_UPDATE - self::CLOCK_SKEW) {
      throw new \RuntimeException('certificate_invalid');
    }
  }

}
