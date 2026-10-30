<?php

declare(strict_types=1);

namespace Drupal\audit_chain\Witness;

use phpseclib3\File\ASN1;
use phpseclib3\File\ASN1\Element;
use phpseclib3\Math\BigInteger;

/**
 * RFC 3161 and OCSP structure only. No signatures are computed here.
 *
 * Phpseclib's ASN.1 module encodes and decodes DER. Hashing, CMS
 * signatures, and certificate checks stay in Rfc3161Crypto so a FIPS
 * OpenSSL provider still performs every cryptographic operation.
 *
 * @phpstan-type OcspSingleResponse array{hash_alg: string, name_hash: string, key_hash: string, serial_hex: string, status: string, this_update: int, next_update: int|null}
 * @phpstan-type OcspBasicResponse array{produced_at: int, responder_id: array{type: string, value: string}, responses: list<OcspSingleResponse>, nonce: string|null, tbs: string, signature: string, certs: list<string>, hash_alg: string}
 */
final class Rfc3161Asn1 {

  public const ENVELOPE_VERSION = 'audit_chain.rfc3161.v1';

  public const OID_SHA256 = '2.16.840.1.101.3.4.2.1';

  public const OID_SHA384 = '2.16.840.1.101.3.4.2.2';

  public const OID_SHA512 = '2.16.840.1.101.3.4.2.3';

  public const OID_SHA1 = '1.3.14.3.2.26';

  public const OID_MD5 = '1.2.840.113549.2.5';

  public const OID_SHA224 = '2.16.840.1.101.3.4.2.4';

  public const OID_SHA1_RSA = '1.2.840.113549.1.1.5';

  public const OID_MD5_RSA = '1.2.840.113549.1.1.4';

  public const OID_SHA256_RSA = '1.2.840.113549.1.1.11';

  public const OID_ECDSA_SHA1 = '1.2.840.10045.4.1';

  public const OID_SIGNED_DATA = '1.2.840.113549.1.7.2';

  public const OID_DATA = '1.2.840.113549.1.7.1';

  public const OID_TST_INFO = '1.2.840.113549.1.9.16.1.4';

  public const OID_TIME_STAMPING = '1.3.6.1.5.5.7.3.8';

  public const OID_EKU = '2.5.29.37';

  public const OID_OCSP_BASIC = '1.3.6.1.5.5.7.48.1.1';

  /**
   * OCSP nonce extension (RFC 8954).
   */
  public const OID_OCSP_NONCE = '1.3.6.1.5.5.7.48.1.2';

  /**
   * Id-kp-OCSPSigning, required on a delegated OCSP responder certificate.
   */
  public const OID_OCSP_SIGNING = '1.3.6.1.5.5.7.3.9';

  /**
   * Weak hash and signature OIDs rejected as weak_algorithm.
   */
  private const WEAK_OIDS = [
    self::OID_SHA1,
    self::OID_SHA224,
    self::OID_MD5,
    self::OID_SHA1_RSA,
    self::OID_MD5_RSA,
    self::OID_ECDSA_SHA1,
  ];

  /**
   * Builds a TimeStampReq for the raw 32-byte checkpoint digest.
   *
   * The imprint is the digest itself, not a second hash of it. A random
   * 64-bit nonce, certReq, and the configured policy travel with it.
   *
   * @return array{der: string, nonce: string}
   *   DER request and the decimal nonce the TSA must echo.
   */
  public static function encodeTimeStampReq(string $digest, string $policyOid): array {
    if (strlen($digest) !== 32) {
      throw new \RuntimeException('receipt_malformed');
    }
    $nonce = new BigInteger(random_bytes(8), 256);
    $der = ASN1::encodeDER([
      'version' => 1,
      'messageImprint' => self::imprint($digest),
      'reqPolicy' => $policyOid,
      'nonce' => $nonce,
      'certReq' => TRUE,
    ], self::timeStampReqMap());
    if (!is_string($der) || $der === '') {
      throw new \RuntimeException('receipt_malformed');
    }
    return ['der' => $der, 'nonce' => $nonce->toString()];
  }

  /**
   * Reads a TimeStampReq so a fixture can echo the nonce.
   *
   * @return array{imprint: string, nonce: string, policy: string}
   *   Imprint bytes, decimal nonce, and requested policy.
   */
  public static function decodeTimeStampReq(string $der): array {
    $mapped = self::map($der, self::timeStampReqMap());
    $imprint = $mapped['messageImprint']['hashedMessage'] ?? NULL;
    $nonce = self::integerString($mapped['nonce'] ?? NULL);
    $policy = $mapped['reqPolicy'] ?? '';
    if (!is_string($imprint) || $imprint === '' || $nonce === '' || !is_string($policy)) {
      throw new \RuntimeException('receipt_malformed');
    }
    return [
      'imprint' => $imprint,
      'nonce' => $nonce,
      'policy' => $policy,
    ];
  }

  /**
   * Wraps a CMS TimeStampToken in a TimeStampResp.
   */
  public static function encodeTimeStampResp(int $status, ?string $token): string {
    $source = [
      'status' => ['status' => $status],
    ];
    if (is_string($token) && $token !== '') {
      $source['timeStampToken'] = new Element($token);
    }
    $der = ASN1::encodeDER($source, self::timeStampRespMap());
    if (!is_string($der) || $der === '') {
      throw new \RuntimeException('receipt_malformed');
    }
    return $der;
  }

  /**
   * Reads a TimeStampResp. A missing token is an empty string.
   *
   * @return array{status: int, token: string}
   *   PKIStatus and the CMS TimeStampToken DER.
   */
  public static function decodeTimeStampResp(string $der): array {
    $mapped = self::map($der, self::timeStampRespMap());
    $status = $mapped['status']['status'] ?? NULL;
    if ($status instanceof BigInteger) {
      $status = (int) $status->toString();
    }
    if (!is_int($status)) {
      throw new \RuntimeException('receipt_malformed');
    }
    $token = $mapped['timeStampToken'] ?? '';
    if ($token instanceof Element) {
      $token = $token->element;
    }
    if (!is_string($token)) {
      throw new \RuntimeException('receipt_malformed');
    }
    return ['status' => $status, 'token' => $token];
  }

  /**
   * Encodes TSTInfo for fixture tokens.
   */
  public static function encodeTstInfo(string $digest, string $policyOid, string $nonce, string $genTime): string {
    $der = ASN1::encodeDER([
      'version' => 1,
      'policy' => $policyOid,
      'messageImprint' => self::imprint($digest),
      'serialNumber' => 1,
      'genTime' => $genTime,
      'nonce' => new BigInteger($nonce),
    ], self::tstInfoEncodeMap());
    if (!is_string($der) || $der === '') {
      throw new \RuntimeException('receipt_malformed');
    }
    return $der;
  }

  /**
   * Reads TSTInfo from the CMS encapsulated content.
   *
   * @return array{policy: string, imprint: string, hash_alg: string, nonce: string, gen_time: int}
   *   Policy, imprint bytes, imprint OID, echoed nonce, and genTime.
   */
  public static function decodeTstInfo(string $der): array {
    $mapped = self::map($der, self::tstInfoMap());
    $policy = $mapped['policy'] ?? '';
    $imprint = $mapped['messageImprint']['hashedMessage'] ?? NULL;
    $hashAlg = $mapped['messageImprint']['hashAlgorithm']['algorithm'] ?? '';
    $nonce = self::integerString($mapped['nonce'] ?? NULL);
    $genTime = $mapped['genTime'] ?? '';
    if (!is_string($policy) || $policy === '' || !is_string($imprint) || !is_string($hashAlg) || !is_string($genTime) || $genTime === '') {
      throw new \RuntimeException('receipt_malformed');
    }
    $stamp = strtotime($genTime);
    if ($stamp === FALSE) {
      throw new \RuntimeException('receipt_malformed');
    }
    return [
      'policy' => $policy,
      'imprint' => $imprint,
      'hash_alg' => $hashAlg,
      'nonce' => $nonce,
      'gen_time' => $stamp,
    ];
  }

  /**
   * Stores the TimeStampToken and the OCSP evidence captured at submit.
   */
  public static function encodeEnvelope(string $token, string $ocsp): string {
    $der = ASN1::encodeDER([
      'version' => self::ENVELOPE_VERSION,
      'timeStampToken' => $token,
      'ocspResponse' => $ocsp,
    ], self::envelopeMap());
    if (!is_string($der) || $der === '') {
      throw new \RuntimeException('receipt_malformed');
    }
    return $der;
  }

  /**
   * Reads the versioned envelope. Any other version is malformed.
   *
   * @return array{token: string, ocsp: string}
   *   CMS TimeStampToken and the stored OCSP response.
   */
  public static function decodeEnvelope(string $der): array {
    $mapped = self::map($der, self::envelopeMap());
    $version = $mapped['version'] ?? '';
    $token = $mapped['timeStampToken'] ?? '';
    $ocsp = $mapped['ocspResponse'] ?? '';
    if ($version !== self::ENVELOPE_VERSION || !is_string($token) || $token === '' || !is_string($ocsp) || $ocsp === '') {
      throw new \RuntimeException('receipt_malformed');
    }
    return ['token' => $token, 'ocsp' => $ocsp];
  }

  /**
   * Builds an OCSP request for the TSA signer.
   *
   * @param string $issuerNameHash
   *   SHA-1 of the signer's issuer Name.
   * @param string $issuerKeyHash
   *   SHA-1 of the issuer public-key bits.
   * @param string $serialHex
   *   Signer serial as hex.
   * @param string|null $nonce
   *   Raw nonce bytes for an OCSP nonce request extension (RFC 8954), or NULL
   *   to send no nonce. A responder that answers must then echo it.
   */
  public static function encodeOcspRequest(string $issuerNameHash, string $issuerKeyHash, string $serialHex, ?string $nonce = NULL): string {
    $tbs = [
      'requestList' => [[
        'reqCert' => self::certId($issuerNameHash, $issuerKeyHash, $serialHex),
      ],
      ],
    ];
    if ($nonce !== NULL) {
      $tbs['requestExtensions'] = [self::nonceExtension($nonce)];
    }
    $der = ASN1::encodeDER(['tbsRequest' => $tbs], self::ocspRequestMap());
    if (!is_string($der) || $der === '') {
      throw new \RuntimeException('revocation_unreachable');
    }
    return $der;
  }

  /**
   * Reads the nonce from an OCSP request, or NULL when none was sent.
   *
   * Fixtures use this to echo the nonce the backend generated.
   */
  public static function decodeOcspRequestNonce(string $der): ?string {
    $mapped = self::map($der, self::ocspRequestMap());
    $extensions = $mapped['tbsRequest']['requestExtensions'] ?? NULL;
    return is_array($extensions) ? self::nonceFromExtensions($extensions) : NULL;
  }

  /**
   * Builds a fixture OCSP response around signed ResponseData.
   *
   * @param string $tbs
   *   Encoded ResponseData that $signature covers.
   * @param string $signature
   *   Raw signature bytes.
   * @param list<string>|string $certificates
   *   Certificates to embed (DER). An empty list embeds none, which is how
   *   a response signed directly by the issuing CA usually arrives.
   * @param string $responseStatus
   *   OCSPResponseStatus name.
   */
  public static function encodeOcspResponse(
    string $tbs,
    string $signature,
    array|string $certificates,
    string $responseStatus = 'successful',
  ): string {
    $status = match ($responseStatus) {
      'successful' => 0,
      'malformed' => 1,
      'internal' => 2,
      'try_later' => 3,
      default => 0,
    };
    $certs = array_values(array_filter(is_array($certificates) ? $certificates : [$certificates], static fn (string $der): bool => $der !== ''));
    $source = [
      'tbsResponseData' => new Element($tbs),
      'signatureAlgorithm' => [
        'algorithm' => self::OID_SHA256_RSA,
        'parameters' => NULL,
      ],
      'signature' => "\x00" . $signature,
    ];
    if ($certs !== []) {
      $source['certs'] = array_map(static fn (string $der): Element => new Element($der), $certs);
    }
    $basic = ASN1::encodeDER($source, self::basicOcspMap());
    if (!is_string($basic) || $basic === '') {
      throw new \RuntimeException('receipt_malformed');
    }
    $der = ASN1::encodeDER([
      'responseStatus' => $status,
      'responseBytes' => [
        'responseType' => self::OID_OCSP_BASIC,
        'response' => $basic,
      ],
    ], self::ocspResponseMap());
    if (!is_string($der) || $der === '') {
      throw new \RuntimeException('receipt_malformed');
    }
    return $der;
  }

  /**
   * Encodes ResponseData for a fixture OCSP signature.
   *
   * @param string $responderNameDer
   *   Responder subject Name DER, used for a byName responderID.
   * @param string $issuerNameHash
   *   SHA-1 of the issuer Name.
   * @param string $issuerKeyHash
   *   SHA-1 of the issuer public-key bits.
   * @param string $serialHex
   *   Signer serial as hex.
   * @param string $certStatus
   *   Good, revoked, or unknown.
   * @param string $producedAt
   *   GeneralizedTime source string.
   * @param array{this_update?: string, next_update?: string, responder_key_hash?: string, nonce?: string, extra_responses?: list<array{name_hash: string, key_hash: string, serial_hex: string, status: string}>} $options
   *   Fixture-only knobs: thisUpdate (defaults to producedAt), nextUpdate
   *   (omitted by default), a byKey responderID instead of byName, a nonce
   *   extension, and additional SingleResponses placed before this one.
   */
  public static function encodeOcspTbs(
    string $responderNameDer,
    string $issuerNameHash,
    string $issuerKeyHash,
    string $serialHex,
    string $certStatus,
    string $producedAt,
    array $options = [],
  ): string {
    $responses = [];
    foreach ($options['extra_responses'] ?? [] as $extra) {
      $responses[] = self::singleResponse($extra['name_hash'], $extra['key_hash'], $extra['serial_hex'], $extra['status'], $producedAt, $options);
    }
    $responses[] = self::singleResponse($issuerNameHash, $issuerKeyHash, $serialHex, $certStatus, $producedAt, $options);
    $responderId = isset($options['responder_key_hash'])
      ? self::explicitTag(2, self::octetString($options['responder_key_hash']))
      : self::explicitTag(1, $responderNameDer);
    $source = [
      'responderID' => new Element($responderId),
      'producedAt' => $producedAt,
      'responses' => $responses,
    ];
    if (isset($options['nonce'])) {
      $source['responseExtensions'] = [self::nonceExtension($options['nonce'])];
    }
    $der = ASN1::encodeDER($source, self::ocspTbsEncodeMap());
    if (!is_string($der) || $der === '') {
      throw new \RuntimeException('receipt_malformed');
    }
    return $der;
  }

  /**
   * One fixture SingleResponse.
   *
   * @param string $nameHash
   *   CertID issuerNameHash.
   * @param string $keyHash
   *   CertID issuerKeyHash.
   * @param string $serialHex
   *   CertID serial as hex.
   * @param string $certStatus
   *   Good, revoked, or unknown.
   * @param string $producedAt
   *   Fallback for thisUpdate and the revocation time.
   * @param array<string, mixed> $options
   *   The encodeOcspTbs() options.
   *
   * @return array<string, mixed>
   *   Mapping source for encodeDER.
   */
  private static function singleResponse(string $nameHash, string $keyHash, string $serialHex, string $certStatus, string $producedAt, array $options): array {
    $revokedTime = ASN1::encodeDER($producedAt, [
      'type' => ASN1::TYPE_GENERALIZED_TIME,
    ]);
    $statusDer = match ($certStatus) {
      'revoked' => is_string($revokedTime) ? self::implicitConstructed(1, $revokedTime) : "\x82\x00",
      'unknown' => "\x82\x00",
      default => "\x80\x00",
    };
    $single = [
      'certID' => self::certId($nameHash, $keyHash, $serialHex),
      'certStatus' => new Element($statusDer),
      'thisUpdate' => $options['this_update'] ?? $producedAt,
    ];
    if (isset($options['next_update'])) {
      $single['nextUpdate'] = $options['next_update'];
    }
    return $single;
  }

  /**
   * Reads an OCSP response and the exact TBS bytes that were signed.
   *
   * Nothing here decides whether the response is acceptable; that is
   * OcspResponseValidator's job. Every SingleResponse is returned so the
   * validator can pick the one whose CertID names the TSA signer, instead
   * of trusting whichever response happens to come first.
   *
   * @return OcspBasicResponse
   *   Parsed basic response.
   */
  public static function decodeOcspResponse(string $der): array {
    $mapped = self::map($der, self::ocspResponseMap());
    $status = $mapped['responseStatus'] ?? NULL;
    if ($status instanceof BigInteger) {
      $status = (int) $status->toString();
    }
    if ($status !== 0) {
      throw new \RuntimeException('revocation_unreachable');
    }
    $bytes = $mapped['responseBytes'] ?? NULL;
    if (!is_array($bytes) || ($bytes['responseType'] ?? '') !== self::OID_OCSP_BASIC) {
      throw new \RuntimeException('receipt_malformed');
    }
    $basic = $bytes['response'] ?? '';
    if (!is_string($basic) || $basic === '') {
      throw new \RuntimeException('receipt_malformed');
    }
    return self::decodeBasicOcsp($basic);
  }

  /**
   * Reads the signer certificate and CMS digest/signature algorithms.
   *
   * @return array{digest_algs: list<string>, signature_algs: list<string>, econtent_type: string}
   *   OIDs taken from SignedData. The signer cert comes from CMS verify.
   */
  public static function cmsAlgorithms(string $cms): array {
    $decoded = ASN1::decodeBER($cms);
    if (!is_array($decoded) || !isset($decoded[0]['content']) || !is_array($decoded[0]['content'])) {
      throw new \RuntimeException('receipt_malformed');
    }
    $children = $decoded[0]['content'];
    $contentType = self::oidFromNode($children[0] ?? NULL);
    if ($contentType !== self::OID_SIGNED_DATA) {
      throw new \RuntimeException('receipt_malformed');
    }
    $explicit = $children[1] ?? NULL;
    if (!is_array($explicit)) {
      throw new \RuntimeException('receipt_malformed');
    }
    $signedData = self::explicitSequence($explicit);
    if ($signedData === []) {
      throw new \RuntimeException('receipt_malformed');
    }
    $digestAlgs = [];
    $set = $signedData[1]['content'] ?? NULL;
    if (is_array($set)) {
      foreach ($set as $alg) {
        if (is_array($alg) && isset($alg['content'][0])) {
          $digestAlgs[] = self::oidFromNode($alg['content'][0]);
        }
      }
    }
    $encap = $signedData[2]['content'] ?? NULL;
    $econtent = '';
    if (is_array($encap) && isset($encap[0])) {
      $econtent = self::oidFromNode($encap[0]);
    }
    $signerInfos = self::lastSet($signedData);
    $signatureAlgs = [];
    if (is_array($signerInfos)) {
      foreach ($signerInfos as $info) {
        if (!is_array($info['content'] ?? NULL)) {
          continue;
        }
        $parts = $info['content'];
        // version, sid, digestAlgorithm, [signedAttrs], signatureAlgorithm.
        foreach ($parts as $part) {
          if (($part['type'] ?? NULL) === ASN1::TYPE_SEQUENCE && isset($part['content'][0])) {
            $oid = self::oidFromNode($part['content'][0]);
            if (str_starts_with($oid, '1.2.840.') || str_starts_with($oid, '2.16.840.')) {
              $signatureAlgs[] = $oid;
            }
          }
        }
      }
    }
    return [
      'digest_algs' => $digestAlgs,
      'signature_algs' => $signatureAlgs,
      'econtent_type' => $econtent,
    ];
  }

  /**
   * Whether an OID is below the SHA-256 / 2048-bit floor.
   */
  public static function isWeakOid(string $oid): bool {
    return in_array($oid, self::WEAK_OIDS, TRUE);
  }

  /**
   * Issuer Name DER and the public-key bits used for an OCSP CertID.
   *
   * @return array{name: string, key: string, serial_hex: string}
   *   Name TLV, raw subjectPublicKey bits, and the serial as hex.
   */
  public static function certIdMaterial(string $certDer): array {
    $decoded = ASN1::decodeBER($certDer);
    if (!is_array($decoded) || !isset($decoded[0]['content'][0]['content']) || !is_array($decoded[0]['content'][0]['content'])) {
      throw new \RuntimeException('certificate_invalid');
    }
    $tbs = $decoded[0]['content'][0]['content'];
    // v3: version, serial, signature, issuer, validity, subject, SPKI.
    $serialNode = $tbs[1] ?? NULL;
    $issuerNode = $tbs[3] ?? NULL;
    $spkiNode = $tbs[6] ?? NULL;
    if (!is_array($serialNode) || !is_array($issuerNode) || !is_array($spkiNode)) {
      throw new \RuntimeException('certificate_invalid');
    }
    $name = self::tlv($certDer, $issuerNode);
    $parsed = openssl_x509_parse(Rfc3161Crypto::derToPem($certDer));
    $serialHex = is_array($parsed) ? (string) ($parsed['serialNumberHex'] ?? '') : '';
    if ($serialHex === '') {
      $serialHex = bin2hex(self::integerContent($certDer, $serialNode));
    }
    $spki = $spkiNode['content'] ?? NULL;
    if (!is_array($spki) || !isset($spki[1])) {
      throw new \RuntimeException('certificate_invalid');
    }
    $bit = $spki[1]['content'] ?? '';
    if (!is_string($bit) || $bit === '') {
      throw new \RuntimeException('certificate_invalid');
    }
    // RFC 6960 hashes the BIT STRING value without the unused-bits count.
    $key = (ord($bit[0]) === 0) ? substr($bit, 1) : $bit;
    return [
      'name' => $name,
      'key' => $key,
      'serial_hex' => $serialHex,
    ];
  }

  /**
   * Subject Name DER, used as an OCSP responderID byName.
   */
  public static function subjectNameDer(string $certDer): string {
    $decoded = ASN1::decodeBER($certDer);
    if (!is_array($decoded) || !isset($decoded[0]['content'][0]['content'][5]) || !is_array($decoded[0]['content'][0]['content'][5])) {
      throw new \RuntimeException('certificate_invalid');
    }
    return self::tlv($certDer, $decoded[0]['content'][0]['content'][5]);
  }

  /**
   * Whether the certificate has a critical id-kp-timeStamping EKU.
   */
  public static function hasCriticalTimeStamping(string $certDer): bool {
    $eku = self::extendedKeyUsage($certDer);
    return $eku !== NULL && $eku['critical'] && in_array(self::OID_TIME_STAMPING, $eku['purposes'], TRUE);
  }

  /**
   * Whether the certificate's EKU lists one purpose (critical or not).
   *
   * RFC 6960 4.2.2.2 only requires id-kp-OCSPSigning to be present on a
   * delegated responder; it does not require the extension to be critical.
   */
  public static function hasExtendedKeyUsage(string $certDer, string $purposeOid): bool {
    $eku = self::extendedKeyUsage($certDer);
    return $eku !== NULL && in_array($purposeOid, $eku['purposes'], TRUE);
  }

  /**
   * Reads the extendedKeyUsage extension, or NULL when it is absent.
   *
   * @return array{critical: bool, purposes: list<string>}|null
   *   Criticality and the listed purpose OIDs.
   */
  private static function extendedKeyUsage(string $certDer): ?array {
    $decoded = ASN1::decodeBER($certDer);
    if (!is_array($decoded) || !isset($decoded[0]['content'][0]['content']) || !is_array($decoded[0]['content'][0]['content'])) {
      return NULL;
    }
    $tbs = $decoded[0]['content'][0]['content'];
    $extNode = NULL;
    foreach ($tbs as $child) {
      if (is_array($child) && ($child['constant'] ?? NULL) === 3) {
        $extNode = $child;
        break;
      }
    }
    if ($extNode === NULL) {
      return NULL;
    }
    $sequence = $extNode['content'][0] ?? $extNode;
    $mapped = ASN1::asn1map($sequence, self::extensionsMap());
    if (!is_array($mapped)) {
      return NULL;
    }
    foreach ($mapped as $ext) {
      if (($ext['extnId'] ?? '') !== self::OID_EKU) {
        continue;
      }
      $value = $ext['extnValue'] ?? '';
      if (!is_string($value) || $value === '') {
        return NULL;
      }
      $purposes = ASN1::asn1map(ASN1::decodeBER($value)[0] ?? [], [
        'type' => ASN1::TYPE_SEQUENCE,
        'min' => 1,
        'max' => -1,
        'children' => ['type' => ASN1::TYPE_OBJECT_IDENTIFIER],
      ]);
      if (!is_array($purposes)) {
        return NULL;
      }
      return [
        'critical' => !empty($ext['critical']),
        'purposes' => array_values(array_filter($purposes, 'is_string')),
      ];
    }
    return NULL;
  }

  /**
   * SHA-1 of a certificate's subjectPublicKey bits (RFC 6960 byKey).
   */
  public static function publicKeyHash(string $certDer): string {
    return hash('sha1', self::certIdMaterial($certDer)['key'], TRUE);
  }

  /**
   * SHA-1 of the issuer Name and of the issuer public-key bits.
   *
   * CertID still uses SHA-1 in RFC 6960. That identifies the issuer; it
   * is not a TSA signature algorithm and is not the weak_algorithm floor.
   *
   * @return array{name_hash: string, key_hash: string, serial_hex: string, name: string}
   *   CertID hashes, signer serial, and issuer Name DER.
   */
  public static function ocspIssuerHashes(string $signerDer, string $issuerDer): array {
    $issuer = self::certIdMaterial($issuerDer);
    $signer = self::certIdMaterial($signerDer);
    // Name hash is the TSA certificate's issuer Name TLV. Key hash is
    // the issuer certificate's subjectPublicKey bits. The two certs
    // must be a pair or CertID will not match the responder.
    return [
      'name_hash' => hash('sha1', $signer['name'], TRUE),
      'key_hash' => hash('sha1', $issuer['key'], TRUE),
      'serial_hex' => $signer['serial_hex'],
      'name' => $signer['name'],
    ];
  }

  /**
   * Maps a DER blob or throws receipt_malformed.
   *
   * @param string $der
   *   DER bytes to map.
   * @param array<string, mixed> $mapping
   *   Phpseclib ASN.1 mapping.
   *
   * @return array<string, mixed>
   *   Mapped structure.
   */
  private static function map(string $der, array $mapping): array {
    $decoded = ASN1::decodeBER($der);
    if (!is_array($decoded) || !isset($decoded[0])) {
      throw new \RuntimeException('receipt_malformed');
    }
    $mapped = ASN1::asn1map($decoded[0], $mapping);
    if (!is_array($mapped)) {
      throw new \RuntimeException('receipt_malformed');
    }
    return $mapped;
  }

  /**
   * MessageImprint for the raw digest under SHA-256.
   *
   * @return array<string, mixed>
   *   Mapping source for encodeDER.
   */
  private static function imprint(string $digest): array {
    return [
      'hashAlgorithm' => [
        'algorithm' => self::OID_SHA256,
        'parameters' => NULL,
      ],
      'hashedMessage' => $digest,
    ];
  }

  /**
   * CertID used by both the OCSP request and the fixture response.
   *
   * @return array<string, mixed>
   *   Mapping source for encodeDER.
   */
  private static function certId(string $issuerNameHash, string $issuerKeyHash, string $serialHex): array {
    return [
      'hashAlgorithm' => [
        'algorithm' => self::OID_SHA1,
        'parameters' => NULL,
      ],
      'issuerNameHash' => $issuerNameHash,
      'issuerKeyHash' => $issuerKeyHash,
      'serialNumber' => new BigInteger($serialHex, 16),
    ];
  }

  /**
   * Decimal string of a mapped INTEGER.
   */
  private static function integerString(mixed $value): string {
    if ($value instanceof BigInteger) {
      return $value->toString();
    }
    if (is_int($value) || is_string($value)) {
      return (string) $value;
    }
    return '';
  }

  /**
   * Exact TLV bytes for a decoded node.
   *
   * Phpseclib3's start is the TLV start when the first byte is a tag.
   *
   * @param string $der
   *   Certificate or CMS DER.
   * @param array<string, mixed> $node
   *   One decodeBER node.
   */
  private static function tlv(string $der, array $node): string {
    $start = (int) ($node['start'] ?? 0);
    $header = (int) ($node['headerlength'] ?? 0);
    if (isset($der[$start]) && self::looksLikeTlv($der[$start])) {
      return self::exactTlv($der, $start);
    }
    $before = max(0, $start - $header);
    if (isset($der[$before]) && self::looksLikeTlv($der[$before])) {
      return self::exactTlv($der, $before);
    }
    throw new \RuntimeException('certificate_invalid');
  }

  /**
   * Whether a byte is a plausible DER tag.
   */
  private static function looksLikeTlv(string $byte): bool {
    $tag = ord($byte);
    return $tag === 0x02 || $tag === 0x30 || $tag === 0x31 || ($tag & 0xC0) === 0x80;
  }

  /**
   * Reads one TLV using the length that is encoded in the DER.
   */
  private static function exactTlv(string $der, int $start): string {
    $lenByte = ord($der[$start + 1] ?? "\x00");
    if ($lenByte < 0x80) {
      return substr($der, $start, 2 + $lenByte);
    }
    $count = $lenByte & 0x7F;
    $length = 0;
    for ($i = 0; $i < $count; $i++) {
      $length = ($length << 8) | ord($der[$start + 2 + $i] ?? "\x00");
    }
    return substr($der, $start, 2 + $count + $length);
  }

  /**
   * Wraps bytes as EXPLICIT [n].
   */
  private static function explicitTag(int $tag, string $inner): string {
    return self::derTag(0xA0 | $tag, $inner);
  }

  /**
   * Wraps bytes as constructed IMPLICIT [n].
   */
  private static function implicitConstructed(int $tag, string $inner): string {
    return self::derTag(0xA0 | $tag, $inner);
  }

  /**
   * Builds one constructed context-specific TLV.
   */
  private static function derTag(int $tag, string $inner): string {
    $length = strlen($inner);
    if ($length < 0x80) {
      return chr($tag) . chr($length) . $inner;
    }
    $bytes = ltrim(pack('N', $length), "\x00");
    return chr($tag) . chr(0x80 | strlen($bytes)) . $bytes . $inner;
  }

  /**
   * Content bytes of an INTEGER node (the serial).
   *
   * @param string $der
   *   Certificate DER.
   * @param array<string, mixed> $node
   *   One decodeBER node.
   */
  private static function integerContent(string $der, array $node): string {
    $start = (int) ($node['start'] ?? 0);
    // Prefer a short-form INTEGER at start: tag, length, value.
    if (isset($der[$start]) && $der[$start] === "\x02") {
      $len = ord($der[$start + 1]);
      return substr($der, $start + 2, $len);
    }
    $tlv = self::tlv($der, $node);
    return substr($tlv, 2, ord($tlv[1] ?? "\x00"));
  }

  /**
   * Reads an OBJECT IDENTIFIER node as a dotted string.
   *
   * @param array<string, mixed>|null $node
   *   One decodeBER node.
   */
  private static function oidFromNode(?array $node): string {
    if ($node === NULL) {
      return '';
    }
    $mapped = ASN1::asn1map($node, ['type' => ASN1::TYPE_OBJECT_IDENTIFIER]);
    return is_string($mapped) ? $mapped : '';
  }

  /**
   * Children of an EXPLICIT [0] SignedData wrapper.
   *
   * @param array<string, mixed> $node
   *   Context-specific node.
   *
   * @return list<array<string, mixed>>
   *   SignedData children.
   */
  private static function explicitSequence(array $node): array {
    $inner = $node['content'] ?? NULL;
    if (is_array($inner) && isset($inner[0]['content']) && is_array($inner[0]['content'])) {
      return $inner[0]['content'];
    }
    if (is_array($inner) && isset($inner['content']) && is_array($inner['content'])) {
      return $inner['content'];
    }
    if (is_string($inner) && $inner !== '') {
      $decoded = ASN1::decodeBER($inner);
      if (is_array($decoded) && isset($decoded[0]['content']) && is_array($decoded[0]['content'])) {
        return $decoded[0]['content'];
      }
    }
    return [];
  }

  /**
   * Last SET in SignedData is signerInfos.
   *
   * @param list<array<string, mixed>> $signedData
   *   SignedData children.
   *
   * @return list<array<string, mixed>>|null
   *   SignerInfo nodes.
   */
  private static function lastSet(array $signedData): ?array {
    $set = NULL;
    foreach ($signedData as $child) {
      if (($child['type'] ?? NULL) === ASN1::TYPE_SET && isset($child['content']) && is_array($child['content'])) {
        $set = $child['content'];
      }
    }
    return $set;
  }

  /**
   * Reads BasicOCSPResponse including the original signed TBS.
   *
   * @return OcspBasicResponse
   *   Parsed basic response.
   */
  private static function decodeBasicOcsp(string $basic): array {
    $decoded = ASN1::decodeBER($basic);
    if (!is_array($decoded) || !isset($decoded[0]['content']) || !is_array($decoded[0]['content'])) {
      throw new \RuntimeException('receipt_malformed');
    }
    $mapped = ASN1::asn1map($decoded[0], self::basicOcspMap());
    if (!is_array($mapped)) {
      throw new \RuntimeException('receipt_malformed');
    }
    $tbsNode = $decoded[0]['content'][0] ?? NULL;
    if (!is_array($tbsNode)) {
      throw new \RuntimeException('receipt_malformed');
    }
    $tbs = $mapped['tbsResponseData'] ?? NULL;
    $tbsDer = $tbs instanceof Element ? $tbs->element : self::tlv($basic, $tbsNode);
    $tbsMapped = self::map($tbsDer, self::ocspTbsMap());
    $stamp = self::timeValue($tbsMapped['producedAt'] ?? NULL);
    if ($stamp === NULL) {
      throw new \RuntimeException('receipt_malformed');
    }

    $responderId = $tbsMapped['responderID'] ?? NULL;
    if (is_array($responderId) && isset($responderId['byName'])) {
      $name = $responderId['byName'];
      $responder = ['type' => 'name', 'value' => $name instanceof Element ? $name->element : ''];
    }
    elseif (is_array($responderId) && isset($responderId['byKey']) && is_string($responderId['byKey'])) {
      $responder = ['type' => 'key', 'value' => $responderId['byKey']];
    }
    else {
      throw new \RuntimeException('receipt_malformed');
    }
    if ($responder['value'] === '') {
      throw new \RuntimeException('receipt_malformed');
    }

    $responses = [];
    foreach (is_array($tbsMapped['responses'] ?? NULL) ? $tbsMapped['responses'] : [] as $single) {
      $certId = $single['certID'] ?? [];
      $serial = $certId['serialNumber'] ?? NULL;
      $thisUpdate = self::timeValue($single['thisUpdate'] ?? NULL);
      $nextUpdate = array_key_exists('nextUpdate', $single) ? self::timeValue($single['nextUpdate']) : NULL;
      if (!$serial instanceof BigInteger || $thisUpdate === NULL || (array_key_exists('nextUpdate', $single) && $nextUpdate === NULL)) {
        throw new \RuntimeException('receipt_malformed');
      }
      $choice = $single['certStatus'] ?? [];
      $status = 'unknown';
      if (is_array($choice) && array_key_exists('good', $choice)) {
        $status = 'good';
      }
      elseif (is_array($choice) && array_key_exists('revoked', $choice)) {
        $status = 'revoked';
      }
      $responses[] = [
        'hash_alg' => (string) ($certId['hashAlgorithm']['algorithm'] ?? ''),
        'name_hash' => (string) ($certId['issuerNameHash'] ?? ''),
        'key_hash' => (string) ($certId['issuerKeyHash'] ?? ''),
        'serial_hex' => self::normalizeSerialHex($serial->toHex()),
        'status' => $status,
        'this_update' => $thisUpdate,
        'next_update' => $nextUpdate,
      ];
    }
    if ($responses === []) {
      throw new \RuntimeException('receipt_malformed');
    }

    $extensions = $tbsMapped['responseExtensions'] ?? NULL;
    $nonce = is_array($extensions) ? self::nonceFromExtensions($extensions) : NULL;

    $signature = $mapped['signature'] ?? '';
    if (!is_string($signature) || strlen($signature) < 2) {
      throw new \RuntimeException('signature_invalid');
    }
    if (ord($signature[0]) === 0) {
      $signature = substr($signature, 1);
    }
    $certs = [];
    foreach (is_array($mapped['certs'] ?? NULL) ? $mapped['certs'] : [] as $cert) {
      $der = $cert instanceof Element ? $cert->element : (is_string($cert) ? $cert : '');
      if ($der !== '') {
        $certs[] = $der;
      }
    }
    $hashAlg = $mapped['signatureAlgorithm']['algorithm'] ?? '';
    if (!is_string($hashAlg) || $hashAlg === '') {
      throw new \RuntimeException('receipt_malformed');
    }
    return [
      'produced_at' => $stamp,
      'responder_id' => $responder,
      'responses' => $responses,
      'nonce' => $nonce,
      'tbs' => $tbsDer,
      'signature' => $signature,
      'certs' => $certs,
      'hash_alg' => $hashAlg,
    ];
  }

  /**
   * Lowercase hex without leading zeros, so serials compare as numbers.
   */
  public static function normalizeSerialHex(string $hex): string {
    $trimmed = ltrim(strtolower($hex), '0');
    return $trimmed === '' ? '0' : $trimmed;
  }

  /**
   * Unix time for a mapped GeneralizedTime, or NULL when unreadable.
   */
  private static function timeValue(mixed $value): ?int {
    if (!is_string($value) || $value === '') {
      return NULL;
    }
    $stamp = strtotime($value);
    return $stamp === FALSE ? NULL : $stamp;
  }

  /**
   * Builds an OCSP nonce extension (RFC 8954). The value is an OCTET STRING.
   *
   * @return array<string, mixed>
   *   Mapping source for one Extension.
   */
  private static function nonceExtension(string $nonce): array {
    return [
      'extnId' => self::OID_OCSP_NONCE,
      'critical' => FALSE,
      'extnValue' => self::octetString($nonce),
    ];
  }

  /**
   * Reads the nonce from mapped Extensions, or NULL when there is none.
   *
   * @param array<int, array<string, mixed>> $extensions
   *   Mapped Extensions.
   */
  private static function nonceFromExtensions(array $extensions): ?string {
    foreach ($extensions as $ext) {
      if (($ext['extnId'] ?? '') !== self::OID_OCSP_NONCE) {
        continue;
      }
      $value = $ext['extnValue'] ?? '';
      if (!is_string($value) || $value === '') {
        return '';
      }
      // RFC 8954 wraps the nonce in an OCTET STRING. Older responders sent
      // the bytes bare; keep those as-is so the comparison still works.
      $inner = ASN1::decodeBER($value);
      if (is_array($inner) && isset($inner[0])) {
        $octets = ASN1::asn1map($inner[0], ['type' => ASN1::TYPE_OCTET_STRING]);
        if (is_string($octets) && strlen($value) === ($inner[0]['length'] ?? -1)) {
          return $octets;
        }
      }
      return $value;
    }
    return NULL;
  }

  /**
   * DER OCTET STRING for raw bytes.
   */
  private static function octetString(string $bytes): string {
    $der = ASN1::encodeDER($bytes, ['type' => ASN1::TYPE_OCTET_STRING]);
    if (!is_string($der)) {
      throw new \RuntimeException('receipt_malformed');
    }
    return $der;
  }

  /**
   * TimeStampReq mapping.
   *
   * @return array<string, mixed>
   *   phpseclib mapping.
   */
  private static function timeStampReqMap(): array {
    return [
      'type' => ASN1::TYPE_SEQUENCE,
      'children' => [
        'version' => ['type' => ASN1::TYPE_INTEGER],
        'messageImprint' => self::imprintMap(),
        'reqPolicy' => [
          'type' => ASN1::TYPE_OBJECT_IDENTIFIER,
          'optional' => TRUE,
        ],
        'nonce' => [
          'type' => ASN1::TYPE_INTEGER,
          'optional' => TRUE,
        ],
        'certReq' => [
          'type' => ASN1::TYPE_BOOLEAN,
          'optional' => TRUE,
          'default' => FALSE,
        ],
      ],
    ];
  }

  /**
   * TimeStampResp mapping.
   *
   * @return array<string, mixed>
   *   phpseclib mapping.
   */
  private static function timeStampRespMap(): array {
    return [
      'type' => ASN1::TYPE_SEQUENCE,
      'children' => [
        'status' => [
          'type' => ASN1::TYPE_SEQUENCE,
          'children' => [
            'status' => ['type' => ASN1::TYPE_INTEGER],
            'statusString' => [
              'type' => ASN1::TYPE_ANY,
              'optional' => TRUE,
            ],
            'failInfo' => [
              'type' => ASN1::TYPE_BIT_STRING,
              'optional' => TRUE,
            ],
          ],
        ],
        'timeStampToken' => [
          'type' => ASN1::TYPE_ANY,
          'optional' => TRUE,
        ],
      ],
    ];
  }

  /**
   * TSTInfo mapping used when building fixture tokens.
   *
   * Accuracy and ordering are omitted so the nonce sits next to
   * genTime. A real TSA may still send those fields; decode uses the
   * fuller map.
   *
   * @return array<string, mixed>
   *   Phpseclib mapping.
   */
  private static function tstInfoEncodeMap(): array {
    return [
      'type' => ASN1::TYPE_SEQUENCE,
      'children' => [
        'version' => ['type' => ASN1::TYPE_INTEGER],
        'policy' => ['type' => ASN1::TYPE_OBJECT_IDENTIFIER],
        'messageImprint' => self::imprintMap(),
        'serialNumber' => ['type' => ASN1::TYPE_INTEGER],
        'genTime' => ['type' => ASN1::TYPE_GENERALIZED_TIME],
        'nonce' => [
          'type' => ASN1::TYPE_INTEGER,
          'optional' => TRUE,
        ],
      ],
    ];
  }

  /**
   * TSTInfo mapping.
   *
   * @return array<string, mixed>
   *   phpseclib mapping.
   */
  private static function tstInfoMap(): array {
    return [
      'type' => ASN1::TYPE_SEQUENCE,
      'children' => [
        'version' => ['type' => ASN1::TYPE_INTEGER],
        'policy' => ['type' => ASN1::TYPE_OBJECT_IDENTIFIER],
        'messageImprint' => self::imprintMap(),
        'serialNumber' => ['type' => ASN1::TYPE_INTEGER],
        'genTime' => ['type' => ASN1::TYPE_GENERALIZED_TIME],
        'accuracy' => [
          'type' => ASN1::TYPE_SEQUENCE,
          'optional' => TRUE,
          'children' => [
            'seconds' => [
              'type' => ASN1::TYPE_INTEGER,
              'optional' => TRUE,
            ],
            'millis' => [
              'type' => ASN1::TYPE_INTEGER,
              'constant' => 0,
              'optional' => TRUE,
              'implicit' => TRUE,
            ],
            'micros' => [
              'type' => ASN1::TYPE_INTEGER,
              'constant' => 1,
              'optional' => TRUE,
              'implicit' => TRUE,
            ],
          ],
        ],
        'ordering' => [
          'type' => ASN1::TYPE_BOOLEAN,
          'optional' => TRUE,
          'default' => FALSE,
        ],
        'nonce' => [
          'type' => ASN1::TYPE_INTEGER,
          'optional' => TRUE,
        ],
        'tsa' => [
          'type' => ASN1::TYPE_ANY,
          'constant' => 0,
          'optional' => TRUE,
          'explicit' => TRUE,
        ],
        'extensions' => [
          'type' => ASN1::TYPE_ANY,
          'constant' => 1,
          'optional' => TRUE,
          'implicit' => TRUE,
        ],
      ],
    ];
  }

  /**
   * MessageImprint mapping.
   *
   * @return array<string, mixed>
   *   phpseclib mapping.
   */
  private static function imprintMap(): array {
    return [
      'type' => ASN1::TYPE_SEQUENCE,
      'children' => [
        'hashAlgorithm' => [
          'type' => ASN1::TYPE_SEQUENCE,
          'children' => [
            'algorithm' => ['type' => ASN1::TYPE_OBJECT_IDENTIFIER],
            'parameters' => [
              'type' => ASN1::TYPE_ANY,
              'optional' => TRUE,
            ],
          ],
        ],
        'hashedMessage' => ['type' => ASN1::TYPE_OCTET_STRING],
      ],
    ];
  }

  /**
   * Versioned receipt envelope mapping.
   *
   * @return array<string, mixed>
   *   phpseclib mapping.
   */
  private static function envelopeMap(): array {
    return [
      'type' => ASN1::TYPE_SEQUENCE,
      'children' => [
        'version' => ['type' => ASN1::TYPE_UTF8_STRING],
        'timeStampToken' => ['type' => ASN1::TYPE_OCTET_STRING],
        'ocspResponse' => ['type' => ASN1::TYPE_OCTET_STRING],
      ],
    ];
  }

  /**
   * OCSPRequest mapping.
   *
   * @return array<string, mixed>
   *   phpseclib mapping.
   */
  private static function ocspRequestMap(): array {
    return [
      'type' => ASN1::TYPE_SEQUENCE,
      'children' => [
        'tbsRequest' => [
          'type' => ASN1::TYPE_SEQUENCE,
          'children' => [
            'requestList' => [
              'type' => ASN1::TYPE_SEQUENCE,
              'min' => 1,
              'max' => -1,
              'children' => [
                'type' => ASN1::TYPE_SEQUENCE,
                'children' => [
                  'reqCert' => self::certIdMap(),
                ],
              ],
            ],
            'requestExtensions' => [
              'constant' => 2,
              'optional' => TRUE,
              'explicit' => TRUE,
            ] + self::extensionsMap(),
          ],
        ],
      ],
    ];
  }

  /**
   * Extensions mapping (RFC 5280).
   *
   * @return array<string, mixed>
   *   phpseclib mapping.
   */
  private static function extensionsMap(): array {
    return [
      'type' => ASN1::TYPE_SEQUENCE,
      'min' => 1,
      'max' => -1,
      'children' => [
        'type' => ASN1::TYPE_SEQUENCE,
        'children' => [
          'extnId' => ['type' => ASN1::TYPE_OBJECT_IDENTIFIER],
          'critical' => [
            'type' => ASN1::TYPE_BOOLEAN,
            'optional' => TRUE,
            'default' => FALSE,
          ],
          'extnValue' => ['type' => ASN1::TYPE_OCTET_STRING],
        ],
      ],
    ];
  }

  /**
   * CertID mapping.
   *
   * @return array<string, mixed>
   *   phpseclib mapping.
   */
  private static function certIdMap(): array {
    return [
      'type' => ASN1::TYPE_SEQUENCE,
      'children' => [
        'hashAlgorithm' => [
          'type' => ASN1::TYPE_SEQUENCE,
          'children' => [
            'algorithm' => ['type' => ASN1::TYPE_OBJECT_IDENTIFIER],
            'parameters' => [
              'type' => ASN1::TYPE_ANY,
              'optional' => TRUE,
            ],
          ],
        ],
        'issuerNameHash' => ['type' => ASN1::TYPE_OCTET_STRING],
        'issuerKeyHash' => ['type' => ASN1::TYPE_OCTET_STRING],
        'serialNumber' => ['type' => ASN1::TYPE_INTEGER],
      ],
    ];
  }

  /**
   * OCSPResponse mapping.
   *
   * @return array<string, mixed>
   *   phpseclib mapping.
   */
  private static function ocspResponseMap(): array {
    return [
      'type' => ASN1::TYPE_SEQUENCE,
      'children' => [
        'responseStatus' => ['type' => ASN1::TYPE_ENUMERATED],
        'responseBytes' => [
          'constant' => 0,
          'optional' => TRUE,
          'explicit' => TRUE,
          'type' => ASN1::TYPE_SEQUENCE,
          'children' => [
            'responseType' => ['type' => ASN1::TYPE_OBJECT_IDENTIFIER],
            'response' => ['type' => ASN1::TYPE_OCTET_STRING],
          ],
        ],
      ],
    ];
  }

  /**
   * BasicOCSPResponse mapping.
   *
   * @return array<string, mixed>
   *   phpseclib mapping.
   */
  private static function basicOcspMap(): array {
    return [
      'type' => ASN1::TYPE_SEQUENCE,
      'children' => [
        'tbsResponseData' => ['type' => ASN1::TYPE_ANY],
        'signatureAlgorithm' => [
          'type' => ASN1::TYPE_SEQUENCE,
          'children' => [
            'algorithm' => ['type' => ASN1::TYPE_OBJECT_IDENTIFIER],
            'parameters' => [
              'type' => ASN1::TYPE_ANY,
              'optional' => TRUE,
            ],
          ],
        ],
        'signature' => ['type' => ASN1::TYPE_BIT_STRING],
        'certs' => [
          'constant' => 0,
          'optional' => TRUE,
          'explicit' => TRUE,
          'type' => ASN1::TYPE_SEQUENCE,
          'min' => 1,
          'max' => -1,
          'children' => ['type' => ASN1::TYPE_ANY],
        ],
      ],
    ];
  }

  /**
   * ResponseData mapping used when building fixture OCSP.
   *
   * Tagged CHOICE fields are supplied as raw Elements so phpseclib
   * does not have to encode implicit NULL.
   *
   * @return array<string, mixed>
   *   Phpseclib mapping.
   */
  private static function ocspTbsEncodeMap(): array {
    return [
      'type' => ASN1::TYPE_SEQUENCE,
      'children' => [
        'responderID' => ['type' => ASN1::TYPE_ANY],
        'producedAt' => ['type' => ASN1::TYPE_GENERALIZED_TIME],
        'responses' => [
          'type' => ASN1::TYPE_SEQUENCE,
          'min' => 1,
          'max' => -1,
          'children' => [
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => [
              'certID' => self::certIdMap(),
              'certStatus' => ['type' => ASN1::TYPE_ANY],
              'thisUpdate' => ['type' => ASN1::TYPE_GENERALIZED_TIME],
              'nextUpdate' => [
                'type' => ASN1::TYPE_GENERALIZED_TIME,
                'constant' => 0,
                'optional' => TRUE,
                'explicit' => TRUE,
              ],
            ],
          ],
        ],
        'responseExtensions' => [
          'constant' => 1,
          'optional' => TRUE,
          'explicit' => TRUE,
        ] + self::extensionsMap(),
      ],
    ];
  }

  /**
   * ResponseData mapping.
   *
   * @return array<string, mixed>
   *   phpseclib mapping.
   */
  private static function ocspTbsMap(): array {
    return [
      'type' => ASN1::TYPE_SEQUENCE,
      'children' => [
        'version' => [
          'type' => ASN1::TYPE_INTEGER,
          'constant' => 0,
          'optional' => TRUE,
          'explicit' => TRUE,
        ],
        // ResponderID ::= CHOICE { byName [1] Name, byKey [2] KeyHash }.
        // Both are EXPLICIT; a responder may use either.
        'responderID' => [
          'type' => ASN1::TYPE_CHOICE,
          'children' => [
            'byName' => [
              'type' => ASN1::TYPE_ANY,
              'constant' => 1,
              'explicit' => TRUE,
            ],
            'byKey' => [
              'type' => ASN1::TYPE_OCTET_STRING,
              'constant' => 2,
              'explicit' => TRUE,
            ],
          ],
        ],
        'producedAt' => ['type' => ASN1::TYPE_GENERALIZED_TIME],
        'responses' => [
          'type' => ASN1::TYPE_SEQUENCE,
          'min' => 1,
          'max' => -1,
          'children' => [
            'type' => ASN1::TYPE_SEQUENCE,
            'children' => [
              'certID' => self::certIdMap(),
              'certStatus' => [
                'type' => ASN1::TYPE_CHOICE,
                'children' => [
                  'good' => [
                    'type' => ASN1::TYPE_NULL,
                    'constant' => 0,
                    'implicit' => TRUE,
                  ],
                  'revoked' => [
                    'type' => ASN1::TYPE_SEQUENCE,
                    'constant' => 1,
                    'implicit' => TRUE,
                    'children' => [
                      'revocationTime' => [
                        'type' => ASN1::TYPE_GENERALIZED_TIME,
                      ],
                    ],
                  ],
                  'unknown' => [
                    'type' => ASN1::TYPE_NULL,
                    'constant' => 2,
                    'implicit' => TRUE,
                  ],
                ],
              ],
              'thisUpdate' => ['type' => ASN1::TYPE_GENERALIZED_TIME],
              'nextUpdate' => [
                'type' => ASN1::TYPE_GENERALIZED_TIME,
                'constant' => 0,
                'optional' => TRUE,
                'explicit' => TRUE,
              ],
              'singleExtensions' => [
                'constant' => 1,
                'optional' => TRUE,
                'explicit' => TRUE,
              ] + self::extensionsMap(),
            ],
          ],
        ],
        'responseExtensions' => [
          'constant' => 1,
          'optional' => TRUE,
          'explicit' => TRUE,
        ] + self::extensionsMap(),
      ],
    ];
  }

}
