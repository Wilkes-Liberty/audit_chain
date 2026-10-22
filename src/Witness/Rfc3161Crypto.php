<?php

declare(strict_types=1);

namespace Drupal\audit_chain\Witness;

/**
 * OpenSSL operations for RFC 3161 tokens and OCSP evidence.
 *
 * Every signature and certificate check goes through PHP's openssl
 * extension so a host using the OpenSSL 3 FIPS provider stays on
 * validated crypto. Temporary files are used only because the CMS
 * functions are file-based; they are unlinked in finally.
 */
final class Rfc3161Crypto {

  /**
   * Verifies the CMS signature and returns the encapsulated TSTInfo.
   *
   * OPENSSL_CMS_NOVERIFY skips OpenSSL's own purpose and chain checks.
   * A TSA certificate has a critical timeStamping EKU, so OpenSSL would
   * otherwise reject it as an S/MIME signer. The chain and EKU are
   * checked separately with openssl_x509_*.
   *
   * @return array{content: string, signer_pem: string}
   *   Encapsulated content and the signer certificate PEM.
   */
  public static function verifyCms(string $cms): array {
    $input = self::writeTemp($cms);
    $content = self::writeTemp('');
    $signers = self::writeTemp('');
    try {
      self::clearErrors();
      $ok = openssl_cms_verify(
        $input,
        OPENSSL_CMS_BINARY | OPENSSL_CMS_NOVERIFY,
        $signers,
        [],
        NULL,
        $content,
        NULL,
        NULL,
        OPENSSL_ENCODING_DER,
      );
      if ($ok !== TRUE) {
        throw new \RuntimeException('signature_invalid');
      }
      $body = file_get_contents($content);
      $signer = file_get_contents($signers);
      if (!is_string($body) || $body === '' || !is_string($signer) || $signer === '') {
        throw new \RuntimeException('signature_invalid');
      }
      return ['content' => $body, 'signer_pem' => $signer];
    }
    finally {
      self::unlinkTemps([$input, $content, $signers]);
    }
  }

  /**
   * Whether the signer chains to one of the configured trust anchors.
   *
   * @param string $signerPem
   *   Signer certificate PEM.
   * @param list<string> $anchorPems
   *   PEM trust anchors.
   */
  public static function chainsToAnchor(string $signerPem, array $anchorPems): bool {
    $public = openssl_pkey_get_public($signerPem);
    if ($public === FALSE) {
      return FALSE;
    }
    // A trust-anchor signer is accepted when it is itself listed.
    foreach ($anchorPems as $anchor) {
      if (self::sameCert($signerPem, $anchor)) {
        return TRUE;
      }
      $issuerKey = openssl_pkey_get_public($anchor);
      if ($issuerKey === FALSE) {
        continue;
      }
      self::clearErrors();
      if (openssl_x509_verify($signerPem, $issuerKey) === 1) {
        return TRUE;
      }
    }
    return FALSE;
  }

  /**
   * Algorithm-floor check for the CMS token and the signer certificate.
   *
   * SHA-1 and anything weaker is weak_algorithm. RSA must be 2048-bit
   * or larger. ECDSA must be P-256 or larger.
   *
   * @param string $signerPem
   *   Signer certificate PEM.
   * @param list<string> $cmsOids
   *   Digest and signature OIDs taken from the CMS.
   */
  public static function meetsAlgorithmFloor(string $signerPem, array $cmsOids): bool {
    $parsed = openssl_x509_parse($signerPem);
    if ($parsed === FALSE) {
      return FALSE;
    }
    $sn = strtoupper((string) ($parsed['signatureTypeSN'] ?? ''));
    if (str_contains($sn, 'SHA1') || str_contains($sn, 'MD5') || str_contains($sn, 'SHA224')) {
      return FALSE;
    }
    foreach ($cmsOids as $oid) {
      if (Rfc3161Asn1::isWeakOid($oid)) {
        return FALSE;
      }
    }
    $public = openssl_pkey_get_public($signerPem);
    if ($public === FALSE) {
      return FALSE;
    }
    $details = openssl_pkey_get_details($public);
    if ($details === FALSE) {
      return FALSE;
    }
    $bits = (int) ($details['bits'] ?? 0);
    $type = $details['type'] ?? NULL;
    if ($type === OPENSSL_KEYTYPE_RSA) {
      return $bits >= 2048;
    }
    if ($type === OPENSSL_KEYTYPE_EC) {
      return $bits >= 256;
    }
    return FALSE;
  }

  /**
   * Signer notBefore / notAfter as Unix timestamps.
   *
   * @return array{from: int, to: int}
   *   Certificate validity window.
   */
  public static function validity(string $pem): array {
    $parsed = openssl_x509_parse($pem);
    if ($parsed === FALSE) {
      throw new \RuntimeException('certificate_invalid');
    }
    $from = $parsed['validFrom_time_t'] ?? NULL;
    $to = $parsed['validTo_time_t'] ?? NULL;
    if (!is_int($from) || !is_int($to)) {
      throw new \RuntimeException('certificate_invalid');
    }
    return ['from' => $from, 'to' => $to];
  }

  /**
   * AIA OCSP URI from the signer certificate, if present.
   */
  public static function ocspUri(string $pem): string {
    $parsed = openssl_x509_parse($pem);
    if ($parsed === FALSE) {
      return '';
    }
    $aia = $parsed['extensions']['authorityInfoAccess'] ?? '';
    if (!is_string($aia) || $aia === '') {
      return '';
    }
    if (preg_match('/OCSP\s*-\s*URI:(https:[^\s,;]+)/i', $aia, $matches) !== 1) {
      return '';
    }
    return $matches[1];
  }

  /**
   * Verifies an OCSP signature with openssl_verify.
   */
  public static function verifyOcspSignature(string $tbs, string $signature, string $responderPem, string $algorithmOid): bool {
    $public = openssl_pkey_get_public($responderPem);
    if ($public === FALSE) {
      return FALSE;
    }
    $algo = self::opensslAlgo($algorithmOid);
    if ($algo === NULL) {
      return FALSE;
    }
    self::clearErrors();
    return openssl_verify($tbs, $signature, $public, $algo) === 1;
  }

  /**
   * Signs fixture bytes with the PHP openssl extension.
   */
  public static function sign(string $data, string $privateKeyPem): string {
    $signature = '';
    self::clearErrors();
    if (!openssl_sign($data, $signature, $privateKeyPem, OPENSSL_ALGO_SHA256)) {
      throw new \RuntimeException('signature_invalid');
    }
    return $signature;
  }

  /**
   * CMS-signs TSTInfo for fixtures. Content type stays id-data.
   *
   * The CMS sign helper cannot set id-ct-TSTInfo. Verify reads the
   * encapsulated bytes as TSTInfo regardless of that OID.
   */
  public static function signCms(string $content, string $certPem, string $keyPem): string {
    $input = self::writeTemp($content);
    $output = self::writeTemp('');
    try {
      self::clearErrors();
      $ok = openssl_cms_sign(
        $input,
        $output,
        $certPem,
        $keyPem,
        [],
        OPENSSL_CMS_BINARY | OPENSSL_CMS_NOATTR,
        OPENSSL_ENCODING_DER,
      );
      $cms = $ok === TRUE ? file_get_contents($output) : FALSE;
      if (!is_string($cms) || $cms === '') {
        throw new \RuntimeException('signature_invalid');
      }
      return $cms;
    }
    finally {
      self::unlinkTemps([$input, $output]);
    }
  }

  /**
   * Splits a PEM bundle into individual certificates.
   *
   * @return list<string>
   *   One PEM per certificate.
   */
  public static function splitPemBundle(string $bundle): array {
    $certs = [];
    if (preg_match_all('/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/s', $bundle, $matches) !== FALSE) {
      foreach ($matches[0] as $pem) {
        if (openssl_x509_parse($pem) !== FALSE) {
          $certs[] = $pem . (str_ends_with($pem, "\n") ? '' : "\n");
        }
      }
    }
    return $certs;
  }

  /**
   * PEM to DER.
   */
  public static function pemToDer(string $pem): string {
    $b64 = preg_replace('/-----BEGIN [A-Z0-9 ]+-----|-----END [A-Z0-9 ]+-----|\s+/', '', $pem);
    if (!is_string($b64) || $b64 === '') {
      throw new \RuntimeException('certificate_invalid');
    }
    $der = base64_decode($b64, TRUE);
    if ($der === FALSE || $der === '') {
      throw new \RuntimeException('certificate_invalid');
    }
    return $der;
  }

  /**
   * DER to PEM.
   */
  public static function derToPem(string $der, string $type = 'CERTIFICATE'): string {
    return "-----BEGIN $type-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END $type-----\n";
  }

  /**
   * Whether two PEM certificates are the same parsed certificate.
   */
  private static function sameCert(string $left, string $right): bool {
    $a = openssl_x509_parse($left);
    $b = openssl_x509_parse($right);
    if ($a === FALSE || $b === FALSE) {
      return FALSE;
    }
    $leftSerial = $a['serialNumberHex'] ?? '';
    $rightSerial = $b['serialNumberHex'] ?? '';
    return $leftSerial !== '' && $leftSerial === $rightSerial && ($a['name'] ?? '') === ($b['name'] ?? '');
  }

  /**
   * Maps a signature OID to an openssl_verify algorithm constant.
   */
  private static function opensslAlgo(string $oid): ?int {
    return match ($oid) {
      Rfc3161Asn1::OID_SHA256, Rfc3161Asn1::OID_SHA256_RSA => OPENSSL_ALGO_SHA256,
      Rfc3161Asn1::OID_SHA384 => OPENSSL_ALGO_SHA384,
      Rfc3161Asn1::OID_SHA512 => OPENSSL_ALGO_SHA512,
      default => str_contains($oid, '1.2.840.113549.1.1.12') || str_contains($oid, '1.2.840.10045.4.3.3')
        ? OPENSSL_ALGO_SHA384
        : (str_contains($oid, '1.2.840.113549.1.1.13') || str_contains($oid, '1.2.840.10045.4.3.4')
          ? OPENSSL_ALGO_SHA512
          : (str_contains($oid, '1.2.840.10045.4.3.2') ? OPENSSL_ALGO_SHA256 : NULL)),
    };
  }

  /**
   * Writes bytes to a unique temporary file.
   */
  private static function writeTemp(string $contents): string {
    $path = tempnam(sys_get_temp_dir(), 'ac3161');
    if ($path === FALSE) {
      throw new \RuntimeException('signature_invalid');
    }
    file_put_contents($path, $contents);
    return $path;
  }

  /**
   * Deletes temporary CMS files.
   *
   * @param list<string> $paths
   *   Files created for this OpenSSL call.
   */
  private static function unlinkTemps(array $paths): void {
    foreach ($paths as $path) {
      if (is_file($path)) {
        unlink($path);
      }
    }
  }

  /**
   * Drains the OpenSSL error queue so the next call is isolated.
   */
  private static function clearErrors(): void {
    while (openssl_error_string() !== FALSE) {
    }
  }

}
