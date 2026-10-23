<?php

declare(strict_types=1);

namespace Drupal\Tests\audit_chain\Kernel;

use Drupal\audit_chain\Witness\Rfc3161Asn1;
use Drupal\audit_chain\Witness\Rfc3161Crypto;

/**
 * Builds an offline RFC 3161 PKI and protocol fixtures.
 *
 * Certificates and CMS/OCSP signatures use PHP's openssl extension.
 * Nothing here contacts a network.
 */
final class Rfc3161FixtureFactory {

  public const POLICY = '1.2.3.4.1.9999';

  public const OTHER_POLICY = '1.2.3.4.1.1111';

  /**
   * Root CA PEM.
   */
  public string $rootPem = '';

  /**
   * TSA signer PEM.
   */
  public string $tsaPem = '';

  /**
   * TSA private key PEM.
   */
  public string $tsaKeyPem = '';

  /**
   * OCSP responder PEM.
   */
  public string $ocspPem = '';

  /**
   * OCSP private key PEM.
   */
  public string $ocspKeyPem = '';

  /**
   * Second root used for the untrusted-signer case.
   */
  public string $otherRootPem = '';

  public function __construct(
    private readonly string $variant = 'good',
  ) {
    $this->build();
  }

  /**
   * Trust-anchor bundle for the configured backend.
   */
  public function trustBundle(): string {
    return $this->rootPem;
  }

  /**
   * Granted TimeStampResp that echoes the request nonce and imprint.
   */
  public function grantedResponse(string $requestDer, ?string $policy = NULL, ?string $nonce = NULL): string {
    $req = Rfc3161Asn1::decodeTimeStampReq($requestDer);
    return Rfc3161Asn1::encodeTimeStampResp(0, $this->token(
      $req['imprint'],
      $nonce ?? $req['nonce'],
      $policy ?? $req['policy'],
    ));
  }

  /**
   * Rejected TimeStampResp with no token.
   */
  public function rejectedResponse(): string {
    return Rfc3161Asn1::encodeTimeStampResp(2, NULL);
  }

  /**
   * CMS TimeStampToken for one imprint.
   */
  public function token(string $imprint, string $nonce, string $policy): string {
    $tst = Rfc3161Asn1::encodeTstInfo(
      $imprint,
      $policy,
      $nonce,
      gmdate('Y-m-d H:i:s') . ' GMT',
    );
    return Rfc3161Crypto::signCms($tst, $this->tsaPem, $this->tsaKeyPem);
  }

  /**
   * OCSP response for the TSA signer.
   *
   * @param string $status
   *   Good, revoked, or unknown.
   */
  public function ocsp(string $status = 'good'): string {
    $hashes = Rfc3161Asn1::ocspIssuerHashes(
      Rfc3161Crypto::pemToDer($this->tsaPem),
      Rfc3161Crypto::pemToDer($this->rootPem),
    );
    $produced = gmdate('Y-m-d H:i:s') . ' GMT';
    $tbs = Rfc3161Asn1::encodeOcspTbs(
      Rfc3161Asn1::subjectNameDer(Rfc3161Crypto::pemToDer($this->ocspPem)),
      $hashes['name_hash'],
      $hashes['key_hash'],
      $hashes['serial_hex'],
      $status,
      $produced,
    );
    $signature = Rfc3161Crypto::sign($tbs, $this->ocspKeyPem);
    return Rfc3161Asn1::encodeOcspResponse(
      $tbs,
      $signature,
      Rfc3161Crypto::pemToDer($this->ocspPem),
    );
  }

  /**
   * Builds the requested fixture PKI.
   */
  private function build(): void {
    $cnf = $this->opensslConfig();
    $rootKey = $this->newKey();
    $tsaKey = $this->newKey();
    $ocspKey = $this->newKey();
    $digest = $this->variant === 'sha1' ? 'sha1' : 'sha256';
    $root = $this->signCert(
      ['CN' => 'Audit Chain Test Root'],
      $rootKey,
      NULL,
      $rootKey,
      'v3_ca',
      $cnf,
      $digest,
      1,
    );
    $tsaExt = match ($this->variant) {
      'no_eku' => 'tsa_no_eku',
      default => 'tsa_cert',
    };
    $tsa = $this->signCert(
      ['CN' => 'Audit Chain Test TSA'],
      $tsaKey,
      $root['cert'],
      $rootKey,
      $tsaExt,
      $cnf,
      $digest,
      2,
    );
    $ocsp = $this->signCert(
      ['CN' => 'Audit Chain Test OCSP'],
      $ocspKey,
      $root['cert'],
      $rootKey,
      'ocsp_cert',
      $cnf,
      'sha256',
      3,
    );
    $this->rootPem = $root['pem'];
    $this->tsaPem = $tsa['pem'];
    $this->tsaKeyPem = $this->exportKey($tsaKey);
    $this->ocspPem = $ocsp['pem'];
    $this->ocspKeyPem = $this->exportKey($ocspKey);

    $otherKey = $this->newKey();
    $other = $this->signCert(
      ['CN' => 'Audit Chain Other Root'],
      $otherKey,
      NULL,
      $otherKey,
      'v3_ca',
      $cnf,
      'sha256',
      1,
    );
    $this->otherRootPem = $other['pem'];
    unlink($cnf);
  }

  /**
   * OpenSSL config used only to stamp certificate extensions.
   */
  private function opensslConfig(): string {
    $path = tempnam(sys_get_temp_dir(), 'acpkicnf');
    if ($path === FALSE) {
      throw new \RuntimeException('fixture_pki_config');
    }
    file_put_contents($path, <<<'CNF'
[ req ]
distinguished_name = req_dn
[ req_dn ]
[ v3_ca ]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
[ tsa_cert ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,timeStamping
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
authorityInfoAccess = OCSP;URI:https://ocsp.example/ocsp
[ tsa_no_eku ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
authorityInfoAccess = OCSP;URI:https://ocsp.example/ocsp
[ ocsp_cert ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
extendedKeyUsage = critical,OCSPSigning
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
CNF);
    return $path;
  }

  /**
   * RSA 2048 key through the openssl extension.
   */
  private function newKey(): \OpenSSLAsymmetricKey {
    $key = openssl_pkey_new([
      'private_key_type' => OPENSSL_KEYTYPE_RSA,
      'private_key_bits' => 2048,
    ]);
    if ($key === FALSE) {
      throw new \RuntimeException('fixture_pki_key');
    }
    return $key;
  }

  /**
   * Signs one certificate.
   *
   * @param array<string, string> $dn
   *   Subject DN.
   * @param \OpenSSLAsymmetricKey $key
   *   Subject key.
   * @param \OpenSSLCertificate|null $caCert
   *   Issuer certificate, or NULL for a self-signed root.
   * @param \OpenSSLAsymmetricKey $caKey
   *   Issuer private key.
   * @param string $ext
   *   OpenSSL config extension section.
   * @param string $cnf
   *   OpenSSL config path.
   * @param string $digest
   *   Certificate signature digest.
   * @param int $serial
   *   Certificate serial number.
   *
   * @return array{cert: \OpenSSLCertificate, pem: string}
   *   Certificate resource and PEM.
   */
  private function signCert(
    array $dn,
    \OpenSSLAsymmetricKey $key,
    ?\OpenSSLCertificate $caCert,
    \OpenSSLAsymmetricKey $caKey,
    string $ext,
    string $cnf,
    string $digest,
    int $serial,
  ): array {
    $csr = openssl_csr_new($dn, $key, ['digest_alg' => $digest, 'config' => $cnf]);
    if ($csr === FALSE) {
      throw new \RuntimeException('fixture_pki_csr');
    }
    $cert = openssl_csr_sign($csr, $caCert, $caKey, 3650, [
      'digest_alg' => $digest,
      'x509_extensions' => $ext,
      'config' => $cnf,
    ], $serial);
    if ($cert === FALSE) {
      throw new \RuntimeException('fixture_pki_sign');
    }
    $pem = '';
    openssl_x509_export($cert, $pem);
    return ['cert' => $cert, 'pem' => $pem];
  }

  /**
   * Exports a private key PEM.
   */
  private function exportKey(\OpenSSLAsymmetricKey $key): string {
    $pem = '';
    openssl_pkey_export($key, $pem);
    return $pem;
  }

}
