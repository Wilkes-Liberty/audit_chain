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

  /**
   * Root CA private key PEM, for responses the issuer signs itself.
   */
  public string $rootKeyPem = '';

  /**
   * Responder issued by the root but without id-kp-OCSPSigning.
   */
  public string $ocspNoEkuPem = '';

  /**
   * Private key for $ocspNoEkuPem.
   */
  public string $ocspNoEkuKeyPem = '';

  /**
   * Responder with id-kp-OCSPSigning, but issued by the other root.
   */
  public string $ocspOtherRootPem = '';

  /**
   * Private key for $ocspOtherRootPem.
   */
  public string $ocspOtherRootKeyPem = '';

  /**
   * Unix time stamped into tokens and OCSP responses.
   */
  public readonly int $now;

  /**
   * Builds the PKI.
   *
   * @param string $variant
   *   Good, no_eku, or sha1.
   * @param int|null $now
   *   Clock for genTime and OCSP times. Defaults to the time right after
   *   the certificates are minted: openssl stamps notBefore with the real
   *   current time, so an earlier clock would fall outside their validity.
   *   Tests that mock the Drupal clock should read $now back from here.
   */
  public function __construct(
    private readonly string $variant = 'good',
    ?int $now = NULL,
  ) {
    $this->build();
    $this->now = $now ?? time();
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
      self::generalizedTime($this->now),
    );
    return Rfc3161Crypto::signCms($tst, $this->tsaPem, $this->tsaKeyPem);
  }

  /**
   * OCSP response for the TSA signer.
   *
   * Defaults describe a correct answer from the delegated responder:
   * byName responderID, responder certificate embedded, CertID for the TSA
   * signer, thisUpdate = producedAt = the factory clock, no nextUpdate.
   *
   * @param string $status
   *   Good, revoked, or unknown.
   * @param array<string, mixed> $options
   *   Fixture knobs used by the rejection tests:
   *   - signer: delegated (default), issuer, no_eku, other_root, or tsa.
   *   - responder_id: name (default) or key.
   *   - certs: list of PEMs to embed instead of the signer's certificate.
   *   - serial_hex, name_hash, key_hash: CertID overrides.
   *   - produced_at, this_update, next_update: Unix times.
   *   - nonce: raw nonce bytes to echo in responseExtensions.
   *   - extra_responses: SingleResponses placed before the real one.
   */
  public function ocsp(string $status = 'good', array $options = []): string {
    $hashes = Rfc3161Asn1::ocspIssuerHashes(
      Rfc3161Crypto::pemToDer($this->tsaPem),
      Rfc3161Crypto::pemToDer($this->rootPem),
    );
    [$signerPem, $signerKeyPem] = match ($options['signer'] ?? 'delegated') {
      'issuer' => [$this->rootPem, $this->rootKeyPem],
      'no_eku' => [$this->ocspNoEkuPem, $this->ocspNoEkuKeyPem],
      'other_root' => [$this->ocspOtherRootPem, $this->ocspOtherRootKeyPem],
      'tsa' => [$this->tsaPem, $this->tsaKeyPem],
      default => [$this->ocspPem, $this->ocspKeyPem],
    };
    $signerDer = Rfc3161Crypto::pemToDer($signerPem);
    $produced = (int) ($options['produced_at'] ?? $this->now);
    $tbsOptions = [
      'this_update' => self::generalizedTime((int) ($options['this_update'] ?? $produced)),
    ];
    if (isset($options['next_update'])) {
      $tbsOptions['next_update'] = self::generalizedTime((int) $options['next_update']);
    }
    if (($options['responder_id'] ?? 'name') === 'key') {
      $tbsOptions['responder_key_hash'] = Rfc3161Asn1::publicKeyHash($signerDer);
    }
    if (isset($options['nonce'])) {
      $tbsOptions['nonce'] = $options['nonce'];
    }
    if (isset($options['extra_responses'])) {
      $tbsOptions['extra_responses'] = $options['extra_responses'];
    }
    $tbs = Rfc3161Asn1::encodeOcspTbs(
      Rfc3161Asn1::subjectNameDer($signerDer),
      $options['name_hash'] ?? $hashes['name_hash'],
      $options['key_hash'] ?? $hashes['key_hash'],
      $options['serial_hex'] ?? $hashes['serial_hex'],
      $status,
      self::generalizedTime($produced),
      $tbsOptions,
    );
    $signature = Rfc3161Crypto::sign($tbs, $signerKeyPem);
    // An issuer-signed answer normally carries no certificates.
    $certs = $options['certs'] ?? (($options['signer'] ?? 'delegated') === 'issuer' ? [] : [$signerPem]);
    return Rfc3161Asn1::encodeOcspResponse(
      $tbs,
      $signature,
      array_map([Rfc3161Crypto::class, 'pemToDer'], $certs),
    );
  }

  /**
   * GeneralizedTime source string for phpseclib.
   */
  public static function generalizedTime(int $stamp): string {
    return gmdate('Y-m-d H:i:s', $stamp) . ' GMT';
  }

  /**
   * Builds the requested fixture PKI.
   */
  private function build(): void {
    $cnf = $this->opensslConfig();
    // SHA-1 certificates are loaded, not minted. An OpenSSL 3 FIPS
    // provider refuses SHA-1, and the algorithm-floor test still needs
    // a SHA-1 signer to reject.
    if ($this->variant === 'sha1') {
      $this->loadSha1Signer();
      $this->buildSha256Companions($cnf);
      unlink($cnf);
      return;
    }
    $rootKey = $this->newKey();
    $tsaKey = $this->newKey();
    $ocspKey = $this->newKey();
    $root = $this->signCert(
      ['CN' => 'Audit Chain Test Root'],
      $rootKey,
      NULL,
      $rootKey,
      'v3_ca',
      $cnf,
      'sha256',
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
      'sha256',
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
    $this->rootKeyPem = $this->exportKey($rootKey);
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

    // Responders that must be refused: right issuer but no OCSPSigning
    // EKU, and right EKU but issued by a CA that did not issue the TSA.
    $noEkuKey = $this->newKey();
    $noEku = $this->signCert(
      ['CN' => 'Audit Chain Test OCSP No EKU'],
      $noEkuKey,
      $root['cert'],
      $rootKey,
      'ocsp_no_eku',
      $cnf,
      'sha256',
      4,
    );
    $this->ocspNoEkuPem = $noEku['pem'];
    $this->ocspNoEkuKeyPem = $this->exportKey($noEkuKey);
    $strayKey = $this->newKey();
    $stray = $this->signCert(
      ['CN' => 'Audit Chain Other OCSP'],
      $strayKey,
      $other['cert'],
      $otherKey,
      'ocsp_cert',
      $cnf,
      'sha256',
      5,
    );
    $this->ocspOtherRootPem = $stray['pem'];
    $this->ocspOtherRootKeyPem = $this->exportKey($strayKey);
    unlink($cnf);
  }

  /**
   * Loads the committed SHA-1 TSA pair.
   */
  private function loadSha1Signer(): void {
    $dir = dirname(__DIR__, 2) . '/fixtures/rfc3161_sha1';
    $root = file_get_contents($dir . '/root.pem');
    $tsa = file_get_contents($dir . '/tsa.pem');
    $key = file_get_contents($dir . '/tsa.key');
    if ($root === FALSE || $tsa === FALSE || $key === FALSE) {
      throw new \RuntimeException('fixture_pki_sha1');
    }
    $this->rootPem = $root;
    $this->tsaPem = $tsa;
    $this->tsaKeyPem = $key;
  }

  /**
   * Builds the OCSP responder and untrusted root with SHA-256.
   *
   * The SHA-1 rejection test fails in inspectToken before OCSP is
   * fetched. These companions stay approved so a FIPS provider can
   * still construct the factory.
   */
  private function buildSha256Companions(string $cnf): void {
    $ocspKey = $this->newKey();
    $ocsp = $this->signCert(
      ['CN' => 'Audit Chain Test OCSP'],
      $ocspKey,
      NULL,
      $ocspKey,
      'ocsp_cert',
      $cnf,
      'sha256',
      3,
    );
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
  }

  /**
   * OpenSSL config used only to stamp certificate extensions.
   */
  private function opensslConfig(): string {
    // cspell:ignore acpkicnf
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
[ ocsp_no_eku ]
basicConstraints = critical,CA:FALSE
keyUsage = critical,digitalSignature
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid,issuer
CNF);
    return $path;
  }

  /**
   * RSA 2048 key through the openssl extension.
   *
   * 2048-bit RSA and SHA-256 are approved under the OpenSSL 3 FIPS
   * provider. SHA-1 signers are not generated here.
   */
  private function newKey(): \OpenSSLAsymmetricKey {
    $key = openssl_pkey_new([
      'private_key_type' => OPENSSL_KEYTYPE_RSA,
      'private_key_bits' => 2048,
      'digest_alg' => 'sha256',
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
