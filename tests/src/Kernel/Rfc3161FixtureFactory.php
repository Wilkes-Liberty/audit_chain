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
   * Second OCSP responder with the same subject as $ocspPem and a new key.
   *
   * A byName responderID matches both certificates. Responses signed by
   * this key, with $ocspPem embedded first, are the rollover case.
   */
  public string $ocspRolloverPem = '';

  /**
   * Private key for $ocspRolloverPem.
   */
  public string $ocspRolloverKeyPem = '';

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
   * Signer and expired responder for a backdated producedAt.
   *
   * @var array{signer_pem: string, responder_pem: string, responder_key: string}|null
   */
  private ?array $historical = NULL;

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
  public function grantedResponse(string $requestDer, ?string $policy = NULL, ?string $nonce = NULL, ?int $genTime = NULL): string {
    $req = Rfc3161Asn1::decodeTimeStampReq($requestDer);
    return Rfc3161Asn1::encodeTimeStampResp(0, $this->token(
      $req['imprint'],
      $nonce ?? $req['nonce'],
      $policy ?? $req['policy'],
      $genTime,
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
  public function token(string $imprint, string $nonce, string $policy, ?int $genTime = NULL): string {
    $tst = Rfc3161Asn1::encodeTstInfo(
      $imprint,
      $policy,
      $nonce,
      self::generalizedTime($genTime ?? $this->now),
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
   *   - nonce_critical: mark that nonce extension critical.
   *   - extra_responses: SingleResponses placed before the real one.
   *   - extra_response_extensions, extra_single_extensions: extensions
   *     beyond the nonce, each array{oid: string, critical: bool}.
   *   - signer_pem, signer_key_pem: sign with this key instead of signer.
   *   - subject_pem: certificate the CertID names. Defaults to the TSA.
   */
  public function ocsp(string $status = 'good', array $options = []): string {
    $subjectPem = is_string($options['subject_pem'] ?? NULL) ? $options['subject_pem'] : $this->tsaPem;
    $hashes = Rfc3161Asn1::ocspIssuerHashes(
      Rfc3161Crypto::pemToDer($subjectPem),
      Rfc3161Crypto::pemToDer($this->rootPem),
    );
    if (is_string($options['signer_pem'] ?? NULL) && is_string($options['signer_key_pem'] ?? NULL)) {
      $signerPem = $options['signer_pem'];
      $signerKeyPem = $options['signer_key_pem'];
    }
    else {
      [$signerPem, $signerKeyPem] = match ($options['signer'] ?? 'delegated') {
        'issuer' => [$this->rootPem, $this->rootKeyPem],
        'no_eku' => [$this->ocspNoEkuPem, $this->ocspNoEkuKeyPem],
        'other_root' => [$this->ocspOtherRootPem, $this->ocspOtherRootKeyPem],
        'tsa' => [$this->tsaPem, $this->tsaKeyPem],
        'rollover' => [$this->ocspRolloverPem, $this->ocspRolloverKeyPem],
        default => [$this->ocspPem, $this->ocspKeyPem],
      };
    }
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
    if (($options['nonce_critical'] ?? FALSE) === TRUE) {
      $tbsOptions['nonce_critical'] = TRUE;
    }
    if (isset($options['extra_responses'])) {
      $tbsOptions['extra_responses'] = $options['extra_responses'];
    }
    if (isset($options['extra_response_extensions'])) {
      $tbsOptions['extra_response_extensions'] = $options['extra_response_extensions'];
    }
    if (isset($options['extra_single_extensions'])) {
      $tbsOptions['extra_single_extensions'] = $options['extra_single_extensions'];
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
   * OCSP signed by a responder certificate that has already expired.
   *
   * The signer is valid from 40 days ago through the next decade. The
   * responder was valid from 40 days ago until yesterday, so producedAt
   * can sit inside that window while thisUpdate claims "now". Returns
   * the signer PEM because it is not $this->tsaPem.
   *
   * @return array{der: string, signer_pem: string}
   *   Response DER and the certificate the CertID names.
   */
  public function historicalOcsp(int $producedAt, int $thisUpdate, ?int $nextUpdate = NULL): array {
    $this->historical ??= $this->buildHistoricalPair();
    $options = [
      'signer_pem' => $this->historical['responder_pem'],
      'signer_key_pem' => $this->historical['responder_key'],
      'subject_pem' => $this->historical['signer_pem'],
      'produced_at' => $producedAt,
      'this_update' => $thisUpdate,
    ];
    if ($nextUpdate !== NULL) {
      $options['next_update'] = $nextUpdate;
    }
    return [
      'der' => $this->ocsp('good', $options),
      'signer_pem' => $this->historical['signer_pem'],
    ];
  }

  /**
   * Mints the signer and expired responder used by historicalOcsp().
   *
   * @return array{signer_pem: string, responder_pem: string, responder_key: string}
   *   PEMs. The responder key is a PEM too.
   */
  private function buildHistoricalPair(): array {
    $cnf = $this->opensslConfig();
    try {
      $rootCert = openssl_x509_read($this->rootPem);
      $rootKey = openssl_pkey_get_private($this->rootKeyPem);
      if ($rootCert === FALSE || $rootKey === FALSE) {
        throw new \RuntimeException('fixture_pki_sign');
      }
      $signerKey = $this->newKey();
      $responderKey = $this->newKey();
      $signer = $this->signCert(
        ['CN' => 'Audit Chain Backdated TSA'],
        $signerKey,
        $rootCert,
        $rootKey,
        'tsa_cert',
        $cnf,
        'sha256',
        11,
        $this->now - 40 * 86400,
        $this->now + 3650 * 86400,
      );
      $responder = $this->signCert(
        ['CN' => 'Audit Chain Expired OCSP'],
        $responderKey,
        $rootCert,
        $rootKey,
        'ocsp_cert',
        $cnf,
        'sha256',
        12,
        $this->now - 40 * 86400,
        $this->now - 86400,
      );
    }
    finally {
      unlink($cnf);
    }
    return [
      'signer_pem' => $signer['pem'],
      'responder_pem' => $responder['pem'],
      'responder_key' => $this->exportKey($responderKey),
    ];
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
    // notBefore sits two hours before the factory clock. A token genTime
    // a few minutes behind $this->now is then still inside the certificate,
    // which is what the submit-versus-verify clock-split test needs.
    // openssl_csr_sign always starts at the current time, so this one
    // certificate is dated through the openssl CLI.
    $tsaNotBefore = time() - 7200;
    $tsa = $this->signCert(
      ['CN' => 'Audit Chain Test TSA'],
      $tsaKey,
      $root['cert'],
      $rootKey,
      $tsaExt,
      $cnf,
      'sha256',
      2,
      $tsaNotBefore,
      $tsaNotBefore + 3650 * 86400,
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
    // Same subject as the delegated responder, different key. Both stay
    // valid at the factory clock so a byName rollover has two candidates.
    $rolloverKey = $this->newKey();
    $rollover = $this->signCert(
      ['CN' => 'Audit Chain Test OCSP'],
      $rolloverKey,
      $root['cert'],
      $rootKey,
      'ocsp_cert',
      $cnf,
      'sha256',
      6,
    );
    $this->ocspRolloverPem = $rollover['pem'];
    $this->ocspRolloverKeyPem = $this->exportKey($rolloverKey);

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
   * @param int|null $notBefore
   *   Unix notBefore. NULL keeps openssl_csr_sign's "now".
   * @param int|null $notAfter
   *   Unix notAfter, required when $notBefore is set.
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
    ?int $notBefore = NULL,
    ?int $notAfter = NULL,
  ): array {
    $csr = openssl_csr_new($dn, $key, ['digest_alg' => $digest, 'config' => $cnf]);
    if ($csr === FALSE) {
      throw new \RuntimeException('fixture_pki_csr');
    }
    if ($notBefore !== NULL) {
      if ($caCert === NULL || $notAfter === NULL || $digest !== 'sha256') {
        throw new \RuntimeException('fixture_pki_sign');
      }
      $pem = $this->signCsrWithValidity($csr, $caCert, $caKey, $ext, $cnf, $serial, $notBefore, $notAfter);
      $cert = openssl_x509_read($pem);
      if ($cert === FALSE) {
        throw new \RuntimeException('fixture_pki_sign');
      }
      return ['cert' => $cert, 'pem' => $pem];
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
   * Signs a CSR with an explicit validity window.
   *
   * PHP's openssl_csr_sign starts the certificate at the current time, so
   * a notBefore in the past has to go through the openssl CLI. openssl
   * x509 -not_before exists on 3.2 and later, but the FIPS job builds
   * OpenSSL 3.0.16, whose x509 command rejects that flag. openssl ca
   * -startdate is in both. The command keeps the process environment, and
   * when OPENSSL_CONF is set (the FIPS provider config) those sections are
   * copied in front of the CA database sections so the provider stays
   * loaded. SHA-256 is an approved digest.
   */
  private function signCsrWithValidity(
    \OpenSSLCertificateSigningRequest $csr,
    \OpenSSLCertificate $caCert,
    \OpenSSLAsymmetricKey $caKey,
    string $ext,
    string $cnf,
    int $serial,
    int $notBefore,
    int $notAfter,
  ): string {
    // cspell:ignore acca startdate enddate extfile newcerts preserveDN
    $work = tempnam(sys_get_temp_dir(), 'acca');
    if ($work === FALSE) {
      throw new \RuntimeException('fixture_pki_sign');
    }
    unlink($work);
    if (!mkdir($work, 0700)) {
      throw new \RuntimeException('fixture_pki_sign');
    }
    $csrPem = '';
    $caPem = '';
    $keyPem = '';
    try {
      if (!openssl_csr_export($csr, $csrPem) || !openssl_x509_export($caCert, $caPem) || !openssl_pkey_export($caKey, $keyPem)) {
        throw new \RuntimeException('fixture_pki_sign');
      }
      $csrPath = $work . '/request.pem';
      $caPath = $work . '/anchor.pem';
      $keyPath = $work . '/private.pem';
      $outPath = $work . '/signed.pem';
      $serialFile = $work . '/serial';
      $newCerts = $work . '/issued';
      file_put_contents($csrPath, $csrPem);
      file_put_contents($caPath, $caPem);
      file_put_contents($keyPath, $keyPem);
      file_put_contents($work . '/index.txt', '');
      file_put_contents($serialFile, $this->evenHexSerial($serial) . "\n");
      if (!mkdir($newCerts, 0700)) {
        throw new \RuntimeException('fixture_pki_sign');
      }
      $configPath = $work . '/ca.cnf';
      file_put_contents($configPath, $this->caConfig($work, $serialFile, $newCerts));
      $env = getenv();
      if (!is_array($env)) {
        $env = [];
      }
      $env['OPENSSL_CONF'] = $configPath;
      $command = [
        'openssl', 'ca', '-batch', '-notext',
        '-in', $csrPath,
        '-cert', $caPath,
        '-keyfile', $keyPath,
        '-startdate', gmdate('YmdHis', $notBefore) . 'Z',
        '-enddate', gmdate('YmdHis', $notAfter) . 'Z',
        '-md', 'sha256',
        '-extfile', $cnf,
        '-extensions', $ext,
        '-preserveDN',
        '-out', $outPath,
      ];
      $process = proc_open($command, [1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, NULL, $env);
      if (!is_resource($process)) {
        throw new \RuntimeException('fixture_pki_sign');
      }
      stream_get_contents($pipes[1]);
      $stderr = stream_get_contents($pipes[2]);
      fclose($pipes[1]);
      fclose($pipes[2]);
      $exit = proc_close($process);
      $pem = file_get_contents($outPath);
      if ($exit !== 0 || !is_string($pem) || !str_contains($pem, 'BEGIN CERTIFICATE')) {
        $detail = is_string($stderr) ? trim($stderr) : '';
        throw new \RuntimeException('fixture_pki_sign' . ($detail === '' ? '' : ': ' . $detail));
      }
      return $pem;
    }
    finally {
      $this->removeTree($work);
    }
  }

  /**
   * Even-width hex serial for the openssl ca serial file.
   */
  private function evenHexSerial(int $serial): string {
    $hex = strtoupper(dechex($serial));
    if (strlen($hex) % 2 === 1) {
      $hex = '0' . $hex;
    }
    return $hex;
  }

  /**
   * OpenSSL config for one openssl ca invocation.
   *
   * A FIPS job points OPENSSL_CONF at the provider config. openssl ca
   * reads that variable as its whole config, so the provider sections
   * have to be in the same file as the CA database.
   */
  private function caConfig(string $work, string $serialFile, string $newCerts): string {
    $prefix = '';
    $inherited = getenv('OPENSSL_CONF');
    if (is_string($inherited) && $inherited !== '' && is_readable($inherited)) {
      $copied = file_get_contents($inherited);
      if (!is_string($copied)) {
        throw new \RuntimeException('fixture_pki_sign');
      }
      $prefix = $copied . "\n";
    }
    return $prefix . <<<CNF
[ ca ]
default_ca = ca_default

[ ca_default ]
database = {$work}/index.txt
serial = {$serialFile}
new_certs_dir = {$newCerts}
default_md = sha256
policy = ca_policy
email_in_dn = no
unique_subject = no
copy_extensions = none

[ ca_policy ]
commonName = supplied
countryName = optional
stateOrProvinceName = optional
localityName = optional
organizationName = optional
organizationalUnitName = optional
emailAddress = optional
CNF;
  }

  /**
   * Deletes a temporary directory tree.
   */
  private function removeTree(string $dir): void {
    if (!is_dir($dir)) {
      return;
    }
    $items = scandir($dir);
    if (!is_array($items)) {
      return;
    }
    foreach ($items as $item) {
      if ($item === '.' || $item === '..') {
        continue;
      }
      $path = $dir . '/' . $item;
      if (is_dir($path)) {
        $this->removeTree($path);
      }
      else {
        unlink($path);
      }
    }
    rmdir($dir);
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
