<?php

declare(strict_types=1);

namespace Drupal\audit_chain;

use Drupal\audit_chain\Witness\DestinationPolicy;
use Drupal\audit_chain\Witness\OcspResponseValidator;
use Drupal\audit_chain\Witness\Rfc3161Asn1;
use Drupal\audit_chain\Witness\Rfc3161Crypto;
use Drupal\audit_chain\Witness\WitnessDnsResolverInterface;
use Drupal\audit_chain\Witness\WitnessTransportInterface;
use Drupal\Component\Datetime\TimeInterface;
use Drupal\Component\Uuid\UuidInterface;
use Drupal\Core\Config\ConfigFactoryInterface;
use Drupal\key\KeyRepositoryInterface;

/**
 * Witnesses a checkpoint digest with an RFC 3161 Time Stamping Authority.
 *
 * Submit posts only the 32 raw digest bytes inside a TimeStampReq. The
 * receipt is written only after the token is granted, the nonce and
 * imprint match, the policy matches, the CMS signature verifies, the
 * signer chains to a configured trust anchor with a critical
 * timeStamping EKU, algorithms meet the floor, and OCSP returns good.
 * Upgrade makes no network call. Verify re-checks the stored evidence
 * and, while the signer is unexpired, re-checks OCSP live.
 *
 * OCSP answers are judged by OcspResponseValidator: the response must be
 * about this signer, signed by its issuing CA or a delegated responder
 * that CA authorized, current, and (when ocsp_nonce is on) bound to our
 * request.
 *
 * @phpstan-import-type OcspBasicResponse from \Drupal\audit_chain\Witness\Rfc3161Asn1
 */
final class Rfc3161WitnessBackend implements IdentifiedWitnessBackendInterface {

  private const CONTRACT = 'audit_chain.checkpoint.v1';

  private const MAX_BYTES = 65536;

  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly WitnessTransportInterface $transport,
    private readonly WitnessDnsResolverInterface $dns,
    private readonly UuidInterface $uuid,
    private readonly KeyRepositoryInterface $keyRepository,
    private readonly TimeInterface $time,
  ) {}

  /**
   * {@inheritdoc}
   */
  public function id(): string {
    return 'rfc3161';
  }

  /**
   * {@inheritdoc}
   */
  public function submit(string $digestHex, array $context): WitnessReceipt {
    if ($context !== ['contract' => self::CONTRACT]) {
      throw new \RuntimeException('witness_context_rejected');
    }
    $digest = $this->rawDigest($digestHex);
    $config = $this->configuration();
    $request = Rfc3161Asn1::encodeTimeStampReq($digest, $config['policy_oid']);
    $headers = [
      'Accept' => 'application/timestamp-reply',
      'Content-Type' => 'application/timestamp-query',
    ];
    $this->authorize($headers, $config['credential_key']);
    $policy = new DestinationPolicy($this->dns);
    $policy->assertAllowed($config['tsa_url'], [DestinationPolicy::host($config['tsa_url'])]);
    try {
      $result = $this->transport->request('POST', $config['tsa_url'], $request['der'], $headers, self::MAX_BYTES);
    }
    catch (\RuntimeException $exception) {
      throw new \RuntimeException('backend_unreachable', 0, $exception);
    }
    if ($result['status'] < 200 || $result['status'] >= 300) {
      throw new \RuntimeException('backend_unreachable');
    }
    try {
      $response = Rfc3161Asn1::decodeTimeStampResp($result['body']);
    }
    catch (\RuntimeException) {
      throw new \RuntimeException('receipt_malformed');
    }
    if ($response['status'] !== 0 || $response['token'] === '') {
      throw new \RuntimeException('timestamp_rejected');
    }
    $checked = $this->inspectToken($response['token'], $digest, $request['nonce'], $config);
    // liveOcsp() throws unless the signer is confirmed good, so a receipt
    // is never written on a revoked, unknown, or unauthenticated answer.
    $ocsp = $this->liveOcsp($checked['signer_pem'], $config, TRUE);
    $token = base64_encode(Rfc3161Asn1::encodeEnvelope($response['token'], $ocsp));
    return new WitnessReceipt(
      $this->uuid->generate(),
      $this->id(),
      WitnessReceipt::STATUS_CONFIRMED,
      $token,
    );
  }

  /**
   * {@inheritdoc}
   */
  public function upgrade(WitnessReceipt $pending): WitnessReceipt {
    $this->assertBackend($pending);
    // Fail closed if the operator selected this backend without config.
    $this->configuration();
    return $pending;
  }

  /**
   * {@inheritdoc}
   */
  public function verify(WitnessReceipt $receipt, string $digestHex): WitnessVerdict {
    $this->assertBackend($receipt);
    try {
      $config = $this->configuration();
      $digest = $this->rawDigest($digestHex);
      $bytes = base64_decode($receipt->opaqueToken, TRUE);
      if ($bytes === FALSE) {
        return new WitnessVerdict(FALSE, 'receipt_malformed');
      }
      $envelope = Rfc3161Asn1::decodeEnvelope($bytes);
      $checked = $this->inspectToken($envelope['token'], $digest, NULL, $config);
      $stored = Rfc3161Asn1::decodeOcspResponse($envelope['ocsp']);
      $this->assertStoredOcsp($stored, $checked['signer_pem'], $checked['gen_time'], $config);
      if ($this->time->getCurrentTime() <= $checked['validity']['to']) {
        // Throws certificate_revoked / certificate_invalid / etc., which
        // the catch below turns into the matching verdict.
        $this->liveOcsp($checked['signer_pem'], $config, FALSE);
      }
      return new WitnessVerdict(TRUE, 'confirmed', [
        'policy' => $checked['policy'],
        'gen_time' => $checked['gen_time'],
        'trust_mode' => 'rfc3161',
      ]);
    }
    catch (\InvalidArgumentException) {
      return new WitnessVerdict(FALSE, 'receipt_malformed');
    }
    catch (\RuntimeException $exception) {
      $reason = $exception->getMessage();
      // Submit uses extra throw tokens (unconfigured, nonce, transport).
      // Verify only reports the documented reasons so an operator never
      // sees an undocumented verdict as "valid" or as a private code.
      if ($this->verifyReason($reason)) {
        return new WitnessVerdict(FALSE, $reason);
      }
      return new WitnessVerdict(FALSE, 'receipt_malformed');
    }
  }

  /**
   * Checks the CMS token, TSTInfo, chain, EKU, and algorithm floor.
   *
   * On submit the nonce must echo. Verify already bound the digest
   * through the imprint, so a missing nonce is not a verify failure.
   *
   * @param string $token
   *   CMS TimeStampToken DER.
   * @param string $digest
   *   Raw 32-byte checkpoint digest.
   * @param string|null $nonce
   *   Decimal nonce that must echo, or NULL on verify.
   * @param array<string, mixed> $config
   *   Loaded RFC 3161 settings.
   *
   * @return array{signer_pem: string, validity: array{from: int, to: int}, policy: string, gen_time: int}
   *   Signer and the TSTInfo fields verify needs later.
   */
  private function inspectToken(string $token, string $digest, ?string $nonce, array $config): array {
    $cms = Rfc3161Crypto::verifyCms($token);
    $tst = Rfc3161Asn1::decodeTstInfo($cms['content']);
    if (!hash_equals($digest, $tst['imprint'])) {
      throw new \RuntimeException('digest_mismatch');
    }
    if ($nonce !== NULL && !hash_equals($nonce, $tst['nonce'])) {
      throw new \RuntimeException('nonce_mismatch');
    }
    if (!hash_equals($config['policy_oid'], $tst['policy'])) {
      throw new \RuntimeException('policy_mismatch');
    }
    if (Rfc3161Asn1::isWeakOid($tst['hash_alg'])) {
      throw new \RuntimeException('weak_algorithm');
    }
    $algs = Rfc3161Asn1::cmsAlgorithms($token);
    $oids = array_merge($algs['digest_algs'], $algs['signature_algs'], [$tst['hash_alg']]);
    if (!Rfc3161Crypto::meetsAlgorithmFloor($cms['signer_pem'], $oids)) {
      throw new \RuntimeException('weak_algorithm');
    }
    $signerDer = Rfc3161Crypto::pemToDer($cms['signer_pem']);
    if (!Rfc3161Asn1::hasCriticalTimeStamping($signerDer)) {
      throw new \RuntimeException('certificate_invalid');
    }
    if (!Rfc3161Crypto::chainsToAnchor($cms['signer_pem'], $config['trust_anchors'])) {
      throw new \RuntimeException('untrusted_tsa');
    }
    $validity = Rfc3161Crypto::validity($cms['signer_pem']);
    if ($tst['gen_time'] < $validity['from'] || $tst['gen_time'] > $validity['to']) {
      throw new \RuntimeException('certificate_invalid');
    }
    return [
      'signer_pem' => $cms['signer_pem'],
      'validity' => $validity,
      'policy' => $tst['policy'],
      'gen_time' => $tst['gen_time'],
    ];
  }

  /**
   * Asks the OCSP responder about the TSA signer and checks the answer.
   *
   * Anything short of an authenticated, current "good" for this signer
   * throws. On submit every failure propagates so no receipt is stored.
   * On verify, failures that are not documented verify reasons (transport
   * trouble, an unparsable body) become revocation_unreachable.
   *
   * @param string $signerPem
   *   TSA signer certificate PEM.
   * @param array<string, mixed> $config
   *   Loaded RFC 3161 settings.
   * @param bool $submit
   *   TRUE when a failed check must throw before a receipt is written.
   *
   * @return string
   *   The raw OCSP response, for the submit envelope.
   */
  private function liveOcsp(string $signerPem, array $config, bool $submit): string {
    $url = $config['ocsp_override'] !== '' ? $config['ocsp_override'] : Rfc3161Crypto::ocspUri($signerPem);
    if ($url === '') {
      throw new \RuntimeException('revocation_unreachable');
    }
    $policy = new DestinationPolicy($this->dns);
    try {
      $policy->assertAllowed($url, [DestinationPolicy::host($url)]);
    }
    catch (\RuntimeException $exception) {
      throw new \RuntimeException('revocation_unreachable', 0, $exception);
    }
    $signerDer = Rfc3161Crypto::pemToDer($signerPem);
    $issuerDer = Rfc3161Crypto::pemToDer($this->issuerPem($signerPem, $config['trust_anchors']));
    $hashes = Rfc3161Asn1::ocspIssuerHashes($signerDer, $issuerDer);
    // A nonce stops a captured "good" answer from being replayed later.
    // It is opt-in because many CDN-fronted responders serve pre-signed
    // answers and ignore request nonces (RFC 8954 allows that).
    $nonce = $config['ocsp_nonce'] ? random_bytes(32) : NULL;
    $body = Rfc3161Asn1::encodeOcspRequest($hashes['name_hash'], $hashes['key_hash'], $hashes['serial_hex'], $nonce);
    try {
      $result = $this->transport->request('POST', $url, $body, [
        'Accept' => 'application/ocsp-response',
        'Content-Type' => 'application/ocsp-request',
      ], self::MAX_BYTES);
    }
    catch (\RuntimeException $exception) {
      throw new \RuntimeException('revocation_unreachable', 0, $exception);
    }
    if ($result['status'] < 200 || $result['status'] >= 300) {
      throw new \RuntimeException('revocation_unreachable');
    }
    try {
      $parsed = Rfc3161Asn1::decodeOcspResponse($result['body']);
      OcspResponseValidator::assertGood($parsed, $signerDer, $issuerDer, $this->time->getCurrentTime(), $nonce);
    }
    catch (\RuntimeException $exception) {
      if ($submit) {
        throw $exception;
      }
      if ($this->verifyReason($exception->getMessage())) {
        throw $exception;
      }
      throw new \RuntimeException('revocation_unreachable', 0, $exception);
    }
    return $result['body'];
  }

  /**
   * Re-checks the OCSP answer stored at submit.
   *
   * Freshness is judged against the token genTime: the stored answer has
   * to show the signer was good when the timestamp was issued. The nonce
   * used at submit is not kept, so it is not re-checked here; the live
   * check in verify() covers replay while the signer is still valid.
   *
   * @param OcspBasicResponse $stored
   *   Envelope OCSP, as returned by Rfc3161Asn1::decodeOcspResponse().
   * @param string $signerPem
   *   TSA signer certificate PEM.
   * @param int $genTime
   *   TSTInfo genTime of the stored token.
   * @param array<string, mixed> $config
   *   Loaded RFC 3161 settings.
   */
  private function assertStoredOcsp(array $stored, string $signerPem, int $genTime, array $config): void {
    $issuerDer = Rfc3161Crypto::pemToDer($this->issuerPem($signerPem, $config['trust_anchors']));
    OcspResponseValidator::assertGood($stored, Rfc3161Crypto::pemToDer($signerPem), $issuerDer, $genTime, NULL);
  }

  /**
   * Finds the trust anchor that issued the TSA signer.
   *
   * There is no fallback: the OCSP CertID and responder checks are only
   * meaningful against the real issuer, so a signer that no configured
   * anchor signed is untrusted_tsa rather than checked against a guess.
   *
   * @param string $signerPem
   *   TSA signer certificate PEM.
   * @param list<string> $anchors
   *   Configured trust-anchor PEMs.
   */
  private function issuerPem(string $signerPem, array $anchors): string {
    foreach ($anchors as $anchor) {
      $key = openssl_pkey_get_public($anchor);
      if ($key !== FALSE && openssl_x509_verify($signerPem, $key) === 1) {
        return $anchor;
      }
    }
    throw new \RuntimeException('untrusted_tsa');
  }

  /**
   * Adds a Key-held Authorization header when the vendor requires one.
   *
   * The secret never lives in exported config. A scheme already on the
   * key is kept. user:pass becomes Basic. Anything else is Bearer.
   *
   * @param array<string, string> $headers
   *   Request headers, modified in place.
   * @param string $keyId
   *   Key entity id, or empty when the TSA needs no credential.
   */
  private function authorize(array &$headers, string $keyId): void {
    if ($keyId === '') {
      return;
    }
    $key = $this->keyRepository->getKey($keyId);
    $value = $key ? (string) $key->getKeyValue() : '';
    if ($value === '') {
      throw new \RuntimeException('witness_rfc3161_unconfigured');
    }
    if (str_starts_with($value, 'Basic ') || str_starts_with($value, 'Bearer ')) {
      $headers['Authorization'] = $value;
      return;
    }
    if (str_contains($value, ':')) {
      $headers['Authorization'] = 'Basic ' . base64_encode($value);
      return;
    }
    $headers['Authorization'] = 'Bearer ' . $value;
  }

  /**
   * Converts a lowercase hex digest to 32 raw bytes.
   */
  private function rawDigest(string $digestHex): string {
    if (preg_match('/^[a-f0-9]{64}$/D', $digestHex) !== 1) {
      throw new \InvalidArgumentException('A lowercase SHA-256 checkpoint digest is required.');
    }
    $raw = hex2bin($digestHex);
    if ($raw === FALSE) {
      throw new \InvalidArgumentException('A lowercase SHA-256 checkpoint digest is required.');
    }
    return $raw;
  }

  /**
   * Loads RFC 3161 settings and fails closed when they are incomplete.
   *
   * Empty install defaults cannot be selected. A private or non-HTTPS
   * TSA URL is rejected by DestinationPolicy at request time.
   *
   * @return array{tsa_url: string, policy_oid: string, trust_anchors: list<string>, ocsp_override: string, credential_key: string, ocsp_nonce: bool}
   *   TSA URL, policy, anchors, optional OCSP override, optional key id,
   *   and whether OCSP requests carry a nonce.
   */
  private function configuration(): array {
    $value = $this->configFactory->get('audit_chain.settings')->get('witness_rfc3161');
    if (!is_array($value)) {
      throw new \RuntimeException('witness_rfc3161_unconfigured');
    }
    $url = $value['tsa_url'] ?? '';
    $policy = $value['policy_oid'] ?? '';
    $bundle = $value['trust_anchors'] ?? '';
    $ocsp = $value['ocsp_override'] ?? '';
    $credential = $value['credential_key'] ?? '';
    if (!is_string($url) || $url === '' || !is_string($policy) || preg_match('/^[0-9]+(\.[0-9]+)+$/', $policy) !== 1) {
      throw new \RuntimeException('witness_rfc3161_unconfigured');
    }
    if (!is_string($bundle) || $bundle === '' || !is_string($ocsp) || !is_string($credential)) {
      throw new \RuntimeException('witness_rfc3161_unconfigured');
    }
    $anchors = Rfc3161Crypto::splitPemBundle($bundle);
    if ($anchors === []) {
      throw new \RuntimeException('witness_rfc3161_unconfigured');
    }
    return [
      'tsa_url' => $url,
      'policy_oid' => $policy,
      'trust_anchors' => $anchors,
      'ocsp_override' => $ocsp,
      'credential_key' => $credential,
      // Only a real TRUE turns nonces on; a missing key keeps them off.
      'ocsp_nonce' => ($value['ocsp_nonce'] ?? FALSE) === TRUE,
    ];
  }

  /**
   * Rejects a receipt that belongs to another backend.
   */
  private function assertBackend(WitnessReceipt $receipt): void {
    if ($receipt->backendId !== $this->id()) {
      throw new \RuntimeException('witness_backend_mismatch');
    }
  }

  /**
   * Whether a thrown message is a documented verify failure reason.
   *
   * The listed tokens are the only ones verify may return. Submit may
   * still throw nonce_mismatch, backend_unreachable, or
   * witness_rfc3161_unconfigured; those stay off the verify surface.
   */
  private function verifyReason(string $reason): bool {
    return in_array($reason, [
      'receipt_malformed',
      'digest_mismatch',
      'signature_invalid',
      'untrusted_tsa',
      'policy_mismatch',
      'weak_algorithm',
      'certificate_invalid',
      'certificate_revoked',
      'revocation_unreachable',
    ], TRUE);
  }

}
