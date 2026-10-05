<?php

declare(strict_types=1);

namespace Drupal\audit_chain;

use Drupal\audit_chain\Witness\DestinationPolicy;
use Drupal\audit_chain\Witness\OtsProof;
use Drupal\audit_chain\Witness\WitnessDnsResolverInterface;
use Drupal\audit_chain\Witness\WitnessTransportInterface;
use Drupal\Component\Uuid\UuidInterface;
use Drupal\Core\Config\ConfigFactoryInterface;

/**
 * Witnesses a checkpoint digest with OpenTimestamps and Bitcoin headers.
 *
 * Submit posts only the 32 raw digest bytes. Confirmation requires a checked
 * Bitcoin header in the best chain at the configured depth. Calendar HTTP is
 * not used while verifying a proof that has no pending attestation.
 */
final class OpenTimestampsWitnessBackend implements IdentifiedWitnessBackendInterface {

  private const CONTRACT = 'audit_chain.checkpoint.v1';

  public function __construct(
    private readonly ConfigFactoryInterface $configFactory,
    private readonly WitnessTransportInterface $transport,
    private readonly WitnessDnsResolverInterface $dns,
    private readonly UuidInterface $uuid,
  ) {}

  /**
   * {@inheritdoc}
   */
  public function id(): string {
    return 'opentimestamps';
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
    $policy = new DestinationPolicy($this->dns);
    $failures = 0;
    foreach ($config['calendars'] as $calendar) {
      $url = rtrim($calendar, '/') . '/digest';
      try {
        $policy->assertAllowed($url, [DestinationPolicy::host($calendar)]);
        $result = $this->transport->request('POST', $url, $digest, [
          'Accept' => 'application/vnd.opentimestamps.v1',
          'Content-Type' => 'application/octet-stream',
          'User-Agent' => 'audit_chain',
        ]);
      }
      catch (\RuntimeException) {
        $failures++;
        continue;
      }
      if ($result['status'] < 200 || $result['status'] >= 300) {
        continue;
      }
      try {
        $proof = OtsProof::decodeTimestamp($result['body'], $digest);
        if (!$proof->hasCompletionRoute()) {
          continue;
        }
        $detached = OtsProof::encodeDetached($digest, $proof);
      }
      catch (\RuntimeException) {
        continue;
      }
      $status = WitnessReceipt::STATUS_PENDING;
      if ($proof->bitcoinCandidates() !== []) {
        $inspection = $this->inspectBitcoin($proof, $config, $policy);
        if ($inspection['state'] === 'confirmed') {
          $status = WitnessReceipt::STATUS_CONFIRMED;
        }
      }
      return new WitnessReceipt(
        $this->uuid->generate(),
        $this->id(),
        $status,
        base64_encode($detached),
      );
    }
    throw new \RuntimeException($failures > 0 ? 'backend_unreachable' : 'witness_submit_unusable');
  }

  /**
   * {@inheritdoc}
   */
  public function upgrade(WitnessReceipt $pending): WitnessReceipt {
    $this->assertBackend($pending);
    $config = $this->configuration();
    $decoded = $this->decodeReceipt($pending->opaqueToken);
    $proof = $decoded['proof'];
    if ($proof->pendingNodes() === []) {
      if ($pending->status === WitnessReceipt::STATUS_CONFIRMED) {
        return $pending;
      }
      return $this->receiptFromInspection($pending, $proof, $config, $decoded['digest']);
    }
    $policy = new DestinationPolicy($this->dns);
    $allowed = [];
    foreach ($config['upgrade_allowlist'] as $origin) {
      $allowed[] = DestinationPolicy::host($origin);
    }
    $attempted = 0;
    $transportFailures = 0;
    $merged = 0;
    foreach ($proof->pendingNodes() as $node) {
      foreach ($node->attestations() as $attestation) {
        if ($attestation['kind'] !== 'pending' || $attestation['uri'] === NULL) {
          continue;
        }
        $attempted++;
        $commitment = bin2hex($node->message());
        $url = rtrim($attestation['uri'], '/') . '/timestamp/' . $commitment;
        try {
          $policy->assertAllowed($url, $allowed);
          $result = $this->transport->request('GET', $url, '', [
            'Accept' => 'application/vnd.opentimestamps.v1',
            'User-Agent' => 'audit_chain',
          ]);
        }
        catch (\RuntimeException) {
          $transportFailures++;
          continue;
        }
        if ($result['status'] === 404) {
          continue;
        }
        if ($result['status'] < 200 || $result['status'] >= 300) {
          $transportFailures++;
          continue;
        }
        try {
          $upgrade = OtsProof::decodeTimestamp($result['body'], $node->message());
          $node->merge($upgrade);
          $merged++;
        }
        catch (\RuntimeException) {
          continue;
        }
      }
    }
    if ($attempted > 0 && $transportFailures === $attempted && $merged === 0) {
      throw new \RuntimeException('backend_unreachable');
    }
    if ($merged === 0) {
      if ($proof->bitcoinCandidates() === []) {
        return $pending;
      }
      return $this->receiptFromInspection($pending, $proof, $config, $decoded['digest']);
    }
    return $this->receiptFromInspection($pending, $proof, $config, $decoded['digest'], TRUE);
  }

  /**
   * {@inheritdoc}
   */
  public function verify(WitnessReceipt $receipt, string $digestHex): WitnessVerdict {
    $this->assertBackend($receipt);
    try {
      $decoded = $this->decodeReceipt($receipt->opaqueToken);
    }
    catch (\RuntimeException) {
      return new WitnessVerdict(FALSE, 'receipt_malformed');
    }
    $digest = $this->rawDigest($digestHex);
    if (!hash_equals($digest, $decoded['digest'])) {
      return new WitnessVerdict(FALSE, 'receipt_malformed');
    }
    $config = $this->configuration();
    $inspection = $this->inspectBitcoin($decoded['proof'], $config, new DestinationPolicy($this->dns));
    return $this->verdict($inspection);
  }

  /**
   * Builds the receipt after a header inspection.
   *
   * A header outage throws and leaves the stored token untouched. A Bitcoin
   * mismatch also throws when the proof changed, so a bad branch is not stored
   * over the previous receipt.
   *
   * @param \Drupal\audit_chain\WitnessReceipt $pending
   *   Receipt being upgraded or submitted.
   * @param \Drupal\audit_chain\Witness\OtsProof $proof
   *   Proof to inspect.
   * @param array<string, mixed> $config
   *   OpenTimestamps client settings.
   * @param string $digest
   *   Raw 32-byte checkpoint digest.
   * @param bool $changed
   *   TRUE when upgrade merged new attestations.
   *
   * @return \Drupal\audit_chain\WitnessReceipt
   *   The same receipt, or a new one with the checked status.
   */
  private function receiptFromInspection(WitnessReceipt $pending, OtsProof $proof, array $config, string $digest, bool $changed = FALSE): WitnessReceipt {
    $inspection = $this->inspectBitcoin($proof, $config, new DestinationPolicy($this->dns));
    if ($inspection['state'] === 'unavailable') {
      throw new \RuntimeException('backend_unreachable');
    }
    if ($inspection['state'] === 'mismatch') {
      throw new \RuntimeException('attestation_mismatch');
    }
    if ($inspection['state'] === 'none' && !$changed) {
      return $pending;
    }
    $status = $inspection['state'] === 'confirmed'
      ? WitnessReceipt::STATUS_CONFIRMED
      : WitnessReceipt::STATUS_PENDING;
    $token = base64_encode(OtsProof::encodeDetached($digest, $proof));
    if ($token === $pending->opaqueToken && $status === $pending->status) {
      return $pending;
    }
    return new WitnessReceipt($pending->id, $pending->backendId, $status, $token);
  }

  /**
   * Checks every Bitcoin branch and returns the strongest honest result.
   *
   * @param \Drupal\audit_chain\Witness\OtsProof $proof
   *   Detached proof to inspect.
   * @param array<string, mixed> $config
   *   OpenTimestamps client settings.
   * @param \Drupal\audit_chain\Witness\DestinationPolicy $policy
   *   Destination policy for header reads.
   *
   * @return array{state: string, evidence: array<string, int|string|bool>}
   *   confirmed, not_final, mismatch, none, or unavailable.
   */
  private function inspectBitcoin(OtsProof $proof, array $config, DestinationPolicy $policy): array {
    $candidates = $proof->bitcoinCandidates();
    if ($candidates === []) {
      if ($proof->pendingNodes() !== []) {
        return ['state' => 'not_final', 'evidence' => []];
      }
      return ['state' => 'mismatch', 'evidence' => []];
    }
    $unavailable = FALSE;
    $notFinal = NULL;
    foreach ($candidates as $candidate) {
      try {
        $checked = $this->checkHeader(
          $candidate['height'],
          $candidate['message'],
          $config,
          $policy,
        );
      }
      catch (\RuntimeException $exception) {
        if ($exception->getMessage() !== 'backend_unreachable') {
          throw $exception;
        }
        $unavailable = TRUE;
        continue;
      }
      if ($checked['state'] === 'confirmed') {
        return $checked;
      }
      if ($checked['state'] === 'not_final') {
        $notFinal = $checked;
      }
    }
    if ($unavailable) {
      return ['state' => 'unavailable', 'evidence' => []];
    }
    if (is_array($notFinal)) {
      return $notFinal;
    }
    return ['state' => 'mismatch', 'evidence' => []];
  }

  /**
   * Checks one Bitcoin attestation against a header provider.
   *
   * @param int $height
   *   Attested block height.
   * @param string $message
   *   Message that must equal the internal-order merkle root.
   * @param array<string, mixed> $config
   *   OpenTimestamps client settings.
   * @param \Drupal\audit_chain\Witness\DestinationPolicy $policy
   *   Destination policy for header reads.
   *
   * @return array{state: string, evidence: array<string, int|string|bool>}
   *   confirmed, not_final, or mismatch. A transport failure throws.
   */
  private function checkHeader(int $height, string $message, array $config, DestinationPolicy $policy): array {
    $base = rtrim((string) $config['header_url'], '/');
    $host = DestinationPolicy::host($base);
    $heightUrl = $base . '/block-height/' . $height;
    $policy->assertAllowed($heightUrl, [$host]);
    $heightResult = $this->transport->request('GET', $heightUrl, '', [
      'Accept' => 'text/plain',
      'User-Agent' => 'audit_chain',
    ]);
    if ($heightResult['status'] >= 500 || $heightResult['status'] >= 300 && $heightResult['status'] < 400) {
      throw new \RuntimeException('backend_unreachable');
    }
    $display = strtolower(trim($heightResult['body']));
    if ($heightResult['status'] !== 200 || preg_match('/^[0-9a-f]{64}$/', $display) !== 1) {
      return ['state' => 'mismatch', 'evidence' => []];
    }
    $headerUrl = $base . '/block/' . $display . '/header';
    $policy->assertAllowed($headerUrl, [$host]);
    $headerResult = $this->transport->request('GET', $headerUrl, '', [
      'Accept' => 'text/plain',
      'User-Agent' => 'audit_chain',
    ]);
    if ($headerResult['status'] >= 500 || $headerResult['status'] >= 300 && $headerResult['status'] < 400) {
      throw new \RuntimeException('backend_unreachable');
    }
    $header = hex2bin(trim($headerResult['body']));
    if ($headerResult['status'] !== 200 || $header === FALSE || strlen($header) !== 80) {
      return ['state' => 'mismatch', 'evidence' => []];
    }
    $computed = bin2hex(strrev(hash('sha256', hash('sha256', $header, TRUE), TRUE)));
    $root = substr($header, 36, 32);
    if (!hash_equals($display, $computed) || !hash_equals($message, $root)) {
      return ['state' => 'mismatch', 'evidence' => []];
    }
    $unpacked = unpack('V', substr($header, 68, 4));
    $blockTime = is_array($unpacked) ? (int) $unpacked[1] : 0;
    $tipUrl = $base . '/blocks/tip/height';
    $policy->assertAllowed($tipUrl, [$host]);
    $tipResult = $this->transport->request('GET', $tipUrl, '', [
      'Accept' => 'text/plain',
      'User-Agent' => 'audit_chain',
    ]);
    if ($tipResult['status'] !== 200 || preg_match('/^\d+$/', trim($tipResult['body'])) !== 1) {
      throw new \RuntimeException('backend_unreachable');
    }
    $statusUrl = $base . '/block/' . $display . '/status';
    $policy->assertAllowed($statusUrl, [$host]);
    $statusResult = $this->transport->request('GET', $statusUrl, '', [
      'Accept' => 'application/json',
      'User-Agent' => 'audit_chain',
    ]);
    if ($statusResult['status'] >= 500 || $statusResult['status'] >= 300 && $statusResult['status'] < 400) {
      throw new \RuntimeException('backend_unreachable');
    }
    $status = json_decode($statusResult['body'], TRUE);
    $inBestChain = is_array($status) && ($status['in_best_chain'] ?? NULL) === TRUE;
    if ($statusResult['status'] !== 200 || !$inBestChain) {
      return ['state' => 'mismatch', 'evidence' => []];
    }
    $depth = ((int) trim($tipResult['body'])) - $height;
    $evidence = [
      'bitcoin_height' => $height,
      'bitcoin_block_hash' => $display,
      'bitcoin_block_time' => $blockTime,
      'header_depth' => $depth,
      'trust_mode' => 'header_provider',
      'final' => $depth >= (int) $config['min_depth'],
    ];
    if ($depth < (int) $config['min_depth']) {
      return ['state' => 'not_final', 'evidence' => $evidence];
    }
    return ['state' => 'confirmed', 'evidence' => $evidence];
  }

  /**
   * Maps a header inspection to a fail-closed verdict.
   *
   * @param array{state: string, evidence: array<string, int|string|bool>} $inspection
   *   Result from inspectBitcoin().
   *
   * @return \Drupal\audit_chain\WitnessVerdict
   *   Valid only when the inspection state is confirmed.
   */
  private function verdict(array $inspection): WitnessVerdict {
    if ($inspection['state'] === 'confirmed') {
      return new WitnessVerdict(TRUE, 'confirmed', $inspection['evidence']);
    }
    if ($inspection['state'] === 'unavailable') {
      return new WitnessVerdict(FALSE, 'backend_unreachable', $inspection['evidence']);
    }
    if ($inspection['state'] === 'not_final') {
      return new WitnessVerdict(FALSE, 'receipt_not_final', $inspection['evidence']);
    }
    return new WitnessVerdict(FALSE, 'attestation_mismatch', $inspection['evidence']);
  }

  /**
   * Decodes a stored detached proof.
   *
   * @param string $token
   *   Standard base64 detached proof.
   *
   * @return array{digest: string, proof: OtsProof}
   *   File digest and timestamp tree.
   */
  private function decodeReceipt(string $token): array {
    $bytes = base64_decode($token, TRUE);
    if ($bytes === FALSE) {
      throw new \RuntimeException('ots_malformed');
    }
    return OtsProof::decodeDetached($bytes);
  }

  /**
   * Converts a lowercase hex digest to 32 raw bytes.
   *
   * @param string $digestHex
   *   Persisted checkpoint digest.
   *
   * @return string
   *   Raw digest bytes.
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
   * Loads OpenTimestamps settings and fails closed when they are incomplete.
   *
   * @return array{calendars: list<string>, upgrade_allowlist: list<string>, header_url: string, min_depth: int}
   *   Calendars, upgrade hosts, header URL, and minimum depth.
   */
  private function configuration(): array {
    $value = $this->configFactory->get('audit_chain.settings')->get('witness_opentimestamps');
    if (!is_array($value)) {
      throw new \RuntimeException('witness_opentimestamps_unconfigured');
    }
    $calendars = array_values(array_filter(
      $value['calendars'] ?? [],
      static fn ($item): bool => is_string($item) && $item !== '',
    ));
    $allowlist = array_values(array_filter(
      $value['upgrade_allowlist'] ?? [],
      static fn ($item): bool => is_string($item) && $item !== '',
    ));
    $header = $value['header_url'] ?? '';
    $depth = $value['min_depth'] ?? NULL;
    if (is_string($depth) && preg_match('/^[1-9][0-9]*$/', $depth) === 1) {
      $depth = (int) $depth;
    }
    if ($calendars === [] || $allowlist === [] || !is_string($header) || $header === '' || !is_int($depth) || $depth < 1) {
      throw new \RuntimeException('witness_opentimestamps_unconfigured');
    }
    return [
      'calendars' => $calendars,
      'upgrade_allowlist' => $allowlist,
      'header_url' => $header,
      'min_depth' => $depth,
    ];
  }

  /**
   * Rejects a receipt that belongs to another backend.
   *
   * @param \Drupal\audit_chain\WitnessReceipt $receipt
   *   Receipt being upgraded or verified.
   */
  private function assertBackend(WitnessReceipt $receipt): void {
    if ($receipt->backendId !== $this->id()) {
      throw new \RuntimeException('witness_backend_mismatch');
    }
  }

}
